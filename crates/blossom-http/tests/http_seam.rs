//! Integration tests at the HTTP seam.
//!
//! Every test drives the real [`blossom_http::router`] with
//! `tower::ServiceExt::oneshot` against a real [`FsBlobStore`] in a temporary
//! directory and a fixed [`Clock`]. No sockets and no mocks: the assertions are
//! the status codes and headers the BUDs specify.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::header::{self, HeaderMap};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blossom_core::auth::{event_id, NostrEvent};
use blossom_core::mime::MimeType;
use blossom_core::sha256::Sha256;
use blossom_http::config::{AuthMode, AuthPolicy};
use blossom_http::state::Clock;
use blossom_http::{router, AppState, Config};
use blossom_store::{DeleteOutcome, FsBlobStore, PutOptions, PutOutcome, StoreConfig};
use http_body_util::BodyExt;
use secp256k1::Keypair;
use sha2::{Digest, Sha256 as Sha2};
use tower::ServiceExt;

const HOST: &str = "cdn.example.com";
const NOW: i64 = 1_700_000_000;

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> i64 {
        self.0
    }
}

fn base_config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: PathBuf::new(),
        public_base: format!("https://{HOST}"),
        host: HOST.to_string(),
        max_blob_size: 4096,
        auth: AuthPolicy::for_mode(AuthMode::Writes),
        enable_list: true,
        enable_mirror: true,
        enable_media: true,
        mirror_allow_private: false,
        blocked_mime: vec!["text/x-blocked".to_string()],
    }
}

async fn harness(config: Config) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config;
    config.data_dir = dir.path().to_path_buf();
    let store = FsBlobStore::open(StoreConfig {
        data_dir: config.data_dir.clone(),
        max_blob_size: config.max_blob_size,
    })
    .await
    .unwrap();
    let state = AppState::new(Arc::new(store), Arc::new(config), Arc::new(FixedClock(NOW)));
    (state, dir)
}

// ---------------------------------------------------------------------------
// BUD-11 token construction
// ---------------------------------------------------------------------------

struct Signer {
    keypair: Keypair,
}

impl Signer {
    fn new(seed: u8) -> Self {
        let mut secret = [0u8; 32];
        secret[31] = seed;
        Self {
            keypair: Keypair::from_secret_bytes(secret).unwrap(),
        }
    }

    fn pubkey(&self) -> String {
        self.keypair.x_only_public_key().0.to_string()
    }

    fn sign_event(&self, event: &mut NostrEvent) {
        event.id = event_id(event).unwrap();
        let digest: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        event.sig = hex::encode(
            self.keypair
                .sign_schnorr_no_aux_rand(&digest)
                .to_byte_array(),
        );
    }

    /// A kind-24242 token as an `Authorization` header value.
    fn token(&self, action: &str, scopes: &[(&str, &str)]) -> String {
        let mut tags = vec![
            vec!["t".to_string(), action.to_string()],
            vec!["expiration".to_string(), (NOW + 3600).to_string()],
        ];
        for (name, value) in scopes {
            tags.push(vec![name.to_string(), value.to_string()]);
        }
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: self.pubkey(),
            created_at: NOW - 10,
            kind: 24242,
            tags,
            content: "Test authorization".to_string(),
            sig: String::new(),
        };
        self.sign_event(&mut event);
        format!(
            "Nostr {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
        )
    }

    /// A signed NIP-56 kind-1984 report body, optionally with a broken signature.
    fn report(&self, hashes: &[&str], corrupted: bool) -> Vec<u8> {
        let tags = hashes
            .iter()
            .map(|hash| vec!["x".to_string(), (*hash).to_string(), "illegal".to_string()])
            .collect();
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: self.pubkey(),
            created_at: NOW - 10,
            kind: 1984,
            tags,
            content: "Reported".to_string(),
            sig: String::new(),
        };
        self.sign_event(&mut event);
        if corrupted {
            event.sig = "00".repeat(64);
        }
        serde_json::to_vec(&event).unwrap()
    }
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha2::digest(bytes))
}

fn header(headers: &HeaderMap, name: impl header::AsHeaderName) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn request(method: &str, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder = builder.header(header::CONTENT_LENGTH, body.len().to_string());
    builder.body(Body::from(body)).unwrap()
}

fn request_without_content_length(
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body)).unwrap()
}

fn head_request(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().method("HEAD").uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

async fn send(state: &AppState, request: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let response = router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

/// Stores bytes directly, bypassing the HTTP layer, to set up read tests.
async fn seed(state: &AppState, bytes: &[u8], mime: Option<&str>, owner: Option<&str>) -> String {
    let opts = PutOptions {
        mime: mime.map(MimeType::parse),
        owner: owner.map(str::to_string),
        ..Default::default()
    };
    let outcome = state
        .store
        .put(Box::new(std::io::Cursor::new(bytes.to_vec())), opts)
        .await
        .unwrap();
    match outcome {
        PutOutcome::Created(meta) | PutOutcome::Existed(meta) => meta.sha256.to_hex(),
    }
}

// ---------------------------------------------------------------------------
// GET / HEAD blob (BUD-01)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_blob_returns_bytes_and_metadata_headers() {
    let (state, _dir) = harness(base_config()).await;
    let body = b"hello world".to_vec();
    let hash = seed(&state, &body, Some("text/plain"), None).await;

    let (status, headers, bytes) =
        send(&state, request("GET", &format!("/{hash}"), &[], vec![])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, header::CONTENT_TYPE), "text/plain");
    assert_eq!(header(&headers, header::CONTENT_LENGTH), "11");
    assert_eq!(header(&headers, header::ACCEPT_RANGES), "bytes");
    assert_eq!(bytes.as_ref(), body.as_slice());
}

#[tokio::test]
async fn get_blob_ignores_the_url_extension_for_the_mime_type() {
    let (state, _dir) = harness(base_config()).await;
    let hash = seed(&state, b"%PDF-1.7", Some("application/pdf"), None).await;

    let (status, headers, _) =
        send(&state, request("GET", &format!("/{hash}.png"), &[], vec![])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, header::CONTENT_TYPE), "application/pdf");
}

#[tokio::test]
async fn head_blob_matches_get_without_a_body() {
    let (state, _dir) = harness(base_config()).await;
    let body = b"hello world".to_vec();
    let hash = seed(&state, &body, Some("text/plain"), None).await;

    let (status, headers, bytes) = send(&state, head_request(&format!("/{hash}"), &[])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, header::CONTENT_TYPE), "text/plain");
    assert_eq!(header(&headers, header::CONTENT_LENGTH), "11");
    assert_eq!(header(&headers, header::ACCEPT_RANGES), "bytes");
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn range_request_returns_partial_content() {
    let (state, _dir) = harness(base_config()).await;
    let hash = seed(&state, b"0123456789", Some("text/plain"), None).await;

    let (status, headers, bytes) = send(
        &state,
        request(
            "GET",
            &format!("/{hash}"),
            &[("range", "bytes=2-5")],
            vec![],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(header(&headers, header::CONTENT_RANGE), "bytes 2-5/10");
    assert_eq!(header(&headers, header::CONTENT_LENGTH), "4");
    assert_eq!(bytes.as_ref(), b"2345");
}

#[tokio::test]
async fn unsatisfiable_range_is_416_and_malformed_range_is_400() {
    let (state, _dir) = harness(base_config()).await;
    let hash = seed(&state, b"0123456789", Some("text/plain"), None).await;

    let (status, headers, _) = send(
        &state,
        request(
            "GET",
            &format!("/{hash}"),
            &[("range", "bytes=50-")],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(header(&headers, header::CONTENT_RANGE), "bytes */10");
    assert!(!header(&headers, "x-reason").is_empty());

    let (status, _, _) = send(
        &state,
        request(
            "GET",
            &format!("/{hash}"),
            &[("range", "bytes=5-2")],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_hash_is_404_and_malformed_hash_is_400() {
    let (state, _dir) = harness(base_config()).await;
    let unknown = "0".repeat(64);

    let (status, headers, _) =
        send(&state, request("GET", &format!("/{unknown}"), &[], vec![])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!header(&headers, "x-reason").is_empty());

    let (status, _, _) = send(&state, request("GET", "/not-a-hash", &[], vec![])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, _) = send(&state, head_request("/not-a-hash", &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// CORS (BUD-01)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_the_cors_origin_header() {
    let (state, _dir) = harness(base_config()).await;
    let (_, headers, _) = send(&state, request("GET", "/", &[], vec![])).await;
    assert_eq!(header(&headers, header::ACCESS_CONTROL_ALLOW_ORIGIN), "*");
}

#[tokio::test]
async fn options_preflight_succeeds() {
    let (state, _dir) = harness(base_config()).await;
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/upload")
        .header(header::ORIGIN, "https://app.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .unwrap();

    let response = router(state.clone()).oneshot(request).await.unwrap();

    assert!(response.status().is_success());
    assert_eq!(
        header(response.headers(), header::ACCESS_CONTROL_ALLOW_ORIGIN),
        "*"
    );
    assert!(header(response.headers(), header::ACCESS_CONTROL_ALLOW_METHODS).contains("PUT"));
    assert!(
        header(response.headers(), header::ACCESS_CONTROL_ALLOW_HEADERS)
            .to_ascii_lowercase()
            .contains("authorization")
    );
}

// ---------------------------------------------------------------------------
// PUT /upload (BUD-02)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_created_then_existed_returns_a_descriptor() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let body = b"fake png bytes".to_vec();
    let hash = sha256_hex(&body);
    let auth = signer.token("upload", &[("x", &hash), ("server", HOST)]);

    let make = || {
        request(
            "PUT",
            "/upload",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "image/png"),
                ("x-sha-256", hash.as_str()),
            ],
            body.clone(),
        )
    };

    let (status, _, bytes) = send(&state, make()).await;
    assert_eq!(status, StatusCode::CREATED);
    let descriptor: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(descriptor["url"], format!("https://{HOST}/{hash}.png"));
    assert_eq!(descriptor["sha256"], hash);
    assert_eq!(descriptor["type"], "image/png");

    let (status, _, _) = send(&state, make()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn upload_without_authorization_is_401() {
    let (state, _dir) = harness(base_config()).await;
    let body = b"hello world".to_vec();
    let hash = sha256_hex(&body);

    let (status, headers, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[("content-type", "text/plain"), ("x-sha-256", &hash)],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!header(&headers, "x-reason").is_empty());
}

#[tokio::test]
async fn upload_with_a_token_for_another_server_is_401() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let body = b"hello world".to_vec();
    let hash = sha256_hex(&body);
    let auth = signer.token("upload", &[("x", &hash), ("server", "other.example.com")]);

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "text/plain"),
                ("x-sha-256", &hash),
            ],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_with_a_mismatched_x_tag_is_401() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let body = b"hello world".to_vec();
    let hash = sha256_hex(&body);
    let other = sha256_hex(b"something else");
    let auth = signer.token("upload", &[("x", &other), ("server", HOST)]);

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "text/plain"),
                ("x-sha-256", &hash),
            ],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_with_a_declared_hash_that_does_not_match_the_body_is_409() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let body = b"hello world".to_vec();
    let declared = sha256_hex(b"a different body");
    let auth = signer.token("upload", &[("x", &declared), ("server", HOST)]);

    let (status, headers, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "text/plain"),
                ("x-sha-256", &declared),
            ],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!header(&headers, "x-reason").is_empty());
}

#[tokio::test]
async fn upload_rejections_map_to_411_413_and_415() {
    let mut config = base_config();
    config.max_blob_size = 16;
    let (state, _dir) = harness(config).await;

    let (status, headers, _) = send(
        &state,
        request_without_content_length(
            "PUT",
            "/upload",
            &[("content-type", "text/plain")],
            b"hello".to_vec(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::LENGTH_REQUIRED);
    assert!(!header(&headers, "x-reason").is_empty());

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[("content-type", "text/plain")],
            vec![b'a'; 64],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/upload",
            &[("content-type", "text/x-blocked")],
            b"hello".to_vec(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// HEAD /upload (BUD-06)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn head_upload_accepts_an_acceptable_blob() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let hash = sha256_hex(b"hello world");
    let auth = signer.token("upload", &[("x", &hash), ("server", HOST)]);

    let (status, _, bytes) = send(
        &state,
        head_request(
            "/upload",
            &[
                ("authorization", &auth),
                ("x-sha-256", &hash),
                ("x-content-type", "image/png"),
                ("x-content-length", "11"),
            ],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn head_upload_refusals_map_to_411_413_and_415() {
    let mut config = base_config();
    config.max_blob_size = 16;
    config.auth = AuthPolicy::for_mode(AuthMode::None);
    let (state, _dir) = harness(config).await;

    let (status, headers, _) = send(
        &state,
        head_request(
            "/upload",
            &[
                ("x-sha-256", &"a".repeat(64)),
                ("x-content-type", "image/png"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::LENGTH_REQUIRED);
    assert!(!header(&headers, "x-reason").is_empty());

    let (status, _, _) = send(
        &state,
        head_request(
            "/upload",
            &[
                ("x-sha-256", &"a".repeat(64)),
                ("x-content-type", "image/png"),
                ("x-content-length", "1024"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let (status, _, _) = send(
        &state,
        head_request(
            "/upload",
            &[
                ("x-sha-256", &"a".repeat(64)),
                ("x-content-type", "text/x-blocked"),
                ("x-content-length", "11"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ---------------------------------------------------------------------------
// PUT / DELETE (BUD-12)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_by_owner_removes_the_blob() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let owner = signer.pubkey();
    let body = b"owned blob".to_vec();
    let hash = seed(&state, &body, Some("text/plain"), Some(&owner)).await;
    let auth = signer.token("delete", &[("x", &hash), ("server", HOST)]);

    let (status, _, _) = send(
        &state,
        request(
            "DELETE",
            &format!("/{hash}"),
            &[("authorization", auth.as_str())],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(&state, request("GET", &format!("/{hash}"), &[], vec![])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_by_another_pubkey_is_403() {
    let (state, _dir) = harness(base_config()).await;
    let owner_signer = Signer::new(1);
    let other_signer = Signer::new(2);
    let hash = seed(
        &state,
        b"owned blob",
        Some("text/plain"),
        Some(&owner_signer.pubkey()),
    )
    .await;
    let auth = other_signer.token("delete", &[("x", &hash), ("server", HOST)]);

    let (status, _, _) = send(
        &state,
        request(
            "DELETE",
            &format!("/{hash}"),
            &[("authorization", auth.as_str())],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_unknown_blob_is_404_and_missing_x_is_401() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let unknown = "a".repeat(64);

    let auth = signer.token("delete", &[("x", &unknown), ("server", HOST)]);
    let (status, _, _) = send(
        &state,
        request(
            "DELETE",
            &format!("/{unknown}"),
            &[("authorization", auth.as_str())],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let no_x = signer.token("delete", &[("server", HOST)]);
    let (status, headers, _) = send(
        &state,
        request(
            "DELETE",
            &format!("/{unknown}"),
            &[("authorization", no_x.as_str())],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!header(&headers, "x-reason").is_empty());
}

// ---------------------------------------------------------------------------
// GET /list/<pubkey> (BUD-12)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_returns_newest_first_and_paginates_with_a_cursor() {
    let mut config = base_config();
    config.auth = AuthPolicy::for_mode(AuthMode::None);
    let (state, _dir) = harness(config).await;
    let owner = Signer::new(1).pubkey();

    let older = seed(&state, b"alpha", Some("text/plain"), Some(&owner)).await;
    // The store timestamps uploads from the system clock, so cross a second
    // boundary to guarantee distinct `uploaded` values.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let newer = seed(&state, b"beta", Some("text/plain"), Some(&owner)).await;

    let (status, _, bytes) = send(
        &state,
        request("GET", &format!("/list/{owner}"), &[], vec![]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let entries = page.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["sha256"], newer, "newest descriptor first");
    assert_eq!(entries[1]["sha256"], older);

    let (status, _, bytes) = send(
        &state,
        request("GET", &format!("/list/{owner}?limit=1"), &[], vec![]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(first.as_array().unwrap().len(), 1);
    assert_eq!(first[0]["sha256"], newer);

    let (status, _, bytes) = send(
        &state,
        request(
            "GET",
            &format!("/list/{owner}?limit=1&cursor={newer}"),
            &[],
            vec![],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(second.as_array().unwrap().len(), 1);
    assert_eq!(second[0]["sha256"], older);
}

#[tokio::test]
async fn list_with_a_token_for_another_pubkey_is_401() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let other = Signer::new(2).pubkey();
    let auth = signer.token("list", &[("server", HOST)]);

    let (status, headers, _) = send(
        &state,
        request(
            "GET",
            &format!("/list/{other}"),
            &[("authorization", auth.as_str())],
            vec![],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!header(&headers, "x-reason").is_empty());
}

// ---------------------------------------------------------------------------
// PUT /report (BUD-09)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn report_records_a_valid_event_without_blocking() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let hash = sha256_hex(b"reported blob");

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/report",
            &[("content-type", "application/json")],
            signer.report(&[&hash], false),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let parsed = Sha256::parse(&hash).unwrap();
    assert!(!state.store.is_blocked(&parsed).await.unwrap());
}

#[tokio::test]
async fn report_with_a_bad_signature_is_400() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let hash = sha256_hex(b"reported blob");

    let (status, headers, _) = send(
        &state,
        request(
            "PUT",
            "/report",
            &[("content-type", "application/json")],
            signer.report(&[&hash], true),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!header(&headers, "x-reason").is_empty());

    let parsed = Sha256::parse(&hash).unwrap();
    assert!(!state.store.is_blocked(&parsed).await.unwrap());
}

// ---------------------------------------------------------------------------
// PUT /mirror (BUD-04)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mirror_of_a_loopback_url_is_refused() {
    let mut config = base_config();
    config.auth = AuthPolicy::for_mode(AuthMode::None);
    let (state, _dir) = harness(config).await;

    let body = serde_json::to_vec(&serde_json::json!({
        "url": "http://127.0.0.1:9/blob"
    }))
    .unwrap();

    let (status, headers, _) = send(
        &state,
        request(
            "PUT",
            "/mirror",
            &[("content-type", "application/json")],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!header(&headers, "x-reason").is_empty());
}

// ---------------------------------------------------------------------------
// Disabled endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_endpoints_are_404() {
    let mut config = base_config();
    config.enable_media = false;
    config.enable_mirror = false;
    config.enable_list = false;
    let (state, _dir) = harness(config).await;

    let (status, _, _) = send(&state, request("PUT", "/media", &[], vec![])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(&state, head_request("/media", &[])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/mirror",
            &[("content-type", "application/json")],
            b"{\"url\":\"https://cdn.example.com/a\"}".to_vec(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &state,
        request("GET", &format!("/list/{}", "a".repeat(64)), &[], vec![]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// PUT /media (BUD-05)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn media_rejects_non_image_or_video_types() {
    let (state, _dir) = harness(base_config()).await;

    let (status, _, _) = send(
        &state,
        request(
            "PUT",
            "/media",
            &[("content-type", "text/plain")],
            b"hello".to_vec(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn media_stores_images_unmodified() {
    let (state, _dir) = harness(base_config()).await;
    let signer = Signer::new(1);
    let body = b"fake image bytes".to_vec();
    let hash = sha256_hex(&body);
    let auth = signer.token("media", &[("x", &hash), ("server", HOST)]);

    let (status, _, bytes) = send(
        &state,
        request(
            "PUT",
            "/media",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "image/png"),
                ("x-sha-256", &hash),
            ],
            body,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let descriptor: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(descriptor["sha256"], hash);
}

// ---------------------------------------------------------------------------
// Ownership seam used by the delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn store_delete_contract_is_what_the_handler_relies_on() {
    // Guard against a store change that would silently change the DELETE
    // status mapping: the handler maps these three outcomes to 204/404/403.
    let (state, _dir) = harness(base_config()).await;
    let owner = Signer::new(1).pubkey();
    let hash = seed(&state, b"blob", Some("text/plain"), Some(&owner)).await;
    let parsed = Sha256::parse(&hash).unwrap();

    assert_eq!(
        state.store.delete(&parsed, "someone-else").await.unwrap(),
        DeleteOutcome::NotOwner
    );
    assert_eq!(
        state.store.delete(&parsed, &owner).await.unwrap(),
        DeleteOutcome::Deleted
    );
    assert_eq!(
        state.store.delete(&parsed, &owner).await.unwrap(),
        DeleteOutcome::NotFound
    );
}
