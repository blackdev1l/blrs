//! One handler per BUD route.
//!
//! Every handler is a thin adapter: it enforces BUD-11 authorization, maps the
//! request onto [`blossom_store::BlobStore`], and turns the result into the
//! status code and headers the relevant BUD specifies. No blob body is ever
//! buffered: reads stream out of the store and uploads stream into it.

use std::io;
use std::net::{IpAddr, SocketAddr};

use axum::body::{to_bytes, Body};
use axum::extract::{Path, Query, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{Stream, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};
use url::Url;

use blossom_core::auth::{
    verify_signature, Action, AuthToken, AuthorizedUser, NostrEvent, VerifyContext,
};
use blossom_core::path::parse_blob_path;
use blossom_core::range::{parse_range, RangeOutcome};
use blossom_core::sha256::Sha256;
use blossom_core::AuthError;
use blossom_core::{BlobDescriptor, MimeType};
use blossom_store::{
    BlobMeta, DeleteOutcome, ListQuery, PutOptions, PutOutcome, ReportRecord, StoreError,
};

use crate::error::HttpError;
use crate::mirror::{self, MirrorError};
use crate::state::AppState;

/// Largest request body accepted for the JSON endpoints (`/mirror`, `/report`).
const JSON_BODY_LIMIT: usize = 64 * 1024;

/// Page size for `GET /list/<pubkey>` when the query omits `limit`.
///
/// Matches the store's own maximum, so a client asking for more is clamped to
/// the same value instead of being silently truncated differently.
const DEFAULT_LIST_LIMIT: u32 = 100;

/// Maximum redirect hops followed while mirroring.
const MAX_MIRROR_REDIRECTS: usize = 5;

const X_SHA_256: HeaderName = HeaderName::from_static("x-sha-256");
const X_CONTENT_TYPE: HeaderName = HeaderName::from_static("x-content-type");
const X_CONTENT_LENGTH: HeaderName = HeaderName::from_static("x-content-length");

/// Cursor pagination parameters for `GET /list/<pubkey>` (BUD-12).
#[derive(Debug, serde::Deserialize)]
pub struct ListParams {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

// ---------------------------------------------------------------------------
// Shared request plumbing
// ---------------------------------------------------------------------------

/// Decodes the `Authorization` header, if present.
fn bearer_token(headers: &HeaderMap) -> Result<Option<AuthToken>, HttpError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| HttpError::unauthorized(&AuthError::BadBase64))?;
    AuthToken::from_authorization_header(value)
        .map(Some)
        .map_err(|err| HttpError::unauthorized(&err))
}

/// Verifies the token against the endpoint, enforcing `Config::auth`.
///
/// A token is validated whenever it is present, even on an endpoint that does
/// not require one; only its absence is tolerated when the policy allows it.
fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    action: Action,
    blob: Option<&Sha256>,
) -> Result<Option<AuthorizedUser>, HttpError> {
    let token = match bearer_token(headers) {
        Ok(token) => token,
        Err(err) => {
            tracing::warn!(action = action.verb(), "authorization header is malformed");
            return Err(err);
        }
    };
    match token {
        Some(token) => {
            let ctx = VerifyContext::new(action, &state.config.host, blob, state.clock.now());
            match token.verify(ctx) {
                Ok(user) => Ok(Some(user)),
                Err(err) => {
                    tracing::warn!(
                        action = action.verb(),
                        reason = err.reason(),
                        detail = %err,
                        "authorization token rejected"
                    );
                    Err(HttpError::unauthorized(&err))
                }
            }
        }
        None if state.config.auth.requires(action) => {
            tracing::warn!(
                action = action.verb(),
                "authorization is required but the request carried no token"
            );
            Err(HttpError::unauthorized(&AuthError::Missing))
        }
        None => Ok(None),
    }
}

/// Logs a failed store write at the level its cause deserves.
///
/// A backend failure (an `io` or index error, a corrupt file) is an `error`;
/// every other store error is the request's own fault and is only a `warn`, so
/// a client sending a mismatched hash does not read as a storage outage.
fn log_store_failure(action: &str, err: &StoreError, message: &str) {
    let internal = matches!(
        err,
        StoreError::Io(_)
            | StoreError::Index(_)
            | StoreError::IndexTask(_)
            | StoreError::Corrupt(_)
    );
    if internal {
        tracing::error!(action, error = %err, "{message}");
    } else {
        tracing::warn!(action, error = %err, "{message}");
    }
}

/// Authorization for the endpoints whose implied blob hash is the client's
/// `X-SHA-256` declaration (`/upload`, `/media`).
///
/// BUD-11 makes `x` mandatory for these endpoints, and `x` can only be checked
/// against a declared hash, so an authenticated request must carry one. When no
/// hash is declared and no token is required, the request is treated as
/// anonymous rather than failing on a constraint that cannot be evaluated.
fn authorize_declared(
    state: &AppState,
    headers: &HeaderMap,
    action: Action,
    declared: Option<&Sha256>,
) -> Result<Option<AuthorizedUser>, HttpError> {
    match declared {
        Some(hash) => authorize(state, headers, action, Some(hash)),
        None if state.config.auth.requires(action) => {
            tracing::warn!(
                action = action.verb(),
                "authorization is required but the request did not declare X-SHA-256"
            );
            Err(HttpError::unauthorized(&AuthError::MissingXTag))
        }
        None => Ok(None),
    }
}

/// Collects a small JSON request body.
async fn json_body<T: serde::de::DeserializeOwned>(body: Body, what: &str) -> Result<T, HttpError> {
    let bytes = to_bytes(body, JSON_BODY_LIMIT).await.map_err(|_| {
        HttpError::bad_request(format!("{what} request body is missing or too large"))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| HttpError::bad_request(format!("{what} request body is malformed")))
}

/// A `PUT`/`POST` body as a streaming reader.
fn body_reader(body: Body) -> Box<dyn AsyncRead + Send + Unpin> {
    boxed_reader(body.into_data_stream())
}

/// Wraps any `Bytes` stream as the boxed reader `BlobStore::put` wants.
fn boxed_reader<S, E>(stream: S) -> Box<dyn AsyncRead + Send + Unpin>
where
    S: Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    let stream = Box::pin(stream).map_err(io::Error::other);
    Box::new(StreamReader::new(stream))
}

fn content_type_value(mime: &MimeType) -> HeaderValue {
    HeaderValue::from_str(mime.as_str())
        .unwrap_or_else(|_| HeaderValue::from_static(MimeType::OCTET_STREAM))
}

/// The MIME type declared by `header`, if the header is present and readable.
fn header_mime(headers: &HeaderMap, header: HeaderName) -> Option<MimeType> {
    headers
        .get(header)
        .and_then(|value| value.to_str().ok())
        .map(MimeType::parse)
}

/// The MIME type suggested by `X-Content-Type`, used by the `HEAD` pre-flights.
fn declared_mime(headers: &HeaderMap) -> MimeType {
    header_mime(headers, header::CONTENT_TYPE)
        .or_else(|| header_mime(headers, X_CONTENT_TYPE))
        .unwrap_or_else(MimeType::octet_stream)
}

fn content_length(headers: &HeaderMap) -> Result<u64, HttpError> {
    let value = headers.get(header::CONTENT_LENGTH).ok_or_else(|| {
        HttpError::length_required("Content-Length header is required to upload a blob")
    })?;
    parse_u64_header(value, "Content-Length")
}

fn declared_content_length(headers: &HeaderMap) -> Result<u64, HttpError> {
    let value = headers.get(X_CONTENT_LENGTH).ok_or_else(|| {
        HttpError::length_required("X-Content-Length header is required to pre-flight an upload")
    })?;
    parse_u64_header(value, "X-Content-Length")
}

fn parse_u64_header(value: &HeaderValue, name: &str) -> Result<u64, HttpError> {
    let raw = value
        .to_str()
        .map_err(|_| HttpError::bad_request(format!("{name} header is malformed")))?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| HttpError::bad_request(format!("{name} header is malformed")))
}

/// Parses `X-SHA-256`, rejecting a malformed value with `400`.
fn declared_hash(headers: &HeaderMap) -> Result<Option<Sha256>, HttpError> {
    let Some(value) = headers.get(&X_SHA_256) else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| HttpError::bad_request("X-SHA-256 header is malformed"))?;
    Sha256::parse(raw.trim())
        .map(Some)
        .map_err(|_| HttpError::bad_request("X-SHA-256 header must be 64 lowercase hex characters"))
}

fn normalized(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn mime_blocked(state: &AppState, mime: &MimeType) -> bool {
    state
        .config
        .blocked_mime
        .iter()
        .any(|blocked| normalized(blocked) == mime.as_str())
}

fn is_media(mime: &MimeType) -> bool {
    mime.as_str().starts_with("image/") || mime.as_str().starts_with("video/")
}

/// The descriptor for a stored blob.
fn descriptor(state: &AppState, meta: &BlobMeta) -> BlobDescriptor {
    BlobDescriptor::new(
        &state.config.public_base,
        &meta.sha256,
        meta.size,
        &meta.mime,
        meta.uploaded,
    )
}

fn descriptor_response(state: &AppState, outcome: PutOutcome) -> Response {
    let (status, meta) = match outcome {
        PutOutcome::Created(meta) => (StatusCode::CREATED, meta),
        PutOutcome::Existed(meta) => (StatusCode::OK, meta),
    };
    (status, Json(descriptor(state, &meta))).into_response()
}

fn blob_hash(segment: &str) -> Result<Sha256, HttpError> {
    parse_blob_path(segment)
        .map(|(hash, _)| hash)
        .map_err(|_| HttpError::bad_request("Blob path is not a valid sha256 hash"))
}

/// A blob metadata header set shared by `GET` and `HEAD`.
fn blob_response(
    status: StatusCode,
    meta: &BlobMeta,
    length: u64,
    content_range: Option<String>,
    body: Body,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type_value(&meta.mime))
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(value) = content_range {
        builder = builder.header(header::CONTENT_RANGE, value);
    }
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn range_not_satisfiable(meta: &BlobMeta) -> Response {
    let mut response = HttpError::new(
        StatusCode::RANGE_NOT_SATISFIABLE,
        "Requested range is not satisfiable",
    )
    .into_response();
    let headers = response.headers_mut();
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{}", meta.size)) {
        headers.insert(header::CONTENT_RANGE, value);
    }
    response
}

// ---------------------------------------------------------------------------
// GET / and blob retrieval
// ---------------------------------------------------------------------------

/// `GET /` - a small server banner.
pub async fn get_index(State(state): State<AppState>) -> Result<Response, HttpError> {
    let banner = serde_json::json!({
        "name": "blossom",
        "version": env!("CARGO_PKG_VERSION"),
        "host": state.config.host,
    });
    Ok((StatusCode::OK, Json(banner)).into_response())
}

/// `GET /<sha256>[.ext]` - BUD-01.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let hash = blob_hash(&name)?;
    authorize(&state, &headers, Action::Get, Some(&hash))?;

    let meta = state
        .store
        .meta(&hash)
        .await?
        .ok_or_else(|| HttpError::not_found("Blob not found"))?;

    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match parse_range(range_header, meta.size) {
        RangeOutcome::Full => {
            let reader = state
                .store
                .read(&hash, None)
                .await?
                .ok_or_else(|| HttpError::not_found("Blob not found"))?;
            let body = Body::from_stream(ReaderStream::new(reader.stream));
            Ok(blob_response(StatusCode::OK, &meta, meta.size, None, body))
        }
        RangeOutcome::Partial(range) => {
            let reader = state
                .store
                .read(&hash, Some(range))
                .await?
                .ok_or_else(|| HttpError::not_found("Blob not found"))?;
            let body = Body::from_stream(ReaderStream::new(reader.stream));
            Ok(blob_response(
                StatusCode::PARTIAL_CONTENT,
                &meta,
                range.len(),
                Some(range.content_range(meta.size)),
                body,
            ))
        }
        RangeOutcome::Unsatisfiable => Ok(range_not_satisfiable(&meta)),
        RangeOutcome::Malformed => Err(HttpError::bad_request("Range header is malformed")),
    }
}

/// `HEAD /<sha256>[.ext]` - BUD-01. Metadata only; never opens the blob file.
pub async fn head_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let hash = blob_hash(&name)?;
    authorize(&state, &headers, Action::Get, Some(&hash))?;

    let meta = state
        .store
        .meta(&hash)
        .await?
        .ok_or_else(|| HttpError::not_found("Blob not found"))?;

    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match parse_range(range_header, meta.size) {
        RangeOutcome::Full => Ok(blob_response(
            StatusCode::OK,
            &meta,
            meta.size,
            None,
            Body::empty(),
        )),
        RangeOutcome::Partial(range) => Ok(blob_response(
            StatusCode::PARTIAL_CONTENT,
            &meta,
            range.len(),
            Some(range.content_range(meta.size)),
            Body::empty(),
        )),
        RangeOutcome::Unsatisfiable => Ok(range_not_satisfiable(&meta)),
        RangeOutcome::Malformed => Err(HttpError::bad_request("Range header is malformed")),
    }
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

/// `PUT /upload` - BUD-02.
pub async fn put_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    store_upload(state, headers, body, Action::Upload, false).await
}

/// `PUT /media` - BUD-05.
///
/// The server owns the optimisation policy (BUD-05). This server currently
/// stores the media bytes unmodified - a documented no-op optimiser - so the
/// endpoint is an upload that additionally refuses anything that is not
/// `image/*` or `video/*`.
pub async fn put_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    if !state.config.enable_media {
        tracing::warn!(
            endpoint = "PUT /media",
            "media optimisation is disabled; enable it with --enable-media or BLOSSOM_ENABLE_MEDIA=true"
        );
        return Err(HttpError::not_found("Media optimisation is disabled"));
    }
    store_upload(state, headers, body, Action::Media, true).await
}

/// The body of `PUT /upload` and `PUT /media`.
async fn store_upload(
    state: AppState,
    headers: HeaderMap,
    body: Body,
    action: Action,
    require_media: bool,
) -> Result<Response, HttpError> {
    // Validate the cheap declarations first so a refusal does not depend on the
    // request being authenticated.
    let length = content_length(&headers)?;
    if length > state.config.max_blob_size {
        return Err(HttpError::payload_too_large(
            "Blob exceeds the maximum allowed size",
        ));
    }
    let mime = header_mime(&headers, header::CONTENT_TYPE);
    let resolved_mime = mime.clone().unwrap_or_else(MimeType::octet_stream);
    if require_media && !is_media(&resolved_mime) {
        return Err(HttpError::unsupported_media_type(
            "Only image/* and video/* media is accepted",
        ));
    }
    if mime_blocked(&state, &resolved_mime) {
        return Err(HttpError::unsupported_media_type(
            "Blob MIME type is blocked by server policy",
        ));
    }

    let declared = declared_hash(&headers)?;
    let user = authorize_declared(&state, &headers, action, declared.as_ref())?;

    let owner = user.map(|user| user.pubkey().to_string());
    let opts = PutOptions {
        expected: declared,
        mime,
        owner: owner.clone(),
        declared_size: Some(length),
        extension: None,
    };
    let outcome = match state.store.put(body_reader(body), opts).await {
        Ok(outcome) => outcome,
        Err(err) => {
            log_store_failure(action.verb(), &err, "upload failed");
            return Err(err.into());
        }
    };
    let (outcome_label, meta) = match &outcome {
        PutOutcome::Created(meta) => ("created", meta),
        PutOutcome::Existed(meta) => ("existed", meta),
    };
    tracing::info!(
        action = action.verb(),
        sha256 = %meta.sha256,
        size = meta.size,
        owner = owner.as_deref().unwrap_or(""),
        outcome = outcome_label,
        "blob stored"
    );
    Ok(descriptor_response(&state, outcome))
}

/// `HEAD /upload` - BUD-06 pre-flight.
pub async fn head_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    preflight(state, headers, Action::Upload, false).await
}

/// `HEAD /media` - BUD-05 pre-flight.
pub async fn head_media(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    if !state.config.enable_media {
        tracing::warn!(
            endpoint = "HEAD /media",
            "media optimisation is disabled; enable it with --enable-media or BLOSSOM_ENABLE_MEDIA=true"
        );
        return Err(HttpError::not_found("Media optimisation is disabled"));
    }
    preflight(state, headers, Action::Media, true).await
}

/// The status-only evaluation shared by the `HEAD` pre-flights.
///
/// Never reads a body: every input is a header. Mirrors the checks `store_upload`
/// makes, in the same order, so an accepted pre-flight predicts an accepted put.
async fn preflight(
    state: AppState,
    headers: HeaderMap,
    action: Action,
    require_media: bool,
) -> Result<Response, HttpError> {
    let declared = declared_hash(&headers)?;
    let length = declared_content_length(&headers)?;
    if length > state.config.max_blob_size {
        return Err(HttpError::payload_too_large(
            "Blob would exceed the maximum allowed size",
        ));
    }
    let mime = declared_mime(&headers);
    if require_media && !is_media(&mime) {
        return Err(HttpError::unsupported_media_type(
            "Only image/* and video/* media is accepted",
        ));
    }
    if mime_blocked(&state, &mime) {
        return Err(HttpError::unsupported_media_type(
            "Blob MIME type is blocked by server policy",
        ));
    }

    authorize_declared(&state, &headers, action, declared.as_ref())?;

    if let Some(hash) = declared.as_ref() {
        if state.store.is_blocked(hash).await? {
            return Err(HttpError::forbidden("Blob is blocked by server policy"));
        }
        // Deduplication is free: a blob that is already stored consumes no new
        // space, so an exhausted budget must not refuse its re-upload.
        if state.store.meta(hash).await?.is_some() {
            return Ok(StatusCode::OK.into_response());
        }
    }
    // BUD-06 exists so a client is told before it uploads. Mirror the store's
    // admission check here rather than letting it discover the full disk only
    // after sending the body.
    if !state.store.has_quota_room(length).await? {
        return Err(StoreError::QuotaExceeded.into());
    }
    Ok(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// Mirroring
// ---------------------------------------------------------------------------

/// `PUT /mirror` - BUD-04.
pub async fn put_mirror(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    if !state.config.enable_mirror {
        tracing::warn!(
            endpoint = "PUT /mirror",
            "mirroring is disabled; enable it with --enable-mirror or BLOSSOM_ENABLE_MIRROR=true"
        );
        return Err(HttpError::not_found("Mirroring is disabled"));
    }

    #[derive(serde::Deserialize)]
    struct MirrorRequest {
        url: String,
    }
    let request: MirrorRequest = json_body(body, "Mirror").await?;
    let url =
        Url::parse(&request.url).map_err(|_| HttpError::bad_request("Mirror url is invalid"))?;
    mirror::check_url(&url, state.config.mirror_allow_private).map_err(mirror_error)?;

    // BUD-11 makes `x` mandatory for `/mirror`, and the endpoint's implied hash
    // is the mirrored blob's. The client knows that hash (it came from the
    // origin's descriptor), so the token's `x` declares it and the store proves
    // the fetched bytes hash to it - a mismatch is BUD-04's `409 Conflict`.
    let token = bearer_token(&headers)?;
    let expected = token.as_ref().and_then(first_x_hash);
    let owner = match (&token, &expected) {
        (Some(token), Some(hash)) => Some(verify_mirror_token(&state, token, hash)?),
        (Some(_), None) if state.config.auth.requires(Action::Upload) => {
            return Err(HttpError::unauthorized(&AuthError::MissingXTag));
        }
        (None, None) if state.config.auth.requires(Action::Upload) => {
            return Err(HttpError::unauthorized(&AuthError::Missing));
        }
        _ => None,
    };

    let (final_url, response) = fetch_origin(&state, &url).await?;
    if !response.status().is_success() {
        return Err(HttpError::bad_gateway(format!(
            "Origin returned status {}",
            response.status().as_u16()
        )));
    }

    let content_length = response.content_length();
    if let Some(length) = content_length {
        if length > state.config.max_blob_size {
            return Err(HttpError::payload_too_large(
                "Mirrored blob exceeds the maximum allowed size",
            ));
        }
    }
    let mime = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(MimeType::parse);
    if let Some(mime) = mime.as_ref() {
        if mime_blocked(&state, mime) {
            return Err(HttpError::unsupported_media_type(
                "Mirrored blob MIME type is blocked by server policy",
            ));
        }
    }

    let opts = PutOptions {
        expected,
        mime,
        owner: owner.clone(),
        declared_size: content_length,
        extension: url_extension(&final_url),
    };
    let stream = boxed_reader(response.bytes_stream());
    let outcome = match state.store.put(stream, opts).await {
        Ok(outcome) => outcome,
        Err(err) => {
            log_store_failure(Action::Upload.verb(), &err, "mirror failed");
            return Err(err.into());
        }
    };
    let (outcome_label, meta) = match &outcome {
        PutOutcome::Created(meta) => ("created", meta),
        PutOutcome::Existed(meta) => ("existed", meta),
    };
    tracing::info!(
        url = %final_url,
        sha256 = %meta.sha256,
        size = meta.size,
        owner = owner.as_deref().unwrap_or(""),
        outcome = outcome_label,
        "blob mirrored"
    );
    Ok(descriptor_response(&state, outcome))
}

/// The first declared blob hash in the token's `x` tags.
///
/// `/mirror` cannot know the endpoint's implied hash until the origin has been
/// fetched, so the token's own declaration stands in for it: the token must
/// declare a hash, and the store then proves the fetched bytes hash to it.
fn first_x_hash(token: &AuthToken) -> Option<Sha256> {
    token
        .event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("x"))
        .filter_map(|tag| tag.get(1))
        .find_map(|value| Sha256::parse(value).ok())
}

fn verify_mirror_token(
    state: &AppState,
    token: &AuthToken,
    hash: &Sha256,
) -> Result<String, HttpError> {
    let ctx = VerifyContext::new(
        Action::Upload,
        &state.config.host,
        Some(hash),
        state.clock.now(),
    );
    let user = token.verify(ctx).map_err(|err| {
        tracing::warn!(
            action = Action::Upload.verb(),
            reason = err.reason(),
            detail = %err,
            "mirror authorization token rejected"
        );
        HttpError::unauthorized(&err)
    })?;
    Ok(user.pubkey().to_string())
}

fn mirror_error(err: MirrorError) -> HttpError {
    match &err {
        MirrorError::DisallowedAddress => HttpError::forbidden(err.to_string()),
        MirrorError::BadUrl | MirrorError::BadScheme => HttpError::bad_request(err.to_string()),
    }
}

/// Extension from the origin path, used for the store's MIME fallback.
fn url_extension(url: &Url) -> Option<String> {
    url.path_segments()?
        .next_back()
        .and_then(|segment| segment.rsplit_once('.').map(|(_, ext)| ext.to_string()))
        .filter(|ext| !ext.is_empty())
}

/// Follows redirects manually so the SSRF policy runs on every hop.
///
/// `reqwest`'s redirect policy is synchronous and cannot resolve DNS, so it
/// cannot enforce the resolved-address rule after a redirect. This loop instead
/// re-runs [`mirror::check_url`] and [`fetch_once`] (which resolves and pins the
/// address) for each hop.
async fn fetch_origin(
    state: &AppState,
    start: &Url,
) -> Result<(Url, reqwest::Response), HttpError> {
    let mut url = start.clone();
    for _ in 0..=MAX_MIRROR_REDIRECTS {
        mirror::check_url(&url, state.config.mirror_allow_private).map_err(mirror_error)?;
        let response = fetch_once(state, &url).await?;
        if !response.status().is_redirection() {
            return Ok((url, response));
        }
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| HttpError::bad_gateway("Origin redirected without a Location header"))?;
        url = url
            .join(location)
            .map_err(|_| HttpError::bad_gateway("Origin redirected to an invalid URL"))?;
    }
    Err(HttpError::bad_gateway("Origin redirected too many times"))
}

/// Resolves `url`, checks every address, then fetches with the checked address
/// pinned so the connection cannot be rebound to another one.
async fn fetch_once(state: &AppState, url: &Url) -> Result<reqwest::Response, HttpError> {
    let allow_private = state.config.mirror_allow_private;
    let host = url
        .host_str()
        .ok_or_else(|| HttpError::bad_request("Mirror url has no host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| HttpError::bad_request("Mirror url has no port"))?;

    let addresses: Vec<SocketAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        Some(url::Host::Domain(_)) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| HttpError::bad_gateway("Origin host could not be resolved"))?
            .collect(),
        None => return Err(HttpError::bad_request("Mirror url has no host")),
    };
    if addresses.is_empty() {
        return Err(HttpError::bad_gateway("Origin host did not resolve"));
    }
    let ips: Vec<IpAddr> = addresses.iter().map(SocketAddr::ip).collect();
    mirror::check_addresses(&ips, allow_private).map_err(mirror_error)?;

    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if matches!(url.host(), Some(url::Host::Domain(_))) {
        builder = builder.resolve(&host, addresses[0]);
    }
    let client = builder
        .build()
        .map_err(|_| HttpError::bad_gateway("Could not prepare the origin request"))?;
    client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| HttpError::bad_gateway("Could not fetch the origin blob"))
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// `PUT /report` - BUD-09.
pub async fn put_report(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    let event: NostrEvent = json_body(body, "Report").await?;
    if event.kind != 1984 {
        return Err(HttpError::bad_request(
            "Report must be a NIP-56 kind 1984 event",
        ));
    }
    verify_signature(&event).map_err(|err| HttpError::bad_request(err.reason()))?;

    let mut hashes = Vec::new();
    let mut kind = String::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("x") {
            continue;
        }
        let Some(value) = tag.get(1) else {
            continue;
        };
        let hash = Sha256::parse(value)
            .map_err(|_| HttpError::bad_request("Report x tag is not a sha256 hash"))?;
        if hashes.is_empty() {
            kind = tag.get(2).cloned().unwrap_or_default();
        }
        hashes.push(hash);
    }
    if hashes.is_empty() {
        return Err(HttpError::bad_request(
            "Report must contain at least one x tag",
        ));
    }

    // A report is recorded for operator review and blocks nothing (BUD-09), so
    // no blocklist check is performed here.
    state
        .store
        .save_report(ReportRecord {
            hashes,
            reporter: event.pubkey,
            kind,
            content: event.content,
            created_at: event.created_at,
        })
        .await?;
    Ok(StatusCode::OK.into_response())
}

// ---------------------------------------------------------------------------
// Listing and deletion
// ---------------------------------------------------------------------------

/// `GET /list/<pubkey>` - BUD-12.
pub async fn get_list(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
    Query(query): Query<ListParams>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    if !state.config.enable_list {
        tracing::warn!(
            endpoint = "GET /list",
            "listing is disabled; enable it with --enable-list or BLOSSOM_ENABLE_LIST=true"
        );
        return Err(HttpError::not_found("Listing is disabled"));
    }

    // Action::List is the one action with no implied blob hash, and core cannot
    // express "the token signer is the listed pubkey", so compare here.
    if let Some(user) = authorize(&state, &headers, Action::List, None)? {
        if user.pubkey() != pubkey {
            return Err(HttpError::new(
                StatusCode::UNAUTHORIZED,
                "Token pubkey does not match the requested list",
            ));
        }
    }

    let cursor = match query.cursor.as_deref() {
        Some(value) if !value.is_empty() => Some(
            Sha256::parse(value)
                .map_err(|_| HttpError::bad_request("cursor must be a sha256 hash"))?,
        ),
        _ => None,
    };

    let metas = state
        .store
        .list(ListQuery {
            pubkey,
            cursor,
            limit: query.limit.unwrap_or(DEFAULT_LIST_LIMIT),
            since: query.since,
            until: query.until,
        })
        .await?;
    let descriptors: Vec<BlobDescriptor> =
        metas.iter().map(|meta| descriptor(&state, meta)).collect();
    Ok((StatusCode::OK, Json(descriptors)).into_response())
}

/// `DELETE /<sha256>` - BUD-12.
pub async fn delete_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let hash = blob_hash(&name)?;
    let user = authorize(&state, &headers, Action::Delete, Some(&hash))?;

    // An ownerless blob (stored while authorization was disabled) is deletable
    // by any requester, which the store expresses as an empty requester.
    let requester = user
        .map(|user| user.pubkey().to_string())
        .unwrap_or_default();
    match state.store.delete(&hash, &requester).await {
        Ok(DeleteOutcome::Deleted) => {
            tracing::info!(
                sha256 = %hash,
                requester = %requester,
                outcome = "deleted",
                "blob deleted"
            );
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(DeleteOutcome::NotFound) => {
            tracing::info!(
                sha256 = %hash,
                requester = %requester,
                outcome = "not_found",
                "delete found no blob"
            );
            Err(HttpError::not_found("Blob not found"))
        }
        Ok(DeleteOutcome::NotOwner) => {
            tracing::warn!(
                sha256 = %hash,
                requester = %requester,
                "delete refused: requester does not own the blob"
            );
            Err(HttpError::forbidden("Requester does not own this blob"))
        }
        Err(err) => {
            log_store_failure(Action::Delete.verb(), &err, "delete failed");
            Err(err.into())
        }
    }
}
