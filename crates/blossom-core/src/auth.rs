use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use secp256k1::{schnorr, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha2};

use crate::error::AuthError;
use crate::sha256::Sha256;

/// The action an authorization token authorizes (BUD-11 `t` tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Get,
    Upload,
    /// BUD-11 rule 4 additionally requires that, for a list operation, the
    /// token `pubkey` equals the pubkey named by the request path. Core cannot
    /// express that constraint, so the caller must compare
    /// [`AuthorizedUser::pubkey`] against the path segment itself.
    List,
    Delete,
    Media,
}

impl Action {
    /// The `t` tag verb for this action.
    pub fn verb(self) -> &'static str {
        match self {
            Action::Get => "get",
            Action::Upload => "upload",
            Action::List => "list",
            Action::Delete => "delete",
            Action::Media => "media",
        }
    }

    /// Parses a `t` tag verb.
    ///
    /// This is for client and error-reporting use only. The server must derive
    /// [`VerifyContext::action`] from the target endpoint, never from the
    /// token's own `t` tag: validating the tag against itself would make
    /// BUD-11 rule 4 a tautology.
    pub fn from_verb(verb: &str) -> Option<Self> {
        match verb {
            "get" => Some(Action::Get),
            "upload" => Some(Action::Upload),
            "list" => Some(Action::List),
            "delete" => Some(Action::Delete),
            "media" => Some(Action::Media),
            _ => None,
        }
    }

    /// Whether the BUD-11 endpoint table mandates an `x` tag for this action.
    ///
    /// `Upload`, `Delete`, and `Media` name a blob hash in the request, so an
    /// `x` tag is required; `Get` and `List` carry it only optionally.
    pub fn requires_x(self) -> bool {
        matches!(self, Action::Upload | Action::Delete | Action::Media)
    }
}

/// A NIP-01 nostr event, as carried inside an authorization token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    #[serde(default)]
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    /// All values for the first tag named `name`, in order.
    pub fn tag_values(&self, name: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|k| k == name))
            .filter_map(|tag| tag.get(1).map(String::as_str))
            .collect()
    }
}

/// A parsed BUD-11 authorization token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthToken {
    pub event: NostrEvent,
}

/// Everything the server must supply to validate a token.
#[derive(Clone, Copy, Debug)]
pub struct VerifyContext<'a> {
    /// The action the target endpoint performs.
    pub action: Action,
    /// This server's domain name, matched against `server` tags (e.g. `cdn.example.com`).
    pub host: &'a str,
    /// The blob hash implied by the endpoint, when it has one.
    pub blob: Option<&'a Sha256>,
    /// Whether at least one matching `x` tag is required (BUD-11 table).
    ///
    /// Derived from [`Action::requires_x`] by [`VerifyContext::new`] and kept
    /// private so a caller cannot drop a requirement the endpoint mandates.
    require_x: bool,
    /// Current unix time, injected so expiry is testable.
    pub now: i64,
}

impl<'a> VerifyContext<'a> {
    /// Builds a context for `action`, deriving `require_x` from the BUD-11
    /// endpoint table via [`Action::requires_x`].
    pub fn new(action: Action, host: &'a str, blob: Option<&'a Sha256>, now: i64) -> Self {
        Self {
            action,
            host,
            blob,
            require_x: action.requires_x(),
            now,
        }
    }

    /// Whether at least one matching `x` tag is required for this context.
    pub fn require_x(&self) -> bool {
        self.require_x
    }
}

/// The verified identity behind a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedUser {
    pubkey: String,
}

impl AuthorizedUser {
    /// The verified signer pubkey, as lowercase hex.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }
}

impl AuthToken {
    /// Decodes an `Authorization: Nostr <base64url-no-pad json>` header value.
    pub fn from_authorization_header(value: &str) -> Result<Self, AuthError> {
        let (scheme, token) = value.split_once(' ').ok_or(AuthError::BadScheme)?;
        // RFC 7235 section 2.1: the auth scheme name is case-insensitive.
        if !scheme.eq_ignore_ascii_case("Nostr") {
            return Err(AuthError::BadScheme);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| AuthError::BadBase64)?;
        let event: NostrEvent = serde_json::from_slice(&bytes).map_err(|_| AuthError::BadJson)?;
        Ok(Self { event })
    }

    /// Runs the BUD-11 validation checklist in order, after proving the token
    /// was really signed by its `pubkey`.
    ///
    /// The signature is checked first: the declared `id` is never trusted, it
    /// is recomputed from the event contents (NIP-01) and compared, then the
    /// schnorr signature is verified over that recomputed digest. This closes
    /// the forgery hole where a valid signature over a bogus declared id would
    /// otherwise sail through the checklist checks.
    ///
    /// 1. kind is 24242
    /// 2. `created_at` is in the past
    /// 3. `expiration` tag is present and in the future
    /// 4. a `t` tag matches the endpoint's action
    /// 5. if any `server` tag is present, this host is among its values
    /// 6. if an `x` tag is present it names the endpoint's blob hash; when the
    ///    endpoint mandates `x`, at least one such tag must be present
    pub fn verify(&self, ctx: VerifyContext<'_>) -> Result<AuthorizedUser, AuthError> {
        verify_signature(&self.event)?;

        let event = &self.event;
        if event.kind != 24242 {
            return Err(AuthError::WrongKind);
        }
        if event.created_at > ctx.now {
            return Err(AuthError::CreatedInFuture);
        }
        let expiration = event
            .tag_values("expiration")
            .into_iter()
            .next()
            .ok_or(AuthError::MissingExpiration)?;
        let expiration: i64 = expiration.parse().map_err(|_| AuthError::Expired)?;
        if expiration <= ctx.now {
            return Err(AuthError::Expired);
        }
        let verb = ctx.action.verb();
        if !event.tag_values("t").contains(&verb) {
            return Err(AuthError::WrongVerb);
        }
        // Rule 5 is unconditional on tag *presence*: a tag `["server"]` with
        // no value carries no host to match, so it must still fail here.
        let has_server_tag = event
            .tags
            .iter()
            .any(|tag| tag.first().is_some_and(|k| k == "server"));
        if has_server_tag
            && !event
                .tag_values("server")
                .iter()
                .any(|s| s.eq_ignore_ascii_case(ctx.host))
        {
            return Err(AuthError::ServerMismatch);
        }
        if let Some(blob) = ctx.blob {
            let xs = event.tag_values("x");
            if ctx.require_x && xs.is_empty() {
                return Err(AuthError::MissingXTag);
            }
            if !xs.is_empty() && !xs.contains(&blob.to_hex().as_str()) {
                return Err(AuthError::XTagMismatch);
            }
        } else if ctx.require_x {
            return Err(AuthError::MissingXTag);
        }
        Ok(AuthorizedUser {
            pubkey: event.pubkey.clone(),
        })
    }
}

/// Computes the NIP-01 canonical event id.
///
/// This is `sha256` of the compact JSON array
/// `[0, pubkey, created_at, kind, tags, content]`.
pub fn event_id(event: &NostrEvent) -> Result<String, AuthError> {
    // NIP-01: `[0, pubkey, created_at, kind, tags, content]`, serialized with
    // no insignificant whitespace. A tuple serializes to a JSON array, so this
    // is exactly the canonical form (see the BUD-11 worked example).
    let canonical = (
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    let bytes = serde_json::to_vec(&canonical).map_err(|_| AuthError::BadJson)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha2::digest(bytes));
    Ok(Sha256::from_bytes(digest).to_hex())
}

/// Verifies the event's BIP-340 schnorr signature against its `pubkey`.
///
/// The message signed is the *recomputed* NIP-01 canonical id; if the declared
/// `id` disagrees with it the event is rejected as [`AuthError::BadEventId`].
pub fn verify_signature(event: &NostrEvent) -> Result<(), AuthError> {
    let recomputed = event_id(event)?;
    if recomputed != event.id {
        return Err(AuthError::BadEventId);
    }
    let digest: [u8; 32] = hex::decode(recomputed)
        .map_err(|_| AuthError::BadEventId)?
        .try_into()
        .map_err(|_| AuthError::BadEventId)?;
    let pubkey: [u8; 32] = hex::decode(event.pubkey.as_str())
        .map_err(|_| AuthError::BadSignature)?
        .try_into()
        .map_err(|_| AuthError::BadSignature)?;
    let pubkey = XOnlyPublicKey::from_byte_array(pubkey).map_err(|_| AuthError::BadSignature)?;
    let signature: [u8; 64] = hex::decode(event.sig.as_str())
        .map_err(|_| AuthError::BadSignature)?
        .try_into()
        .map_err(|_| AuthError::BadSignature)?;
    let signature = schnorr::Signature::from_byte_array(signature);
    schnorr::verify(&signature, &digest, &pubkey).map_err(|_| AuthError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Keypair;

    const BUD_EVENT_ID: &str = "7a1735c3852cf3f374edae4b2af2ee18e750e6dec583e19c4795d3b179af6d17";
    const BUD_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const BUD_SIG: &str = "4b57c22b1797b109530ffe5d04cabac468b1a5942873a5141334ecbc77694fc968a1b941979ba13602fceb1dad8014ab6469c6ae9cef0b5668cc23ad1449e103";
    const X_HEX: &str = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    const HOST: &str = "cdn.example.com";
    const NOW: i64 = 1_700_000_000;

    fn tag(name: &str, value: &str) -> Vec<String> {
        vec![name.to_string(), value.to_string()]
    }

    fn tag_without_value(name: &str) -> Vec<String> {
        vec![name.to_string()]
    }

    /// The worked example from `docs/buds/11.md`.
    ///
    /// The spec renders only three tags (`t`, `expiration`, `x`), but the `id`
    /// it states (and the accompanying `sig`) only reproduce when a fourth
    /// `server` tag is appended. The tag order is the intended
    /// `[t, expiration, x, server]`; see `docs/buds/KNOWN-ISSUES.md`.
    fn bud_event() -> NostrEvent {
        NostrEvent {
            id: BUD_EVENT_ID.into(),
            pubkey: BUD_PUBKEY.into(),
            created_at: 1772019044,
            kind: 24242,
            tags: vec![
                tag("t", "upload"),
                tag("expiration", "1708858680"),
                tag("x", X_HEX),
                tag("server", HOST),
            ],
            content: String::new(),
            sig: BUD_SIG.into(),
        }
    }

    fn token(event: NostrEvent) -> AuthToken {
        AuthToken { event }
    }

    /// A BUD-11-shaped event whose `id` and `sig` are self-consistent. The
    /// deterministic secret key `1` derives the x-only pubkey equal to the
    /// secp256k1 generator x coordinate, i.e. `79be667e...f81798`.
    fn signed_event(
        kind: u64,
        created_at: i64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> NostrEvent {
        let mut seckey = [0u8; 32];
        seckey[31] = 1;
        let keypair = Keypair::from_secret_bytes(seckey).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: xonly.to_string(),
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: String::new(),
        };
        event.id = event_id(&event).unwrap();
        let digest: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        event.sig = hex::encode(keypair.sign_schnorr_no_aux_rand(&digest).to_byte_array());
        event
    }

    fn upload_tags() -> Vec<Vec<String>> {
        vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", HOST),
        ]
    }

    /// Builds an event whose `id` matches its (possibly malformed) `pubkey`,
    /// so signature verification reaches the pubkey decode step.
    fn event_with_raw_pubkey(pubkey: &str) -> NostrEvent {
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: pubkey.to_string(),
            created_at: NOW - 100,
            kind: 24242,
            tags: upload_tags(),
            content: "Upload Blob".to_string(),
            sig: "00".repeat(64),
        };
        event.id = event_id(&event).unwrap();
        event
    }

    fn upload_ctx(blob: &Sha256) -> VerifyContext<'_> {
        VerifyContext::new(Action::Upload, HOST, Some(blob), NOW)
    }

    // ---- event_id --------------------------------------------------------

    #[test]
    fn event_id_matches_bud11_worked_example() {
        assert_eq!(event_id(&bud_event()).unwrap(), BUD_EVENT_ID);
    }

    // ---- verify_signature ------------------------------------------------

    #[test]
    fn verify_signature_accepts_bud11_worked_example() {
        assert_eq!(verify_signature(&bud_event()), Ok(()));
    }

    #[test]
    fn verify_signature_rejects_content_change_with_bad_event_id() {
        let mut event = bud_event();
        event.content = "Upload Blob".to_string();
        assert_eq!(verify_signature(&event), Err(AuthError::BadEventId));
    }

    #[test]
    fn verify_signature_rejects_signature_over_a_different_digest() {
        let mut event = signed_event(24242, NOW - 100, upload_tags(), "Upload Blob");
        // A genuine signature by the same key, but over another event's id.
        let other = signed_event(24242, NOW - 100, upload_tags(), "Something else");
        event.sig = other.sig;
        assert_eq!(verify_signature(&event), Err(AuthError::BadSignature));
    }

    // ---- from_authorization_header ---------------------------------------

    #[test]
    fn from_authorization_header_decodes_corrected_token() {
        // The BUD-11 token with the upstream defects fixed: `pubkey` spelled
        // correctly, JSONC comments removed, and the `server` tag restored.
        const CORRECTED_JSON: &str = r#"{"id":"7a1735c3852cf3f374edae4b2af2ee18e750e6dec583e19c4795d3b179af6d17","kind":24242,"pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1772019044,"tags":[["t","upload"],["expiration","1708858680"],["x","b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553"],["server","cdn.example.com"]],"content":"","sig":"4b57c22b1797b109530ffe5d04cabac468b1a5942873a5141334ecbc77694fc968a1b941979ba13602fceb1dad8014ab6469c6ae9cef0b5668cc23ad1449e103"}"#;
        let header = format!("Nostr {}", URL_SAFE_NO_PAD.encode(CORRECTED_JSON));
        assert_eq!(
            AuthToken::from_authorization_header(&header).unwrap(),
            token(bud_event())
        );
    }

    #[test]
    fn from_authorization_header_rejects_upstream_jsonc_header() {
        // The literal header value from `docs/buds/11.md`: it decodes to JSONC
        // (a `//` comment) and misspells `pubkey`, so it is not valid JSON.
        const UPSTREAM: &str = "Nostr ewogICJpZCI6ICI3YTE3MzVjMzg1MmNmM2YzNzRlZGFlNGIyYWYyZWUxOGU3NTBlNmRlYzU4M2UxOWM0Nzk1ZDNiMTc5YWY2ZDE3IiwKICAia2luZCI6IDI0MjQyLAogICJwdWJrZXkiOiAiNzliZTY2N2VmOWRjYmJhYzU1YTA2Mjk1Y2U4NzBiMDcwMjliZmNkYjJkY2UyOGQ5NTlmMjgxNWIxNmY4MTc5OCIsCiAgImNyZWF0ZWRfYXQiOiAxNzcyMDE5MDQ0LAogICJ0YWdzIjogWwogICAgWyJ0IiwidXBsb2FkIl0sCiAgICBbImV4cGlyYXRpb24iLCIxNzA4ODU4NjgwIl0sCiAgICAvLyBBdXRob3JpemF0aW9uIHRva2VuIE1BWSBoYXZlIG11bHRpcGxlICJ4IiB0YWdzCiAgICBbIngiLCJiMTY3NDE5MWE4OGVjNWNkZDczM2U0MjQwYTgxODAzMTA1ZGM0MTJkNmM2NzA4ZDUzYWI5NGZjMjQ4ZjRmNTUzIl0sCiAgXSwKICAiY29udGVudCI6ICIiLAogICJzaWciOiAiNGI1N2MyMmIxNzk3YjEwOTUzMGZmZTVkMDRjYWJhYzQ2OGIxYTU5NDI4NzNhNTE0MTMzNGVjYmM3NzY5NGZjOTY4YTFiOTQxOTc5YmExMzYwMmZjZWIxZGFkODAxNGFiNjQ2OWM2YWU5Y2VmMGI1NjY4Y2MyM2FkMTQ0OWUxMDMiCn0";
        assert_eq!(
            AuthToken::from_authorization_header(UPSTREAM),
            Err(AuthError::BadJson)
        );
    }

    #[test]
    fn from_authorization_header_rejects_non_nostr_scheme() {
        assert_eq!(
            AuthToken::from_authorization_header("Bearer x"),
            Err(AuthError::BadScheme)
        );
    }

    #[test]
    fn from_authorization_header_accepts_scheme_case_insensitively() {
        // RFC 7235 section 2.1: the auth scheme name is case-insensitive.
        let json = serde_json::to_vec(&bud_event()).unwrap();
        let header = format!("nostr {}", URL_SAFE_NO_PAD.encode(json));
        assert_eq!(
            AuthToken::from_authorization_header(&header).unwrap(),
            token(bud_event())
        );
    }

    #[test]
    fn from_authorization_header_rejects_bad_base64() {
        assert_eq!(
            AuthToken::from_authorization_header("Nostr !!!"),
            Err(AuthError::BadBase64)
        );
    }

    #[test]
    fn from_authorization_header_rejects_non_json_payload() {
        let header = format!("Nostr {}", URL_SAFE_NO_PAD.encode("not json"));
        assert_eq!(
            AuthToken::from_authorization_header(&header),
            Err(AuthError::BadJson)
        );
    }

    // ---- verify: happy paths ---------------------------------------------

    #[test]
    fn verify_happy_path_returns_the_event_pubkey() {
        let event = signed_event(24242, NOW - 100, upload_tags(), "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)).unwrap().pubkey(),
            BUD_PUBKEY
        );
    }

    #[test]
    fn verify_without_server_tags_is_valid_on_any_host() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        let ctx = VerifyContext::new(Action::Upload, "somewhere.else", Some(&blob), NOW);
        assert_eq!(token(event).verify(ctx).unwrap().pubkey(), BUD_PUBKEY);
    }

    #[test]
    fn verify_matches_server_tag_case_insensitively() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", "CDN.Example.COM"),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)).unwrap().pubkey(),
            BUD_PUBKEY
        );
    }

    #[test]
    fn verify_get_without_required_x_is_ok() {
        // `GET /<sha256>` has an optional `x` tag, so a token without one is fine.
        let tags = vec![
            tag("t", "get"),
            tag("expiration", &(NOW + 3600).to_string()),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Get blob");
        let ctx = VerifyContext::new(Action::Get, HOST, None, NOW);
        assert_eq!(token(event).verify(ctx).unwrap().pubkey(), BUD_PUBKEY);
    }

    // ---- verify: one test per BUD-11 rule --------------------------------

    #[test]
    fn verify_rejects_wrong_kind() {
        let event = signed_event(1, NOW - 100, upload_tags(), "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::WrongKind)
        );
    }

    #[test]
    fn verify_rejects_created_in_future() {
        let event = signed_event(24242, NOW + 1, upload_tags(), "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::CreatedInFuture)
        );
    }

    #[test]
    fn verify_rejects_missing_expiration() {
        let tags = vec![tag("t", "upload"), tag("x", X_HEX), tag("server", HOST)];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::MissingExpiration)
        );
    }

    #[test]
    fn verify_rejects_expired_token() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &NOW.to_string()),
            tag("x", X_HEX),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::Expired)
        );
    }

    #[test]
    fn verify_rejects_wrong_verb() {
        let tags = vec![
            tag("t", "delete"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Delete blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::WrongVerb)
        );
    }

    #[test]
    fn verify_rejects_server_mismatch() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", "other.example.com"),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::ServerMismatch)
        );
    }

    #[test]
    fn verify_rejects_missing_x_tag() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::MissingXTag)
        );
    }

    #[test]
    fn verify_rejects_x_tag_mismatch() {
        let other = "00".repeat(32);
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", &other),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::XTagMismatch)
        );
    }

    // ---- verify: signature is checked first ------------------------------

    #[test]
    fn verify_rejects_tampered_declared_id() {
        let mut event = bud_event();
        event.content = "Upload Blob".to_string();
        let blob = Sha256::parse(X_HEX).unwrap();
        let ctx = VerifyContext::new(Action::Upload, HOST, Some(&blob), NOW);
        assert_eq!(token(event).verify(ctx), Err(AuthError::BadEventId));
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let mut event = signed_event(24242, NOW - 100, upload_tags(), "Upload Blob");
        let other = signed_event(24242, NOW - 100, upload_tags(), "Something else");
        event.sig = other.sig;
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::BadSignature)
        );
    }

    // ---- verify: BUD-11 rule 5 (server) scoping --------------------------

    #[test]
    fn verify_rejects_valueless_server_tag() {
        // BUD-11 rule 5 keys on tag *presence*: `["server"]` carries no host,
        // so it cannot match and must not fall through as a global token.
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag_without_value("server"),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::ServerMismatch)
        );
    }

    #[test]
    fn verify_accepts_one_of_several_server_tags() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", "other.example.com"),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)).unwrap().pubkey(),
            BUD_PUBKEY
        );
    }

    #[test]
    fn verify_server_tag_must_match_whole_host() {
        // `example.com` is a mere suffix of `cdn.example.com`; scoping must not
        // be fooled by a substring match.
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
            tag("server", "example.com"),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::ServerMismatch)
        );
    }

    // ---- verify: `x` tags on endpoints where they are optional -----------

    #[test]
    fn verify_get_rejects_x_tag_mismatch() {
        // BUD-11: on GET/HEAD `x` is optional, but when present it must name
        // the requested blob.
        let other = "11".repeat(32);
        let tags = vec![
            tag("t", "get"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", &other),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Get blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        let ctx = VerifyContext::new(Action::Get, HOST, Some(&blob), NOW);
        assert_eq!(token(event).verify(ctx), Err(AuthError::XTagMismatch));
    }

    #[test]
    fn verify_get_accepts_matching_x_tag() {
        let tags = vec![
            tag("t", "get"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Get blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        let ctx = VerifyContext::new(Action::Get, HOST, Some(&blob), NOW);
        assert_eq!(token(event).verify(ctx).unwrap().pubkey(), BUD_PUBKEY);
    }

    #[test]
    fn verify_accepts_one_of_several_x_tags() {
        let other = "22".repeat(32);
        let tags = vec![
            tag("t", "get"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", &other),
            tag("x", X_HEX),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Get blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        let ctx = VerifyContext::new(Action::Get, HOST, Some(&blob), NOW);
        assert_eq!(token(event).verify(ctx).unwrap().pubkey(), BUD_PUBKEY);
    }

    #[test]
    fn verify_missing_x_without_blob_is_missing_x_tag() {
        // `require_x` with no blob to match is always MissingXTag.
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", &(NOW + 3600).to_string()),
            tag("x", X_HEX),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let ctx = VerifyContext::new(Action::Upload, HOST, None, NOW);
        assert_eq!(token(event).verify(ctx), Err(AuthError::MissingXTag));
    }

    // ---- endpoint table is encoded in the type ---------------------------

    #[test]
    fn action_requires_x_truth_table() {
        assert!(Action::Upload.requires_x());
        assert!(Action::Delete.requires_x());
        assert!(Action::Media.requires_x());
        assert!(!Action::Get.requires_x());
        assert!(!Action::List.requires_x());
    }

    #[test]
    fn verify_context_new_derives_require_x_from_action() {
        let blob = Sha256::parse(X_HEX).unwrap();
        assert!(VerifyContext::new(Action::Upload, HOST, Some(&blob), NOW).require_x());
        assert!(!VerifyContext::new(Action::Get, HOST, Some(&blob), NOW).require_x());
    }

    // ---- verify: malformed signature material ----------------------------

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let mut event = signed_event(24242, NOW - 100, upload_tags(), "Upload Blob");
        event.sig = "ab".to_string();
        assert_eq!(verify_signature(&event), Err(AuthError::BadSignature));
    }

    #[test]
    fn verify_rejects_non_hex_signature() {
        let mut event = signed_event(24242, NOW - 100, upload_tags(), "Upload Blob");
        event.sig = "zz".repeat(32);
        assert_eq!(verify_signature(&event), Err(AuthError::BadSignature));
    }

    #[test]
    fn verify_rejects_wrong_length_pubkey() {
        let event = event_with_raw_pubkey("ab");
        assert_eq!(verify_signature(&event), Err(AuthError::BadSignature));
    }

    #[test]
    fn verify_rejects_non_hex_pubkey() {
        let event = event_with_raw_pubkey(&"zz".repeat(32));
        assert_eq!(verify_signature(&event), Err(AuthError::BadSignature));
    }

    #[test]
    fn verify_rejects_non_numeric_expiration() {
        let tags = vec![
            tag("t", "upload"),
            tag("expiration", "soon"),
            tag("x", X_HEX),
            tag("server", HOST),
        ];
        let event = signed_event(24242, NOW - 100, tags, "Upload Blob");
        let blob = Sha256::parse(X_HEX).unwrap();
        assert_eq!(
            token(event).verify(upload_ctx(&blob)),
            Err(AuthError::Expired)
        );
    }

    // ---- Action verb parsing ---------------------------------------------

    #[test]
    fn action_verb_round_trips_and_rejects_garbage() {
        for action in [
            Action::Get,
            Action::Upload,
            Action::List,
            Action::Delete,
            Action::Media,
        ] {
            assert_eq!(Action::from_verb(action.verb()), Some(action));
        }
        assert_eq!(Action::from_verb("garbage"), None);
    }
}
