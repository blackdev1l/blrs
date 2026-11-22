use thiserror::Error;

/// Errors from pure domain parsing and validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// Not exactly 64 lowercase hex characters.
    #[error("invalid sha256: expected 64 lowercase hex characters")]
    InvalidHash,
}

/// Errors from BUD-11 authorization token validation.
///
/// Each variant maps to a human-readable `X-Reason` value (BUD-01) and is
/// surfaced to clients as `401 Unauthorized`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing Authorization header")]
    Missing,
    #[error("authorization scheme must be `Nostr`")]
    BadScheme,
    #[error("authorization token is not valid base64url")]
    BadBase64,
    #[error("authorization token is not a valid nostr event")]
    BadJson,
    #[error("authorization token kind must be 24242")]
    WrongKind,
    #[error("event id does not match the event contents")]
    BadEventId,
    #[error("event signature is invalid")]
    BadSignature,
    #[error(
        "created_at {created_at} is {}s ahead of server time {now}",
        .created_at - .now
    )]
    CreatedInFuture { created_at: i64, now: i64 },
    #[error("missing expiration tag")]
    MissingExpiration,
    #[error("authorization token has expired")]
    Expired,
    #[error("missing or mismatched `t` tag verb")]
    WrongVerb,
    #[error("token is scoped to a different server")]
    ServerMismatch,
    #[error("token is missing a required `x` tag")]
    MissingXTag,
    #[error("token `x` tag does not match the blob")]
    XTagMismatch,
}

impl AuthError {
    /// The value for the `X-Reason` response header (BUD-01).
    pub fn reason(&self) -> &'static str {
        match self {
            AuthError::Missing => "Missing authorization token",
            AuthError::BadScheme => "Authorization scheme must be `Nostr`",
            AuthError::BadBase64 => "Authorization token is not valid base64url",
            AuthError::BadJson => "Authorization token is not a valid nostr event",
            AuthError::WrongKind => "Authorization token kind must be 24242",
            AuthError::BadEventId => "Event id does not match the event contents",
            AuthError::BadSignature => "Event signature is invalid",
            AuthError::CreatedInFuture { .. } => "created_at is in the future",
            AuthError::MissingExpiration => "Missing expiration tag",
            AuthError::Expired => "Authorization token has expired",
            AuthError::WrongVerb => "Token `t` tag does not authorize this action",
            AuthError::ServerMismatch => "Token is scoped to a different server",
            AuthError::MissingXTag => "Token is missing a required `x` tag",
            AuthError::XTagMismatch => "Token `x` tag does not match the blob",
        }
    }
}
