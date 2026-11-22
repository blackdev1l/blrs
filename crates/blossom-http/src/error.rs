use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use blossom_core::AuthError;
use blossom_store::StoreError;

/// An error response.
///
/// BUD-01 allows a human-readable `X-Reason` header on any `>= 400` response,
/// and clients are forbidden from parsing it for control flow. That makes it
/// the right place for every diagnostic this server emits.
#[derive(Debug)]
pub struct HttpError {
    pub status: StatusCode,
    pub reason: Option<String>,
}

impl HttpError {
    pub fn new(status: StatusCode, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: Some(reason.into()),
        }
    }

    pub fn bare(status: StatusCode) -> Self {
        Self {
            status,
            reason: None,
        }
    }

    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason)
    }

    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, reason)
    }

    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, reason)
    }

    pub fn conflict(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, reason)
    }

    pub fn payload_too_large(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, reason)
    }

    /// BUD-02 lists `429` for "a rate limit or quota".
    pub fn too_many_requests(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, reason)
    }

    pub fn unsupported_media_type(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, reason)
    }

    pub fn length_required(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::LENGTH_REQUIRED, reason)
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, reason)
    }

    pub fn bad_gateway(reason: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, reason)
    }

    /// Maps a BUD-11 validation failure onto `401 Unauthorized`.
    pub fn unauthorized(err: &AuthError) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, err.reason())
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut response = self.status.into_response();
        if let Some(reason) = self.reason {
            // The reason is operator-authored, but never trust that: strip
            // anything that would make it an invalid header value.
            let sanitized: String = reason
                .chars()
                .filter(|c| !c.is_control())
                .take(512)
                .collect();
            if let Ok(value) = HeaderValue::from_str(&sanitized) {
                response.headers_mut().insert("x-reason", value);
            }
        }
        response
    }
}

impl From<StoreError> for HttpError {
    fn from(err: StoreError) -> Self {
        let reason = err.reason();
        // `StoreError` is `#[non_exhaustive]`, so the wildcard is required and
        // a new variant can never break this build again.
        match err {
            StoreError::TooLarge => Self::payload_too_large(reason),
            StoreError::HashMismatch => Self::conflict(reason),
            StoreError::Blocked => Self::forbidden(reason),
            StoreError::QuotaExceeded => Self::too_many_requests(reason),
            StoreError::BodyRead(_) => Self::bad_request(reason),
            StoreError::IndexTask(_) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, reason),
            StoreError::InvalidOwner
            | StoreError::InvalidRange
            | StoreError::EmptyReport
            | StoreError::InvalidReporter => Self::bad_request(reason),
            StoreError::Index(_) | StoreError::Corrupt(_) | StoreError::Io(_) => {
                Self::unavailable(reason)
            }
            _ => Self::unavailable(reason),
        }
    }
}

/// The JSON error body used where a body is permitted.
pub fn json_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}
