use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::error::HttpError;
use crate::state::AppState;

/// `GET /<sha256>[.ext]` - BUD-01.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `HEAD /<sha256>[.ext]` - BUD-01. Metadata only; never opens the blob.
pub async fn head_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `PUT /upload` - BUD-02.
pub async fn put_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `HEAD /upload` - BUD-06 pre-flight.
pub async fn head_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `PUT /mirror` - BUD-04.
pub async fn put_mirror(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `PUT /media` - BUD-05.
pub async fn put_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `HEAD /media` - BUD-05 pre-flight.
pub async fn head_media(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `PUT /report` - BUD-09.
pub async fn put_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `GET /list/<pubkey>` - BUD-12.
pub async fn get_list(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
    Query(query): Query<ListParams>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `DELETE /<sha256>` - BUD-12.
pub async fn delete_blob(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// `GET /` - a small server banner.
pub async fn get_index(State(state): State<AppState>) -> Result<Response, HttpError> {
    todo!("lane C")
}

/// Cursor pagination parameters for `GET /list/<pubkey>` (BUD-12).
#[derive(Debug, serde::Deserialize)]
pub struct ListParams {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}
