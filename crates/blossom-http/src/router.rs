use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, RANGE};
use axum::http::{HeaderValue, Method};
use axum::routing::{get, on, MethodFilter};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::handlers;
use crate::state::AppState;

/// Builds the BUD route table.
///
/// Static segments (`/upload`, `/mirror`, `/media`, `/report`, `/list/...`)
/// take precedence over the `/{name}` blob route, so `PUT /upload` can never be
/// mistaken for a blob write.
pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        // BUD-01 requires `*` on every response.
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            RANGE,
            axum::http::HeaderName::from_static("x-sha-256"),
            axum::http::HeaderName::from_static("x-content-type"),
            axum::http::HeaderName::from_static("x-content-length"),
        ])
        .max_age(std::time::Duration::from_secs(86_400));

    Router::new()
        .route("/", get(handlers::get_index))
        .route(
            "/upload",
            on(MethodFilter::PUT, handlers::put_upload)
                .on(MethodFilter::HEAD, handlers::head_upload),
        )
        .route("/mirror", on(MethodFilter::PUT, handlers::put_mirror))
        .route(
            "/media",
            on(MethodFilter::PUT, handlers::put_media).on(MethodFilter::HEAD, handlers::head_media),
        )
        .route("/report", on(MethodFilter::PUT, handlers::put_report))
        .route("/list/{pubkey}", get(handlers::get_list))
        .route(
            "/{name}",
            on(MethodFilter::GET, handlers::get_blob)
                .on(MethodFilter::HEAD, handlers::head_blob)
                .on(MethodFilter::DELETE, handlers::delete_blob),
        )
        .layer(cors)
        // Mounted after CORS, so this is the outermost layer: its span then also
        // covers CORS preflights and fallback 404s. Both the span and the
        // response event default to DEBUG, which the default `info` filter
        // hides, so the levels are raised explicitly — otherwise a request
        // produces no line at all under the default configuration.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

/// The `Access-Control-Allow-Headers` value BUD-01 requires.
pub const CORS_ALLOW_HEADERS: HeaderValue = HeaderValue::from_static(
    "Authorization, Content-Type, Range, X-SHA-256, X-Content-Type, X-Content-Length",
);
