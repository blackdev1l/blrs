//! Blossom HTTP server.
//!
//! The HTTP layer does three things and nothing else: map requests onto
//! [`blossom_store::BlobStore`], enforce BUD-11 authorization, and translate
//! domain errors into the status codes and headers the BUDs specify.
//!
//! Endpoint coverage:
//!
//! | Endpoint | BUD |
//! | --- | --- |
//! | `GET /<sha256>[.ext]` | 01 |
//! | `HEAD /<sha256>[.ext]` | 01 |
//! | `PUT /upload` | 02 |
//! | `HEAD /upload` | 06 |
//! | `PUT /mirror` | 04 |
//! | `PUT /media` | 05 |
//! | `HEAD /media` | 05 |
//! | `PUT /report` | 09 |
//! | `GET /list/<pubkey>` | 12 |
//! | `DELETE /<sha256>` | 12 |

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod handlers;
pub mod mirror;
pub mod router;
pub mod state;

pub use config::Config;
pub use error::HttpError;
pub use router::router;
pub use state::AppState;

/// Boots the server from the environment.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    todo!("lane C: tracing + config + FsBlobStore::open + bind + axum::serve")
}
