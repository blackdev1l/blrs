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
pub use state::{AppState, SystemClock};

use std::sync::Arc;

use blossom_store::{FsBlobStore, StoreConfig};
use tracing_subscriber::EnvFilter;

/// Boots the server from the environment.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let store = FsBlobStore::open(StoreConfig {
        data_dir: config.data_dir.clone(),
        max_blob_size: config.max_blob_size,
        max_total_bytes: config.max_total_bytes,
    })
    .await?;

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let bound = listener.local_addr()?;
    tracing::info!(address = %bound, "blrs server listening");

    let state = AppState::new(Arc::new(store), Arc::new(config), Arc::new(SystemClock));
    axum::serve(listener, router(state)).await?;
    Ok(())
}
