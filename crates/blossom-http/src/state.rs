use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use blossom_store::BlobStore;

use crate::config::Config;

/// A source of unix time.
///
/// Injected so authorization expiry and `uploaded` timestamps are testable
/// without sleeping.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> i64;
}

/// The real clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn BlobStore>,
    pub config: Arc<Config>,
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    pub fn new(store: Arc<dyn BlobStore>, config: Arc<Config>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            config,
            clock,
        }
    }
}
