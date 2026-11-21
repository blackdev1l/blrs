//! Content-addressed blob storage.
//!
//! Blobs live on disk under their sha256; metadata (size, MIME type, uploader,
//! upload time) lives in a SQLite index so `/list` and quota queries never walk
//! the blob tree. Bodies stream to a temporary file and are renamed into place
//! only once the hash has been verified, so a partially written blob is never
//! visible under its final name.
//!
//! The [`BlobStore`] trait is the seam: the HTTP layer depends on it, and tests
//! exercise it against a real temporary directory rather than a mock.

#![forbid(unsafe_code)]

mod error;
mod fs;
mod traits;

pub use error::StoreError;
pub use fs::FsBlobStore;
pub use traits::{
    BlobMeta, BlobReader, BlobStore, DeleteOutcome, ListQuery, PutOptions, PutOutcome,
    ReportRecord, StoreConfig,
};
