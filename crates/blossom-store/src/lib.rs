//! Content-addressed blob storage.
//!
//! Blobs live on disk under their sha256; metadata (size, MIME type, uploader,
//! upload time) lives in a SQLite index so `/list` and quota queries never walk
//! the blob tree. Bodies stream to a temporary file in bounded chunks and are
//! renamed into place only once the hash has been verified, so a partially
//! written blob is never visible under its final name.
//!
//! Writes are crash-aware. The temp file is removed by a guard on every
//! non-successful exit (including a cancelled request) and `open` sweeps
//! `tmp/*.part`; after the rename the shard directory is `fsync`ed before the
//! index row is inserted; and `open` re-indexes any orphan blob file, skipping
//! blocklisted hashes. A `DELETE` records the hash on the blocklist in the same
//! transaction as its row delete and unlinks the file afterwards, so a removed
//! blob cannot be rewritten (BUD-09) and a crash leaves an orphan file the next
//! `open` removes rather than a row pointing at nothing.
//!
//! `open` runs those recovery passes once per process: they assume the store is
//! the only writer to `data_dir`, so a second `open` on a live store can delete
//! an in-flight upload's temp file or re-index a blob whose row has not
//! committed yet.
//!
//! Durability across a power cut is best-effort, not absolute: an upload that
//! had not reached the row insert is recovered by the next `open`, but the most
//! recent write can still be lost.
//!
//! The [`BlobStore`] trait is the seam: the HTTP layer depends on it, and tests
//! exercise it against a real temporary directory rather than a mock.

#![forbid(unsafe_code)]

mod error;
mod fs;
mod index;
mod traits;

pub use error::StoreError;
pub use fs::FsBlobStore;
pub use traits::{
    BlobMeta, BlobReader, BlobStore, DeleteOutcome, ListQuery, PutOptions, PutOutcome,
    ReportRecord, StoreConfig,
};
