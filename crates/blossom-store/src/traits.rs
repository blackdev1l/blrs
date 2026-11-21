use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncRead;

use blossom_core::mime::MimeType;
use blossom_core::range::ByteRange;
use blossom_core::sha256::Sha256;

use crate::error::StoreError;

/// Metadata recorded for every stored blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub sha256: Sha256,
    pub size: u64,
    pub mime: MimeType,
    /// Unix timestamp of the first upload.
    pub uploaded: i64,
    /// Hex pubkey of the first uploader, when the server required authorization.
    pub owner: Option<String>,
}

/// How to treat an incoming body.
#[derive(Clone, Debug, Default)]
pub struct PutOptions {
    /// When set, the body must hash to exactly this value or the put fails with
    /// [`StoreError::HashMismatch`]. This is the `X-SHA-256` header.
    pub expected: Option<Sha256>,
    /// MIME type to record. When `None` the store sniffs the leading bytes and
    /// falls back to the extension, then `application/octet-stream`.
    pub mime: Option<MimeType>,
    /// Recorded as the blob's owner. Ignored when the blob already exists.
    pub owner: Option<String>,
    /// Client-supplied size, used for an early rejection before reading the body.
    pub declared_size: Option<u64>,
}

/// Whether a put stored a new blob or matched an existing one.
///
/// BUD-02 maps these to `201 Created` and `200 OK` respectively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created(BlobMeta),
    Existed(BlobMeta),
}

/// Result of a delete request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    /// The blob does not exist (BUD-12 `404`).
    NotFound,
    /// The requester is not the blob's owner (BUD-12 `403`).
    NotOwner,
}

/// Filters for `GET /list/<pubkey>` (BUD-12).
#[derive(Clone, Debug)]
pub struct ListQuery {
    pub pubkey: String,
    /// The `sha256` of the last blob on the previous page; excluded from results.
    pub cursor: Option<Sha256>,
    pub limit: u32,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

/// A stored blob report (BUD-09).
#[derive(Clone, Debug)]
pub struct ReportRecord {
    pub hashes: Vec<Sha256>,
    pub reporter: String,
    /// The NIP-56 report type for the first `x` tag.
    pub kind: String,
    pub content: String,
    pub created_at: i64,
}

/// An opened blob read, already positioned and length-limited.
pub struct BlobReader {
    pub meta: BlobMeta,
    /// The range being served, or `None` for the whole blob.
    pub range: Option<ByteRange>,
    pub stream: Box<dyn AsyncRead + Send + Unpin>,
}

/// Where the blob store keeps its data and how much it accepts.
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Root directory; blob files and the SQLite index live underneath.
    pub data_dir: PathBuf,
    /// Hard ceiling on a single blob, enforced while streaming.
    pub max_blob_size: u64,
}

/// The storage seam.
///
/// Every method is fallible and takes `&self`: implementations are shared
/// across request tasks behind an `Arc`.
#[async_trait]
pub trait BlobStore: Send + Sync + 'static {
    /// Streams `body` into the store, hashing as it goes.
    ///
    /// Never buffers the whole body in memory. If `opts.expected` is set and the
    /// computed hash differs, the temporary file is discarded and
    /// [`StoreError::HashMismatch`] is returned.
    async fn put(
        &self,
        body: Box<dyn AsyncRead + Send + Unpin>,
        opts: PutOptions,
    ) -> Result<PutOutcome, StoreError>;

    /// Looks up metadata without touching the blob file.
    async fn meta(&self, hash: &Sha256) -> Result<Option<BlobMeta>, StoreError>;

    /// Opens a blob for reading, optionally restricted to `range`.
    async fn read(
        &self,
        hash: &Sha256,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobReader>, StoreError>;

    /// Deletes a blob, enforcing ownership.
    async fn delete(&self, hash: &Sha256, requester: &str) -> Result<DeleteOutcome, StoreError>;

    /// Lists a pubkey's blobs, newest first, excluding the cursor (BUD-12).
    async fn list(&self, query: ListQuery) -> Result<Vec<BlobMeta>, StoreError>;

    /// Persists a NIP-56 report for operator review (BUD-09).
    async fn save_report(&self, report: ReportRecord) -> Result<(), StoreError>;

    /// Whether a hash has been blocked by moderation (BUD-09).
    async fn is_blocked(&self, hash: &Sha256) -> Result<bool, StoreError>;
}
