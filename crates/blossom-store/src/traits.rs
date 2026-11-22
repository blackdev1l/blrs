use std::path::PathBuf;

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
    ///
    /// It is also the BUD-02 fast path: when a blob with this hash is already
    /// stored and its file is intact, the store answers [`PutOutcome::Existed`]
    /// **without reading the body**. The caller is responsible for draining or
    /// closing the request body on that path.
    pub expected: Option<Sha256>,
    /// MIME type to record. When `None` the store sniffs the leading bytes,
    /// then falls back to `extension`, then `application/octet-stream`.
    pub mime: Option<MimeType>,
    /// Recorded as the blob's owner. Ignored when the blob already exists. Must
    /// be 64-character lowercase hex or the put fails with
    /// [`StoreError::InvalidOwner`].
    pub owner: Option<String>,
    /// Client-supplied size, used for an early rejection before reading the body.
    pub declared_size: Option<u64>,
    /// Filename or extension (`.pdf`, `pdf`, or `photo.png`) used for the MIME
    /// fallback when neither `mime` nor sniffing resolves a type. BUD-04's
    /// `/mirror` sets this from the fetched URL.
    pub extension: Option<String>,
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
    /// The `sha256` of the last blob on the previous page; excluded from
    /// results. The cursor is only honoured when it names a blob owned by
    /// `pubkey`; an unknown or other-owner cursor yields an empty page rather
    /// than silently repeating the first page.
    pub cursor: Option<Sha256>,
    /// Requested page size, clamped by the store to a small maximum.
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
    /// Total committed blob bytes allowed across all owners, or `None` for no
    /// limit. In-flight uploads are counted against the same budget until they
    /// finish or are abandoned.
    pub max_total_bytes: Option<u64>,
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
    /// [`StoreError::HashMismatch`] is returned. A cancelled or failed upload
    /// leaves no temporary file behind, and a hash on the blocklist is refused
    /// with [`StoreError::Blocked`] without storing the body.
    ///
    /// Re-uploading a hash that is already stored answers
    /// [`PutOutcome::Existed`] without rewriting the file, provided the file is
    /// present and exactly the row's `size` bytes. A file that is missing or the
    /// wrong length is healed by renaming the freshly verified bytes over it.
    /// Bit rot that leaves the length intact is not detected: the hash is not
    /// re-read on this path.
    async fn put(
        &self,
        body: Box<dyn AsyncRead + Send + Unpin>,
        opts: PutOptions,
    ) -> Result<PutOutcome, StoreError>;

    /// Looks up metadata without touching the blob file.
    async fn meta(&self, hash: &Sha256) -> Result<Option<BlobMeta>, StoreError>;

    /// Opens a blob for reading, optionally restricted to `range`.
    ///
    /// The blob file's length is verified against the row's `size` before any
    /// bytes are served, so the stream matches the advertised
    /// `Content-Length`: for a whole-blob read the file length must equal
    /// `size`, and for a range read the file must be long enough to cover the
    /// range. A short or grown file is reported as [`StoreError::Corrupt`]. A
    /// `range` that is not fully inside the blob is rejected with
    /// [`StoreError::InvalidRange`]. Returns `Ok(None)` when no row exists.
    /// When a row exists but its blob file does not, reading returns
    /// [`StoreError::Corrupt`]; `meta` still reports the row, and a later
    /// `put` of the same bytes heals it.
    async fn read(
        &self,
        hash: &Sha256,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobReader>, StoreError>;

    /// Deletes a blob, enforcing ownership.
    ///
    /// A blob whose `owner` is `None` may be deleted by any authenticated
    /// requester; a blob with an owner is only removable by that owner. The
    /// consequence is that blobs uploaded while the server ran with `--auth
    /// none` are ownerless and stay deletable by anyone forever.
    ///
    /// Only a delete authorised by an owner match records the hash on the
    /// blocklist, so it cannot be re-uploaded (BUD-09). Deleting an ownerless
    /// blob removes the row and the file but leaves the blocklist untouched,
    /// so the same bytes stay uploadable: otherwise any authenticated
    /// requester could block a hash server-wide with no moderation step.
    /// Blocking a hash that is reported but not stored locally has no path yet.
    async fn delete(&self, hash: &Sha256, requester: &str) -> Result<DeleteOutcome, StoreError>;

    /// Lists a pubkey's blobs, newest first, excluding the cursor (BUD-12).
    async fn list(&self, query: ListQuery) -> Result<Vec<BlobMeta>, StoreError>;

    /// Persists a NIP-56 report for operator review (BUD-09).
    async fn save_report(&self, report: ReportRecord) -> Result<(), StoreError>;

    /// Whether a hash has been blocked by moderation (BUD-09).
    async fn is_blocked(&self, hash: &Sha256) -> Result<bool, StoreError>;

    /// Whether a new blob of `size` bytes would fit under the configured total
    /// disk budget. Advisory: the authoritative check happens at insert, and
    /// deduplication (a blob that already exists) never needs this check because
    /// it consumes no new space. `HEAD /upload` uses it to tell a client before
    /// it uploads (BUD-06). Returns `true` when no budget is configured.
    async fn has_quota_room(&self, size: u64) -> Result<bool, StoreError>;
}
