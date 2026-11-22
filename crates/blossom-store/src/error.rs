use thiserror::Error;

/// Errors from the blob store.
///
/// `#[non_exhaustive]`: new variants can appear as the store grows, so a
/// cross-crate matcher (the HTTP error mapping) must include a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The request exceeded a configured maximum: a blob body larger than
    /// `StoreConfig::max_blob_size`, or a report carrying more hashes than the
    /// store accepts.
    #[error("request exceeds the configured maximum size")]
    TooLarge,
    /// The streamed body did not hash to the expected sha256 (BUD-02 `409`).
    #[error("body hash does not match the expected sha256")]
    HashMismatch,
    /// The metadata index could not be read or written.
    #[error("index error: {0}")]
    Index(#[from] rusqlite::Error),
    /// A stored blob file was missing or unreadable.
    #[error("stored blob is missing or corrupt: {0}")]
    Corrupt(String),
    /// The filesystem failed on the write side of an upload.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Reading the request body failed, typically because the client aborted
    /// the upload. Kept distinct from [`StoreError::Io`] so an abandoned upload
    /// is not reported as a storage outage.
    #[error("error reading request body: {0}")]
    BodyRead(std::io::Error),
    /// The hash is on the blocklist (BUD-09): re-upload and rewrite are refused.
    #[error("blob hash is blocked")]
    Blocked,
    /// Storing the blob would push the total disk budget over its limit.
    #[error("total disk quota is exhausted")]
    QuotaExceeded,
    /// The index worker task failed (for example its thread panicked), so the
    /// query result is unknown. Distinct from [`StoreError::Corrupt`], which is
    /// about a blob file on disk.
    #[error("index worker failed: {0}")]
    IndexTask(String),
    /// A supplied owner is not a 64-character lowercase hex pubkey (BUD-12).
    #[error("owner must be 64-character lowercase hex")]
    InvalidOwner,
    /// A requested byte range does not lie inside the stored blob.
    #[error("requested range is outside the blob")]
    InvalidRange,
    /// A report arrived with no hashes to attach it to (BUD-09).
    #[error("report must reference at least one hash")]
    EmptyReport,
    /// A report's reporter is not a 64-character lowercase hex pubkey (BUD-09).
    #[error("reporter must be 64-character lowercase hex")]
    InvalidReporter,
}

impl StoreError {
    /// The value for the `X-Reason` response header (BUD-01).
    pub fn reason(&self) -> &'static str {
        match self {
            StoreError::TooLarge => "Request exceeds the maximum allowed size",
            StoreError::HashMismatch => "Body hash does not match the expected sha256",
            StoreError::Blocked => "Blob is blocked by server policy",
            StoreError::QuotaExceeded => "Total disk quota is exhausted",
            StoreError::InvalidOwner => "Owner must be 64-character lowercase hex",
            StoreError::InvalidRange => "Requested range is outside the blob",
            StoreError::EmptyReport => "Report must reference at least one hash",
            StoreError::InvalidReporter => "Reporter must be 64-character lowercase hex",
            StoreError::BodyRead(_) => "Could not read the request body",
            StoreError::Index(_)
            | StoreError::IndexTask(_)
            | StoreError::Corrupt(_)
            | StoreError::Io(_) => "Storage backend error",
        }
    }
}
