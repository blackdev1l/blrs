use thiserror::Error;

/// Errors from the blob store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The body exceeded the configured maximum blob size.
    #[error("blob exceeds the configured maximum size")]
    TooLarge,
    /// The streamed body did not hash to the expected sha256 (BUD-02 `409`).
    #[error("body hash does not match the expected sha256")]
    HashMismatch,
    /// The metadata index could not be read or written.
    #[error("index error: {0}")]
    Index(#[from] rusqlite::Error),
    /// A blob file was missing or unreadable.
    #[error("stored blob is missing or corrupt: {0}")]
    Corrupt(String),
    /// Underlying filesystem failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl StoreError {
    /// The value for the `X-Reason` response header (BUD-01).
    pub fn reason(&self) -> &'static str {
        match self {
            StoreError::TooLarge => "Blob exceeds the maximum allowed size",
            StoreError::HashMismatch => "Body hash does not match the expected sha256",
            StoreError::Index(_) | StoreError::Corrupt(_) | StoreError::Io(_) => {
                "Storage backend error"
            }
        }
    }
}
