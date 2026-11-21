use async_trait::async_trait;
use tokio::io::AsyncRead;

use blossom_core::sha256::Sha256;

use crate::error::StoreError;
use crate::traits::{
    BlobMeta, BlobReader, BlobStore, DeleteOutcome, ListQuery, PutOptions, PutOutcome,
    ReportRecord, StoreConfig,
};

/// A filesystem blob store with a SQLite metadata index.
///
/// Layout under `data_dir`:
///
/// ```text
/// data_dir/
///   blobs/<aa>/<sha256>     sharded by the first hex byte
///   tmp/                    in-progress uploads, removed on failure
///   index.db                metadata, ownership, reports, blocklist
/// ```
pub struct FsBlobStore {
    // Lane B owns these fields.
    _config: StoreConfig,
}

impl FsBlobStore {
    /// Opens (creating if needed) a blob store rooted at `config.data_dir`.
    ///
    /// Creates the directory tree and applies the SQLite schema.
    pub async fn open(config: StoreConfig) -> Result<Self, StoreError> {
        todo!("lane B: create dirs + apply schema")
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(
        &self,
        _body: Box<dyn AsyncRead + Send + Unpin>,
        _opts: PutOptions,
    ) -> Result<PutOutcome, StoreError> {
        todo!("lane B: stream to tmp, hash, verify, atomic rename, index")
    }

    async fn meta(&self, _hash: &Sha256) -> Result<Option<BlobMeta>, StoreError> {
        todo!("lane B")
    }

    async fn read(
        &self,
        _hash: &Sha256,
        _range: Option<blossom_core::range::ByteRange>,
    ) -> Result<Option<BlobReader>, StoreError> {
        todo!("lane B")
    }

    async fn delete(&self, _hash: &Sha256, _requester: &str) -> Result<DeleteOutcome, StoreError> {
        todo!("lane B")
    }

    async fn list(&self, _query: ListQuery) -> Result<Vec<BlobMeta>, StoreError> {
        todo!("lane B")
    }

    async fn save_report(&self, _report: ReportRecord) -> Result<(), StoreError> {
        todo!("lane B")
    }

    async fn is_blocked(&self, _hash: &Sha256) -> Result<bool, StoreError> {
        todo!("lane B")
    }
}
