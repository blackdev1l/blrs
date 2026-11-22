//! A filesystem blob store with a SQLite metadata index.
//!
//! Bodies stream to a uniquely named file under `tmp/` in bounded chunks and
//! are hashed as they arrive, so the whole body is never resident in memory.
//! The file is `fsync`ed, renamed into place, and the containing shard
//! directory is `fsync`ed before the metadata row that references it is
//! written. A guard removes the temp file on every non-successful exit,
//! including a cancelled request, and [`FsBlobStore::open`] sweeps `tmp/*.part`
//! left by a crash.
//!
//! Durability is best-effort, not absolute. A power cut can still lose the
//! most recent writes:
//!
//! - an upload that had not reached the shard-directory `fsync` leaves no blob;
//! - an upload that crashed after the rename but before the row insert leaves a
//!   blob file with no row, which `open` re-indexes (the filename is the hash,
//!   so the bytes are already valid);
//! - a delete commits its row delete and blocklist entry first and unlinks the
//!   file second, so a crash mid-delete leaves an orphan file whose hash is
//!   already blocked; `open` deletes that file rather than leaving a row
//!   pointing at a missing blob.
//!
//! `open` never resurrects a hash that is on the blocklist.

use std::io::{ErrorKind, Read, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use blossom_core::mime::MimeType;
use blossom_core::range::ByteRange;
use blossom_core::sha256::Sha256;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256 as Sha2};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::error::StoreError;
use crate::index::SCHEMA;
use crate::traits::{
    BlobMeta, BlobReader, BlobStore, DeleteOutcome, ListQuery, PutOptions, PutOutcome,
    ReportRecord, StoreConfig,
};

/// Bytes read per iteration while streaming an upload. Bounded on purpose: the
/// store target is a Raspberry Pi and bodies can be much larger than RAM.
const CHUNK: usize = 64 * 1024;

/// Leading bytes kept so an unsniffed MIME type can be guessed from the magic
/// bytes without buffering the body.
const SNIFF_LEN: usize = 512;

/// Suffix of in-progress upload files under `tmp/`, swept by [`FsBlobStore::open`].
const TMP_SUFFIX: &str = "part";

/// Number of buckets in the per-hash lock array. A byte of the hash selects
/// one, so unrelated blobs rarely contend.
const HASH_BUCKETS: usize = 256;

/// Largest number of hashes accepted in a single report. BUD-09 reports are
/// operator-facing; an unbounded list is an easy way to grow the table.
const MAX_REPORT_HASHES: usize = 32;

/// Largest `ListQuery::limit` the store honours, regardless of what a caller
/// asks for.
const MAX_LIST_LIMIT: u32 = 100;

/// A selected row from the `blobs` table, before validation.
type RawMeta = (String, i64, String, i64, Option<String>);

/// The state of a hash under the per-hash lock: blocked, indexed, or absent.
enum Probe {
    Blocked,
    Existing(BlobMeta),
    Absent,
}

/// The result of the authoritative, transactional admission in
/// [`Inner::insert_admitted`].
enum Admitted {
    /// The insert ran; `1` means the row was created, `0` that it already
    /// existed.
    Inserted(usize),
    Blocked,
    QuotaExceeded,
}

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
    inner: Arc<Inner>,
}

/// Shared, `Send + Sync` state.
///
/// `rusqlite::Connection` is `Send` but not `Sync`, so it lives behind a mutex
/// and every query runs inside `spawn_blocking`; the async runtime is never
/// blocked on SQLite and the lock is never held across an `.await`.
struct Inner {
    config: StoreConfig,
    conn: Mutex<Connection>,
    blobs_dir: PathBuf,
    tmp_dir: PathBuf,
    /// Monotonic suffix that makes concurrent temp files unique.
    tmp_seq: AtomicU64,
    /// Committed blob bytes. Seeded from the index in `open` and kept current
    /// by insert and delete, so the advisory quota checks are O(1).
    used: AtomicU64,
    /// Bytes reserved by uploads that are currently streaming, so concurrent
    /// uploads cannot overshoot the total budget.
    inflight: AtomicU64,
    /// Per-hash-bucket locks serializing `put` and `delete` for one hash.
    locks: Vec<tokio::sync::Mutex<()>>,
    /// Rows re-inserted by the reconciliation pass in `open`.
    reconciled: u64,
    /// Test-only rendezvous that interleaves a delete between streaming and the
    /// admission critical section. `None` in production.
    #[cfg(test)]
    put_gate: Mutex<Option<Arc<PutGate>>>,
}

impl Inner {
    /// The shard directory for a blob, `blobs/<aa>`.
    fn shard_dir(&self, hash: &Sha256) -> PathBuf {
        self.blobs_dir.join(&hash.to_hex()[..2])
    }

    /// The final path for a blob, `blobs/<aa>/<sha256>`.
    fn blob_path(&self, hash: &Sha256) -> PathBuf {
        let hex = hash.to_hex();
        self.shard_dir(hash).join(hex)
    }

    /// A fresh, never-before-used path under `tmp/`.
    fn new_tmp_path(&self) -> PathBuf {
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.tmp_dir
            .join(format!("{}-{seq}-{nanos}.part", std::process::id()))
    }

    fn lookup(&self, hash: &Sha256) -> Result<Option<BlobMeta>, StoreError> {
        let conn = self.lock();
        lookup_meta(&conn, hash)
    }

    /// Classifies `hash` against the blocklist and the index in one read, for a
    /// single consistent snapshot the caller can act on.
    fn probe(&self, hash: &Sha256) -> Result<Probe, StoreError> {
        let conn = self.lock();
        if hash_blocked(&conn, hash)? {
            return Ok(Probe::Blocked);
        }
        match lookup_meta(&conn, hash)? {
            Some(meta) => Ok(Probe::Existing(meta)),
            None => Ok(Probe::Absent),
        }
    }

    /// The authoritative admission, run while the caller holds the per-hash
    /// lock and the blob file is already in place: refuses a blocked hash or an
    /// insert that would push the committed total over the budget, then inserts
    /// the row, all in one transaction. A refusal is rolled back by the caller
    /// removing the file.
    fn insert_admitted(&self, meta: &BlobMeta) -> Result<Admitted, StoreError> {
        let mut conn = self.lock();
        let limit = self.config.max_total_bytes;
        let tx = conn.transaction()?;
        if hash_blocked(&tx, &meta.sha256)? {
            return Ok(Admitted::Blocked);
        }
        if let Some(limit) = limit {
            let total: i64 =
                tx.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |row| {
                    row.get(0)
                })?;
            let total = u64::try_from(total).unwrap_or(0);
            if total.saturating_add(meta.size) > limit {
                return Ok(Admitted::QuotaExceeded);
            }
        }
        let changed = insert_meta(&tx, meta)?;
        tx.commit()?;
        Ok(Admitted::Inserted(changed))
    }

    /// Whether `additional` more committed bytes fit, using the live counters.
    /// This is the advisory check before a body and the streaming check that
    /// bounds `tmp/`.
    fn has_room(&self, additional: u64) -> bool {
        match self.config.max_total_bytes {
            None => true,
            Some(limit) => {
                self.used
                    .load(Ordering::Relaxed)
                    .saturating_add(self.inflight.load(Ordering::Relaxed))
                    .saturating_add(additional)
                    <= limit
            }
        }
    }

    /// The streaming form of [`Self::has_room`]: our own reservation already
    /// supplies this upload's floor in `inflight`, so only the bytes actually
    /// written are added on top of the other uploads' reservations. That stops
    /// a client that lies about `Content-Length` without double-counting a
    /// well-behaved one.
    fn within_budget(&self, own_reserved: u64, written: u64) -> bool {
        match self.config.max_total_bytes {
            None => true,
            Some(limit) => {
                let others = self
                    .inflight
                    .load(Ordering::Relaxed)
                    .saturating_sub(own_reserved);
                self.used
                    .load(Ordering::Relaxed)
                    .saturating_add(others)
                    .saturating_add(written)
                    <= limit
            }
        }
    }

    /// Test-only: pauses a put at the admission boundary until the test resumes
    /// it, so a delete can be interleaved deterministically.
    #[cfg(test)]
    async fn run_put_gate(&self) {
        let gate = match self.put_gate.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.resume.notified().await;
        }
    }

    /// Deletes the row and records the hash on the blocklist in one transaction.
    fn remove_and_block(&self, hash: &Sha256) -> Result<usize, StoreError> {
        let mut conn = self.lock();
        delete_meta_and_block(&mut conn, hash)
    }

    fn list(&self, query: &ListQuery) -> Result<Vec<BlobMeta>, StoreError> {
        let conn = self.lock();
        list_meta(&conn, query)
    }

    fn save(&self, report: &ReportRecord) -> Result<(), StoreError> {
        let mut conn = self.lock();
        insert_report(&mut conn, report)
    }

    fn blocked(&self, hash: &Sha256) -> Result<bool, StoreError> {
        let conn = self.lock();
        hash_blocked(&conn, hash)
    }

    /// Recovers the connection guard even if a previous holder panicked:
    /// one failed request must not take the store down for every later one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The `put`/`delete` lock for a hash.
    fn keyed_lock(&self, hash: &Sha256) -> &tokio::sync::Mutex<()> {
        &self.locks[usize::from(hash.as_bytes()[0])]
    }
}

impl FsBlobStore {
    /// Opens (creating if needed) a blob store rooted at `config.data_dir`.
    ///
    /// Creates the directory tree, applies the SQLite schema, sweeps leftover
    /// `tmp/*.part` files, and reconciles blob files that have no index row.
    pub async fn open(config: StoreConfig) -> Result<Self, StoreError> {
        let blobs_dir = config.data_dir.join("blobs");
        let tmp_dir = config.data_dir.join("tmp");
        tokio::fs::create_dir_all(&blobs_dir).await?;
        tokio::fs::create_dir_all(&tmp_dir).await?;

        let db_path = config.data_dir.join("index.db");
        let inner = blocking(move || -> Result<Inner, StoreError> {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch(SCHEMA)?;
            sweep_tmp(&tmp_dir);
            let reconciled = reconcile(&conn, &blobs_dir);
            // Recompute the committed total from the index so the counter
            // cannot drift across crashes, then keep it current in memory.
            let used = total_blob_bytes(&conn)?;
            Ok(Inner {
                config,
                conn: Mutex::new(conn),
                blobs_dir,
                tmp_dir,
                tmp_seq: AtomicU64::new(0),
                used: AtomicU64::new(used),
                inflight: AtomicU64::new(0),
                locks: (0..HASH_BUCKETS)
                    .map(|_| tokio::sync::Mutex::new(()))
                    .collect(),
                reconciled,
                #[cfg(test)]
                put_gate: Mutex::new(None),
            })
        })
        .await?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Number of orphan blob files the reconciliation pass in [`Self::open`]
    /// re-inserted into the index. Zero on a clean start.
    pub fn reconciled_count(&self) -> u64 {
        self.inner.reconciled
    }

    /// The shared implementation of [`BlobStore::put`] with an explicit upload
    /// time, so tests can place blobs at chosen points on the timeline.
    async fn put_with_time(
        &self,
        mut body: Box<dyn AsyncRead + Send + Unpin>,
        opts: PutOptions,
        uploaded: i64,
    ) -> Result<PutOutcome, StoreError> {
        let PutOptions {
            expected,
            mime,
            owner,
            declared_size,
            extension,
        } = opts;
        let max = self.inner.config.max_blob_size;

        // An owner is a BUD-12 hex pubkey; reject anything else before storing,
        // so a bad value cannot later fail every delete and hide the blob.
        if let Some(owner) = owner.as_deref() {
            if Sha256::parse(owner).is_err() {
                return Err(StoreError::InvalidOwner);
            }
        }

        // BUD-02 lets `X-SHA-256` be used for policy before persisting. The
        // whole check runs under the per-hash lock, so a concurrent delete
        // cannot interleave between the blocklist/existence reads and the
        // `Existed` answer. It runs before the declared-size check, so
        // re-uploading a known blob answers `Existed` even if the client
        // over-declared its `Content-Length`, and before the quota check,
        // because deduplication consumes no new space.
        if let Some(expected) = expected {
            let lock = self.inner.keyed_lock(&expected);
            let _lock = lock.lock().await;
            let inner = Arc::clone(&self.inner);
            match blocking(move || inner.probe(&expected)).await? {
                Probe::Blocked => return Err(StoreError::Blocked),
                Probe::Existing(existing) => {
                    // A row whose file is missing is not really stored: fall
                    // through so the streaming path can heal it.
                    if tokio::fs::try_exists(self.inner.blob_path(&expected)).await? {
                        return Ok(PutOutcome::Existed(existing));
                    }
                }
                Probe::Absent => {}
            }
        }

        // A declared size over the single-blob limit never needs the body.
        if let Some(declared) = declared_size {
            if declared > max {
                return Err(StoreError::TooLarge);
            }
            // Advisory early refusal: the cheapest place to reject a put that
            // cannot fit, before any of the body is read.
            if !self.inner.has_room(declared) {
                return Err(StoreError::QuotaExceeded);
            }
        }

        let tmp_path = self.inner.new_tmp_path();
        // From here on every exit path — an error or a cancelled future —
        // removes the temp file and releases the reserved budget; only a
        // successful rename disarms the file removal.
        let reserved = declared_size.unwrap_or(max);
        let mut guard = TempGuard::new(tmp_path.clone(), Arc::clone(&self.inner), reserved);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;

        let (hash, head, size) =
            match stream_body(&mut *body, &mut file, max, &self.inner, reserved).await {
                Ok(streamed) => streamed,
                Err(err) => {
                    drop(file);
                    return Err(err);
                }
            };

        if let Some(expected) = expected {
            if hash != expected {
                drop(file);
                return Err(StoreError::HashMismatch);
            }
        }

        // The hash is verified; only now make the bytes durable.
        let durable = async {
            file.flush().await?;
            file.sync_all().await
        }
        .await;
        drop(file);
        durable?;

        #[cfg(test)]
        self.inner.run_put_gate().await;

        // Serialize the rest per hash so a concurrent delete cannot remove the
        // file between the rename and the insert, or vice versa. Every check
        // below runs inside this critical section, so nothing can interleave.
        let lock = self.inner.keyed_lock(&hash);
        let _lock = lock.lock().await;

        let shard = self.inner.shard_dir(&hash);
        let dest = shard.join(hash.to_hex());

        // Re-uploading identical bytes: discard the temp copy instead of
        // rewriting the same bytes to the SD card and losing the original
        // mtime. A blocked hash is refused and a row whose file is gone is
        // healed instead.
        let inner = Arc::clone(&self.inner);
        match blocking(move || inner.probe(&hash)).await? {
            Probe::Blocked => return Err(StoreError::Blocked),
            Probe::Existing(existing) => {
                if tokio::fs::try_exists(&dest).await? {
                    return Ok(PutOutcome::Existed(existing));
                }
                tokio::fs::create_dir_all(&shard).await?;
                tokio::fs::rename(&tmp_path, &dest).await?;
                guard.disarm();
                sync_dir(&shard).await?;
                return Ok(PutOutcome::Existed(existing));
            }
            Probe::Absent => {}
        }

        let mime = mime
            .or_else(|| MimeType::sniff(&head))
            .or_else(|| extension.as_deref().and_then(MimeType::from_extension))
            .unwrap_or_else(MimeType::octet_stream);

        tokio::fs::create_dir_all(&shard).await?;
        tokio::fs::rename(&tmp_path, &dest).await?;
        guard.disarm();
        // fsync the shard directory so the rename is durable before the row
        // that references it is written.
        sync_dir(&shard).await?;

        let meta = BlobMeta {
            sha256: hash,
            size,
            mime,
            uploaded,
            owner,
        };

        // The authoritative admission re-checks the blocklist and the committed
        // total (against concurrent uploads of other hashes) and inserts the row
        // in one transaction. A refusal rolls the renamed file back.
        let inner = Arc::clone(&self.inner);
        let candidate = meta.clone();
        let admitted = match blocking(move || inner.insert_admitted(&candidate)).await {
            Ok(admitted) => admitted,
            Err(err) => {
                let _ = tokio::fs::remove_file(&dest).await;
                return Err(err);
            }
        };

        match admitted {
            Admitted::Inserted(1) => {
                self.inner.used.fetch_add(size, Ordering::Relaxed);
                Ok(PutOutcome::Created(meta))
            }
            Admitted::Inserted(_) => {
                // Another writer committed first; its owner and timestamp are
                // the canonical ones.
                match self.meta(&hash).await? {
                    Some(existing) => Ok(PutOutcome::Existed(existing)),
                    None => Err(StoreError::IndexTask(
                        "index row disappeared after insert".to_string(),
                    )),
                }
            }
            Admitted::Blocked => {
                let _ = tokio::fs::remove_file(&dest).await;
                Err(StoreError::Blocked)
            }
            Admitted::QuotaExceeded => {
                let _ = tokio::fs::remove_file(&dest).await;
                Err(StoreError::QuotaExceeded)
            }
        }
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(
        &self,
        body: Box<dyn AsyncRead + Send + Unpin>,
        opts: PutOptions,
    ) -> Result<PutOutcome, StoreError> {
        self.put_with_time(body, opts, now_unix()).await
    }

    async fn meta(&self, hash: &Sha256) -> Result<Option<BlobMeta>, StoreError> {
        let inner = Arc::clone(&self.inner);
        let hash = *hash;
        blocking(move || inner.lookup(&hash)).await
    }

    async fn read(
        &self,
        hash: &Sha256,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobReader>, StoreError> {
        let Some(meta) = self.meta(hash).await? else {
            return Ok(None);
        };

        // A range that is not inside the row's size would make the advertised
        // `Content-Length` disagree with the bytes on the wire.
        if let Some(range) = range.as_ref() {
            if range.start > range.end || range.end >= meta.size {
                return Err(StoreError::InvalidRange);
            }
        }

        let path = self.inner.blob_path(hash);
        let mut file = match File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(StoreError::Corrupt(format!(
                    "indexed blob {hash} missing at {}",
                    path.display()
                )));
            }
            Err(err) => return Err(err.into()),
        };

        // Opening the file reads nothing: the returned stream stays lazy and is
        // bounded to the row's size, so a file that grew cannot over-send.
        let stream: Box<dyn AsyncRead + Send + Unpin> = match range {
            Some(range) => {
                file.seek(SeekFrom::Start(range.start)).await?;
                Box::new(file.take(range.len()))
            }
            None => Box::new(file.take(meta.size)),
        };

        Ok(Some(BlobReader {
            meta,
            range,
            stream,
        }))
    }

    async fn delete(&self, hash: &Sha256, requester: &str) -> Result<DeleteOutcome, StoreError> {
        // Hold the per-hash lock across the whole delete so a concurrent put
        // cannot land a file we are about to remove, and so this delete cannot
        // miss a blob that a concurrent put is right now committing.
        let lock = self.inner.keyed_lock(hash);
        let _lock = lock.lock().await;

        let Some(meta) = self.meta(hash).await? else {
            return Ok(DeleteOutcome::NotFound);
        };

        // An ownerless blob is one stored while the server ran without auth;
        // anyone may delete it. A blob with an owner is only removable by that
        // owner, and a refused delete leaves the blob untouched.
        if let Some(owner) = meta.owner.as_deref() {
            if owner != requester {
                return Ok(DeleteOutcome::NotOwner);
            }
        }

        // BUD-09/12: commit the row delete and the blocklist entry together
        // FIRST, so the hash is blocked before the file disappears. A crash
        // then leaves an orphan file whose hash is already blocked, which
        // `open` deletes; the inverse order could leave a row pointing at a
        // missing blob that nothing repairs.
        let inner = Arc::clone(&self.inner);
        let owned = *hash;
        let changed = blocking(move || inner.remove_and_block(&owned)).await?;
        if changed == 0 {
            return Ok(DeleteOutcome::NotFound);
        }
        // The row was counted when it was inserted (or seeded from the index),
        // so this cannot underflow.
        self.inner.used.fetch_sub(meta.size, Ordering::Relaxed);

        // Only now unlink the file, and fsync the shard so the removal is
        // durable. A missing file is fine: the row is already gone.
        match tokio::fs::remove_file(self.inner.blob_path(hash)).await {
            Ok(()) => sync_dir(&self.inner.shard_dir(hash)).await?,
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        Ok(DeleteOutcome::Deleted)
    }

    async fn list(&self, query: ListQuery) -> Result<Vec<BlobMeta>, StoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.list(&query)).await
    }

    async fn save_report(&self, report: ReportRecord) -> Result<(), StoreError> {
        if report.hashes.len() > MAX_REPORT_HASHES {
            return Err(StoreError::TooLarge);
        }
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.save(&report)).await
    }

    async fn is_blocked(&self, hash: &Sha256) -> Result<bool, StoreError> {
        let inner = Arc::clone(&self.inner);
        let hash = *hash;
        blocking(move || inner.blocked(&hash)).await
    }

    async fn has_quota_room(&self, size: u64) -> Result<bool, StoreError> {
        Ok(self.inner.has_room(size))
    }
}

/// Deletes an in-progress temp file unless it has been disarmed, and releases
/// the budget it reserved.
///
/// `put` arms this as soon as it has a temp path and disarms the file removal
/// only after the file has been renamed into place, so a cancelled upload, a
/// client abort, or any early return cannot leave `tmp/*.part` behind. The
/// reservation is released on every exit path, disarmed or not. `Drop` cannot
/// await, so the removal is a blocking `std::fs::remove_file`.
struct TempGuard {
    path: PathBuf,
    armed: bool,
    inner: Arc<Inner>,
    reserved: u64,
}

impl TempGuard {
    fn new(path: PathBuf, inner: Arc<Inner>, reserved: u64) -> Self {
        inner.inflight.fetch_add(reserved, Ordering::Relaxed);
        Self {
            path,
            armed: true,
            inner,
            reserved,
        }
    }

    /// Keeps the temp file, called once it has been renamed into place.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
        self.inner
            .inflight
            .fetch_sub(self.reserved, Ordering::Relaxed);
    }
}

/// Test-only rendezvous: a put notifies `reached` and waits on `resume`, so a
/// test can run a delete in the window between streaming and the admission
/// critical section.
#[cfg(test)]
#[derive(Default)]
struct PutGate {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

/// Runs a synchronous closure on the blocking pool.
///
/// The closure's own `Result` is returned unchanged. An `Err` from the join
/// itself means the blocking task failed to run or panicked, which is reported
/// as [`StoreError::IndexTask`].
async fn blocking<T, F>(f: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| StoreError::IndexTask(err.to_string()))?
}

/// Reads `body` to EOF in bounded chunks, hashing and writing as it goes,
/// aborting the moment the total budget would be exceeded. That streaming
/// check is what stops a client that lies about `Content-Length` and bounds
/// `tmp/` usage, not just the committed total.
async fn stream_body(
    body: &mut (dyn AsyncRead + Send + Unpin),
    file: &mut File,
    max: u64,
    inner: &Inner,
    reserved: u64,
) -> Result<(Sha256, Vec<u8>, u64), StoreError> {
    let mut hasher = Sha2::new();
    let mut head = Vec::with_capacity(SNIFF_LEN);
    let mut total: u64 = 0;
    let mut buf = vec![0u8; CHUNK];

    loop {
        // A failure here is the client's body, not the disk.
        let read = body.read(&mut buf).await.map_err(StoreError::BodyRead)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max {
            return Err(StoreError::TooLarge);
        }
        if !inner.within_budget(reserved, total) {
            return Err(StoreError::QuotaExceeded);
        }
        hasher.update(&buf[..read]);
        if head.len() < SNIFF_LEN {
            let keep = (SNIFF_LEN - head.len()).min(read);
            head.extend_from_slice(&buf[..keep]);
        }
        file.write_all(&buf[..read]).await?;
    }

    Ok((Sha256::from_bytes(hasher.finalize().into()), head, total))
}

/// Opens a directory and `fsync`s it, making a completed rename durable.
#[cfg(unix)]
async fn sync_dir(path: &Path) -> Result<(), StoreError> {
    let dir = File::open(path).await?;
    dir.sync_all().await?;
    Ok(())
}

/// No-op on Windows: `File::open` on a directory fails with `Access denied`,
/// so there is no directory handle to flush. It is not needed either — NTFS
/// journals metadata, so a completed rename is already durable without an
/// explicit directory flush.
#[cfg(not(unix))]
async fn sync_dir(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Removes leftover `tmp/*.part` files from a previous run that crashed before
/// its upload finished.
fn sweep_tmp(tmp_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(tmp_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some(TMP_SUFFIX) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Re-inserts an index row for every blob file that survived a crash before its
/// row was written. The filename is the blob's sha256, so the bytes are already
/// content-addressed and trustworthy; size comes from the file, the MIME type
/// from sniffing its head, and `uploaded` from the file mtime. A file whose
/// hash is blocklisted is deleted instead, so a removed blob is never
/// resurrected. Returns the number of rows inserted.
fn reconcile(conn: &Connection, blobs_dir: &Path) -> u64 {
    let Ok(shards) = std::fs::read_dir(blobs_dir) else {
        return 0;
    };
    let mut inserted = 0;
    for shard in shards.flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(shard.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(hash) = Sha256::parse(name) else {
                continue;
            };
            // Only the canonical path counts; anything else is not ours.
            if path != blobs_dir.join(&hash.to_hex()[..2]).join(name) {
                continue;
            }
            if hash_blocked(conn, &hash).unwrap_or(false) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if matches!(lookup_meta(conn, &hash), Ok(Some(_))) {
                continue;
            }
            let Some(meta) = meta_from_file(&path, &hash) else {
                continue;
            };
            if matches!(insert_meta(conn, &meta), Ok(1)) {
                inserted += 1;
            }
        }
    }
    inserted
}

/// Builds a row for an untracked blob file: size from the file, MIME from the
/// head, `uploaded` from the mtime, and no owner.
fn meta_from_file(path: &Path, hash: &Sha256) -> Option<BlobMeta> {
    let metadata = std::fs::metadata(path).ok()?;
    let uploaded = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut head = [0u8; SNIFF_LEN];
    let read = {
        let mut file = std::fs::File::open(path).ok()?;
        file.read(&mut head).ok()?
    };
    let mime = MimeType::sniff(&head[..read]).unwrap_or_else(MimeType::octet_stream);
    Some(BlobMeta {
        sha256: *hash,
        size: metadata.len(),
        mime,
        uploaded,
        owner: None,
    })
}

/// The current unix timestamp, or `0` if the clock predates the epoch.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn row_tuple(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMeta> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn tuple_to_meta(raw: RawMeta) -> Result<BlobMeta, StoreError> {
    let (hex, size, mime, uploaded, owner) = raw;
    let sha256 = Sha256::parse(&hex)
        .map_err(|err| StoreError::Corrupt(format!("index has invalid sha256 {hex:?}: {err}")))?;
    let size = u64::try_from(size)
        .map_err(|_| StoreError::Corrupt(format!("index has negative size {size} for {hex}")))?;
    Ok(BlobMeta {
        sha256,
        size,
        mime: MimeType::parse(&mime),
        uploaded,
        owner,
    })
}

fn lookup_meta(conn: &Connection, hash: &Sha256) -> Result<Option<BlobMeta>, StoreError> {
    let raw = conn
        .query_row(
            "SELECT sha256, size, mime, uploaded, owner FROM blobs WHERE sha256 = ?1",
            [hash.to_hex()],
            row_tuple,
        )
        .optional()?;
    raw.map(tuple_to_meta).transpose()
}

fn insert_meta(conn: &Connection, meta: &BlobMeta) -> Result<usize, StoreError> {
    let changed = conn.execute(
        "INSERT OR IGNORE INTO blobs (sha256, size, mime, uploaded, owner) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            meta.sha256.to_hex(),
            meta.size as i64,
            meta.mime.as_str(),
            meta.uploaded,
            meta.owner,
        ],
    )?;
    Ok(changed)
}

/// Deletes the blob's row and records its hash on the blocklist atomically.
fn delete_meta_and_block(conn: &mut Connection, hash: &Sha256) -> Result<usize, StoreError> {
    let tx = conn.transaction()?;
    let changed = tx.execute("DELETE FROM blobs WHERE sha256 = ?1", [hash.to_hex()])?;
    if changed == 0 {
        return Ok(0);
    }
    tx.execute(
        "INSERT OR IGNORE INTO blocklist (sha256, blocked_at) VALUES (?1, ?2)",
        rusqlite::params![hash.to_hex(), now_unix()],
    )?;
    tx.commit()?;
    Ok(changed)
}

/// The `uploaded` time of a blob, only when it belongs to `owner`.
fn cursor_uploaded(
    conn: &Connection,
    hash: &Sha256,
    owner: &str,
) -> Result<Option<i64>, StoreError> {
    let uploaded = conn
        .query_row(
            "SELECT uploaded FROM blobs WHERE sha256 = ?1 AND owner = ?2",
            rusqlite::params![hash.to_hex(), owner],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    Ok(uploaded)
}

fn list_meta(conn: &Connection, query: &ListQuery) -> Result<Vec<BlobMeta>, StoreError> {
    let owner = query.pubkey.clone();

    // A cursor that is not in the index, or belongs to another owner, cannot
    // anchor a page: return nothing rather than leaking another user's
    // timestamp or silently serving the first page again.
    let cursor_pos = match query.cursor {
        None => None,
        Some(hash) => match cursor_uploaded(conn, &hash, &owner)? {
            None => return Ok(Vec::new()),
            Some(uploaded) => Some((uploaded, hash)),
        },
    };

    let cursor_hex = cursor_pos.as_ref().map(|(_, hash)| hash.to_hex());
    let since = query.since;
    let until = query.until;
    let limit = i64::from(query.limit.min(MAX_LIST_LIMIT));

    let mut sql =
        String::from("SELECT sha256, size, mime, uploaded, owner FROM blobs WHERE owner = ?");
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&owner];
    if let Some(since) = since.as_ref() {
        sql.push_str(" AND uploaded >= ?");
        params.push(since);
    }
    if let Some(until) = until.as_ref() {
        sql.push_str(" AND uploaded <= ?");
        params.push(until);
    }
    if let Some((cursor_uploaded, _)) = cursor_pos.as_ref() {
        // Keyset pagination over the `(uploaded DESC, sha256 DESC)` ordering,
        // never OFFSET, so a concurrent insert cannot shift a later page.
        sql.push_str(" AND (uploaded < ? OR (uploaded = ? AND sha256 < ?))");
        params.push(cursor_uploaded);
        params.push(cursor_uploaded);
    }
    if let Some(cursor_hex) = cursor_hex.as_ref() {
        params.push(cursor_hex);
    }
    sql.push_str(" ORDER BY uploaded DESC, sha256 DESC LIMIT ?");
    params.push(&limit);

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(&params[..], row_tuple)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(tuple_to_meta(row?)?);
    }
    Ok(out)
}

fn insert_report(conn: &mut Connection, report: &ReportRecord) -> Result<(), StoreError> {
    // Reporting is not removal (BUD-09): a report is recorded for operator
    // review and does NOT block. The unique key plus `INSERT OR IGNORE` makes a
    // repeat report a no-op instead of growing the table without bound.
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO reports (sha256, reporter, kind, content, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for hash in &report.hashes {
            stmt.execute(rusqlite::params![
                hash.to_hex(),
                report.reporter,
                report.kind,
                report.content,
                report.created_at,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn hash_blocked(conn: &Connection, hash: &Sha256) -> Result<bool, StoreError> {
    let blocked = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocklist WHERE sha256 = ?1)",
        [hash.to_hex()],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(blocked)
}

/// The committed total of every indexed blob, used to seed the in-memory
/// counter so it cannot drift across a crash.
fn total_blob_bytes(conn: &Connection) -> Result<u64, StoreError> {
    let total: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |row| {
        row.get(0)
    })?;
    Ok(u64::try_from(total).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;
    use tokio::sync::{Barrier, Notify};

    use super::*;

    /// sha256("hello world"), a well-known digest used as a literal.
    const HELLO_WORLD_HASH: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    /// sha256("abc"), a second well-known digest.
    const ABC_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    async fn open_store(max_blob_size: u64) -> (FsBlobStore, tempfile::TempDir) {
        open_store_with(max_blob_size, None).await
    }

    async fn open_store_with(
        max_blob_size: u64,
        max_total_bytes: Option<u64>,
    ) -> (FsBlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            max_blob_size,
            max_total_bytes,
        };
        let store = FsBlobStore::open(config).await.unwrap();
        (store, dir)
    }

    fn body(bytes: &[u8]) -> Box<dyn AsyncRead + Send + Unpin> {
        Box::new(std::io::Cursor::new(bytes.to_vec()))
    }

    fn hash_of(hex: &str) -> Sha256 {
        Sha256::parse(hex).unwrap()
    }

    /// A stable per-file identity, so a test can prove a path still refers to
    /// the same file. Unix uses the inode. Windows cannot use a real file
    /// index — `MetadataExt::file_index()` is still unstable behind
    /// `windows_by_handle` — so it falls back to a size + last-write-time
    /// proxy. A rewrite inside the same timestamp tick could evade that proxy,
    /// which is acceptable here: the two puts are separated by real file I/O.
    #[cfg(unix)]
    fn file_identity(metadata: &std::fs::Metadata) -> (u64, Option<std::time::SystemTime>) {
        use std::os::unix::fs::MetadataExt;
        (metadata.ino(), None)
    }

    #[cfg(not(unix))]
    fn file_identity(metadata: &std::fs::Metadata) -> (u64, Option<std::time::SystemTime>) {
        (metadata.len(), metadata.modified().ok())
    }

    /// A 64-character lowercase-hex pubkey, the only owner shape accepted.
    fn pubkey(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// Number of files anywhere under `dir`, used to prove nothing was stored.
    fn count_files(dir: &Path) -> usize {
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    total += count_files(&path);
                } else {
                    total += 1;
                }
            }
        }
        total
    }

    async fn read_all(reader: BlobReader) -> Vec<u8> {
        let mut stream = reader.stream;
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    async fn put_at(store: &FsBlobStore, bytes: &[u8], owner: &str, uploaded: i64) -> BlobMeta {
        let outcome = store
            .put_with_time(
                body(bytes),
                PutOptions {
                    owner: Some(owner.to_string()),
                    ..Default::default()
                },
                uploaded,
            )
            .await
            .unwrap();
        match outcome {
            PutOutcome::Created(meta) | PutOutcome::Existed(meta) => meta,
        }
    }

    fn hashes(metas: &[BlobMeta]) -> Vec<Sha256> {
        metas.iter().map(|meta| meta.sha256).collect()
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7) & 0xff) as u8)
            .collect()
    }

    /// A reader that fails if anything tries to read it, proving a code path
    /// answered without consuming the body.
    struct FailReader;

    impl AsyncRead for FailReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("body must not be read")))
        }
    }

    /// A reader that serves bytes lazily from a counter and records how many it
    /// produced, so a test can prove the store does not read a whole body.
    struct CountingReader {
        remaining: u64,
        produced: Arc<AtomicU64>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let n = this.remaining.min(buf.remaining().min(CHUNK) as u64) as usize;
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            let chunk = vec![0x5a_u8; n];
            buf.put_slice(&chunk);
            this.remaining -= n as u64;
            this.produced.fetch_add(n as u64, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that yields some bytes and then fails, modelling a client that
    /// aborts partway through an upload.
    struct ErrorReader {
        produced: bool,
    }

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.produced {
                return Poll::Ready(Err(std::io::Error::other("client aborted")));
            }
            this.produced = true;
            buf.put_slice(b"partial body");
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that yields one chunk and then never finishes, so a put future
    /// can be abandoned mid-stream.
    struct HangReader {
        started: Arc<Notify>,
        sent: bool,
    }

    impl AsyncRead for HangReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.sent {
                return Poll::Pending;
            }
            this.sent = true;
            buf.put_slice(&[0x7f_u8; 4096]);
            this.started.notify_one();
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn put_small_blob_creates_and_stores_it() {
        let (store, dir) = open_store(1024).await;
        let owner = pubkey(0xab);

        let outcome = store
            .put(
                body(b"hello world"),
                PutOptions {
                    owner: Some(owner.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let PutOutcome::Created(meta) = outcome else {
            panic!("expected Created, got {outcome:?}");
        };
        assert_eq!(meta.sha256, hash_of(HELLO_WORLD_HASH));
        assert_eq!(meta.size, 11);
        assert_eq!(meta.mime.as_str(), MimeType::OCTET_STREAM);
        assert!(meta.uploaded > 0);
        assert_eq!(meta.owner.as_deref(), Some(owner.as_str()));

        let path = store.inner.blob_path(&meta.sha256);
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
        assert_eq!(store.meta(&meta.sha256).await.unwrap(), Some(meta));

        assert_eq!(count_files(&dir.path().join("blobs")), 1);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn put_honours_explicit_and_sniffed_mime() {
        let (store, _dir) = open_store(1024).await;

        let sniffed = store
            .put(body(b"\x89PNG\r\n\x1a\nrest"), PutOptions::default())
            .await
            .unwrap();
        let PutOutcome::Created(sniffed) = sniffed else {
            panic!("expected Created");
        };
        assert_eq!(sniffed.mime.as_str(), "image/png");

        let explicit = store
            .put(
                body(b"plain old text"),
                PutOptions {
                    mime: Some(MimeType::parse("text/plain")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let PutOutcome::Created(explicit) = explicit else {
            panic!("expected Created");
        };
        assert_eq!(explicit.mime.as_str(), "text/plain");
    }

    #[tokio::test]
    async fn mime_falls_back_from_sniff_to_extension_to_octet_stream() {
        let (store, _dir) = open_store(1024).await;

        // `mime` wins over everything, including a sniffable body.
        let explicit = store
            .put(
                body(b"\x89PNG\r\n\x1a\nrest"),
                PutOptions {
                    mime: Some(MimeType::parse("text/plain")),
                    extension: Some("pdf".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let PutOutcome::Created(explicit) = explicit else {
            panic!("expected Created");
        };
        assert_eq!(explicit.mime.as_str(), "text/plain");

        // Sniffing wins over the extension.
        let sniffed = store
            .put(
                body(b"\x89PNG\r\n\x1a\nrest-two"),
                PutOptions {
                    extension: Some("txt".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let PutOutcome::Created(sniffed) = sniffed else {
            panic!("expected Created");
        };
        assert_eq!(sniffed.mime.as_str(), "image/png");

        // No magic bytes: the extension resolves the type.
        let extension = store
            .put(
                body(b"just some bytes with no signature"),
                PutOptions {
                    extension: Some("photo.pdf".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let PutOutcome::Created(extension) = extension else {
            panic!("expected Created");
        };
        assert_eq!(extension.mime.as_str(), "application/pdf");

        // Nothing resolves it: the octet-stream fallback.
        let fallback = store
            .put(
                body(b"just some bytes with no signature two"),
                PutOptions::default(),
            )
            .await
            .unwrap();
        let PutOutcome::Created(fallback) = fallback else {
            panic!("expected Created");
        };
        assert_eq!(fallback.mime.as_str(), MimeType::OCTET_STREAM);
    }

    #[tokio::test]
    async fn reupload_returns_existed_with_first_owner_and_time() {
        let (store, _dir) = open_store(1024).await;
        let first_owner = pubkey(0x11);
        let second_owner = pubkey(0x22);

        let first = store
            .put_with_time(
                body(b"hello world"),
                PutOptions {
                    owner: Some(first_owner.clone()),
                    ..Default::default()
                },
                1_000,
            )
            .await
            .unwrap();
        let PutOutcome::Created(first_meta) = first else {
            panic!("expected Created");
        };

        let second = store
            .put_with_time(
                body(b"hello world"),
                PutOptions {
                    owner: Some(second_owner),
                    ..Default::default()
                },
                2_000,
            )
            .await
            .unwrap();
        let PutOutcome::Existed(second_meta) = second else {
            panic!("expected Existed");
        };

        assert_eq!(second_meta, first_meta);
        assert_eq!(second_meta.uploaded, 1_000);
        assert_eq!(second_meta.owner.as_deref(), Some(first_owner.as_str()));
    }

    #[tokio::test]
    async fn reupload_without_fast_path_does_not_rewrite_the_file() {
        let (store, dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        let path = store.inner.blob_path(&hash);
        let identity_before = file_identity(&std::fs::metadata(&path).unwrap());

        // No X-SHA-256: the body is streamed and hashed, but the identical
        // bytes must not be renamed over the existing file.
        let outcome = store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        assert!(matches!(outcome, PutOutcome::Existed(_)));
        assert_eq!(
            file_identity(&std::fs::metadata(&path).unwrap()),
            identity_before,
            "a re-upload must not replace the blob file"
        );
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn expected_matching_hash_is_stored() {
        let (store, _dir) = open_store(1024).await;
        let outcome = store
            .put(
                body(b"hello world"),
                PutOptions {
                    expected: Some(hash_of(HELLO_WORLD_HASH)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Created(_)));
        assert!(store
            .meta(&hash_of(HELLO_WORLD_HASH))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn expected_existing_hash_short_circuits_the_body() {
        let (store, _dir) = open_store(1024).await;
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // The body reader errors if read; a fast-path hit must never touch it.
        let outcome = store
            .put(
                Box::new(FailReader),
                PutOptions {
                    expected: Some(hash_of(HELLO_WORLD_HASH)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Existed(_)));
    }

    #[tokio::test]
    async fn expected_hash_mismatch_leaves_nothing_behind() {
        let (store, dir) = open_store(1024).await;

        let err = store
            .put(
                body(b"hello world"),
                PutOptions {
                    expected: Some(hash_of(ABC_HASH)),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::HashMismatch));
        assert!(store
            .meta(&hash_of(HELLO_WORLD_HASH))
            .await
            .unwrap()
            .is_none());
        assert!(store.meta(&hash_of(ABC_HASH)).await.unwrap().is_none());
        assert_eq!(count_files(&dir.path().join("blobs")), 0);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn oversized_body_is_too_large_and_nothing_is_stored() {
        let (store, dir) = open_store(16).await;

        let err = store
            .put(body(&[7u8; 100]), PutOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::TooLarge));
        assert_eq!(count_files(&dir.path().join("blobs")), 0);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn oversized_stream_stops_after_one_chunk() {
        let (store, dir) = open_store(16).await;
        let produced = Arc::new(AtomicU64::new(0));
        let reader = CountingReader {
            remaining: 1 << 40,
            produced: Arc::clone(&produced),
        };

        let err = store
            .put(Box::new(reader), PutOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::TooLarge));
        let served = produced.load(Ordering::Relaxed);
        assert!(
            served <= 16 + CHUNK as u64,
            "the store read {served} bytes of a body it had already rejected"
        );
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn declared_size_over_limit_is_rejected_without_reading() {
        let (store, dir) = open_store(16).await;

        let err = store
            .put(
                Box::new(FailReader),
                PutOptions {
                    declared_size: Some(1_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::TooLarge));
        assert_eq!(count_files(&dir.path().join("blobs")), 0);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn declared_size_over_limit_is_ignored_for_an_existing_blob() {
        let (store, _dir) = open_store(16).await;
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // BUD-02: the X-SHA-256 fast path answers 200 before size policy.
        let outcome = store
            .put(
                Box::new(FailReader),
                PutOptions {
                    expected: Some(hash_of(HELLO_WORLD_HASH)),
                    declared_size: Some(1_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Existed(_)));
    }

    #[tokio::test]
    async fn cancelled_upload_leaves_no_temp_file() {
        let (store, dir) = open_store(1024 * 1024).await;
        let tmp = dir.path().join("tmp");
        let started = Arc::new(Notify::new());

        {
            let fut = store.put(
                Box::new(HangReader {
                    started: Arc::clone(&started),
                    sent: false,
                }),
                PutOptions::default(),
            );
            tokio::pin!(fut);

            tokio::select! {
                () = started.notified() => {}
                out = fut.as_mut() => panic!("put finished unexpectedly: {out:?}"),
            }

            // Mid-upload the temp file exists; abandoning the future (at the
            // end of this block) must remove it.
            assert_eq!(count_files(&tmp), 1);
        }
        assert_eq!(count_files(&tmp), 0);
        // The cancelled upload also releases the budget it reserved.
        assert_eq!(store.inner.inflight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn body_error_mid_stream_is_reported_and_cleans_up() {
        let (store, dir) = open_store(1024).await;

        let err = store
            .put(
                Box::new(ErrorReader { produced: false }),
                PutOptions::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::BodyRead(_)));
        assert_eq!(count_files(&dir.path().join("blobs")), 0);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn put_fails_and_cleans_up_when_the_shard_cannot_be_created() {
        let (store, dir) = open_store(1024).await;
        // Occupy the shard path with a file so `create_dir_all` must fail.
        let shard = dir.path().join("blobs").join(&HELLO_WORLD_HASH[..2]);
        std::fs::write(&shard, b"not a directory").unwrap();

        let err = store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::Io(_)));
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
    }

    #[tokio::test]
    async fn reopening_the_same_directory_keeps_blobs_readable() {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            max_blob_size: 1024,
            max_total_bytes: None,
        };

        {
            let store = FsBlobStore::open(config.clone()).await.unwrap();
            store
                .put(body(b"hello world"), PutOptions::default())
                .await
                .unwrap();
        }

        // Schema application is idempotent and the data survives a restart.
        let store = FsBlobStore::open(config).await.unwrap();
        let hash = hash_of(HELLO_WORLD_HASH);
        assert!(store.meta(&hash).await.unwrap().is_some());
        let reader = store.read(&hash, None).await.unwrap().unwrap();
        assert_eq!(read_all(reader).await, b"hello world");
    }

    #[tokio::test]
    async fn open_reconciles_a_blob_file_that_has_no_row() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"\x89PNG\r\n\x1a\nreconciled-body";
        let hash = {
            let mut hasher = Sha2::new();
            hasher.update(data);
            Sha256::from_bytes(hasher.finalize().into())
        };
        let hex = hash.to_hex();
        let shard = dir.path().join("blobs").join(&hex[..2]);
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join(&hex), data).unwrap();

        let store = FsBlobStore::open(StoreConfig {
            data_dir: dir.path().to_path_buf(),
            max_blob_size: 1024,
            max_total_bytes: None,
        })
        .await
        .unwrap();

        assert_eq!(store.reconciled_count(), 1);
        let meta = store.meta(&hash).await.unwrap().unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.mime.as_str(), "image/png");
        assert_eq!(meta.owner, None);
        let reader = store.read(&hash, None).await.unwrap().unwrap();
        assert_eq!(read_all(reader).await, data);
    }

    #[tokio::test]
    async fn open_removes_a_blocked_blob_file_and_does_not_resurrect_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            max_blob_size: 1024,
            max_total_bytes: None,
        };
        let hash = hash_of(ABC_HASH);
        let hex = hash.to_hex();

        {
            let store = FsBlobStore::open(config.clone()).await.unwrap();
            store
                .put(body(b"abc"), PutOptions::default())
                .await
                .unwrap();
            // Deleting blocks the hash and removes the file.
            assert_eq!(
                store.delete(&hash, "anyone").await.unwrap(),
                DeleteOutcome::Deleted
            );
            // Simulate a crash leftover by re-creating the file.
            let shard = dir.path().join("blobs").join(&hex[..2]);
            std::fs::create_dir_all(&shard).unwrap();
            std::fs::write(shard.join(&hex), b"abc").unwrap();
        }

        let store = FsBlobStore::open(config).await.unwrap();
        assert_eq!(store.reconciled_count(), 0);
        assert!(store.meta(&hash).await.unwrap().is_none());
        assert!(!dir.path().join("blobs").join(&hex[..2]).join(&hex).exists());
    }

    #[tokio::test]
    async fn unknown_blob_has_no_meta_and_no_reader() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);

        assert!(store.meta(&hash).await.unwrap().is_none());
        assert!(store.read(&hash, None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_whole_and_ranges_match_stored_bytes() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        let whole = store.read(&hash, None).await.unwrap().unwrap();
        assert_eq!(whole.range, None);
        assert_eq!(read_all(whole).await, b"hello world");

        let middle = store
            .read(&hash, Some(ByteRange { start: 6, end: 10 }))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_all(middle).await, b"world");

        let last = store
            .read(&hash, Some(ByteRange { start: 10, end: 10 }))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_all(last).await, b"d");
    }

    #[tokio::test]
    async fn read_bounds_the_stream_to_the_indexed_size() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // Simulate a file that grew past its row (corruption or a partial
        // overwrite): the store must not serve more than `meta.size`.
        let path = store.inner.blob_path(&hash);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"TRAILING GARBAGE");
        std::fs::write(&path, &bytes).unwrap();

        let reader = store.read(&hash, None).await.unwrap().unwrap();
        assert_eq!(read_all(reader).await, b"hello world");
    }

    #[tokio::test]
    async fn range_outside_the_blob_is_rejected() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        let err = store
            .read(&hash, Some(ByteRange { start: 0, end: 99 }))
            .await
            .err()
            .expect("a range past the end must be rejected");
        assert!(matches!(err, StoreError::InvalidRange));
    }

    #[tokio::test]
    async fn read_reports_corrupt_when_the_row_has_no_file() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();
        std::fs::remove_file(store.inner.blob_path(&hash)).unwrap();

        // The row survives, so `meta` still reports it...
        assert!(store.meta(&hash).await.unwrap().is_some());
        // ...but reading the bytes is a documented `Corrupt` error.
        let err = store
            .read(&hash, None)
            .await
            .err()
            .expect("a missing file must be reported");
        assert!(matches!(err, StoreError::Corrupt(_)));
    }

    #[tokio::test]
    async fn delete_enforces_ownership_and_removes_the_blob() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        let owner = pubkey(0x11);
        store
            .put(
                body(b"hello world"),
                PutOptions {
                    owner: Some(owner.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let path = store.inner.blob_path(&hash);

        assert_eq!(
            store.delete(&hash, &pubkey(0x22)).await.unwrap(),
            DeleteOutcome::NotOwner
        );
        assert!(store.meta(&hash).await.unwrap().is_some());
        assert!(path.exists());

        assert_eq!(
            store.delete(&hash, &owner).await.unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(store.meta(&hash).await.unwrap().is_none());
        assert!(!path.exists());
        assert!(store.read(&hash, None).await.unwrap().is_none());

        assert_eq!(
            store.delete(&hash, &owner).await.unwrap(),
            DeleteOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn ownerless_blob_can_be_deleted_by_anyone() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        assert_eq!(
            store.delete(&hash, "whoever").await.unwrap(),
            DeleteOutcome::Deleted
        );
    }

    #[tokio::test]
    async fn invalid_owner_is_rejected() {
        let (store, _dir) = open_store(1024).await;

        for bad in [
            "not-hex".to_string(),
            "AB".repeat(32), // uppercase hex is not a valid pubkey
            "a".repeat(63),  // too short
        ] {
            let err = store
                .put(
                    body(b"hello world"),
                    PutOptions {
                        owner: Some(bad),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(matches!(err, StoreError::InvalidOwner));
        }

        // The canonical lowercase form is accepted.
        let outcome = store
            .put(
                body(b"hello world"),
                PutOptions {
                    owner: Some(pubkey(0x11)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Created(_)));
    }

    #[tokio::test]
    async fn blocked_hash_is_refused_but_reporting_does_not_block() {
        let (store, _dir) = open_store(1024).await;
        let owner = pubkey(0x11);
        let hash = hash_of(HELLO_WORLD_HASH);

        store
            .put(
                body(b"hello world"),
                PutOptions {
                    owner: Some(owner.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store.delete(&hash, &owner).await.unwrap(),
            DeleteOutcome::Deleted
        );

        // BUD-09: removal blocks the hash, so it cannot be rewritten.
        assert!(store.is_blocked(&hash).await.unwrap());
        let err = store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Blocked));

        // The X-SHA-256 fast path must also refuse, without reading the body.
        let err = store
            .put(
                Box::new(FailReader),
                PutOptions {
                    expected: Some(hash),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Blocked));

        // Reporting is not removal: a report must never block.
        let reported = hash_of(ABC_HASH);
        store
            .save_report(ReportRecord {
                hashes: vec![reported],
                reporter: pubkey(0x22),
                kind: "malware".to_string(),
                content: "bad blob".to_string(),
                created_at: 123,
            })
            .await
            .unwrap();
        assert!(!store.is_blocked(&reported).await.unwrap());
    }

    #[tokio::test]
    async fn repeat_reports_are_deduplicated() {
        let (store, _dir) = open_store(1024).await;
        let report = || ReportRecord {
            hashes: vec![hash_of(HELLO_WORLD_HASH)],
            reporter: pubkey(0x22),
            kind: "malware".to_string(),
            content: "bad blob".to_string(),
            created_at: 123,
        };

        store.save_report(report()).await.unwrap();
        store.save_report(report()).await.unwrap();

        let count: i64 = store
            .inner
            .lock()
            .query_row("SELECT COUNT(*) FROM reports", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn report_with_too_many_hashes_is_rejected() {
        let (store, _dir) = open_store(1024).await;
        let hashes: Vec<Sha256> = (0..33u8).map(|i| Sha256::from_bytes([i; 32])).collect();

        let err = store
            .save_report(ReportRecord {
                hashes,
                reporter: pubkey(0x22),
                kind: "spam".to_string(),
                content: String::new(),
                created_at: 1,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::TooLarge));

        let count: i64 = store
            .inner
            .lock()
            .query_row("SELECT COUNT(*) FROM reports", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn list_paginates_newest_first_and_filters_by_owner_and_time() {
        let (store, _dir) = open_store(1024).await;
        let owner_a = pubkey(0x11);
        let owner_b = pubkey(0x22);
        let oldest = put_at(&store, b"aaa", &owner_a, 100).await;
        let middle = put_at(&store, b"bbb", &owner_a, 200).await;
        let newest = put_at(&store, b"ccc", &owner_a, 300).await;
        let other = put_at(&store, b"ddd", &owner_b, 400).await;

        let query = |cursor, limit, since, until| ListQuery {
            pubkey: owner_a.clone(),
            cursor,
            limit,
            since,
            until,
        };

        let page1 = store.list(query(None, 2, None, None)).await.unwrap();
        assert_eq!(hashes(&page1), vec![newest.sha256, middle.sha256]);

        let page2 = store
            .list(query(Some(middle.sha256), 2, None, None))
            .await
            .unwrap();
        assert_eq!(hashes(&page2), vec![oldest.sha256]);

        let since = store.list(query(None, 10, Some(200), None)).await.unwrap();
        assert_eq!(hashes(&since), vec![newest.sha256, middle.sha256]);

        let until = store.list(query(None, 10, None, Some(200))).await.unwrap();
        assert_eq!(hashes(&until), vec![middle.sha256, oldest.sha256]);

        let window = store
            .list(query(None, 10, Some(200), Some(200)))
            .await
            .unwrap();
        assert_eq!(hashes(&window), vec![middle.sha256]);

        let other_pubkey = store
            .list(ListQuery {
                pubkey: owner_b.clone(),
                cursor: None,
                limit: 10,
                since: None,
                until: None,
            })
            .await
            .unwrap();
        assert_eq!(hashes(&other_pubkey), vec![other.sha256]);
    }

    #[tokio::test]
    async fn list_pages_across_an_uploaded_tie() {
        let (store, _dir) = open_store(1024).await;
        let owner = pubkey(0x11);
        let mut all = Vec::new();
        for bytes in [b"aaa".as_slice(), b"bbb", b"ccc", b"ddd"] {
            all.push(put_at(&store, bytes, &owner, 500).await.sha256);
        }

        let query = |cursor| ListQuery {
            pubkey: owner.clone(),
            cursor,
            limit: 2,
            since: None,
            until: None,
        };

        // Every blob shares `uploaded = 500`, so paging exercises the
        // `(uploaded = ? AND sha256 < ?)` keyset branch.
        let page1 = store.list(query(None)).await.unwrap();
        assert_eq!(page1.len(), 2);
        let page2 = store.list(query(Some(page1[1].sha256))).await.unwrap();
        assert_eq!(page2.len(), 2);

        let mut seen = hashes(&page1);
        seen.extend(hashes(&page2));
        seen.sort();
        all.sort();
        assert_eq!(seen, all);
    }

    #[tokio::test]
    async fn list_with_unknown_cursor_returns_no_rows() {
        let (store, _dir) = open_store(1024).await;
        put_at(&store, b"aaa", &pubkey(0x11), 100).await;

        let page = store
            .list(ListQuery {
                pubkey: pubkey(0x11),
                cursor: Some(hash_of(HELLO_WORLD_HASH)),
                limit: 10,
                since: None,
                until: None,
            })
            .await
            .unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn cursor_from_another_owner_is_not_honoured() {
        let (store, _dir) = open_store(1024).await;
        put_at(&store, b"aaa", &pubkey(0x11), 100).await;
        let theirs = put_at(&store, b"bbb", &pubkey(0x22), 200).await;

        let page = store
            .list(ListQuery {
                pubkey: pubkey(0x11),
                cursor: Some(theirs.sha256),
                limit: 10,
                since: None,
                until: None,
            })
            .await
            .unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_breaks_uploaded_ties_by_hash_descending() {
        let (store, _dir) = open_store(1024).await;
        let owner = pubkey(0x11);
        put_at(&store, b"aaa", &owner, 500).await;
        put_at(&store, b"bbb", &owner, 500).await;

        let page = store
            .list(ListQuery {
                pubkey: owner,
                cursor: None,
                limit: 10,
                since: None,
                until: None,
            })
            .await
            .unwrap();

        assert_eq!(page.len(), 2);
        assert!(page[0].sha256 > page[1].sha256);
    }

    #[tokio::test]
    async fn list_clamps_a_limit_above_the_maximum() {
        let (store, _dir) = open_store(1024).await;
        let owner = pubkey(0x11);
        for i in 0..101u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            let meta = BlobMeta {
                sha256: Sha256::from_bytes(bytes),
                size: 1,
                mime: MimeType::octet_stream(),
                uploaded: 1,
                owner: Some(owner.clone()),
            };
            store.inner.insert_admitted(&meta).unwrap();
        }

        let page = store
            .list(ListQuery {
                pubkey: owner,
                cursor: None,
                limit: 10_000,
                since: None,
                until: None,
            })
            .await
            .unwrap();
        assert_eq!(page.len(), MAX_LIST_LIMIT as usize);
    }

    #[tokio::test]
    async fn large_blob_streams_and_round_trips() {
        let (store, _dir) = open_store(16 * 1024 * 1024).await;
        let data = patterned_bytes(8 * 1024 * 1024);
        let expected = {
            let mut hasher = Sha2::new();
            hasher.update(&data);
            Sha256::from_bytes(hasher.finalize().into())
        };

        let outcome = store.put(body(&data), PutOptions::default()).await.unwrap();
        let PutOutcome::Created(meta) = outcome else {
            panic!("expected Created");
        };
        assert_eq!(meta.sha256, expected);
        assert_eq!(meta.size, data.len() as u64);

        let reader = store.read(&meta.sha256, None).await.unwrap().unwrap();
        assert_eq!(read_all(reader).await, data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_of_the_same_blob_create_exactly_once() {
        const PUTS: usize = 8;
        let (store, dir) = open_store(1024 * 1024).await;
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(PUTS + 1));

        let mut tasks = Vec::new();
        for i in 0..PUTS {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let owner = pubkey(i as u8 + 1);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let outcome = store
                    .put(
                        body(b"hello world"),
                        PutOptions {
                            owner: Some(owner),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
                outcome
            }));
        }
        barrier.wait().await;

        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.unwrap());
        }

        let created = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PutOutcome::Created(_)))
            .count();
        assert_eq!(created, 1, "exactly one put must create the row");

        // The winner's owner is canonical; every outcome must agree.
        let canonical = outcomes
            .iter()
            .map(|outcome| match outcome {
                PutOutcome::Created(meta) | PutOutcome::Existed(meta) => meta.owner.clone(),
            })
            .next()
            .unwrap();
        for outcome in &outcomes {
            let meta = match outcome {
                PutOutcome::Created(meta) | PutOutcome::Existed(meta) => meta,
            };
            assert_eq!(meta.owner, canonical);
        }

        // Exactly one file and one row survive the race.
        let hash = hash_of(HELLO_WORLD_HASH);
        assert_eq!(count_files(&dir.path().join("blobs")), 1);
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
        let rows = store
            .list(ListQuery {
                pubkey: canonical.unwrap(),
                cursor: None,
                limit: 10,
                since: None,
                until: None,
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sha256, hash);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delete_during_put_never_leaves_a_row_without_a_file() {
        let (store, _dir) = open_store(1024 * 1024).await;
        let store = Arc::new(store);
        let hash = hash_of(HELLO_WORLD_HASH);
        let owner = pubkey(0x11);

        let put = {
            let store = Arc::clone(&store);
            let owner = owner.clone();
            tokio::spawn(async move {
                store
                    .put(
                        body(b"hello world"),
                        PutOptions {
                            owner: Some(owner),
                            ..Default::default()
                        },
                    )
                    .await
            })
        };
        let delete = {
            let store = Arc::clone(&store);
            let owner = owner.clone();
            tokio::spawn(async move { store.delete(&hash, &owner).await })
        };

        let put = put.await.unwrap().unwrap();
        let delete = delete.await.unwrap().unwrap();

        assert!(matches!(
            put,
            PutOutcome::Created(_) | PutOutcome::Existed(_)
        ));
        // The delete either saw the blob (Deleted) or raced ahead of it
        // (NotFound); it never sees a half-built blob.
        assert!(matches!(
            delete,
            DeleteOutcome::Deleted | DeleteOutcome::NotFound
        ));

        // Invariant: a row never outlives its file.
        let row = store.meta(&hash).await.unwrap();
        let file = store.inner.blob_path(&hash).exists();
        assert_eq!(row.is_some(), file, "row and file must agree");
    }

    // -----------------------------------------------------------------------
    // Blocklist resurrection race
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_between_streaming_and_admission_is_not_resurrected() {
        let (store, _dir) = open_store(1024).await;
        let store = Arc::new(store);
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // Park the next put between streaming and the admission critical
        // section, the exact window the old code left open.
        let gate = Arc::new(PutGate::default());
        *store.inner.put_gate.lock().unwrap() = Some(Arc::clone(&gate));

        let put = {
            let store = Arc::clone(&store);
            tokio::spawn(
                async move { store.put(body(b"hello world"), PutOptions::default()).await },
            )
        };
        gate.reached.notified().await;

        // The delete commits while the put is parked.
        assert_eq!(
            store.delete(&hash, "anyone").await.unwrap(),
            DeleteOutcome::Deleted
        );
        gate.resume.notify_one();

        let err = put.await.unwrap().unwrap_err();
        assert!(matches!(err, StoreError::Blocked), "got {err:?}");
        assert!(store.meta(&hash).await.unwrap().is_none());
        assert!(!store.inner.blob_path(&hash).exists());
        assert!(store.is_blocked(&hash).await.unwrap());
    }

    // -----------------------------------------------------------------------
    // Delete order
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn failed_delete_commit_keeps_row_and_file_in_agreement() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // Force the row-delete transaction to fail: reads still work, writes do
        // not. The commit is the first step of a delete now, so a failure must
        // leave the file untouched.
        store
            .inner
            .lock()
            .execute_batch("PRAGMA query_only = ON")
            .unwrap();

        let err = store.delete(&hash, "anyone").await.unwrap_err();
        assert!(matches!(err, StoreError::Index(_)));

        let row = store.meta(&hash).await.unwrap();
        let file = store.inner.blob_path(&hash).exists();
        assert_eq!(
            row.is_some(),
            file,
            "a failed delete must leave the blob intact, not a row without a file"
        );
        assert!(row.is_some());
    }

    // -----------------------------------------------------------------------
    // Total disk quota
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn put_within_total_budget_succeeds() {
        let (store, _dir) = open_store_with(1024, Some(64)).await;

        let outcome = store
            .put(
                body(b"hello world"),
                PutOptions {
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(matches!(outcome, PutOutcome::Created(_)));
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 11);
        assert_eq!(store.inner.inflight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn put_exceeding_total_budget_is_refused() {
        let (store, dir) = open_store_with(1024, Some(16)).await;
        store
            .put(
                body(b"hello world"),
                PutOptions {
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let err = store
            .put(
                body(b"abcdefghijk"),
                PutOptions {
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::QuotaExceeded));
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 11);
        assert_eq!(count_files(&dir.path().join("blobs")), 1);
    }

    #[tokio::test]
    async fn dedupe_at_full_budget_is_free() {
        let (store, _dir) = open_store_with(1024, Some(11)).await;
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 11);

        // The X-SHA-256 fast path answers before the quota is consulted.
        let outcome = store
            .put(
                Box::new(FailReader),
                PutOptions {
                    expected: Some(hash_of(HELLO_WORLD_HASH)),
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(matches!(outcome, PutOutcome::Existed(_)));
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 11);
    }

    #[tokio::test]
    async fn delete_frees_total_budget() {
        let (store, _dir) = open_store_with(1024, Some(11)).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(body(b"hello world"), PutOptions::default())
            .await
            .unwrap();

        // The budget is full, so a different blob is refused...
        let refused = store
            .put(
                body(b"abcdefghijk"),
                PutOptions {
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(refused, StoreError::QuotaExceeded));

        // ...until the first blob is deleted.
        assert_eq!(
            store.delete(&hash, "anyone").await.unwrap(),
            DeleteOutcome::Deleted
        );
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 0);

        let outcome = store
            .put(
                body(b"abcdefghijk"),
                PutOptions {
                    declared_size: Some(11),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Created(_)));
    }

    #[tokio::test]
    async fn authoritative_insert_refuses_when_the_total_would_exceed() {
        let (store, _dir) = open_store_with(1024, Some(16)).await;
        let meta = |hash| BlobMeta {
            sha256: hash,
            size: 11,
            mime: MimeType::octet_stream(),
            uploaded: 1,
            owner: None,
        };

        assert!(matches!(
            store
                .inner
                .insert_admitted(&meta(hash_of(HELLO_WORLD_HASH))),
            Ok(Admitted::Inserted(1))
        ));
        assert!(matches!(
            store.inner.insert_admitted(&meta(hash_of(ABC_HASH))),
            Ok(Admitted::QuotaExceeded)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_cannot_exceed_the_total_budget() {
        let (store, _dir) = open_store_with(4096, Some(3000)).await;
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(3));

        let mut tasks = Vec::new();
        for i in 0..2usize {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let data = patterned_bytes(2000 + i);
                let declared = data.len() as u64;
                barrier.wait().await;
                store
                    .put(
                        body(&data),
                        PutOptions {
                            declared_size: Some(declared),
                            ..Default::default()
                        },
                    )
                    .await
            }));
        }
        barrier.wait().await;
        for task in tasks {
            // Both may fail, or one may win; neither may push the total over.
            let _ = task.await.unwrap();
        }

        let total = store.inner.used.load(Ordering::Relaxed);
        assert!(
            total <= 3000,
            "committed {total} bytes over a 3000-byte budget"
        );
    }

    #[tokio::test]
    async fn lying_content_length_is_stopped_mid_stream() {
        let (store, dir) = open_store_with(1 << 20, Some(1024)).await;
        let produced = Arc::new(AtomicU64::new(0));
        let reader = CountingReader {
            remaining: 1 << 20,
            produced: Arc::clone(&produced),
        };

        let err = store
            .put(
                Box::new(reader),
                PutOptions {
                    declared_size: Some(10),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(err, StoreError::QuotaExceeded));
        let served = produced.load(Ordering::Relaxed);
        assert!(
            served <= 1024 + CHUNK as u64,
            "the store read {served} bytes before stopping"
        );
        assert_eq!(count_files(&dir.path().join("tmp")), 0);
        assert_eq!(store.inner.used.load(Ordering::Relaxed), 0);
        assert_eq!(store.inner.inflight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn aborted_upload_releases_its_reservation() {
        let (store, _dir) = open_store_with(1 << 20, Some(1024)).await;

        // A client that declared a large body and then aborted must not leak
        // its reservation against the budget.
        let err = store
            .put(
                Box::new(ErrorReader { produced: false }),
                PutOptions {
                    declared_size: Some(900),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::BodyRead(_)));
        assert_eq!(store.inner.inflight.load(Ordering::Relaxed), 0);

        // This only fits if the reservation was released.
        let outcome = store
            .put(
                body(&patterned_bytes(900)),
                PutOptions {
                    declared_size: Some(900),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, PutOutcome::Created(_)));
    }
}
