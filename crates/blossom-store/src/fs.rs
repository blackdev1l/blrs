//! A filesystem blob store with a SQLite metadata index.
//!
//! Bodies stream to a uniquely named file under `tmp/` in bounded chunks and
//! are hashed as they arrive, so the whole body is never resident in memory.
//! The file is `fsync`ed and renamed into place only after the hash has been
//! verified, which is what keeps a partially written blob from ever appearing
//! under its final name. Metadata is written once and never overwritten, so the
//! first uploader's owner and upload time win regardless of races.

use std::io::ErrorKind;
use std::io::SeekFrom;
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

/// A selected row from the `blobs` table, before validation.
type RawMeta = (String, i64, String, i64, Option<String>);

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
}

impl Inner {
    /// The final path for a blob, `blobs/<aa>/<sha256>`.
    fn blob_path(&self, hash: &Sha256) -> PathBuf {
        let hex = hash.to_hex();
        self.blobs_dir.join(&hex[..2]).join(hex)
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

    /// Inserts only when absent; the returned count is `1` for the writer that
    /// created the row and `0` for every loser of the race.
    fn insert(&self, meta: &BlobMeta) -> Result<usize, StoreError> {
        let conn = self.lock();
        insert_meta(&conn, meta)
    }

    fn remove(&self, hash: &Sha256) -> Result<usize, StoreError> {
        let conn = self.lock();
        delete_meta(&conn, hash)
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("index mutex poisoned")
    }
}

impl FsBlobStore {
    /// Opens (creating if needed) a blob store rooted at `config.data_dir`.
    ///
    /// Creates the directory tree and applies the SQLite schema.
    pub async fn open(config: StoreConfig) -> Result<Self, StoreError> {
        let blobs_dir = config.data_dir.join("blobs");
        let tmp_dir = config.data_dir.join("tmp");
        tokio::fs::create_dir_all(&blobs_dir).await?;
        tokio::fs::create_dir_all(&tmp_dir).await?;

        let db_path = config.data_dir.join("index.db");
        let inner = blocking(move || -> Result<Inner, StoreError> {
            let conn = Connection::open(&db_path)?;
            conn.execute_batch(SCHEMA)?;
            Ok(Inner {
                config,
                conn: Mutex::new(conn),
                blobs_dir,
                tmp_dir,
                tmp_seq: AtomicU64::new(0),
            })
        })
        .await?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The shared implementation of [`BlobStore::put`] with an explicit upload
    /// time, so tests can place blobs at chosen points on the timeline.
    async fn put_with_time(
        &self,
        mut body: Box<dyn AsyncRead + Send + Unpin>,
        opts: PutOptions,
        uploaded: i64,
    ) -> Result<PutOutcome, StoreError> {
        let max = self.inner.config.max_blob_size;

        // A declared size over the limit never needs the body at all.
        if let Some(declared) = opts.declared_size {
            if declared > max {
                return Err(StoreError::TooLarge);
            }
        }

        // BUD-02 lets `X-SHA-256` be used for policy before persisting: if the
        // blob is already known, answer without reading the body.
        if let Some(expected) = opts.expected {
            if let Some(existing) = self.meta(&expected).await? {
                return Ok(PutOutcome::Existed(existing));
            }
        }

        let tmp_path = self.inner.new_tmp_path();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;

        let (hash, head, size) = match stream_body(&mut *body, &mut file, max).await {
            Ok(streamed) => streamed,
            Err(err) => {
                drop(file);
                discard(&tmp_path).await;
                return Err(err);
            }
        };

        if let Some(expected) = opts.expected {
            if hash != expected {
                drop(file);
                discard(&tmp_path).await;
                return Err(StoreError::HashMismatch);
            }
        }

        // The hash is verified; only now make the bytes durable and move them
        // under the content-addressed name.
        let durable = async {
            file.flush().await?;
            file.sync_all().await?;
            Ok::<(), StoreError>(())
        }
        .await;
        drop(file);
        if let Err(err) = durable {
            discard(&tmp_path).await;
            return Err(err);
        }

        let mime = opts
            .mime
            .unwrap_or_else(|| MimeType::sniff(&head).unwrap_or_else(MimeType::octet_stream));

        let dest = self.inner.blob_path(&hash);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&tmp_path, &dest).await?;

        let meta = BlobMeta {
            sha256: hash,
            size,
            mime,
            uploaded,
            owner: opts.owner,
        };

        let inner = Arc::clone(&self.inner);
        let candidate = meta.clone();
        let changed = blocking(move || inner.insert(&candidate)).await?;

        if changed == 1 {
            Ok(PutOutcome::Created(meta))
        } else {
            // Another writer committed first; its owner and timestamp are the
            // canonical ones.
            match self.meta(&hash).await? {
                Some(existing) => Ok(PutOutcome::Existed(existing)),
                None => Err(StoreError::Corrupt(
                    "index row disappeared after insert".to_string(),
                )),
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

        // Opening the file reads nothing: the returned stream stays lazy and a
        // range is expressed as a seek plus a bounded `Take`.
        let stream: Box<dyn AsyncRead + Send + Unpin> = match range {
            Some(range) => {
                file.seek(SeekFrom::Start(range.start)).await?;
                Box::new(file.take(range.len()))
            }
            None => Box::new(file),
        };

        Ok(Some(BlobReader {
            meta,
            range,
            stream,
        }))
    }

    async fn delete(&self, hash: &Sha256, requester: &str) -> Result<DeleteOutcome, StoreError> {
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

        let inner = Arc::clone(&self.inner);
        let owned = *hash;
        let changed = blocking(move || inner.remove(&owned)).await?;
        if changed == 0 {
            return Ok(DeleteOutcome::NotFound);
        }

        match tokio::fs::remove_file(self.inner.blob_path(hash)).await {
            Ok(()) => {}
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
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.save(&report)).await
    }

    async fn is_blocked(&self, hash: &Sha256) -> Result<bool, StoreError> {
        let inner = Arc::clone(&self.inner);
        let hash = *hash;
        blocking(move || inner.blocked(&hash)).await
    }
}

/// Runs a synchronous closure on the blocking pool and unwraps the join result.
async fn blocking<T, F>(f: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| StoreError::Corrupt(format!("index task failed: {err}")))?
}

/// Reads `body` to EOF in bounded chunks, hashing and writing as it goes.
async fn stream_body(
    body: &mut (dyn AsyncRead + Send + Unpin),
    file: &mut File,
    max: u64,
) -> Result<(Sha256, Vec<u8>, u64), StoreError> {
    let mut hasher = Sha2::new();
    let mut head = Vec::with_capacity(SNIFF_LEN);
    let mut total: u64 = 0;
    let mut buf = vec![0u8; CHUNK];

    loop {
        let read = body.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max {
            return Err(StoreError::TooLarge);
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

/// Best-effort removal of an abandoned temp file.
async fn discard(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
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
    Ok(BlobMeta {
        sha256,
        size: size as u64,
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

fn delete_meta(conn: &Connection, hash: &Sha256) -> Result<usize, StoreError> {
    let changed = conn.execute("DELETE FROM blobs WHERE sha256 = ?1", [hash.to_hex()])?;
    Ok(changed)
}

fn cursor_uploaded(conn: &Connection, hash: &Sha256) -> Result<Option<i64>, StoreError> {
    let uploaded = conn
        .query_row(
            "SELECT uploaded FROM blobs WHERE sha256 = ?1",
            [hash.to_hex()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    Ok(uploaded)
}

fn list_meta(conn: &Connection, query: &ListQuery) -> Result<Vec<BlobMeta>, StoreError> {
    // A cursor that is not in the index cannot anchor a page: return nothing
    // rather than silently serving the first page again.
    let cursor_pos = match query.cursor {
        None => None,
        Some(hash) => match cursor_uploaded(conn, &hash)? {
            None => return Ok(Vec::new()),
            Some(uploaded) => Some((uploaded, hash)),
        },
    };

    let owner = query.pubkey.clone();
    let cursor_hex = cursor_pos.as_ref().map(|(_, hash)| hash.to_hex());
    let since = query.since;
    let until = query.until;
    let limit = i64::from(query.limit);

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
    // One `reports` row per hash, and each reported hash joins the blocklist so
    // `is_blocked` (which reads only `blocklist`) reflects the report.
    let tx = conn.transaction()?;
    {
        let mut report_stmt = tx.prepare(
            "INSERT INTO reports (sha256, reporter, kind, content, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let mut block_stmt =
            tx.prepare("INSERT OR IGNORE INTO blocklist (sha256, blocked_at) VALUES (?1, ?2)")?;
        for hash in &report.hashes {
            let hex = hash.to_hex();
            report_stmt.execute(rusqlite::params![
                hex,
                report.reporter,
                report.kind,
                report.content,
                report.created_at,
            ])?;
            block_stmt.execute(rusqlite::params![hex, report.created_at])?;
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;
    use tokio::sync::Barrier;

    use super::*;

    /// sha256("hello world"), a well-known digest used as a literal.
    const HELLO_WORLD_HASH: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    /// sha256("abc"), a second well-known digest.
    const ABC_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    async fn open_store(max_blob_size: u64) -> (FsBlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            max_blob_size,
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

    #[tokio::test]
    async fn put_small_blob_creates_and_stores_it() {
        let (store, dir) = open_store(1024).await;
        let owner = "ab".repeat(32);

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
    async fn reupload_returns_existed_with_first_owner_and_time() {
        let (store, _dir) = open_store(1024).await;

        let first = store
            .put_with_time(
                body(b"hello world"),
                PutOptions {
                    owner: Some("first".to_string()),
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
                    owner: Some("second".to_string()),
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
        assert_eq!(second_meta.owner.as_deref(), Some("first"));
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
    async fn delete_enforces_ownership_and_removes_the_blob() {
        let (store, _dir) = open_store(1024).await;
        let hash = hash_of(HELLO_WORLD_HASH);
        store
            .put(
                body(b"hello world"),
                PutOptions {
                    owner: Some("owner-a".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let path = store.inner.blob_path(&hash);

        assert_eq!(
            store.delete(&hash, "owner-b").await.unwrap(),
            DeleteOutcome::NotOwner
        );
        assert!(store.meta(&hash).await.unwrap().is_some());
        assert!(path.exists());

        assert_eq!(
            store.delete(&hash, "owner-a").await.unwrap(),
            DeleteOutcome::Deleted
        );
        assert!(store.meta(&hash).await.unwrap().is_none());
        assert!(!path.exists());
        assert!(store.read(&hash, None).await.unwrap().is_none());

        assert_eq!(
            store.delete(&hash, "owner-a").await.unwrap(),
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
    async fn list_paginates_newest_first_and_filters_by_owner_and_time() {
        let (store, _dir) = open_store(1024).await;
        let oldest = put_at(&store, b"aaa", "pk1", 100).await;
        let middle = put_at(&store, b"bbb", "pk1", 200).await;
        let newest = put_at(&store, b"ccc", "pk1", 300).await;
        let other = put_at(&store, b"ddd", "pk2", 400).await;

        let query = |cursor, limit, since, until| ListQuery {
            pubkey: "pk1".to_string(),
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
                pubkey: "pk2".to_string(),
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
    async fn list_with_unknown_cursor_returns_no_rows() {
        let (store, _dir) = open_store(1024).await;
        put_at(&store, b"aaa", "pk1", 100).await;

        let page = store
            .list(ListQuery {
                pubkey: "pk1".to_string(),
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
    async fn list_breaks_uploaded_ties_by_hash_descending() {
        let (store, _dir) = open_store(1024).await;
        put_at(&store, b"aaa", "pk1", 500).await;
        put_at(&store, b"bbb", "pk1", 500).await;

        let page = store
            .list(ListQuery {
                pubkey: "pk1".to_string(),
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
    async fn save_report_blocks_every_reported_hash() {
        let (store, _dir) = open_store(1024).await;
        let reported_a = hash_of(HELLO_WORLD_HASH);
        let reported_b = hash_of(ABC_HASH);
        let unrelated = Sha256::from_bytes([0x42; 32]);

        store
            .save_report(ReportRecord {
                hashes: vec![reported_a, reported_b],
                reporter: "reporter".to_string(),
                kind: "malware".to_string(),
                content: "bad blob".to_string(),
                created_at: 123,
            })
            .await
            .unwrap();

        assert!(store.is_blocked(&reported_a).await.unwrap());
        assert!(store.is_blocked(&reported_b).await.unwrap());
        assert!(!store.is_blocked(&unrelated).await.unwrap());
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
        use std::sync::Arc as StdArc;

        const PUTS: usize = 8;
        let (store, _dir) = open_store(1024 * 1024).await;
        let store = StdArc::new(store);
        let barrier = StdArc::new(Barrier::new(PUTS + 1));

        let mut tasks = Vec::new();
        for _ in 0..PUTS {
            let store = StdArc::clone(&store);
            let barrier = StdArc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .put(body(b"hello world"), PutOptions::default())
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;

        let mut created = 0;
        let mut existed = 0;
        for task in tasks {
            match task.await.unwrap() {
                PutOutcome::Created(_) => created += 1,
                PutOutcome::Existed(_) => existed += 1,
            }
        }
        assert_eq!(created, 1);
        assert_eq!(existed, PUTS - 1);
    }
}
