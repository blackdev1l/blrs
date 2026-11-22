//! SQLite metadata index.
//!
//! Blob bodies live on disk; everything queryable lives here. Keeping metadata
//! out of the blob tree means `/list`, quota checks, and ownership checks never
//! touch the filesystem.
//!
//! Lane B owns this module.

/// Schema applied on every open; each statement is idempotent.
///
/// - `blobs` is keyed by the blob hash, so a re-upload is a lookup, not a write.
/// - `reports` keeps NIP-56 reports for operator review (BUD-09). Reporting is
///   kept separate from removal: a report never blocks, and the unique key on
///   `(sha256, reporter)` makes a repeat report a no-op instead of growing the
///   table without bound. `created_at` is client-supplied, so it is deliberately
///   not part of the key: a reporter has exactly one report per blob.
/// - `blocklist` records hashes moderation has removed, so `put` can refuse to
///   rewrite them (BUD-09).
pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS blobs (
    sha256   TEXT PRIMARY KEY,
    size     INTEGER NOT NULL,
    mime     TEXT NOT NULL,
    uploaded INTEGER NOT NULL,
    owner    TEXT
);
CREATE INDEX IF NOT EXISTS blobs_owner_uploaded ON blobs (owner, uploaded DESC, sha256);

CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT NOT NULL,
    reporter   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (sha256, reporter)
);
CREATE INDEX IF NOT EXISTS reports_sha256 ON reports (sha256);

CREATE TABLE IF NOT EXISTS blocklist (
    sha256     TEXT PRIMARY KEY,
    blocked_at INTEGER NOT NULL
);
"#;
