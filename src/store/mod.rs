//! SQLite-backed clipboard entry store.
//!
//! Step 2 surface:
//!   - `insert_or_bump` — write path with blake3 dedup.
//!   - `list`           — read path for `clipd list`.
//!
//! WAL journal mode lets the daemon's writer coexist with read-only handles
//! opened by short-lived `clipd list` invocations. Step 5 will replace the
//! direct-DB read path with named-pipe IPC.
//!
//! Encryption is deferred: `content` is plaintext and `nonce` is a zero-byte
//! BLOB until Step 4 wires `crypto::Vault` into insert/fetch.

pub mod crypto;
mod schema;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;

pub struct NewEntry<'a> {
    pub kind: &'a str,
    pub content: &'a [u8],
    pub hash: &'a [u8],
    pub size_bytes: usize,
    pub created_at: i64,
    pub preview: String,
    pub source_app: Option<String>,
}

pub enum Outcome {
    Inserted { id: i64 },
    BumpedLastSeen { id: i64 },
}

pub struct EntryRow {
    pub id: i64,
    // created_at: surfaced for Step 9 (date filters) and stable client display.
    // size_bytes: surfaced for Step 12 (retention purge) and Step 13 (doctor stats).
    #[allow(dead_code)]
    pub created_at: i64,
    pub last_seen: i64,
    pub kind: String,
    pub preview: String,
    pub pinned: bool,
    #[allow(dead_code)]
    pub size_bytes: i64,
}

fn open_rw(db_path: &Path) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).context("creating db parent dir")?;
    }
    let conn = Connection::open(db_path).context("opening sqlite db")?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("enabling foreign_keys")?;
    schema::migrate(&conn).context("running migrations")?;
    Ok(conn)
}

fn open_ro(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening sqlite db (ro): {}", db_path.display()))?;
    Ok(conn)
}

pub fn insert_or_bump(db_path: &Path, e: &NewEntry) -> Result<Outcome> {
    let conn = open_rw(db_path)?;

    let bumped = conn
        .execute(
            "UPDATE entries SET last_seen = ?1 WHERE hash = ?2",
            params![e.created_at, e.hash],
        )
        .context("dedup UPDATE entries")?;
    if bumped > 0 {
        let id: i64 = conn
            .query_row(
                "SELECT id FROM entries WHERE hash = ?1",
                params![e.hash],
                |r| r.get(0),
            )
            .context("looking up bumped row id")?;
        return Ok(Outcome::BumpedLastSeen { id });
    }

    conn.execute(
        "INSERT INTO entries
            (created_at, last_seen, kind, content, nonce, preview,
             source_app, pinned, sensitive, hash, size_bytes, formats)
         VALUES (?1, ?1, ?2, ?3, x'', ?4, ?5, 0, 0, ?6, ?7, NULL)",
        params![
            e.created_at,
            e.kind,
            e.content,
            e.preview,
            e.source_app,
            e.hash,
            e.size_bytes as i64,
        ],
    )
    .context("INSERT entries")?;

    Ok(Outcome::Inserted {
        id: conn.last_insert_rowid(),
    })
}

pub fn list(db_path: &Path, limit: usize) -> Result<Vec<EntryRow>> {
    // Daemon hasn't started yet, or hasn't captured anything: empty result is
    // a better UX than an error.
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = open_ro(db_path)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, created_at, last_seen, kind, preview, pinned, size_bytes
             FROM entries
             ORDER BY last_seen DESC
             LIMIT ?1",
        )
        .context("preparing list statement")?;
    let rows = stmt
        .query_map(params![limit as i64], |r| {
            Ok(EntryRow {
                id: r.get(0)?,
                created_at: r.get(1)?,
                last_seen: r.get(2)?,
                kind: r.get(3)?,
                preview: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                pinned: r.get::<_, i64>(5)? != 0,
                size_bytes: r.get(6)?,
            })
        })
        .context("executing list query")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collecting list rows")
}

/// First 200 chars of `text`, lowercased, with every control char (\n, \r,
/// \t, ANSI escape, …) collapsed to a single space. Matches the schema's
/// `preview` semantics in `clipd-plan.md` and keeps the value safe for
/// console rendering and (Step 5) FTS5 indexing.
pub fn derive_preview(text: &str) -> String {
    let one_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    one_line
        .chars()
        .take(200)
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("test.db");
        (dir, p)
    }

    fn new_text<'a>(text: &'a str, hash: &'a [u8], t: i64) -> NewEntry<'a> {
        NewEntry {
            kind: "text",
            content: text.as_bytes(),
            hash,
            size_bytes: text.len(),
            created_at: t,
            preview: derive_preview(text),
            source_app: None,
        }
    }

    #[test]
    fn open_and_migrate_creates_entries_table() {
        let (_d, p) = fixture();
        let conn = open_rw(&p).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn migrate_is_idempotent() {
        let (_d, p) = fixture();
        let _ = open_rw(&p).unwrap();
        let _ = open_rw(&p).unwrap();
        let _ = open_rw(&p).unwrap();
    }

    #[test]
    fn insert_then_list_roundtrip() {
        let (_d, p) = fixture();
        let h1 = blake3::hash(b"alpha");
        let h2 = blake3::hash(b"bravo");
        let h3 = blake3::hash(b"charlie");
        insert_or_bump(&p, &new_text("alpha", h1.as_bytes(), 1000)).unwrap();
        insert_or_bump(&p, &new_text("bravo", h2.as_bytes(), 2000)).unwrap();
        insert_or_bump(&p, &new_text("charlie", h3.as_bytes(), 3000)).unwrap();

        let rows = list(&p, 50).unwrap();
        assert_eq!(rows.len(), 3);
        // Ordered by last_seen DESC.
        assert_eq!(rows[0].preview, "charlie");
        assert_eq!(rows[1].preview, "bravo");
        assert_eq!(rows[2].preview, "alpha");
        assert_eq!(rows[0].kind, "text");
        assert_eq!(rows[0].size_bytes, "charlie".len() as i64);
        assert!(!rows[0].pinned);
    }

    #[test]
    fn duplicate_hash_bumps_last_seen() {
        let (_d, p) = fixture();
        let h = blake3::hash(b"once");
        let r1 = insert_or_bump(&p, &new_text("once", h.as_bytes(), 1000)).unwrap();
        let id1 = match r1 {
            Outcome::Inserted { id } => id,
            _ => panic!("expected Inserted"),
        };
        let r2 = insert_or_bump(&p, &new_text("once", h.as_bytes(), 5000)).unwrap();
        let id2 = match r2 {
            Outcome::BumpedLastSeen { id } => id,
            _ => panic!("expected BumpedLastSeen"),
        };
        assert_eq!(id1, id2);

        let rows = list(&p, 50).unwrap();
        assert_eq!(rows.len(), 1, "dedup must not add a row");
        assert_eq!(rows[0].created_at, 1000, "created_at preserved");
        assert_eq!(rows[0].last_seen, 5000, "last_seen bumped");
    }

    #[test]
    fn list_respects_limit() {
        let (_d, p) = fixture();
        for i in 0..10 {
            let s = format!("line-{i}");
            let h = blake3::hash(s.as_bytes());
            insert_or_bump(&p, &new_text(&s, h.as_bytes(), 1000 + i as i64)).unwrap();
        }
        assert_eq!(list(&p, 3).unwrap().len(), 3);
        assert_eq!(list(&p, 100).unwrap().len(), 10);
    }

    #[test]
    fn list_dedup_orders_by_last_seen() {
        let (_d, p) = fixture();
        let ha = blake3::hash(b"a");
        let hb = blake3::hash(b"b");
        insert_or_bump(&p, &new_text("a", ha.as_bytes(), 1000)).unwrap();
        insert_or_bump(&p, &new_text("b", hb.as_bytes(), 2000)).unwrap();
        // Re-copy "a" later — should float to the top.
        insert_or_bump(&p, &new_text("a", ha.as_bytes(), 3000)).unwrap();
        let rows = list(&p, 50).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].preview, "a");
        assert_eq!(rows[0].last_seen, 3000);
        assert_eq!(rows[1].preview, "b");
    }

    #[test]
    fn derive_preview_lowercases_and_collapses_newlines() {
        assert_eq!(derive_preview("Hello World"), "hello world");
        assert_eq!(derive_preview("Foo\nBar"), "foo bar");
        assert_eq!(derive_preview("Foo\r\nBar"), "foo  bar");
        assert_eq!(derive_preview("a\tb\x1bc"), "a b c");
    }

    #[test]
    fn derive_preview_truncates_at_200_chars() {
        let long: String = "a".repeat(300);
        assert_eq!(derive_preview(&long).chars().count(), 200);
    }
}
