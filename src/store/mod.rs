//! SQLite-backed clipboard entry store.
//!
//! Surface:
//!   - `insert_or_bump` — write path with blake3 dedup. Encrypts `content`
//!     with the process [`Vault`] before insert.
//!   - `list`           — read path for `clipd list`. Does not touch
//!     ciphertext — only `preview`, which is plaintext by design (Step 9
//!     FTS5 indexes it).
//!   - `open_or_init`   — connect, run schema migrations, run the v2
//!     encryption sweep against any plaintext rows left from v1 DBs.
//!
//! WAL journal mode lets the daemon's writer coexist with read-only handles
//! opened by short-lived `clipd list` invocations. Step 5 will replace the
//! direct-DB read path with named-pipe IPC.

pub mod crypto;
mod schema;

use crate::store::crypto::Vault;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
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
    pub created_at: i64,
    pub last_seen: i64,
    pub kind: String,
    pub preview: String,
    pub pinned: bool,
    // size_bytes: surfaced for Step 12 (retention purge) and Step 13 (doctor stats).
    #[allow(dead_code)]
    pub size_bytes: i64,
}

/// Open the DB read-write, run all migrations (DDL + crypto sweep), and
/// return the connection. The vault is required because v2 needs to encrypt
/// any plaintext rows carried over from a v1 DB.
pub fn open_or_init(db_path: &Path, vault: &Vault) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).context("creating db parent dir")?;
    }
    let mut conn = Connection::open(db_path).context("opening sqlite db")?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous=NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("enabling foreign_keys")?;
    schema::migrate(&conn).context("running DDL migrations")?;
    schema::migrate_v2_encryption(&mut conn, vault).context("running v2 encryption migration")?;
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

pub fn insert_or_bump(db_path: &Path, vault: &Vault, e: &NewEntry) -> Result<Outcome> {
    let conn = open_or_init(db_path, vault)?;

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

    let (nonce, ciphertext) = vault.encrypt(e.content).context("encrypting content")?;

    conn.execute(
        "INSERT INTO entries
            (created_at, last_seen, kind, content, nonce, preview,
             source_app, pinned, sensitive, hash, size_bytes, formats)
         VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7, ?8, NULL)",
        params![
            e.created_at,
            e.kind,
            ciphertext,
            nonce,
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
    // a better UX than an error. `list` does not need a Vault — `content` and
    // `nonce` are not in the projection.
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

/// Substring search over `preview` for Step 5 IPC. FTS5 lands in Step 9 — this
/// is intentionally a `LIKE` scan. Previews are stored lowercased ([`derive_preview`]),
/// so the query is lowercased before binding to keep the match case-insensitive.
pub fn search(db_path: &Path, query: &str, limit: usize) -> Result<Vec<EntryRow>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = open_ro(db_path)?;
    let needle = query.to_lowercase();
    let mut stmt = conn
        .prepare(
            "SELECT id, created_at, last_seen, kind, preview, pinned, size_bytes
             FROM entries
             WHERE preview LIKE '%' || ?1 || '%'
             ORDER BY last_seen DESC
             LIMIT ?2",
        )
        .context("preparing search statement")?;
    let rows = stmt
        .query_map(params![needle, limit as i64], |r| {
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
        .context("executing search query")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collecting search rows")
}

/// Fetch a single entry by id, returning the row metadata and its decrypted
/// content. Used by the IPC `Promote` handler.
pub fn get_decrypted(
    db_path: &Path,
    vault: &Vault,
    id: i64,
) -> Result<Option<(EntryRow, Vec<u8>)>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_ro(db_path)?;
    let row = conn
        .query_row(
            "SELECT id, created_at, last_seen, kind, preview, pinned, size_bytes, content, nonce
             FROM entries WHERE id = ?1",
            params![id],
            |r| {
                let entry = EntryRow {
                    id: r.get(0)?,
                    created_at: r.get(1)?,
                    last_seen: r.get(2)?,
                    kind: r.get(3)?,
                    preview: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    pinned: r.get::<_, i64>(5)? != 0,
                    size_bytes: r.get(6)?,
                };
                let content: Vec<u8> = r.get(7)?;
                let nonce: Vec<u8> = r.get(8)?;
                Ok((entry, content, nonce))
            },
        )
        .optional()
        .context("get_decrypted query")?;
    match row {
        None => Ok(None),
        Some((entry, ciphertext, nonce)) => {
            let plaintext = vault.decrypt(&nonce, &ciphertext)?;
            Ok(Some((entry, plaintext)))
        }
    }
}

/// Delete an entry by id. Returns `true` if a row was removed.
pub fn delete(db_path: &Path, vault: &Vault, id: i64) -> Result<bool> {
    let conn = open_or_init(db_path, vault)?;
    let n = conn
        .execute("DELETE FROM entries WHERE id = ?1", params![id])
        .context("DELETE entries")?;
    Ok(n > 0)
}

/// Set or clear the `pinned` flag. Returns `true` if a row matched.
pub fn set_pinned(db_path: &Path, vault: &Vault, id: i64, pinned: bool) -> Result<bool> {
    let conn = open_or_init(db_path, vault)?;
    let n = conn
        .execute(
            "UPDATE entries SET pinned = ?1 WHERE id = ?2",
            params![pinned as i64, id],
        )
        .context("UPDATE entries.pinned")?;
    Ok(n > 0)
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

    struct Fix {
        _dir: TempDir,
        db: std::path::PathBuf,
        vault: Vault,
    }

    fn fixture() -> Fix {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("test.db");
        let key = dir.path().join("k.dpapi");
        let vault = Vault::open(&key).unwrap();
        Fix {
            _dir: dir,
            db,
            vault,
        }
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
        let f = fixture();
        let conn = open_or_init(&f.db, &f.vault).unwrap();
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
        // Empty DB jumps straight to v2 since the v2 sweep is a no-op when
        // there are no plaintext rows.
        assert_eq!(v, 2);
    }

    #[test]
    fn migrate_is_idempotent() {
        let f = fixture();
        let _ = open_or_init(&f.db, &f.vault).unwrap();
        let _ = open_or_init(&f.db, &f.vault).unwrap();
        let _ = open_or_init(&f.db, &f.vault).unwrap();
    }

    #[test]
    fn insert_then_list_roundtrip() {
        let f = fixture();
        let h1 = blake3::hash(b"alpha");
        let h2 = blake3::hash(b"bravo");
        let h3 = blake3::hash(b"charlie");
        insert_or_bump(&f.db, &f.vault, &new_text("alpha", h1.as_bytes(), 1000)).unwrap();
        insert_or_bump(&f.db, &f.vault, &new_text("bravo", h2.as_bytes(), 2000)).unwrap();
        insert_or_bump(&f.db, &f.vault, &new_text("charlie", h3.as_bytes(), 3000)).unwrap();

        let rows = list(&f.db, 50).unwrap();
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
        let f = fixture();
        let h = blake3::hash(b"once");
        let r1 = insert_or_bump(&f.db, &f.vault, &new_text("once", h.as_bytes(), 1000)).unwrap();
        let id1 = match r1 {
            Outcome::Inserted { id } => id,
            _ => panic!("expected Inserted"),
        };
        let r2 = insert_or_bump(&f.db, &f.vault, &new_text("once", h.as_bytes(), 5000)).unwrap();
        let id2 = match r2 {
            Outcome::BumpedLastSeen { id } => id,
            _ => panic!("expected BumpedLastSeen"),
        };
        assert_eq!(id1, id2);

        let rows = list(&f.db, 50).unwrap();
        assert_eq!(rows.len(), 1, "dedup must not add a row");
        assert_eq!(rows[0].created_at, 1000, "created_at preserved");
        assert_eq!(rows[0].last_seen, 5000, "last_seen bumped");
    }

    #[test]
    fn list_respects_limit() {
        let f = fixture();
        for i in 0..10 {
            let s = format!("line-{i}");
            let h = blake3::hash(s.as_bytes());
            insert_or_bump(
                &f.db,
                &f.vault,
                &new_text(&s, h.as_bytes(), 1000 + i as i64),
            )
            .unwrap();
        }
        assert_eq!(list(&f.db, 3).unwrap().len(), 3);
        assert_eq!(list(&f.db, 100).unwrap().len(), 10);
    }

    #[test]
    fn list_dedup_orders_by_last_seen() {
        let f = fixture();
        let ha = blake3::hash(b"a");
        let hb = blake3::hash(b"b");
        insert_or_bump(&f.db, &f.vault, &new_text("a", ha.as_bytes(), 1000)).unwrap();
        insert_or_bump(&f.db, &f.vault, &new_text("b", hb.as_bytes(), 2000)).unwrap();
        // Re-copy "a" later — should float to the top.
        insert_or_bump(&f.db, &f.vault, &new_text("a", ha.as_bytes(), 3000)).unwrap();
        let rows = list(&f.db, 50).unwrap();
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

    // ---- Step 4 encryption tests ----

    #[test]
    fn encrypt_on_insert() {
        let f = fixture();
        let plaintext = b"super secret clipboard payload";
        let h = blake3::hash(plaintext);
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text(std::str::from_utf8(plaintext).unwrap(), h.as_bytes(), 1000),
        )
        .unwrap();

        let conn = open_ro(&f.db).unwrap();
        let (content, nonce): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT content, nonce FROM entries LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_ne!(content.as_slice(), plaintext, "content must be ciphertext");
        assert_eq!(nonce.len(), 12, "AES-GCM nonce is 12 bytes");
        assert!(
            content.len() >= plaintext.len() + 16,
            "ciphertext+tag must be at least plaintext + 16-byte GCM tag"
        );
    }

    #[test]
    fn decrypt_roundtrip() {
        let f = fixture();
        let plaintext = b"roundtrip me";
        let h = blake3::hash(plaintext);
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text(std::str::from_utf8(plaintext).unwrap(), h.as_bytes(), 1000),
        )
        .unwrap();

        let conn = open_ro(&f.db).unwrap();
        let (content, nonce): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT content, nonce FROM entries LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let recovered = f.vault.decrypt(&nonce, &content).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn migrate_v1_to_v2_encrypts_existing_rows() {
        let f = fixture();
        // Stand up a v1 DB by hand: run only the DDL migrations, then INSERT
        // a plaintext row with `nonce = x''` to mimic a pre-Step-4 DB.
        {
            let conn = Connection::open(&f.db).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            schema::migrate(&conn).unwrap();
            // Schema migrate moved us to v1. Force back to v1 just to be
            // explicit about the test's starting state.
            conn.execute_batch("PRAGMA user_version = 1").unwrap();
            let plaintext = b"legacy plaintext row";
            let h = blake3::hash(plaintext);
            conn.execute(
                "INSERT INTO entries
                    (created_at, last_seen, kind, content, nonce, preview,
                     source_app, pinned, sensitive, hash, size_bytes, formats)
                 VALUES (?1, ?1, 'text', ?2, x'', ?3, NULL, 0, 0, ?4, ?5, NULL)",
                params![
                    1000_i64,
                    plaintext.as_slice(),
                    "legacy plaintext row",
                    h.as_bytes(),
                    plaintext.len() as i64,
                ],
            )
            .unwrap();
        }

        // Re-open with `open_or_init` — the v2 sweep should encrypt the row.
        let _ = open_or_init(&f.db, &f.vault).unwrap();

        let conn = open_ro(&f.db).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
        let (content, nonce): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT content, nonce FROM entries LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(nonce.len(), 12, "v2 sweep must stamp a 12-byte nonce");
        assert_ne!(
            content.as_slice(),
            b"legacy plaintext row".as_slice(),
            "v2 sweep must replace plaintext with ciphertext"
        );
        let recovered = f.vault.decrypt(&nonce, &content).unwrap();
        assert_eq!(recovered.as_slice(), b"legacy plaintext row");
    }

    #[test]
    fn dedup_still_works_under_encryption() {
        let f = fixture();
        let plaintext = "duplicate me";
        let h = blake3::hash(plaintext.as_bytes());
        let r1 = insert_or_bump(&f.db, &f.vault, &new_text(plaintext, h.as_bytes(), 1000)).unwrap();
        let id1 = match r1 {
            Outcome::Inserted { id } => id,
            _ => panic!("first insert should be Inserted"),
        };
        // Second insert: same plaintext → same blake3 → dedup. Note the new
        // call would otherwise produce a fresh nonce + ciphertext, but the
        // hash-based dedup short-circuits before encryption.
        let r2 = insert_or_bump(&f.db, &f.vault, &new_text(plaintext, h.as_bytes(), 5000)).unwrap();
        let id2 = match r2 {
            Outcome::BumpedLastSeen { id } => id,
            _ => panic!("second insert should be BumpedLastSeen"),
        };
        assert_eq!(id1, id2);

        // Confirm exactly one row, last_seen bumped, content still decrypts.
        let conn = open_ro(&f.db).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let (content, nonce, last_seen): (Vec<u8>, Vec<u8>, i64) = conn
            .query_row(
                "SELECT content, nonce, last_seen FROM entries LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(last_seen, 5000);
        let recovered = f.vault.decrypt(&nonce, &content).unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_bytes());
    }
}
