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

use crate::daemon::clipboard_format::FormatPayload;
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
    /// Step 7: every clipboard format captured at copy time, in
    /// EnumClipboardFormats order. Empty slice = text-only legacy capture
    /// or pre-Step-7 row; promote falls back to the `set_text` path.
    pub formats: &'a [FormatPayload],
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

/// Result of [`get_decrypted`]: row metadata + canonical decrypted text +
/// every per-format payload captured at copy time (Step 7). `formats` is
/// empty for pre-Step-7 rows, in which case the IPC promote handler falls
/// back to the text-only `set_text` path.
pub struct DecryptedEntry {
    pub row: EntryRow,
    pub plaintext: Vec<u8>,
    pub formats: Vec<FormatPayload>,
}

/// Open the DB read-write, run all migrations (v1 DDL → v2 encryption sweep
/// → v3 child-table DDL), and return the connection. The vault is required
/// because v2 needs to encrypt any plaintext rows carried over from a v1 DB.
pub fn open_or_init(db_path: &Path, vault: &Vault) -> Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).context("creating db parent dir")?;
    }
    let mut conn = Connection::open(db_path).context("opening sqlite db")?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enabling WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("setting synchronous=NORMAL")?;
    // foreign_keys=ON is load-bearing for the v3 entry_formats ON DELETE
    // CASCADE — without it, deleting an entry would leave orphaned format
    // rows.
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("enabling foreign_keys")?;
    schema::run_all(&mut conn, vault).context("running schema migrations")?;
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
    let mut conn = open_or_init(db_path, vault)?;

    // Dedup is hash-on-canonical-text only (Step 2 design). If the same
    // text shows up later with a richer format set (e.g. first from
    // Notepad, then from Excel with HTML+RTF+Biff12), the existing row's
    // formats are kept. Re-capturing formats per dedup hit would be a
    // separate UX decision.
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

    let tx = conn.transaction().context("opening insert transaction")?;
    tx.execute(
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
    let id = tx.last_insert_rowid();

    // Step 7: per-format encrypted child rows. Each format gets a fresh
    // AES-GCM nonce — `Vault::encrypt` generates a fresh random nonce per
    // call, so reuse-across-formats is impossible.
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO entry_formats (entry_id, name, ord, ciphertext, nonce)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .context("prepare INSERT entry_formats")?;
        for (ord, fmt) in e.formats.iter().enumerate() {
            let (fnonce, fct) = vault
                .encrypt(&fmt.bytes)
                .with_context(|| format!("encrypting format {}", fmt.name))?;
            stmt.execute(params![id, &fmt.name, ord as i64, fct, fnonce])
                .with_context(|| format!("INSERT entry_formats row {}", fmt.name))?;
        }
    }

    tx.commit().context("commit insert transaction")?;
    Ok(Outcome::Inserted { id })
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

/// Fetch a single entry by id, returning the row metadata, its decrypted
/// canonical text content, and every per-format payload captured at copy
/// time (Step 7). Used by the IPC `Promote` handler.
///
/// The `formats` vector is empty for pre-Step-7 rows; the IPC handler
/// falls back to the text-only `set_text` path in that case.
pub fn get_decrypted(db_path: &Path, vault: &Vault, id: i64) -> Result<Option<DecryptedEntry>> {
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
    let Some((entry, ciphertext, nonce)) = row else {
        return Ok(None);
    };
    let plaintext = vault.decrypt(&nonce, &ciphertext)?;

    // Sibling query: every captured format, in capture order. The
    // `entry_formats` table may not exist on a v1/v2 DB opened in RO mode
    // (run_all only fires for RW opens) — but in practice anything that
    // calls get_decrypted has already opened RW elsewhere (the daemon
    // owns the writer), so the migration has run. If a tooling caller
    // ever opens RO before RW, add a CREATE-TABLE-IF-NOT-EXISTS guard
    // here; for v0.1, defer.
    let mut stmt = conn
        .prepare(
            "SELECT name, ciphertext, nonce
             FROM entry_formats
             WHERE entry_id = ?1
             ORDER BY ord",
        )
        .context("prepare SELECT entry_formats")?;
    let format_rows = stmt
        .query_map(params![entry.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .context("query entry_formats")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect entry_formats rows")?;

    let mut formats = Vec::with_capacity(format_rows.len());
    for (name, ct, fnonce) in format_rows {
        let bytes = vault
            .decrypt(&fnonce, &ct)
            .with_context(|| format!("decrypting format {name}"))?;
        formats.push(FormatPayload { name, bytes });
    }

    Ok(Some(DecryptedEntry {
        row: entry,
        plaintext,
        formats,
    }))
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
            formats: &[],
        }
    }

    fn new_text_with_formats<'a>(
        text: &'a str,
        hash: &'a [u8],
        t: i64,
        formats: &'a [FormatPayload],
    ) -> NewEntry<'a> {
        NewEntry {
            kind: "text",
            content: text.as_bytes(),
            hash,
            size_bytes: text.len(),
            created_at: t,
            preview: derive_preview(text),
            source_app: None,
            formats,
        }
    }

    #[test]
    fn open_and_migrate_creates_entries_and_entry_formats() {
        let f = fixture();
        let conn = open_or_init(&f.db, &f.vault).unwrap();
        let entries_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(entries_count, 1);
        let formats_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entry_formats'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            formats_count, 1,
            "v3 entry_formats child table should exist"
        );
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        // Empty DB jumps straight to v3 — v2 sweep is a no-op when there
        // are no plaintext rows, then v3 DDL creates entry_formats.
        assert_eq!(v, 3);
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
    fn migrate_v1_to_v3_encrypts_then_adds_entry_formats() {
        let f = fixture();
        // Stand up a v1 DB by hand: install only v1 DDL, then INSERT a
        // plaintext row with `nonce = x''` to mimic a pre-Step-4 DB.
        {
            let conn = Connection::open(&f.db).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            schema::install_v1_for_test(&conn).unwrap();
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

        // Re-open with `open_or_init` — the v2 sweep encrypts the row,
        // and the v3 DDL adds entry_formats.
        let _ = open_or_init(&f.db, &f.vault).unwrap();

        let conn = open_ro(&f.db).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 3, "must walk all the way to v3 in one open_or_init");
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

        // entry_formats table exists and is empty for the legacy row.
        let formats_table_exists: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='entry_formats'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(formats_table_exists, 1);
        let formats_for_row: i64 = conn
            .query_row("SELECT count(*) FROM entry_formats", [], |r| r.get(0))
            .unwrap();
        assert_eq!(formats_for_row, 0, "legacy row carries no captured formats");
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

    // ---- Step 7 multi-format tests ----

    fn fmt(name: &str, bytes: &[u8]) -> FormatPayload {
        FormatPayload {
            name: name.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn insert_with_formats_persists_to_child_table() {
        let f = fixture();
        let text = "from excel";
        let h = blake3::hash(text.as_bytes());
        let formats = [
            fmt("CF_UNICODETEXT", b"from excel\0"),
            fmt(
                "HTML Format",
                b"<table><tr><td>from excel</td></tr></table>",
            ),
            fmt("Rich Text Format", b"{\\rtf1 from excel}"),
        ];
        let outcome = insert_or_bump(
            &f.db,
            &f.vault,
            &new_text_with_formats(text, h.as_bytes(), 1000, &formats),
        )
        .unwrap();
        let id = match outcome {
            Outcome::Inserted { id } => id,
            _ => panic!("expected Inserted"),
        };

        let conn = open_ro(&f.db).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM entry_formats WHERE entry_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 3, "all three formats persisted");

        // Names are stored verbatim, ord is 0..N preserving capture order.
        let mut stmt = conn
            .prepare(
                "SELECT name, ord, length(ciphertext), length(nonce)
                 FROM entry_formats WHERE entry_id = ?1 ORDER BY ord",
            )
            .unwrap();
        let rows: Vec<(String, i64, i64, i64)> = stmt
            .query_map(params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows[0].0, "CF_UNICODETEXT");
        assert_eq!(rows[1].0, "HTML Format");
        assert_eq!(rows[2].0, "Rich Text Format");
        assert_eq!(rows[0].1, 0);
        assert_eq!(rows[1].1, 1);
        assert_eq!(rows[2].1, 2);
        for (name, _, ct_len, nonce_len) in &rows {
            assert_eq!(*nonce_len, 12, "{name}: 12-byte AES-GCM nonce");
            assert!(*ct_len >= 16, "{name}: ciphertext+tag at least GCM tag");
        }
    }

    #[test]
    fn get_decrypted_returns_formats_in_capture_order() {
        let f = fixture();
        let text = "ordered";
        let h = blake3::hash(text.as_bytes());
        let formats = [
            fmt("CF_UNICODETEXT", b"ordered\0"),
            fmt("HTML Format", b"<p>ordered</p>"),
            fmt("Csv", b"ordered"),
        ];
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text_with_formats(text, h.as_bytes(), 1000, &formats),
        )
        .unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        let d = get_decrypted(&f.db, &f.vault, id).unwrap().unwrap();
        let (plaintext, got_formats) = (d.plaintext, d.formats);
        assert_eq!(plaintext, b"ordered");
        assert_eq!(got_formats.len(), 3);
        assert_eq!(got_formats[0].name, "CF_UNICODETEXT");
        assert_eq!(got_formats[0].bytes, b"ordered\0");
        assert_eq!(got_formats[1].name, "HTML Format");
        assert_eq!(got_formats[1].bytes, b"<p>ordered</p>");
        assert_eq!(got_formats[2].name, "Csv");
        assert_eq!(got_formats[2].bytes, b"ordered");
    }

    #[test]
    fn get_decrypted_text_only_row_has_empty_formats() {
        let f = fixture();
        let text = "text only";
        let h = blake3::hash(text.as_bytes());
        insert_or_bump(&f.db, &f.vault, &new_text(text, h.as_bytes(), 1000)).unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        let d = get_decrypted(&f.db, &f.vault, id).unwrap().unwrap();
        let (plaintext, got_formats) = (d.plaintext, d.formats);
        assert_eq!(plaintext, b"text only");
        assert!(
            got_formats.is_empty(),
            "no formats stored = empty vec, not error"
        );
    }

    #[test]
    fn delete_cascades_to_entry_formats() {
        let f = fixture();
        let text = "doomed";
        let h = blake3::hash(text.as_bytes());
        let formats = [fmt("CF_UNICODETEXT", b"doomed\0"), fmt("Csv", b"doomed")];
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text_with_formats(text, h.as_bytes(), 1000, &formats),
        )
        .unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        // Sanity: child rows are present.
        let before: i64 = open_ro(&f.db)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM entry_formats WHERE entry_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, 2);

        assert!(delete(&f.db, &f.vault, id).unwrap());

        let after: i64 = open_ro(&f.db)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM entry_formats WHERE entry_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            after, 0,
            "ON DELETE CASCADE must remove orphaned format rows"
        );
    }

    #[test]
    fn dedup_preserves_existing_formats() {
        let f = fixture();
        let text = "twice";
        let h = blake3::hash(text.as_bytes());
        // First copy: rich formats from "Excel".
        let rich = [
            fmt("CF_UNICODETEXT", b"twice\0"),
            fmt("HTML Format", b"<i>twice</i>"),
        ];
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text_with_formats(text, h.as_bytes(), 1000, &rich),
        )
        .unwrap();
        // Second copy: text-only from "Notepad". Same hash → dedup.
        // Existing formats must NOT be overwritten or duplicated.
        let outcome = insert_or_bump(&f.db, &f.vault, &new_text(text, h.as_bytes(), 5000)).unwrap();
        assert!(matches!(outcome, Outcome::BumpedLastSeen { .. }));

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        let count: i64 = open_ro(&f.db)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM entry_formats WHERE entry_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 2,
            "dedup leaves the original two formats intact, no duplicates"
        );
    }

    #[test]
    fn insert_with_formats_is_atomic() {
        // If a format-row insert fails mid-transaction, the parent entry
        // must roll back too. We can't easily make the format insert fail
        // without mocking; instead, verify the happy path commits both.
        let f = fixture();
        let text = "atomic";
        let h = blake3::hash(text.as_bytes());
        let formats = [fmt("CF_UNICODETEXT", b"atomic\0")];
        insert_or_bump(
            &f.db,
            &f.vault,
            &new_text_with_formats(text, h.as_bytes(), 1000, &formats),
        )
        .unwrap();

        let conn = open_ro(&f.db).unwrap();
        let entries: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .unwrap();
        let formats_n: i64 = conn
            .query_row("SELECT count(*) FROM entry_formats", [], |r| r.get(0))
            .unwrap();
        assert_eq!(entries, 1);
        assert_eq!(formats_n, 1);
    }
}
