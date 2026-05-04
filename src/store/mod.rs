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
use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Step 9: a date predicate applied to `entries.created_at` before the
/// text search runs. Bounds are unix-milliseconds. Constructed by
/// `picker::query::parse` from `:today`-style tokens, serialized over IPC,
/// and consumed by [`search`] as `WHERE created_at` clauses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DateFilter {
    /// `created_at >= ts`
    After(i64),
    /// `created_at < ts`
    Before(i64),
    /// `start <= created_at < end`
    Range { start: i64, end: i64 },
}

pub struct NewEntry<'a> {
    pub kind: &'a str,
    /// Step 10: content-shape kind (`url|json|hex|base64|code|text`).
    /// Pass `"text"` for image/files captures — picker badge logic falls
    /// back to `kind` when content_kind isn't meaningful.
    pub content_kind: &'a str,
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
    /// Step 10: content-shape kind. See `crate::classify::ContentKind`.
    pub content_kind: String,
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
            (created_at, last_seen, kind, content_kind, content, nonce, preview,
             source_app, pinned, sensitive, hash, size_bytes, formats)
         VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, ?9, NULL)",
        params![
            e.created_at,
            e.kind,
            e.content_kind,
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
            "SELECT id, created_at, last_seen, kind, content_kind, preview, pinned, size_bytes
             FROM entries
             ORDER BY pinned DESC, last_seen DESC
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
                content_kind: r.get(4)?,
                preview: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                pinned: r.get::<_, i64>(6)? != 0,
                size_bytes: r.get(7)?,
            })
        })
        .context("executing list query")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collecting list rows")
}

/// Substring search over `preview` for Step 5 IPC. Step 9 layered on the
/// `DateFilter` predicates and pinned-first ordering; the text matcher
/// itself is still a `LIKE` scan (FTS5 deferred — adequate up to ~10k rows).
/// Previews are stored lowercased ([`derive_preview`]), so the needle is
/// lowercased before binding to keep the match case-insensitive.
///
/// Pass `&[]` for `filters` to skip date predicates. An empty `query`
/// combined with non-empty `filters` (e.g. `:today` with no search term)
/// is the documented case for date-only browsing.
pub fn search(
    db_path: &Path,
    query: &str,
    filters: &[DateFilter],
    limit: usize,
) -> Result<Vec<EntryRow>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = open_ro(db_path)?;

    let mut sql = String::from(
        "SELECT id, created_at, last_seen, kind, content_kind, preview, pinned, size_bytes \
         FROM entries WHERE 1=1",
    );
    let mut binds: Vec<Value> = Vec::new();

    let needle = query.to_lowercase();
    if !needle.is_empty() {
        sql.push_str(" AND preview LIKE '%' || ? || '%'");
        binds.push(Value::Text(needle));
    }
    for f in filters {
        match f {
            DateFilter::After(ts) => {
                sql.push_str(" AND created_at >= ?");
                binds.push(Value::Integer(*ts));
            }
            DateFilter::Before(ts) => {
                sql.push_str(" AND created_at < ?");
                binds.push(Value::Integer(*ts));
            }
            DateFilter::Range { start, end } => {
                sql.push_str(" AND created_at >= ? AND created_at < ?");
                binds.push(Value::Integer(*start));
                binds.push(Value::Integer(*end));
            }
        }
    }
    sql.push_str(" ORDER BY pinned DESC, last_seen DESC LIMIT ?");
    binds.push(Value::Integer(limit as i64));

    let mut stmt = conn.prepare(&sql).context("preparing search statement")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(EntryRow {
                id: r.get(0)?,
                created_at: r.get(1)?,
                last_seen: r.get(2)?,
                kind: r.get(3)?,
                content_kind: r.get(4)?,
                preview: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                pinned: r.get::<_, i64>(6)? != 0,
                size_bytes: r.get(7)?,
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
            "SELECT id, created_at, last_seen, kind, content_kind, preview, pinned,
                    size_bytes, content, nonce
             FROM entries WHERE id = ?1",
            params![id],
            |r| {
                let entry = EntryRow {
                    id: r.get(0)?,
                    created_at: r.get(1)?,
                    last_seen: r.get(2)?,
                    kind: r.get(3)?,
                    content_kind: r.get(4)?,
                    preview: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    pinned: r.get::<_, i64>(6)? != 0,
                    size_bytes: r.get(7)?,
                };
                let content: Vec<u8> = r.get(8)?;
                let nonce: Vec<u8> = r.get(9)?;
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

/// Step 8: fetch and decrypt the `clipd:png_thumb` payload for an entry,
/// if any. Returns `Ok(None)` for entries that have no thumbnail (text
/// rows, images whose DIB couldn't be decoded for thumbnail generation).
pub fn get_thumbnail(db_path: &Path, vault: &Vault, id: i64) -> Result<Option<Vec<u8>>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = open_ro(db_path)?;
    let row = conn
        .query_row(
            "SELECT ciphertext, nonce
             FROM entry_formats
             WHERE entry_id = ?1 AND name = 'clipd:png_thumb'",
            params![id],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .context("get_thumbnail query")?;
    match row {
        None => Ok(None),
        Some((ciphertext, nonce)) => {
            let png = vault
                .decrypt(&nonce, &ciphertext)
                .context("decrypting thumbnail")?;
            Ok(Some(png))
        }
    }
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
            content_kind: "text",
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
            content_kind: "text",
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
        // Empty DB walks all migrations: v2 sweep is a no-op (no plaintext
        // rows), v3 creates entry_formats, v4 adds idx_created.
        assert_eq!(v, 5);
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
        // the v3 DDL adds entry_formats, the v4 DDL adds idx_created.
        let _ = open_or_init(&f.db, &f.vault).unwrap();

        let conn = open_ro(&f.db).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 5, "must walk all the way to v5 in one open_or_init");
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

    // ---- Step 8 thumbnail tests ----

    #[test]
    fn get_thumbnail_returns_decrypted_bytes() {
        let f = fixture();
        let dib = b"fake-dib-bytes";
        let h = blake3::hash(dib);
        let png = b"\x89PNG\r\n\x1a\nthumb-bytes".to_vec();
        let formats = [fmt("clipd:png_thumb", &png)];
        insert_or_bump(
            &f.db,
            &f.vault,
            &NewEntry {
                kind: "image",
                content_kind: "text",
                content: dib,
                hash: h.as_bytes(),
                size_bytes: dib.len(),
                created_at: 1000,
                preview: "image (1x1)".into(),
                source_app: None,
                formats: &formats,
            },
        )
        .unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        let recovered = get_thumbnail(&f.db, &f.vault, id)
            .unwrap()
            .expect("thumb should be present");
        assert_eq!(recovered, png);
    }

    #[test]
    fn get_thumbnail_returns_none_for_text_row() {
        let f = fixture();
        let h = blake3::hash(b"plain text");
        insert_or_bump(&f.db, &f.vault, &new_text("plain text", h.as_bytes(), 1000)).unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        let result = get_thumbnail(&f.db, &f.vault, id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_thumbnail_returns_none_for_unknown_id() {
        let f = fixture();
        // Create the DB so the path exists.
        let _ = open_or_init(&f.db, &f.vault).unwrap();

        let result = get_thumbnail(&f.db, &f.vault, 999_999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_thumbnail_skips_other_clipd_internal_rows() {
        // An image row with `clipd:png_full` but no `clipd:png_thumb`
        // should return None — get_thumbnail filters strictly by name.
        let f = fixture();
        let dib = b"another-fake-dib";
        let h = blake3::hash(dib);
        let formats = [fmt("clipd:png_full", b"big png blob")];
        insert_or_bump(
            &f.db,
            &f.vault,
            &NewEntry {
                kind: "image",
                content_kind: "text",
                content: dib,
                hash: h.as_bytes(),
                size_bytes: dib.len(),
                created_at: 1000,
                preview: "image (2x2)".into(),
                source_app: None,
                formats: &formats,
            },
        )
        .unwrap();

        let id: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row("SELECT id FROM entries LIMIT 1", [], |r| r.get(0))
            .unwrap();

        assert!(get_thumbnail(&f.db, &f.vault, id).unwrap().is_none());
    }

    // ---- Step 9: search with date filters ----

    fn insert_at(f: &Fix, text: &str, t: i64) {
        let h = blake3::hash(text.as_bytes());
        insert_or_bump(&f.db, &f.vault, &new_text(text, h.as_bytes(), t)).unwrap();
    }

    #[test]
    fn search_no_filters_matches_all_with_text() {
        let f = fixture();
        insert_at(&f, "alpha", 1000);
        insert_at(&f, "bravo alpha", 2000);
        insert_at(&f, "charlie", 3000);

        let rows = search(&f.db, "alpha", &[], 50).unwrap();
        assert_eq!(rows.len(), 2);
        // Pinned-first then last_seen DESC: "bravo alpha" (newer) before "alpha".
        assert_eq!(rows[0].preview, "bravo alpha");
        assert_eq!(rows[1].preview, "alpha");
    }

    #[test]
    fn search_after_filter_excludes_old_rows() {
        let f = fixture();
        insert_at(&f, "old kubectl", 1_000_000);
        insert_at(&f, "new kubectl", 5_000_000);

        let rows = search(&f.db, "kubectl", &[DateFilter::After(3_000_000)], 50).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].preview, "new kubectl");
    }

    #[test]
    fn search_before_filter_excludes_recent_rows() {
        let f = fixture();
        insert_at(&f, "old kubectl", 1_000_000);
        insert_at(&f, "new kubectl", 5_000_000);

        let rows = search(&f.db, "kubectl", &[DateFilter::Before(3_000_000)], 50).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].preview, "old kubectl");
    }

    #[test]
    fn search_range_filter_brackets_window() {
        let f = fixture();
        insert_at(&f, "before", 500);
        insert_at(&f, "inside", 1500);
        insert_at(&f, "after", 2500);

        let rows = search(
            &f.db,
            "",
            &[DateFilter::Range {
                start: 1000,
                end: 2000,
            }],
            50,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].preview, "inside");
    }

    #[test]
    fn search_filters_only_no_text_returns_filtered_rows() {
        // The `:today` with no search term case — empty `query`, filters
        // do all the narrowing.
        let f = fixture();
        insert_at(&f, "yesterday", 1000);
        insert_at(&f, "today-a", 5000);
        insert_at(&f, "today-b", 5500);

        let rows = search(&f.db, "", &[DateFilter::After(3000)], 50).unwrap();
        assert_eq!(rows.len(), 2);
    }

    // ---- Step 10: content_kind + pinned-first list ----

    #[test]
    fn list_pinned_floats_to_top() {
        // Step 10's list() now applies `ORDER BY pinned DESC, last_seen DESC`,
        // so an older pinned row outranks newer unpinned rows even with no
        // search query (where the picker's fuzzy_rank early-returns without
        // a pin tiebreaker).
        let f = fixture();
        insert_at(&f, "old-pin", 1000);
        insert_at(&f, "newer", 5000);
        insert_at(&f, "newest", 9000);

        let id_old: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row(
                "SELECT id FROM entries WHERE preview = ?1",
                params!["old-pin"],
                |r| r.get(0),
            )
            .unwrap();
        set_pinned(&f.db, &f.vault, id_old, true).unwrap();

        let rows = list(&f.db, 50).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].preview, "old-pin");
        assert!(rows[0].pinned);
    }

    #[test]
    fn capture_records_content_kind() {
        let f = fixture();
        // Insert via NewEntry directly with the content_kind the daemon
        // would have derived. Verify the column round-trips.
        let url = "https://example.com/path";
        let h = blake3::hash(url.as_bytes());
        insert_or_bump(
            &f.db,
            &f.vault,
            &NewEntry {
                kind: "text",
                content_kind: "url",
                content: url.as_bytes(),
                hash: h.as_bytes(),
                size_bytes: url.len(),
                created_at: 1000,
                preview: derive_preview(url),
                source_app: None,
                formats: &[],
            },
        )
        .unwrap();

        let rows = list(&f.db, 50).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content_kind, "url");
    }

    #[test]
    fn migrate_v3_to_v5_backfills_content_kind() {
        // Stand up a v3 DB by hand: install v1 DDL, then v3 DDL (entry_formats),
        // and stamp user_version = 3. Insert a row with NO content_kind column
        // and an encrypted URL payload (so v2 sweep is a no-op). Re-open via
        // open_or_init: v4 adds idx_created, v5 adds the column AND backfills
        // via the classifier.
        let f = fixture();
        let url = "https://example.com/foo";
        let h = blake3::hash(url.as_bytes());
        {
            let conn = Connection::open(&f.db).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            schema::install_v1_for_test(&conn).unwrap();
            // Encrypt the row content so the v2 sweep is a no-op (it only
            // touches rows with empty nonce).
            let (nonce, ciphertext) = f.vault.encrypt(url.as_bytes()).unwrap();
            conn.execute(
                "INSERT INTO entries
                    (created_at, last_seen, kind, content, nonce, preview,
                     source_app, pinned, sensitive, hash, size_bytes, formats)
                 VALUES (?1, ?1, 'text', ?2, ?3, ?4, NULL, 0, 0, ?5, ?6, NULL)",
                params![
                    1000_i64,
                    ciphertext,
                    nonce,
                    url,
                    h.as_bytes(),
                    url.len() as i64,
                ],
            )
            .unwrap();
            // Run v3 DDL by hand and stamp user_version = 3.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS entry_formats (
                    entry_id    INTEGER NOT NULL,
                    name        TEXT    NOT NULL,
                    ord         INTEGER NOT NULL,
                    ciphertext  BLOB    NOT NULL,
                    nonce       BLOB    NOT NULL,
                    PRIMARY KEY (entry_id, name),
                    FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS idx_entry_formats_entry_id
                    ON entry_formats(entry_id);
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        }

        // Re-open with the production migrator. v4 + v5 both run.
        let _ = open_or_init(&f.db, &f.vault).unwrap();

        let rows = list(&f.db, 50).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].content_kind, "url",
            "v5 backfill must classify the URL row from its decrypted content"
        );
    }

    #[test]
    fn search_pinned_floats_to_top() {
        // Step 9 query rewrite includes `ORDER BY pinned DESC, last_seen DESC`.
        // An older pinned row should outrank a newer unpinned row.
        let f = fixture();
        insert_at(&f, "old pinned needle", 1000);
        insert_at(&f, "new unpinned needle", 9000);

        let id_old: i64 = Connection::open(&f.db)
            .unwrap()
            .query_row(
                "SELECT id FROM entries WHERE preview = ?1",
                params!["old pinned needle"],
                |r| r.get(0),
            )
            .unwrap();
        set_pinned(&f.db, &f.vault, id_old, true).unwrap();

        let rows = search(&f.db, "needle", &[], 50).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].preview, "old pinned needle");
        assert!(rows[0].pinned);
    }
}
