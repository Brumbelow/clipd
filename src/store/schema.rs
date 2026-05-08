//! Schema migrations. Versioned via SQLite's `user_version` pragma.
//!
//! v1: base `entries` table + dedup/last_seen indexes.
//! v2: encrypt any plaintext `content` left over from v1 with the process
//!   Vault and stamp a fresh nonce. The schema itself does not change; only
//!   values do.
//! v3: per-format encrypted payloads in `entry_formats` child table. The
//!   unused `formats TEXT` column on `entries` stays in place — `DROP
//!   COLUMN`'s risk isn't worth it, and queries ignore it.
//! v4: `idx_created` index over `entries.created_at DESC`. Lets the
//!   `:today`/`:7d`/`>YYYY-MM-DD` predicates short-circuit the LIKE scan on
//!   anything but the smallest databases.
//! v5: `content_kind` column for the content-shape taxonomy
//!   (`url|json|hex|base64|code|text`). DDL adds the column with default
//!   `'text'`; the data step decrypts every existing text row and stamps
//!   the classifier's verdict so older rows badge correctly without waiting
//!   on a re-capture.
//!
//! Migrations are version-anchored, not index-anchored, because v2 is a
//! data-only step that needs the [`Vault`] — interleaving DDL and data
//! across versions cleanly requires walking the version list explicitly
//! rather than using a slice index.

use crate::store::crypto::Vault;
use anyhow::Result;
use rusqlite::{params, Connection};

const V1_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS entries (
        id          INTEGER PRIMARY KEY,
        created_at  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        kind        TEXT    NOT NULL,
        content     BLOB    NOT NULL,
        nonce       BLOB    NOT NULL,
        preview     TEXT,
        source_app  TEXT,
        pinned      INTEGER NOT NULL DEFAULT 0,
        sensitive   INTEGER NOT NULL DEFAULT 0,
        hash        BLOB    NOT NULL,
        size_bytes  INTEGER NOT NULL,
        formats     TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_hash      ON entries(hash);
    CREATE INDEX        IF NOT EXISTS idx_last_seen ON entries(last_seen DESC);
"#;

const V3_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS entry_formats (
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
"#;

const V4_DDL: &str = r#"
    CREATE INDEX IF NOT EXISTS idx_created ON entries(created_at DESC);
"#;

const V5_DDL: &str = r#"
    ALTER TABLE entries ADD COLUMN content_kind TEXT NOT NULL DEFAULT 'text';
"#;

/// Run every migration the DB needs to reach the current schema version,
/// in order. Idempotent — safe to call on a fresh DB, on a v1 DB with
/// plaintext rows, on a v2 DB, or on an already-current v3 DB.
///
/// The v2 step is the only one that touches row data (decrypts/re-encrypts
/// via [`Vault`]) and runs in a single transaction so a crash mid-sweep
/// leaves the DB consistent.
pub fn run_all(conn: &mut Connection, vault: &Vault) -> Result<()> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if v < 1 {
        conn.execute_batch(V1_DDL)?;
        conn.execute_batch("PRAGMA user_version = 1")?;
    }
    if v < 2 {
        encrypt_v1_plaintext(conn, vault)?;
        // The encryption sweep commits PRAGMA user_version = 2 inside its
        // transaction so the version stamp and the encrypted rows land
        // atomically.
    }
    if v < 3 {
        conn.execute_batch(V3_DDL)?;
        conn.execute_batch("PRAGMA user_version = 3")?;
    }
    if v < 4 {
        conn.execute_batch(V4_DDL)?;
        conn.execute_batch("PRAGMA user_version = 4")?;
    }
    if v < 5 {
        conn.execute_batch(V5_DDL)?;
        backfill_content_kind(conn, vault)?;
        // backfill_content_kind commits PRAGMA user_version = 5 inside its
        // transaction so the version stamp and the backfilled rows land
        // atomically.
    }
    Ok(())
}

/// v5 data migration: walk every `kind == 'text'` row, decrypt the
/// canonical content with the [`Vault`], run the content-shape classifier,
/// and stamp `content_kind`. Image/files rows keep the column default
/// (`'text'`) — the picker badge logic ignores `content_kind` for non-text
/// `kind`s.
fn backfill_content_kind(conn: &mut Connection, vault: &Vault) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("SELECT id, content, nonce FROM entries WHERE kind = 'text'")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        let mut update = tx.prepare("UPDATE entries SET content_kind = ?1 WHERE id = ?2")?;
        let count = rows.len();
        for (id, ciphertext, nonce) in rows {
            let plaintext = vault.decrypt(&nonce, &ciphertext)?;
            if let Ok(text) = std::str::from_utf8(&plaintext) {
                let kind = crate::classify::classify(text);
                update.execute(params![kind.as_str(), id])?;
            }
        }
        drop(update);

        if count > 0 {
            tracing::info!(count, "v5 migration: backfilled content_kind");
        }
    }
    tx.execute_batch("PRAGMA user_version = 5")?;
    tx.commit()?;
    Ok(())
}

/// v2 data migration: encrypt any plaintext rows left from a v1 DB.
/// Caller is `run_all`; not exposed because correctness depends on running
/// inside the version-walk.
fn encrypt_v1_plaintext(conn: &mut Connection, vault: &Vault) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("SELECT id, content FROM entries WHERE length(nonce) = 0")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        let mut update = tx.prepare("UPDATE entries SET content = ?1, nonce = ?2 WHERE id = ?3")?;
        let count = rows.len();
        for (id, plaintext) in rows {
            let (nonce, ciphertext) = vault.encrypt(&plaintext)?;
            update.execute(params![ciphertext, nonce, id])?;
        }
        drop(update);

        if count > 0 {
            tracing::info!(count, "v2 migration: encrypted plaintext rows");
        }
    }
    tx.execute_batch("PRAGMA user_version = 2")?;
    tx.commit()?;
    Ok(())
}

/// Test-only helper to stand up a bare v1 DB. The production path is
/// [`run_all`]; tests need this to verify the v1→v2/v3 migration story.
#[cfg(test)]
pub(crate) fn install_v1_for_test(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(V1_DDL)?;
    conn.execute_batch("PRAGMA user_version = 1")?;
    Ok(())
}
