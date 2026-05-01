//! Schema migrations. Versioned via SQLite's `user_version` pragma.
//!
//! v1 (Step 2): base `entries` table + dedup/last_seen indexes.
//! v2 (Step 4): encrypt any plaintext `content` left over from v1 with the
//!   process Vault and stamp a fresh nonce. The schema itself does not change;
//!   only values do.
//!
//! Deferred to later steps:
//!   - FTS5 virtual table (Step 5/9)
//!   - `idx_created` (Step 9 date filtering)

use crate::store::crypto::Vault;
use rusqlite::{params, Connection};

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
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
    "#,
];

/// Run all pure-DDL migrations. Idempotent. Does not touch row data —
/// crypto-aware migrations live in `migrate_v2_encryption`.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let target = (i as i64) + 1;
        if v < target {
            conn.execute_batch(sql)?;
            conn.execute_batch(&format!("PRAGMA user_version = {target}"))?;
        }
    }
    Ok(())
}

/// Step 4 migration: encrypt any plaintext rows left from a v1 DB. Idempotent
/// once `user_version >= 2`. All work runs inside a single transaction so a
/// crash mid-sweep leaves the DB consistent.
pub fn migrate_v2_encryption(conn: &mut Connection, vault: &Vault) -> anyhow::Result<()> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if v >= 2 {
        return Ok(());
    }

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
