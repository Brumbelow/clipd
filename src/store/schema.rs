//! Schema migrations. Versioned via SQLite's `user_version` pragma.
//!
//! v1 (Step 2): base `entries` table + dedup/last_seen indexes.
//!
//! Deferred to later steps:
//!   - FTS5 virtual table (Step 5/9)
//!   - `idx_created` (Step 9 date filtering)
//!   - Encryption migration: nonce stays empty until Step 4 swaps it for a
//!     real 12-byte nonce. Schema does not change; values do.

use rusqlite::Connection;

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
