//! Clipboard capture: read CF_UNICODETEXT, hash, persist (or bump dedup).
//!
//! Step 2 only handles plain text. Non-text formats (CF_DIB, CF_HDROP,
//! CF_HTML, RTF) are silently ignored at debug level until Step 7/8.
//!
//! **Logging contract (AGENTS rule 8/123):** metadata only. Never log
//! preview text, content bytes, or anything derived from clipboard payload
//! beyond size + hash prefix.

use crate::daemon::DaemonState;
use crate::store;
use anyhow::Result;
use clipboard_win::{formats, get_clipboard};
use windows::Win32::Foundation::HWND;

pub fn handle_clipboard_update(state: &DaemonState, _hwnd: HWND) -> Result<()> {
    let text: String = match get_clipboard(formats::Unicode) {
        Ok(s) => s,
        Err(e) => {
            // Common: clipboard held by another app, or non-text format only.
            // Do NOT log the payload — only the error code.
            tracing::debug!(error = %e, "get_clipboard(Unicode) miss");
            return Ok(());
        }
    };

    if text.is_empty() {
        tracing::debug!("empty clipboard text");
        return Ok(());
    }

    let bytes = text.as_bytes();
    let size_bytes = bytes.len();
    let hash = blake3::hash(bytes);

    tracing::info!(
        kind = "text",
        size_bytes,
        hash_prefix = %hex_prefix(hash.as_bytes(), 8),
        "clipboard update"
    );

    let now_ms = chrono::Utc::now().timestamp_millis();
    let outcome = store::insert_or_bump(
        &state.cfg.db_full_path(),
        &store::NewEntry {
            kind: "text",
            content: bytes,
            hash: hash.as_bytes(),
            size_bytes,
            created_at: now_ms,
            preview: store::derive_preview(&text),
            source_app: None,
        },
    )?;

    match outcome {
        store::Outcome::Inserted { id } => tracing::info!(id, "stored"),
        store::Outcome::BumpedLastSeen { id } => {
            tracing::debug!(id, "deduped, bumped last_seen")
        }
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes.iter().take(n).map(|b| format!("{b:02x}")).collect()
}
