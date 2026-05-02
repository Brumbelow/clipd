//! Clipboard write path.
//!
//! Step 5: text-only via [`set_text`] (kept as fallback for pre-Step-7 rows
//!         whose `entry_formats` table is empty).
//! Step 7: multi-format via [`set_all_formats`] — opens the clipboard,
//!         empties it, then loops `SetClipboardData` over every captured
//!         format. Standard CF_* codes resolve via
//!         [`clipboard_format::standard_code`]; registered names re-resolve
//!         to a session-local code via [`raw::register_format`].

use crate::daemon::clipboard_format::{self, FormatPayload};
use anyhow::{anyhow, bail, Result};
use clipboard_win::{raw, Clipboard};

pub fn set_text(s: &str) -> Result<()> {
    clipboard_win::set_clipboard_string(s).map_err(|e| anyhow!("set_clipboard_string: {e}"))
}

/// Replace the clipboard with every captured format, in capture order.
///
/// Per-format failures are logged at `warn!` and skipped — one bad format
/// shouldn't take down the whole paste. Returns `Err` only if zero formats
/// were placed (clipboard would be left empty, which is worse than the
/// pre-promote state).
pub fn set_all_formats(formats: &[FormatPayload]) -> Result<()> {
    if formats.is_empty() {
        bail!("set_all_formats called with empty format list");
    }

    let _clip = Clipboard::new_attempts(10).map_err(|e| anyhow!("open clipboard: {e}"))?;
    raw::empty().map_err(|e| anyhow!("empty clipboard: {e}"))?;

    let mut placed = 0usize;
    for fmt in formats {
        let code = match clipboard_format::standard_code(&fmt.name) {
            Some(c) => c,
            None => match raw::register_format(&fmt.name) {
                Some(nz) => nz.get(),
                None => {
                    tracing::warn!(name = %fmt.name, "register_format failed; skipping");
                    continue;
                }
            },
        };
        match raw::set_without_clear(code, &fmt.bytes) {
            Ok(()) => placed += 1,
            Err(e) => {
                tracing::warn!(name = %fmt.name, code, error = %e, "set_without_clear failed; skipping")
            }
        }
    }

    if placed == 0 {
        bail!("no formats placed on clipboard (all SetClipboardData calls failed)");
    }
    tracing::debug!(placed, total = formats.len(), "promote: set formats");
    Ok(())
}
