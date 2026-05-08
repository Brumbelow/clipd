//! Clipboard write path.
//!
//! [`set_text`] — text-only, kept as fallback for legacy rows whose
//!     `entry_formats` table is empty.
//! [`set_all_formats`] — multi-format: opens the clipboard, empties it,
//!     then loops `SetClipboardData` over every captured format. Standard
//!     CF_* codes resolve via [`clipboard_format::standard_code`];
//!     registered names re-resolve to a session-local code via
//!     [`raw::register_format`].
//! [`set_image`] — places the canonical CF_DIB bytes, then best-effort
//!     wraps them into BMP-file format and registers CF_BITMAP for legacy
//!     GDI receivers (Paint, older Office).

use crate::daemon::clipboard_format::{self, FormatPayload};
use crate::daemon::image as clipd_image;
use anyhow::{anyhow, bail, Result};
use clipboard_win::{formats, raw, Clipboard};

pub fn set_text(s: &str) -> Result<()> {
    clipboard_win::set_clipboard_string(s).map_err(|e| anyhow!("set_clipboard_string: {e}"))
}

/// Replace the clipboard with every captured format, in capture order.
///
/// Per-format failures are logged at `warn!` and skipped — one bad format
/// shouldn't take down the whole paste. `clipd:`-prefixed names are
/// internal derived data (PNG thumbnails) and are skipped silently.
/// Returns `Err` only if zero formats were placed (clipboard would be left
/// empty, which is worse than the pre-promote state).
pub fn set_all_formats(formats: &[FormatPayload]) -> Result<()> {
    if formats.is_empty() {
        bail!("set_all_formats called with empty format list");
    }

    let _clip = Clipboard::new_attempts(10).map_err(|e| anyhow!("open clipboard: {e}"))?;
    raw::empty().map_err(|e| anyhow!("empty clipboard: {e}"))?;

    let mut placed = 0usize;
    let mut considered = 0usize;
    for fmt in formats {
        if clipboard_format::is_clipd_internal(&fmt.name) {
            continue;
        }
        considered += 1;
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
    tracing::debug!(placed, considered, "promote: set formats");
    Ok(())
}

/// Place a CF_DIB payload on the clipboard, plus a best-effort
/// reconstructed CF_BITMAP for receivers that prefer the GDI handle (Paint,
/// some legacy Office paths). The DIB write is the load-bearing one — Paint
/// accepts CF_DIB directly and `Ctrl+V` will work even if the CF_BITMAP
/// step fails.
pub fn set_image(dib_bytes: &[u8]) -> Result<()> {
    let _clip = Clipboard::new_attempts(10).map_err(|e| anyhow!("open clipboard: {e}"))?;
    raw::empty().map_err(|e| anyhow!("empty clipboard: {e}"))?;
    raw::set_without_clear(formats::CF_DIB, dib_bytes)
        .map_err(|e| anyhow!("set_without_clear(CF_DIB): {e}"))?;

    // CF_BITMAP via clipboard-win's set_bitmap, which expects BMP-file format
    // (BITMAPFILEHEADER + DIB) and internally CreateDIBitmap → SetClipboardData.
    // Treat any failure as best-effort — CF_DIB above is enough for Paint.
    if let Some(bmp) = clipd_image::dib_to_bmp_file(dib_bytes) {
        if let Err(e) = raw::set_bitmap(&bmp) {
            tracing::warn!(error = %e, "set_bitmap (CF_BITMAP) failed; CF_DIB still placed");
        }
    } else {
        tracing::debug!("DIB too short to wrap as BMP-file; skipping CF_BITMAP");
    }
    Ok(())
}
