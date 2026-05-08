//! Clipboard-format enumeration + name/code lookup.
//!
//! Surface:
//!   - [`FormatPayload`] — `(name, bytes)` pair captured from one clipboard format.
//!   - [`enumerate_formats`] — read every format the source app put on the
//!     clipboard, filter through [`is_allowed`], cap by size, return an
//!     in-capture-order vector. Requires the clipboard to already be open
//!     (the caller in `capture.rs` holds `Clipboard::new_attempts(10)` for
//!     the duration of the capture).
//!   - [`standard_code`] / [`name_for_code`] — name <-> code helpers for the
//!     fixed CF_* constants. Registered formats (>= 0xC000) get their codes
//!     resolved at promote time via [`clipboard_win::raw::register_format`]
//!     because the numeric code is allocated dynamically per Windows session.
//!
//! Text + rich-text formats are captured here. CF_DIB / CF_BITMAP /
//! CF_DIBV5 are handled separately on the image path; CF_HDROP is
//! reserved for a future "kind=files" step that needs a paste-target UX.

use clipboard_win::raw;

/// One clipboard format's worth of bytes, tagged with its Win32 name.
///
/// `name` is the canonical text identifier (`"CF_UNICODETEXT"` for standard
/// formats, `"HTML Format"` / `"Rich Text Format"` / `"Biff12"` etc. for
/// registered formats). `bytes` is whatever `GetClipboardData` handed back
/// for that format — for text formats this includes the trailing NUL the
/// source app wrote (`SetClipboardData` round-trips it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatPayload {
    pub name: String,
    pub bytes: Vec<u8>,
}

const SIZE_CAP_PER_FORMAT: usize = 4 * 1024 * 1024; // 4 MiB
const SIZE_CAP_TOTAL: usize = 16 * 1024 * 1024; // 16 MiB

/// Capture this format on copy?
///
/// Allow-list (not deny-list) — keeps the blast radius tight. CF_DIB /
/// CF_BITMAP / CF_DIBV5 are handled on the image path; CF_HDROP needs a
/// "where do these files paste to" UX that doesn't exist yet.
pub fn is_allowed(name: &str) -> bool {
    matches!(
        name,
        // Plain text — primary fallback for any paste target.
        "CF_UNICODETEXT" | "CF_TEXT"
        // Rich-text family — load-bearing for "paste into Word/Excel keeps formatting".
        | "HTML Format"
        | "Rich Text Format"
        | "Csv"
        // Excel-specific OLE bundle. Names verified against Office's public
        // clipboard docs; without these, "paste back into Excel" loses cell
        // types, formulas, and conditional formatting.
        | "Biff12"
        | "Biff8"
        | "DataObject"
        | "Link Source"
        | "Embed Source"
        | "Object Descriptor"
        | "Native"
        | "Link Source Descriptor"
        | "Star Object Descriptor"
        | "Ole Private Data"
    )
}

/// Numeric code for a standard CF_* format name.
///
/// Returns `None` for registered names like `"HTML Format"` — caller must
/// then call [`clipboard_win::raw::register_format`] to get the
/// session-local code.
pub fn standard_code(name: &str) -> Option<u32> {
    Some(match name {
        "CF_TEXT" => 1,
        "CF_BITMAP" => 2,
        "CF_METAFILEPICT" => 3,
        "CF_SYLK" => 4,
        "CF_DIF" => 5,
        "CF_TIFF" => 6,
        "CF_OEMTEXT" => 7,
        "CF_DIB" => 8,
        "CF_PALETTE" => 9,
        "CF_PENDATA" => 10,
        "CF_RIFF" => 11,
        "CF_WAVE" => 12,
        "CF_UNICODETEXT" => 13,
        "CF_ENHMETAFILE" => 14,
        "CF_HDROP" => 15,
        "CF_LOCALE" => 16,
        "CF_DIBV5" => 17,
        _ => return None,
    })
}

/// Reverse of [`standard_code`] for the capture side: resolve a numeric
/// clipboard code to its canonical text name. Delegates to clipboard-win's
/// [`raw::format_name_big`] which handles the standard table, GDI/private
/// ranges, and registered names via `GetClipboardFormatNameW`.
pub fn name_for_code(code: u32) -> Option<String> {
    raw::format_name_big(code)
}

/// `clipd:`-prefixed `entry_formats` names are clipd-internal derived data
/// (PNG thumbnails / full-size encodes; future OCR text, etc.) — not
/// Win32 clipboard formats. Promote loops must skip these so we don't
/// register garbage format names with the OS clipboard.
pub fn is_clipd_internal(name: &str) -> bool {
    name.starts_with("clipd:")
}

/// Enumerate every clipboard format the source app made available, filtered
/// through [`is_allowed`] and the per-format / total size caps.
///
/// **Pre-condition:** the clipboard must already be open. The caller in
/// `capture.rs` holds a [`clipboard_win::Clipboard`] guard for the duration
/// of the capture.
///
/// Failure modes (per format) are silent at `tracing::debug` — one bad
/// format must not lose the rest. The total-size cap stops enumeration
/// rather than skipping individual oversized formats so we don't truncate
/// the natural fidelity ordering (CF_UNICODETEXT first, richer formats
/// after — losing a richer format mid-list is more confusing than capping
/// the tail).
pub fn enumerate_formats() -> Vec<FormatPayload> {
    let mut out = Vec::new();
    let mut total = 0usize;

    for code in raw::EnumFormats::new() {
        let Some(name) = name_for_code(code) else {
            continue;
        };
        if !is_allowed(&name) {
            continue;
        }

        let size = match raw::size(code) {
            Some(n) => n.get(),
            None => continue,
        };
        if size == 0 {
            continue;
        }
        if size > SIZE_CAP_PER_FORMAT {
            // Surface as info so "paste lost formatting" reports are
            // diagnosable. Logging the format name is fine — names are
            // public Win32 metadata, not content.
            tracing::info!(
                name = %name,
                size_bytes = size,
                cap = SIZE_CAP_PER_FORMAT,
                "clipboard format dropped: exceeds per-format cap"
            );
            continue;
        }
        if total.saturating_add(size) > SIZE_CAP_TOTAL {
            tracing::info!(
                total_bytes = total,
                cap = SIZE_CAP_TOTAL,
                "clipboard format enumeration stopped: total cap reached"
            );
            break;
        }

        let mut buf = Vec::with_capacity(size);
        if let Err(e) = raw::get_vec(code, &mut buf) {
            tracing::debug!(name = %name, error = %e, "get_vec failed");
            continue;
        }
        total += buf.len();
        out.push(FormatPayload { name, bytes: buf });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_covers_text_and_rich_text() {
        for name in [
            "CF_UNICODETEXT",
            "CF_TEXT",
            "HTML Format",
            "Rich Text Format",
            "Csv",
            "Biff12",
            "Biff8",
            "DataObject",
            "Link Source",
            "Embed Source",
            "Object Descriptor",
            "Native",
        ] {
            assert!(is_allowed(name), "{name} should be allowed");
        }
    }

    #[test]
    fn allow_list_rejects_image_and_files_and_unknown() {
        // Image kinds are handled on the image path, not here.
        assert!(!is_allowed("CF_DIB"));
        assert!(!is_allowed("CF_DIBV5"));
        assert!(!is_allowed("CF_BITMAP"));
        // File-list belongs to a future "kind=files" step.
        assert!(!is_allowed("CF_HDROP"));
        // Owner-display / legacy / non-roundtrippable formats.
        assert!(!is_allowed("CF_OWNERDISPLAY"));
        assert!(!is_allowed("CF_DSPTEXT"));
        assert!(!is_allowed("CF_PALETTE"));
        assert!(!is_allowed("CF_METAFILEPICT"));
        // Unknown registered names.
        assert!(!is_allowed("Some Random Format"));
        assert!(!is_allowed(""));
    }

    #[test]
    fn standard_code_known_constants() {
        // Spot-check the load-bearing ones; if any of these drift the whole
        // promote path is wrong.
        assert_eq!(standard_code("CF_TEXT"), Some(1));
        assert_eq!(standard_code("CF_UNICODETEXT"), Some(13));
        assert_eq!(standard_code("CF_HDROP"), Some(15));
        assert_eq!(standard_code("CF_DIBV5"), Some(17));
    }

    #[test]
    fn standard_code_rejects_registered_names() {
        // Registered names must fall through to register_format at the
        // call site — standard_code returning Some for a registered name
        // would hand back a stale or wrong code.
        assert_eq!(standard_code("HTML Format"), None);
        assert_eq!(standard_code("Rich Text Format"), None);
        assert_eq!(standard_code("Biff12"), None);
        assert_eq!(standard_code(""), None);
    }

    #[test]
    fn clipd_internal_prefix_matches_only_clipd_names() {
        assert!(is_clipd_internal("clipd:png_thumb"));
        assert!(is_clipd_internal("clipd:png_full"));
        assert!(is_clipd_internal("clipd:"));
        // Real Win32 names must NOT match the prefix.
        assert!(!is_clipd_internal("CF_UNICODETEXT"));
        assert!(!is_clipd_internal("HTML Format"));
        assert!(!is_clipd_internal("Biff12"));
        assert!(!is_clipd_internal(""));
    }

    #[test]
    fn standard_code_round_trip_with_format_payload_name() {
        // FormatPayload's `name` field for a standard format is whatever
        // `format_name_big` returns — confirmed via clipboard-win source:
        // standard codes come back as "CF_UNICODETEXT" et al. Make sure
        // standard_code accepts that exact spelling.
        let payload = FormatPayload {
            name: "CF_UNICODETEXT".into(),
            bytes: vec![1, 2, 3],
        };
        assert_eq!(standard_code(&payload.name), Some(13));
    }
}
