//! Clipboard capture: read CF_UNICODETEXT or CF_DIB, classify, hash,
//! persist (or bump dedup).
//!
//! Text captures pull every text + rich-text format the source app put
//! down into a per-row child table; the image branch fires when no
//! CF_UNICODETEXT is present but CF_DIB is.
//!
//! **Logging contract:** metadata only. Never log
//! preview text, content bytes, hashes, or other content-derived values.

use crate::config::{CaptureConfig, SensitivePolicy};
use crate::daemon::clipboard_format;
use crate::daemon::clipboard_format::FormatPayload;
use crate::daemon::image as clipd_image;
use crate::daemon::win_hook::ForegroundInfo;
use crate::daemon::DaemonState;
use crate::secrets::{self, Reason, Verdict};
use crate::store;
use anyhow::Result;
use clipboard_win::{formats, get, raw, Clipboard};

const EXCLUDE_FORMAT: &str = "ExcludeClipboardContentFromMonitoring";
const CAN_INCLUDE_HISTORY_FORMAT: &str = "CanIncludeInClipboardHistory";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClipboardHistoryFlag {
    Missing,
    Allow,
    Deny,
}

pub fn handle_clipboard_update(state: &DaemonState, fg: &ForegroundInfo) -> Result<()> {
    let _clip = match Clipboard::new_attempts(10) {
        Ok(clip) => clip,
        Err(e) => {
            tracing::info!(kind = "unknown", "clipboard update");
            tracing::debug!(error = %e, "clipboard open failed");
            return Ok(());
        }
    };

    let had_exclude_flag = has_registered_format(EXCLUDE_FORMAT);
    let history_flag = read_clipboard_history_flag();
    if let Some(reason) = skip_reason(
        None,
        fg,
        had_exclude_flag,
        history_flag,
        &state.cfg.capture,
        &state.cfg.secrets,
    ) {
        log_skip("unknown", None, reason);
        return Ok(());
    }

    let text: String = match get(formats::Unicode) {
        Ok(s) => s,
        Err(e) => {
            // No text — fall through to the image branch. The pre-text
            // gates above have already fired and apply equally to image
            // events (exclude flag, history flag, browser-extension popup).
            tracing::debug!(error = %e, "get_clipboard(Unicode) miss; trying image");
            if let Err(img_err) = try_capture_image(state) {
                tracing::info!(kind = "unsupported", "clipboard update");
                tracing::debug!(error = %img_err, "image capture failed");
            }
            return Ok(());
        }
    };

    let size_bytes = text.len();
    if text.is_empty() {
        tracing::info!(kind = "text", size_bytes, "clipboard update");
        return Ok(());
    }

    let mark_sensitive = match skip_reason(
        Some(&text),
        fg,
        had_exclude_flag,
        history_flag,
        &state.cfg.capture,
        &state.cfg.secrets,
    ) {
        None => false,
        Some(reason) => {
            // Explicit signals (clipboard flags, excluded apps) always skip.
            // Heuristic detections honor `sensitive_policy = "mark"`.
            if reason.is_explicit_skip()
                || state.cfg.capture.sensitive_policy == SensitivePolicy::Skip
            {
                log_skip("text", Some(size_bytes), reason);
                return Ok(());
            }
            tracing::info!(
                size_bytes,
                reason = reason.as_str(),
                "marking sensitive (policy=mark)"
            );
            true
        }
    };

    let bytes = text.as_bytes();
    let hash = blake3::hash(bytes);

    // Enumerate every clipboard format the source app put down, filtered
    // by the allow-list and size caps. The `_clip` RAII guard above keeps
    // the clipboard open across this call, which EnumFormats requires.
    let captured_formats = clipboard_format::enumerate_formats();
    let total_format_bytes: usize = captured_formats.iter().map(|f| f.bytes.len()).sum();

    tracing::info!(
        kind = "text",
        size_bytes,
        format_count = captured_formats.len(),
        format_bytes = total_format_bytes,
        "clipboard update"
    );

    let now_ms = chrono::Utc::now().timestamp_millis();
    // Classify content shape from the canonical text. Cheap —
    // bounded-time regex/prefix checks over the captured payload.
    let content_kind = crate::classify::classify(&text);
    let outcome = store::insert_or_bump(
        &state.cfg.db_full_path(),
        &state.vault,
        &store::NewEntry {
            kind: "text",
            content_kind: content_kind.as_str(),
            content: bytes,
            hash: hash.as_bytes(),
            size_bytes,
            created_at: now_ms,
            preview: store::derive_preview(&text),
            source_app: None,
            formats: &captured_formats,
            sensitive: mark_sensitive,
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

/// Read CF_DIB off the clipboard (assumes [`Clipboard`] is already open
/// via the caller's RAII guard), encode a thumbnail + full PNG via the
/// `image` module, and persist with `kind="image"`.
///
/// Returns `Ok(())` on a successful insert OR a clean "no CF_DIB present"
/// — the latter is the common case for non-image, non-text clipboard
/// events (e.g. CF_HDROP-only file drag) and isn't surfaced as an error.
fn try_capture_image(state: &DaemonState) -> Result<()> {
    if !raw::is_format_avail(formats::CF_DIB) {
        return Ok(());
    }

    let mut dib = Vec::new();
    if let Err(e) = raw::get_vec(formats::CF_DIB, &mut dib) {
        anyhow::bail!("get_vec(CF_DIB): {e}");
    }
    let size_bytes = dib.len();
    if size_bytes == 0 {
        return Ok(());
    }
    if size_bytes > clipd_image::IMAGE_DIB_CAP_BYTES {
        tracing::info!(
            size_bytes,
            cap = clipd_image::IMAGE_DIB_CAP_BYTES,
            "image dropped: exceeds size cap"
        );
        return Ok(());
    }

    // Preview string + thumbnail/full PNG. Both are best-effort: an
    // unsupported DIB layout (e.g., paletted) still stores the canonical
    // bytes and round-trips on promote, but the picker shows a placeholder
    // because we can't decode for thumbnail.
    let meta = clipd_image::parse_dib_meta(&dib);
    let preview = match meta {
        Some(m) => format!("image ({}x{})", m.width, m.height),
        None => "image (unsupported format)".to_string(),
    };

    let derived: Vec<FormatPayload> = match clipd_image::dib_to_rgba(&dib) {
        Some(rgba) => {
            let thumb = clipd_image::thumbnail(&rgba, clipd_image::THUMB_MAX_DIM);
            let thumb_png = clipd_image::rgba_to_png(&thumb)?;
            let full_png = clipd_image::rgba_to_png(&rgba)?;
            vec![
                FormatPayload {
                    name: "clipd:png_thumb".into(),
                    bytes: thumb_png,
                },
                FormatPayload {
                    name: "clipd:png_full".into(),
                    bytes: full_png,
                },
            ]
        }
        None => Vec::new(),
    };
    let derived_bytes: usize = derived.iter().map(|f| f.bytes.len()).sum();

    let hash = blake3::hash(&dib);
    let now_ms = chrono::Utc::now().timestamp_millis();

    tracing::info!(
        kind = "image",
        size_bytes,
        format_count = derived.len(),
        format_bytes = derived_bytes,
        "clipboard update"
    );

    let outcome = store::insert_or_bump(
        &state.cfg.db_full_path(),
        &state.vault,
        &store::NewEntry {
            kind: "image",
            // Image rows take the column default — picker badge logic
            // routes on `kind == "image"` and ignores content_kind for
            // non-text kinds.
            content_kind: "text",
            content: &dib,
            hash: hash.as_bytes(),
            size_bytes,
            created_at: now_ms,
            preview: store::derive_preview(&preview),
            source_app: None,
            formats: &derived,
            sensitive: false,
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

fn registered_format_code(name: &str) -> Option<u32> {
    raw::register_format(name).map(|code| code.get())
}

fn has_registered_format(name: &str) -> bool {
    registered_format_code(name).is_some_and(raw::is_format_avail)
}

fn read_clipboard_history_flag() -> ClipboardHistoryFlag {
    let Some(code) = registered_format_code(CAN_INCLUDE_HISTORY_FORMAT) else {
        return ClipboardHistoryFlag::Missing;
    };
    if !raw::is_format_avail(code) {
        return ClipboardHistoryFlag::Missing;
    }

    match get::<Vec<u8>, _>(formats::RawData(code)) {
        Ok(bytes) => parse_clipboard_history_flag(Some(&bytes)),
        Err(e) => {
            tracing::debug!(error = %e, "CanIncludeInClipboardHistory read failed");
            ClipboardHistoryFlag::Deny
        }
    }
}

fn parse_clipboard_history_flag(bytes: Option<&[u8]>) -> ClipboardHistoryFlag {
    let Some(bytes) = bytes else {
        return ClipboardHistoryFlag::Missing;
    };
    if bytes.is_empty() {
        return ClipboardHistoryFlag::Deny;
    }

    let value = if bytes.len() >= 4 {
        u32::from_le_bytes(bytes[..4].try_into().expect("slice length checked"))
    } else {
        bytes.iter().fold(0u32, |acc, b| acc | u32::from(*b))
    };

    if value == 0 {
        ClipboardHistoryFlag::Deny
    } else {
        ClipboardHistoryFlag::Allow
    }
}

fn skip_reason(
    text: Option<&str>,
    fg: &ForegroundInfo,
    had_exclude_flag: bool,
    history_flag: ClipboardHistoryFlag,
    capture_cfg: &CaptureConfig,
    secrets_cfg: &crate::config::SecretsConfig,
) -> Option<Reason> {
    if had_exclude_flag {
        return Some(Reason::ExcludeFormatFlag);
    }
    if history_flag == ClipboardHistoryFlag::Deny {
        return Some(Reason::ClipboardHistoryDisabled);
    }
    if is_excluded_app(fg, &capture_cfg.excluded_apps) {
        return Some(Reason::ExcludedApp);
    }

    // Browser-extension-popup signal does not depend on text contents — fire
    // even on the pre-text-fetch first pass so we skip cleanly.
    if secrets::is_browser_extension_popup_signal(fg.title.as_deref(), fg.image.as_deref()) {
        return Some(Reason::BrowserExtensionPopup);
    }

    let text = text?;
    match secrets::classify(
        text,
        fg.title.as_deref(),
        fg.image.as_deref(),
        false,
        secrets_cfg,
    ) {
        Verdict::Ok => None,
        Verdict::Sensitive(reason) => Some(reason),
    }
}

/// Case-insensitive basename match against the configured
/// `[capture] excluded_apps` list. Empty list short-circuits.
fn is_excluded_app(fg: &ForegroundInfo, excluded: &[String]) -> bool {
    if excluded.is_empty() {
        return false;
    }
    let Some(image) = fg.image.as_deref() else {
        return false;
    };
    let basename = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase();
    excluded.iter().any(|e| e.to_ascii_lowercase() == basename)
}

fn log_skip(kind: &str, size_bytes: Option<usize>, reason: Reason) {
    tracing::info!(
        kind,
        size_bytes = size_bytes.unwrap_or_default(),
        size_known = size_bytes.is_some(),
        sensitive = true,
        reason = reason.as_str(),
        "clipboard update skipped"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CaptureConfig, SecretsConfig};

    fn fg_none() -> ForegroundInfo {
        ForegroundInfo {
            title: None,
            image: None,
        }
    }

    fn fg(title: Option<&str>, image: Option<&str>) -> ForegroundInfo {
        ForegroundInfo {
            title: title.map(str::to_string),
            image: image.map(str::to_string),
        }
    }

    #[test]
    fn history_flag_missing_allows_storage() {
        assert_eq!(
            parse_clipboard_history_flag(None),
            ClipboardHistoryFlag::Missing
        );
    }

    #[test]
    fn history_flag_zero_denies_storage() {
        assert_eq!(
            parse_clipboard_history_flag(Some(&[0, 0, 0, 0])),
            ClipboardHistoryFlag::Deny
        );
        assert_eq!(
            parse_clipboard_history_flag(Some(&[0])),
            ClipboardHistoryFlag::Deny
        );
    }

    #[test]
    fn history_flag_nonzero_allows_storage() {
        assert_eq!(
            parse_clipboard_history_flag(Some(&[1, 0, 0, 0])),
            ClipboardHistoryFlag::Allow
        );
        assert_eq!(
            parse_clipboard_history_flag(Some(&[1])),
            ClipboardHistoryFlag::Allow
        );
    }

    #[test]
    fn skip_reason_prefers_clipboard_flags() {
        let cfg = SecretsConfig::default();
        assert_eq!(
            skip_reason(
                Some("plain text"),
                &fg_none(),
                true,
                ClipboardHistoryFlag::Missing,
                &CaptureConfig::default(),
                &cfg
            ),
            Some(Reason::ExcludeFormatFlag)
        );
        assert_eq!(
            skip_reason(
                Some("plain text"),
                &fg_none(),
                false,
                ClipboardHistoryFlag::Deny,
                &CaptureConfig::default(),
                &cfg
            ),
            Some(Reason::ClipboardHistoryDisabled)
        );
    }

    #[test]
    fn skip_reason_detects_sensitive_text_and_title() {
        let cfg = SecretsConfig::default();
        assert_eq!(
            skip_reason(
                Some("hello world"),
                &fg(Some("Personal Password Vault"), None),
                false,
                ClipboardHistoryFlag::Missing,
                &CaptureConfig::default(),
                &cfg
            ),
            Some(Reason::PasswordManagerWindow)
        );
        assert_eq!(
            skip_reason(
                Some("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                &fg_none(),
                false,
                ClipboardHistoryFlag::Missing,
                &CaptureConfig::default(),
                &cfg
            ),
            Some(Reason::KnownSecretPattern)
        );
    }

    #[test]
    fn skip_reason_catches_browser_extension_popup_pre_text() {
        // First skip-reason pass (text=None) must already detect the
        // browser-extension-popup signal so the daemon never even reads the
        // CF_UNICODETEXT payload from a Bitwarden popup.
        let cfg = SecretsConfig::default();
        assert_eq!(
            skip_reason(
                None,
                &fg(
                    None,
                    Some(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
                ),
                false,
                ClipboardHistoryFlag::Missing,
                &CaptureConfig::default(),
                &cfg
            ),
            Some(Reason::BrowserExtensionPopup)
        );
    }

    #[test]
    fn skip_reason_passes_browser_with_titled_window() {
        // Wikipedia Ctrl+C: msedge.exe + non-empty title → must NOT be flagged
        // as a popup.
        let cfg = SecretsConfig::default();
        assert_eq!(
            skip_reason(
                Some("the quick brown fox"),
                &fg(
                    Some("Article Title - Wikipedia and 4 more pages - Microsoft Edge"),
                    Some(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
                ),
                false,
                ClipboardHistoryFlag::Missing,
                &CaptureConfig::default(),
                &cfg
            ),
            None
        );
    }

    #[test]
    fn excluded_app_basename_match_is_case_insensitive() {
        let excluded = vec!["KeePassXC.exe".to_string()];
        assert!(is_excluded_app(
            &fg(None, Some(r"C:\Program Files\KeePassXC\keepassxc.exe")),
            &excluded,
        ));
        assert!(is_excluded_app(
            &fg(None, Some(r"C:\Program Files\KeePassXC\KEEPASSXC.EXE")),
            &excluded,
        ));
    }

    #[test]
    fn excluded_app_does_not_match_unrelated_exe() {
        let excluded = vec!["1password.exe".to_string()];
        assert!(!is_excluded_app(
            &fg(None, Some(r"C:\Windows\System32\notepad.exe")),
            &excluded,
        ));
    }

    #[test]
    fn excluded_app_empty_list_short_circuits() {
        assert!(!is_excluded_app(
            &fg(None, Some(r"C:\Windows\System32\notepad.exe")),
            &[],
        ));
    }

    #[test]
    fn excluded_app_no_image_does_not_panic() {
        let excluded = vec!["something.exe".to_string()];
        assert!(!is_excluded_app(&fg(None, None), &excluded));
    }

    #[test]
    fn skip_reason_returns_excluded_app_for_listed_exe() {
        let cap = CaptureConfig {
            excluded_apps: vec!["notepad.exe".to_string()],
            ..Default::default()
        };
        let cfg = SecretsConfig::default();
        assert_eq!(
            skip_reason(
                Some("plain text"),
                &fg(
                    Some("Untitled - Notepad"),
                    Some(r"C:\Windows\System32\notepad.exe")
                ),
                false,
                ClipboardHistoryFlag::Missing,
                &cap,
                &cfg,
            ),
            Some(Reason::ExcludedApp)
        );
    }
}
