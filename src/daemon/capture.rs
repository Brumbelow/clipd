//! Clipboard capture: read CF_UNICODETEXT, classify, hash, persist (or bump dedup).
//!
//! Step 2 only handles plain text. Non-text formats (CF_DIB, CF_HDROP,
//! CF_HTML, RTF) are logged as unsupported until Step 7/8.
//!
//! **Logging contract (AGENTS rule 8/123):** metadata only. Never log
//! preview text, content bytes, hashes, or other content-derived values.

use crate::daemon::clipboard_format;
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
    if let Some(reason) = skip_reason(None, fg, had_exclude_flag, history_flag, &state.cfg.secrets)
    {
        log_skip("unknown", None, reason);
        return Ok(());
    }

    let text: String = match get(formats::Unicode) {
        Ok(s) => s,
        Err(e) => {
            // Common: clipboard held by another app, or non-text format only.
            // Do NOT log the payload — only the error code.
            tracing::info!(kind = "unsupported", "clipboard update");
            tracing::debug!(error = %e, "get_clipboard(Unicode) miss");
            return Ok(());
        }
    };

    let size_bytes = text.len();
    if text.is_empty() {
        tracing::info!(kind = "text", size_bytes, "clipboard update");
        return Ok(());
    }

    if let Some(reason) = skip_reason(
        Some(&text),
        fg,
        had_exclude_flag,
        history_flag,
        &state.cfg.secrets,
    ) {
        log_skip("text", Some(size_bytes), reason);
        return Ok(());
    }

    let bytes = text.as_bytes();
    let hash = blake3::hash(bytes);

    // Step 7: enumerate every clipboard format the source app put down,
    // filtered by the allow-list and size caps. The `_clip` RAII guard
    // above keeps the clipboard open across this call, which EnumFormats
    // requires.
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
    let outcome = store::insert_or_bump(
        &state.cfg.db_full_path(),
        &state.vault,
        &store::NewEntry {
            kind: "text",
            content: bytes,
            hash: hash.as_bytes(),
            size_bytes,
            created_at: now_ms,
            preview: store::derive_preview(&text),
            source_app: None,
            formats: &captured_formats,
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
    cfg: &crate::config::SecretsConfig,
) -> Option<Reason> {
    if had_exclude_flag {
        return Some(Reason::ExcludeFormatFlag);
    }
    if history_flag == ClipboardHistoryFlag::Deny {
        return Some(Reason::ClipboardHistoryDisabled);
    }

    // Browser-extension-popup signal does not depend on text contents — fire
    // even on the pre-text-fetch first pass so we skip cleanly.
    if secrets::is_browser_extension_popup_signal(fg.title.as_deref(), fg.image.as_deref()) {
        return Some(Reason::BrowserExtensionPopup);
    }

    let text = text?;
    match secrets::classify(text, fg.title.as_deref(), fg.image.as_deref(), false, cfg) {
        Verdict::Ok => None,
        Verdict::Sensitive(reason) => Some(reason),
    }
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
    use crate::config::SecretsConfig;

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
                &cfg
            ),
            None
        );
    }
}
