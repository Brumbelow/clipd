//! Sensitive-content detection. The day-1 line of defense.
//!
//! Independent signals trigger a "sensitive" verdict:
//!   1. Format-flag check (caller's responsibility — checks for the
//!      `ExcludeClipboardContentFromMonitoring` clipboard format).
//!   2. Foreground window title matches a password-manager pattern.
//!   3. Foreground process is a known web browser AND its window has no
//!      title (extension-popup signal — Chromium-based password manager
//!      extensions write from an untitled top-level popup HWND, while
//!      legitimate page-content copies surface the tab title).
//!   4. Content matches a known-secret regex.
//!   5. Content is a high-entropy single token in the configured length range.
//!
//! Default policy: skip storage entirely. See `SecretsPolicy`.

use crate::config::SecretsConfig;

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Content is safe to store as-is.
    Ok,
    /// Content is sensitive — apply the configured policy.
    Sensitive(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    ExcludeFormatFlag,
    ClipboardHistoryDisabled,
    ExcludedApp,
    PasswordManagerWindow,
    BrowserExtensionPopup,
    KnownSecretPattern,
    HighEntropyToken,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::ExcludeFormatFlag => "exclude_format_flag",
            Reason::ClipboardHistoryDisabled => "clipboard_history_disabled",
            Reason::ExcludedApp => "excluded_app",
            Reason::PasswordManagerWindow => "password_manager_window",
            Reason::BrowserExtensionPopup => "browser_extension_popup",
            Reason::KnownSecretPattern => "known_secret_pattern",
            Reason::HighEntropyToken => "high_entropy_token",
        }
    }

    /// True for reasons driven by user/app explicit signals (clipboard
    /// flags, excluded-apps list). These always skip storage regardless
    /// of `sensitive_policy`. Heuristic reasons (regex / entropy / window
    /// title / browser popup) honor the policy.
    pub fn is_explicit_skip(self) -> bool {
        matches!(
            self,
            Reason::ExcludeFormatFlag | Reason::ClipboardHistoryDisabled | Reason::ExcludedApp
        )
    }
}

/// Process image basenames we treat as Chromium/Firefox-family browsers for
/// the extension-popup heuristic. Match is case-insensitive.
const BROWSER_EXES: &[&str] = &[
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "arc.exe",
    "chromium.exe",
];

fn is_browser_exe(image_path: &str) -> bool {
    let basename = image_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image_path)
        .to_ascii_lowercase();
    BROWSER_EXES.iter().any(|e| *e == basename)
}

/// True when the foreground window belongs to a known browser process AND
/// has no caption text. This is the live signature of a Chromium extension
/// popup (Bitwarden / 1Password / Dashlane / LastPass / KeePass et al.) at
/// the moment they write the clipboard. Legitimate web-page copies surface
/// the tab title, so this discriminates cleanly without false-positiving
/// right-click context-menu copies (the menu has closed by the time we read
/// foreground; focus is back on the titled tab window).
pub fn is_browser_extension_popup_signal(
    foreground_title: Option<&str>,
    foreground_image: Option<&str>,
) -> bool {
    let Some(image) = foreground_image else {
        return false;
    };
    if !is_browser_exe(image) {
        return false;
    }
    foreground_title.map(str::is_empty).unwrap_or(true)
}

/// Patterns we'll never store. Order matters only for diagnostics.
static SECRET_PATTERNS: Lazy<Vec<(Reason, Regex)>> = Lazy::new(|| {
    let pat = |s: &str| Regex::new(s).expect("static regex");
    vec![
        // GitHub PAT
        (Reason::KnownSecretPattern, pat(r"\bghp_[A-Za-z0-9]{36}\b")),
        // GitHub fine-grained PAT
        (
            Reason::KnownSecretPattern,
            pat(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        ),
        // OpenAI / Anthropic-style
        (
            Reason::KnownSecretPattern,
            pat(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
        ),
        // Slack tokens
        (
            Reason::KnownSecretPattern,
            pat(r"\bxox[bpars]-[A-Za-z0-9-]{10,}\b"),
        ),
        // AWS access key id
        (Reason::KnownSecretPattern, pat(r"\bAKIA[0-9A-Z]{16}\b")),
        // AWS secret access key (heuristic: 40 base64-ish chars after specific contexts is hard;
        // we only flag the standalone access-key id reliably)
        // JWT (3 base64url segments separated by `.`)
        (
            Reason::KnownSecretPattern,
            pat(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        ),
        // PEM private key block
        (
            Reason::KnownSecretPattern,
            pat(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ),
        // Stripe live keys
        (
            Reason::KnownSecretPattern,
            pat(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        ),
    ]
});

/// Window titles indicating a password-manager-adjacent context.
static PWM_TITLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(password|vault|1password|bitwarden|keepass|keepassxc|lastpass|dashlane|nordpass|vaultwarden)",
    )
    .expect("static regex")
});

/// Classify clipboard text payload + foreground-window context.
///
/// `had_exclude_flag` should be true if the clipboard contained the
/// `ExcludeClipboardContentFromMonitoring` format. The capture layer
/// is responsible for that check (Win32 ClipboardFormat enumeration).
///
/// `foreground_image` is the full path of the executable that owns the
/// foreground window — used by the browser-extension-popup heuristic.
pub fn classify(
    text: &str,
    foreground_window_title: Option<&str>,
    foreground_image: Option<&str>,
    had_exclude_flag: bool,
    cfg: &SecretsConfig,
) -> Verdict {
    if had_exclude_flag {
        return Verdict::Sensitive(Reason::ExcludeFormatFlag);
    }

    if let Some(title) = foreground_window_title {
        if PWM_TITLE.is_match(title) {
            return Verdict::Sensitive(Reason::PasswordManagerWindow);
        }
    }

    if is_browser_extension_popup_signal(foreground_window_title, foreground_image) {
        return Verdict::Sensitive(Reason::BrowserExtensionPopup);
    }

    for (reason, re) in SECRET_PATTERNS.iter() {
        if re.is_match(text) {
            return Verdict::Sensitive(*reason);
        }
    }

    if is_high_entropy_token(text, cfg) {
        return Verdict::Sensitive(Reason::HighEntropyToken);
    }

    Verdict::Ok
}

/// True if the entire payload (after trim) is a single token of length in
/// `[entropy_min_len, entropy_max_len]` with Shannon entropy above the
/// configured threshold (bits per character).
fn is_high_entropy_token(text: &str, cfg: &SecretsConfig) -> bool {
    let trimmed = text.trim();
    if trimmed.contains(char::is_whitespace) {
        return false;
    }
    // URLs frequently pass the whitespace-free + length + entropy gate because
    // of slug / video-id segments, but they aren't credentials. Pre-signed
    // URLs, JWTs in query strings, and embedded API keys are already caught
    // by the regex layer above; the entropy gate is supposed to catch *bare*
    // opaque tokens, not links.
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return false;
    }
    let len = trimmed.chars().count();
    if len < cfg.entropy_min_len || len > cfg.entropy_max_len {
        return false;
    }
    shannon_entropy(trimmed) > cfg.entropy_threshold
}

/// Shannon entropy of `s` in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretsConfig;

    fn cfg() -> SecretsConfig {
        SecretsConfig::default()
    }

    #[test]
    fn exclude_flag_dominates() {
        assert!(matches!(
            classify("hello world", None, None, true, &cfg()),
            Verdict::Sensitive(Reason::ExcludeFormatFlag)
        ));
    }

    #[test]
    fn pwm_window_title() {
        assert!(matches!(
            classify("anything", Some("1Password 8"), None, false, &cfg()),
            Verdict::Sensitive(Reason::PasswordManagerWindow)
        ));
        assert!(matches!(
            classify(
                "anything",
                Some("Corporate Password Vault"),
                None,
                false,
                &cfg()
            ),
            Verdict::Sensitive(Reason::PasswordManagerWindow)
        ));
    }

    #[test]
    fn github_pat() {
        let pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(matches!(
            classify(pat, None, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn aws_access_key() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(matches!(
            classify(key, None, None, false, &cfg()),
            Verdict::Sensitive(_)
        ));
    }

    #[test]
    fn jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(matches!(
            classify(jwt, None, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn pem_block() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert!(matches!(
            classify(pem, None, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn plain_english_passes() {
        let text = "This is a normal sentence with several words in it.";
        assert!(matches!(
            classify(text, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn url_passes() {
        let text = "https://example.com/path?query=value&other=1";
        assert!(matches!(
            classify(text, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn youtube_style_url_passes_entropy_check() {
        // 50-char YouTube URL — high-entropy slug, but a URL not a credential.
        // Regression for a live false-positive observed during secrets hardening.
        let text = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s";
        assert!(matches!(
            classify(text, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn http_prefix_url_passes_entropy_check() {
        let text = "http://shorturl.at/abXYZ123QwErTyUiOpAsDfGhJkLz";
        assert!(matches!(
            classify(text, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn high_entropy_token_caught() {
        // 40-char base64-ish opaque token
        let token = "aB3xQ9zP7vK2rN8mL6jH4gF1dS5tY0wE9cV2bX7n";
        assert!(matches!(
            classify(token, None, None, false, &cfg()),
            Verdict::Sensitive(Reason::HighEntropyToken)
        ));
    }

    #[test]
    fn short_token_passes_entropy_check() {
        // Below entropy_min_len
        let token = "hello123";
        assert!(matches!(
            classify(token, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn long_text_passes_entropy_check() {
        // Above entropy_max_len even though dense — likely real content
        let token: String = "the quick brown fox jumps over the lazy dog ".repeat(5);
        assert!(matches!(
            classify(&token, None, None, false, &cfg()),
            Verdict::Ok
        ));
    }

    #[test]
    fn browser_extension_popup_with_no_title() {
        // Bitwarden Edge extension signature: msedge.exe in foreground,
        // popup HWND has no title. Matched even on benign-looking text.
        assert!(matches!(
            classify(
                "anything",
                None,
                Some(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                false,
                &cfg()
            ),
            Verdict::Sensitive(Reason::BrowserExtensionPopup)
        ));
    }

    #[test]
    fn browser_extension_popup_with_empty_title_string() {
        // GetWindowTextW can return zero-length on accessible-but-empty title.
        assert!(matches!(
            classify(
                "anything",
                Some(""),
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                false,
                &cfg()
            ),
            Verdict::Sensitive(Reason::BrowserExtensionPopup)
        ));
    }

    #[test]
    fn browser_with_page_title_does_not_trigger_popup_heuristic() {
        // Wikipedia Ctrl+C signature: msedge.exe + non-empty page title.
        assert!(matches!(
            classify(
                "the quick brown fox",
                Some(
                    "Crusading movement - Wikipedia and 4 more pages - Profile 1 - Microsoft Edge"
                ),
                Some(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                false,
                &cfg()
            ),
            Verdict::Ok
        ));
    }

    #[test]
    fn non_browser_with_no_title_does_not_trigger_popup_heuristic() {
        // A native app with no title MUST NOT be treated as a browser extension.
        assert!(matches!(
            classify(
                "the quick brown fox",
                None,
                Some(r"C:\Windows\System32\notepad.exe"),
                false,
                &cfg()
            ),
            Verdict::Ok
        ));
    }

    #[test]
    fn browser_exe_match_is_case_insensitive() {
        assert!(is_browser_exe("MSEDGE.EXE"));
        assert!(is_browser_exe(
            r"C:\Program Files (x86)\Microsoft\Edge\Application\MsEdge.exe"
        ));
        assert!(is_browser_exe(
            "C:/Program Files/Google/Chrome/Application/chrome.exe"
        ));
        assert!(!is_browser_exe(r"C:\Windows\System32\explorer.exe"));
    }

    #[test]
    fn shannon_entropy_bounds() {
        assert_eq!(shannon_entropy(""), 0.0);
        // All same byte → 0
        assert!(shannon_entropy("aaaaaaaa") < 0.001);
        // Uniform random-ish → close to log2(distinct)
        let h = shannon_entropy("abcdefghABCDEFGH01234567");
        assert!(h > 4.0);
    }
}
