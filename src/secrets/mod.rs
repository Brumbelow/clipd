//! Sensitive-content detection. The day-1 line of defense.
//!
//! Three independent signals trigger a "sensitive" verdict:
//!   1. Format-flag check (caller's responsibility — checks for the
//!      `ExcludeClipboardContentFromMonitoring` clipboard format).
//!   2. Foreground window title matches a password-manager pattern.
//!   3. Content matches a known-secret regex.
//!   4. Content is a high-entropy single token in the configured length range.
//!
//! Default policy: skip storage entirely. See `SecretsPolicy`.

// Wired into `daemon::capture` in Step 3. Tests exercise the public surface
// today; the binary doesn't call it yet, hence the module-wide allow.
#![allow(dead_code)]

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
    PasswordManagerWindow,
    KnownSecretPattern,
    HighEntropyToken,
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
        r"(?i)(1password|bitwarden|keepass|keepassxc|lastpass|dashlane|nordpass|vaultwarden)",
    )
    .expect("static regex")
});

/// Classify clipboard text payload + foreground window title.
///
/// `had_exclude_flag` should be true if the clipboard contained the
/// `ExcludeClipboardContentFromMonitoring` format. The capture layer
/// is responsible for that check (Win32 ClipboardFormat enumeration).
pub fn classify(
    text: &str,
    foreground_window_title: Option<&str>,
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
            classify("hello world", None, true, &cfg()),
            Verdict::Sensitive(Reason::ExcludeFormatFlag)
        ));
    }

    #[test]
    fn pwm_window_title() {
        assert!(matches!(
            classify("anything", Some("1Password 8"), false, &cfg()),
            Verdict::Sensitive(Reason::PasswordManagerWindow)
        ));
    }

    #[test]
    fn github_pat() {
        let pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(matches!(
            classify(pat, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn aws_access_key() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(matches!(
            classify(key, None, false, &cfg()),
            Verdict::Sensitive(_)
        ));
    }

    #[test]
    fn jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(matches!(
            classify(jwt, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn pem_block() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert!(matches!(
            classify(pem, None, false, &cfg()),
            Verdict::Sensitive(Reason::KnownSecretPattern)
        ));
    }

    #[test]
    fn plain_english_passes() {
        let text = "This is a normal sentence with several words in it.";
        assert!(matches!(classify(text, None, false, &cfg()), Verdict::Ok));
    }

    #[test]
    fn url_passes() {
        let text = "https://example.com/path?query=value&other=1";
        assert!(matches!(classify(text, None, false, &cfg()), Verdict::Ok));
    }

    #[test]
    fn high_entropy_token_caught() {
        // 40-char base64-ish opaque token
        let token = "aB3xQ9zP7vK2rN8mL6jH4gF1dS5tY0wE9cV2bX7n";
        assert!(matches!(
            classify(token, None, false, &cfg()),
            Verdict::Sensitive(Reason::HighEntropyToken)
        ));
    }

    #[test]
    fn short_token_passes_entropy_check() {
        // Below entropy_min_len
        let token = "hello123";
        assert!(matches!(classify(token, None, false, &cfg()), Verdict::Ok));
    }

    #[test]
    fn long_text_passes_entropy_check() {
        // Above entropy_max_len even though dense — likely real content
        let token: String = "the quick brown fox jumps over the lazy dog ".repeat(5);
        assert!(matches!(classify(&token, None, false, &cfg()), Verdict::Ok));
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
