//! Content-shape auto-classifier (Step 10).
//!
//! Distinct from `kind` (capture-format taxonomy: text/image/files), this
//! returns one of `url|json|hex|base64|code|text` based on the *shape* of
//! a captured text payload. Stored alongside the row as `content_kind` and
//! surfaced as a colored badge in the picker.
//!
//! Detection priority (first match wins):
//!   1. **Url** — trimmed input starts with `http://` or `https://`.
//!   2. **Json** — trimmed input starts with `{` or `[` AND parses as a
//!      `serde_json::Value`. Strict on purpose: `{not really` stays text.
//!   3. **Hex** — single-line, length ≥ 8, every char in `[0-9a-fA-F]`.
//!   4. **Base64** — single-line, length ≥ 16, every char in
//!      `[A-Za-z0-9+/=]`, length is a multiple of 4 OR the string ends
//!      with `=`/`==`. Strict enough that random URL slugs don't trip it.
//!   5. **Code** — preview contains a recognisable code marker
//!      (`fn `, `def `, `function `, ` => `, ` -> `, `;\n`, `{\n`,
//!      `#include`, `import `, `from `).
//!   6. **Text** — fallback.
//!
//! Capture-format `kind == "image"` rows skip classification entirely
//! (they keep the default `"text"` content_kind which the picker badge
//! ignores in favour of the capture kind).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Url,
    Json,
    Hex,
    Base64,
    Code,
    Text,
}

impl ContentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ContentKind::Url => "url",
            ContentKind::Json => "json",
            ContentKind::Hex => "hex",
            ContentKind::Base64 => "base64",
            ContentKind::Code => "code",
            ContentKind::Text => "text",
        }
    }
}

/// Classify a captured text payload by content shape.
pub fn classify(text: &str) -> ContentKind {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return ContentKind::Text;
    }

    if is_url(trimmed) {
        return ContentKind::Url;
    }
    if is_json(trimmed) {
        return ContentKind::Json;
    }
    if is_hex(trimmed) {
        return ContentKind::Hex;
    }
    if is_base64(trimmed) {
        return ContentKind::Base64;
    }
    if looks_like_code(text) {
        return ContentKind::Code;
    }
    ContentKind::Text
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn is_json(s: &str) -> bool {
    let first = s.as_bytes().first().copied();
    if !matches!(first, Some(b'{') | Some(b'[')) {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(s).is_ok()
}

fn is_hex(s: &str) -> bool {
    if s.len() < 8 || s.contains(|c: char| c.is_whitespace()) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base64(s: &str) -> bool {
    if s.len() < 16 || s.contains(|c: char| c.is_whitespace()) {
        return false;
    }
    let valid_alpha = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if !valid_alpha {
        return false;
    }
    // Either canonical block-aligned, or terminates with `=`/`==` padding.
    s.len() % 4 == 0 || s.ends_with('=')
}

fn looks_like_code(text: &str) -> bool {
    const MARKERS: &[&str] = &[
        "fn ",
        "def ",
        "function ",
        " => ",
        " -> ",
        ";\n",
        "{\n",
        "#include",
        "import ",
        "from ",
    ];
    MARKERS.iter().any(|m| text.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_detected() {
        assert_eq!(classify("https://example.com/path"), ContentKind::Url);
        assert_eq!(classify("http://localhost:8080"), ContentKind::Url);
        assert_eq!(
            classify("  https://example.com/with-leading-space  "),
            ContentKind::Url
        );
    }

    #[test]
    fn url_trumps_other_classes() {
        // A URL whose path slug looks base64-y stays a URL.
        let url = "https://example.com/abcdefghijklmnop1234567890";
        assert_eq!(classify(url), ContentKind::Url);
    }

    #[test]
    fn json_object_detected() {
        assert_eq!(classify(r#"{"a": 1, "b": [1, 2]}"#), ContentKind::Json);
    }

    #[test]
    fn json_array_detected() {
        assert_eq!(classify("[1, 2, 3]"), ContentKind::Json);
    }

    #[test]
    fn unparseable_brace_is_not_json() {
        assert_eq!(classify("{not really json"), ContentKind::Text);
    }

    #[test]
    fn hex_detected_lowercase() {
        assert_eq!(classify("deadbeef0123abcd"), ContentKind::Hex);
    }

    #[test]
    fn hex_detected_uppercase() {
        assert_eq!(classify("DEADBEEF12345678"), ContentKind::Hex);
    }

    #[test]
    fn hex_too_short_is_text() {
        assert_eq!(classify("dead"), ContentKind::Text);
    }

    #[test]
    fn hex_with_non_hex_char_is_not_hex() {
        // 'g' isn't a hex digit. Should not classify as Hex; falls through
        // to base64 (doesn't qualify — too short / not base64-shaped) /
        // text.
        assert_eq!(classify("deadbeefg0"), ContentKind::Text);
    }

    #[test]
    fn base64_detected_with_padding() {
        // 16 chars, valid base64 alphabet, ends with `=` padding.
        assert_eq!(classify("aGVsbG8gd29ybGQ="), ContentKind::Base64);
    }

    #[test]
    fn base64_detected_block_aligned() {
        // 20 chars, multiple of 4, no padding required.
        assert_eq!(classify("YWxwaGFicmF2b2NoYXJsaQ=="), ContentKind::Base64);
    }

    #[test]
    fn base64_too_short_is_text() {
        assert_eq!(classify("aGVsbG8="), ContentKind::Text);
    }

    #[test]
    fn random_url_slug_doesnt_trip_base64() {
        // 19 chars, base64-alphabet-clean, but not block-aligned and no
        // padding — stays text.
        assert_eq!(classify("dQw4w9WgXcQabc1234"), ContentKind::Text);
    }

    #[test]
    fn rust_function_is_code() {
        assert_eq!(
            classify("fn main() { println!(\"hi\"); }"),
            ContentKind::Code
        );
    }

    #[test]
    fn python_def_is_code() {
        assert_eq!(classify("def hello():\n    return 1"), ContentKind::Code);
    }

    #[test]
    fn js_arrow_is_code() {
        assert_eq!(classify("const x = () => 42"), ContentKind::Code);
    }

    #[test]
    fn c_include_is_code() {
        assert_eq!(classify("#include <stdio.h>"), ContentKind::Code);
    }

    #[test]
    fn plain_english_is_text() {
        assert_eq!(
            classify("This is a normal English sentence."),
            ContentKind::Text
        );
    }

    #[test]
    fn empty_is_text() {
        assert_eq!(classify(""), ContentKind::Text);
        assert_eq!(classify("   \n\t  "), ContentKind::Text);
    }

    #[test]
    fn round_trip_as_str() {
        for k in [
            ContentKind::Url,
            ContentKind::Json,
            ContentKind::Hex,
            ContentKind::Base64,
            ContentKind::Code,
            ContentKind::Text,
        ] {
            assert!(!k.as_str().is_empty());
        }
    }
}
