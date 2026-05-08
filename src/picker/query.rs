//! Picker query parser. Splits the user's input string into a free-text
//! portion and a list of [`DateFilter`] predicates that the daemon applies
//! as SQL `WHERE` clauses before the text search.
//!
//! Recognized prefix tokens:
//!   - `:today` / `:yesterday` — anchored to local-time midnight
//!   - `:Nd` (e.g. `:7d`, `:30d`) — last-N-days from `now`
//!   - `>YYYY-MM-DD` / `<YYYY-MM-DD` — half-bounded
//!   - `YYYY-MM-DD..YYYY-MM-DD` — closed range (end inclusive)
//!
//! Anything that doesn't match a token form is treated as free-text and
//! joined back into the search string with single-space separators.
//!
//! All bounds in the emitted [`DateFilter`]s are unix-milliseconds (matching
//! `entries.created_at`). The parser anchors "today" at local-time midnight
//! so `:today` matches the user's wall clock, not UTC.
//!
//! The `now` argument is taken as a parameter to keep tests deterministic;
//! production callers pass `chrono::Local::now()`.
//!
//! Parser is intentionally lenient — typos in dates fall through to free
//! text rather than surfacing an error, matching the inline-filter UX of
//! every other tool on the planet.

use crate::store::DateFilter;
use chrono::{DateTime, Local, NaiveDate, TimeZone};

/// Output of [`parse`]. `text` is the free-text portion suitable for the
/// existing `LIKE '%q%'` matcher; `filters` is 0..N predicates.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedQuery {
    pub text: String,
    pub filters: Vec<DateFilter>,
}

/// Parse a raw picker input string against the supplied reference time.
pub fn parse(raw: &str, now: DateTime<Local>) -> ParsedQuery {
    let mut filters = Vec::new();
    let mut text_tokens = Vec::new();

    for tok in raw.split_whitespace() {
        if let Some(filter) = try_parse_token(tok, now) {
            filters.push(filter);
        } else {
            text_tokens.push(tok);
        }
    }

    ParsedQuery {
        text: text_tokens.join(" "),
        filters,
    }
}

fn try_parse_token(tok: &str, now: DateTime<Local>) -> Option<DateFilter> {
    if let Some(rest) = tok.strip_prefix(':') {
        return parse_relative(rest, now);
    }
    if let Some(rest) = tok.strip_prefix('>') {
        return parse_date(rest).map(|d| DateFilter::After(midnight_local_ms(d)));
    }
    if let Some(rest) = tok.strip_prefix('<') {
        return parse_date(rest).map(|d| DateFilter::Before(midnight_local_ms(d)));
    }
    if let Some((a, b)) = tok.split_once("..") {
        if let (Some(start), Some(end)) = (parse_date(a), parse_date(b)) {
            return Some(DateFilter::Range {
                start: midnight_local_ms(start),
                // End-inclusive: include the entire `end` day.
                end: midnight_local_ms(end) + ms_per_day(),
            });
        }
    }
    None
}

fn parse_relative(rest: &str, now: DateTime<Local>) -> Option<DateFilter> {
    match rest {
        "today" => {
            let start = midnight_local(now);
            Some(DateFilter::Range {
                start: dt_to_ms(start),
                end: dt_to_ms(start) + ms_per_day(),
            })
        }
        "yesterday" => {
            let today = midnight_local(now);
            Some(DateFilter::Range {
                start: dt_to_ms(today) - ms_per_day(),
                end: dt_to_ms(today),
            })
        }
        s if s.ends_with('d') => {
            let n: i64 = s[..s.len() - 1].parse().ok()?;
            if !(1..=3650).contains(&n) {
                return None;
            }
            let cutoff = dt_to_ms(now) - n * ms_per_day();
            Some(DateFilter::After(cutoff))
        }
        _ => None,
    }
}

fn parse_date(s: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

fn midnight_local(now: DateTime<Local>) -> DateTime<Local> {
    now.date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|naive| Local.from_local_datetime(&naive).single())
        .unwrap_or(now)
}

fn midnight_local_ms(d: NaiveDate) -> i64 {
    d.and_hms_opt(0, 0, 0)
        .and_then(|naive| Local.from_local_datetime(&naive).single())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

fn dt_to_ms(dt: DateTime<Local>) -> i64 {
    dt.timestamp_millis()
}

const fn ms_per_day() -> i64 {
    86_400_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, hh: u32, mm: u32) -> DateTime<Local> {
        Local
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(y, m, d)
                    .unwrap()
                    .and_hms_opt(hh, mm, 0)
                    .unwrap(),
            )
            .single()
            .unwrap()
    }

    #[test]
    fn empty_input_yields_empty_parsed() {
        let out = parse("", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, "");
        assert!(out.filters.is_empty());
    }

    #[test]
    fn pure_text_passes_through() {
        let out = parse("kubectl get pods", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, "kubectl get pods");
        assert!(out.filters.is_empty());
    }

    #[test]
    fn today_anchors_at_local_midnight() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(":today", now);
        let expected_start = at(2026, 5, 3, 0, 0).timestamp_millis();
        assert_eq!(out.text, "");
        assert_eq!(
            out.filters,
            vec![DateFilter::Range {
                start: expected_start,
                end: expected_start + ms_per_day()
            }]
        );
    }

    #[test]
    fn yesterday_is_previous_day_window() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(":yesterday", now);
        let yesterday = at(2026, 5, 2, 0, 0).timestamp_millis();
        assert_eq!(
            out.filters,
            vec![DateFilter::Range {
                start: yesterday,
                end: yesterday + ms_per_day()
            }]
        );
    }

    #[test]
    fn n_days_filter() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(":7d", now);
        let expected = now.timestamp_millis() - 7 * ms_per_day();
        assert_eq!(out.filters, vec![DateFilter::After(expected)]);
    }

    #[test]
    fn n_days_with_text() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(":7d kubectl", now);
        assert_eq!(out.text, "kubectl");
        assert_eq!(out.filters.len(), 1);
        assert!(matches!(out.filters[0], DateFilter::After(_)));
    }

    #[test]
    fn after_date() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(">2026-04-01", now);
        let expected = at(2026, 4, 1, 0, 0).timestamp_millis();
        assert_eq!(out.filters, vec![DateFilter::After(expected)]);
    }

    #[test]
    fn before_date() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse("<2026-04-01", now);
        let expected = at(2026, 4, 1, 0, 0).timestamp_millis();
        assert_eq!(out.filters, vec![DateFilter::Before(expected)]);
    }

    #[test]
    fn range_dates() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse("2026-04-01..2026-04-30", now);
        let start = at(2026, 4, 1, 0, 0).timestamp_millis();
        let end = at(2026, 4, 30, 0, 0).timestamp_millis() + ms_per_day();
        assert_eq!(out.filters, vec![DateFilter::Range { start, end }]);
    }

    #[test]
    fn invalid_date_falls_back_to_text() {
        let out = parse(">2026-13-99", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, ">2026-13-99");
        assert!(out.filters.is_empty());
    }

    #[test]
    fn ambiguous_year_token_is_text() {
        // A token that starts with a year but isn't a valid date filter
        // (no comparator prefix, not in YYYY-MM-DD..YYYY-MM-DD form) is text.
        let out = parse("2026project", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, "2026project");
        assert!(out.filters.is_empty());
    }

    #[test]
    fn multiple_filters_compose() {
        let now = at(2026, 5, 3, 14, 30);
        let out = parse(":7d >2026-04-15", now);
        assert_eq!(out.filters.len(), 2);
        assert!(matches!(out.filters[0], DateFilter::After(_)));
        assert!(matches!(out.filters[1], DateFilter::After(_)));
    }

    #[test]
    fn implausibly_large_n_falls_back_to_text() {
        let out = parse(":99999d", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, ":99999d");
        assert!(out.filters.is_empty());
    }

    #[test]
    fn whitespace_collapses() {
        let out = parse("  foo   bar  ", at(2026, 5, 3, 12, 0));
        assert_eq!(out.text, "foo bar");
    }
}
