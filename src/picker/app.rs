//! egui picker: search box on top, virtualized result list below.
//!
//! Keyboard:
//!   typing       — incremental search
//!   ↑ / ↓        — move selection
//!   Enter        — promote selected entry, close
//!   Ctrl+P       — toggle pin on selected entry
//!   Delete       — remove selected entry
//!   Esc          — close without action

use crate::config::Config;
use crate::daemon::ipc::{self, EntrySummary, Request, Response};
use eframe::App;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

pub struct PickerApp {
    cfg: Arc<Config>,
    query: String,
    last_query: String,
    results: Vec<EntrySummary>,
    selected: usize,
    error: Option<String>,
    last_query_at: Instant,
    needs_refresh: bool,
    focused_once: bool,
    started_at: Instant,
    first_frame_logged: bool,
}

impl PickerApp {
    pub fn new(cfg: Arc<Config>, started_at: Instant) -> Self {
        let mut s = Self {
            cfg,
            query: String::new(),
            last_query: String::new(),
            results: Vec::new(),
            selected: 0,
            error: None,
            last_query_at: Instant::now(),
            needs_refresh: true,
            focused_once: false,
            started_at,
            first_frame_logged: false,
        };
        s.refresh();
        s
    }

    fn refresh(&mut self) {
        self.needs_refresh = false;
        self.last_query = self.query.clone();
        self.last_query_at = Instant::now();

        let req = if self.query.trim().is_empty() {
            Request::List {
                limit: self.cfg.picker.result_limit,
            }
        } else {
            Request::Search {
                query: self.query.clone(),
                limit: self.cfg.picker.result_limit,
            }
        };

        match ipc::client::send(&self.cfg, req) {
            Ok(Response::Entries(entries)) => {
                self.results = fuzzy_rank(&self.query, entries);
                if self.selected >= self.results.len() {
                    self.selected = self.results.len().saturating_sub(1);
                }
                self.error = None;
            }
            Ok(Response::Error(msg)) => self.error = Some(msg),
            Ok(_) => self.error = Some("unexpected response shape".into()),
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn promote_selected(&mut self, ctx: &egui::Context) {
        if let Some(entry) = self.results.get(self.selected) {
            if let Err(e) = ipc::client::send(&self.cfg, Request::Promote { id: entry.id }) {
                self.error = Some(format!("promote: {e:#}"));
                return;
            }
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn delete_selected(&mut self) {
        if let Some(entry) = self.results.get(self.selected) {
            let id = entry.id;
            if let Err(e) = ipc::client::send(&self.cfg, Request::Delete { id }) {
                self.error = Some(format!("delete: {e:#}"));
                return;
            }
            self.needs_refresh = true;
        }
    }

    fn toggle_pin_selected(&mut self) {
        if let Some(entry) = self.results.get(self.selected) {
            let id = entry.id;
            let pinned = !entry.pinned;
            if let Err(e) = ipc::client::send(&self.cfg, Request::Pin { id, pinned }) {
                self.error = Some(format!("pin: {e:#}"));
                return;
            }
            self.needs_refresh = true;
        }
    }
}

impl App for PickerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.first_frame_logged {
            self.first_frame_logged = true;
            info!(
                "picker cold-start to first frame: {}ms",
                self.started_at.elapsed().as_millis()
            );
        }
        // Debounced search refresh: 80ms after last keystroke.
        if self.query != self.last_query
            && self.last_query_at.elapsed() >= std::time::Duration::from_millis(80)
        {
            self.needs_refresh = true;
        }
        if self.needs_refresh {
            self.refresh();
        }
        // Keep refreshing while typing so debounce fires.
        if self.query != self.last_query {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }

        // Global key handling.
        ctx.input(|i| {
            if i.key_pressed(egui::Key::Escape) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if i.key_pressed(egui::Key::ArrowDown) && self.selected + 1 < self.results.len() {
                self.selected += 1;
            }
            if i.key_pressed(egui::Key::ArrowUp) && self.selected > 0 {
                self.selected -= 1;
            }
            if i.key_pressed(egui::Key::Delete) {
                self.delete_selected();
            }
            if i.modifiers.ctrl && i.key_pressed(egui::Key::P) {
                self.toggle_pin_selected();
            }
        });

        let promote = ctx.input(|i| i.key_pressed(egui::Key::Enter));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("search clipboard… (:today, :7d, :pinned)")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Heading),
                );
                if !self.focused_once {
                    resp.request_focus();
                    self.focused_once = true;
                }
                if let Some(err) = &self.error {
                    ui.colored_label(egui::Color32::RED, err);
                }
                ui.separator();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (i, entry) in self.results.iter().enumerate() {
                            let is_sel = i == self.selected;
                            let bg = if is_sel {
                                ui.style().visuals.selection.bg_fill
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            egui::Frame::none().fill(bg).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.set_width(ui.available_width());
                                    ui.label(badge(&entry.kind));
                                    if entry.pinned {
                                        ui.label("📌");
                                    }
                                    ui.label(truncate(&entry.preview, 100));
                                });
                            });
                        }
                    });
            });
        });

        if promote {
            self.promote_selected(ctx);
        }
    }
}

/// Rerank server candidates by nucleo fuzzy score against `query`.
///
/// Empty query → return as-is (server already returns recency-ordered List).
/// Otherwise: filter out non-matchers, sort pinned-first → score desc → recency desc.
///
/// Pinned-first is folded in here even though Step 10 owns the broader
/// pinning UX; without it, high-fuzzy-score noise can bury pins.
fn fuzzy_rank(query: &str, items: Vec<EntrySummary>) -> Vec<EntrySummary> {
    use nucleo::pattern::{CaseMatching, Normalization, Pattern};
    use nucleo::Matcher;

    let q = query.trim();
    if q.is_empty() {
        return items;
    }
    let mut matcher = Matcher::new(nucleo::Config::DEFAULT);
    let pattern = Pattern::parse(q, CaseMatching::Smart, Normalization::Smart);
    let mut buf: Vec<char> = Vec::new();

    let mut scored: Vec<(u32, EntrySummary)> = items
        .into_iter()
        .filter_map(|e| {
            buf.clear();
            let haystack = nucleo::Utf32Str::new(&e.preview, &mut buf);
            pattern.score(haystack, &mut matcher).map(|s| (s, e))
        })
        .collect();

    scored.sort_by(|a, b| {
        b.1.pinned
            .cmp(&a.1.pinned)
            .then(b.0.cmp(&a.0))
            .then(b.1.last_seen.cmp(&a.1.last_seen))
    });
    scored.into_iter().map(|(_, e)| e).collect()
}

fn badge(kind: &str) -> egui::RichText {
    let color = match kind {
        "image" => egui::Color32::from_rgb(180, 120, 220),
        "files" => egui::Color32::from_rgb(220, 180, 120),
        "html" | "rtf" => egui::Color32::from_rgb(120, 180, 220),
        _ => egui::Color32::from_rgb(120, 220, 180),
    };
    egui::RichText::new(format!(" {kind:<5} "))
        .color(egui::Color32::BLACK)
        .background_color(color)
        .monospace()
}

fn truncate(s: &str, max: usize) -> String {
    let one_line: String = s.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    if one_line.chars().count() <= max {
        one_line
    } else {
        let mut out: String = one_line.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: i64, preview: &str, last_seen: i64, pinned: bool) -> EntrySummary {
        EntrySummary {
            id,
            kind: "text".into(),
            preview: preview.into(),
            created_at: last_seen,
            last_seen,
            pinned,
        }
    }

    #[test]
    fn truncate_keeps_short_strings_intact() {
        assert_eq!(truncate("hello", 100), "hello");
        assert_eq!(truncate("", 100), "");
    }

    #[test]
    fn truncate_collapses_newlines_and_appends_ellipsis() {
        assert_eq!(truncate("a\nb\nc", 100), "a b c");
        let long = "a".repeat(200);
        let out = truncate(&long, 50);
        assert_eq!(out.chars().count(), 50);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn fuzzy_rank_empty_query_preserves_order() {
        let items = vec![
            entry(1, "alpha", 3000, false),
            entry(2, "bravo", 2000, false),
            entry(3, "charlie", 1000, false),
        ];
        let out = fuzzy_rank("", items.clone());
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].preview, "alpha");
        assert_eq!(out[1].preview, "bravo");
        assert_eq!(out[2].preview, "charlie");
    }

    #[test]
    fn fuzzy_rank_filters_non_matching() {
        let items = vec![
            entry(1, "foobar", 1000, false),
            entry(2, "baz", 1000, false),
            entry(3, "frobnicate", 1000, false),
        ];
        let out = fuzzy_rank("foo", items);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].preview, "foobar");
    }

    #[test]
    fn fuzzy_rank_pins_float_to_top() {
        // Pinned entry has a weak match ("kub" inside "kubernetes-pinned"),
        // unpinned has a strong direct prefix match. Pinned still wins.
        let items = vec![
            entry(1, "kubectl get pods", 2000, false),
            entry(2, "noisy kub reference", 1000, true),
        ];
        let out = fuzzy_rank("kub", items);
        assert_eq!(out.len(), 2);
        assert!(
            out[0].pinned,
            "pinned entry must sort first regardless of score"
        );
    }

    #[test]
    fn fuzzy_rank_ties_break_by_recency() {
        // Two identical previews → identical scores → newer last_seen first.
        let items = vec![
            entry(1, "exact match", 1000, false),
            entry(2, "exact match", 5000, false),
        ];
        let out = fuzzy_rank("exact match", items);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, 2, "newer entry should rank first on tie");
        assert_eq!(out[1].id, 1);
    }
}
