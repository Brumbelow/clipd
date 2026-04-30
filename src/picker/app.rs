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

pub struct PickerApp {
    cfg: Arc<Config>,
    query: String,
    last_query: String,
    results: Vec<EntrySummary>,
    selected: usize,
    error: Option<String>,
    last_query_at: Instant,
    needs_refresh: bool,
}

impl PickerApp {
    pub fn new(cfg: Arc<Config>) -> Self {
        let mut s = Self {
            cfg,
            query: String::new(),
            last_query: String::new(),
            results: Vec::new(),
            selected: 0,
            error: None,
            last_query_at: Instant::now(),
            needs_refresh: true,
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
                self.results = entries;
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
                resp.request_focus();
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
