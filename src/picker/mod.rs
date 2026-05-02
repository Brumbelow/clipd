//! egui picker process. Wired in Step 6.
//!
//! `clipd pick` boots a borderless, always-on-top eframe window. The daemon's
//! WM_HOTKEY handler spawns this binary with `pick`; the picker talks back to
//! the daemon over the Step-5 named-pipe IPC for List/Search/Promote/Pin/Delete.

mod app;

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

pub fn run(cfg: Config) -> Result<()> {
    // Measures eframe init + first-paint — the part Step 6.5's wgpu→glow swap
    // is targeting. Process spawn + arg parse + config load happen before this
    // and are tracked as residual in the SESSION_LOG.
    let started_at = Instant::now();
    let cfg = Arc::new(cfg);
    let viewport = egui::ViewportBuilder::default()
        .with_title("clipd")
        .with_inner_size([680.0, 420.0])
        .with_min_inner_size([480.0, 240.0])
        .with_resizable(false)
        .with_decorations(false)
        .with_always_on_top()
        .with_active(true)
        .with_visible(true);
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        vsync: true,
        ..Default::default()
    };
    eframe::run_native(
        "clipd",
        options,
        Box::new(move |_cc| Ok(Box::new(app::PickerApp::new(cfg.clone(), started_at)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {e}"))
}
