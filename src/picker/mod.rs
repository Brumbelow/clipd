//! egui picker process.
//!
//! `clipd pick` boots a borderless, always-on-top eframe window. The daemon's
//! WM_HOTKEY handler spawns this binary with `pick`; the picker talks back to
//! the daemon over the named-pipe IPC for List/Search/Promote/Pin/Delete.
//!
//! `clipd pick --prewarm` boots hidden and listens on
//! `\\.\pipe\clipd-picker` for `Show` requests so the daemon can re-show the
//! same process on hotkey instead of fork-execing every time. Esc/Enter hide
//! instead of exiting.

mod app;
mod query;

use crate::config::Config;
use crate::daemon::ipc::picker_pipe::{self, PickerRequest, PICKER_PIPE_NAME};
use anyhow::Result;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

pub fn run(cfg: Config, prewarm: bool) -> Result<()> {
    // Measures eframe init + first-paint — the part the wgpu→glow swap
    // is targeting. Process spawn + arg parse + config load happen before
    // this and are not measured here.
    let started_at = Instant::now();
    let cfg = Arc::new(cfg);

    let show_requested = Arc::new(AtomicBool::new(false));
    let show_request_at = Arc::new(parking_lot::Mutex::new(None::<Instant>));

    if prewarm {
        // Listener thread funnels Show requests into the show_requested flag
        // and stamps a timestamp the App reads to log show-to-visible latency.
        let (tx, rx) = mpsc::channel::<PickerRequest>();
        if let Err(e) = picker_pipe::spawn_listener(PICKER_PIPE_NAME, tx) {
            warn!("picker IPC listener failed; running without prewarm: {e:#}");
        } else {
            let flag = show_requested.clone();
            let stamp = show_request_at.clone();
            std::thread::Builder::new()
                .name("clipd-picker-show-fanout".into())
                .spawn(move || {
                    while let Ok(req) = rx.recv() {
                        match req {
                            PickerRequest::Show => {
                                *stamp.lock() = Some(Instant::now());
                                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }
                })
                .ok();
            info!("picker prewarm: listener up");
        }
    }

    let viewport = egui::ViewportBuilder::default()
        .with_title("clipd")
        .with_inner_size([680.0, 420.0])
        .with_min_inner_size([480.0, 240.0])
        .with_resizable(false)
        .with_decorations(false)
        .with_always_on_top()
        .with_active(!prewarm)
        // Prewarm starts hidden — first frame paints offscreen, hotkey shows.
        .with_visible(!prewarm);
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        vsync: true,
        ..Default::default()
    };
    let close_behaviour = if prewarm {
        app::CloseBehaviour::Hide
    } else {
        app::CloseBehaviour::Exit
    };
    eframe::run_native(
        "clipd",
        options,
        Box::new(move |cc| {
            // Wake egui from the listener thread so a Show signal renders
            // within one frame instead of waiting for the next idle repaint.
            let ctx = cc.egui_ctx.clone();
            let flag = show_requested.clone();
            std::thread::Builder::new()
                .name("clipd-picker-repaint".into())
                .spawn(move || {
                    use std::sync::atomic::Ordering;
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(16));
                        if flag.load(Ordering::SeqCst) {
                            ctx.request_repaint();
                        }
                    }
                })
                .ok();

            Ok(Box::new(app::PickerApp::new(
                cfg.clone(),
                started_at,
                close_behaviour,
                show_requested.clone(),
                show_request_at.clone(),
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {e}"))
}
