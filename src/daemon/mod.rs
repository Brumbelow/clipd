//! Daemon: long-lived process owning the clipboard hook, hotkey, and store.
//!
//! Composition:
//!   - `win_hook`         — Win32 message-only window, listener, hotkey, message pump.
//!   - `capture`          — clipboard payload read + store insert.
//!   - `clipboard`        — clipboard write path (text, multi-format, image).
//!   - `clipboard_format` — format enumeration + name/code helpers.
//!   - `image`            — DIB↔PNG conversion + thumbnail resize.
//!   - `ipc`              — named-pipe server.
//!   - `tray`             — notification-area icon + popup menu
//!     (native Shell_NotifyIconW; runs inside wnd_proc on the main thread).

pub mod capture;
pub mod clipboard;
pub mod clipboard_format;
pub mod image;
pub mod ipc;
pub mod purge;
pub mod tray;
pub mod win_hook;

use crate::config::Config;
use crate::store::crypto::Vault;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Shared daemon state. Cloneable: each subsystem holds its own handle.
#[derive(Clone)]
pub struct DaemonState {
    pub cfg: Arc<Config>,
    pub vault: Arc<Vault>,
    paused: Arc<RwLock<bool>>,
    /// Set true by `daemon::run` after the message pump exits so background
    /// threads (currently `purge`) can break out of their wait loops.
    pub shutting_down: Arc<AtomicBool>,
}

impl DaemonState {
    pub fn new(cfg: Arc<Config>, vault: Arc<Vault>) -> Self {
        Self {
            cfg,
            vault,
            paused: Arc::new(RwLock::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.read()
    }

    pub fn set_paused(&self, v: bool) {
        *self.paused.write() = v;
    }
}

/// Daemon entrypoint. Blocks on the Win32 message pump until WM_QUIT.
pub fn run(cfg: Config) -> Result<()> {
    let key_path = cfg.key_full_path();
    let vault = Vault::open(&key_path).context("opening clipd vault (DPAPI key)")?;
    let state = DaemonState::new(Arc::new(cfg), Arc::new(vault));
    ipc::server::spawn(state.clone()).context("starting IPC server")?;
    // Nightly retention purge. Detached thread; observes
    // `state.shutting_down` to exit cleanly with the daemon.
    let _ = purge::spawn(state.clone());
    // WM_HOTKEY cold-spawns `clipd pick` per press (~150–400ms each but
    // reliable). A previous prewarmed-picker design was removed because a
    // hidden eframe window stopped servicing `Visible(true)` viewport
    // commands after one hide cycle on Windows.
    let pump_result = win_hook::run(state.clone());
    state
        .shutting_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    pump_result
}
