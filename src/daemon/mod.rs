//! Daemon: long-lived process owning the clipboard hook, hotkey, and store.
//!
//! Composition:
//!   - `win_hook`         — Win32 message-only window, listener, hotkey, message pump.
//!   - `capture`          — clipboard payload read + store insert.
//!   - `clipboard`        — clipboard write path (Step 5 text, Step 7 multi-format,
//!     Step 8 image).
//!   - `clipboard_format` — Step 7: format enumeration + name/code helpers.
//!   - `image`            — Step 8: DIB↔PNG conversion + thumbnail resize.
//!   - `ipc`              — named-pipe server.
//!   - `tray`             — Step 11: notification-area icon + popup menu
//!     (native Shell_NotifyIconW; runs inside wnd_proc on the main thread).

pub mod capture;
pub mod clipboard;
pub mod clipboard_format;
pub mod image;
pub mod ipc;
pub mod picker_supervisor;
pub mod purge;
pub mod tray;
pub mod win_hook;

use crate::config::Config;
use crate::store::crypto::Vault;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Shared daemon state. Cloneable: each subsystem holds its own handle.
#[derive(Clone)]
pub struct DaemonState {
    pub cfg: Arc<Config>,
    pub vault: Arc<Vault>,
    paused: Arc<RwLock<bool>>,
    /// Step 11: PID of the current `clipd pick --prewarm` child, or 0 if no
    /// prewarmed picker is alive. Set by the supervisor on each spawn.
    pub picker_pid: Arc<AtomicU32>,
    /// Step 11: supervisor flips this after a crash-loop. With this set,
    /// `WM_HOTKEY` falls back to spawning a fresh one-shot picker instead
    /// of sending Show over IPC.
    pub prewarm_disabled: Arc<AtomicBool>,
    /// Step 11: tells the picker supervisor to stop respawning. Set by
    /// `daemon::run` after the message pump exits.
    pub shutting_down: Arc<AtomicBool>,
}

impl DaemonState {
    pub fn new(cfg: Arc<Config>, vault: Arc<Vault>) -> Self {
        Self {
            cfg,
            vault,
            paused: Arc::new(RwLock::new(false)),
            picker_pid: Arc::new(AtomicU32::new(0)),
            prewarm_disabled: Arc::new(AtomicBool::new(false)),
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
    // Step 12: nightly retention purge. Detached thread; observes
    // `state.shutting_down` to exit cleanly with the daemon.
    let _ = purge::spawn(state.clone());
    // Step 11: prewarm the picker so WM_HOTKEY can re-show instead of
    // fork-execing a fresh process per press.
    if let Err(e) = picker_supervisor::spawn(state.clone()) {
        // Non-fatal: the WM_HOTKEY handler falls back to legacy spawn.
        tracing::warn!("picker supervisor failed to start: {e:#}");
        state.prewarm_disabled.store(true, Ordering::SeqCst);
    }
    let pump_result = win_hook::run(state.clone());
    // Step 11: stop the supervisor and reap the picker child so it doesn't
    // outlive the daemon as an orphan.
    state.shutting_down.store(true, Ordering::SeqCst);
    let pid = state.picker_pid.load(Ordering::SeqCst);
    if pid != 0 {
        picker_supervisor::kill_pid(pid);
    }
    pump_result
}
