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
//!   - `tray`             — Step 11: notification-area icon + menu.

pub mod capture;
pub mod clipboard;
pub mod clipboard_format;
pub mod image;
pub mod ipc;
pub mod tray;
pub mod win_hook;

use crate::config::Config;
use crate::store::crypto::Vault;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::sync::Arc;

/// Shared daemon state. Cloneable: each subsystem holds its own handle.
#[derive(Clone)]
pub struct DaemonState {
    pub cfg: Arc<Config>,
    pub vault: Arc<Vault>,
    paused: Arc<RwLock<bool>>,
}

impl DaemonState {
    pub fn new(cfg: Arc<Config>, vault: Arc<Vault>) -> Self {
        Self {
            cfg,
            vault,
            paused: Arc::new(RwLock::new(false)),
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
    // Tray needs the daemon's message-only HWND for its Quit menu item.
    // win_hook posts the HWND down this channel after CreateWindowExW.
    let (hwnd_tx, hwnd_rx) = std::sync::mpsc::channel::<isize>();
    tray::spawn(state.clone(), hwnd_rx).context("starting tray icon")?;
    win_hook::run(state, Some(hwnd_tx))
}
