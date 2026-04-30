//! Daemon: long-lived process owning the clipboard hook, hotkey, and store.
//!
//! Composition:
//!   - `win_hook`  — Win32 message-only window, listener, hotkey, message pump.
//!   - `capture`   — clipboard payload read + store insert.
//!   - `ipc`       — named-pipe server (stub until Step 5).

pub mod capture;
pub mod ipc;
pub mod win_hook;

use crate::config::Config;
use anyhow::Result;
use parking_lot::RwLock;
use std::sync::Arc;

/// Shared daemon state. Cloneable: each subsystem holds its own handle.
#[derive(Clone)]
pub struct DaemonState {
    pub cfg: Arc<Config>,
    paused: Arc<RwLock<bool>>,
}

impl DaemonState {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {
            cfg,
            paused: Arc::new(RwLock::new(false)),
        }
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.read()
    }

    #[allow(dead_code)] // wired in Step 5 via IPC Pause/Resume
    pub fn set_paused(&self, v: bool) {
        *self.paused.write() = v;
    }
}

/// Daemon entrypoint. Blocks on the Win32 message pump until WM_QUIT.
pub fn run(cfg: Config) -> Result<()> {
    let state = DaemonState::new(Arc::new(cfg));
    win_hook::run(state)
}
