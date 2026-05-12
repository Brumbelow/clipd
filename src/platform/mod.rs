//! Platform-specific implementations.
//!
//! Each submodule exposes a target-neutral API (`autostart::enable_autostart`,
//! `keyring::wrap`, …) and selects between a real Windows impl and a stub
//! via inline `#[cfg(target_os = "…")]` gates. Linux/Mac ports replace the
//! `cfg(not(target_os = "windows"))` stub blocks with sibling
//! `cfg(target_os = "linux")` / `cfg(target_os = "macos")` implementations.
//!
//! What's NOT yet abstracted (still inline in `crate::daemon::*`):
//!   - `win_hook`        — message-only window, hotkey, foreground introspection
//!   - `tray`            — `Shell_NotifyIconW`
//!   - `clipboard_format`— `CF_*` constants and dispatch
//!   - `image`           — DIB↔PNG conversion
//!
//! These move under `platform/` during the Linux/Mac port, where the second
//! implementation forces a workable abstraction shape.

pub mod autostart;
pub mod keyring;
