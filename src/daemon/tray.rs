//! Step 11: notification-area tray icon for the daemon.
//!
//! Lives on a dedicated `clipd-tray` thread that owns its own Win32 message
//! pump (the `tray-icon` crate creates internal hidden windows; messages on
//! the creating thread keep the icon and menu callbacks alive).
//!
//! Menu:
//! - "Pause capture" (check toggle, mirrored to `DaemonState.paused`)
//! - "Open config" (opens `config.toml` in the default editor)
//! - "Quit" (PostMessageW WM_CLOSE → daemon's wnd_proc → PostQuitMessage)
//!
//! The daemon's main HWND is needed for Quit. We receive it over an mpsc
//! channel from `win_hook::run` after `CreateWindowExW` returns — HWND is
//! `*mut c_void` and not `Send`, so we marshal as `isize` and reconstruct
//! on the receiving end.

use crate::daemon::DaemonState;
use anyhow::{Context, Result};
use std::sync::mpsc::Receiver;
use tracing::{info, warn};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, KillTimer, PostMessageW, SetTimer, TranslateMessage, MSG,
    WM_CLOSE, WM_TIMER,
};

/// Timer id for the tray's reconcile pulse. Arbitrary non-zero value; only one
/// active timer per tray thread.
const RECONCILE_TIMER_ID: usize = 0xC11D_0001;
/// Reconcile cadence — how often the tray thread re-syncs the "Pause capture"
/// check state with `DaemonState.paused`. 200ms is below the Windows menu
/// open-animation budget so any state change appears instant.
const RECONCILE_INTERVAL_MS: u32 = 200;

/// Spawn the tray thread. `hwnd_rx` delivers the daemon's main HWND (as an
/// `isize`) once `win_hook::run` has created the message-only window.
pub fn spawn(state: DaemonState, hwnd_rx: Receiver<isize>) -> Result<()> {
    std::thread::Builder::new()
        .name("clipd-tray".into())
        .spawn(move || {
            if let Err(e) = run_tray(state, hwnd_rx) {
                warn!("tray thread exited with error: {e:#}");
            }
        })
        .context("spawning clipd-tray thread")?;
    Ok(())
}

fn run_tray(state: DaemonState, hwnd_rx: Receiver<isize>) -> Result<()> {
    // Block until the daemon's main hwnd is available. Without it, the Quit
    // menu item has no target.
    let raw_hwnd = hwnd_rx
        .recv()
        .context("waiting for daemon HWND from win_hook")?;
    let daemon_hwnd = HWND(raw_hwnd as *mut _);

    let (rgba, w, h) = make_icon();
    let icon = Icon::from_rgba(rgba, w, h).context("Icon::from_rgba")?;

    let menu = Menu::new();
    let pause_item = CheckMenuItem::new("Pause capture", true, state.is_paused(), None);
    let open_cfg_item = MenuItem::new("Open config", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append_items(&[&pause_item, &open_cfg_item, &quit_item])
        .context("appending tray menu items")?;

    let pause_id = pause_item.id().clone();
    let open_cfg_id = open_cfg_item.id().clone();
    let quit_id = quit_item.id().clone();

    // Tray icon must outlive the message pump.
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .with_tooltip("clipd")
        .build()
        .context("building tray icon")?;

    info!("tray icon registered");

    let pause_state = state.clone();
    let cfg_path = state.cfg.source_path.clone();

    // Marshal the HWND through a usize so the closure stays Send.
    let daemon_hwnd_raw = daemon_hwnd.0 as usize;

    // CheckMenuItem is !Send/!Sync (muda holds an Rc internally), so the
    // global handler can only mutate DaemonState. The tray thread itself
    // owns `pause_item` and reconciles its check state on a WM_TIMER tick
    // below, after each pause toggle settles in DaemonState.
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id == pause_id {
            let new = !pause_state.is_paused();
            pause_state.set_paused(new);
            info!(paused = new, "tray pause toggled");
        } else if event.id == open_cfg_id {
            // `cmd /C start "" "<path>"` honours user file associations and
            // returns immediately; the empty `""` is the literal command-window
            // title arg required by `start`.
            let path = cfg_path.clone();
            let path_str = path.to_string_lossy().into_owned();
            if let Err(e) = std::process::Command::new("cmd")
                .args(["/C", "start", "", &path_str])
                .spawn()
            {
                warn!("open config failed: {e:#}");
            }
        } else if event.id == quit_id {
            info!("tray Quit selected — posting WM_CLOSE to daemon hwnd");
            let hwnd = HWND(daemon_hwnd_raw as *mut _);
            // SAFETY: hwnd is the daemon's message-only window, valid for
            // the daemon's lifetime. WM_CLOSE → DefWindowProcW →
            // DestroyWindow → WM_DESTROY → PostQuitMessage(0).
            unsafe {
                let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
    }));

    // Schedule the periodic reconcile — drives the "Pause capture" check
    // state from `DaemonState.paused` so external pause/resume (CLI,
    // future autopause) also surfaces in the menu.
    // SAFETY: timer with HWND=NULL delivers WM_TIMER to the thread queue
    // with no callback (lpTimerFunc = None).
    let timer_id = unsafe {
        SetTimer(
            HWND::default(),
            RECONCILE_TIMER_ID,
            RECONCILE_INTERVAL_MS,
            None,
        )
    };
    if timer_id == 0 {
        warn!("SetTimer for tray reconcile failed; menu check state will lag");
    }

    // Run a Win32 message pump on this thread to keep the tray icon alive
    // and dispatch tray-icon's internal window callbacks. WM_TIMER ticks
    // also drive the menu's check-state reconcile.
    let mut msg = MSG::default();
    loop {
        // SAFETY: msg is a valid out-pointer; HWND::default() (NULL) means
        // any window owned by this thread.
        let r = unsafe { GetMessageW(&mut msg, HWND::default(), 0, 0) };
        if r.0 <= 0 {
            break; // 0 = WM_QUIT, -1 = error
        }

        if msg.message == WM_TIMER && msg.wParam.0 == RECONCILE_TIMER_ID {
            let want = state.is_paused();
            if pause_item.is_checked() != want {
                pause_item.set_checked(want);
            }
        }

        // SAFETY: msg has been populated by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if timer_id != 0 {
        // SAFETY: timer was created with HWND=NULL above; same args here.
        unsafe {
            let _ = KillTimer(HWND::default(), RECONCILE_TIMER_ID);
        }
    }
    info!("tray thread exiting");
    Ok(())
}

/// Build a 16×16 RGBA tray icon in-process. Solid blue square with a lighter
/// border, no asset file needed. Picked to read cleanly at small sizes
/// against both light and dark Windows themes.
fn make_icon() -> (Vec<u8>, u32, u32) {
    const W: u32 = 16;
    const H: u32 = 16;
    let mut rgba = vec![0u8; (W * H * 4) as usize];
    for y in 0..H {
        for x in 0..W {
            let i = ((y * W + x) * 4) as usize;
            let on_border = x == 0 || x == W - 1 || y == 0 || y == H - 1;
            let (r, g, b) = if on_border {
                (180, 180, 180)
            } else {
                (60, 120, 220)
            };
            rgba[i] = r;
            rgba[i + 1] = g;
            rgba[i + 2] = b;
            rgba[i + 3] = 0xFF;
        }
    }
    (rgba, W, H)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_bytes_have_expected_shape() {
        let (rgba, w, h) = make_icon();
        assert_eq!(w, 16);
        assert_eq!(h, 16);
        assert_eq!(rgba.len(), 16 * 16 * 4);
        // Alpha is fully opaque on every pixel.
        for px in rgba.chunks_exact(4) {
            assert_eq!(px[3], 0xFF);
        }
        // Border pixel (0,0) is the grey border.
        assert_eq!(&rgba[0..4], &[180, 180, 180, 0xFF]);
        // Interior pixel (1,1) is the blue fill.
        let i = ((16 + 1) * 4) as usize;
        assert_eq!(&rgba[i..i + 4], &[60, 120, 220, 0xFF]);
    }
}
