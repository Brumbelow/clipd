//! Notification-area tray icon for the daemon (Win32-native).
//!
//! Built on `Shell_NotifyIconW` + a `TrackPopupMenu` popup. No third-party
//! crate — the previous `tray-icon` 0.23 implementation was reverted because
//! its Linux build pulls `gtk 0.18 -> glib 0.18.5` (RUSTSEC-2024-0429) into
//! Cargo.lock even though that chain never compiles on Windows.
//!
//! Lifecycle:
//!   * `install(hwnd, state)` — adds the icon and stashes a [`TrayHandle`].
//!     Called from `win_hook::run` after `CreateWindowExW`.
//!   * `handle_callback(hwnd, lparam, state)` — called from `wnd_proc` when
//!     the icon receives a mouse event. We open a popup menu on right-click.
//!   * `uninstall(handle)` — removes the icon from the notification area
//!     and destroys the HICON. Called from `win_hook::run` after the message
//!     pump exits.
//!
//! The icon, popup, and dispatch all run on the daemon's main thread inside
//! the existing `wnd_proc`. There is no separate worker thread, no mpsc
//! HWND shuttle, and no WM_TIMER reconcile — the popup menu is rebuilt fresh
//! on each right-click and reads `state.is_paused()` directly, so the
//! checkmark always reflects current state.

use crate::daemon::DaemonState;
use anyhow::{bail, Context, Result};
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIcon, CreatePopupMenu, DestroyIcon, DestroyMenu, GetCursorPos, PostMessageW,
    SetForegroundWindow, TrackPopupMenu, HICON, HMENU, MF_CHECKED, MF_SEPARATOR, MF_STRING,
    TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_RBUTTONUP,
};

/// Stable id for our tray icon. Same hwnd may host multiple icons in the
/// future; this one is `clip d` in hex.
pub const TRAY_UID: u32 = 0xC11D;

/// Callback message Windows posts to our wnd_proc when the tray icon
/// receives input. `WM_APP` is the documented private-message base; `+1`
/// is unique within our app.
pub const TRAY_CALLBACK_MSG: u32 = WM_APP + 1;

const MENU_ID_PAUSE: u32 = 1;
const MENU_ID_OPEN_CFG: u32 = 2;
const MENU_ID_QUIT: u32 = 3;

/// Returned by [`install`] — caller owns it for the lifetime of the daemon
/// and passes it to [`uninstall`] before exit.
pub struct TrayHandle {
    hwnd: HWND,
    uid: u32,
    hicon: HICON,
}

/// Action chosen from the popup menu. Pure value so the id→action mapping
/// is unit-testable; the side effect (state mutation, child spawn,
/// PostMessageW) lives in the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    TogglePause,
    OpenConfig,
    Quit,
    Unknown,
}

fn dispatch(menu_id: u32) -> Action {
    match menu_id {
        MENU_ID_PAUSE => Action::TogglePause,
        MENU_ID_OPEN_CFG => Action::OpenConfig,
        MENU_ID_QUIT => Action::Quit,
        _ => Action::Unknown,
    }
}

/// Add the tray icon. Must be called from the same thread as `hwnd`'s
/// message pump (the daemon's main thread).
pub fn install(hwnd: HWND, _state: DaemonState) -> Result<TrayHandle> {
    let hicon = build_hicon().context("building tray HICON")?;

    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: TRAY_CALLBACK_MSG,
        hIcon: hicon,
        ..Default::default()
    };
    write_tip(&mut nid.szTip, "clipd");

    // SAFETY: nid is fully populated; hwnd and hicon are valid handles
    // owned by this process.
    let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
    if !ok.as_bool() {
        // SAFETY: hicon came from CreateIcon above; destroying once on the
        // failure path so we don't leak a system handle.
        unsafe {
            let _ = DestroyIcon(hicon);
        }
        bail!("Shell_NotifyIconW(NIM_ADD) failed");
    }
    info!("tray icon registered (uid={TRAY_UID:#x})");

    Ok(TrayHandle {
        hwnd,
        uid: TRAY_UID,
        hicon,
    })
}

/// Remove the tray icon and destroy its HICON. Idempotent on a freshly-
/// constructed handle — calling twice would re-attempt NIM_DELETE and
/// log a warning, which is harmless.
pub fn uninstall(handle: &TrayHandle) {
    let nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: handle.hwnd,
        uID: handle.uid,
        ..Default::default()
    };
    // SAFETY: nid carries cbSize/hWnd/uID; that's all NIM_DELETE needs.
    let ok = unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
    if !ok.as_bool() {
        warn!("Shell_NotifyIconW(NIM_DELETE) failed");
    }
    // SAFETY: hicon was created by install via CreateIcon; ownership ours.
    unsafe {
        let _ = DestroyIcon(handle.hicon);
    }
}

/// Called from wnd_proc when `TRAY_CALLBACK_MSG` arrives. The mouse event
/// is in the low word of `lparam`. Right-click opens the popup; other
/// events are ignored for now.
pub fn handle_callback(hwnd: HWND, lparam: LPARAM, state: &DaemonState) {
    let event = (lparam.0 as u32) & 0xFFFF;
    if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
        show_popup_menu(hwnd, state);
    }
}

fn show_popup_menu(hwnd: HWND, state: &DaemonState) {
    // SAFETY: CreatePopupMenu returns NULL on failure; checked below.
    let menu: HMENU = match unsafe { CreatePopupMenu() } {
        Ok(m) => m,
        Err(e) => {
            warn!("CreatePopupMenu failed: {e}");
            return;
        }
    };

    let pause_label = wide("Pause capture");
    let open_label = wide("Open config");
    let quit_label = wide("Quit");
    let pause_flags = MF_STRING
        | if state.is_paused() {
            MF_CHECKED
        } else {
            windows::Win32::UI::WindowsAndMessaging::MENU_ITEM_FLAGS(0)
        };

    // SAFETY: menu valid; PCWSTRs point at NUL-terminated UTF-16 strings
    // owned by locals that outlive this call. The numeric ids are non-zero
    // u32s, encoded as usize per the AppendMenuW contract.
    unsafe {
        let _ = AppendMenuW(
            menu,
            pause_flags,
            MENU_ID_PAUSE as usize,
            PCWSTR(pause_label.as_ptr()),
        );
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_ID_OPEN_CFG as usize,
            PCWSTR(open_label.as_ptr()),
        );
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_ID_QUIT as usize,
            PCWSTR(quit_label.as_ptr()),
        );
    }

    let mut pt = windows::Win32::Foundation::POINT::default();
    // SAFETY: pt is a valid out-pointer.
    let got_pos = unsafe { GetCursorPos(&mut pt) };
    if got_pos.is_err() {
        warn!("GetCursorPos failed");
        // SAFETY: menu owned; destroy before returning to avoid handle leak.
        unsafe {
            let _ = DestroyMenu(menu);
        }
        return;
    }

    // Required by Shell_NotifyIcon docs: focus must transfer to our window
    // for the menu to dismiss correctly when the user clicks outside it.
    // SAFETY: hwnd is the daemon's message-only window; valid for the call.
    unsafe {
        let _ = SetForegroundWindow(hwnd);
    }

    // SAFETY: menu valid; hwnd valid; TPM_RETURNCMD makes TrackPopupMenu
    // return the chosen item id (or 0 on dismiss) instead of posting
    // WM_COMMAND. lptpm = NULL accepts the default exclude rect.
    let cmd = unsafe {
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | windows::Win32::UI::WindowsAndMessaging::TPM_RETURNCMD,
            pt.x,
            pt.y,
            0,
            hwnd,
            None,
        )
    };
    // SAFETY: menu owned; destroy once, regardless of cmd outcome.
    unsafe {
        let _ = DestroyMenu(menu);
    }

    if cmd.0 == 0 {
        // User dismissed without choosing. No-op.
        return;
    }

    apply_action(dispatch(cmd.0 as u32), hwnd, state);
}

fn apply_action(action: Action, hwnd: HWND, state: &DaemonState) {
    match action {
        Action::TogglePause => {
            let new = !state.is_paused();
            state.set_paused(new);
            info!(paused = new, "tray pause toggled");
        }
        Action::OpenConfig => {
            let path = state.cfg.source_path.clone();
            let path_str = path.to_string_lossy().into_owned();
            // `cmd /C start "" <path>` honours user file associations and
            // returns immediately; the empty `""` is the literal command-
            // window title arg that `start` requires when the path is quoted.
            if let Err(e) = std::process::Command::new("cmd")
                .args(["/C", "start", "", &path_str])
                .spawn()
            {
                warn!("open config failed: {e:#}");
            }
        }
        Action::Quit => {
            info!("tray Quit selected — posting WM_CLOSE");
            // SAFETY: hwnd is valid for the daemon's lifetime. WM_CLOSE →
            // DefWindowProcW → DestroyWindow → WM_DESTROY → PostQuitMessage.
            unsafe {
                let _ = PostMessageW(
                    hwnd,
                    WM_CLOSE,
                    windows::Win32::Foundation::WPARAM(0),
                    LPARAM(0),
                );
            }
        }
        Action::Unknown => {}
    }
}

/// Build a 16×16 RGBA tray icon in-process. Solid blue square with a
/// lighter border, no asset file needed. Picked to read cleanly at small
/// sizes against both light and dark Windows themes.
fn make_icon_rgba() -> (Vec<u8>, u32, u32) {
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

/// Convert top-down RGBA pixels into the bottom-up BGRA buffer that
/// `CreateIcon`'s XOR mask expects for a 32-bit DIB. Scanlines are
/// already 4-byte-aligned at 32bpp; no row padding needed.
fn rgba_to_icon_bits(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    debug_assert_eq!(rgba.len() as u32, w * h * 4);
    let mut out = Vec::with_capacity(rgba.len());
    for y in (0..h).rev() {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            // RGBA -> BGRA
            out.push(rgba[i + 2]);
            out.push(rgba[i + 1]);
            out.push(rgba[i]);
            out.push(rgba[i + 3]);
        }
    }
    out
}

fn build_hicon() -> Result<HICON> {
    let (rgba, w, h) = make_icon_rgba();
    let xor_bits = rgba_to_icon_bits(&rgba, w, h);
    // Monochrome AND mask: 1 bit per pixel, 0 = visible (fully opaque),
    // each scanline padded to a DWORD (4 bytes). 16 cols = 2 bytes raw,
    // padded to 4; 16 rows × 4 = 64 bytes.
    let and_mask = vec![0u8; (h * 4) as usize];

    // SAFETY: hInstance=NULL is valid for CreateIcon (the icon is process-
    // scoped, not module-scoped). cPlanes=1 / cBitsPixel=32 matches the
    // BGRA layout of xor_bits. Both buffers outlive the call.
    let hicon = unsafe {
        CreateIcon(
            None,
            w as i32,
            h as i32,
            1,
            32,
            and_mask.as_ptr(),
            xor_bits.as_ptr(),
        )
    }
    .context("CreateIcon")?;

    if hicon.0.is_null() {
        bail!("CreateIcon returned NULL");
    }
    Ok(hicon)
}

fn write_tip(buf: &mut [u16; 128], text: &str) {
    for (i, ch) in text.encode_utf16().take(127).enumerate() {
        buf[i] = ch;
    }
    // Ensure NUL termination — `text` may be ≤127 wchars, the tail is
    // already zero-initialized by NOTIFYICONDATAW::default but be explicit.
    let n = text.encode_utf16().count().min(127);
    buf[n] = 0;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_icon_rgba_has_expected_shape() {
        let (rgba, w, h) = make_icon_rgba();
        assert_eq!(w, 16);
        assert_eq!(h, 16);
        assert_eq!(rgba.len(), 16 * 16 * 4);
        for px in rgba.chunks_exact(4) {
            assert_eq!(px[3], 0xFF, "all pixels are fully opaque");
        }
        assert_eq!(&rgba[0..4], &[180, 180, 180, 0xFF], "border at (0,0)");
        let interior = ((16 + 1) * 4) as usize;
        assert_eq!(
            &rgba[interior..interior + 4],
            &[60, 120, 220, 0xFF],
            "blue at (1,1)"
        );
    }

    #[test]
    fn rgba_to_icon_bits_swaps_rgb_and_reverses_rows() {
        // 2x2 fixture, top-down RGBA:
        //   (0,0)=A:(10,20,30,40)   (1,0)=B:(50,60,70,80)
        //   (0,1)=C:(90,100,110,120) (1,1)=D:(130,140,150,160)
        let rgba: Vec<u8> = vec![
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ];
        let out = rgba_to_icon_bits(&rgba, 2, 2);
        // Bottom-up BGRA: row 1 first (C, D), then row 0 (A, B). Each
        // pixel BGRA = swap R↔B from source RGBA.
        let expected: Vec<u8> = vec![
            // row 1 (was bottom in top-down): C then D, BGRA each
            110, 100, 90, 120, 150, 140, 130, 160, // row 0: A then B, BGRA each
            30, 20, 10, 40, 70, 60, 50, 80,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn dispatch_maps_known_menu_ids() {
        assert_eq!(dispatch(MENU_ID_PAUSE), Action::TogglePause);
        assert_eq!(dispatch(MENU_ID_OPEN_CFG), Action::OpenConfig);
        assert_eq!(dispatch(MENU_ID_QUIT), Action::Quit);
    }

    #[test]
    fn dispatch_unknown_id_returns_unknown() {
        assert_eq!(dispatch(0), Action::Unknown);
        assert_eq!(dispatch(9999), Action::Unknown);
    }

    #[test]
    fn write_tip_nul_terminates_within_buffer() {
        let mut buf = [0u16; 128];
        write_tip(&mut buf, "clipd");
        assert_eq!(
            &buf[..5],
            &[
                b'c' as u16,
                b'l' as u16,
                b'i' as u16,
                b'p' as u16,
                b'd' as u16
            ]
        );
        assert_eq!(buf[5], 0);
    }
}
