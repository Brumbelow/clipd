//! Win32 plumbing: message-only window, clipboard listener, global hotkey.
//!
//! All Win32 calls are unsafe; SAFETY comments cover each block.

use crate::daemon::{capture, DaemonState};
use anyhow::{anyhow, bail, Context, Result};
use once_cell::sync::OnceCell;
use tracing::{debug, error, info, warn};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetForegroundWindow, GetMessageW,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, PostQuitMessage,
    RegisterClassExW, TranslateMessage, HMENU, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_CLIPBOARDUPDATE, WM_DESTROY, WM_HOTKEY, WNDCLASSEXW,
};

const HOTKEY_ID: i32 = 0xC11D; // "clip d"

/// Module-global state pointer. Set once at startup. The wnd_proc reads it.
static STATE: OnceCell<DaemonState> = OnceCell::new();

pub fn run(state: DaemonState) -> Result<()> {
    STATE
        .set(state.clone())
        .map_err(|_| anyhow!("daemon already running in this process"))?;

    let class_name = wide("clipd-listener");
    let window_name = wide("clipd");

    // SAFETY: GetModuleHandleW(NULL) returns a handle to the calling process
    // executable; documented to never fail with NULL.
    let hinstance = unsafe { GetModuleHandleW(PCWSTR::null()).context("GetModuleHandleW")? };

    let wnd_class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinstance.into(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    // SAFETY: wnd_class is fully initialized; pointer is valid for the duration of the call.
    let atom = unsafe { RegisterClassExW(&wnd_class) };
    if atom == 0 {
        bail!("RegisterClassExW failed");
    }

    // SAFETY: HWND_MESSAGE is a documented sentinel parent for message-only windows.
    // No menu, no instance ptr, no extra param. Window has no visible style and
    // never appears on screen.
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(window_name.as_ptr()),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        )
        .context("CreateWindowExW (message-only)")?
    };

    info!("message-only window created: hwnd={:p}", hwnd.0);

    // Register clipboard format listener.
    // SAFETY: hwnd is a valid window handle owned by this thread.
    unsafe { AddClipboardFormatListener(hwnd) }.context("AddClipboardFormatListener")?;
    info!("clipboard format listener registered");

    // Register hotkey.
    let (mods, vk) = parse_chord(&state.cfg.hotkey.chord)
        .with_context(|| format!("parsing hotkey chord {:?}", state.cfg.hotkey.chord))?;
    // SAFETY: hwnd valid; HOTKEY_ID is unique within this process.
    unsafe { RegisterHotKey(hwnd, HOTKEY_ID, mods, vk) }
        .with_context(|| format!("RegisterHotKey ({})", state.cfg.hotkey.chord))?;
    info!("hotkey registered: {}", state.cfg.hotkey.chord);

    // Message pump.
    let mut msg = MSG::default();
    loop {
        // SAFETY: msg is a valid out-pointer; passing HWND::default() (NULL) means
        // "any window owned by this thread".
        let r = unsafe { GetMessageW(&mut msg, HWND::default(), 0, 0) };
        if r.0 == 0 {
            break; // WM_QUIT
        }
        if r.0 == -1 {
            error!("GetMessageW failed");
            break;
        }
        // SAFETY: msg has been populated by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // Cleanup.
    // SAFETY: hwnd still valid; ids match the registrations above.
    unsafe {
        let _ = RemoveClipboardFormatListener(hwnd);
        let _ = UnregisterHotKey(hwnd, HOTKEY_ID);
    }
    info!("daemon message loop exited cleanly");
    Ok(())
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CLIPBOARDUPDATE => {
            if let Some(state) = STATE.get() {
                if state.is_paused() {
                    debug!("clipboard update ignored (paused)");
                } else {
                    let fg = read_foreground_info();
                    if let Err(e) = capture::handle_clipboard_update(state, &fg) {
                        warn!("capture failed: {e:#}");
                    }
                }
            }
            LRESULT(0)
        }
        WM_HOTKEY => {
            if wparam.0 as i32 == HOTKEY_ID {
                info!("hotkey!");
                if let Err(e) = launch_picker() {
                    warn!("picker launch failed: {e:#}");
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: PostQuitMessage signals the message pump to exit.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        // SAFETY: DefWindowProcW is the documented fallback for unhandled messages.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn window_title(hwnd: HWND) -> Option<String> {
    if hwnd.0.is_null() {
        return None;
    }
    // SAFETY: hwnd is non-null. Zero/negative length means no title or
    // inaccessible — non-fatal.
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize + 1];
    // SAFETY: buf is writable and includes room for the trailing NUL.
    let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if copied <= 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..copied as usize]))
}

fn window_pid(hwnd: HWND) -> Option<u32> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut pid: u32 = 0;
    // SAFETY: hwnd non-null; pid is a valid out-pointer.
    let tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if tid == 0 {
        None
    } else {
        Some(pid)
    }
}

fn process_image_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: PROCESS_QUERY_LIMITED_INFORMATION is the minimum-privilege right
    // for path queries. Returns Err on access denial; we propagate via `ok()?`.
    let handle: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid) }.ok()?;
    let mut buf = [0u16; 1024];
    let mut size: u32 = buf.len() as u32;
    // SAFETY: handle valid; buf and size pointers valid for the call duration.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
    };
    // SAFETY: handle came from OpenProcess; must close to avoid handle leak.
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.ok()?;
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}

/// Foreground-window context used by the secrets layer's password-manager and
/// browser-extension-popup heuristics.
pub struct ForegroundInfo {
    pub title: Option<String>,
    pub image: Option<String>,
}

/// Read the foreground window's title and the full path of its owning
/// executable. Both feed `secrets::classify` — the title drives the
/// password-manager regex, the image powers the browser-extension-popup
/// heuristic.
fn read_foreground_info() -> ForegroundInfo {
    // SAFETY: GetForegroundWindow returns NULL or a valid HWND.
    let hwnd = unsafe { GetForegroundWindow() };
    ForegroundInfo {
        title: window_title(hwnd),
        image: window_pid(hwnd).and_then(process_image_name),
    }
}

/// Spawn `clipd pick` as a subprocess. Picker connects back over IPC.
fn launch_picker() -> Result<()> {
    let exe = std::env::current_exe().context("locating clipd.exe")?;
    std::process::Command::new(exe)
        .arg("pick")
        .spawn()
        .context("spawning picker")?;
    Ok(())
}

/// Parse a chord like "ctrl+alt+c" into (modifiers, virtual_key).
pub fn parse_chord(chord: &str) -> Result<(HOT_KEY_MODIFIERS, u32)> {
    let mut mods = HOT_KEY_MODIFIERS(0);
    let mut vk: Option<u32> = None;

    for tok in chord.split('+').map(|t| t.trim().to_ascii_lowercase()) {
        match tok.as_str() {
            "ctrl" | "control" => mods |= MOD_CONTROL,
            "alt" => mods |= MOD_ALT,
            "shift" => mods |= MOD_SHIFT,
            "win" | "super" | "meta" => mods |= MOD_WIN,
            other => {
                if vk.is_some() {
                    bail!("multiple non-modifier keys in chord: {chord}");
                }
                vk = Some(parse_vkey(other)?);
            }
        }
    }
    let vk = vk.ok_or_else(|| anyhow!("no key in chord: {chord}"))?;
    Ok((mods, vk))
}

fn parse_vkey(s: &str) -> Result<u32> {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    if s.len() == 1 {
        let c = s.chars().next().unwrap().to_ascii_uppercase();
        if c.is_ascii_alphabetic() || c.is_ascii_digit() {
            return Ok(c as u32);
        }
    }
    let vk = match s {
        "f1" => VK_F1,
        "f2" => VK_F2,
        "f3" => VK_F3,
        "f4" => VK_F4,
        "f5" => VK_F5,
        "f6" => VK_F6,
        "f7" => VK_F7,
        "f8" => VK_F8,
        "f9" => VK_F9,
        "f10" => VK_F10,
        "f11" => VK_F11,
        "f12" => VK_F12,
        "space" => VK_SPACE,
        "tab" => VK_TAB,
        "esc" | "escape" => VK_ESCAPE,
        "enter" | "return" => VK_RETURN,
        "v" => VK_V, // common explicit case
        other => bail!("unknown key: {other}"),
    };
    Ok(vk.0 as u32)
}

/// Encode a Rust string as a NUL-terminated UTF-16 vector for Win32 `PCWSTR`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_chord() {
        let (mods, vk) = parse_chord("ctrl+alt+c").unwrap();
        assert_eq!(mods, MOD_CONTROL | MOD_ALT);
        assert_eq!(vk, b'C' as u32);
    }

    #[test]
    fn parse_default_win_alt_c_chord() {
        let (mods, vk) = parse_chord("win+alt+c").unwrap();
        assert_eq!(mods, MOD_WIN | MOD_ALT);
        assert_eq!(vk, b'C' as u32);
    }

    #[test]
    fn parse_with_shift_and_function_key() {
        let (mods, vk) = parse_chord("ctrl+shift+f9").unwrap();
        assert_eq!(mods, MOD_CONTROL | MOD_SHIFT);
        // F9 = 0x78
        assert_eq!(vk, 0x78);
    }

    #[test]
    fn rejects_chord_with_no_key() {
        assert!(parse_chord("ctrl+alt").is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(parse_chord("ctrl+banana").is_err());
    }
}
