//! Autostart registry shim.
//!
//! `clipd install --autostart` writes
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\clipd` =
//! `"<exe>" --daemon` (REG_SZ). `clipd uninstall` deletes the value.
//!
//! Unsafe Win32 surface is contained here; each block carries a
//! `// SAFETY:` comment.

use anyhow::{Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_CREATE_KEY_DISPOSITION,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ,
};

/// Registry value name under the Run key.
const VALUE_NAME: &str = "clipd";

/// Path under HKCU. Test code overrides this via [`run_key_path`].
const RUN_KEY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(test)]
thread_local! {
    /// Per-test override so tests don't poison the real Run key.
    static RUN_KEY_OVERRIDE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_key_path() -> String {
    RUN_KEY_OVERRIDE.with(|c| {
        c.borrow()
            .clone()
            .unwrap_or_else(|| RUN_KEY_PATH.to_string())
    })
}

#[cfg(not(test))]
fn run_key_path() -> &'static str {
    RUN_KEY_PATH
}

/// Write the Run-key value pointing at the current executable with `--daemon`.
pub fn enable_autostart() -> Result<()> {
    let exe = std::env::current_exe().context("locating clipd.exe")?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("exe path is not valid UTF-16: {}", exe.display()))?;
    // Quote the path so spaces don't fragment the command line, then append flag.
    let command = format!("\"{exe_str}\" --daemon");
    write_value(&command)
}

/// Remove the Run-key value. Idempotent: missing value is not an error.
pub fn disable_autostart() -> Result<()> {
    let path = wide(run_key_path());
    let value = wide(VALUE_NAME);

    let mut hkey = HKEY::default();
    // SAFETY: HKCU is a documented predefined handle; `path` is NUL-terminated.
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            0,
            REG_SAM_FLAGS(KEY_SET_VALUE.0),
            &mut hkey,
        )
    };
    if open == ERROR_FILE_NOT_FOUND {
        return Ok(()); // key doesn't exist → value can't exist
    }
    if open != ERROR_SUCCESS {
        anyhow::bail!("RegOpenKeyExW failed: {:?}", open);
    }

    // SAFETY: hkey is a valid open key from RegOpenKeyExW.
    let del = unsafe { RegDeleteValueW(hkey, PCWSTR(value.as_ptr())) };
    // SAFETY: hkey is open; closing exactly once.
    let _ = unsafe { RegCloseKey(hkey) };

    if del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        anyhow::bail!("RegDeleteValueW failed: {:?}", del);
    }
}

/// Whether the Run-key value currently exists. Used by `clipd doctor`.
pub fn autostart_enabled() -> Result<bool> {
    let path = wide(run_key_path());
    let value = wide(VALUE_NAME);

    let mut hkey = HKEY::default();
    // SAFETY: HKCU predefined; path NUL-terminated.
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            0,
            REG_SAM_FLAGS(KEY_READ.0),
            &mut hkey,
        )
    };
    if open == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if open != ERROR_SUCCESS {
        anyhow::bail!("RegOpenKeyExW failed: {:?}", open);
    }

    // SAFETY: hkey valid; passing all NULL out-pointers — RegQueryValueExW
    // accepts that and only signals existence.
    let query = unsafe { RegQueryValueExW(hkey, PCWSTR(value.as_ptr()), None, None, None, None) };
    // SAFETY: hkey opened above.
    let _ = unsafe { RegCloseKey(hkey) };

    Ok(query == ERROR_SUCCESS)
}

fn write_value(command: &str) -> Result<()> {
    let path = wide(run_key_path());
    let value = wide(VALUE_NAME);
    let data = wide(command); // NUL-terminated UTF-16 for REG_SZ

    let mut hkey = HKEY::default();
    let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
    // SAFETY: HKCU predefined; path NUL-terminated; out-pointers writable.
    let create = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            0,
            PWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            REG_SAM_FLAGS(KEY_SET_VALUE.0),
            None,
            &mut hkey,
            Some(&mut disposition),
        )
    };
    if create != ERROR_SUCCESS {
        anyhow::bail!("RegCreateKeyExW failed: {:?}", create);
    }

    let bytes: &[u8] = unsafe {
        // SAFETY: re-borrow `data` as bytes for the REG_SZ payload. UTF-16
        // wide chars are 2 bytes each; size = data.len() * 2.
        std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2)
    };
    // SAFETY: hkey valid; bytes is a valid slice for the duration of the call.
    let set = unsafe { RegSetValueExW(hkey, PCWSTR(value.as_ptr()), 0, REG_SZ, Some(bytes)) };
    // SAFETY: hkey opened above; closing once.
    let _ = unsafe { RegCloseKey(hkey) };

    if set != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueExW failed: {:?}", set);
    }
    Ok(())
}

fn wide(s: impl AsRef<str>) -> Vec<u16> {
    s.as_ref()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(1);

    /// Switch the Run-key target to a per-test subkey for the duration of the
    /// closure, then clean up. Tests serialize implicitly through HKCU
    /// scoping (different keys per test).
    fn with_test_key<F: FnOnce()>(f: F) {
        let id = N.fetch_add(1, Ordering::Relaxed);
        let path = format!(
            r"Software\clipd-test\{pid}-{id}",
            pid = std::process::id(),
            id = id,
        );
        RUN_KEY_OVERRIDE.with(|c| *c.borrow_mut() = Some(path.clone()));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        // Best-effort cleanup: delete the value, then the subkey.
        let _ = disable_autostart();
        cleanup_subkey(&path);
        RUN_KEY_OVERRIDE.with(|c| *c.borrow_mut() = None);
        if let Err(e) = res {
            std::panic::resume_unwind(e);
        }
    }

    fn cleanup_subkey(path: &str) {
        use windows::Win32::System::Registry::RegDeleteKeyW;
        let w = wide(path);
        // SAFETY: HKCU predefined; path NUL-terminated. RegDeleteKeyW
        // ignores ERROR_FILE_NOT_FOUND so this is idempotent.
        let _ = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(w.as_ptr())) };
    }

    #[test]
    fn enable_then_disable_roundtrips() {
        with_test_key(|| {
            assert!(!autostart_enabled().unwrap(), "starts absent");
            enable_autostart().unwrap();
            assert!(autostart_enabled().unwrap(), "present after enable");
            disable_autostart().unwrap();
            assert!(!autostart_enabled().unwrap(), "absent after disable");
        });
    }

    #[test]
    fn disable_is_idempotent_on_missing_value() {
        with_test_key(|| {
            // No enable first.
            disable_autostart().unwrap();
            disable_autostart().unwrap();
            assert!(!autostart_enabled().unwrap());
        });
    }

    #[test]
    fn enable_overwrites_existing_value() {
        with_test_key(|| {
            enable_autostart().unwrap();
            // Second enable replaces the value (current_exe is the same in
            // tests, but the call must succeed without erroring on
            // ERROR_FILE_EXISTS or similar).
            enable_autostart().unwrap();
            assert!(autostart_enabled().unwrap());
        });
    }
}
