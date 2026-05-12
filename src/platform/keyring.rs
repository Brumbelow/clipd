//! Windows DPAPI key wrap/unwrap.
//!
//! `wrap` calls `CryptProtectData` against the current Windows user; the
//! resulting blob can only be unwrapped by the same user on the same
//! machine. Used by `store::crypto::Vault` to seal the AES-GCM data-key
//! file at `%APPDATA%\clipd\key.dpapi`.
//!
//! The non-Windows fallback is an identity function gated by
//! `#[cfg(not(target_os = "windows"))]` so the crate builds and the
//! AES-GCM unit tests run on Linux dev hosts. It is not a real keyring —
//! the real Linux/Mac implementations land during the cross-platform
//! port (Secret Service / Keychain), as sibling files under `platform/`.

use anyhow::{Context, Result};

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::LocalFree;
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

#[cfg(target_os = "windows")]
pub fn wrap(plaintext: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: CryptProtectData with NULL description, NULL entropy, NULL prompt;
    // CRYPTPROTECT_UI_FORBIDDEN ensures no UI thread is required. Output blob
    // memory is allocated by the OS and must be freed with LocalFree.
    unsafe {
        CryptProtectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .context("CryptProtectData")?;
    }

    // SAFETY: out_blob.pbData is valid for cbData bytes per the API contract.
    let result =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    // SAFETY: must free the OS allocation.
    unsafe {
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(
            out_blob.pbData as *mut _,
        ));
    }
    Ok(result)
}

#[cfg(target_os = "windows")]
pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: wrapped.len() as u32,
        pbData: wrapped.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: same invariants as CryptProtectData.
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .context("CryptUnprotectData")?;
    }

    // SAFETY: out_blob.pbData valid for cbData bytes.
    let result =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    // SAFETY: free OS allocation.
    unsafe {
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(
            out_blob.pbData as *mut _,
        ));
    }
    Ok(result)
}

// ---- Non-Windows fallback (for `cargo check` / unit tests on Linux dev hosts) ----

#[cfg(not(target_os = "windows"))]
pub fn wrap(plaintext: &[u8]) -> Result<Vec<u8>> {
    tracing::warn!("DPAPI not available on this platform — using identity wrap (DEV ONLY)");
    Ok(plaintext.to_vec())
}

#[cfg(not(target_os = "windows"))]
pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>> {
    tracing::warn!("DPAPI not available on this platform — using identity unwrap (DEV ONLY)");
    Ok(wrapped.to_vec())
}
