//! Encryption at rest. Per-install AES-GCM-256 key, wrapped with Windows DPAPI.
//!
//! Threat model:
//!   - Defends against: other Windows users, disk-image attacks without creds.
//!   - Does NOT defend against: malware in the same user session.
//!
//! Key file lifecycle:
//!   - Generated on first `Vault::open()` if the key file is missing.
//!   - Stored as DPAPI-protected blob at `key.dpapi`.
//!   - Tied to the current Windows user via `CryptProtectData`.

use aes_gcm::aead::Aead;

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use windows::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

pub struct Vault {
    cipher: Aes256Gcm,
    #[allow(dead_code)] // retained for future rotation logic
    key_path: PathBuf,
}

impl Vault {
    pub fn open(key_path: &Path) -> Result<Self> {
        let key_bytes = if key_path.exists() {
            let wrapped = std::fs::read(key_path).context("reading key file")?;
            unwrap_with_dpapi(&wrapped).context("unwrapping key with DPAPI")?
        } else {
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent).context("creating key parent dir")?;
            }
            let mut k = vec![0u8; KEY_BYTES];
            rand::thread_rng().fill_bytes(&mut k);
            let wrapped = wrap_with_dpapi(&k).context("wrapping new key with DPAPI")?;
            std::fs::write(key_path, &wrapped).context("writing key file")?;
            tracing::info!("generated new clipd key at {}", key_path.display());
            k
        };
        if key_bytes.len() != KEY_BYTES {
            return Err(anyhow!(
                "key file has wrong length: expected {KEY_BYTES}, got {}",
                key_bytes.len()
            ));
        }
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Self {
            cipher,
            key_path: key_path.to_path_buf(),
        })
    }

    /// Encrypt a payload. Returns `(nonce, ciphertext+tag)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES-GCM encrypt: {e}"))?;
        Ok((nonce_bytes.to_vec(), ct))
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_BYTES {
            return Err(anyhow!(
                "nonce wrong length: expected {NONCE_BYTES}, got {}",
                nonce.len()
            ));
        }
        let nonce = Nonce::from_slice(nonce);
        let pt = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("AES-GCM decrypt: {e}"))?;
        Ok(pt)
    }
}

// ---- DPAPI wrap/unwrap ----

#[cfg(windows)]
fn wrap_with_dpapi(plaintext: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(windows)]
fn unwrap_with_dpapi(wrapped: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(not(windows))]
fn wrap_with_dpapi(plaintext: &[u8]) -> Result<Vec<u8>> {
    // Dev-only no-op so unit tests can run on Linux. NEVER ship this enabled
    // on a non-Windows target — Cargo.toml restricts the target triple.
    tracing::warn!("DPAPI not available on this platform — using identity wrap (DEV ONLY)");
    Ok(plaintext.to_vec())
}

#[cfg(not(windows))]
fn unwrap_with_dpapi(wrapped: &[u8]) -> Result<Vec<u8>> {
    tracing::warn!("DPAPI not available on this platform — using identity unwrap (DEV ONLY)");
    Ok(wrapped.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("k.dpapi");
        let vault = Vault::open(&key_path).unwrap();
        let plaintext = b"hello clipboard world";
        let (nonce, ct) = vault.encrypt(plaintext).unwrap();
        let pt = vault.decrypt(&nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn key_persists_across_open() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("k.dpapi");
        let v1 = Vault::open(&key_path).unwrap();
        let (nonce, ct) = v1.encrypt(b"persist me").unwrap();
        drop(v1);

        let v2 = Vault::open(&key_path).unwrap();
        let pt = v2.decrypt(&nonce, &ct).unwrap();
        assert_eq!(pt, b"persist me");
    }

    #[test]
    fn tamper_detected() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("k.dpapi");
        let vault = Vault::open(&key_path).unwrap();
        let (nonce, mut ct) = vault.encrypt(b"important").unwrap();
        ct[0] ^= 0xFF;
        assert!(vault.decrypt(&nonce, &ct).is_err());
    }
}
