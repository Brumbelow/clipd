//! Encryption at rest. Per-install AES-GCM-256 key, wrapped with Windows DPAPI.
//!
//! Threat model:
//!   - Defends against: other Windows users, disk-image attacks without creds.
//!   - Does NOT defend against: malware in the same user session.
//!
//! Key file lifecycle:
//!   - Generated on first `Vault::open()` if the key file is missing.
//!   - Stored as a DPAPI-protected blob at `key.dpapi` on Windows.
//!   - Tied to the current Windows user via `CryptProtectData`.
//!
//! Platform-specific wrap/unwrap lives in [`crate::platform::keyring`].

use aes_gcm::aead::Aead;

use crate::platform::keyring;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use std::path::{Path, PathBuf};

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
            keyring::unwrap(&wrapped).context("unwrapping key")?
        } else {
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent).context("creating key parent dir")?;
            }
            let mut k = vec![0u8; KEY_BYTES];
            rand::thread_rng().fill_bytes(&mut k);
            let wrapped = keyring::wrap(&k).context("wrapping new key")?;
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

    /// Read-only key validation for `clipd doctor`.
    ///
    /// `Vault::open` creates and persists a fresh key when the file is
    /// missing — wrong shape for a diagnostic probe. `probe` only verifies
    /// an existing file: read bytes, run the platform unwrap, check the
    /// unwrapped length. Returns `Ok(unwrapped_len)` on success. Errors if
    /// the file is missing, unreadable, fails unwrap (wrong user /
    /// corrupted), or has the wrong unwrapped length.
    pub fn probe(key_path: &Path) -> Result<usize> {
        if !key_path.exists() {
            return Err(anyhow!("key file missing: {}", key_path.display()));
        }
        let wrapped = std::fs::read(key_path).context("reading key file")?;
        let unwrapped = keyring::unwrap(&wrapped).context("unwrapping key")?;
        if unwrapped.len() != KEY_BYTES {
            return Err(anyhow!(
                "key file has wrong length: expected {KEY_BYTES}, got {}",
                unwrapped.len()
            ));
        }
        Ok(unwrapped.len())
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

    // probe is the read-only diagnostic the `clipd doctor` subcommand
    // calls. Unlike `Vault::open`, it must NOT create the file.
    #[test]
    fn probe_missing_file_errors_without_creating_it() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("missing.dpapi");
        assert!(Vault::probe(&key_path).is_err());
        assert!(
            !key_path.exists(),
            "probe must not create a key file when one is missing"
        );
    }

    #[test]
    fn probe_existing_key_returns_byte_count() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("k.dpapi");
        let _ = Vault::open(&key_path).unwrap();
        let bytes = Vault::probe(&key_path).expect("probe should succeed for healthy key");
        assert_eq!(bytes, KEY_BYTES);
    }
}
