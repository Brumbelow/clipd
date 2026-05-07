//! Configuration loaded from `%APPDATA%\clipd\config.toml`.
//!
//! Steps 1+2 only need a small slice of this; downstream steps will extend
//! the schema (retention purge job, picker theme, sensitive policy, etc.).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip)]
    pub source_path: PathBuf,
    #[serde(default)]
    pub hotkey: HotkeyConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub picker: PickerConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub paths: PathsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotkeyConfig {
    pub chord: String,
}
impl Default for HotkeyConfig {
    fn default() -> Self {
        // Win+Alt+C: avoids the Win+C collision with Windows Copilot while
        // staying close to "Win+C" muscle memory. RegisterHotKey treats both
        // Alt keys the same (MOD_ALT) — left/right differentiation would
        // need a WH_KEYBOARD_LL hook.
        Self {
            chord: "win+alt+c".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    pub days: u32,
    pub max_entries: u32,
}
impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            days: 30,
            max_entries: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PickerConfig {
    pub result_limit: usize,
}
impl Default for PickerConfig {
    fn default() -> Self {
        Self { result_limit: 200 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub entropy_min_len: usize,
    pub entropy_max_len: usize,
    pub entropy_threshold: f64,
}
impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            entropy_min_len: 20,
            entropy_max_len: 80,
            entropy_threshold: 4.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureConfig {
    /// Exe basenames (case-insensitive, e.g. "keepassxc.exe") whose
    /// foreground captures are dropped before the secrets layer runs.
    #[serde(default)]
    pub excluded_apps: Vec<String>,
    #[serde(default)]
    pub sensitive_policy: SensitivePolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SensitivePolicy {
    #[default]
    Skip,
    Mark,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathsConfig {
    pub data_dir: Option<PathBuf>,
}

impl Config {
    pub fn load_or_default(path: Option<&Path>) -> anyhow::Result<Self> {
        let p = path.map(PathBuf::from).unwrap_or_else(default_config_path);
        let mut cfg: Config = if p.exists() {
            let s = std::fs::read_to_string(&p)?;
            toml::from_str(&s)?
        } else {
            Self::default()
        };
        cfg.source_path = p;
        Ok(cfg)
    }

    pub fn db_full_path(&self) -> PathBuf {
        self.data_dir().join("entries.db")
    }

    pub fn key_full_path(&self) -> PathBuf {
        self.data_dir().join("key.dpapi")
    }

    fn data_dir(&self) -> PathBuf {
        self.paths
            .data_dir
            .clone()
            .unwrap_or_else(|| dirs::config_dir().unwrap_or_default().join("clipd"))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            source_path: default_config_path(),
            hotkey: Default::default(),
            retention: Default::default(),
            picker: Default::default(),
            secrets: Default::default(),
            capture: Default::default(),
            paths: Default::default(),
        }
    }
}

fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_default()
        .join("clipd")
        .join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_section_parses() {
        let toml_src = r#"
            [capture]
            excluded_apps = ["KeePassXC.exe", "1password.exe"]
            sensitive_policy = "mark"
        "#;
        let cfg: Config = toml::from_str(toml_src).expect("parse");
        assert_eq!(
            cfg.capture.excluded_apps,
            vec!["KeePassXC.exe".to_string(), "1password.exe".to_string()]
        );
        assert_eq!(cfg.capture.sensitive_policy, SensitivePolicy::Mark);
    }

    #[test]
    fn capture_section_defaults_when_absent() {
        let cfg: Config = toml::from_str("").expect("parse empty");
        assert!(cfg.capture.excluded_apps.is_empty());
        assert_eq!(cfg.capture.sensitive_policy, SensitivePolicy::Skip);
    }
}
