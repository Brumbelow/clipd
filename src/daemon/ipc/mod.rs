//! Named-pipe IPC between the daemon and short-lived CLI / picker processes.
//!
//! **Stub for Steps 1–4.** The named-pipe server lands in Step 5; the wire
//! types are pinned now so `main.rs` and `picker::app` can link.

use crate::config::Config;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    List { limit: usize },
    Search { query: String, limit: usize },
    Delete { id: i64 },
    Pin { id: i64, pinned: bool },
    Promote { id: i64 },
    Pause,
    Resume,
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Entries(Vec<EntrySummary>),
    Ok,
    Pong,
    Error(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EntrySummary {
    pub id: i64,
    pub kind: String,
    pub preview: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub pinned: bool,
}

pub mod client {
    use super::*;

    /// Stub. Real implementation lands in Step 5 (named-pipe client at
    /// `\\.\pipe\clipd`).
    pub fn send(_cfg: &Config, _req: Request) -> Result<Response> {
        bail!("IPC not yet implemented (Step 5). Use `clipd list` (direct DB) for now.")
    }
}
