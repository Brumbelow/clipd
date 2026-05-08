//! Named-pipe IPC between the daemon and short-lived CLI / picker processes.
//!
//! Wire types live here so both the [`server`] (daemon-side) and [`client`]
//! (CLI / picker-side) can deserialize without a circular dep.

pub mod picker_pipe;
pub mod server;

use crate::config::Config;
use crate::store::{DateFilter, EntryRow};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    List {
        limit: usize,
    },
    Search {
        query: String,
        limit: usize,
        /// Zero or more `created_at` predicates. Empty for callers that
        /// don't expose date syntax (e.g. the `clipd search` CLI).
        #[serde(default)]
        filters: Vec<DateFilter>,
    },
    Delete {
        id: i64,
    },
    Pin {
        id: i64,
        pinned: bool,
    },
    Promote {
        id: i64,
    },
    /// Picker fetches a PNG thumbnail for an image-kind row.
    GetThumbnail {
        id: i64,
    },
    Pause,
    Resume,
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Entries(Vec<EntrySummary>),
    Ok,
    Pong,
    /// PNG thumbnail bytes, base64-encoded so they fit the JSON-line
    /// protocol without a binary side channel.
    Thumbnail {
        png_b64: String,
    },
    Error(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EntrySummary {
    pub id: i64,
    pub kind: String,
    /// Content-shape kind (`url|json|hex|base64|code|text`).
    /// `#[serde(default)]` keeps wire-compat with older callers during
    /// in-place upgrades — daemon and picker ship as one binary today,
    /// but the default doesn't cost anything.
    #[serde(default = "default_content_kind")]
    pub content_kind: String,
    pub preview: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub pinned: bool,
}

fn default_content_kind() -> String {
    "text".to_string()
}

pub(crate) fn to_summary(row: &EntryRow) -> EntrySummary {
    EntrySummary {
        id: row.id,
        kind: row.kind.clone(),
        content_kind: row.content_kind.clone(),
        preview: row.preview.clone(),
        created_at: row.created_at,
        last_seen: row.last_seen,
        pinned: row.pinned,
    }
}

pub mod client {
    use super::server::PIPE_NAME;
    use super::*;
    use interprocess::local_socket::{prelude::*, GenericNamespaced, Stream};
    use std::io::{BufRead, BufReader, Write};

    pub fn send(_cfg: &Config, req: Request) -> Result<Response> {
        send_to(PIPE_NAME, req)
    }

    /// Like [`send`] but targets a specific pipe name. Used by tests.
    pub fn send_to(name: &str, req: Request) -> Result<Response> {
        let pipe_name = name
            .to_ns_name::<GenericNamespaced>()
            .with_context(|| format!("invalid pipe name: {name}"))?;
        let stream =
            Stream::connect(pipe_name).context("connecting to clipd daemon (is it running?)")?;
        let mut reader = BufReader::new(stream);

        let body = serde_json::to_string(&req)?;
        {
            let stream = reader.get_mut();
            stream.write_all(body.as_bytes())?;
            stream.write_all(b"\n")?;
            stream.flush()?;
        }

        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.is_empty() {
            anyhow::bail!("daemon closed pipe without sending a response");
        }
        Ok(serde_json::from_str(line.trim_end())?)
    }
}
