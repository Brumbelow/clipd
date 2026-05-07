//! Step 11: separate named pipe for daemon → picker messages.
//!
//! Direction is the inverse of the existing `clipd` pipe (where the daemon
//! is the listener and CLI/picker are clients): here the *picker* listens at
//! `\\.\pipe\clipd-picker` and the *daemon* connects on hotkey to deliver a
//! [`PickerRequest::Show`].
//!
//! Protocol mirrors the existing pipe — JSON-line over a single
//! request/response per connection. No response body today; the daemon
//! reads "ack\n" on success.
//!
//! Lifetime: the listener thread runs for the lifetime of the picker
//! process. If the picker crashes, the daemon's
//! [`picker_supervisor`](super::super::picker_supervisor) respawns it,
//! which recreates the pipe.

use anyhow::{Context, Result};
use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions, Stream};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::Sender;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Short name; resolves to `\\.\pipe\clipd-picker` via `GenericNamespaced`.
pub const PICKER_PIPE_NAME: &str = "clipd-picker";

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum PickerRequest {
    /// Bring the prewarmed picker window to the foreground.
    Show,
}

/// Used by the picker process. Spawns a listener thread that accepts
/// connections on `name` and forwards each decoded request to `tx`.
pub fn spawn_listener(name: &str, tx: Sender<PickerRequest>) -> Result<()> {
    let pipe_name = name
        .to_ns_name::<GenericNamespaced>()
        .with_context(|| format!("invalid pipe name: {name}"))?;
    let listener = ListenerOptions::new()
        .name(pipe_name)
        .create_sync()
        .with_context(|| format!("creating picker IPC listener at \\\\.\\pipe\\{name}"))?;
    info!("picker IPC listener up at \\\\.\\pipe\\{name}");

    std::thread::Builder::new()
        .name("clipd-picker-ipc".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("picker IPC accept failed: {e:#}");
                        continue;
                    }
                };
                if let Err(e) = handle_conn(stream, &tx) {
                    warn!("picker IPC connection error: {e:#}");
                }
            }
        })
        .context("spawning picker IPC listener thread")?;

    Ok(())
}

fn handle_conn(stream: Stream, tx: &Sender<PickerRequest>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    match serde_json::from_str::<PickerRequest>(line.trim_end()) {
        Ok(req) => {
            debug!("picker IPC request: {req:?}");
            // Best-effort send; if the picker UI side is gone, the listener
            // outlives the receiver but the send error is non-fatal.
            let _ = tx.send(req);
            let stream = reader.get_mut();
            stream.write_all(b"ack\n")?;
            stream.flush()?;
        }
        Err(e) => {
            let stream = reader.get_mut();
            let msg = format!("invalid JSON: {e}\n");
            stream.write_all(msg.as_bytes())?;
            stream.flush()?;
        }
    }
    Ok(())
}

/// Used by the daemon. Connects to the picker pipe and sends a single
/// request, retrying with backoff to bridge picker-respawn windows.
pub fn send_show() -> Result<()> {
    send_show_to(PICKER_PIPE_NAME)
}

/// Like [`send_show`] but lets tests target a per-test pipe name.
pub fn send_show_to(name: &str) -> Result<()> {
    // Backoff schedule: 50ms, 150ms, 400ms — total ~600ms, enough to bridge
    // the picker_supervisor's typical respawn (≤1s).
    const BACKOFF_MS: &[u64] = &[0, 50, 150, 400];
    let mut last_err: Option<anyhow::Error> = None;
    for (attempt, delay) in BACKOFF_MS.iter().enumerate() {
        if *delay > 0 {
            std::thread::sleep(Duration::from_millis(*delay));
        }
        match try_send(name, PickerRequest::Show) {
            Ok(()) => {
                if attempt > 0 {
                    debug!(attempt, "picker show succeeded after retry");
                }
                return Ok(());
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("picker show: all retries failed")))
}

fn try_send(name: &str, req: PickerRequest) -> Result<()> {
    let pipe_name = name
        .to_ns_name::<GenericNamespaced>()
        .with_context(|| format!("invalid pipe name: {name}"))?;
    let stream = Stream::connect(pipe_name).context("connecting to picker pipe")?;
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
    if line.trim_end() != "ack" {
        anyhow::bail!("unexpected response from picker: {line:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    static N: AtomicU64 = AtomicU64::new(1);

    fn unique_name() -> String {
        let n = N.fetch_add(1, Ordering::Relaxed);
        format!("clipd-picker-test-{}-{n}", std::process::id())
    }

    #[test]
    fn show_roundtrip() {
        let (tx, rx) = mpsc::channel();
        let name = unique_name();
        spawn_listener(&name, tx).unwrap();
        // Give the listener thread a moment to begin accepting.
        std::thread::sleep(Duration::from_millis(20));

        send_show_to(&name).unwrap();

        let req = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(req, PickerRequest::Show);
    }

    #[test]
    fn send_to_missing_pipe_returns_error_after_retries() {
        let res = send_show_to("clipd-picker-no-such-pipe-zzzz");
        assert!(res.is_err(), "should fail when no listener is up");
    }

    #[test]
    fn second_show_works_after_first() {
        let (tx, rx) = mpsc::channel();
        let name = unique_name();
        spawn_listener(&name, tx).unwrap();
        std::thread::sleep(Duration::from_millis(20));

        send_show_to(&name).unwrap();
        send_show_to(&name).unwrap();

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            PickerRequest::Show
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            PickerRequest::Show
        );
    }
}
