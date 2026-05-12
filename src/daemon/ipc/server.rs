//! Named-pipe IPC server.
//!
//! Synchronous design: one accept-loop thread, one OS thread per inbound
//! connection. Each connection is a single request/response: read one
//! newline-terminated JSON [`Request`], write one newline-terminated JSON
//! [`Response`], close. The picker uses an "open, query, close" flow
//! per request.
//!
//! No graceful shutdown: the daemon exits via `WM_QUIT` on the main thread
//! and the OS reaps the listener / connection threads.

use crate::daemon::clipboard_format::FormatPayload;
use crate::daemon::ipc::{to_summary, Request, Response};
use crate::daemon::{clipboard, DaemonState};
use crate::store;
use anyhow::{Context, Result};
use base64::Engine;
use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions, Stream};
use std::io::{BufRead, BufReader, Write};
use tracing::{debug, info, warn};

/// Short name; resolves to `\\.\pipe\clipd` via [`GenericNamespaced`] on Windows.
pub const PIPE_NAME: &str = "clipd";

/// Spawn the IPC listener using the production pipe name.
pub fn spawn(state: DaemonState) -> Result<()> {
    spawn_with_name(state, PIPE_NAME)
}

/// Spawn the IPC listener with an arbitrary pipe name. Tests use this with a
/// unique per-test name so parallel tests do not collide.
pub fn spawn_with_name(state: DaemonState, name: &str) -> Result<()> {
    let pipe_name = name
        .to_ns_name::<GenericNamespaced>()
        .with_context(|| format!("invalid pipe name: {name}"))?;
    let listener = ListenerOptions::new()
        .name(pipe_name)
        .create_sync()
        .with_context(|| format!("creating IPC listener at \\\\.\\pipe\\{name}"))?;
    info!("IPC listener up at \\\\.\\pipe\\{name}");

    std::thread::Builder::new()
        .name("clipd-ipc-listener".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("IPC accept failed: {e:#}");
                        continue;
                    }
                };
                let st = state.clone();
                let _ = std::thread::Builder::new()
                    .name("clipd-ipc-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_conn(stream, &st) {
                            warn!("IPC connection error: {e:#}");
                        }
                    });
            }
            // No graceful shutdown: the listener blocks on accept() until
            // the process exits, at which point the OS reaps the thread and
            // closes the pipe handle. There's no leak to clean up — see the
            // module-level doc comment.
        })
        .context("spawning IPC listener thread")?;

    Ok(())
}

fn handle_conn(stream: Stream, state: &DaemonState) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let resp = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(req) => {
            debug!("IPC request: {req:?}");
            dispatch(req, state)
        }
        Err(e) => Response::Error(format!("invalid JSON: {e}")),
    };

    let body = serde_json::to_string(&resp)?;
    let stream = reader.get_mut();
    stream.write_all(body.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn dispatch(req: Request, state: &DaemonState) -> Response {
    let db = state.cfg.db_full_path();
    let vault = &state.vault;
    match req {
        Request::Ping => Response::Pong,
        Request::List { limit } => match store::list(&db, limit) {
            Ok(rows) => Response::Entries(rows.iter().map(to_summary).collect()),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Search {
            query,
            limit,
            filters,
        } => match store::search(&db, &query, &filters, limit) {
            Ok(rows) => Response::Entries(rows.iter().map(to_summary).collect()),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Pin { id, pinned } => match store::set_pinned(&db, vault, id, pinned) {
            Ok(true) => Response::Ok,
            Ok(false) => Response::Error(format!("entry #{id} not found")),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Delete { id } => match store::delete(&db, vault, id) {
            Ok(true) => Response::Ok,
            Ok(false) => Response::Error(format!("entry #{id} not found")),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Promote { id } => match store::get_decrypted(&db, vault, id) {
            Ok(Some(d)) => {
                if d.row.kind == "image" {
                    promote_image(&d.plaintext)
                } else {
                    promote(d.row.kind.as_str(), &d.plaintext, &d.formats)
                }
            }
            Ok(None) => Response::Error(format!("entry #{id} not found")),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::GetThumbnail { id } => match store::get_thumbnail(&db, vault, id) {
            Ok(Some(png)) => Response::Thumbnail {
                png_b64: base64::engine::general_purpose::STANDARD.encode(&png),
            },
            Ok(None) => Response::Error(format!("entry #{id} has no thumbnail")),
            Err(e) => Response::Error(format!("{e:#}")),
        },
        Request::Pause => {
            state.set_paused(true);
            Response::Ok
        }
        Request::Resume => {
            state.set_paused(false);
            Response::Ok
        }
    }
}

/// Image promote. The canonical CF_DIB lives in `entries.content`; the
/// picker has already shown the user a thumbnail, so this just hands the
/// original bytes back to the OS clipboard.
fn promote_image(dib: &[u8]) -> Response {
    match clipboard::set_image(dib) {
        Ok(()) => Response::Ok,
        Err(e) => Response::Error(format!("{e:#}")),
    }
}

fn promote(kind: &str, plaintext: &[u8], formats: &[FormatPayload]) -> Response {
    // Row carries the full format set captured at copy time. Replay them
    // all so the receiver picks the highest-fidelity payload it understands.
    if !formats.is_empty() {
        return match clipboard::set_all_formats(formats) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error(format!("{e:#}")),
        };
    }
    // Fallback: legacy row with no captured formats. Text-only restore
    // via CF_UNICODETEXT.
    if kind != "text" {
        return Response::Error(format!("entry kind={kind} has no captured formats"));
    }
    match std::str::from_utf8(plaintext) {
        Err(_) => Response::Error("text entry has invalid UTF-8".into()),
        Ok(s) => match clipboard::set_text(s) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error(format!("{e:#}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::daemon::ipc::{client, EntrySummary, Request, Response};
    use crate::store::{self, crypto::Vault, NewEntry};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Fix {
        _dir: TempDir,
        pipe: String,
        state: DaemonState,
    }

    fn fixture() -> Fix {
        let dir = TempDir::new().unwrap();
        let mut cfg = Config::default();
        cfg.paths.data_dir = Some(dir.path().to_path_buf());

        let vault = Vault::open(&cfg.key_full_path()).unwrap();
        let state = DaemonState::new(Arc::new(cfg), Arc::new(vault));

        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pipe = format!("clipd-test-{}-{n}", std::process::id());
        spawn_with_name(state.clone(), &pipe).unwrap();
        // Give the listener thread a moment to call incoming(); on Windows
        // named pipes Stream::connect can fail with ERROR_PIPE_BUSY if the
        // first ConnectNamedPipe hasn't run yet.
        std::thread::sleep(std::time::Duration::from_millis(20));
        Fix {
            _dir: dir,
            pipe,
            state,
        }
    }

    fn insert_text(state: &DaemonState, text: &str, t: i64) -> i64 {
        let h = blake3::hash(text.as_bytes());
        let outcome = store::insert_or_bump(
            &state.cfg.db_full_path(),
            &state.vault,
            &NewEntry {
                kind: "text",
                content_kind: "text",
                content: text.as_bytes(),
                hash: h.as_bytes(),
                size_bytes: text.len(),
                created_at: t,
                preview: store::derive_preview(text),
                source_app: None,
                formats: &[],
                sensitive: false,
            },
        )
        .unwrap();
        match outcome {
            store::Outcome::Inserted { id } => id,
            store::Outcome::BumpedLastSeen { id } => id,
        }
    }

    fn entries(resp: Response) -> Vec<EntrySummary> {
        match resp {
            Response::Entries(v) => v,
            other => panic!("expected Entries, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_ping() {
        let f = fixture();
        let resp = client::send_to(&f.pipe, Request::Ping).unwrap();
        assert!(matches!(resp, Response::Pong));
    }

    #[test]
    fn list_returns_entries_newest_first() {
        let f = fixture();
        insert_text(&f.state, "alpha", 1000);
        insert_text(&f.state, "bravo", 2000);
        insert_text(&f.state, "charlie", 3000);

        let resp = client::send_to(&f.pipe, Request::List { limit: 10 }).unwrap();
        let v = entries(resp);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].preview, "charlie");
        assert_eq!(v[1].preview, "bravo");
        assert_eq!(v[2].preview, "alpha");
    }

    #[test]
    fn search_filters_by_preview() {
        let f = fixture();
        insert_text(&f.state, "kubectl get pods", 1000);
        insert_text(&f.state, "git status", 2000);

        let resp = client::send_to(
            &f.pipe,
            Request::Search {
                query: "kube".into(),
                limit: 10,
                filters: Vec::new(),
            },
        )
        .unwrap();
        let v = entries(resp);
        assert_eq!(v.len(), 1);
        assert!(v[0].preview.contains("kubectl"));
    }

    #[test]
    fn search_with_date_filter_narrows_to_window() {
        // `:7d kubectl` shape — text + a single After filter.
        let f = fixture();
        insert_text(&f.state, "old kubectl", 1_000_000);
        insert_text(&f.state, "new kubectl", 9_000_000);
        insert_text(&f.state, "new git", 9_500_000);

        let resp = client::send_to(
            &f.pipe,
            Request::Search {
                query: "kubectl".into(),
                limit: 10,
                filters: vec![store::DateFilter::After(5_000_000)],
            },
        )
        .unwrap();
        let v = entries(resp);
        assert_eq!(v.len(), 1, "After filter must drop the old row");
        assert_eq!(v[0].preview, "new kubectl");
    }

    #[test]
    fn search_with_only_filter_no_text() {
        // Empty `query` + non-empty `filters` (the `:today` with no search
        // term case) should still return matching rows.
        let f = fixture();
        insert_text(&f.state, "yesterday-row", 1_000_000);
        insert_text(&f.state, "today-row", 9_000_000);

        let resp = client::send_to(
            &f.pipe,
            Request::Search {
                query: String::new(),
                limit: 10,
                filters: vec![store::DateFilter::After(5_000_000)],
            },
        )
        .unwrap();
        let v = entries(resp);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].preview, "today-row");
    }

    #[test]
    fn pin_then_list_shows_pinned() {
        let f = fixture();
        let id = insert_text(&f.state, "important", 1000);

        let resp = client::send_to(&f.pipe, Request::Pin { id, pinned: true }).unwrap();
        assert!(matches!(resp, Response::Ok));

        let v = entries(client::send_to(&f.pipe, Request::List { limit: 10 }).unwrap());
        assert_eq!(v.len(), 1);
        assert!(v[0].pinned);

        // Pinning a missing id reports not-found, listener stays alive.
        let resp = client::send_to(
            &f.pipe,
            Request::Pin {
                id: 9999,
                pinned: true,
            },
        )
        .unwrap();
        assert!(matches!(resp, Response::Error(ref m) if m.contains("not found")));
    }

    #[test]
    fn delete_removes_row() {
        let f = fixture();
        let id = insert_text(&f.state, "ephemeral", 1000);

        let resp = client::send_to(&f.pipe, Request::Delete { id }).unwrap();
        assert!(matches!(resp, Response::Ok));

        let v = entries(client::send_to(&f.pipe, Request::List { limit: 10 }).unwrap());
        assert!(v.is_empty());

        // Second delete reports not-found.
        let resp = client::send_to(&f.pipe, Request::Delete { id }).unwrap();
        assert!(matches!(resp, Response::Error(ref m) if m.contains("not found")));
    }

    #[test]
    fn pause_and_resume_toggle_state() {
        let f = fixture();
        assert!(!f.state.is_paused());

        client::send_to(&f.pipe, Request::Pause).unwrap();
        assert!(f.state.is_paused());

        client::send_to(&f.pipe, Request::Resume).unwrap();
        assert!(!f.state.is_paused());
    }

    #[test]
    fn promote_unknown_id_returns_error() {
        let f = fixture();
        let resp = client::send_to(&f.pipe, Request::Promote { id: 12345 }).unwrap();
        assert!(matches!(resp, Response::Error(ref m) if m.contains("not found")));
    }

    #[test]
    fn promote_non_text_non_image_with_no_formats_returns_error() {
        // A row with no captured formats and a non-text, non-image kind
        // has nothing to restore. Use kind="files" so the dispatch
        // doesn't route to the image path (which would touch the real
        // clipboard).
        let f = fixture();
        let h = blake3::hash(b"unknown-bytes");
        let outcome = store::insert_or_bump(
            &f.state.cfg.db_full_path(),
            &f.state.vault,
            &NewEntry {
                kind: "files",
                content_kind: "text",
                content: b"unknown-bytes",
                hash: h.as_bytes(),
                size_bytes: 13,
                created_at: 1000,
                preview: "unknown-bytes".into(),
                source_app: None,
                formats: &[],
                sensitive: false,
            },
        )
        .unwrap();
        let id = match outcome {
            store::Outcome::Inserted { id } => id,
            _ => panic!("expected Inserted"),
        };

        let resp = client::send_to(&f.pipe, Request::Promote { id }).unwrap();
        match resp {
            Response::Error(m) => {
                assert!(
                    m.contains("kind=files") && m.contains("no captured formats"),
                    "unexpected error message: {m}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_thumbnail_unknown_id_returns_error() {
        let f = fixture();
        let resp = client::send_to(&f.pipe, Request::GetThumbnail { id: 99999 }).unwrap();
        match resp {
            Response::Error(m) => assert!(m.contains("no thumbnail")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_thumbnail_text_row_returns_error() {
        let f = fixture();
        let id = insert_text(&f.state, "no thumb here", 1000);
        let resp = client::send_to(&f.pipe, Request::GetThumbnail { id }).unwrap();
        match resp {
            Response::Error(m) => assert!(m.contains("no thumbnail")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_thumbnail_returns_base64_png_for_image_row() {
        // Insert an image-kind row with a fake `clipd:png_thumb` format
        // payload. We don't actually decode the "PNG" — the IPC layer
        // just base64-encodes whatever bytes are stored, and the test
        // verifies the round-trip.
        use crate::daemon::clipboard_format::FormatPayload;

        let f = fixture();
        let h = blake3::hash(b"fake-dib");
        let png_bytes = b"\x89PNG\r\n\x1a\n--fake--".to_vec();
        let outcome = store::insert_or_bump(
            &f.state.cfg.db_full_path(),
            &f.state.vault,
            &NewEntry {
                kind: "image",
                content_kind: "text",
                content: b"fake-dib",
                hash: h.as_bytes(),
                size_bytes: 8,
                created_at: 1000,
                preview: "image (1x1)".into(),
                source_app: None,
                formats: &[FormatPayload {
                    name: "clipd:png_thumb".into(),
                    bytes: png_bytes.clone(),
                }],
                sensitive: false,
            },
        )
        .unwrap();
        let id = match outcome {
            store::Outcome::Inserted { id } => id,
            _ => panic!("expected Inserted"),
        };

        let resp = client::send_to(&f.pipe, Request::GetThumbnail { id }).unwrap();
        match resp {
            Response::Thumbnail { png_b64 } => {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&png_b64)
                    .unwrap();
                assert_eq!(decoded, png_bytes);
            }
            other => panic!("expected Thumbnail, got {other:?}"),
        }
    }

    // Note: success paths for Promote (text fallback, multi-format,
    // image) are intentionally not unit-tested — they touch the real
    // Windows clipboard, which races with other processes during CI.
    // Live verification covers the round-trip.

    #[test]
    fn bad_json_keeps_listener_alive() {
        let f = fixture();
        // Send raw garbage via the underlying API.
        use interprocess::local_socket::{prelude::*, GenericNamespaced, Stream};
        use std::io::{BufRead, BufReader, Write};
        let name = f.pipe.as_str().to_ns_name::<GenericNamespaced>().unwrap();
        let mut stream = BufReader::new(Stream::connect(name).unwrap());
        stream.get_mut().write_all(b"not json\n").unwrap();
        stream.get_mut().flush().unwrap();
        let mut line = String::new();
        stream.read_line(&mut line).unwrap();
        let resp: Response = serde_json::from_str(line.trim_end()).unwrap();
        assert!(matches!(resp, Response::Error(_)));

        // Listener still serves valid traffic.
        let resp = client::send_to(&f.pipe, Request::Ping).unwrap();
        assert!(matches!(resp, Response::Pong));
    }
}
