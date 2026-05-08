//! clipd — local-first clipboard history manager for Windows 11.
//!
//! Single-binary, two-process design: a long-lived daemon owns the clipboard
//! hook, hotkey, SQLite store, and IPC server; the picker is a short-lived
//! egui window that talks to the daemon over a named pipe.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod classify;
mod config;
mod daemon;
mod install;
mod picker;
mod secrets;
mod store;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "clipd",
    version,
    about = "local-first clipboard history manager"
)]
struct Cli {
    /// Run as the background daemon (clipboard hook + hotkey + IPC server).
    #[arg(long)]
    daemon: bool,

    /// Override config path (default: %APPDATA%\clipd\config.toml).
    #[arg(long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Open the picker window. Talks to the running daemon.
    Pick {
        /// Start hidden, listen on `\\.\pipe\clipd-picker`, and re-show on
        /// Show requests instead of exiting on Esc/Enter. The daemon
        /// launches the prewarmed instance at startup.
        #[arg(long)]
        prewarm: bool,
    },

    /// Print recent clipboard entries.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Search clipboard entries.
    Search {
        query: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Delete an entry by id.
    Delete { id: i64 },

    /// Pin or unpin an entry.
    Pin {
        id: i64,
        #[arg(long)]
        unpin: bool,
    },

    /// Pause clipboard capture (daemon keeps running).
    Pause,
    /// Resume clipboard capture.
    Resume,

    /// Print diagnostics: config, key file, DB integrity, named pipe reachability.
    Doctor,

    /// Print effective config or its file path.
    Config {
        /// Print the resolved config file path.
        #[arg(long)]
        path: bool,
        /// Print the effective config as TOML (default if no flag given).
        #[arg(long)]
        show: bool,
    },

    /// Install autostart registry entry (HKCU\...\Run\clipd).
    Install {
        #[arg(long)]
        autostart: bool,
    },

    /// Remove autostart entry.
    Uninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Load config before init_tracing so the file logger can write inside
    // the resolved data dir (`%APPDATA%\clipd\logs\`). The tiny window
    // before init_tracing — clap parse + one TOML read — can't emit
    // tracing events anyway, so reordering loses nothing.
    let cfg = config::Config::load_or_default(cli.config.as_deref()).context("loading config")?;
    init_tracing(&cfg)?;

    if cli.daemon {
        return daemon::run(cfg);
    }

    match cli.cmd {
        Some(Cmd::Pick { prewarm }) => picker::run(cfg, prewarm),
        None => picker::run(cfg, false),
        Some(Cmd::List { limit }) => cli_list(&cfg, limit),
        Some(Cmd::Search { query, limit }) => cli_search(&cfg, &query, limit),
        Some(Cmd::Delete { id }) => cli_delete(&cfg, id),
        Some(Cmd::Pin { id, unpin }) => cli_pin(&cfg, id, !unpin),
        Some(Cmd::Pause) => cli_send(&cfg, daemon::ipc::Request::Pause),
        Some(Cmd::Resume) => cli_send(&cfg, daemon::ipc::Request::Resume),
        Some(Cmd::Doctor) => cli_doctor(&cfg),
        Some(Cmd::Config { path, show }) => cli_config(&cfg, path, show),
        Some(Cmd::Install { autostart }) => cli_install(&cfg, autostart),
        Some(Cmd::Uninstall) => cli_uninstall(&cfg),
    }
}

fn init_tracing(cfg: &config::Config) -> Result<()> {
    // Layered subscriber — console (stderr, default) plus a daily-rotating
    // file appender at `%APPDATA%\clipd\logs\clipd.log.<date>`.
    //
    // Synchronous writes (no `tracing_appender::non_blocking`) are
    // deliberate: release builds set `panic = "abort"` in Cargo.toml, which
    // skips Drop and would race a background flush thread against process
    // termination — exactly when we most need the panic line on disk. The
    // logging volume here is tiny (one line per copy event), so blocking
    // the WM_CLIPBOARDUPDATE handler on a file write is acceptable.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let console_layer = tracing_subscriber::fmt::layer().with_target(false);
    let file_layer = match build_file_appender(&cfg.logs_dir()) {
        Ok(appender) => Some(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(appender),
        ),
        Err(e) => {
            // Don't fail startup over logging — surface and continue with
            // console-only. `clipd doctor` will show the empty logs dir.
            eprintln!("clipd: file logger disabled: {e:#}");
            None
        }
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    install_panic_hook();
    Ok(())
}

fn build_file_appender(
    logs_dir: &std::path::Path,
) -> Result<tracing_appender::rolling::RollingFileAppender> {
    std::fs::create_dir_all(logs_dir)
        .with_context(|| format!("creating logs dir {}", logs_dir.display()))?;
    tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("clipd")
        .filename_suffix("log")
        .max_log_files(14)
        .build(logs_dir)
        .context("building rolling file appender")
}

/// Panic hook that logs the message, source location, thread name, and a
/// forced backtrace via `tracing::error!` so it lands in both the console
/// and file subscribers. Guarded by `Once` because the picker supervisor
/// relaunches `clipd pick --prewarm` and tests re-init the process;
/// double-installing would chain hooks and double-log.
fn install_panic_hook() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let thread = std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_string();
            // `force_capture` ignores RUST_BACKTRACE; we always want the
            // trace in the daemon's log even when the env var isn't set.
            let backtrace = std::backtrace::Backtrace::force_capture();
            tracing::error!(
                target: "clipd::panic",
                thread = %thread,
                location = %location,
                backtrace = %backtrace,
                "panic: {msg}"
            );
            // Defer to the previous (default) hook so stderr-attached
            // builds still print the standard panic summary.
            prev(info);
        }));
    });
}

// ---- thin CLI wrappers — all real work goes through the daemon over IPC ----

fn cli_list(cfg: &config::Config, limit: usize) -> Result<()> {
    match daemon::ipc::client::send(cfg, daemon::ipc::Request::List { limit }) {
        Ok(resp) => print_entries(resp),
        Err(_) => {
            // Daemon down: WAL mode lets a short-lived reader peek directly.
            print_rows(store::list(&cfg.db_full_path(), limit)?);
        }
    }
    Ok(())
}

fn cli_search(cfg: &config::Config, query: &str, limit: usize) -> Result<()> {
    let resp = daemon::ipc::client::send(
        cfg,
        daemon::ipc::Request::Search {
            query: query.to_string(),
            limit,
            filters: Vec::new(),
        },
    )?;
    print_entries(resp);
    Ok(())
}

fn cli_delete(cfg: &config::Config, id: i64) -> Result<()> {
    expect_ok(daemon::ipc::client::send(
        cfg,
        daemon::ipc::Request::Delete { id },
    )?)?;
    println!("deleted #{id}");
    Ok(())
}

fn cli_pin(cfg: &config::Config, id: i64, pinned: bool) -> Result<()> {
    expect_ok(daemon::ipc::client::send(
        cfg,
        daemon::ipc::Request::Pin { id, pinned },
    )?)?;
    println!("{}: #{id}", if pinned { "pinned" } else { "unpinned" });
    Ok(())
}

fn cli_send(cfg: &config::Config, req: daemon::ipc::Request) -> Result<()> {
    expect_ok(daemon::ipc::client::send(cfg, req)?)?;
    Ok(())
}

fn expect_ok(resp: daemon::ipc::Response) -> Result<()> {
    match resp {
        daemon::ipc::Response::Ok | daemon::ipc::Response::Pong => Ok(()),
        daemon::ipc::Response::Error(msg) => anyhow::bail!("{msg}"),
        daemon::ipc::Response::Entries(_) => anyhow::bail!("unexpected Entries response"),
        daemon::ipc::Response::Thumbnail { .. } => {
            anyhow::bail!("unexpected Thumbnail response")
        }
    }
}

fn cli_doctor(cfg: &config::Config) -> Result<()> {
    println!("clipd doctor");
    println!("  config:    {}", cfg.source_path.display());
    println!("  logs:      {}", cfg.logs_dir().display());
    println!(
        "  retention: {} days, max {} entries",
        cfg.retention.days, cfg.retention.max_entries
    );
    println!("  excluded:  {} app(s)", cfg.capture.excluded_apps.len());
    println!("  sensitive: policy={:?}", cfg.capture.sensitive_policy);

    // Key file probe. `Vault::probe` reads + DPAPI-unwraps without creating
    // the file (`Vault::open` would side-effect a fresh key).
    let key_path = cfg.key_full_path();
    if !key_path.exists() {
        println!(
            "  key:       {} (missing — will be created on first daemon run)",
            key_path.display()
        );
    } else {
        match store::crypto::Vault::probe(&key_path) {
            Ok(bytes) => println!(
                "  key:       {} (present, {} bytes, decryptable)",
                key_path.display(),
                bytes
            ),
            Err(e) => println!(
                "  key:       {} (present but DPAPI unwrap failed: {e})",
                key_path.display()
            ),
        }
    }

    // DB integrity probe. PRAGMA integrity_check returns "ok" on a healthy
    // file; anything else is a red flag (truncation, page corruption,
    // missing tables, etc.).
    let db_path = cfg.db_full_path();
    if !db_path.exists() {
        println!("  db:        {} (not yet created)", db_path.display());
    } else {
        match store::integrity_check(&db_path) {
            Ok(ref s) if s == "ok" => {
                println!("  db:        {} (integrity: ok)", db_path.display())
            }
            Ok(s) => {
                println!("  db:        {} (integrity FAIL):", db_path.display());
                for line in s.lines() {
                    println!("             {line}");
                }
            }
            Err(e) => println!("  db:        {} (integrity probe failed: {e})", db_path.display()),
        }
    }

    // Pipe reachability + derived hotkey-registration status. The daemon
    // bails on RegisterHotKey failure (src/daemon/win_hook.rs), so a
    // running daemon proves the chord is bound to its message-only window.
    let daemon_up = match daemon::ipc::client::send(cfg, daemon::ipc::Request::Ping) {
        Ok(_) => {
            println!(
                "  pipe:      \\\\.\\pipe\\{} (reachable)",
                daemon::ipc::server::PIPE_NAME
            );
            true
        }
        Err(e) => {
            println!(
                "  pipe:      \\\\.\\pipe\\{} (unreachable: {e})",
                daemon::ipc::server::PIPE_NAME
            );
            false
        }
    };
    if daemon_up {
        println!("  hotkey:    {} (registered)", cfg.hotkey.chord);
    } else {
        println!(
            "  hotkey:    {} (not registered — daemon offline)",
            cfg.hotkey.chord
        );
    }

    match install::autostart_enabled() {
        Ok(true) => println!("  autostart: enabled"),
        Ok(false) => println!("  autostart: disabled"),
        Err(e) => println!("  autostart: unknown ({e})"),
    }
    Ok(())
}

fn cli_config(cfg: &config::Config, path: bool, show: bool) -> Result<()> {
    if path {
        println!("{}", cfg.source_path.display());
        return Ok(());
    }
    // Default behavior (no flags or --show): pretty-print effective config.
    let _ = show;
    let serialized = toml::to_string_pretty(cfg).context("serializing config to TOML")?;
    print!("{serialized}");
    Ok(())
}

fn cli_install(_cfg: &config::Config, autostart: bool) -> Result<()> {
    if autostart {
        install::enable_autostart()?;
        println!("autostart enabled (HKCU\\…\\Run\\clipd)");
    } else {
        println!("nothing to do — pass --autostart to register the daemon at logon");
    }
    Ok(())
}

fn cli_uninstall(_cfg: &config::Config) -> Result<()> {
    install::disable_autostart()?;
    println!("autostart removed");
    Ok(())
}

fn print_entries(resp: daemon::ipc::Response) {
    use daemon::ipc::Response;
    match resp {
        Response::Entries(entries) => {
            for e in entries {
                println!(
                    "#{:<6} {:<7} [{:<5}] {} {}",
                    e.id,
                    e.kind,
                    if e.pinned { "pin" } else { "" },
                    chrono::DateTime::<chrono::Local>::from(
                        std::time::UNIX_EPOCH
                            + std::time::Duration::from_millis(e.created_at as u64),
                    )
                    .format("%Y-%m-%d %H:%M:%S"),
                    truncate(&e.preview, 80)
                );
            }
        }
        Response::Ok => println!("ok"),
        Response::Pong => println!("pong"),
        Response::Thumbnail { png_b64 } => println!("thumbnail ({} bytes b64)", png_b64.len()),
        Response::Error(msg) => eprintln!("error: {msg}"),
    }
}

fn print_rows(rows: Vec<store::EntryRow>) {
    for r in rows {
        println!(
            "#{:<6} {:<7} [{:<5}] {} {}",
            r.id,
            r.kind,
            if r.pinned { "pin" } else { "" },
            chrono::DateTime::<chrono::Local>::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(r.last_seen as u64),
            )
            .format("%Y-%m-%d %H:%M:%S"),
            truncate(&r.preview, 80)
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    // Replace ALL control chars (\n, \r, \t, ANSI escape, etc.) with a space.
    // A bare \r in the preview will reset the cursor and corrupt the listing.
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if one_line.chars().count() <= max {
        one_line
    } else {
        let mut out: String = one_line.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}
