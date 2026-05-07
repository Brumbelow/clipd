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
        /// Step 11: start hidden, listen on `\\.\pipe\clipd-picker`, and
        /// re-show on Show requests instead of exiting on Esc/Enter.
        /// The daemon launches the prewarmed instance at startup.
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
    init_tracing()?;

    let cli = Cli::parse();
    let cfg = config::Config::load_or_default(cli.config.as_deref()).context("loading config")?;

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

fn init_tracing() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    Ok(())
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
    println!("  db:        {}", cfg.db_full_path().display());
    println!("  key:       {}", cfg.key_full_path().display());
    println!("  hotkey:    {}", cfg.hotkey.chord);
    println!(
        "  retention: {} days, max {} entries",
        cfg.retention.days, cfg.retention.max_entries
    );
    println!(
        "  excluded:  {} app(s)",
        cfg.capture.excluded_apps.len()
    );
    println!(
        "  sensitive: policy={:?}",
        cfg.capture.sensitive_policy
    );
    match daemon::ipc::client::send(cfg, daemon::ipc::Request::Ping) {
        Ok(_) => println!("  daemon:    UP"),
        Err(e) => println!("  daemon:    DOWN ({e})"),
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
