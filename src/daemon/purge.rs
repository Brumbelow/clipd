//! Nightly retention purge.
//!
//! Spawned at daemon startup. Runs `store::purge` once on launch (so a daemon
//! that's been off for a week catches up without waiting), then sleeps 24h
//! between iterations. The sleep is broken into 1-minute chunks so the
//! `state.shutting_down` flag is observed promptly when the daemon exits.

use crate::daemon::DaemonState;
use crate::store;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

const PURGE_INTERVAL_MINUTES: u64 = 24 * 60;

pub fn spawn(state: DaemonState) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("clipd-purge".into())
        .spawn(move || run(state))
        .expect("spawn clipd-purge thread")
}

fn run(state: DaemonState) {
    loop {
        if state.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        match store::purge(
            &state.cfg.db_full_path(),
            state.cfg.retention.days,
            state.cfg.retention.max_entries,
            chrono::Utc::now().timestamp_millis(),
        ) {
            Ok(stats) => {
                if stats.by_age + stats.by_cap > 0 {
                    tracing::info!(
                        by_age = stats.by_age,
                        by_cap = stats.by_cap,
                        "purge"
                    );
                } else {
                    tracing::debug!("purge: nothing to drop");
                }
            }
            Err(e) => tracing::warn!(error = %e, "purge failed"),
        }
        for _ in 0..PURGE_INTERVAL_MINUTES {
            if state.shutting_down.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_secs(60));
        }
    }
}
