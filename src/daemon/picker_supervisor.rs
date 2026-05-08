//! Spawn + monitor the prewarmed picker.
//!
//! Prewarm is currently disabled at the call site in `daemon::run` because
//! a hidden eframe window stops servicing `Visible(true)` viewport
//! commands after one hide cycle on Windows. The infrastructure is kept
//! in place for a future fix; `#![allow(dead_code)]` silences the
//! unused-symbol warnings until then.
//!
//! When enabled, the daemon launches one `clipd pick --prewarm` child at
//! startup. The supervisor thread:
//!
//!   1. Records the child's PID on `DaemonState.picker_pid`.
//!   2. Forwards the child's stderr into `tracing::warn!` (so panics from
//!      the picker show up in daemon logs).
//!   3. Watches for exit. On exit:
//!      - if the run was shorter than 2s, increment a fail counter;
//!      - at fail counter ≥ 3, set `prewarm_disabled` and stop respawning;
//!      - otherwise reset the counter and respawn.
//!
//! Shutdown: `DaemonState.shutting_down` flipped by `daemon::run` after
//! the message pump exits causes the supervisor to kill the child and
//! return. `daemon::run` also calls [`kill_pid`] on the recorded PID as
//! a belt-and-braces against orphaning.

#![allow(dead_code)]

use crate::daemon::DaemonState;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// Maximum number of consecutive sub-2s exits before the supervisor declares
/// the picker unhealthy and disables prewarming.
const MAX_FAILS: u32 = 3;
/// Threshold below which an exit counts as a "fast crash" toward the fail
/// counter. Two seconds covers normal eframe init even on cold disks.
const FAST_CRASH_WINDOW: Duration = Duration::from_secs(2);
/// Polling interval inside the supervisor's wait loop. 250ms is the worst-case
/// latency to notice either an exit or a shutdown signal.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Result of feeding one exit into the crash-loop policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashDecision {
    /// Reset fail counter and respawn.
    Healthy,
    /// Below the fast-crash threshold but under the max-fails cap; respawn.
    FastButRespawn,
    /// At or above the cap — disable prewarm.
    Disable,
}

/// Pure policy used by the supervisor loop. Extracted so the boundary
/// behaviour (fast-crash threshold, fail cap) is unit-testable without
/// spawning processes.
fn classify_exit(elapsed: Duration, fails_after: u32) -> CrashDecision {
    if elapsed >= FAST_CRASH_WINDOW {
        CrashDecision::Healthy
    } else if fails_after >= MAX_FAILS {
        CrashDecision::Disable
    } else {
        CrashDecision::FastButRespawn
    }
}

/// Spawn the supervisor thread. Returns immediately; spawning the actual
/// picker child happens on the worker thread.
pub fn spawn(state: DaemonState) -> Result<()> {
    std::thread::Builder::new()
        .name("clipd-picker-supervisor".into())
        .spawn(move || run_supervisor(state))
        .context("spawning picker supervisor thread")?;
    Ok(())
}

fn run_supervisor(state: DaemonState) {
    let mut fails = 0u32;
    while !state.shutting_down.load(Ordering::SeqCst) {
        let spawn_at = Instant::now();
        let mut child = match spawn_picker_child() {
            Ok(c) => c,
            Err(e) => {
                error!("picker spawn failed: {e:#}");
                fails += 1;
                if fails >= MAX_FAILS {
                    error!(
                        fails,
                        "picker repeatedly failed to spawn — disabling prewarm"
                    );
                    state.prewarm_disabled.store(true, Ordering::SeqCst);
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        let pid = child.id();
        state.picker_pid.store(pid, Ordering::SeqCst);
        info!(pid, "spawned prewarmed picker child");

        // Forward child stderr to daemon logs.
        if let Some(stderr) = child.stderr.take() {
            std::thread::Builder::new()
                .name("clipd-picker-stderr".into())
                .spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(|r| r.ok()) {
                        if !line.is_empty() {
                            warn!(target: "picker", "{line}");
                        }
                    }
                })
                .ok();
        }

        // Wait for exit (or shutdown).
        let exit_status = wait_for_exit(&mut child, &state);
        state.picker_pid.store(0, Ordering::SeqCst);

        if state.shutting_down.load(Ordering::SeqCst) {
            // wait_for_exit already killed the child if the daemon is shutting down.
            return;
        }

        let elapsed = spawn_at.elapsed();
        match exit_status {
            Some(status) => info!(?status, ?elapsed, "picker child exited"),
            None => warn!(?elapsed, "picker child exit status unknown"),
        }

        let provisional = if elapsed < FAST_CRASH_WINDOW {
            fails + 1
        } else {
            0
        };
        match classify_exit(elapsed, provisional) {
            CrashDecision::Healthy => fails = 0,
            CrashDecision::FastButRespawn => fails = provisional,
            CrashDecision::Disable => {
                error!(
                    fails = provisional,
                    "picker crash-loop detected — disabling prewarm"
                );
                state.prewarm_disabled.store(true, Ordering::SeqCst);
                return;
            }
        }

        // Brief pause before respawn so we don't burn CPU on tight crash loops
        // before the threshold kicks in.
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn spawn_picker_child() -> Result<Child> {
    let exe = std::env::current_exe().context("locating clipd.exe")?;
    Command::new(exe)
        .arg("pick")
        .arg("--prewarm")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning clipd pick --prewarm")
}

fn wait_for_exit(child: &mut Child, state: &DaemonState) -> Option<std::process::ExitStatus> {
    loop {
        if state.shutting_down.load(Ordering::SeqCst) {
            // Daemon is going away; kill and reap.
            let _ = child.kill();
            return child.wait().ok();
        }
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(e) => {
                warn!("try_wait error: {e:#}");
                return None;
            }
        }
    }
}

/// Best-effort kill by PID. Used by `daemon::run` on shutdown to ensure the
/// picker doesn't outlive its parent.
pub fn kill_pid(pid: u32) {
    if pid == 0 {
        return;
    }
    // SAFETY: PROCESS_TERMINATE is the minimum-privilege right for kill.
    // OpenProcess returns Err on access denial or invalid pid; we propagate.
    let handle: HANDLE = match unsafe { OpenProcess(PROCESS_TERMINATE, BOOL(0), pid) } {
        Ok(h) => h,
        Err(e) => {
            warn!(pid, "OpenProcess failed: {e}");
            return;
        }
    };
    // SAFETY: handle valid; exit code 0 is fine for forced kill.
    let _ = unsafe { TerminateProcess(handle, 0) };
    // SAFETY: handle came from OpenProcess; close exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_exit_healthy_above_window() {
        // A run longer than FAST_CRASH_WINDOW resets the fail counter
        // regardless of prior state.
        assert_eq!(
            classify_exit(Duration::from_secs(5), 5),
            CrashDecision::Healthy
        );
        assert_eq!(classify_exit(FAST_CRASH_WINDOW, 99), CrashDecision::Healthy);
    }

    #[test]
    fn classify_exit_fast_under_cap() {
        // Below threshold but fails_after still under MAX_FAILS → respawn.
        assert_eq!(
            classify_exit(Duration::from_millis(100), 1),
            CrashDecision::FastButRespawn
        );
        assert_eq!(
            classify_exit(Duration::from_millis(100), MAX_FAILS - 1),
            CrashDecision::FastButRespawn
        );
    }

    #[test]
    fn classify_exit_disables_at_cap() {
        // At MAX_FAILS, supervisor must disable.
        assert_eq!(
            classify_exit(Duration::from_millis(100), MAX_FAILS),
            CrashDecision::Disable
        );
        assert_eq!(
            classify_exit(Duration::from_millis(100), MAX_FAILS + 5),
            CrashDecision::Disable
        );
    }

    #[test]
    fn kill_pid_zero_is_no_op() {
        // Sentinel value (no picker alive) must not panic or call into Win32.
        kill_pid(0);
    }

    #[test]
    fn kill_pid_nonexistent_is_safe() {
        // Choose a PID extremely unlikely to be alive. OpenProcess errors
        // out gracefully; kill_pid logs and returns.
        kill_pid(0xFFFF_0000);
    }
}
