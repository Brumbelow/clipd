//! egui picker process. Wired in Step 6.
//!
//! Today this is a stub: `clipd pick` (or no-arg invocation) bails out so
//! the binary builds while Steps 1–5 land. The `app` module compiles as
//! dead code so the search/promote/pin handlers stay close to the rest of
//! the code; Step 6 will replace `run` with `eframe::run_native`.

#[allow(dead_code)] // wired in Step 6 (egui picker)
mod app;

use crate::config::Config;
use anyhow::Result;

pub fn run(_cfg: Config) -> Result<()> {
    // Exit cleanly so the daemon's console doesn't show an `Error: …` line on
    // every hotkey press during Steps 1–5.
    tracing::warn!("picker not yet implemented (Step 6)");
    Ok(())
}
