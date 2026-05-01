//! Clipboard write path. Step 5 supports text only; Step 7 will replace this
//! with a multi-format restore that loops over the saved `formats` payload.

use anyhow::{anyhow, Result};

pub fn set_text(s: &str) -> Result<()> {
    clipboard_win::set_clipboard_string(s).map_err(|e| anyhow!("set_clipboard_string: {e}"))
}
