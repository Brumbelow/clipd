# clipd — Local-First Clipboard History Manager for Windows 11

**Target platform:** Windows 11 (x86_64-pc-windows-msvc)
**Repo:** https://github.com/Brumbelow/clipd

---

## Thesis

Win+V is bad: 25-item cap, no real search, no filtering, cloud-sync without
clear opt-out. ClipboardFusion / ArsClip / Ditto are aging Win32/.NET UIs with
no fuzzy search and no developer affordances. 

`clipd` wins on:

1. **Fast fuzzy search** — sub-100ms hotkey-to-results, nucleo-ranked.
2. **Local-only by default** — no cloud sync, ever.
3. **Encrypted at rest** — DPAPI-wrapped AES-GCM, per-user keying.
4. **Password-manager-aware** — respects `ExcludeClipboardContentFromMonitoring`,
   detects high-entropy secrets, refuses to store sensitive content.
5. **Dev-friendly** — auto-classifies entries (URL / JSON / hash / base64 / code),
   preserves all formats on paste-back, search syntax for date filters.
6. **Single static binary** — no runtime, no installer required.

---

## Architecture

Two-process model, one binary:

```
┌──────────────────────┐         named pipe \\.\pipe\clipd
│ clipd --daemon       │ ─────────────────────────────────┐
│  · Win32 msg pump    │                                  │
│  · clipboard listener│                                  │
│  · global hotkey     │                                  ▼
│  · IPC server        │                          ┌──────────────────┐
│  · tray icon         │                          │ clipd pick       │
│  · SQLite + crypto   │                          │  · egui picker   │
└──────────────────────┘                          │  · IPC client    │
                                                  │  · short-lived   │
                                                  └──────────────────┘
```

### Why two processes

- Picker can crash without losing the clipboard hook or DB connection.
- Hotkey launches a fresh process — feels snappier than unhiding a window.
- Daemon stays minimal; picker pulls in eframe/wgpu without bloating the daemon.

### Win32 capture details

- `AddClipboardFormatListener` on a message-only window (`HWND_MESSAGE` parent).
- Single message pump handles `WM_CLIPBOARDUPDATE` and `WM_HOTKEY`.
- `RegisterHotKey` for the configured chord (default `Win+Alt+C`).
- IPC server runs on a separate thread with blocking `interprocess` named pipe.

### Storage

SQLite via `rusqlite` (bundled). Schema in `src/store/schema.rs`:

```sql
CREATE TABLE entries (
    id          INTEGER PRIMARY KEY,
    created_at  INTEGER NOT NULL,           -- unix ms
    last_seen   INTEGER NOT NULL,           -- unix ms (bumped on dedup)
    kind        TEXT NOT NULL,              -- text|image|files|html|rtf|mixed
    content     BLOB NOT NULL,              -- AES-GCM ciphertext
    nonce       BLOB NOT NULL,              -- 12-byte nonce
    preview     TEXT,                       -- first 200 chars, lowercased
    source_app  TEXT,                       -- foreground process at capture
    pinned      INTEGER NOT NULL DEFAULT 0,
    sensitive   INTEGER NOT NULL DEFAULT 0,
    hash        BLOB NOT NULL,              -- blake3 of plaintext content
    size_bytes  INTEGER NOT NULL,
    formats     TEXT                        -- JSON: extra format payloads
);

CREATE UNIQUE INDEX idx_hash ON entries(hash);
CREATE INDEX idx_created ON entries(created_at DESC);
CREATE INDEX idx_last_seen ON entries(last_seen DESC);

CREATE VIRTUAL TABLE entries_fts USING fts5(
    preview,
    content=entries,
    content_rowid=id,
    tokenize='porter unicode61'
);
```

### Encryption

- Per-install AES-GCM-256 key generated on first run.
- Key wrapped with Windows DPAPI (`CryptProtectData`) and stored at
  `%APPDATA%\clipd\key.dpapi`.
- Each row's `content` BLOB encrypted with a fresh 12-byte nonce stored alongside.
- Rationale: DPAPI ties unwrap to the current Windows user account, so the DB
  is unreadable from another user on the same box and unreadable if exfiltrated
  without the user's Windows credentials.

### Search

1. FTS5 prefilter with the user's textual query (porter stemmer).
2. nucleo fuzzy rerank over FTS candidates for ordering.
3. Date filters (`:today`, `:7d`, `>2026-04-01`) applied as SQL `WHERE` before
   text search.

---

## Sensitive content policy (DAY 1, NOT v0.3)

`clipd` MUST refuse to persist any of the following:

1. Clipboard payload includes the `ExcludeClipboardContentFromMonitoring`
   registered format. Bitwarden, 1Password, KeePass, modern browsers set this.
2. Clipboard payload includes `CanIncludeInClipboardHistory` = 0.
3. Foreground window title at capture time matches `(?i)(password|vault|1password|bitwarden|keepass|lastpass)`.
4. Foreground process is a Chromium/Firefox-family browser AND its window has
   no caption text. This is the live signature of a browser-extension password
   manager (Bitwarden / 1Password / Dashlane / LastPass / KeePass) at the
   moment it writes the clipboard — Chromium does not expose
   `ExcludeClipboardContentFromMonitoring` to extensions, so #1 misses them.
   Legitimate page-content copies surface the tab title; right-click context
   menu copies surface the tab title too (the menu has closed by the time the
   `WM_CLIPBOARDUPDATE` handler runs).
5. Content matches a known-secret pattern:
   - `sk-[A-Za-z0-9]{20,}` (OpenAI-style)
   - `ghp_[A-Za-z0-9]{36}` (GitHub PAT)
   - `xox[bpars]-[A-Za-z0-9-]{10,}` (Slack)
   - `AKIA[0-9A-Z]{16}` (AWS access key)
   - JWT structure (3 base64url segments separated by `.`)
   - PEM block headers (`-----BEGIN ... PRIVATE KEY-----`)
6. Content is a single token of length 20–80, no whitespace, with
   Shannon entropy > 4.5 bits/char. URLs (anything starting with `http://`
   or `https://`) bypass this gate — pre-signed URLs and embedded credentials
   are caught by #5 already, and YouTube-style URLs trip the entropy gate
   without being credentials.

Default: **skip storage entirely** for matches. User can opt into "store but
mark sensitive" in `config.toml`. Sensitive entries are never auto-promoted
on hotkey, never appear in default search, and require an explicit `:sensitive`
filter to surface.

Test fixture: copy a password from Bitwarden, confirm zero rows inserted.
This test runs in CI via a recorded clipboard-event fixture (no real Bitwarden
needed — we test the format-detection layer in isolation).

---

## 14-point MVP plan

Acceptance criteria are testable.

### Step 1 — Win32 plumbing ✅
- Message-only window with `wnd_proc`.
- `AddClipboardFormatListener` registered.
- `RegisterHotKey` for `Win+Alt+C` (default; configurable).
- **Accept:** running `clipd --daemon` logs every clipboard change and prints
  `hotkey!` when chord is pressed.

### Step 2 — Storage ✅
- SQLite open / migrate / insert path.
- blake3 dedup; on duplicate, bump `last_seen` instead of inserting.
- `clipd list` subcommand prints last 50 entries.
- **Accept:** copy 5 things, run `clipd list`, see 5 entries; copy the same
  thing twice, see 1 entry with updated `last_seen`.

### Step 3 — Sensitive detection ✅
- `secrets::is_sensitive(payload, foreground_title) -> Decision`.
- Format-flag check for `ExcludeClipboardContentFromMonitoring`.
- Regex + entropy heuristics.
- **Accept:** unit tests pass for: GitHub PAT, AWS key, OpenAI key, JWT,
  PEM block, plain English text (must NOT match), random hex hash
  (configurable — default skip).

### Step 4 — Encryption at rest ✅
- `store::crypto::Vault` — DPAPI-wrap AES-GCM key on first run.
- Encrypt on insert, decrypt on read.
- **Accept:** open `entries.db` in DB Browser for SQLite from a different
  Windows user account → `content` column is opaque ciphertext.

### Step 5 — IPC server ✅
- Named-pipe server at `\\.\pipe\clipd` on a worker thread.
- JSON-line protocol: `list`, `search`, `get`, `promote`, `pin`, `delete`,
  `pause`, `resume`.
- **Accept:** `echo '{"op":"list","limit":10}' | nc -U \\.\pipe\clipd` (or
  PowerShell named-pipe equivalent) returns JSON results.

### Step 6 — egui picker ✅
- `clipd pick` opens a borderless always-on-top egui window.
- Search input on top, virtualized result list below.
- Live nucleo fuzzy filter.
- Enter promotes selected entry, window closes.
- **Accept:** Win+Alt+C opens picker in <100ms. Type 3 chars, see filtered
  results. Enter restores clipboard to selection.
- The literal `<100ms` cold-start budget is **deferred to Step 6.5**: cold
  spawn of `clipd.exe` + wgpu init runs ~150–400ms on first press; subsequent
  presses within a session land under budget. Candidate fixes (out of scope
  here): swap eframe wgpu→glow, or daemon-owned pre-warmed hidden picker.

### Step 6.5 — Cold-start latency ✅
- Swapped eframe render backend `wgpu` → `glow`. Glow uses GL 3.0 directly and
  skips wgpu's adapter-enumeration cost.
- Added cold-start instrumentation: `picker::run` captures an `Instant` at
  entry and the first `App::update` call logs
  `picker cold-start to first frame: Xms` at `info` level.
- Build / clippy / 59 tests / release all clean post-swap.
- **Live measurement** is the user-side gate: with `clipd --daemon` running,
  press the bound hotkey (Win+Alt+C by default) and read the logged number
  from the daemon stderr (debug build) or `RUST_LOG=info clipd.exe pick`
  from a terminal (release).
- **Residual:** the literal `<100ms` target is **not guaranteed** by this
  step alone — process spawn + arg parse + config load happen before the
  measured window. The bigger lever (daemon-spawned hidden-picker + IPC
  re-show) is **deferred to Step 11** where it lives naturally next to
  autostart-at-boot.

### Step 7 — Format preservation on promote ✅
- Capture all clipboard formats at copy time. Implemented as schema v3
  with a per-row child table `entry_formats` (encrypted ciphertext + nonce
  per format), not the JSON column originally sketched — the child table
  keeps AES-GCM nonce-uniqueness trivially correct, eliminates base64/JSON
  inflation, and lets future format-aware queries index by name.
- Restore all formats on promote (loop `SetClipboardData::set_without_clear`
  per format; standard CF_* codes resolve via a static table, registered
  names re-resolve to the session-local code via `RegisterClipboardFormatW`).
- Format scope is text + rich-text (allow-list): CF_UNICODETEXT, CF_TEXT,
  HTML Format, Rich Text Format, Csv, and the Excel OLE bundle
  (Biff12/Biff8/DataObject/Link Source/Embed Source/Object Descriptor/Native).
  CF_DIB/CF_BITMAP/CF_DIBV5 deliberately deferred to Step 8 (image);
  CF_HDROP deferred to a future "kind=files" step.
- Per-format size cap 4 MiB; total cap 16 MiB. Drops surface as `info!`
  with format name + size so "paste into Excel didn't preserve formatting"
  reports are diagnosable.
- Pre-Step-7 rows fall back to the existing `set_text` path (empty
  `entry_formats` set is the marker).
- **Accept:** copy a styled cell from Excel, promote later → paste into Excel
  preserves formatting; paste into Notepad gets the plain text fallback.

### Step 8 — Image support ✅
- New capture branch fires when CF_UNICODETEXT is absent and CF_DIB is
  present. Stores the canonical CF_DIB in `entries.content` (encrypted),
  derives a 256×256-bound PNG thumbnail and a full-size PNG via the
  `image` crate, persists both as `clipd:png_thumb` / `clipd:png_full`
  rows in `entry_formats` (Step 7's child table, reused with a
  `clipd:`-prefix discriminator).
- Promote splits by kind: `kind == "image"` calls a new `set_image`
  that writes CF_DIB + best-effort reconstructs CF_BITMAP for legacy
  GDI receivers (Paint, older Office) by prepending a 14-byte
  `BITMAPFILEHEADER` and calling `clipboard_win::raw::set_bitmap`. All
  other kinds keep the Step 7 multi-format replay path.
- Picker renders image rows at ~80px height with a 64×64 thumbnail
  fetched lazily via the new `Request::GetThumbnail { id }` →
  `Response::Thumbnail { png_b64 }` IPC. Thumbnails are decoded via
  `image::load_from_memory` and uploaded to the GPU as
  `egui::TextureHandle`s cached by entry id for the picker process
  lifetime.
- New direct deps: `base64 = "0.22"` (genuinely new), `image = "0.25"`
  with `default-features = false, features = ["png"]` (promoted from a
  transitive eframe dep).
- Per-image size cap 64 MiB; thumbnail bounding box 256×256 (Triangle
  filter via `image::imageops::resize`).
- **Accept:** Win+PrtScn → picker shows scaled thumbnail; Enter pastes original
  image into Paint.

### Step 9 — Date/time filtering ✅
- Picker query parser at `src/picker/query.rs`: `:today`, `:yesterday`,
  `:Nd` (any 1–3650), `>YYYY-MM-DD`, `<YYYY-MM-DD`, range
  `YYYY-MM-DD..YYYY-MM-DD`. Anchors "today" at local-time midnight so
  the predicate matches the user's wall clock, not UTC.
- Filters applied as SQL `WHERE created_at` clauses before the existing
  `LIKE '%q%'` text match. New `DateFilter` enum lives in `store::mod`,
  serialized over IPC via `Request::Search { query, limit, filters }`.
  Empty `query` + non-empty `filters` (the `:today` with no search term
  case) is supported.
- Schema v4 adds `idx_created` over `entries(created_at DESC)` to back
  the predicates. Search SQL also gains `ORDER BY pinned DESC,
  last_seen DESC` so pinned rows float above recency-ranked unpinned
  rows in search results.
- FTS5 deferred — `LIKE` is adequate up to ~10k rows and the original
  architecture-section reference is now flagged as a v0.2 follow-up.
- **Accept:** `:7d kubectl` returns only entries with "kubectl" in the
  last 7 days.

### Step 10 — Pinning + auto-classification ✅
- New `content_kind` column (schema v5) carries the content-shape
  taxonomy `url|json|hex|base64|code|text`, distinct from the existing
  capture-format `kind` (`text|image|files|...`). Auto-set at capture
  time via `src/classify/mod.rs`. The v5 migration backfills every
  pre-Step-10 text row by decrypting + reclassifying — URLs/JSON/etc.
  copied before the upgrade get correct badges immediately.
- Picker `badge()` now picks colour + label by content_kind for text
  rows and falls back to `kind` for image/files/html/rtf rows. Six new
  colours: blue (url), orange (json), magenta (hex), cyan (base64),
  green (code), grey (text). Image/files/html/rtf colours unchanged.
- Pin write path was already wired (Step 5 IPC + Step 9 picker `Ctrl+P`).
  This step adds `ORDER BY pinned DESC, last_seen DESC` to `store::list`,
  so pinned rows float to the top of the empty-query view too — not
  only in search results.
- The retention-purge half of the original accept criteria is owned
  by Step 12.
- **Accept:** copy a URL → entry shows the `url` badge. Pin via `Ctrl+P`;
  the row floats above newer unpinned entries.

### Step 11 — Tray + autostart ✅
- `tray-icon` on the daemon — quit, open config, pause/resume capture.
- `clipd install --autostart` writes `HKCU\...\Run\clipd` registry key.
- **Accept:** reboot → daemon starts → tray icon visible → hotkey works.
- **Sub-task carried from Step 6.5 (cold-start <100ms):** once the daemon
  autostarts at boot, spawn `clipd pick --prewarm` once at daemon startup;
  the picker boots eframe, paints once, then hides. Add `Request::Show` to
  the IPC; WM_HOTKEY sends `Show` instead of spawning a new process. Picker
  hides instead of exits on Esc/Enter. Daemon supervises and respawns the
  picker on crash. This shape was deliberately deferred from Step 6.5 to
  avoid bloating the daemon process — autostart reframes "daemon at boot"
  as the norm anyway.

### Step 12 — Config + retention ✅
- `config.toml` at `%APPDATA%\clipd\config.toml`: hotkey, retention days,
  max entries, excluded apps (by exe name), sensitive policy. The
  `[capture]` section adds `excluded_apps` (case-insensitive exe basename
  list — capture skips with `Reason::ExcludedApp`) and
  `sensitive_policy = "skip" | "mark"`. Default `skip` matches Step 3
  behaviour. With `mark`, secret-detection reasons (regex / entropy /
  password-manager window / browser-extension popup) insert with
  `sensitive = 1` instead of dropping; the row is hidden from default
  `list`/`search` queries (`WHERE sensitive = 0`). Explicit signals
  (`ExcludeFormatFlag`, `ClipboardHistoryDisabled`, `ExcludedApp`) always
  skip regardless of policy — those are user/app explicit refusals, not
  heuristics. Picker `:sensitive` filter for surfacing marked rows is a
  v0.2 follow-up.
- `store::purge(retention_days, max_entries, now_ms)` in a single
  transaction: age cutoff = `now_ms - days * 86_400_000`, cap deletes the
  oldest `count - max_entries` by `last_seen ASC`. `0` disables either
  half. Pinned rows always survive. ON DELETE CASCADE on `entry_formats`
  (Step 7) reaps child rows. `now_ms` is parameterized so unit tests can
  pass a synthetic clock — covers the accept criteria without touching
  the system clock.
- New `daemon::purge` thread spawns at daemon startup (after IPC
  server, before picker supervisor); runs purge once on boot then sleeps
  24h between iterations. The 24h sleep is broken into 1-min chunks so
  `state.shutting_down` (Step 11) is observed promptly.
- New `clipd config` subcommand with `--show` (default — pretty-print
  effective TOML) and `--path` (resolved file path). `clipd doctor` now
  also reports excluded-apps count and sensitive policy.
- **Accept:** unit tests in `store::tests` cover both purge dimensions
  with synthetic clocks: `purge_by_age_drops_unpinned_old_rows`,
  `purge_by_cap_keeps_newest_by_last_seen`,
  `purge_by_cap_skips_pinned_in_overage`,
  `purge_zero_settings_is_noop`,
  `sensitive_rows_hidden_from_list_and_search`. Capture tests cover the
  exclude-app path: `excluded_app_basename_match_is_case_insensitive`,
  `skip_reason_returns_excluded_app_for_listed_exe`.

### Step 13 — Polish
- Tracing → file logger at `%APPDATA%\clipd\logs\clipd.log` with rotation.
- Crash handler logs panic + backtrace.
- `clipd doctor` subcommand: prints config, checks key file, DB integrity,
  named pipe reachability, hotkey registration.

### Step 14 — Release
- GitHub Actions: Windows MSVC build, `cargo test`, signed release artifact.
- Zipped portable: `clipd.exe` + `config.example.toml` + `README.md`.
- v0.1.0 git tag.
- **Accept:** download zip on a clean Win11 VM, run `clipd install --autostart`,
  reboot, hotkey works.

---

## What's deferred (DO NOT BUILD IN v0.1)

- Cloud sync. Architecturally out of scope. If anyone wants this later it's an
  opt-in plugin with explicit per-entry sync flags. Not in v1.
- Linux / macOS. Port after Windows is stable. Capture layer is the only
  platform-specific code if `trait ClipboardSource` is kept clean.
- Plugin / scripting system. Will balloon scope.
- OCR on copied images.
- Browser extensions / native messaging.
- Snippet expansion.

## Threat model

A clipboard manager that runs as a user-mode daemon and stores everything is,
structurally, a credential exfiltration tool. The user is the threat model.
Mitigations baked into v0.1 and not deferred:

- DPAPI-wrapped AES-GCM at rest (Day 4).
- Password-manager exclusion + secret-pattern heuristics (Day 3).
- Default retention < 30 days (configurable).
- No cloud sync, ever.
- `clipd doctor` surfaces what's stored and where.

## Out-of-scope threats

- Malware running as the same Windows user. DPAPI cannot defend against this;
  the malware can simply call `CryptUnprotectData` itself. This is a fundamental
  limit of any user-mode clipboard tool and is documented in the README.
- Cold-boot / disk-image attacks. DPAPI key is on disk wrapped to the user
  profile; an attacker with the user's NTUSER.DAT and password can decrypt.
  BitLocker is the answer here, not clipd.
