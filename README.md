# clipd

**Local-first clipboard history manager for Windows 11.**

`clipd` is a single-binary clipboard manager that captures everything you copy,
indexes it for fuzzy search, and pastes any past entry back with full format
preservation — without ever leaving your machine.

## Why clipd

Win+V has a 25-item cap, no real search, no filtering, and cloud-syncs by
default with no clear opt-out. ClipboardFusion / ArsClip / Ditto are aging
Win32/.NET UIs without fuzzy search or developer affordances.

`clipd`:

1. **Fast fuzzy search** — sub-100ms hotkey-to-results, nucleo-ranked.
2. **Local-only by default** — no cloud sync, ever.
3. **Encrypted at rest** — DPAPI-wrapped AES-GCM, per-user keying.
4. **Password-manager-aware** — respects `ExcludeClipboardContentFromMonitoring`,
   detects high-entropy secrets, refuses to store sensitive content.
5. **Dev-friendly** — auto-classifies entries (URL / JSON / hash / base64 /
   code), preserves all formats on paste-back, search syntax for date filters.
6. **Single static binary** — no runtime, no installer required.

## Install

1. Download the latest `clipd-vX.Y.Z-x86_64-pc-windows-msvc.zip` from
   [Releases](https://github.com/Brumbelow/clipd/releases).
2. Unzip anywhere — `%LOCALAPPDATA%\Programs\clipd\` is a sensible choice but
   anywhere works; the autostart entry records whatever path you unzip to.
3. Open a terminal in the unzipped folder and run:

   ```
   .\clipd.exe install --autostart
   ```

   This writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\clipd`
   pointing at `clipd.exe --daemon`.
4. Reboot (or start the daemon manually with `.\clipd.exe --daemon`).
5. Press **Win+Alt+C** — the picker opens.

To remove autostart: `.\clipd.exe uninstall`.

### First-run SmartScreen warning

`clipd.exe` is signed by Andrew Brumbelow via Microsoft Trusted Signing.
SmartScreen also weighs application reputation, which builds with download
volume; until reputation accumulates, the first time you run the binary
you may still see "Windows protected your PC."

If that happens:

1. Click **More info**.
2. Click **Run anyway**.

Once SmartScreen has seen the signature on enough machines, the warning
goes away on its own — you do not need to take any action to make that
happen.

## Usage

### Picker (default)

Press **Win+Alt+C** to open the picker.

| Key | Action |
| --- | --- |
| Type | Live fuzzy filter |
| ↑ / ↓ | Navigate results |
| Enter | Restore selection to clipboard, close picker |
| Esc | Close picker |
| Ctrl+P | Pin / unpin selected entry |

### Search syntax

Inside the picker query, prefixed tokens filter by date:

- `:today`, `:yesterday`
- `:Nd` — last N days, e.g. `:7d`
- `>YYYY-MM-DD` — entries after that date
- `<YYYY-MM-DD` — entries before that date
- `YYYY-MM-DD..YYYY-MM-DD` — range

Combine with text: `:7d kubectl` matches "kubectl" entries from the last week.

### CLI

| Command | Effect |
| --- | --- |
| `clipd pick` | Open picker (default if no subcommand) |
| `clipd list [--limit N]` | Print recent entries |
| `clipd search <query> [--limit N]` | Text search |
| `clipd delete <id>` | Delete entry by id |
| `clipd pin <id> [--unpin]` | Pin / unpin entry |
| `clipd pause` / `clipd resume` | Pause / resume capture (daemon stays up) |
| `clipd doctor` | Diagnostics: config, key file, DB integrity, pipe, hotkey |
| `clipd config [--show \| --path]` | Print effective config or its path |
| `clipd install --autostart` | Add HKCU Run entry |
| `clipd uninstall` | Remove HKCU Run entry |
| `clipd --daemon` | Run the daemon directly (autostart calls this) |

## Configuration

Config lives at `%APPDATA%\clipd\config.toml`. The file is created on demand —
defaults apply if it's absent. See [`config.example.toml`](config.example.toml)
for every section, with defaults and one-line descriptions:

- `[hotkey]` — chord (default `win+alt+c`)
- `[retention]` — days + max entries (default 30 days, 5000 entries)
- `[picker]` — result limit
- `[secrets]` — entropy heuristics tuning
- `[capture]` — exe-name exclusions, sensitive-content policy (`skip` | `mark`)
- `[paths]` — override data dir (default `%APPDATA%\clipd\`)

Run `clipd config --show` to print the effective merged config, or
`clipd config --path` for the resolved file path.

## Security

### What clipd defends against

- **Encryption at rest** — every clipboard payload is encrypted with AES-GCM
  using a per-install 32-byte key. The key is wrapped with Windows DPAPI
  (`CryptProtectData`), tied to your user account, and stored at
  `%APPDATA%\clipd\key.dpapi`. Another Windows user on the same machine
  cannot decrypt your clipboard history. A stolen disk image without your
  Windows credentials is unreadable.
- **Password-manager exclusion** — clipd refuses to store payloads tagged
  with the `ExcludeClipboardContentFromMonitoring` clipboard format
  (Bitwarden, 1Password, KeePass, modern browsers all set this). It also
  detects browser-extension password-manager copies that don't surface the
  format flag.
- **Secret-pattern heuristics** — OpenAI / GitHub / Slack / AWS keys, JWTs,
  PEM blocks, and high-entropy short tokens are recognized and dropped (or
  marked sensitive, see config).
- **No cloud sync, ever** — clipd is a local-only tool. There is no opt-in
  sync, no telemetry, no network code.

### What clipd does NOT defend against

- **Malware running as the same Windows user.** DPAPI cannot defend against
  this — the malware can call `CryptUnprotectData` itself. This is a
  fundamental limit of any user-mode clipboard tool.
- **Cold-boot / disk-image attacks where the attacker has your Windows
  password.** BitLocker is the answer here, not clipd.

For full triage info while running, `clipd doctor` prints config paths, key
file status, DB integrity (`PRAGMA integrity_check`), pipe reachability,
hotkey registration, and autostart status.

## Logs

`clipd` writes a daily-rotated log at
`%APPDATA%\clipd\logs\clipd.<YYYY-MM-DD>.log`. Last 14 days kept. Panics are
captured with location, thread, and a forced backtrace.

## License

Licensed under the [Apache License, Version 2.0](LICENSE-APACHE).
