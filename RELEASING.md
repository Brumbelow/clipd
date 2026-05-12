# Releasing clipd

Manual flow. CI is intentionally absent — code signing happens locally via
Azure Trusted Signing using credentials that aren't in this repo.

## 1. Bump and tag

1. Edit `Cargo.toml`: bump `version` (semver: patch for bugfix, minor for
   feature, major for breaking).
2. `cargo build --release` once locally to refresh `Cargo.lock`.
3. Commit: `chore: vX.Y.Z`. Tag: `git tag vX.Y.Z`.

## 2. Build and sign

```
cargo build --release
```

Sign `target\release\clipd.exe` via Azure Trusted Signing. The local config
lives in the gitignored `signing/` directory at the repo root — it
contains the `metadata.json`, account/profile/endpoint, and the signtool
invocation used by `azuresigntool` / `signtool`. If `signing/` is missing
on a fresh machine, follow the Trusted Signing portal docs to recreate the
profile and drop the resulting JSON config in `signing/`.

Sanity-check the signature:

```
signtool verify /pa /v target\release\clipd.exe
```

The output should show "Successfully verified" and a chain that ends at
Microsoft's Trusted Signing root.

## 3. Package

Stage a release directory matching the published naming convention:

```
clipd-vX.Y.Z-x86_64-pc-windows-msvc\
  clipd.exe
  README.md
  LICENSE-APACHE
  config.example.toml
```

Zip it: `Compress-Archive clipd-vX.Y.Z-x86_64-pc-windows-msvc clipd-vX.Y.Z-x86_64-pc-windows-msvc.zip`.

Both the staging directory and the zip are gitignored (see `.gitignore`).

## 4. Publish

```
git push origin main --tags
gh release create vX.Y.Z clipd-vX.Y.Z-x86_64-pc-windows-msvc.zip \
  --title "vX.Y.Z" \
  --notes "…"
```

Notes should list user-visible changes only; mention any config-file or
CLI breaking changes prominently.

## 5. Verify

Download the published zip on a clean machine (or a fresh user account),
unzip, run `.\clipd.exe install --autostart`, reboot, confirm the hotkey
works. SmartScreen may still show "Windows protected your PC" until the
new signature accrues download reputation — that's expected.
