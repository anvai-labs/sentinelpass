# Build Guide

## Toolchain Matrix

| Tool | Minimum |
| --- | --- |
| Rust | 1.70+ |
| Node.js | 20+ |
| npm | 10+ |
| PowerShell (Windows install scripts) | 5.1+ |

## Platform Dependencies

| Platform | Extra system packages |
| --- | --- |
| Windows | None (Tauri Windows toolchain is sufficient) |
| macOS | `brew install openssl` |
| Ubuntu/Debian | `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev build-essential` |

## Build Commands

```bash
npm install
npm run web:build
cargo build --release
```

## Fast Dev Commands

| Task | Command |
| --- | --- |
| UI (debug) | `cargo run --package sentinelpass-ui` |
| Daemon | `cargo run --package sentinelpass-daemon` |
| CLI help | `cargo run --package sentinelpass-cli -- --help` |
| Relay server | `cargo run --bin sentinelpass-relay` |
| Relay (with sync) | `cargo build --features sync` |
| Rust tests | `cargo test --workspace` |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| TS typecheck | `npm run web:typecheck` |
| TS tests | `npm run test:ts` |

## Coverage Gates

| Coverage gate | Command |
| --- | --- |
| Rust LLVM coverage | `bash scripts/coverage-rust.sh` |
| TypeScript coverage | `npm run test:ts` |

## Release CI (tagged)

| Step | Detail |
| --- | --- |
| Trigger | Push tag `v*` |
| Workflow | `.github/workflows/release.yml` |
| Binaries | `sentinelpass`, `sentinelpass-daemon`, `sentinelpass-host`, `sentinelpass-ui` |
| Install bundles | user-level installers for Windows/macOS/Linux |
| Native installers | NSIS/MSI (Windows), DMG/pkg (macOS), AppImage/DEB/RPM (Linux, runner dependent) |

## Browser Native Host Registration

The Tauri desktop app **auto-registers** native messaging host manifests for Chrome, Chromium, and Firefox on every launch. No manual registration is required for users who install via DMG/MSI/DEB/RPM and open the app.

For build-from-source workflows where you run only the CLI/daemon (without the UI), use the install script:

```bash
# macOS / Linux (source build)
./installation/install.sh

# macOS / Linux (installed app bundle)
./installation/install.sh --from-app-bundle

# Windows (source build)
./install.ps1
```

The Chrome extension uses a stable `key` in its manifest, producing a deterministic
extension ID (`nophfgfiiohedlodfeepjoioljbhggdd`) across all machines.

If Chrome reports native host permission errors, restart the browser after the UI has
launched at least once.


## Local DMG builds must stage daemon/host sidecars (WBS-905)

`cargo tauri build` alone bundles an EMPTY `resources/bin` — `tauri.conf.json`
declares `resources: ["src-tauri/resources/bin/*"]` and the bundler silently
tolerates the empty glob, producing a DMG whose app has no daemon or native
host (extension autofill and daemon-backed CLI access dead). The release
workflow stages the binaries and fails closed (`.github/workflows/release.yml`
"Stage daemon/host sidecars"). For a local DMG:

```bash
cargo build --release --bin sentinelpass-daemon --bin sentinelpass-host --bin sentinelpass
cp target/release/sentinelpass-daemon target/release/sentinelpass-host \
   sentinelpass-ui/src-tauri/resources/bin/
cd sentinelpass-ui && cargo tauri build   # then verify the sidecars inside the .app
```
