# sentinelpass-ui

Tauri v2 desktop application for SentinelPass. Provides a native GUI for vault management, credential storage, TOTP codes, and browser extension integration.

## Prerequisites

- **Rust** toolchain (stable, 2021 edition)
- **Node.js** 20+ and npm
- **Platform libraries** (Linux only): GTK development libraries for Tauri — see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

## Build

Web assets must be built before the Tauri binary:

```bash
# From the repository root
npm install
npm run web:build

# Then build the UI crate
cargo build --package sentinelpass-ui
```

For a release build:

```bash
cargo build --package sentinelpass-ui --release
```

## Run

```bash
cargo run --package sentinelpass-ui
```

On first launch the app automatically registers the native messaging host for Chrome, Chromium, and Firefox so the browser extension can communicate with the daemon.

## Architecture

```
index.html            Frontend markup
app.ts → app.js       App bootstrap and event wiring (TypeScript source, transpiled JS)
state.ts              Shared state, DOM references, Tauri invoke/clipboard bridge
credential-types.ts   Credential type model (password, API key, passkey reference)
entries.ts            Entry list rendering and CRUD
registry.ts           Credential registry posture dashboard (ADR-001)
totp.ts               TOTP code display and availability
utils.ts              Toasts, clipboard, HTML escaping, date formatting
url-utils.ts          URL/domain helpers
styles.css            Styles
src-tauri/
  src/main.rs         Tauri backend — Rust commands, native host registration
  resources/bin/      Bundled binaries (daemon, host)
tauri.conf.json       Tauri configuration (window, CSP, bundle settings)
```

The frontend calls Tauri commands defined in `src-tauri/src/main.rs`, which delegate to `sentinelpass-core` for all cryptographic and vault operations.

## Further Reading

- [Project README](../README.md) — overview, installation, quick start
- [CLAUDE.md](../CLAUDE.md) — full architecture reference and development guide
- [BUILD.md](../BUILD.md) — toolchain requirements and build commands
