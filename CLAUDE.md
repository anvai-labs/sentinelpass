# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Current Date:** 2026-05-09 (This context may or may not be relevant to your task)

## Project Overview

SentinelPass is a secure, local-first password manager written in Rust with a Tauri desktop UI, browser extensions (Chrome/Firefox), native messaging architecture, and optional E2E encrypted multi-device sync. The project uses zero-knowledge architecture with military-grade encryption (Argon2id KDF + AES-256-GCM).

## Development Environment

**Prerequisites:**
- Rust 1.70+
- Node.js 20+
- npm 10+

**Platform Dependencies:**
| Platform | Extra system packages |
| --- | --- |
| Windows | None (Tauri Windows toolchain is sufficient) |
| macOS | `brew install openssl` |
| Ubuntu/Debian | `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev build-essential` |

**Quick Start:**
```bash
# First time setup
npm install && npm run web:build
cargo build --release
```

## Common Commands

### Build
```bash
cargo build --workspace                          # Dev build (all crates)
cargo build --release                            # Release build
npm install && npm run web:build                 # Build web assets (required before Tauri UI)
cargo build --package sentinelpass-ui            # Build Tauri UI (needs web assets first)
cargo build --package sentinelpass-relay          # Build relay server
cargo build --features sync                      # Build with sync client enabled
```

### Test
```bash
cargo test --workspace                           # All Rust tests
cargo test --workspace -- --nocapture            # With stdout
cargo test --package sentinelpass-core crypto::tests  # Single test module
cargo test --workspace --test '*'                # Integration tests only
cargo test --workspace security                  # Security tests only
npm run test:ts                                  # TypeScript/Vitest tests
npm run test:ts:watch                            # TypeScript tests (watch mode)
bash scripts/coverage-rust.sh                    # Rust coverage (50% minimum)
```

### Extension E2E Testing
```bash
cd browser-extension/e2e
npm install
npm run test:e2e                                 # Run Playwright tests
npm run test:e2e:headed                          # Run with visible browser
```

### Security Audits
```bash
./scripts/security-audit.sh                      # Runs cargo-audit and npm audit
# Or use trivy if available:
trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --no-progress .
```

### Lint & Format
```bash
cargo fmt --all                                  # Format
cargo fmt --all -- --check                       # Check formatting
cargo clippy --workspace --all-targets -- -D warnings  # Lint
npm run web:typecheck                            # TypeScript typecheck
```

### Run
```bash
cargo run --bin sentinelpass -- [args]            # CLI (binary name: sentinelpass)
cargo run --bin sentinelpass-daemon               # Daemon (required for browser extension)
cargo run --bin sentinelpass-host                 # Native messaging host
cargo run --package sentinelpass-ui               # Tauri desktop UI
cargo run --bin sentinelpass-relay               # Relay server (default: 127.0.0.1:8743)
```

### Just shortcuts
```bash
just ci             # lint + test
just lint           # clippy + fmt-check
just test           # cargo test --workspace
just build          # cargo build --release
```

**Note:** The justfile references old binary names (`pm-cli`, `pm-daemon`). Use the `cargo run --bin` commands above for correct binary names.

## Architecture Overview

### Component Architecture

```
Browser Extension (Chrome/Firefox)
    ↓ Native Messaging (stdio JSON)
sentinelpass-host
    ↓ IPC (Unix socket / TCP)
sentinelpass-daemon
    ├── VaultManager (CRUD operations)
    ├── Crypto (Argon2id + AES-256-GCM)
    ├── Database (SQLite with encrypted entries)
    └── SyncEngine (optional, feature-gated)
            ↓ HTTPS + Ed25519 signed requests
         sentinelpass-relay
            └── SQLite (encrypted blobs only)
```

### Key Components

**sentinelpass-core/** - Core library (all other crates depend on this):
- `crypto/` - `kdf.rs` (Argon2id), `cipher.rs` (AES-256-GCM), `keyring.rs` (KeyHierarchy/MasterKey/WrappedKey), `password.rs` (generation), `strength.rs` (analysis), `zero.rs` (SecureBuffer/zeroization)
- `daemon/` - `ipc.rs` (IPC server/client), `vault_state.rs` (DaemonVault with auto-lock), `native_messaging.rs` (browser protocol), `autolock.rs`
- `database/` - `schema.rs` (SQLite ops), `models.rs` (Entry/DomainMapping/TotpSecret), `migrations.rs` (refinery runner)
- `vault.rs` - VaultManager: central CRUD, encryption, lock/unlock, TOTP, SSH keys, biometric, import/export
- `sync/` - `models.rs` (SyncEntryBlob/payloads), `crypto.rs` (encrypt/decrypt/pad), `auth.rs` (Ed25519 canonical signing), `device.rs` (DeviceIdentity), `pairing.rs` (HKDF pairing key), `conflict.rs` (LWW resolver), `change_tracker.rs` (pending collection), `config.rs` (SyncConfig), `client.rs` (HTTP client, feature-gated `sync`), `engine.rs` (push/pull orchestrator, feature-gated `sync`)
- `audit.rs`, `lockout.rs`, `biometric.rs`, `ssh.rs`, `totp.rs`, `import_export.rs`, `platform.rs`

**sentinelpass-daemon/** - Background service:
- Runs Tokio async runtime
- Manages DaemonVault with auto-lock (5 min default)
- IPC server: Unix socket on Linux/macOS, named pipes on Windows (with per-user ACLs and AES-256-GCM encryption)
- Handles native messaging requests from browser

**sentinelpass-host/** - Native messaging bridge:
- stdin/stdout JSON protocol (length-prefixed)
- Translates between browser extension and daemon
- The Tauri UI auto-registers native messaging host manifests for Chrome, Chromium, and Firefox on every launch
- For manual CLI/daemon-only workflows, use `./installation/install.sh` (Unix) or `.\install.ps1` (Windows)
- Chrome extension has stable extension ID: `nophfgfiiohedlodfeepjoioljbhggdd` (derived from manifest key)

**sentinelpass-cli/** - Command-line interface (binary: `sentinelpass`):
- Clap-based CLI with subcommands
- Commands: init, add, list, search, edit, delete, generate, totp-add/code/remove, ssh-key-add/list/get/delete, export, import, check, biometric-enable/disable
- Sync subcommands: sync init/now/status/device-list/device-revoke/pair-start/pair-join/disable

**sentinelpass-ui/** - Tauri v2 desktop application (binary: `sentinelpass-ui`):
- `src-tauri/src/main.rs` - Tauri backend with Rust commands
- `src-tauri/capabilities/default.json` - Tauri v2 capability-based ACL for plugin permissions
- `app.ts` / `app.js` - TypeScript source and transpiled frontend
- `index.html` - UI markup
- Requires `npm run web:build` before `cargo build`

**browser-extension/** - Chrome & Firefox extensions:
- `chrome/` - MV3 manifest, TypeScript sources (`.ts`) with transpiled JS
- `firefox/` - MV2 manifest (shares content/background scripts)
- `e2e/` - Playwright E2E tests

**sentinelpass-relay/** - Sync relay server:
- Axum-based HTTP server storing encrypted sync blobs
- Ed25519 auth middleware (signature verification, nonce dedup, device revocation)
- Handlers: device registration, push/pull sync, pairing bootstrap
- Config via `relay.toml` (TOML); SQLite storage (`relay.db`)

## Communication Protocols

### Native Messaging Protocol

**Message Format:** Length-prefixed JSON
```
[4 bytes: message length as little-endian u32][JSON payload]
```

**Request Types:**
- `get_credential` - Retrieve credentials for domain
- `save_credential` - Save new credentials
- `check_credential_exists` - Check if credential exists
- `check_vault_status` - Check if vault is unlocked
- `get_totp_code` - Retrieve TOTP code for domain
- `lock_vault` - Lock the vault

**Response Structure:**
```json
{
  "version": 1,
  "type": "credential_response",
  "request_id": "uuid",
  "success": true,
  "data": { "username": "...", "password": "...", "title": "..." },
  "error": null
}
```

### IPC (Inter-Process Communication)

**Unix (Linux/macOS):** Unix domain socket at `/tmp/sentinelpass.sock` (or `$XDG_RUNTIME_DIR/sentinelpass.sock`)
**Windows:** Named pipes at `\\.\pipe\SentinelPass-<username>` (per-user ACLs + AES-256-GCM encryption)
**Legacy TCP:** Custom `tcp://...` paths use loopback TCP with AES-256-GCM encryption
**Auth:** All IPC requests require a 32-byte hex token from `~/.config/sentinelpass/ipc.token` (mode 0600). Messages use length-prefixed JSON with an envelope containing the token.

### Sync Protocol

**Auth Header:**
```
Authorization: SentinelPass-Ed25519 {device_id}:{timestamp}:{nonce}:{base64(signature)}
```

Signature covers the canonical string: `{METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256(BODY)}`

**Push (incremental):**
```json
POST /api/v1/sync/push
{
  "device_sequence": 42,
  "entries": [
    {
      "sync_id": "uuid",
      "entry_type": "credential",
      "sync_version": 3,
      "modified_at": 1700000000,
      "encrypted_payload": "<base64(nonce || ciphertext || tag)>",
      "is_tombstone": false,
      "origin_device_id": "uuid"
    }
  ]
}
```

**Pull (incremental):**
```json
POST /api/v1/sync/pull
{ "since_sequence": 100, "limit": 1000 }
→ { "entries": [...], "server_sequence": 142, "has_more": false }
```

See `docs/SYNC.md` for the full endpoint table, pairing flow, and conflict resolution rules.

## Cryptographic Architecture

### Key Derivation
- Algorithm: Argon2id
- Memory: 256 MB (m=262,144 blocks)
- Iterations: 3 (t=3)
- Parallelism: 4 lanes (p=4)
- Salt: 16 random bytes
- Output: 32-byte master key

### Encryption
- Algorithm: AES-256-GCM
- Per-entry unique nonces (96-bit)
- Authentication tag: 128-bit
- No nonce reuse (critical for security)

### Key Hierarchy
```
Master Password
  ↓ Argon2id
Master Key (32 bytes)
  ↓
┌──────────────┬──────────────┬──────────────┐
│  Vault Key  │  HMAC Key   │  Biometric  │
│  (wrapped)  │  (derived)  │   Wrapper   │
└──────────────┴──────────────┴──────────────┘
  ↓
Data Encryption Key (DEK)
  ├── Per-entry AES-256-GCM encryption (local)
  └── Sync payload AES-256-GCM encryption (per-blob nonce, padded)

Ed25519 keypair (per device, stored encrypted with DEK)
  └── Request signing (canonical string → signature)

Pairing: 6-digit code + salt → HKDF-SHA256 → pairing key
  └── AES-256-GCM encrypt VaultBootstrap (kdf_params, wrapped_dek, relay_url)
```

## Security-Critical Development Rules

### NEVER:
1. **Log secrets** - Use redacted logging for sensitive data
2. **Use `String` for passwords** - Always use `SecureBuffer` from `crypto/keyring.rs`
3. **Compare passwords with `==`** - Use constant-time compare from `subtle` crate
4. **Reuse nonces** - Always generate random per-entry nonce
5. **Skip authentication tag validation** - GCM tag is mandatory
6. **Write plaintext to disk** - Even for debugging
7. **Trust domain from browser** - Validate daemon-side with TLD matching
8. **Return full vault to extension** - Only return requested credential
9. **Store plaintext on the relay** - Relay must only see encrypted blobs
10. **Accept a sync entry without Ed25519 verification** - Always verify device signature
11. **Reuse the DEK as a signing key** - Device identity uses a separate Ed25519 keypair
12. **Accept a lower sync_version** - Sequence must be monotonically increasing (rollback protection)

### ALWAYS:
1. Use parameterized queries only (SQL injection protection)
2. Call `zeroize()` on secrets before dropping
3. Use `mlock()` via `memsec` crate to prevent swap
4. Validate domain on daemon-side, not browser-side
5. Use exponential backoff for failed auth attempts
6. Implement constant-time operations for secret comparison
7. Run `cargo clippy` and `cargo test` before committing
8. Pad sync payloads to fixed bucket sizes before encryption (metadata leakage prevention)
9. Verify auth nonce uniqueness on the relay (replay protection)
10. Include body hash in the canonical signing string (tamper protection)

## Testing Browser Extension

### Debugging Content Script
1. Open DevTools (F12) → Console tab
2. Filter for `[SentinelPass]` logs
3. Look for: `[SentinelPass] Content script loaded`
4. Check password field detection logs

### Debugging Background Worker
1. Navigate to `chrome://extensions/`
2. Find "SentinelPass" extension
3. Click "Service worker" link
4. Look for `[SentinelPass Background]` logs

### Manual Testing Checklist
- [ ] Content script loads on page
- [ ] Password fields detected (check console count)
- [ ] Autofill button appears next to password fields
- [ ] Save prompt appears after registration form submission
- [ ] Credentials saved to vault (verify via CLI)
- [ ] Background script communicates with native host

See `browser-extension/chrome/DEBUGGING.md` for detailed debugging guide.

## Debugging

### Daemon Logs
- **Unix (Linux/macOS):** Check syslog: `log stream --predicate 'process == "sentinelpass-daemon"'` (macOS) or `journalctl -f` (Linux)
- **Windows:** Event Viewer → Windows Logs → Application

### Extension Issues
- Open DevTools (F12) → Console tab
- Filter for `[SentinelPass]` logs for content script
- Navigate to `chrome://extensions/` → Service worker for background script logs

### Native Host Registration
The Tauri UI auto-registers native messaging host manifests on launch. For manual registration:
```bash
# macOS / Linux — from installed app bundle
./installation/install.sh --from-app-bundle

# macOS / Linux — from source build
./installation/install.sh

# Windows (PowerShell)
.\installation\install.ps1
```

## Platform-Specific Notes

### Windows
- Build from native Windows (not WSL) for proper executable
- Registry paths for native messaging:
  - Chrome: `HKCU\Software\Google\Chrome\NativeMessagingHosts\`
  - Firefox: `HKCU\Software\Mozilla\NativeMessagingHosts\`
- IPC uses named pipes with per-user ACLs (`\\.\pipe\SentinelPass-<username>`)
- Transport encryption: AES-256-GCM (defense-in-depth)
- Legacy TCP fallback: Custom `tcp://...` paths still use loopback TCP with AES-256-GCM

### macOS
- OS keystore: Keychain for biometric wrapper
- IPC uses Unix domain sockets
- Native messaging: `~/Library/Application Support/Mozilla/NativeMessagingHosts/`

### Linux
- Install GTK development libraries for Tauri UI
- IPC uses Unix domain sockets
- Native messaging: `~/.config/mozilla/native-messaging-hosts/`

### Tauri v2 Plugin Permissions

Tauri v2 uses a capability-based ACL. Every plugin command must be:
1. Initialized in `src-tauri/src/main.rs` via `.plugin(tauri_plugin_*::init())`
2. Granted in `src-tauri/capabilities/default.json`

Current plugins: clipboard-manager, shell, dialog. See `src-tauri/capabilities/default.json` for the full permission list.

## Common Development Workflows

### Adding a New Credential Field
1. Update `database/schema.rs` (add column to table)
2. Create migration in `migrations/` folder
3. Update `database/models.rs` (struct field)
4. Update `native_messaging.rs` (request/response serialization)
5. Update extension `background.js` and `content.js`
6. Update Tauri UI `app.js` and `index.html`

### Adding a New Native Message Type
1. Add message type constant to `daemon/native_messaging.rs`
2. Create request/response structs with serde
3. Add handler in `NativeMessagingHost::handle_message()`
4. Update extension `background.js` to send new message type
5. Add documentation to CLAUDE.md and DEBUGGING.md

### Testing Database Changes
```bash
# Initialize dev database
cargo run --bin sentinelpass -- init --dev

# Run migrations
cargo run --bin sentinelpass-daemon  # Daemon auto-runs migrations

# Verify schema
sqlite3 ~/.sentinelpass/vault.db ".schema"
```

### Adding a New Sync Entry Type
1. Add variant to `SyncEntryType` in `sync/models.rs`
2. Create payload struct (e.g. `NewTypePayload`) with serde derives
3. Add `collect_pending_*_blobs()` in `sync/change_tracker.rs`
4. Add apply logic in `sync/engine.rs` `pull_changes()` match arm
5. Add sync columns (`sync_id`, `sync_version`, `sync_state`, `last_synced_at`) to the backing table
6. Update `count_pending_changes()` to include the new table

## Important File Locations

- **Vault database:** `~/.sentinelpass/vault.db` (SQLite, encrypted entries)
- **IPC token:** `~/.config/sentinelpass/ipc.token` (32-byte hex token for IPC auth)
- **Daemon logs:** Platform-specific (Windows: Event Viewer, Unix: syslog)
- **Native messaging config:**
  - Windows: `C:\Program Files\PasswordManager\com.passwordmanager.host.json`
  - macOS/Linux: `~/.config/mozilla/native-messaging-hosts/`
- **Sync metadata:** `sync_metadata` table in `vault.db` (device identity, config, sequences)
- **Relay database:** `relay.db` (SQLite, encrypted blobs only)
- **Relay config:** `relay.toml` (server settings)

## Known Limitations

1. Single-user vault (multi-user schema exists but not implemented)
2. TOTP is available in core + CLI; browser/UI setup flows are still maturing
3. SSH key storage and CLI management are implemented; advanced SSH workflows (UI, richer key lifecycle ops) remain limited
4. KeePass XML import/export is implemented in core + CLI; KDBX (encrypted) format is not yet supported
5. Biometric unlock is integrated with Windows Hello and macOS LocalAuthentication (Touch ID); Linux remains unsupported
6. Multi-device sync is feature-gated (`sync`); relay server does not include TLS by default (use a reverse proxy for production)
7. Sync conflict resolution is Last-Write-Wins only; no manual merge UI

## CI/CD Pipeline

The project uses GitHub Actions (`.github/workflows/rust.yml`) with 6 jobs:
- **format** - `cargo fmt --all -- --check`
- **clippy** - `cargo clippy --workspace --all-targets -- -D warnings`
- **test** - `cargo test --workspace --verbose` (matrix: ubuntu/windows/macos)
- **coverage** - Rust LLVM coverage with 50% minimum threshold
- **web_tdd** - TypeScript typecheck + Vitest tests with coverage
- **build** - `cargo build --release --workspace` (matrix: ubuntu/windows/macos)

Additional workflows: `release.yml` (tagged builds), `security.yml` (cargo audit), `extension-e2e.yml`, `release-preflight.yml`.

All checks must pass before merging to main branch.

## Git Workflow

- **Main branch:** `main` (protected, requires CI + review)
- **Development branch:** `develop`
- **Commit format:** `type(scope): imperative summary` (e.g., `fix(daemon): gate save path when vault is locked`)
- **Branch protection:** CI required, 1 approval, no force pushes
- **Pre-commit hook:** `.githooks/pre-commit` runs lint + test scripts for changed Rust/TS files. Configure with `git config core.hooksPath .githooks`

See `CONTRIBUTING.md` for the full contribution workflow and pull request checklist.

## Coding Style

- Rust 2021, 4-space indent, `rustfmt`-clean. Extension JS/TS uses 2-space indent.
- `snake_case` for files/modules/functions, `CamelCase` for structs/enums/traits, `SCREAMING_SNAKE_CASE` for constants.
- Tests are inline `#[cfg(test)]` modules. Use descriptive behavior-focused names (e.g. `locks_after_failed_attempts`).
- Prefer `Result` over panics in production paths.

## Dependencies Note

## Adding Dependencies

The workspace uses centralized dependency management in `Cargo.toml` [workspace.dependencies]. When adding new dependencies, prefer:
- Adding to workspace dependencies if used by multiple crates
- Using workspace version (`{ workspace = true }`) in crate Cargo.toml
- Run `cargo update` after adding dependencies

## Security-Sensitive Areas

Changes touching these paths need extra care and explicit reasoning (see `CONTRIBUTING.md`):
- `sentinelpass-core/src/crypto/`
- `sentinelpass-core/src/vault.rs`
- `sentinelpass-core/src/daemon/`
- `sentinelpass-host/`
- `browser-extension/`

Read `SECURITY.md` and `SECURITY_ARCHITECTURE.md` before submitting security-critical changes.
Check `TECHNICAL_DEBT.md` for known issues and verified technical debt before duplicating effort.
