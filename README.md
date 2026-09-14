# SentinelPass

Local-first password manager with a Rust core, Tauri desktop UI, and browser extension.

## At a Glance

| Area | What SentinelPass does |
| --- | --- |
| Secret model | Zero-knowledge, local vault; no cloud dependency |
| Crypto | Argon2id key derivation + AES-256-GCM encryption |
| Credential registry | Group credentials by logical entity; reuse clusters and rotation posture in CLI + desktop UI |
| Master password rotation | Re-wraps the data key in place — entries are never re-encrypted |
| Forgotten-password recovery | **Not available** — the master password cannot be recovered or reset; a forgotten password means the vault is lost (recovery key slots are in design, see ADR-004) |
| Multi-device sync | **Experimental** — opt-in, disabled by default, not approved for production credentials; v1 will be superseded by sync v2 (ADR-006) |
| App surfaces | CLI (`sentinelpass`), daemon, desktop UI, browser extension, relay server |
| Platforms | Windows, macOS, Linux (Android/iOS clients are unreleased prototypes) |
| License | Apache License 2.0 |

## System Map

| Component | Path | Responsibility |
| --- | --- | --- |
| Core library | `sentinelpass-core/` | Crypto, vault, DB, IPC contracts |
| CLI | `sentinelpass-cli/` | Vault operations from terminal |
| Daemon | `sentinelpass-daemon/` | Background unlock/lock state + IPC |
| Native host | `sentinelpass-host/` | Browser native messaging bridge |
| Desktop app | `sentinelpass-ui/` | Tauri UI and user unlock workflow |
| Browser extension | `browser-extension/` | Autofill + save prompts |
| Relay server | `sentinelpass-relay/` | E2E encrypted sync relay (zero-knowledge) |

## Runtime Flow

```text
Browser Extension -> sentinelpass-host -> sentinelpass-daemon -> sentinelpass-core (vault)
                         ^                      |
                         |                      └── SyncEngine (optional)
                    sentinelpass-ui                    |
                    (unlock + state)             sentinelpass-relay
                                                 (encrypted blobs only)
```

## Install

| Platform | Method |
| --- | --- |
| macOS desktop | Follow the [DMG installation guide](docs/MACOS_INSTALL.md) to verify the download, install in Applications, and check the current signing limitation |
| Homebrew (macOS Apple Silicon / Linux x86_64) | Follow the [Homebrew install and upgrade guide](docs/HOMEBREW.md); the current macOS formula omits the daemon and does not install an Applications-folder app |
| Windows | Download the MSI installer from [Releases](https://github.com/anvai-labs/sentinelpass/releases/latest) and run it |
| Linux (Debian/Ubuntu) | `sudo apt install ./sentinelpass_<VERSION>_amd64.deb` — or `sudo dpkg -i sentinelpass-*.deb` |
| Linux (Fedora/RHEL) | `sudo dnf install sentinelpass-*.rpm` |
| Build from source | `npm install && npm run web:build && cargo build --release` |

> **Tip:** GitHub release links use 302 redirects — use `curl -L -O <url>` when downloading from the command line.

## First Launch

1. **Native installer:** open **SentinelPass** from Applications / Start Menu / launcher. **Homebrew formula:** run `sentinelpass-ui` in Terminal; it stays in the foreground while the window is open. See the [macOS formula limitation](docs/HOMEBREW.md#current-formula-limitations) before using browser autofill.
2. Create a vault and set a master password, or unlock your existing vault.
3. With the daemon and host installed, the app starts or connects to the daemon and registers the native messaging host for Chrome, Chromium, and Firefox. Keep the app open while using browser autofill.

You do not need to launch `sentinelpass-host` manually. Browsers start it when the extension connects. The current formula does not support `brew services`; see [service management](docs/HOMEBREW.md#background-services).

## Secrets Broker for Local Tools

SentinelPass doubles as a least-privilege secrets broker for developer tools
(AI agents, proxies, scripts). Tools authenticate with a per-client token and
may only touch exactly the `client × domain × field` scopes you granted:

```bash
# Grant and receive a client token (shown once)
sentinelpass secret allow --client-id victor --domain anthropic --field password
export SENTINELPASS_CLIENT_TOKEN=spt_...   # from the grant output

# Fetch one field (allowlist + token enforced, audited)
sentinelpass secret get --client-id victor --domain anthropic --field password

# Or serve secrets as env vars to a child process
sentinelpass exec --client-id victor \
  --env ANTHROPIC_API_KEY=anthropic --env OPENAI_API_KEY=openai -- victor chat

# Inspect and revoke
sentinelpass secret list
sentinelpass secret audit --client-id victor
sentinelpass secret token revoke --client-id victor   # fail-closed
```

See `SECURITY_ARCHITECTURE.md` (Secrets Broker section) for the threat model.

## Credential Registry and Rotation Posture

Credentials that belong to the same logical system — a broker, a database, an
API, a webhook — can be grouped under a registered **entity**. The registry
uses that grouping (plus reuse detection across the whole vault, per-entity
criticality, and provider-managed expiries) to answer a question plain
age-based policies can't: *which credentials actually need rotation now?*

```bash
# Register an entity and attach credentials to it
sentinelpass registry entity-add trading-postgres --kind database --criticality high
sentinelpass registry assign 42 --entity trading-postgres --label prod

# Posture summary without decryption; report adds strength analysis
sentinelpass registry status
sentinelpass registry report --only-issues

# Record that a provider-issued key was rotated (resets its age)
sentinelpass registry mark-rotated 42
```

The desktop UI shows the same posture: a header badge counts the entries with
findings, and the registry panel ranks reused/weak/overdue credentials
worst-first with the exact reason for each finding. Reuse clusters expand to
show which other entries share the secret. The panel is read-only — entity
management stays in the CLI for now.

Rotating a provider-issued secret is separate from rotating the vault's own
master password (`sentinelpass passwd`), which re-wraps the data key without
touching any stored entries. Both are covered by
[ADR-001](docs/decisions/adr/ADR-001-credential-registry-by-logical-entity.md)
and [ADR-002](docs/decisions/adr/ADR-002-master-password-rotation.md).

## Browser Extension

| Browser | Steps |
| --- | --- |
| Chrome | Follow the [release archive / stable-folder instructions](docs/MACOS_INSTALL.md#chrome-extension-from-the-release-archive), or load `browser-extension/chrome/` from a source checkout using `chrome://extensions/` → **Developer mode** → **Load unpacked** |
| Firefox | `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → select `browser-extension/firefox/manifest.json` |

After installing the extension, open its popup with SentinelPass running and unlocked. If it shows **Unlocked**, the native connection works and no browser restart is needed. If it does not connect, follow the [connection troubleshooting steps](docs/MACOS_INSTALL.md#chrome-extension-from-the-release-archive); a full browser restart is a fallback after reloading the extension.

## Multi-Device Sync (Experimental)

> **Not approved for production credentials.** Sync is opt-in, disabled by default, and
> labeled experimental: v1 has known protocol gaps (aggregate acknowledgements,
> unauthenticated metadata, six-digit bootstrap) that a v2 replacement will address
> (ADR-006). The relay never sees plaintext payloads.

1. **Start the relay** (self-hosted): `cargo run --bin sentinelpass-relay`
2. **Initialize sync** on the first device: `sentinelpass sync init --relay-url http://localhost:8743`
   — cleartext HTTP is accepted only for loopback development and requires
   `SENTINELPASS_ALLOW_LOOPBACK_RELAY=1`; non-loopback relays must use HTTPS.
3. **Pair additional devices**: run `sentinelpass sync pair-start` on device A, then `sentinelpass sync pair-join --relay-url <URL> --code <CODE>` on device B.

See [`docs/SYNC.md`](docs/SYNC.md) for the full protocol reference, CLI commands, and relay configuration.

## Verify

1. Visit any login page — an autofill icon should appear next to password fields.
2. If not, check the Troubleshooting section below.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Homebrew install/upgrade, `brew services` errors, or no UI window | Follow the [Homebrew troubleshooting guide](docs/HOMEBREW.md#troubleshooting) |
| macOS blocks the DMG app, an older app opens, or unlock reports permissive vault permissions | Follow the [macOS install and upgrade guide](docs/MACOS_INSTALL.md) |
| "Specified native messaging host not found" | Launch SentinelPass to register the host, reload the extension, and reopen its popup; restart the browser if the error persists |
| Autofill icon doesn't appear | Ensure the daemon is running (check SentinelPass UI status) |
| "Vault is locked" | Unlock the vault in the SentinelPass UI first |
| Extension installed but not working | Open DevTools → Console → filter for `[SentinelPass]` logs |

You can also re-register the native host manually:

```bash
# macOS / Linux — from installed app bundle
./installation/install.sh --from-app-bundle

# macOS / Linux — from source build
./installation/install.sh
```

## Developer Loop

| Task | Command |
| --- | --- |
| Rust format check | `cargo fmt --all -- --check` |
| Rust lint (deny warnings) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| TypeScript typecheck | `npm run web:typecheck` |
| TypeScript tests + coverage | `npm run test:ts` |
| Relay server | `cargo run --bin sentinelpass-relay` |
| Rust coverage (LLVM) | `bash scripts/coverage-rust.sh` |

## Release Artifacts

| Trigger | Workflow | Output |
| --- | --- | --- |
| Git tag `v*` | `Release CI` | cross-platform binaries + installer bundles |
| Push / PR | `Rust CI`, `Security CI`, `extension-e2e` | lint, tests, security scans, extension e2e |

## OSS and Contribution Docs

| Topic | File |
| --- | --- |
| Contribution process | `CONTRIBUTING.md` |
| Security reporting | `SECURITY.md` |
| Code of conduct | `CODE_OF_CONDUCT.md` |
| OSS release checklist | `docs/OSS_RELEASE_CHECKLIST.md` |
| Build details | `BUILD.md` |
| Sync protocol & relay | `docs/SYNC.md` |
| Security internals | `SECURITY_ARCHITECTURE.md` |
| Architecture decisions (ADRs) | `docs/decisions/adr/README.md` |
| Roadmap | `ROADMAP.md` |
