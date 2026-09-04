# SentinelPass

Local-first password manager with a Rust core, Tauri desktop UI, and browser extension.

## At a Glance

| Area | What SentinelPass does |
| --- | --- |
| Secret model | Zero-knowledge, local vault; no cloud dependency |
| Crypto | Argon2id key derivation + AES-256-GCM encryption |
| Credential registry | Group credentials by logical entity; reuse clusters and rotation posture in CLI + desktop UI |
| Master password rotation | Re-wraps the data key in place — entries are never re-encrypted |
| Multi-device sync | Optional E2E encrypted sync via relay (Ed25519 auth, LWW conflict resolution) |
| App surfaces | CLI (`sentinelpass`), daemon, desktop UI, browser extension, relay server |
| Platforms | Windows, macOS, Linux |
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
| macOS | `brew tap anvai-labs/tap https://github.com/anvai-labs/homebrew-tap && brew install anvai-labs/tap/sentinelpass` — or download the DMG from [Releases](../../releases) |
| Windows | Download the MSI installer from [Releases](../../releases) and run it |
| Linux (Debian/Ubuntu) | `sudo apt install ./sentinelpass_<VERSION>_amd64.deb` — or `sudo dpkg -i sentinelpass-*.deb` |
| Linux (Fedora/RHEL) | `sudo dnf install sentinelpass-*.rpm` |
| Build from source | `npm install && npm run web:build && cargo build --release` |

> **Tip:** GitHub release links use 302 redirects — use `curl -L -O <url>` when downloading from the command line.

## First Launch

1. Open **SentinelPass** from your Applications folder / Start Menu / launcher.
2. Create a new vault and set a master password.
3. The app automatically starts the background daemon and registers the native messaging host for Chrome, Chromium, and Firefox.

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
| Chrome | `chrome://extensions/` → enable **Developer mode** → **Load unpacked** → select `browser-extension/chrome/` |
| Firefox | `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → select `browser-extension/firefox/manifest.json` |

After installing the extension, **restart the browser** so it picks up the native messaging host manifest written by the app.

## Multi-Device Sync

Sync your vault across devices using the E2E encrypted relay. The relay never sees plaintext.

1. **Start the relay** (self-hosted): `cargo run --bin sentinelpass-relay`
2. **Initialize sync** on the first device: `sentinelpass sync init --relay-url http://localhost:8743`
3. **Pair additional devices**: run `sentinelpass sync pair-start` on device A, then `sentinelpass sync pair-join --relay-url <URL> --code <CODE>` on device B.

See [`docs/SYNC.md`](docs/SYNC.md) for the full protocol reference, CLI commands, and relay configuration.

## Verify

1. Visit any login page — an autofill icon should appear next to password fields.
2. If not, check the Troubleshooting section below.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "Specified native messaging host not found" | Restart the browser after launching SentinelPass at least once |
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
