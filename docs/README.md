# SentinelPass Documentation Index

Quick reference to all project documentation. Most docs live at the repository root; this index serves as a table of contents.

## Project

| Document | Description | Keywords |
|----------|-------------|----------|
| [README.md](../README.md) | Project overview, installation, and quick start | install, setup, quick start, runtime, daemon |
| [BUILD.md](../BUILD.md) | Toolchain requirements, build commands, coverage gates | cargo, npm, build, coverage, toolchain, platform |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution workflow, quality gates, PR process | PR, commit, lint, clippy, fmt, test, branch |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards and expectations | conduct, community |
| [SUPPORT.md](../SUPPORT.md) | How to get help | help, support, issues |

## Security

| Document | Description | Keywords |
|----------|-------------|----------|
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting policy | CVE, vulnerability, disclosure, reporting |
| [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) | Cryptographic design, threat model, hardening | Argon2id, AES-256-GCM, key hierarchy, KDF, nonce, zeroize, IPC token, biometric, threat model |
| [docs/SECURITY_STATUS_MATRIX.md](./SECURITY_STATUS_MATRIX.md) | Code-linked status for implemented, partial, and planned security controls | security status, evidence, residual risk, biometric, IPC, relay, passkeys |

## Development

| Document | Description | Keywords |
|----------|-------------|----------|
| [CLAUDE.md](../CLAUDE.md) | Architecture reference, commands, protocols, coding style | architecture, IPC, native messaging, vault, crypto, TOTP, SSH, CLI, Tauri, daemon |
| [AGENTS.md](../AGENTS.md) | Multi-agent task delegation configuration | agents, delegation |
| [TECHNICAL_DEBT.md](../TECHNICAL_DEBT.md) | Verified issues tracker and roadmap | debt, migration, refinery, IPC token, constant-time |
| [ROADMAP.md](../ROADMAP.md) | Active gap-driven roadmap and phase plan | roadmap, milestones, security hardening, mobile, paid tier |

## Product and Planning

| Document | Description | Keywords |
|----------|-------------|----------|
| [docs/GAP_REVIEW_2026-05-08.md](./GAP_REVIEW_2026-05-08.md) | Current gap review and integration plan for developer secrets, passkeys, and biometrics | audit, victor, api keys, passkeys, biometric, typed credentials |
| [docs/GAP_REVIEW_2026-02-26.md](./GAP_REVIEW_2026-02-26.md) | Evidence-based gap audit across security, features, design, and implementation | audit, review, gaps, security posture |
| [docs/PRD.md](./PRD.md) | Product requirements document (vision, users, scope, metrics, tiers) | prd, vision, users, scope, metrics |
| [docs/REQUIREMENTS.md](./REQUIREMENTS.md) | Traceable functional/security/ops/commercial requirements | requirements, acceptance criteria, security requirements |
| [docs/SOLUTION_DESIGN.md](./SOLUTION_DESIGN.md) | Gap-closing architecture and trust-boundary design | design, trust boundary, ipc, relay, extension |
| [docs/IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | 90-day execution plan and workstreams | plan, implementation, sequencing, verification |
| [docs/OSS_COMMERCIAL_STRATEGY.md](./OSS_COMMERCIAL_STRATEGY.md) | Open-source/free/paid tier strategy and two-repo operating model | open source, paid tier, private repo, licensing |

## Subsystem Docs

| Document | Description | Keywords |
|----------|-------------|----------|
| [docs/OSS_RELEASE_CHECKLIST.md](./OSS_RELEASE_CHECKLIST.md) | Open-source release governance checklist | release, Apache-2.0, license, artifacts |
| [browser-extension/chrome/DEBUGGING.md](../browser-extension/chrome/DEBUGGING.md) | Chrome extension debugging guide | extension, DevTools, content script, background worker, autofill |
| [browser-extension/e2e/README.md](../browser-extension/e2e/README.md) | Browser integration test setup and usage | Playwright, e2e, extension test |
| [sentinelpass-ui/README.md](../sentinelpass-ui/README.md) | Tauri desktop UI build and architecture | Tauri, UI, TypeScript, app.ts, native host |
| [docs/SYNC.md](./SYNC.md) | Multi-device sync protocol, relay server, pairing, conflict resolution | sync, relay, Ed25519, pairing, HKDF, LWW, push, pull |

## Blog & Marketing

| Document | Description |
|----------|-------------|
| [blogs/](../blogs/) | Launch articles and technical infographics |

## Topic Quick-Reference

Looking for something specific? Use these pointers:

| Topic | Where to look |
|-------|---------------|
| **Vault CRUD** | [CLAUDE.md](../CLAUDE.md) § Architecture Overview, `sentinelpass-core/src/vault/` |
| **Crypto (KDF, cipher)** | [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md), `sentinelpass-core/src/crypto/` |
| **Security status evidence** | [docs/SECURITY_STATUS_MATRIX.md](./SECURITY_STATUS_MATRIX.md) |
| **IPC protocol** | [CLAUDE.md](../CLAUDE.md) § IPC, `sentinelpass-core/src/daemon/ipc.rs` |
| **Native messaging** | [CLAUDE.md](../CLAUDE.md) § Native Messaging Protocol, `sentinelpass-core/src/daemon/native_messaging.rs` |
| **Browser extension** | [DEBUGGING.md](../browser-extension/chrome/DEBUGGING.md), `browser-extension/chrome/` |
| **TOTP** | [CLAUDE.md](../CLAUDE.md) § Adding a New Native Message Type, `sentinelpass-core/src/totp.rs` |
| **SSH keys** | `sentinelpass-core/src/ssh.rs` (comprehensive Rust doc comments) |
| **Biometrics** | `sentinelpass-core/src/biometric.rs` (comprehensive Rust doc comments) |
| **Auto-lock** | `sentinelpass-core/src/daemon/autolock.rs` (comprehensive Rust doc comments) |
| **Database models** | `sentinelpass-core/src/database/models.rs`, `sentinelpass-core/src/database/schema.rs` |
| **Testing** | [CLAUDE.md](../CLAUDE.md) § Common Commands → Test, [BUILD.md](../BUILD.md) |
| **Release process** | [OSS_RELEASE_CHECKLIST.md](./OSS_RELEASE_CHECKLIST.md), `.github/workflows/release.yml` |
| **Sync protocol** | [docs/SYNC.md](./SYNC.md), `sentinelpass-core/src/sync/` |
| **Relay server** | [docs/SYNC.md](./SYNC.md) § Relay Server, `sentinelpass-relay/src/` |
| **Device pairing** | [docs/SYNC.md](./SYNC.md) § Sync Lifecycle → Pair, `sentinelpass-core/src/sync/pairing.rs` |
| **Conflict resolution** | [docs/SYNC.md](./SYNC.md) § Conflict Resolution, `sentinelpass-core/src/sync/conflict.rs` |
| **Rust API docs** | Run `cargo doc --no-deps --open` locally |
