# Technical Debt & Roadmap

Last updated: 2026-09-03 (v0.8.1)

---

## DeepSeek Analysis Verification (Feb 2026)

An external codebase analysis was performed by DeepSeek and independently verified against the actual source code. Results below.

### Verified Claims Summary

| # | Claim | Verdict | Severity | Category |
|---|-------|---------|----------|----------|
| 1 | Incomplete zeroization in error paths (vault.rs:164) | **FALSE** | N/A | Security |
| 2 | Mixed error types with inconsistent propagation | **PARTIALLY TRUE** | Low | Code Quality |
| 3 | Simple token auth without encryption on IPC | **TRUE** | Low (Unix) / Medium (Windows TCP) | Security |
| 4 | No version tracking in migrations | **TRUE** | Medium | Technical Debt |
| 5 | vault.rs is 1,764 lines (violates SRP) | **TRUE** | Low | Code Quality |
| 6 | Minimal testing for security-critical code | **PARTIALLY TRUE** | Medium | Testing |
| 7 | Browser extension has incomplete preview features | **TRUE** | Low | Feature Gap |
| 8 | vault.rs lacks function-level docs | **FALSE** | N/A | Docs |
| 9 | Global variables in UI state management | **TRUE** | Low | Code Quality |
| 10 | No clipboard auto-clear in UI | **FALSE** | N/A | Security |
| 11 | No database indexes | **FALSE** | N/A | Performance |
| 12 | Entire vault decrypted when listing | **PARTIALLY TRUE** | Low | Security |

### Detailed Findings

#### Claim 1: Incomplete zeroization in error paths -- FALSE

vault.rs:164 uses a **deferred error check pattern**: the result of `unlock_vault()` is captured into a variable, `master_password.zeroize()` runs unconditionally, and only then the result is checked with `?`. This is deliberately correct. Functions accepting `master_password: &[u8]` (borrowed) correctly leave zeroization to the caller per Rust ownership semantics.

#### Claim 2: Mixed error types -- PARTIALLY TRUE (resolved in v0.3.0)

The dual hierarchy (`CryptoError` + `PasswordManagerError`) with `#[from]` conversion is standard. The real issue: `schema.rs` returns `crypto::Result<T>` and maps database errors to `CryptoError::EncryptionFailed`, which is semantically misleading. `PasswordManagerError::Database(String)` is a catch-all that loses type information.

**Resolved**: `schema.rs` error types fixed in v0.2.0. `PasswordManagerError::Database(String)` replaced with `PasswordManagerError::Database(DatabaseError)` in v0.3.0, where `DatabaseError` has 8 structured variants: `Sqlite`, `Serialization`, `LockPoisoned`, `Ipc`, `FileIo`, `Keyring`, `SchemaMismatch`, `Other`.

#### Claim 3: IPC token auth without encryption -- TRUE

IPC uses plaintext JSON over Unix sockets (macOS/Linux) or TCP localhost (Windows). Token comparison uses `!=` (not constant-time). The master password is sent in cleartext in `IpcMessage::UnlockVault`. For Unix sockets this is low risk (protected by filesystem permissions). For Windows TCP `127.0.0.1:35873`, any local process can sniff traffic.

**Action items**:
- Use `subtle::ConstantTimeEq` for token comparison (follows project's own CLAUDE.md security rules)
- Consider TLS or message-level encryption for Windows TCP path

#### Claim 4: No version tracking in migrations -- TRUE

`MigrationManager::run_migrations()` is an empty stub. Refinery is declared as a dependency but never invoked (zero references in Rust code). Schema initialization uses `CREATE TABLE IF NOT EXISTS` in `schema.rs`, which is idempotent but cannot alter existing tables. The `db_metadata.version` column is hardcoded to `1` and never read back.

**Action items**:
- Wire up refinery for real migration tracking, or remove the dependency
- Implement version check on vault open to detect schema mismatches
- Critical before any schema changes are needed

#### Claim 5: vault.rs is 1,763 lines -- TRUE (resolved in v0.3.0)

Contains vault CRUD, biometric auth, TOTP management, SSH key management, metadata storage, and tests in a single file. This is a deliberate facade pattern but will become harder to maintain.

**Resolved**: Extracted into `vault/` directory module in v0.3.0: `mod.rs` (~700 lines, core CRUD + metadata), `biometric_ops.rs` (~160 lines), `totp_ops.rs` (~245 lines), `ssh_ops.rs` (~290 lines), `tests.rs` (~340 lines). 58% reduction in `mod.rs`.

#### Claim 6: Minimal testing -- PARTIALLY TRUE

99 `#[test]` functions across 17 files (40 in crypto alone) is not "minimal." Crypto tests cover fundamentals (roundtrip, wrong key, tampering, nonce uniqueness). However:
- `proptest` is a declared dev-dependency but unused (zero `proptest!` macro invocations)
- No fuzzing tests for crypto functions
- No timing side-channel tests
- Only 2 web test files (save-heuristics, url-utils)

**Action items**:
- Add property-based tests using proptest for crypto and vault operations
- Add integration tests for IPC auth flow
- Add browser extension integration tests beyond E2E

#### Claim 7: Browser extension preview features -- TRUE

`popup.ts` disables search, "Add Credential" (rendered as "Coming Soon"), and settings with the message "This feature is not available in the current preview build."

**Action item**: Tracked in roadmap -- browser extension polish (form detection, inline TOTP, settings UI).

#### Claim 8: vault.rs lacks function-level docs -- FALSE

Every public function in vault.rs has a `///` doc comment. The docs are brief one-liners compared to cipher.rs's rich `# Arguments` / `# Returns` / `# Security` sections, but they exist.

#### Claim 9: Global variables in UI state -- TRUE

`app.ts` lines 18-25 have 8 module-level `let` variables with no encapsulation. Functional for a single-page Tauri app but will become harder to manage as the UI grows.

**Action item**: Low priority. Consider a simple state management pattern if the UI grows significantly.

#### Claim 10: No clipboard auto-clear -- FALSE

`app.ts` lines 951-976 implement 30-second auto-clear with clipboard content verification before clearing. The browser extension popup does NOT have auto-clear (only the Tauri desktop UI does).

**Action item**: Add clipboard auto-clear to browser extension popup.

#### Claim 11: No database indexes -- FALSE

`schema.rs` (programmatic path) does not create indexes, but `migrations/v1_initial.sql` defines 5 indexes on `vault_id`, `favorite`, `entry_id`, and `domain`. Whether indexes are applied depends on which code path initializes the database.

**Action item**: Add `CREATE INDEX IF NOT EXISTS` statements to `schema.rs::initialize_schema()` so both code paths create indexes.

#### Claim 12: Entire vault decrypted when listing -- PARTIALLY TRUE

`list_entries()` fetches all entries and decrypts title + username for each. Passwords, URLs, and notes are NOT fetched or decrypted. Returns `EntrySummary` (not `Entry`). No pagination.

**Action item**: Add pagination support for large vaults (low priority for v1).

---

## Technical Debt Tracker

### Priority 1 -- Security

| Issue | File(s) | Status | Target |
|-------|---------|--------|--------|
| IPC token uses `!=` instead of constant-time compare | `daemon/ipc.rs:122` | Done (v0.2.0) | v0.2.0 |
| IPC master password sent in plaintext (Windows TCP risk) | `daemon/ipc/client.rs` | Done (v0.3.0) | v0.3.0 |
| Browser extension popup lacks clipboard auto-clear | `browser-extension/chrome/popup.ts` | Done (v0.2.0) | v0.2.0 |
| `schema.rs` uses `CryptoError` for database errors | `database/schema.rs` | Done (v0.2.0) | v0.2.0 |

### Priority 2 -- Technical Debt

| Issue | File(s) | Status | Target |
|-------|---------|--------|--------|
| Migration system is a stub (refinery unused) | `database/migrations.rs` | Done (v0.2.0) | v0.2.0 |
| `db_metadata.version` hardcoded to 1, never validated | `vault.rs:719` | Done (v0.2.0) | v0.2.0 |
| `schema.rs` missing index creation | `database/schema.rs` | Done (v0.2.0) | v0.2.0 |
| `proptest` dev-dependency declared but unused | `Cargo.toml` | Done (v0.2.0) | v0.2.0 |
| `refinery` dependency declared but unused | `Cargo.toml` | Done (v0.2.0) | v0.2.0 |

### Priority 3 -- Code Quality

| Issue | File(s) | Status | Target |
|-------|---------|--------|--------|
| vault.rs at 1,763 lines (facade doing too much) | `vault/mod.rs` | Done (v0.3.0) | v0.3.0 |
| UI app.ts uses module-level global state | `sentinelpass-ui/app.ts` | Done (v0.3.0) | v0.4.0 |
| `PasswordManagerError::Database(String)` loses type info | `lib.rs` | Done (v0.3.0) | v0.3.0 |

---

## Feature Roadmap

### v0.2.0 -- Hardening

- [x] Constant-time IPC token comparison (`subtle` crate)
- [x] Wire up refinery migration runner or implement custom versioned migrations
- [x] Validate `db_metadata.version` on vault open
- [x] Add index creation to `schema.rs::initialize_schema()`
- [x] Add property-based tests with proptest
- [x] Browser extension clipboard auto-clear
- [x] Remove or use `refinery` dependency (compile-time cost for nothing)

### v0.3.0 -- Architecture

- [x] Extract TOTP, SSH, biometric from vault.rs into dedicated modules
- [x] Proper error typing for database operations (`DatabaseError` enum)
- [x] UI state management refactor (state.ts owns all cross-module state; 3 local `let` vars in app.ts are intentionally module-local)
- [x] Pagination for `list_entries()` and `list_ssh_keys()`
- [x] Browser extension: enable search, add credential, settings

### v0.7.0 -- Security, Features & CI Health

- [x] P0/P1 security fixes: Entry.password zeroization, biometric hardening, IPC token constant-time compare
- [x] rustls-webpki CVEs patched (RUSTSEC-2026-0098/0099/0104 → 0.103.13)
- [x] Passkey reference type: credential discriminator, export filtering, secret lookup blocking
- [x] External secret allowlist with expiring grants and audit events
- [x] Browser extension: search, add credential, settings, Firefox parity, sender validation fix
- [x] Architecture: IPC split, CLI module extraction, vault sync/health ops, DB PRAGMAs + WAL
- [x] Pagination for list_ssh_keys; crate-root re-exports for pagination types
- [x] CI stabilisation: clippy collapsible_match, platform cfg gates, Windows import fix

### v0.8.0 -- Features (from blog roadmap)

- [ ] Mobile apps (iOS/Android) with shared Rust core
- [ ] Opt-in encrypted cloud sync (E2E encrypted, self-hostable relay)
- [ ] KeePass import/export
- [ ] Passkey / WebAuthn support
- [ ] Third-party security audit

---

## Session Log

| Date | Version | Changes | PR |
|------|---------|---------|-----|
| 2026-02-16 | v0.1.3 | Auto-register native messaging host on UI launch, stable Chrome extension ID, install.sh --from-app-bundle, README/BUILD docs rewrite | #15 |
| 2026-02-16 | v0.1.3 | DeepSeek analysis verification, TECHNICAL_DEBT.md created | -- |
| 2026-02-16 | v0.2.0 | Hardening: constant-time IPC token, schema error types, indexes/triggers, version validation, remove refinery, proptest, clipboard auto-clear | #16 |
| 2026-02-16 | v0.3.0 | Architecture: extract vault.rs into vault/ directory module (mod.rs + biometric_ops.rs + totp_ops.rs + ssh_ops.rs + tests.rs), add structured DatabaseError enum with 8 variants replacing catch-all String, migrate ~152 call sites across 10 files. CI fix: gate DatabaseError import for biometric platforms, exclude binary entry points from coverage. | #16 |
| 2026-05-09 | v0.3.0 | Code quality: IPC split (ipc/mod.rs + server.rs + client.rs), CLI command extraction (9 modules), vault sync/health ops, error refinement (anyhow removed, DatabaseError::Other→InvalidInput), DB PRAGMAs + WAL checkpoint, list_ssh_keys_paginated + crate-root re-exports, popup search/add/settings + sender validation fix, Windows TCP IPC encryption verified Done | -- |
| 2026-05-09 | v0.7.0 | Version bump to 0.7.0; security: rustls-webpki CVE patches; CI: fix 6 clippy errors (collapsible_match, platform cfg, Windows import); align Cargo.toml + tauri.conf.json versions | -- |
| 2026-09-03 | v0.8.1 | Credential registry (ADR-001) + master-password rotation (ADR-002), single schema v5; adversarial-review fix slice (pair-join epoch threading, biometric epoch-aware unlock, lockout misclassification); CI trigger dedup (drop redundant push:[main,develop]) | #78,#80,#85,#86,#87,#88,#89 |

## v0.8.1 Session Log (2026-09-03)

### Shipped this cycle
- Credential registry (ADR-001): schema v5 — `entities`, `entity_memberships`,
  `secret_equality_index` (DEK-encrypted HMAC reuse-detection tags),
  `entry_lifecycle`, `registry_state`; rotation-policy engine; CLI
  `sentinelpass registry {entity-add,entity-list,entity-delete,assign,
  unassign,mark-rotated,expires-at,status,report}`
- Master-password rotation (ADR-002): `sentinelpass passwd` re-wraps the
  DEK under a new master key (`key_epoch` bound as AEAD associated data;
  entries never re-encrypted); `sentinelpass status` (password-free vault
  metadata + best-effort daemon reachability)
- Adversarial-review fix slice on the merged combination: pair-join from
  a rotated vault (the exact recovery flow `passwd` instructs users to
  run was broken — legacy unlock failed GCM auth against an epoch-bound
  wrap, and the epoch was never persisted); `enable_biometric_unlock`
  fixed for the same reason; rotation failures no longer misclassified
  into brute-force lockout for transient (non-auth) errors
- `key_epoch` surfaced over IPC (`VaultStatusResponse`) and via a new
  password-free `sentinelpass status` CLI command; Windows-safe daemon
  probe replacing an inert `Path::exists()` check on a named pipe
- CI: dropped redundant `push:[main,develop]` triggers from 6 workflows —
  every develop -> main promotion PR was double-CI'd (push-on-merge +
  pull_request-on-promotion for the identical commit); branch protection
  already gates merges on the pull_request checks, so the push-triggered
  re-run validated nothing new
- Branch model change: `develop` is now the integration branch (all
  feature PRs land there first, squash-merged); promotion to `main` is
  an explicit, separate merge-commit PR per release

### Deferred (tracked, do not re-derive)
1. Sync-peer epoch enforcement (ADR-002 D4): peers don't yet reject
   stale-epoch bootstrap blobs; rotation currently only protects the
   local `db_metadata`, not synced peer copies of the DEK
2. `db_metadata` rotation write has no compare-and-set on `key_epoch`
   (TOCTOU under concurrent rotation attempts — low severity, no
   observed exploit path)
3. Registry dashboard (Tauri UI) — ADR-001 P2, not yet started
4. Rotation UI (Tauri) — ADR-002 D5, CLI-only for now
5. External-consumer registry aggregate API over `sentinelpass-protocol`
   — gated on a new grant-class ADR (ADR-001 D3)
6. Entity editor / policy editor (ADR-001 P4)
7. Similarity/breach (HIBP) checks on the equality index (ADR-001 later)

## v0.8.0 Session Log (2026-08-31)

### Shipped this cycle
- `sentinelpass-protocol` crate extracted (stable IPC contract for embedders; sandhi consumes it)
- Per-client grant tokens (grant file v2: `client_tokens` map, fail-closed revoke, `allow_write` flag)
- `GetCredential` CLI bypass closed; staged browser-surface origin gate (deny-by-default lands v0.9)
- `sentinelpass exec` / `env` secret serving; explicit `locked` semantics on all lookup responses
- `SaveSecret` (write grants) + `ExternalSecretWrite` audit; `DeleteSecret` defined-but-rejected
- Relay pairing tokens: salted Argon2id at rest (was unsalted SHA-256 of a 6-digit code)
- SyncNow/Shutdown IPC handlers implemented; CLI `--version` fixed; justfile fixed; dependabot enabled
- Removed dead `crypto/zero.rs` (`SecureBuffer`) and unused `memsec` dep
- Homebrew tap bump automation (`scripts/bump-homebrew-formula.sh` + release.yml job, needs `TAP_TOKEN` secret)
- Sibling PRs: sandhi#176 (native IPC vault backend), victor#985 (allowlisted lookup)

### Deferred (tracked, do not re-derive)
1. Schema v5 typed payloads: api-key provider/scopes/expiry metadata + entry ownership → real `DeleteSecret`
2. Full `Zeroizing` sweep on IPC/export/sync/native-messaging secret fields (wire structs still `String`)
3. Dependency majors: rusqlite 0.30→0.32, thiserror 1→2, rand 0.8→0.9, objc/cocoa replacements
4. Origin gate deny-by-default (v0.9); remove `SENTINELPASS_DENY_LEGACY_GET_CREDENTIAL` (v1.0)
5. `sentinelpass-protocol` → crates.io (removes git-rev pin in sandhi)
6. Repository pattern for sync_ops/delete_entry raw SQL; add_entry/update_entry encrypt-block dedup (vault/mod.rs)
7. audit.toml ignore review; pairing-code lengthening (9 digits, coordinated client+relay)
8. Headless `.deb` via cargo-deb for servers; systemd user unit; launchd plist for daemon supervision
9. DaemonVault mutex `.lock().unwrap()` sites (vault_state.rs) — poison handling
10. CLI CRUD still re-opens the vault + re-runs Argon2id per command; route CRUD through the daemon
