# Technical Debt & Roadmap

Last updated: 2026-09-11 (0.11 cycle — Phase 7 release assurance)

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
| 2026-09-07 | v0.10 (WBS-412/413/708) | File-permission hardening: `platform.rs` owner-only helpers wired at every sensitive creation/open site (vault db+`WAL`/`SHM`, epoch sidecar, IPC token, grants, JSON/CSV/KeePass exports, data/config/audit dirs); typed symlink/type/owner validation (WBS-413); debug-unlock artifacts removed/gated: `unlock_debug_log` release-no-op, unlock-flow `console.log`s dropped from shipped UI bundles | worktree branch |
| 2026-09-09 | v0.11 | 0.11 cycle: authenticated backup + verified restore (WBS-416/417/418 — `.spbackup` format, HKDF-over-DEK manifest MAC, atomic single-rename restore with fail-closed flags, fault-injection sweeps, v6/v7/v8 fixture restores); desktop hardening (WBS-706/707/709 — WHATWG URL parsing + HTTP consent, least-privilege Tauri capabilities + CSP, native expiring clipboard). Integration adversarial review: zero blockers, 2 Majors fixed (corrupt-live-file restore fallback; Wayland clipboard). Windows lesson: SQLite opens corrupt files lazily — classify treats post-open read failures as unknowable | #126 |
| 2026-09-11 | v0.11 (WBS-909/910/913) | Phase 7 stage A1: governed dependency-exception lifecycle (TD-REL-04 closed — `.cargo/audit.toml` single audit-policy source with owner/exposure/expiry metadata, full register in `docs/DEPENDENCY_EXCEPTIONS.md`, two dead ignores removed after raw-audit verification, security.yml inline `--ignore` dropped); relay rate-limiter window math clock-injected and both window-reset tests running UNIGNORED on all CI platforms via a forward-only fake clock (TD-REL-06 closed; minute-refill test no longer sleeps); docs reconciliation (SECURITY.md supported versions 0.9/0.10/0.11, matrix baseline → 0.11 + backup row → Implemented per TD-ROB-12, relay/dependency row evidence, CLAUDE.md workflow list corrected, SECURITY_ARCHITECTURE program-phase roadmap + new sync-v2 §12 and desktop-hardening §13 sections + stale SecureBuffer/padding claims fixed) | worktree branch |

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
4. ~~Origin gate deny-by-default~~ — shipped (WBS-101/102, 2026-09-05): browser-surface IPC denies originless requests by default; `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1` is the temporary escape hatch, remove in v1.0
5. `sentinelpass-protocol` → crates.io (removes git-rev pin in sandhi)
6. Repository pattern for sync_ops/delete_entry raw SQL; add_entry/update_entry encrypt-block dedup (vault/mod.rs)
7. audit.toml ignore review; pairing-code lengthening (9 digits, coordinated client+relay)
8. Headless `.deb` via cargo-deb for servers; systemd user unit; launchd plist for daemon supervision
9. DaemonVault mutex `.lock().unwrap()` sites (vault_state.rs) — poison handling
10. CLI CRUD still re-opens the vault + re-runs Argon2id per command; route CRUD through the daemon
11. Originless-IPC deny warn (`daemon/ipc/server.rs::browser_surface_allowed`) has no rate limit — a pre-0.8 host polling autofill can flood the daemon log (log-hygiene only, not a bypass: gate logic is correct; review round 2, finding 10)

---

## Security and Recovery Reset (2026-09-04)

This section is the current open-debt baseline and supersedes older status statements
when they conflict. Detailed sequencing and acceptance criteria live in
`docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`; governing designs are Proposed in
ADR-003 through ADR-010.

### P0 -- Release-blocking security architecture

| ID | Gap | Evidence area | Required outcome | Target | Status |
|----|-----|---------------|------------------|--------|--------|
| TD-SEC-01 | Local encrypted fields lack semantic AAD | `crypto/cipher.rs`; `vault/mod.rs` | Envelope v2 binds vault/entry/purpose/type/epoch/version | 0.9 | Open; ADR-005 Proposed |
| TD-SEC-02 | Sync identity/version/origin/tombstone metadata is not end-to-end authenticated | `sync/crypto.rs`; `sync/models.rs` | Authenticated v2 mutation envelope and version lineage | 0.11 | Closed 2026-09-10 (sync v2, WBS-601/612): every mutation carries a DEK-derived HMAC-SHA256 over the canonical shared metadata (identity, type, versions, epoch, origin, tombstone, payload hash — one PRF domain, distinct from the ADR-005 envelope); clients verify MAC + deterministic-id recomputation before applying ANY foreign mutation (tamper dead-lettered, `relay_metadata_tamper_is_dead_lettered`); the relay stores the MAC opaquely |
| TD-SEC-03 | No forgotten-password recovery | key hierarchy and UI | Verified recovery key slot; reset access, never recover old password | 0.9 | Done after adversarial review (2026-09-05): slot registry (WBS-302 Done) + 256-bit checksummed recovery key with exhaustive single-char-error rejection (310) + verified onboarding, raw-wrap + full AAD binding (311) + recover-without-old-password flow: verify-before-write, all-slots-revoked, epoch advance, single-use slot (312); CLI recovery setup/recover/status. Desktop-UI flows and the recovery drill remain (WBS-1001/905); ADR-004 Accepted rev 5 |
| TD-SEC-04 | Password rotation adopts the in-memory key before persistence | `crypto/keyring.rs`; `vault/mod.rs` | Stage, verify, commit, then adopt | 0.9 | Done (WBS-309, 2026-09-04): staged+verified rotation, adopt-after-commit, stale-epoch UPDATE guard, commit-failure test with lock injector |
| TD-SEC-05 | Key epoch does not revoke normal sync/device authority | pairing bootstrap vs normal sync | Epoch on every request/object; stale device/slot rejection | 0.11 | Open; ADR-004/006 Proposed |
| TD-SEC-06 | Browser IPC authority relies on a self-asserted origin; originless remains allowed | `protocol/envelope.rs`; daemon IPC server | Native-host-specific capability; deny originless | 0.8.x/0.10 | Closed (WBS-504/505/506, 2026-09): browser-surface ops require a valid `native-host` installation capability presented on the envelope (hashed at rest in `ipc-capabilities.json` 0600, expiry + revocation supported, host secret file 0600 provisioned by the daemon); a general client claiming NativeHost without the material is denied (unit + e2e tests); originless remains denied by default; legacy self-asserted/originless windows are explicit announced env opt-outs removed in 1.0; external-secret grants (audience-bound, token-enforced) retained as the least-privilege tool surface |
| TD-SEC-07 | Six-digit HKDF pairing permits offline guessing | `sync/pairing.rs` | High-entropy QR bootstrap or reviewed PAKE | 0.11 | Closed 2026-09-10 (sync v2, WBS-615/616): pairing root is now a 256-bit CSPRNG secret (base64url/QR) — bootstrap encrypted under HKDF(secret), relay stores only Argon2id(secret) and gates retrieval on knowledge of the secret (POST body, one-use, TTL, attempt-limited); the six-digit value is demoted to a derived transcript-comparison aid that never encrypts material; secret is prompted, not a CLI argument. Reviewed choice: HMAC-challenge over a PAKE (documented per ADR-006) |
| TD-SEC-08 | Android/iOS security functions are incomplete but user-facing scaffolds exist | mobile bridge and native apps | Prototype labeling now; no release-reachable placeholders later | 0.8.x/0.12 | Open; ADR-009 Accepted rev 2 (placeholders removed by WBS-807) |
| TD-SEC-09 | Security-critical key material is generated with `rand::thread_rng()` (ThreadRng) instead of OsRng | `crypto/password.rs:148,275` (password/passphrase generation), `vault/recovery.rs:91,289` (recovery keys), `sync/device.rs:21` (device-identity signing secret) | Key material draws from `rand::rngs::OsRng` directly (ThreadRng kept only for non-secret uses); also fix the false "from the OS CSPRNG" doc comment on `RecoveryKey::generate` | 0.11 | Open (found 2026-09-12 during the WBS-909 exception review: the RUSTSEC-2026-0097 register row's original "runtime randomness uses OsRng" exposure claim was falsified by these call sites — register corrected, escalation opened per the register's own criterion 2. ThreadRng is CSPRNG-reseeded so this is hardening, not an active vulnerability) |

### P1 -- Data integrity, availability, and privacy

| ID | Gap | Evidence area | Required outcome | Target | Status |
|----|-----|---------------|------------------|--------|--------|
| TD-ROB-01 | Sync marks rejected entries synced and uses server cursor as device sequence | `sync/engine.rs`; relay sync handler | Per-object durable ack and distinct counter types | 0.11 | Closed 2026-09-10 (sync v2, WBS-601/602/604/605): engine pushes idempotent v2 mutations (`sync/v2.rs` + `sync/outbox.rs`) with DISTINCT DeviceSequence/ObjectVersion/ServerCursor types and no value-level cursor reuse (the v2 framing counter derives from the relay-cursor diagnostic but nothing gates on it — the types are the contract); outbox entry leaves ONLY on its own `Applied` ack (`rejected rows stay pending`, pinned by `ack_marks_only_applied_objects`); relay stores durable per-mutation results and replays originals (`duplicate_push_returns_original_applied_result` / `..._rejection`); v1 relay handler untouched for old clients, hard-reject lands with v1 retirement (WBS-624) |
| TD-ROB-02 | Remote updates are rewritten pending by local SQLite trigger | `database/schema.rs`; `sync/engine.rs` | Explicit local/remote repositories and transactional unit of work | 0.10/0.11 | Closed 2026-09-08 (write-path PR): trigger never created + `migrate_v8_to_v9` drops both historical shapes in-tx; every production `entries` write carries explicit bookkeeping (integration-review enumeration: no missed path); negative `remote_apply_does_not_remark_pending` pins synced state + stable version/modified_at |
| TD-ROB-03 | Optional encrypted URL/notes become empty blobs instead of NULL | sync apply | Preserve typed null end to end | 0.10 | Closed 2026-09-08 (write-path PR): apply-side empty-blob→NULL coercion removed; url/notes are unconditional full-replace SETs (None→NULL); legacy `X''` optional blobs decode as absence on read and in the sweep; `Some("")` never collapses (pinned by `empty_string_url_roundtrip_not_coerced_to_null`) |
| TD-ROB-04 | Sync page, mapping, registry, cursor, and relay writes are not atomic | sync engine/relay | Transactional client and relay mutations | 0.11 | Closed 2026-09-10 (sync v2, WBS-606/607): relay v2 push is ONE transaction per request (results + object state + log + sequence counters + epoch — authorizer fault-injection sweep `push_v2_fault_injection_is_all_or_nothing` proves all-or-nothing); client pull folds applies + dead-letter dispositions + the cursor advance into ONE page transaction (`pull_page_fault_injection_is_all_or_nothing`: fault at every write → complete-old incl. cursor, or complete-new post-page); per-blob apply atomicity unchanged (WBS-411 sweeps still green). Registry index stays best-effort inside the blob by the documented REGISTRY-BOUNDARY contract |
| TD-ROB-05 | Retry after lost push response is not idempotent | client/relay device sequence | Mutation idempotency record returning original result | 0.11 | Closed 2026-09-10 (sync v2, WBS-603): deterministic mutation ids derived from (vault, object, resulting version) (`v2::mutation_id_for` — stable across re-collection despite fresh GCM nonces, since every local edit bumps the row version); relay `mutation_results` table replays the ORIGINAL durable result for duplicates, ages records out (TTL + per-device cap in cleanup) after which CAS re-evaluation REJECTS rather than replays; end-to-end lost-response acceptance: `lost_push_response_retry_completes_without_wedge` (relay commits, response lost, retry completes the outbox with zero log duplication); the #121 device_sequence wedge is structurally impossible in v2 (framing counter recorded, never gated) |
| TD-ROB-06 | Full sync sequencing/pagination paths diverge from normal sync | client/relay full push/pull | One bounded paginated state machine | 0.11 | Open |
| TD-ROB-07 | Newer unknown database schema is accepted | `database/schema.rs` | Fail closed with explicit compatibility policy | 0.9 | Open |
| TD-ROB-08 | KDF parameters have minimums but no hard maximums; intermediate output is not fully zeroized | `crypto/kdf.rs` | Bounded platform profiles and secret buffer cleanup | 0.9 | Hard maximums + mobile profile Done after adversarial review (WBS-307, 2026-09-05; incl. size-limited WrappedKey decode); intermediate-buffer zeroization sweep remains open (WBS-308); adopted-parameter ceilings for constrained devices under pair-join tracked with on-device calibration (ADR-009) |
| TD-ROB-09 | Security-sensitive files rely partly on ambient permissions | platform/database/audit/token/grant paths | Explicit modes/ACLs and owner/type/symlink checks | 0.10 | Done (WBS-412/413, 2026-09-07): owner-only modes set at creation and verified at open for vault db (+WAL/SHM, refuse-on-loose), epoch sidecar, IPC token, grants, all export formats; dirs 0700; typed symlink/type/owner refusals with tests. Residual: Windows ACLs rely on user-profile inheritance (not CI-provable); audit.log FILE mode still umask-derived (`audit.rs` separately owned; shielded by its 0700 directory); uid-mismatch refusal untestable as non-root in CI |
| TD-ROB-10 | Domain, SSH/TOTP metadata and audit context leak plaintext identity | database schema and audit call sites | Encrypted originals, keyed indexes, opaque audit IDs | 0.9/0.10 | Open |
| TD-ROB-11 | Audit has no integrity chain, retention, or rotation contract | `audit.rs` | Verifiable bounded audit subsystem | 0.10 | Open |
| TD-ROB-12 | No authenticated portable backup and verified restore contract | import/export and platform backup paths | Atomic encrypted snapshot bundle and restore drills | 0.10 | Closed 2026-09-08 (PR #126): `.spbackup` bundles — VACUUM INTO snapshot, HKDF-over-DEK manifest MAC (constant-time, MAC-first restore), digest/identity/epoch/slot binding, bounds-before-allocation; restore = staged validation + single-rename swap + sequenced sidecar re-baseline with fail-closed flags and the retained `.pre-restore` net; fault-injection sweeps prove complete-old/complete-new; routine recovery drill remains for 1.0 (WBS-905) |
| TD-ROB-13 | Desktop UI and daemon can both own unlocked vault state | Tauri commands and daemon | Daemon is sole key/database owner | 0.10 | Partial (WBS-501/502/503, 2026-09): all UI/CLI vault commands rerouted through the daemon application-service boundary (`ServiceCall`/`VaultOp`); daemon holds the exclusive `<vault>.maint-lock` for life (coexistence refusal) and no-vault bootstrap is a daemon maintenance mode; direct access survives only behind the flagged `SENTINELPASS_ALLOW_DIRECT_VAULT=1` env (lock-guarded, announced, ADR-007 migration window) and offline-exclusive maintenance (init/passwd/backup/recovery/pairing) — daemon claims sole-writer only after the env path is removed (1.0); ratchet test pins the direct-open allowlist |
| TD-ROB-14 | IPC serves one Unix connection at a time without comprehensive deadlines; Argon2 may block async work | daemon IPC server | Bounded concurrent connections and blocking pool | 0.10 | Open |
| TD-ROB-15 | Windows named pipe lacks explicit current-user security descriptor | daemon Windows transport | User SID ACL and remote-client rejection | 0.10 | Closed (WBS-508, 2026-09): server instance created via raw CreateNamedPipeW with an explicit DACL (current-user SID only, generic read/write), FILE_FLAG_FIRST_PIPE_INSTANCE on the first instance (name-squatting refusal, ERROR_ACCESS_DENIED fail-closed), and PIPE_REJECT_REMOTE_CLIENTS (remote SMB clients rejected); FFI type-checked against windows 0.61 for x86_64-pc-windows-msvc — runtime Windows behavior verification rides the Windows CI matrix |
| TD-ROB-16 | IPC session crypto lacks a derived directional/session context | protocol Windows frame | HKDF session keys, AAD, counters, replay/reflection tests | 0.10 | Open |

### P1 -- Network and relay operations

| ID | Gap | Required outcome | Target | Status |
|----|-----|------------------|--------|--------|
| TD-NET-01 | Pairing token is fetched in a GET URL | POST body with one-use scoped material | 0.11 | Open |
| TD-NET-02 | Clients accept arbitrary HTTP relay URLs | TLS except explicit loopback development; safe redirects/userinfo rules | 0.8.x/0.11 | 0.8.x half done: `validate_relay_url` (sync/config.rs) enforces HTTPS / loopback-only HTTP (`SENTINELPASS_ALLOW_LOOPBACK_RELAY=1`) / no userinfo at init and client construction, with negative tests; client redirect rules remain for v2 |
| TD-NET-03 | Rate limiting trusts unconfigured forwarded IP values | Trust proxy headers only from configured proxies | 0.11 | Open |
| TD-NET-04 | Public/pairing limits can be bypassed or interfere across vaults | Target-aware per-vault/device quotas and bounded expiring state | 0.11 | Open |
| TD-NET-05 | Relay uses blocking serialized SQLite access in async handlers | Bounded storage pool/actor and short transactions | 0.11 | Open |
| TD-NET-06 | Configured entry/blob/body limits are inconsistent or not all enforced | One validated protocol limit set with negative tests | 0.11 | Open |
| TD-NET-07 | Production sync padding helper is unused | Either integrate authenticated padding profile or remove claim | 0.11 | Open |

### P1/P2 -- Desktop and browser

| ID | Gap | Required outcome | Target | Status |
|----|-----|------------------|--------|--------|
| TD-CLIENT-01 | Full selected credential remains in desktop JS/DOM state | Summary state plus scoped reveal/copy handles; scrub on lock | 0.10 | Open |
| TD-CLIENT-02 | Desktop visibility change does not enforce lifecycle lock/privacy cover | Inactivity/background/session-lock/suspend/logout policy | 0.10 | Open |
| TD-CLIENT-03 | Tauri shell/clipboard/CSP permissions are broader than demonstrated need | Least-privilege capabilities and CSP | 0.10 | Open |
| TD-CLIENT-04 | Windows biometric consent is separate from generic keyring retrieval | Cryptographically Windows Hello/protection-bound slot | 0.10 | Partial (WBS-710, 2026-09-11; downgrade after adversarial review): the design and code are in place — DEK sealed under HKDF of a per-vault KeyCredential signature, non-secret at-rest blob, GCM-authenticated release, determinism self-check at enable, legacy migration — BUT the load-bearing premise (Hello `RequestSignAsync` yields a deterministic RSASSA-PKCS1 signature) is CONTRADICTED by Microsoft's docs (which state PKCS#1 RSA PSS) and unverified on hardware; if PSS, enable self-refuses (fail-closed — biometric simply unavailable, master-password fallback intact) and the goal is unmet. GATE before shipping the feature: one Windows hardware validation pass (enable + release + wrong-key + refused-gesture). Evidence: 10-case platform-free unit suite, windows-0.61 msvc type-check of the OpenAsync/DeleteAsync surface; everything Windows has never executed |
| TD-CLIENT-05 | Browser permits HTTP and broad hosts | Default-deny HTTP; optional site access where feasible | 0.10 | Closed 2026-09-10 (WBS-711/712): daemon origin gate default-denies AUTOFILL delivery for plain-HTTP and unverifiable origins (browser-provided `page_url`, WHATWG-parsed, delivery bound to the validated host; typed denial reason; capability does not bypass); the only allow-list is an explicit EXACT-host user grant (`site_permissions.json` 0600, popup-only management, revoke immediate); manifests moved to `optional_host_permissions` + per-site browser grants so install no longer requests every site |
| TD-CLIENT-06 | Autofill ignores target and chooses the first password field | Validated field/form descriptor and ambiguity chooser | 0.10 | Closed 2026-09-10 (WBS-713/714/715): fill binds to the requested field + its form (never page-first; fillable/visible verification), site binding via the 711 validated-URL host, cross-origin frames default-denied; autocomplete attribute honored as the primary field signal (new-password never silently filled), password-change pairs detected (Update prompt + save_trigger); multiple matches surface an explicit username-only chooser with post-pick fetch via an exact-username daemon filter (no silent first-match; unknown picks never fall back) |
| TD-CLIENT-07 | Plaintext pending credentials live in extension session storage | Eliminate or minimize/scrub with bounded lifetime | 0.10 | Closed 2026-09-10 (WBS-716): pending payloads are background-worker-only (content scripts hold no session secrets and cannot read the trusted-context store), every entry TTL-stamped (30 s / 2 min / 10 min per class) via a tested pure registry, swept by chrome.alarms (unstamped entries swept as expired — fail-closed), purged on vault lock with a content-script scrub broadcast; full inventory in DEBUGGING.md + SECRET_LIFETIME_AUDIT.md §N |
| TD-CLIENT-08 | Chrome/Firefox source and native-host identifiers can drift | Shared generation and CI parity checks | 0.10 | Closed 2026-09-11 (WBS-717/718): single source set + one canonical pipeline (`scripts/build-extension.mjs`, byte-parity across targets asserted on every build AND in `tests/web/extension-pipeline.test.ts` with a fresh rebuild); `tests/web/manifest-parity.test.ts` pins manifest version/permissions parity, DERIVES the stable Chrome ID from the manifest key and requires it in every native-host registration source (install.sh/install.ps1/Tauri), pins one firefox gecko ID across the manifest + all native-host sources (drift @sentinelpass.org vs @localhost found and fixed), and pins the host name everywhere; install.ps1's ExtensionId now defaults to the pinned ID (a default run previously wrote a placeholder origin) |
| TD-CLIENT-09 | Web coverage is concentrated in utilities | Cross-boundary Chromium/Firefox/daemon E2E suite | 0.10 | Closed 2026-09-11 (WBS-719): real-backend Chromium E2E (`daemon-autofill.spec.ts`) drives extension -> native host -> daemon -> vault in an isolated HOME install: HTTPS fill, HTTP default-deny (711) + host-driven per-site grant (712), ambiguity chooser (715), capture-to-held-payload + registration save verified through the CLI, locked-vault negative; found the classic-script injection break, an init-order crash, the gecko-ID + install.ps1 drifts, and the popup-as-tab sender misclassification. Firefox E2E is a documented gap (Playwright cannot load extensions in stock Firefox); Firefox parity is enforced by the byte-parity pipeline gate and shared unit suites |

### P0/P1 -- Mobile bridge and native clients

| ID | Gap | Required outcome | Target | Status |
|----|-----|------------------|--------|--------|
| TD-MOB-01 | Android CI omits JNI and JNI-enabled Rust currently fails | Build every Android ABI with JNI and fail on symbol/signature mismatch | 0.12 | Open |
| TD-MOB-02 | Kotlin `VaultBridge` declarations do not match Rust `VaultManager` exports | One generated class/package/signature contract | 0.12 | Closed 2026-09-11 (WBS-802): Rust exports renamed to `Java_com_sentinelpass_VaultBridge_*`, arity/wire-format mismatches fixed, undeclared Rust extras trimmed; contract pinned both directions by `tests/jni_contract.rs` and the compiled-artifact symbol check lands with WBS-811 |
| TD-MOB-03 | Android biometric/sync/autofill contain placeholders | Keystore-bound slot, real sync v2, complete AutofillService | 0.12 | Open |
| TD-MOB-04 | Android update is delete-then-add and handle lifecycle can leak | Atomic update and deterministic destroy | 0.12 | Open |
| TD-MOB-05 | Android lifecycle/privacy/network/backup policy is incomplete | Lock/privacy cover, cleartext deny, verified backup allowlist/no-backup | 0.12 | Open |
| TD-MOB-06 | iOS biometric state is process-local and unlock is unimplemented | Keychain access-control platform slot surviving restart | 0.12 | Open |
| TD-MOB-07 | iOS lacks scene lock/privacy cover and safe pasteboard behavior | Lifecycle lock/cover and local-only expiring pasteboard | 0.12 | Open |
| TD-MOB-08 | iOS export/delete/backup/Credential Provider are incomplete | Authenticated backup/restore and Credential Provider | 0.12 | Open |
| TD-MOB-09 | Duplicate Swift bridges and FFI buffers lack one proven ownership/zeroization contract | Generated ABI, one bridge, panic containment, zeroizing free | 0.12 | In Progress — WBS-801 Done 2026-09-11 (generated ABI: cbindgen include-list synced, header pinned by contract tests + CI drift check); 804/805/820 remain |
| TD-MOB-10 | Mobile CI does not demonstrate functional native behavior | Simulator/device unlock/CRUD/update/lock/process-death/autofill tests | 0.12 | Open |

### P1 -- Release and supply chain

| ID | Gap | Required outcome | Target | Status |
|----|-----|------------------|--------|--------|
| TD-REL-01 | Tag release is not directly gated by all security workflows/features | Required security and feature-matrix dependencies | 1.0 RC | Partial (WBS-901, 2026-09-12): the release.yml `release` AND `crates-publish` jobs now `needs:` tag-time security audits (RustSec under the governed `.cargo/audit.toml` policy + both npm audits; a failed audit aborts the release/publish; PR preflight runs do not double-run the audits, and the Gate is unaffected — tag jobs register no PR checks). REMAINS: feature/platform matrix builds as prerequisites (WBS-902, rides Phase 6) and signing/notarization gates (WBS-906/907) |
| TD-REL-02 | Official artifacts lack complete signing/notarization/updater trust | Platform signing, notarization, signed updater metadata/checksums | 1.0 RC | Open |
| TD-REL-03 | No published SBOM/provenance assurance | Signed SBOM and provenance attestations | 1.0 RC | Open |
| TD-REL-04 | Dependency vulnerability exception lacks a full expiry lifecycle | Owner/exposure/mitigation/expiry enforcement | 0.10 | Closed 2026-09-11 (WBS-909): governed exception lifecycle adopted — `.cargo/audit.toml` holds ONLY the failing advisory (RUSTSEC-2023-0071) with owner/exposure/expiry metadata; the full register (1 vulnerability + 18 warning-class findings, each with owner=core-maintainer, exposure assessment, quarterly expiry) lives in `docs/DEPENDENCY_EXCEPTIONS.md`; security.yml's redundant inline `--ignore RUSTSEC-2023-0071` dropped (config file is the single audit-policy source); two dead ignores (RUSTSEC-2024-0413, RUSTSEC-2026-0037 — no longer fire) removed; warning-class findings deliberately NOT config-ignored so they stay visible in audit output; next quarterly review 2026-12-31 |
| TD-REL-05 | Release smoke tests do not perform a real unlock/round-trip/restore | Installed-artifact functional and recovery smoke suites | 1.0 RC | Open |
| TD-REL-06 | Relay timing tests remain ignored | Fix deterministic behavior and enable in CI | 0.11 | Closed 2026-09-11 (WBS-910): rate-limiter window math is clock-injected (`rate_limit.rs` `Clock` trait; one timestamp per decision across minute/hour/day windows); the two window-reset tests run UNIGNORED on all CI platforms by driving the public `check` path with a forward-only fake clock (no `Instant` subtraction — the underflow that caused the original hang — and no sleeps; the minute-refill test also lost its 1.1 s real sleep); relay suite 67 passed / 0 ignored |
| TD-REL-07 | Independent security review is not yet complete | Full trust-boundary review with critical/high closure | 1.0 RC | Planned |

### P2/P3 -- UX and missing features

| ID | Gap | Target |
|----|-----|--------|
| TD-UX-01 | Recovery setup, verification, health, and reauthentication UX | 0.9-0.10 |
| TD-UX-02 | Device/revocation/epoch/sync-conflict dashboard | 0.11 |
| TD-UX-03 | Password policy relies on composition cues rather than length/blocklist guidance | 0.9 |
| TD-UX-04 | Security Center for backup, recovery, device, biometric, password health, and events | 0.11-1.0 |
| TD-FEAT-01 | Credential history/trash, custom fields, secure notes, device management | Post-foundation baseline |
| TD-FEAT-02 | Identities, cards, attachments, tags, collections, breach monitoring | Post-1.0 personal expansion |
| TD-FEAT-03 | Emergency/social recovery and secure sharing | Separate accepted design required |
| TD-FEAT-04 | Organization/RBAC/SSO/SCIM and admin recovery | Deferred enterprise program |
| TD-FEAT-05 | Actual passkey private-key custody/provider capability | Deferred separate security architecture |
