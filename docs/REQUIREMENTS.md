# SentinelPass Requirements (Traceable)

**Version:** 2.0

**Date:** 2026-09-04

**Status:** Active security-remediation baseline

This document converts the gap review into traceable requirements with acceptance criteria.

## 1. Status Vocabulary

- `Must`: required for security posture or core product viability
- `Should`: strongly recommended for completeness/usability
- `Could`: opportunistic or later-phase

## 2. Functional Requirements

## FR-CORE (Core vault and local-first)

- `FR-CORE-001 (Must)` SentinelPass must support fully local vault creation, unlock, lock, CRUD, TOTP, and SSH key storage without cloud dependency.
  - Acceptance: Core workflows function with network disabled.

- `FR-CORE-002 (Must)` SentinelPass must preserve backward compatibility for existing local vault files or provide explicit migration paths.
  - Acceptance: schema version validation and migration behavior documented and tested.

## FR-BROWSER (Browser extension and autofill)

- `FR-BROWSER-001 (Must)` Browser extension must request credentials and TOTP through native host/daemon only (no direct vault access in extension).
  - Acceptance: architecture path remains extension -> native host -> daemon -> core.

- `FR-BROWSER-002 (Must)` Background worker must validate sender tab URL/frame context against claimed request domain before credential retrieval or save.
  - Acceptance: negative tests for mismatched sender URL/domain are present.

- `FR-BROWSER-003 (Should)` Browser extension popup must support search, save/add credential, and settings for baseline usability.
  - Acceptance: user can complete common tasks without desktop app context switches.

- `FR-BROWSER-004 (Should)` Extension release builds must use reduced logging, with debug logging gated by explicit build flag.
  - Acceptance: production bundle excludes verbose credential-flow logs.

## FR-SYNC (Sync and relay)

- `FR-SYNC-001 (Must)` Relay must enforce configured limits for pairing TTL, active pairings, nonce freshness, and request body size.
  - Acceptance: config-driven tests verify behavior changes when values are changed.

- `FR-SYNC-002 (Must)` Relay must run cleanup for nonces, expired pairings, and tombstones in production runtime.
  - Acceptance: startup path spawns cleanup task and logs lifecycle.

- `FR-SYNC-003 (Must)` Relay must enforce rate limiting for authenticated and public abuse-prone endpoints.
  - Acceptance: tests verify throttling behavior and 429 responses.

- `FR-SYNC-004 (Should)` Relay must support self-host deployment behind a reverse proxy/TLS terminator with documented hardening profile.
  - Acceptance: docs include minimal production deployment guidance and defaults.

- `FR-SYNC-005 (Should)` Sync UX must expose conflict and device status signals to users.
  - Acceptance: user-visible sync state and device management workflows exist.

## FR-MOBILE (Mobile)

- `FR-MOBILE-001 (Must)` iOS and Android clients must complete autofill integrations before SentinelPass is positioned as feature-complete for consumers.
  - Acceptance: platform autofill services can retrieve and fill stored credentials.

- `FR-MOBILE-002 (Should)` Mobile bridge and app layers must have automated tests for CRUD and unlock flows.
  - Acceptance: CI executes mobile bridge tests or documented automated smoke coverage.

## FR-IMPORT (Import/export and migrations)

- `FR-IMPORT-001 (Should)` SentinelPass must support at least KeePass and Bitwarden imports in the baseline completeness phase.
  - Acceptance: import fixtures and validation/error handling tests exist.

- `FR-IMPORT-002 (Should)` Import/export flows must provide validation and conflict handling (duplicate detection, invalid rows, partial import summary).
  - Acceptance: UI/CLI outputs structured summary and error counts.

## 3. Security Requirements

## SR-IPC (Daemon IPC and local boundaries)

- `SR-IPC-001 (Must)` Windows IPC transport must not rely on plaintext localhost TCP for sensitive vault operations in GA releases.
  - Acceptance: named pipes with per-user ACLs (preferred) or equivalent authenticated encryption and local access controls are implemented.

- `SR-IPC-002 (Must)` IPC protocol documentation must accurately describe the actual platform transport per OS.
  - Acceptance: no doc mismatch between implementation and IPC docs/comments.

## SR-EXT (Extension safety)

- `SR-EXT-001 (Must)` Extension background must enforce origin validation independent of content script claims.
  - Acceptance: sender URL normalization and comparison are centrally implemented and tested.

- `SR-EXT-002 (Should)` Autofill must be constrained by frame and scheme safety rules by default.
  - Acceptance: unsupported/unsafe contexts are denied or require explicit user action.

## SR-RELAY (Relay auth and abuse resistance)

- `SR-RELAY-001 (Must)` Relay public endpoints must have abuse controls (rate limits, quotas, and telemetry hooks for hosted deployments).
  - Acceptance: `/devices/register` and pairing endpoints are throttled.

- `SR-RELAY-002 (Must)` Relay pairing and device registration flows must require an explicit trust proof tied to pairing/bootstrap flow for non-initial devices.
  - Acceptance: registration path cannot silently join arbitrary vaults without possession of valid pairing material or equivalent proof.

- `SR-RELAY-003 (Must)` Replay protection must be tested and config-driven.
  - Acceptance: tests cover nonce reuse rejection and freshness-window enforcement.

- `SR-RELAY-004 (Should)` Pairing tokens should be stored hashed at rest on the relay.
  - Acceptance: token lookup is hash-based and migration path is documented.

## SR-DOCS (Security claim governance)

- `SR-DOCS-001 (Must)` Security/design docs must label controls as `Implemented`,
  `Partial`, `Experimental`, or `Planned`.
  - Acceptance: no ambiguous mitigation tables for major controls.

- `SR-DOCS-002 (Must)` Security claims must include code/test evidence references for implemented controls.
  - Acceptance: docs link to files/tests or to a status matrix.

## SR-CRYPTO (Vault cryptography and durable formats)

- `SR-CRYPTO-001 (Must)` Every encrypted vault and sync payload must authenticate its
  semantic context, including vault, stable object identity, purpose/type, format, and
  crypto epoch.
  - Acceptance: negative tests prove cross-field, cross-record, cross-vault, type,
    tombstone, epoch, and version substitution fail authentication.

- `SR-CRYPTO-002 (Must)` Durable encrypted envelopes must be explicitly versioned,
  language-neutral, and bounded before allocation.
  - Acceptance: format documentation, golden vectors, maximum-size tests, fuzzing, and
    unsupported-version tests exist.

- `SR-CRYPTO-003 (Must)` KDF parameters read from storage must have hard minimum and
  maximum bounds and calibrated platform profiles.
  - Acceptance: hostile memory/time/parallelism/output values fail before expensive
    allocation, and desktop/mobile calibration evidence is recorded.

- `SR-CRYPTO-004 (Must)` Secret-bearing owned values and FFI buffers must use explicit
  lifecycle/zeroization types and must not derive unsafe diagnostic traits by default.
  - Acceptance: a secret-lifetime audit covers core, IPC, export, sync, native messaging,
    C/JNI, Swift, Kotlin, and UI state, with code/test evidence for remediated paths.

- `SR-CRYPTO-005 (Must)` Unsupported newer schema, envelope, or crypto versions must fail
  closed.
  - Acceptance: opening a synthetic newer version returns a specific compatibility error
    without reading or mutating entries.

## SR-RECOVERY (Recovery, key slots, and revocation)

- `SR-RECOVERY-001 (Must)` Vault access must be represented by independently revocable
  password, recovery, platform, and trusted-device key slots around one DEK.
  - Acceptance: each slot is vault/identity/type/epoch/version bound and lifecycle tested.

- `SR-RECOVERY-002 (Must)` Forgotten-password recovery must use at least 128 bits of
  generated recovery entropy and must never store or reveal the old master password.
  - Acceptance: verified onboarding and recovery create a new password slot without the
    old password; relay data alone cannot perform recovery.

- `SR-RECOVERY-003 (Must)` Recovery and compromise flows must advance a cryptographic
  epoch and revoke old online device/slot authority.
  - Acceptance: stale devices and slots are rejected by daemon and relay tests; UI states
    the limit for already copied offline snapshots.

- `SR-RECOVERY-004 (Must)` Removing or rotating slots must be transactional and must not
  accidentally leave a vault without a usable unlock method.
  - Acceptance: failure injection and last-slot negative tests leave a recoverable state.

## SR-DATA (Persistence, audit, and backup)

- `SR-DATA-001 (Must)` Every logical mutation spanning entries, mappings, registry,
  sync state, or cursors must execute through one application-service transaction.
  - Acceptance: fault injection at each statement produces either the complete old or
    complete new state, never a partial state.

- `SR-DATA-002 (Must)` Nullable values must remain nullable through encryption, sync,
  migration, export, backup, and restore.
  - Acceptance: URL/notes and all later optional fields have NULL round-trip tests.

- `SR-DATA-003 (Must)` Vault directories, database/WAL/SHM, tokens, grants, audit logs,
  exports, and backups must receive explicit owner-only platform permissions and safe
  owner/type/symlink validation.
  - Acceptance: Unix mode and Windows ACL tests or platform verification evidence exist.

- `SR-DATA-004 (Must)` Audit records must avoid plaintext credential identity, be
  integrity-verifiable, and have bounded retention/rotation.
  - Acceptance: opaque identifiers, tamper detection, rotation, retention, and secret-log
    negative tests exist.

- `SR-DATA-005 (Must)` The primary backup format must be an authenticated, portable,
  atomic encrypted snapshot with verified restore.
  - Acceptance: fixtures from every supported schema restore successfully; interruption,
    corruption, wrong-vault, and oversized-input tests fail safely.

## Daemon Authority and IPC Session Security

- `SR-IPC-003 (Must)` Browser/native-host authority must use an unforgeable, scoped
  capability distinct from the general daemon credential; origin labels are not
  authorization.
  - Acceptance: a general same-user client cannot obtain browser credential operations
    by claiming `NativeHost` or omitting origin.

- `SR-IPC-004 (Must)` The daemon must be the sole live desktop DEK owner and vault writer.
  - Acceptance: official desktop and CLI CRUD use daemon application services; offline
    maintenance requires exclusive ownership.

- `SR-IPC-005 (Must)` IPC must enforce platform peer/ACL controls, bounded frames,
  directional authenticated sessions, replay counters, deadlines, and bounded
  concurrency.
  - Acceptance: replay, reflection, wrong direction, stall, malformed frame, oversize,
    and concurrent-client tests pass on supported platforms.

## SR-SYNC (End-to-end sync correctness)

- `SR-SYNC-001 (Must)` Sync mutations and retries must be idempotent and return durable
  per-object acknowledgements.
  - Acceptance: response loss and retry never duplicate data or mark rejected objects
    synced.

- `SR-SYNC-002 (Must)` Device request sequence, object version, and server cursor must be
  distinct protocol/storage types.
  - Acceptance: static/API review and sequencing tests prevent cross-assignment.

- `SR-SYNC-003 (Must)` Relay and client application of mutations, indexes, inbox/outbox,
  acknowledgements, and cursors must be transactional.
  - Acceptance: crash/fault injection resumes without data loss or echo loops.

- `SR-SYNC-004 (Must)` Sync identity, type, epoch, version lineage, origin, and tombstone
  state must be authenticated end to end and stale devices must be revocable.
  - Acceptance: malicious-relay mutation and rollback tests are detected by clients.

- `SR-SYNC-005 (Must)` Concurrent secret edits must preserve recoverable alternatives
  for user resolution rather than silently choose solely by relay/client timestamp.
  - Acceptance: multi-device conflict tests preserve both values and expose actionable
    local conflict state.

- `SR-SYNC-006 (Must)` Device pairing must resist offline guessing and bind registration
  to a one-use, short-lived, vault/device-scoped transcript.
  - Acceptance: pairing uses a high-entropy QR secret or reviewed PAKE; short numeric
    values do not encrypt bootstrap material.

- `SR-SYNC-007 (Must)` Non-loopback relay communication must require TLS with bounded,
  safe redirect behavior and no credentials in URLs.
  - Acceptance: HTTP, unsafe redirects, userinfo, and token-in-URL tests fail closed.

## SR-CLIENT (Desktop and browser)

- `SR-CLIENT-001 (Must)` Desktop lock must scrub secret UI/DOM state and activate on
  configured inactivity, background, session lock, suspend, and logout.
  - Acceptance: lifecycle tests and platform/manual evidence cover secret removal and
    privacy cover behavior.

- `SR-CLIENT-002 (Must)` Tauri capabilities and CSP must be limited to functionality used
  by the application.
  - Acceptance: capability review removes unused shell/clipboard/network access and CI
    validates the policy files.

- `SR-CLIENT-003 (Must)` Browser autofill must be bound to the validated site, frame,
  form, and target field and default-deny unsafe HTTP contexts.
  - Acceptance: Chromium/Firefox tests cover login, password change, iframe, ambiguous
    forms, HTTP, and sender mismatch.

- `SR-CLIENT-004 (Should)` Browser variants must be generated from shared security logic
  and release validation must enforce native-host/manifest identifier parity.
  - Acceptance: parity checks and equivalent browser test suites run in CI.

## SR-MOBILE (Mobile security boundary)

- `SR-MOBILE-001 (Must)` The shared mobile ABI/JNI contract must be generated, versioned,
  ownership-safe, zeroizing, panic-contained, and compiled for every release feature/ABI.
  - Acceptance: JNI-enabled builds, ABI negotiation, invalid-handle, repeated lifecycle,
    and FFI allocation tests run in CI.

- `SR-MOBILE-002 (Must)` Mobile biometric unlock must cryptographically gate a platform
  key-slot operation through Android Keystore or iOS Keychain access control.
  - Acceptance: process restart and biometric enrollment/invalidation tests prove that a
    UI prompt alone cannot release the key.

- `SR-MOBILE-003 (Must)` Android AutofillService and iOS Credential Provider must work
  before mobile is described as daily-driver or feature-complete.
  - Acceptance: platform integration tests retrieve/fill credentials and handle a locked
    vault without exposing secrets.

- `SR-MOBILE-004 (Must)` Mobile clients must define lifecycle lock, privacy cover,
  clipboard expiry, protected file storage, and encrypted backup/restore policy.
  - Acceptance: device/simulator tests cover backgrounding, process death, screen lock,
    clipboard, backup/restore, migration, and protected storage.

## SR-SUPPLY (Build and release assurance)

- `SR-SUPPLY-001 (Must)` Security CI and all security-relevant feature/platform builds
  must directly gate tagged releases.
  - Acceptance: a failed/skipped required security job prevents release publication.

- `SR-SUPPLY-002 (Must)` Official artifacts and updater metadata must be signed and
  independently verifiable, with SBOM and provenance attestations.
  - Acceptance: Windows signing, macOS signing/notarization, checksum signature, SBOM,
    provenance, and updater-verification tests pass.

- `SR-SUPPLY-003 (Must)` Security dependency exceptions must have an owner, exposure
  analysis, mitigation, expiry, and review date.
  - Acceptance: expired or incomplete exceptions fail the release gate.

- `SR-SUPPLY-004 (Must for 1.0)` An independent security review must cover crypto use,
  recovery, sync, IPC, desktop/browser, and mobile, with all critical/high findings
  resolved.
  - Acceptance: review scope and remediation evidence are linked from the release record.

## 4. Testing and Verification Requirements

- `TV-001 (Must)` All trust-boundary components (IPC, extension request validation, relay auth/pairing/sync handlers) must have automated negative-path tests.
  - Acceptance: CI runs tests and artifacts show coverage of reject cases.

- `TV-002 (Should)` Relay must have integration tests for push/pull sequencing, replay protection, and device revocation.
  - Acceptance: test suite simulates multi-device flows.

- `TV-003 (Should)` Security-sensitive crates/features must be included in fuzz/property-based testing where practical.
  - Acceptance: documented fuzz/property test targets and run commands.

- `TV-004 (Must)` Release readiness checklists must include docs/runtime alignment review for security claims.
  - Acceptance: release checklist references status matrix and gap review updates.

- `TV-005 (Must)` Every released schema and backup format must have migration/restore
  fixtures plus interruption and corruption tests.
  - Acceptance: CI exercises the complete supported compatibility window.

- `TV-006 (Must)` Sync must have model-based or equivalent state-machine tests plus chaos
  tests for loss, duplication, reordering, retry, concurrent edit, revocation, and crash.
  - Acceptance: convergence/integrity invariants pass for deterministic and randomized
    schedules.

- `TV-007 (Must)` Android JNI-enabled and iOS native bridge builds and functional tests
  must execute in CI rather than relying on default-feature Rust compilation.
  - Acceptance: a native symbol/signature mismatch prevents merge and release.

## 5. Operational Requirements

- `OP-001 (Must)` Self-host relay documentation must define minimum production deployment assumptions (TLS termination, storage path, backups, logs).
  - Acceptance: docs provide a supported baseline profile.

- `OP-002 (Should)` Relay should expose health and structured logs appropriate for self-hosting and managed hosting.
  - Acceptance: health endpoint documented; logs identify auth/rate-limit/cleanup events without leaking secrets.

- `OP-003 (Should)` Official builds should distinguish debug and release logging profiles across UI and extension.
  - Acceptance: build/release process documents log profile behavior.

## 6. Commercialization and Tiering Requirements

- `CM-001 (Must)` Trust-critical components (crypto, vault format, sync protocol, local client path) must remain open and auditable.
  - Acceptance: these components live in the public repo under OSS license.

- `CM-002 (Must)` Paid features must be additive and optional; local-first core must not require a paid service.
  - Acceptance: free tier remains functional without account or subscription.

- `CM-003 (Should)` Entitlement checks should control UX/capability access, not cryptographic correctness.
  - Acceptance: security behavior remains identical regardless of paid status for shared core paths.

- `CM-004 (Should)` Hosted relay service may be private, but protocol and self-host relay compatibility must remain documented and versioned.
  - Acceptance: hosted and self-host variants share protocol compatibility contract.

## 7. Repository and Governance Requirements

- `RG-001 (Must)` Public and private repos must share a stable interface contract (crates/APIs/protocol schemas) to avoid long-lived forks.
  - Acceptance: versioned compatibility matrix and contract tests exist.

- `RG-002 (Must)` Public repo is the source of truth for protocol definitions and trust-critical interfaces.
  - Acceptance: private repo consumes tagged public releases rather than maintaining divergent copies.

- `RG-003 (Should)` Roadmap, PRD, requirements, design, and implementation plan must be updated together for major direction changes.
  - Acceptance: linked docs and update date are maintained.

## 8. Traceability Map

- Historical gap reviews: `docs/GAP_REVIEW_2026-02-26.md`,
  `docs/GAP_REVIEW_2026-05-08.md`
- Current security evidence: `docs/SECURITY_STATUS_MATRIX.md`
- Product scope and packaging: `docs/PRD.md`
- Design response: `docs/SOLUTION_DESIGN.md`
- Active delivery sequencing: `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`
- Historical delivery plan: `docs/IMPLEMENTATION_PLAN.md`
- Long-range milestones: `ROADMAP.md`
- OSS/private repo model: `docs/OSS_COMMERCIAL_STRATEGY.md`
