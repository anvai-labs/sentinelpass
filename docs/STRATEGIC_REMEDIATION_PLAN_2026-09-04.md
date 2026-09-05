# SentinelPass Strategic Remediation Plan

**Version:** 1.0

**Date:** 2026-09-04

**Status:** Active planning baseline

**Scope:** Core vault, recovery, persistence, sync/relay, daemon IPC, desktop,
browser extension, Android, iOS, testing, release engineering, and product gaps

## 1. Executive Direction

SentinelPass has a strong local-first foundation, but the current sync, recovery,
IPC, and mobile implementations are not yet suitable for production credentials.
The next cycle is a security-architecture program, not a feature-completion sprint.

Work is ordered by this fixed priority:

1. Security and recovery correctness
2. Persistence and synchronization resilience
3. Security-conscious UX
4. Baseline password-manager completeness
5. Sharing, enterprise, and true passkey-provider capabilities

The target product sequence is:

- production-ready local desktop and browser operation,
- recoverable encrypted backups,
- adversarially safe optional sync,
- production mobile clients,
- broader personal and organizational features.

Sync remains opt-in and experimental, and mobile remains prototype-status, until
their phase-specific release gates in this plan are met.

## 2. Strategic Invariants

- The master password is never stored, revealed, or recoverable. Recovery unwraps
  the vault data-encryption key (DEK) with an independent recovery credential and
  establishes a new password slot.
- Every ciphertext is cryptographically bound to its vault, record, purpose,
  version, and epoch with AEAD associated data (AAD).
- The daemon is the only live DEK owner and database writer on desktop.
- Sync is an idempotent, transactional state machine. Delivery retry, duplication,
  reordering, or interruption cannot silently lose an accepted change.
- The relay may observe bounded routing metadata but cannot silently change object
  identity, type, tombstone state, epoch, or authenticated version history.
- Platform biometric prompts are useful only when cryptographically bound to key
  release by the platform keystore.
- Unsupported controls fail closed, and documentation distinguishes Implemented,
  Partial, Experimental, and Planned behavior.
- No design claims protection from an administrator/root compromise, code injection
  into an unlocked process, or revocation of an offline vault snapshot already
  copied by an attacker.

## 3. Target Architecture and Dependency Order

```text
Threat model and security claims
              |
Recovery model and key slots
              |
Authenticated envelope v2 + schema migration
              |
Transactional persistence + backup/restore
              |
Daemon as sole key/database authority
        +-----+-------------------+
        |                         |
Desktop/browser capability IPC   Sync protocol v2 + relay
        |                         |
        +-------------+-----------+
                      |
             Stable mobile ABI
                      |
             Android and iOS clients
                      |
         External audit and 1.0 release
```

Recovery, envelope v2, and epoch semantics are the critical path. Sync, backup,
biometric, and mobile work must consume those decisions rather than define separate
key hierarchies.

## 4. Required Architecture Decisions

The following Proposed ADRs are design gates. Implementation begins only after the
relevant ADR is accepted:

- ADR-003: security baseline, supported threat model, and release gates
- ADR-004: recovery key slots, rotation, and revocation
- ADR-005: authenticated vault envelope v2 and migration
- ADR-006: sync protocol v2, conflict handling, and rollback resistance
- ADR-007: daemon authority and IPC capabilities
- ADR-008: authenticated backup and verified restore
- ADR-009: mobile ABI and platform-keystore boundary
- ADR-010: release signing, provenance, and audit assurance

## 5. Program Phases

### Phase 0: Containment and truthful status

**Target:** 1-2 weeks

**Release:** 0.8.x

Deliverables:

- Keep sync disabled by default and label it experimental.
- Label Android and iOS clients as prototypes, not daily-driver clients.
- Label recovery as unavailable; do not imply that the old password can be reset.
- Deny originless browser-surface IPC by default.
- Permit cleartext relay URLs only for an explicit loopback development profile.
- Correct claims about full-database encryption, memory locking, biometric parity,
  sync rollback protection, payload padding, and mobile completeness.
- Update the requirements, roadmap, technical-debt tracker, security matrix, and
  release checklist together.
- Assign an owner and target release to every P0/P1 item before implementation.

Exit criteria:

- Incomplete security features cannot be enabled accidentally.
- Public documentation matches runtime behavior.
- Every known gap has traceable ownership, acceptance criteria, and evidence fields.

### Phase 1: Recovery, key hierarchy, and authenticated vault format

**Target:** 5-8 weeks

**Release:** 0.9

Deliverables:

1. Add a stable vault UUID, explicit format version, and monotonic crypto epoch.
2. Add a key-slot registry for password, recovery, platform device/biometric, and
   trusted-device slots.
3. Generate a 128-256-bit recovery secret with checksum, printable form, QR form,
   and mandatory setup verification.
4. Bind every wrapped DEK to vault UUID, slot UUID/type, epoch, and crypto version.
5. Replace uncontextualized field encryption with versioned summary and secret
   envelopes whose AAD binds vault, entry, type, purpose, epoch, and format.
6. Replace long-lived `bincode` persistence with a documented, language-neutral,
   bounded serialization format.
7. Add hard maximums for KDF memory, time, parallelism, output size, and all decoded
   allocation lengths. Calibrate desktop and mobile KDF profiles above a common floor.
8. Make password rotation atomic: stage and verify new material, commit it, then
   adopt it in memory.
9. Fail closed on a newer unsupported schema or crypto format.

Migration contract:

1. Unlock and validate the legacy vault.
2. Create a verified pre-migration backup.
3. Build v2 tables beside legacy tables.
4. Generate stable identifiers and the initial password slot.
5. Re-encrypt every record with v2 AAD.
6. Decrypt and verify every migrated envelope and relationship.
7. Atomically activate v2 and retain the user-controlled encrypted backup.
8. Refuse downgrade opening from older clients.

Exit criteria:

- Cross-field, cross-record, cross-vault, and metadata substitution fail
  authentication.
- Recovery opens the vault without the old password and creates a new password slot.
- Failed migration leaves the legacy vault usable.
- Fixtures for every released schema migrate to the current format.
- Recovery, slot deletion, epoch change, and compromise rotation have negative tests.

### Phase 2: Transactional persistence, storage hygiene, audit, and backup

**Target:** 4-6 weeks; may overlap late Phase 1

**Release:** 0.9-0.10

Deliverables:

- Introduce application services and a unit-of-work boundary for credential CRUD,
  remote apply, slot rotation, recovery, backup, and restore.
- Remove multi-table write sequences from UI, sync, and ad hoc vault call sites.
- Replace local-change SQL-trigger side effects with explicit local and remote write
  paths, or otherwise prove that remote writes cannot be re-marked pending.
- Preserve SQL NULL through encryption, serialization, sync, and restore.
- Make registry/index updates transactional rather than best-effort.
- Set explicit application-directory, database, WAL/SHM, token, grants, audit,
  export, and backup permissions and Windows ACLs.
- Validate file owner, type, and symlink behavior before opening sensitive files.
- Replace title/domain audit context with opaque identifiers; add integrity chaining,
  rotation, retention, and verification.
- Zeroize intermediate KDF buffers, FFI buffers, and owned secret transport values.
- Remove unnecessary `Debug` and `Clone` from secret-bearing protocol structures.
- Create an authenticated portable backup containing the encrypted snapshot, key
  slots, format manifest, vault identity, epoch, and integrity metadata.
- Use SQLite snapshot/backup APIs rather than copying a live DB/WAL file set.
- Add atomic restore, validation, dry-run reporting, and recovery drills.

Exit criteria:

- Fault injection at each persistence step cannot corrupt the active vault.
- Restores from every supported format pass integrity and functional verification.
- No plaintext secret appears in normal logs, audit context, or crash diagnostics.
- All security-sensitive files receive explicit permissions and owner checks.

### Phase 3: Daemon ownership and capability-based IPC

**Target:** 4-6 weeks

**Release:** 0.10

Deliverables:

- Make the daemon the sole desktop DEK owner and database writer.
- Route CLI and desktop CRUD through application-service IPC.
- Reserve offline maintenance mode for an exclusive, explicitly stopped daemon.
- Replace self-asserted origin authorization with audience- and operation-scoped
  capabilities.
- Give the native host a distinct installation capability unavailable to ordinary
  CLI/external-tool clients.
- Retain least-privilege client/domain/field/write grants for external tools.
- Validate Unix peer UID where supported and apply owner-only socket permissions.
- Apply an explicit current-user SID ACL and remote-client rejection to Windows pipes.
- Derive directional session keys with HKDF; bind protocol version, direction,
  message type, session, and counter as AAD.
- Add connection/read/write/idle/operation deadlines, bounded concurrency, and replay
  counters.
- Run Argon2 and other blocking work in a bounded blocking pool.
- Replace poisoned-lock `unwrap()` paths with controlled errors and safe lock state.

Exit criteria:

- A client possessing only the general daemon token cannot claim native-host access.
- Stalled clients do not block unrelated clients.
- Replay, reflection, wrong-direction, malformed, and oversized frames are rejected.
- One daemon process owns all unlocked desktop key and database state.

### Phase 4: Sync protocol v2 and relay hardening

**Target:** 6-10 weeks

**Release:** 0.11 beta

Deliverables:

- Treat sync v1 as incompatible and re-bootstrap from an authoritative local v2 vault.
- Define a v2 mutation with vault UUID/epoch, entry UUID/type, expected and resulting
  versions, origin device, mutation idempotency key, tombstone, encrypted payload,
  authenticated metadata, and optional origin signature.
- Separate device request sequence, per-entry version, and server pagination cursor
  into distinct types and persistence fields.
- Return per-entry acceptance/rejection/current-version results.
- Remove an outbox item only after its specific acknowledgement.
- Make server mutation, entry, device sequence, and acknowledgement one transaction.
- Make client page apply, mappings, indexes, inbox record, and cursor one transaction.
- Support duplicate request replay by returning the original result.
- Use normal pagination for full sync; enforce limits consistently at client and relay.
- Preserve conflicting secret versions rather than silently resolving solely by time.
- Authenticate tombstones and define deletion retention/garbage collection.
- Include crypto epoch in every request/object and reject revoked devices/stale epochs.
- Add per-entry version/hash lineage and retain a trusted local high-water mark.
- Replace six-digit encryption with a high-entropy QR bootstrap secret or reviewed
  PAKE; retain a short code only as a human comparison value.
- Put pairing material in request bodies, make it one-use and short-lived, and bind
  registration to the pairing transcript.
- Require HTTPS except explicit loopback development, restrict redirects, and reject
  userinfo in relay URLs.
- Trust forwarded IP addresses only from configured proxies.
- Enforce bounded per-vault/device quotas, blob sizes, entry counts, pairing counts,
  and rate-limit state.
- Remove blocking single-connection database access from async relay handlers.
- Publish a supported self-host profile for TLS, proxying, data backup, logs, metrics,
  retention, and disaster recovery.

Exit criteria:

- Model/chaos tests converge under loss, duplication, reordering, retries, concurrent
  edits, stale devices, and crashes.
- No local item is marked synced without a per-object acknowledgement.
- A malicious relay cannot undetectably change identity, type, tombstone, epoch, or
  authenticated version lineage.
- Recovery and compromise workflows revoke prior online sync authority.

### Phase 5: Desktop and browser hardening

**Target:** 4-6 weeks

**Release:** 0.10-0.11

Desktop deliverables:

- Store summaries in UI state and use short-lived reveal/copy handles for secrets.
  *(Amended 2026-09-04 by ADR-005 rev 4 acceptance: the summary index is daemon-owned,
  lazy, and zeroized on lock; the desktop UI re-requests summaries rather than
  caching its own copy.)*
- Scrub DOM fields, JavaScript state, TOTP state, and timers on lock.
- Lock on configured inactivity, background, OS session lock, suspend, and logout.
- Install a privacy cover before the app loses visibility.
- Require configurable reauthentication for reveal, export, recovery, and private keys.
- Parse URLs structurally and refuse or warn on HTTP.
- Minimize Tauri capabilities and CSP; remove unused shell/clipboard permissions.
- Remove production debug-unlock artifacts.
- Use native sensitive clipboard behavior with expiry where available.
- Replace Windows consent-plus-generic-keyring retrieval with key release bound to
  Windows Hello or an approved Windows cryptographic protection API.

Browser deliverables:

- Default-deny HTTP autofill with an explicit per-site override only if retained.
- Use optional/requested site access where feasible instead of unconditional broad
  host permissions.
- Carry a stable field/form descriptor through autofill requests and responses.
- Respect `autocomplete` semantics and never choose the first password field blindly.
- Require a chooser for ambiguous or password-change forms.
- Define explicit top-level and iframe policy.
- Eliminate or minimize plaintext credential data in extension session storage.
- Generate Chrome and Firefox bundles from shared source.
- Validate browser/native-host identifiers and manifest parity in CI.

Exit criteria:

- Lock reliably removes secrets from visible UI and ordinary state snapshots.
- Browser tests cover login, password change, iframe, HTTP, hostile sender, locked
  daemon, save/update, and Chrome/Firefox parity.
- Desktop and extension consume only daemon capability APIs.

### Phase 6: Android and iOS production readiness

**Target:** 10-16 weeks with parallel platform work

**Release:** 0.12 beta

Shared bridge deliverables:

- Define one generated C ABI and one JNI package/class contract.
- Add ABI version and feature negotiation.
- Compile every platform feature in CI, including JNI.
- Define typed ownership for handles and returned buffers; zeroize on free.
- Catch panics at FFI boundaries and test repeated create/lock/destroy cycles.
- Replace delete-then-add edits with atomic updates.
- Remove placeholder biometric and sync operations.
- Implement sync v2 through the shared Rust engine.

Android deliverables:

- Fix JNI name/signature/type mismatches and build every supported ABI.
- Use Android Keystore authentication-bound keys for the platform slot.
- Implement AutofillService retrieval and save flows.
- Lock and cover on background, screen lock, reboot, and configured inactivity.
- Deny cleartext network traffic through network security configuration.
- Use `noBackupFilesDir` or a tested encrypted backup allowlist covering WAL/SHM and
  device transfer.
- Remove camera/network permissions until their features exist.
- Add instrumentation tests for JNI, keystore invalidation, process death, lifecycle,
  backup/restore, migration, and autofill.

iOS deliverables:

- Use Keychain `SecAccessControl` for the platform slot and enrollment-change policy.
- Apply explicit complete file protection and backup policy.
- Lock and cover content on scene transitions.
- Use local-only/expiring pasteboard options.
- Implement a Credential Provider extension.
- Remove unused plaintext credential persistence models.
- Consolidate duplicate Swift bridges.
- Implement encrypted backup/export; gate and clearly label plaintext export.
- Add XCTest coverage for restart, enrollment changes, backgrounding, clipboard,
  Credential Provider, migration, and restore.

Exit criteria:

- No placeholder native operation is reachable in a release build.
- Real device/simulator tests cover unlock, CRUD/update, lock, process death,
  biometric invalidation, sync, and autofill.
- Backup behavior is documented and verified.
- Applicable OWASP MASVS controls are reviewed with evidence.

### Phase 7: Release assurance and independent review

**Target:** 4-6 weeks after feature freeze

**Release:** 1.0 release candidate

Deliverables:

- Make security workflows direct prerequisites of tag releases.
- Test all security-relevant Cargo feature combinations and mobile targets.
- Run dependency, secret, license, container, and artifact scanning.
- Add fuzz targets for envelopes, migrations, IPC, sync, imports, and FFI.
- Add property tests for vault operations and sync convergence.
- Produce signed SBOM and provenance attestations.
- Sign Windows binaries/installers and sign/notarize macOS applications.
- Sign updater metadata and verify it before installation.
- Give every dependency-security exception an owner, exposure analysis, mitigation,
  and expiry.
- Commission an independent assessment of crypto use, recovery, sync, IPC, desktop,
  browser, Android, and iOS.
- Resolve all critical/high findings before 1.0.

Exit criteria:

- Zero unresolved critical/high trust-boundary findings.
- Recovery and restore drills pass on every supported platform.
- Sync model/chaos suites pass.
- Release signatures, provenance, notarization, and updater verification pass.
- Security documentation matches code and automated evidence.

## 6. Data and API Design Rules

- Use stable UUIDs for vaults, entries, devices, slots, and mutations.
- Separate display summaries from secret payloads, but authenticate both contexts.
- Store domain originals encrypted and use keyed equality tags for lookup.
- Use explicit nullable types end to end; never encode absence as an empty ciphertext.
- Validate timestamps and reject corrupt values instead of substituting current time.
- Put algorithm, schema, and payload versions inside every durable envelope.
- Apply maximum encoded/decoded sizes before allocation.
- Return the least secret data necessary for an operation.
- Use scoped reveal/copy/fill capabilities instead of returning a complete entry.
- Keep protocol, backup, and FFI schemas language-neutral and versioned.

## 7. UX Work After the Security Foundation

Onboarding must:

- explain that the old master password cannot be recovered,
- create and verify the recovery key,
- explain backup and device-revocation limits,
- calibrate the KDF above a security floor,
- require password and recovery slots before enabling biometric unlock.

Daily UX must provide:

- consistent locked/unlocked state across daemon, desktop, browser, and mobile,
- understandable reauthentication reasons,
- HTTP and ambiguous-form warnings,
- actionable offline/retry/conflict/revoked-device states,
- safe reveal/copy actions without persistent secret state.

Add a Security Center showing recovery verification, backup age and restore status,
KDF health, devices, epoch, sync/conflicts, biometric slots, password health, security
events, and recent exports/recovery actions.

## 8. Feature Expansion After Foundation Work

Baseline completion:

- encrypted backup/import/export,
- KeePass and Bitwarden imports,
- native Android/iOS autofill,
- credential history and trash,
- custom fields and secure notes,
- device/session management,
- password rotation and recovery UI on all clients.

Later personal features:

- identities, payment cards, attachments, tags, and collections,
- privacy-preserving breach monitoring,
- emergency/social recovery,
- secure item sharing.

Defer until separately designed:

- organization sharing, RBAC, and administrative recovery,
- enterprise policy/SSO/SCIM,
- custody and synchronization of passkey private keys.

`passkey_reference` remains metadata only until an authenticator/credential-provider
architecture is accepted and independently reviewed.

## 9. Verification Matrix

| Boundary | Required evidence |
|----------|-------------------|
| Vault crypto | Golden vectors, AAD substitution negatives, fuzzing, migration fixtures |
| Recovery | Lost-password, lost-device, revoked-slot, compromise-rotation drills |
| Persistence | Transaction fault injection, corruption tests, verified restore |
| IPC | Peer/capability negatives, ACL tests, replay/deadline/concurrency tests |
| Sync | Model-based convergence plus loss/duplicate/reorder/crash chaos tests |
| Browser | Chromium and Firefox E2E across hostile and ambiguous forms |
| Android | JNI feature build, instrumentation, keystore, autofill, lifecycle, restore |
| iOS | XCTest, Keychain invalidation, Credential Provider, lifecycle, restore |
| Release | Signed artifacts, SBOM, provenance, updater verification, clean audit gate |

## 10. Governance and Traceability

Every work item must carry:

- requirement ID and priority,
- threat or user need,
- owner and target release,
- governing ADR,
- implementation and test evidence,
- migration and compatibility impact,
- documentation impact,
- status and accepted residual risk.

No security item is `Implemented` merely because code exists. It also needs relevant
positive/negative tests and operational/documentation evidence.

## 11. Resourcing and Release Train

With three senior engineers (core/security, desktop/browser, mobile), fractional
product design, and an external review, a credible 1.0 is approximately 7-10 months.
A single engineer should plan approximately 12-18 months and ship the local desktop
foundation before sync or mobile.

| Release | Intended scope |
|---------|----------------|
| 0.8.x | Containment, truthful status, safer defaults |
| 0.9 | Key slots, recovery, envelope/schema v2, migration |
| 0.10 | Transactions, backup, daemon ownership, IPC, desktop/browser hardening |
| 0.11 | Sync protocol v2 beta and relay operations |
| 0.12 | Android/iOS beta and native autofill |
| 1.0 RC | Feature freeze, independent audit, signing, recovery/restore drills |
| 1.0 | Release only after all security gates close |

## 12. Definition of Done for 1.0

- Recovery is independent of the old password and verified during onboarding.
- Local and sync ciphertext semantics are authenticated.
- Database migration, backup, restore, and crash recovery are proven across supported
  versions and platforms.
- The daemon is the sole desktop key/database authority with capability IPC.
- Sync is transactional, idempotent, revocable, rollback-resistant, and opt-in.
- Desktop, browser, Android, and iOS pass their platform security gates.
- Release artifacts and updater metadata are signed and independently verifiable.
- No critical/high independent-audit finding remains unresolved.
- Public documentation and the security status matrix match shipped behavior.
