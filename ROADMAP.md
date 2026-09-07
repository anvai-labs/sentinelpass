# SentinelPass Roadmap

**Last Updated:** 2026-09-04

**Workspace Version (Cargo):** 0.8.0

**Roadmap Status:** Active security and recovery reset

## Purpose

This roadmap is the milestone view of the active
[strategic remediation plan](docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md). The
strategic plan owns detailed scope, sequencing, verification, and exit criteria.
Requirements and current implementation evidence remain in
`docs/REQUIREMENTS.md` and `docs/SECURITY_STATUS_MATRIX.md`.

## Product Strategy

SentinelPass will mature in this order:

1. Recoverable, authenticated local vault
2. Transactional persistence, backup, and restore
3. Single-authority daemon and capability-based IPC
4. Adversarially safe optional sync
5. Hardened desktop and browser experience
6. Production Android and iOS clients
7. Broader personal, sharing, and enterprise features

Feature growth does not outrank recovery, data integrity, or trust-boundary work.
Trust-critical components remain open and auditable. Paid features remain additive and
must not alter shared cryptographic correctness.

## Current Readiness

| Surface | Current status | Release posture |
|---------|----------------|-----------------|
| Local Rust core/CLI | Security preview | Continue hardening and migrate to envelope v2 |
| Desktop | Alpha/beta | Do not claim production readiness until daemon/IPC/lifecycle gates close |
| Browser extension | Alpha/beta | Opt-in; harden HTTP, field targeting, and native-host capability |
| Relay sync | Experimental | Disabled by default until sync protocol v2 gates pass |
| Android | Prototype | Not for production credentials |
| iOS | Prototype | Not for production credentials |
| Forgotten-password recovery | Planned | No old-password reset; recovery key-slot design required |

## Release Train

### 0.8.x: Containment and truthful status

- Keep sync opt-in/experimental and mobile prototype-labeled.
- Deny legacy originless browser IPC by default.
- Restrict non-TLS relay URLs to explicit loopback development.
- Align public claims, status matrix, requirements, technical debt, and release checks.
- Accept or revise ADR-003 through ADR-010 before dependent implementation.

**Exit:** unsafe incomplete paths cannot be enabled accidentally and claims match code.

### 0.9: Recovery and authenticated vault foundation

- Stable vault UUID, crypto epoch, and key-slot registry.
- Password, recovery, and platform/device key slots.
- Verified recovery-key onboarding and password replacement workflow.
- Authenticated summary/secret envelope v2 with semantic AAD.
- Bounded, versioned, language-neutral durable serialization.
- Hard KDF/decode limits and atomic password rotation.
- Verified legacy-to-v2 migration and fail-closed forward compatibility.

**Exit:** forgotten-password recovery works without storing the password; ciphertext
substitution fails; every released legacy schema migrates or fails safely.

### 0.10: Persistence, backup, daemon, IPC, and client hardening

- Transaction/unit-of-work boundary for all multi-table changes.
- Correct local vs remote write paths and nullable-field handling.
- Explicit file permissions/ACLs, owner checks, secret memory sweep, and audit integrity.
- Authenticated portable backup and verified restore.
- Daemon as sole desktop key/database owner.
- Audience/operation-scoped IPC capabilities, peer controls, deadlines, and concurrency.
- Desktop lifecycle/privacy/clipboard hardening.
- Browser HTTP/form/iframe/permission hardening and Chrome/Firefox parity.

**Exit:** crash injection cannot corrupt active data; restore drills pass; ordinary
same-user clients cannot claim native-host authority; desktop has one key owner.

### 0.11: Sync protocol v2 beta

- Per-object idempotent acknowledgements and distinct sequence/cursor types.
- Transactional client outbox/inbox and relay mutation processing.
- Authenticated object metadata, tombstones, epoch, and version lineage.
- Explicit secret conflicts; no timestamp-only silent overwrite.
- High-entropy QR or reviewed PAKE pairing.
- Device revocation and stale-epoch rejection.
- TLS/redirect/proxy enforcement and bounded relay quotas/resources.
- Model-based convergence and loss/duplicate/reorder/crash testing.

**Exit:** no accepted change is silently lost; malicious-relay metadata changes are
detected; recovery can revoke old online authority.

### 0.12: Mobile beta

- One generated/versioned C/JNI ABI with ownership, zeroization, and panic containment.
- Android JNI builds in CI for supported ABIs; Keystore slot and AutofillService.
- iOS Keychain slot and Credential Provider.
- Atomic update, lifecycle lock/privacy cover, safe clipboard, protected storage, and
  verified backup policy on both platforms.
- Real simulator/device tests for unlock, CRUD/update, lock, process death, biometric
  invalidation, sync, autofill, migration, and restore.

**Exit:** no release-reachable placeholder operations and applicable mobile security
controls have evidence.

### 1.0 RC: Assurance and independent audit

- Feature freeze and full security-relevant build matrix.
- Fuzz/property/chaos suites and historical restore fixtures.
- Security CI gates tag releases directly.
- Signed artifacts/checksums/updater metadata, SBOM, provenance, Windows signing, and
  macOS signing/notarization.
- Independent review of crypto use, recovery, sync, IPC, desktop/browser, and mobile.

**Exit:** zero unresolved critical/high findings and all recovery, restore, sync,
platform, and release gates pass.

### 1.0: Production baseline

- Release only after the 1.0 definition of done in the strategic plan is met.
- Publish supported platforms, threat-model limits, backup/recovery obligations, and
  compatibility windows.

## Post-Foundation Features

### Baseline completeness

- KeePass and Bitwarden import
- Encrypted import/export and backup scheduling
- Credential history and trash
- Custom fields and secure notes
- Device/session management
- Password rotation and recovery UI on every supported client

### Personal expansion

- Identities, cards, attachments, tags, and collections
- Privacy-preserving breach monitoring
- Emergency/social recovery
- Secure item sharing

### Deferred architecture programs

- Multi-user sharing, RBAC, and administrative recovery
- Enterprise policy, SSO, and SCIM
- Actual passkey private-key custody and synchronization

Passkey reference records remain metadata-only until a separate authenticator or
credential-provider architecture is accepted and reviewed.

## Quality and Security Gates

- Every trust-boundary change has a governing ADR, negative tests, and threat-model
  update.
- Every migration has fixtures for all supported prior versions and interruption tests.
- Security controls are not `Implemented` without code and automated evidence.
- Public protocol/format changes are versioned and carry compatibility notes.
- No release claim exceeds the status recorded in the security matrix.
- 1.0 has no unresolved critical/high trust-boundary finding.

## Planning Sources

- `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`: detailed active execution plan
- `docs/REQUIREMENTS.md`: traceable requirements and acceptance criteria
- `docs/SECURITY_STATUS_MATRIX.md`: current code/test evidence and residual risk
- `TECHNICAL_DEBT.md`: implementation gap tracker
- `docs/decisions/adr/README.md`: design decisions and status
- `docs/OSS_COMMERCIAL_STRATEGY.md`: open/free/paid operating model
