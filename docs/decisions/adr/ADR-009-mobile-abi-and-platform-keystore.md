# ADR-009: Mobile ABI and Platform-Keystore Boundary

| Field | Value |
|-------|-------|
| Status | Accepted (rev 2, 2026-09-08 — owner decision after adversarial review round 1; amendments folded) |
| Date | 2026-09-07 |
| Owners | Mobile maintainers, core maintainer, security lead |
| Related | ADR-004; ADR-005; ADR-006; ADR-008 |

## Summary

Use one generated, versioned native ABI and make Android Keystore/iOS Keychain keys
the cryptographic boundary for mobile convenience unlock.

## Context

Android JNI names and enabled build features do not currently align, JNI-enabled Rust
does not compile, and autofill/biometric/sync operations include placeholders. iOS
biometric state is process-local, bridge sources are duplicated, lifecycle lock and
Credential Provider are absent, and backup/file-protection policy is incomplete.

## Decision

The Rust bridge exposes one versioned C ABI and one declared JNI class/package mapping.
Headers/bindings are generated, not copied: one declared binding generator is
committed to when WBS-801 stabilizes the ABI, and checked-in header copies plus
committed `.a`/xcframework binaries are deleted — consumed artifacts are CI-generated
(WBS-801/820 scope). All handles and returned buffers have explicit ownership,
zeroizing destruction, error contracts, panic containment, ABI version negotiation,
and feature negotiation.

The bridge implements atomic core operations and sync v2; native clients do not
reimplement vault cryptography. Mobile sync is relay-based sync v2 (ADR-006, TLS)
only; the CloudKit/Drive file-sync bridge paths are removed or compiled out of release
builds under WBS-807, and mobile backup uses only the ADR-008 bundle format. Android
uses authentication-bound Keystore keys and iOS uses Keychain `SecAccessControl` keys
to wrap platform key slots, with a hardware-assurance floor: TEE-backed Keystore /
Secure Enclave is the minimum where the hardware offers it, and slot creation on a
software-only fallback is documented or refused. A successful UI prompt alone is not
sufficient unless it authorizes the cryptographic operation.

Each client implements platform lifecycle locking, privacy cover, protected storage,
safe clipboard behavior, native autofill/credential-provider integration, and verified
backup policy.

On-device Argon2id calibration is in scope: `mobile_profile()` is published guidance,
not calibrated (WBS-307). Phase 6 records wall-clock calibration evidence on
representative Android/iOS hardware, defines pair-join adopted-parameter ceilings for
constrained devices, and specifies refusal behavior when the 64,000 KiB hard memory
floor is not executable (explicit error; no silent downgrade below MIN).

## Options Considered

- Maintain handwritten duplicate bindings: rejected due to ABI drift.
- Store DEK material after an independent biometric prompt: rejected because key
  release is not cryptographically bound to user presence.
- Shared Rust core with thin, platform-secure adapters: proposed.

## Threat Model

Addresses process restart, stale/leaked handles, enrollment changes, background
snapshots, insecure platform backup, ABI mismatch, FFI panic, and ordinary app-level
secret remnants. It does not defeat rooted/jailbroken devices or an injected unlocked
process; those conditions require explicit risk messaging.

## MVP vs. Later

- MVP: unlock/CRUD/update/lock, platform slot, process death, backup, sync, autofill.
- Later: richer platform sharing, actual passkey-provider custody, and enterprise
  device posture.

## Migration and Rollout

Stabilize envelope v2 and daemon/application-service semantics first. Fix and test the
bridge contract, then implement Android and iOS in parallel. Bridge sync operations
ship only after sync v2 (ADR-006/WBS-600) lands. No placeholder operation is present
in a release build. Gate evidence is classified: platform-key-release,
enrollment-invalidation, and backup-exclusion gates require device evidence (or
explicitly justified emulator runs naming the keystore security tier); UI, lifecycle,
and autofill flows may pass on simulator/emulator. Prototype status lifts only when
the Phase 6 gate evidence (WBS-818/828) exists.

## Consequences

Mobile release moves later, but core behavior and crypto stay consistent. Platform code
focuses on lifecycle, keystore, autofill, backup, and UX rather than duplicating vault
logic.
