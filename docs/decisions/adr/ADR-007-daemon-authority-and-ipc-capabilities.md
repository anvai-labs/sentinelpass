# ADR-007: Daemon Authority and IPC Capabilities

| Field | Value |
|-------|-------|
| Status | Accepted (rev 2, 2026-09-08 — owner decision after adversarial review round 1; amendments folded) |
| Date | 2026-09-07 |
| Owners | Core maintainer, desktop maintainer, security lead |
| Related | ADR-003; ADR-004; ADR-005 |

## Summary

Make the daemon the sole desktop key/database authority and replace self-asserted IPC
origin labels with authenticated, least-privilege capabilities.

## Context

The desktop UI and daemon can independently open a vault, duplicating unlocked DEKs
and write authority. IPC authenticates a general token, while browser access also
depends on a client-controlled origin label; originless browser requests have been
denied by default since 0.8.x (the `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1` escape
hatch is removed in 1.0). The remaining gap is that the origin label is
client-controlled and the token is ambient authority. The Unix accept loop is serial
and lacks read deadlines; Windows pipe ACLs are not explicit.

## Decision

The daemon owns unlock state, key slots, persistence, sync, backup, recovery, and audit
on desktop. UI, CLI, and native host use application-service IPC. Vault
creation/onboarding and offline maintenance run as exclusive offline operations under a
defined mutual-exclusion mechanism: an advisory lock beside the vault, held by the
daemon for its lifetime, so a live daemon refuses coexistence and the offline process
refuses while the lock is held. During offline maintenance, audit ownership transfers
to the exclusive maintenance process.

Capabilities bind audience, operation, resource scope, issue time, expiry, and nonce.
The native host receives an installation-specific capability not available to general
clients. In the MVP, without process attestation, the native-host capability is damage
limitation per ADR-003 rev 2: it carries audience, expiry, rotation, and audit; its
resource scope is effectively all domains; WBS-505's negative test holds for clients
lacking the material. External tools retain explicit client/domain/field/write grants.
Grants persist in the daemon store; restart does not silently resurrect revoked grants.
Origin is provenance only and cannot authorize an operation.

IPC additionally uses platform peer controls, explicit Windows current-user SID ACLs,
directional session keys, authenticated counters/context, bounded frame sizes,
deadlines, replay protection, and bounded per-client concurrency. Unix sockets live in
an owner-only directory (created/verified 0700 at bind); the /tmp fallback is removed
and both daemon and clients refuse sockets outside a private runtime directory.
Windows pipe-name first-instance creation (squatting protection) is in WBS-508 scope;
an explicit DACL alone does not prevent name squatting. Blocking KDF work and SQLite
I/O run outside the asynchronous executor, with KDF concurrency cross-referencing
ADR-004 rev 5's one-Argon2id-per-vault pool.

## Options Considered

- Keep a shared token plus origin enum: rejected because the origin is forgeable.
- Rely only on filesystem/pipe ACLs: rejected because operation scoping and revocation
  remain necessary.
- A daemon no-vault bootstrap mode for creation/onboarding: considered as the
  alternative to the advisory-lock mutual exclusion; not chosen for the MVP.
- Platform peer controls plus cryptographic capabilities: proposed.

## Threat Model

Reduces access available to ordinary same-user processes, stale clients, replayed
frames, and denial by stalled connections. It does not defeat administrator/root,
debugger access, injection into the daemon, or compromise of an unlocked client with
a valid scoped capability.

## MVP vs. Later

- MVP: single daemon authority, native-host capability, peer identity, ACLs, deadlines.
- Later: optional code-signature/process attestation where stable platform support
  justifies the complexity.

## Migration and Rollout

Introduce versioned capability-aware IPC while legacy clients are updated in one
release train. Originless browser-surface denial (landed 0.8.x) is subsumed;
capabilities replace the forgeable origin label. After all official clients migrate,
remove the compatibility path and rotate installation credentials; the legacy tcp://
loopback branch is removed in Phase 3.

During the transition, shipped UI/CLI binaries may still write the vault directly; the
interim cross-process invariant is the open-time epoch guard plus stale-epoch UPDATE
guards, both fail-closed. The daemon must not claim sole-writer authority until
direct-write paths are gone from shipped binaries; the daemon-owned summary index
(ADR-005) tolerates no legacy writers, which bounds the window.

## Consequences

CLI and desktop behavior depend on daemon availability, so supervision, upgrades, and
recovery-mode UX must be reliable. The security boundary becomes clearer and unlocked
key/database state is no longer split across processes.
