# ADR-007: Daemon Authority and IPC Capabilities

| Field | Value |
|-------|-------|
| Status | Proposed |
| Date | 2026-09-04 |
| Owners | Core maintainer, desktop maintainer, security lead |
| Related | ADR-003; ADR-004; ADR-005 |

## Summary

Make the daemon the sole desktop key/database authority and replace self-asserted IPC
origin labels with authenticated, least-privilege capabilities.

## Context

The desktop UI and daemon can independently open a vault, duplicating unlocked DEKs
and write authority. IPC authenticates a general token, while browser access also
depends on a client-controlled origin label and currently permits legacy originless
requests. The Unix accept loop is serial and lacks read deadlines; Windows pipe ACLs
are not explicit.

## Decision

The daemon owns unlock state, key slots, persistence, sync, backup, recovery, and audit
on desktop. UI, CLI, and native host use application-service IPC. Offline maintenance
requires exclusive vault locking and a stopped daemon.

Capabilities bind audience, operation, resource scope, issue time, expiry, and nonce.
The native host receives an installation-specific capability not available to general
clients. External tools retain explicit client/domain/field/write grants. Origin is
provenance only and cannot authorize an operation.

IPC additionally uses platform peer controls, explicit Windows current-user SID ACLs,
owner-only Unix sockets, directional session keys, authenticated counters/context,
bounded frame sizes, deadlines, replay protection, and bounded per-client concurrency.
Blocking KDF work runs outside the asynchronous executor.

## Options Considered

- Keep a shared token plus origin enum: rejected because the origin is forgeable.
- Rely only on filesystem/pipe ACLs: rejected because operation scoping and revocation
  remain necessary.
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
release train. Originless browser requests become denied first. After all official
clients migrate, remove the compatibility path and rotate installation credentials.

## Consequences

CLI and desktop behavior depend on daemon availability, so supervision, upgrades, and
recovery-mode UX must be reliable. The security boundary becomes clearer and unlocked
key/database state is no longer split across processes.
