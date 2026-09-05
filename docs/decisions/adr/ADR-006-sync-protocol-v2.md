# ADR-006: Transactional Sync Protocol v2

| Field | Value |
|-------|-------|
| Status | Proposed |
| Date | 2026-09-04 |
| Owners | Core maintainer, relay maintainer, security lead |
| Related | ADR-003; ADR-004; ADR-005; ADR-008 |

## Summary

Replace best-effort last-write-wins synchronization with a transactional, idempotent,
epoch-aware mutation protocol that remains confidential and detects relay tampering.

## Context

The current client marks every submitted item synced even when some are rejected,
mixes device and server sequence domains, applies remote writes through local-change
triggers, mishandles nullable encrypted fields, and does not authenticate routing,
version, origin, or tombstone metadata. Six-digit HKDF pairing is offline-guessable.

## Decision

A v2 mutation carries vault UUID/epoch, stable object UUID/type, expected and resulting
versions, origin device, mutation idempotency key, authenticated tombstone state,
encrypted payload, and authenticated metadata. Device request sequence, object version,
and relay pagination cursor are distinct types.

Push responses return a durable per-object result. Client outbox entries are removed
only after their own acknowledgement. Relay mutation/entry/sequence/acknowledgement
writes are atomic; client page/inbox/object/index/cursor writes are atomic. Duplicate
requests return their original result.

Concurrent secret edits preserve both versions for user resolution. Epoch and device
revocation are checked on every request. Clients retain trusted high-water state and
verify authenticated version lineage. Full synchronization uses normal bounded pages.

Pairing uses a high-entropy QR secret or reviewed PAKE. A short numeric value may be
used only for human transcript comparison. Remote relay connections require TLS.

## Options Considered

- Patch v1 counters and retain aggregate acknowledgements: rejected as insufficient.
- Server timestamp last-write-wins: rejected for secret conflicts and malicious-relay
  rollback.
- Transactional mutation log with client-visible conflicts: proposed.

## Threat Model

Addresses lost responses, retry, duplication, reordering, concurrent edits, crashes,
stale/revoked devices, offline pairing capture, and malicious relay metadata changes.
The relay still observes bounded routing metadata and traffic timing/volume.

## MVP vs. Later

- MVP: credential/TOTP/SSH objects, tombstones, idempotency, conflicts, revocation.
- Later: optional metadata padding, multi-user authorization, and sharing semantics.

## Migration and Rollout

Sync v1 is not trusted as migration authority. A successfully migrated local vault is
selected as authoritative, v1 relay state is retired, devices re-pair under the new
epoch, and data is uploaded through normal v2 mutations. Mixed v1/v2 sync is forbidden.

## Consequences

The relay and every client require coordinated protocol changes. Sync stays disabled
by default until model-based and chaos tests demonstrate convergence and rollback
detection.
