# ADR-006: Transactional Sync Protocol v2

| Field | Value |
|-------|-------|
| Status | Proposed (rev 2, 2026-09-07 — folds adversarial review round 1; awaiting owner acceptance) |
| Date | 2026-09-07 |
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

As of rev 2: the local trigger-echo defect has been removed (schema v9) and null
handling is partially fixed on the apply path; the transactional/repository gap
remains what v2 replaces.

## Decision

A v2 mutation carries vault UUID/epoch, stable object UUID/type, expected and resulting
versions, origin device, mutation idempotency key, authenticated tombstone state,
encrypted payload, and authenticated metadata. Device request sequence, object version,
and relay pagination cursor are distinct types. Mutation authentication is a
DEK-derived MAC over canonical shared metadata (vault/object UUIDs, versions, epoch,
tombstone state) and is distinct from the per-device storage envelope of ADR-005; wire
objects never carry another device's storage envelope.

Push responses return a durable per-object result. Client outbox entries are removed
only after their own acknowledgement. Relay mutation/entry/sequence/acknowledgement
writes are atomic; client page/inbox/object/index/cursor writes are atomic. Duplicate
requests return their original result. Idempotency records are bounded and aged; after
expiry a duplicate is rejected rather than replayed.

On pull, mutations that cannot be applied go to a durable, size-bounded requeue or
dead-letter; the cursor never advances past an unappliable mutation.

Concurrent secret edits preserve both versions for user resolution. Epoch and device
revocation are checked on every request. Clients retain a trusted sync-lineage
high-water (distinct from the ADR-004 epoch sidecar) and reject version lineage below
it. Full synchronization uses normal bounded pages.

Pairing uses a high-entropy QR secret or reviewed PAKE. A short numeric value may be
used only for human transcript comparison. Remote relay connections require TLS with
bounded, safe redirect behavior and no credentials in URLs (SR-SYNC-007).

A restored vault (ADR-008) rejoins sync only through v2 re-pairing; restored sync
state, including the lineage high-water, is re-derived, not trusted.

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
- Later: revocation/recovery notification to remaining devices — the channel ADR-004
  rev 5 defers to sync v2; delivering it here discharges that deferral.

## Migration and Rollout

Sync v1 is not trusted as migration authority. The user selects exactly one migrated
device as authoritative; all other devices re-onboard exclusively through its v2
pairing bootstrap (epoch-bound) and never upload from pre-migration state; a second
device attempting an authoritative claim against an already-rebaselined relay epoch is
refused.

Retirement of v1 relay state is client-side abandonment of the old relay vault id; old
encrypted blobs persist relay-side as an accepted residual (the shipped relay has no
purge endpoint, mirroring ADR-004 rev 4). Devices re-pair under the new epoch, and
data is uploaded through normal v2 mutations.

Mixed-protocol operation is forbidden with fail-closed duties on both sides: the relay
hard-rejects v1-shaped requests; clients refuse v1-shaped responses.

## Consequences

The relay and every client require coordinated protocol changes. Sync stays disabled
by default until model-based and chaos tests demonstrate convergence and rollback
detection.
