# KC-02: personal custody storage and native authority

Frozen 2026-10-16 before implementation, following KC-01 on
`feat/personal-custody-contract`. Synthetic data only; no live enrollment.

## Storage decisions

- Dedicated `custody_objects` table, schema 14. Never a password entry, service
  grant, operator credential, sync payload, or replacement for a mailbox key.
- Exact scope and reference metadata are canonical typed JSON. An SPENV
  `personal_custody` envelope authenticates the vault UUID and a SHA-256
  commitment to both complete metadata objects. Only the independent 32-byte
  recovery value is encrypted. Metadata is not confidential.
- One immutable object ID per vault; updates retain scope/object identity,
  increment revision by exactly one and cannot decrease the mailbox key epoch.
  Insert requires absence; update/delete require an authenticated exact reference.
  Deleted identities remain authenticated tombstones and cannot be reused.
- Use the existing content transaction/receipt mechanism for complete metadata,
  ciphertext and tombstones. No independent mutation or synchronization log.
- Include custody in deep backup verification and fresh-DEK rotation. Generic
  entry listing/export never includes it. Existing whole-vault backup contains
  encrypted objects; application portable export remains unavailable.

## Authority decisions

Native administrative source and approval capabilities have private constructors.
The synthetic trusted-UI harness verifies a fresh password through the existing
vault open path, then uses ADR-013's connection/operation-bound, single-use,
60-second approval. No unlocked-state or biometric substitute. Every put/remove
and read authorization consumes approval, regardless of daemon profile. A read
handle cannot obtain a mutation capability. No new JSON secret transport.

Lock, replacement, revoke and drop invalidate registered native sessions and wipe
their values. The daemon lifecycle must fence sessions even while an Arc to the
old vault manager survives. Production enrollment/IPC and platform capabilities
stay unavailable until their separate trusted-UI/transport review passes.

## Red-first acceptance

Storage tests cover exact recovery bytes without printing them, wrong owner and
purpose, metadata/ciphertext substitution, stale CAS, duplicate identity,
tombstone resurrection, transaction failure, reopen/receipt rollback, backup
verification and fresh-DEK rotation. Authority tests cover fresh password denial,
approval mismatch/replay, lock/revoke/late delivery, and read/mutation separation.
Existing KC-01 conformance remains required. Performance limits remain unchanged;
password/KDF time must be reported separately from warm native delivery.

Fresh adversarial review and exact-head CI are merge gates. No release, platform
qualification, mobile sync, browser transport or real mailbox activation follows
from this workcard.

## Scheduling follow-up (frozen before implementation)

Move SQLite, receipt locks and audit I/O off async executor/lifecycle locks.
Fail capacity immediately, with at most 8 read workers per session, one admin
worker per owner/application and 64 custody workers process-wide. Abandoned
blocking work retains its permit until it exits; repeated cancellation cannot
create an unbounded queue. No attempt to forcibly interrupt an OS filesystem call.

Waiters respond to cancellation, absolute deadlines and lifecycle invalidation.
Late secret results are zeroized and never published. Before commit, mutation
cancellation must roll back the transaction. Once the explicit pre-commit check
accepts a write, commit/receipt finalization may finish even if the waiter departs;
the result is then uncertain to that caller and must be inspected with fresh
authorization, never automatically retried. No authority lock spans disk I/O.

Red-first checks cover a blocked worker on a single-thread executor, prompt lock
and cancellation, late output disposal, permits held after abandonment, mutation
cancellation before commit, and the accepted-commit boundary. Re-run unchanged
functional and performance gates; no relaxed latency/RSS limits.

## Grant-retention follow-up (frozen before implementation)

Durable read grants retain exact metadata only, never a plaintext recovery-secret
cache. Authenticate the row when granting and discard the temporary value on its
blocking worker. Delivery loads the value into its bounded operation and receiver.
Only the KC-01 in-memory test adapter may retain synthetic backing values.
Add regression coverage for metadata-only grants, authentic delivery after close,
restart rejection of old approvals/sources/read handles, and synthetic canary
absence in persisted audit output. Keep production constructors unavailable.

## Adversarial-review follow-up

Fresh independent automated reviews of candidate `e69bc9b` identified a custody
receipt rollback via duplicate IDs after offline schema replacement, an alternate
positional-array metadata shape accepted by Rust/native validation, and a negative
test that reused an already burned lease. Preserve the failing synthetic
reproducers before correction. Reject duplicate identities in receipt and deep
snapshot verification, apply existing borrowed-row bounds before receipt copies,
require JSON objects at every metadata port, and isolate each lease denial case.
Keep receipt bytes for valid unique rows, schema/ABI versions, capability gates and
performance limits unchanged. Record corrective review, refreshed receipts and
fresh exact-head CI; automated technical review does not supply code-owner approval.
