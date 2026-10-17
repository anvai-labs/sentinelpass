# Independent custody authority/lifecycle review

Reviewed commit: `e69bc9bf8838222c2b032e4c414fee9ce5ed0eb9`.
Base: `84c7f58d012b428a4f8635d87ae988e0f1ebfc31` (develop).
PR: https://github.com/anvai-labs/sentinelpass/pull/269

Review scope was independently inspected from the actual source and base/head
diff, not accepted from prior implementation summaries. No repository source,
Git state, PR, external account, or real vault was changed. The existing
untracked IPC probe handoff was preserved.

## Assessment

No current KC-01/02 authority/lifecycle security blocker was identified. One
low-severity negative-test coverage issue is recorded below. This assessment
applies to the synthetic native storage/authority slice with production
enrollment unavailable; it is not production approval, platform qualification,
proof of absence of bugs, or the required GitHub code-owner approval.

## Finding

**Low: forged receiver assertion exercises an already invalidated lease.**

Location: `sentinelpass-core/src/custody/tests.rs:343`, in
`forged_receiver_cross_peer_and_restart_handles_are_denied`.

Sequence:

1. The test acquires one lease at line 328.
2. Delivering it to the foreign registry at line 334 correctly returns Denied.
   The armed DeliveryGuard closes that lease on the error path
   (`custody/mod.rs:263`, `custody/mod.rs:382`).
3. The assertion at line 343 presents an unregistered receiver ID using the
   same, already burned lease. It therefore returns Invalidated at the missing
   lease lookup (`custody/mod.rs:393`) before checking the receiver registry
   (`custody/mod.rs:403`).
4. The final invalidation assertion at line 349 also uses this burned lease.

Impact: the test passes without independently exercising its forged-ID branch.
This is a test blind spot, not an observed authorization bypass; actual source
contains the proper receiver lookup and exact scope/reference checks. Other
tests exercise lifecycle invalidation with live leases.

Suggested correction: acquire a fresh lease for each distinct negative case;
assert the new lease is live before presenting the forged receiver. Use another
live lease before the lifecycle invalidation case. Keep the cross-registry
denial separate so its expected one-shot burn cannot mask later assertions.

## Inspected boundaries

- Read the repository guidelines, security architecture/status caveats, full
  custody contract and handoff, KC-02 workcard/evidence review entry point, and
  implementation files below.
- `custody/mod.rs`: native secret ownership, opaque receiver/lease identities,
  exact scope/reference authorization, one delivery/in-flight operation,
  cancellation checks, expiration task ownership, close/drop cleanup,
  receiver disposal, durable revalidation before and after the asynchronous
  boundary, and final registry/lifecycle checks.
- `custody/personal.rs`: private source/approval/admin fields, operation
  commitment over domain separator/vault/action/full scope/expected and target
  references/source ID; authority-registry identity plus connection binding;
  one-use approval consumption; owner checks; source expiration; invalidation
  before mutation; shared grant registry and generation fencing.
- `custody/workers.rs`: immediate local/process admission limits; permits remain
  held when the waiter abandons blocked work; cancellation/lifecycle/deadline
  wakeups; dropped late owned results; PENDING/STOPPED/COMMITTING transition;
  accepted commit uncertainty; bounded best-effort audit dispatch.
- `daemon/ipc/stepup.rs`: reused commitment, connection, replay and expiry
  enforcement, plus new opaque-approval destruction/discard behavior.
- `daemon/vault_state.rs`: invalidation on manual lock, manager replacement,
  automatic lock and daemon drop; manager Arcs retained by workers do not
  restore native capability authority. Lock ordering does not introduce an
  observed authority-lock/storage-lock cycle in the inspected paths.
- `vault/custody_ops.rs`: authority checks after acquiring storage locks and
  immediately before commit, exact authenticated read, and fixed-field audit
  invocation. Full persistence/backup/rekey review is a separate reviewer scope.
- `audit.rs`: custody events use a closed operation enum and success boolean,
  with a fixed message. No scope, key bytes, object reference or approval ID is
  included in this event path. Put/remove/grant attempts and successful delivery
  are covered; this does not claim a complete audit of every failed lease read.
- Searched Rust call sites across protocol/core/daemon/UI/host/mobile crates:
  production code has no custody enrollment/source/approval/receiver constructor
  or generic secret-returning IPC operation. Public traits cannot manufacture
  the private capabilities. Existing service credentials and OIDC cannot mint
  them. Test constructors remain under cfg(test).
- Traced competing grant/mutation order: shared administrative worker admission
  and generation checks prevent registering a stale grant after a mutation's
  invalidation; final delivery checks reject a revoked registry. This review did
  not identify an exploitable ordering that bypasses those checks.

## Verification executed

- `git rev-parse HEAD`: exact reviewed head above.
- `git status --short`: only the pre-existing unrelated untracked handoff.
- `git diff --check 84c7f58..HEAD`: passed.
- `cargo test -p sentinelpass-core custody:: -- --nocapture`: **24 passed,
  0 failed, 2 ignored** (manual performance receipts intentionally not rerun).
  Includes real blocked storage, cancellation/abort/revoke, accepted-commit
  semantics, late-result disposal, daemon restart, metadata-only grant
  retention, replay denial, and actual audit canary checks.
- `cargo test -p sentinelpass-core daemon::ipc::stepup::tests:: -- --nocapture`:
  **5 passed**, covering expiry, connection binding, replay/operation binding,
  independent state keys and throttle engagement.
- Existing future-incompatibility warning for `block v0.1.6` appeared; no test
  failures. No full workspace/performance rerun was needed for this read-only
  review.

## Residual limits and future gates

- Enrollment must eventually enforce authenticated peer/channel identity,
  personal-vault selection, bounded pending sources/approvals, fresh trusted UI
  verification, and unique/shared per-owner/application authority. The current
  shared capacity registry is within one PersonalState; constructing multiple
  authorities for the same app/owner must not become a production bypass.
  Production authority construction is currently unavailable, so this is an
  enrollment gate rather than a presently reachable bypass.
- Root, same-UID privileged IPC access and injected approved native processes
  are outside the isolation claim; opaque Rust types are not a process sandbox.
- Stalled OS calls cannot be forcibly terminated. They can retain bounded native
  values and manager references until return. A write past the accepted commit
  transition may complete after cancellation; fresh authorization and outcome
  inspection are required before retry.
- Audit persistence is best effort. Failure/capacity loss can omit records, and
  successful delivery does not wait for audit persistence. This is documented
  and is not an authenticated new peer boundary.
- No native transport, browser worker transfer, hardware-backed execution,
  physical mobile qualification, relay sync, Sandesha recovery/fingerprint
  proof, migration proof or historical-mail authority was qualified here.
- Timing tests and synthetic hooks do not enumerate every real scheduler or
  filesystem interleaving. Current green CI remains separate evidence, and
  any subsequent source change needs corresponding validation/review.

## Follow-up: corrective working-tree diff

Reviewed the corrective working tree based on the same committed `e69bc9b`
head. This follow-up does not rewrite the original-head finding or claim the
uncommitted files have passed new exact-head CI.

The test correction resolves the finding: foreign-registry denial, forged-ID
denial and session invalidation now use independent fixtures/leases. The
forged-ID test explicitly checks that its lease is still registered and that
the forged receiver is absent before delivery, then checks the lease is burned
and no secret reaches the valid receiver. The invalidation test checks two live
handles before invalidation and zero afterward. No authority implementation
changed in these test corrections; no blocker was found in this diff.

Reviewed file SHA-256:

- `sentinelpass-core/src/custody/tests.rs`:
  `2c87a3d94bd18b6ce3000e759fa6a81085e6fd763a8feba859c368f6bf361318`

Also inspected the concurrent production diffs for authority implications:
map-only metadata deserialization preserves validation and denies the extra
positional-sequence representation; receipt enumeration bounds custody fields
before owned extraction and rejects duplicate identities instead of silently
overwriting them; envelope verification independently rejects duplicate object
IDs. These changes narrow accepted input/storage states and do not mint or
broaden native authority. Full reproducer acceptance for those findings belongs
to the independent persistence/contracts reviewer. Inspected hashes:

- `sentinelpass-protocol/src/custody.rs`:
  `6aa485900650fcfb8311157066819ccc052c0e43103c3a80e16ac55ab21c2299`
- `sentinelpass-core/src/vault/content_guard.rs`:
  `6647f4b532e139fb78c31c5538af862f2fe69c3bf2b8c2faa0d452cd098e4d47`
- `sentinelpass-core/src/vault/custody_ops.rs`:
  `aae3ef236ce40e7e45a1333f21b661c7e91027344493c80afdd8242d76cec50a`

This follow-up was source/diff inspection. The parent is running focused tests;
I did not duplicate them or compete with its test session. Final validation and
fresh CI must identify the eventual committed head.
