# KC-01: scoped personal custody contract

Frozen 2026-10-16 before implementation, against develop
`84c7f58d012b428a4f8635d87ae988e0f1ebfc31` (remote checked).
Implements the first ordered gate of
[the custody handoff](SANDESHA_USER_KEY_CUSTODY_HANDOFF_2026-10-16.md).

The initial deliverable is a neutral Rust metadata contract, generated bindings,
and an in-process synthetic adapter exercising native ownership and lifecycle.
No production provider is enabled by this slice. KC-02 requires KC-01 acceptance;
platform, browser, recovery, migration and sync qualification remain later gates.

## Frozen decisions

- Protocol 1. Exact immutable namespace, issuer, subject, mailbox and purpose;
  no aliases, normalization, wildcard grants or OIDC-derived authority.
- Separate `mail-recovery` and `storage-recovery` objects, exactly 32 bytes each.
  Object references pin object ID, revision, key epoch and binding digest.
- Revision/epoch are canonical positive decimal u64 strings. Digests are exactly
  64 lowercase hex characters. Identity strings are 1–512 printable nonspace
  ASCII bytes (namespace/object ID maximum 128). Metadata JSON maximum 4096 bytes,
  with unknown/duplicate fields rejected. No secret-bearing wire object.
- Read, administrative and lifecycle ports remain separate. Runtime endpoints
  and leases are opaque, unforgeable, nonserializable native capabilities.
  No generic secret getter or caller-supplied plaintext callback.
- Eight live leases per owner/application session; one delivery and one in-flight
  operation per lease. Acquisition deadline and absolute lease lifetime 120 s;
  delivery deadline 5 s. Monotonic clocks and explicit lifecycle invalidation.
  Check authority before and after asynchronous work; dispose late results.
  Close/drop releases capacity. Restart invalidates all handles.
- A frozen reference must be explicitly authorized in the session. Possessing
  reference metadata or unlocking a vault does not grant read access.
- Native ABI stays v2. Reserve optional custody feature, do not advertise it until
  a real ABI provider is implemented and qualified. Generated native metadata is
  not permission to call a secret transport. Browser adapter stays unavailable.
- Admin approval must ultimately reuse ADR-013, always required on custody
  mutations, including enrollment/grants. Synthetic fixtures cannot mint real
  approvals. Sources must bind their exact desired reference, resolving the
  semantic sketch's missing target-reference argument for `put`.

## Acceptance, recorded before measurements

Red-first tests: wrong owner, purpose, reference, epoch and peer; unknown schema,
forged handle, close/drop/replay, cancellation, expiry, in-flight duplicate,
lock/revoke/account-change/restart and late completion. Golden metadata vectors
and generated-artifact drift tests; Rust and TypeScript contract negatives;
ABI mismatch and unavailable-feature negatives; property-based malformed input.
Secret ownership must lack Debug/Display/Clone/Serialize and wipe on destruction.

Synthetic workload: two independent 32-byte objects per owner, 1 and 8 parallel
owner sessions, 100 unlock/deliver/close cycles and 100 denied requests per owner.
Three warmups plus 30 retained trials per cohort. Warm dispatch+delivery p95
<=100 ms; <=8 live leases/session; zero handles after close. Cold startup and RSS
high-water separately recorded, incremental RSS <=16 MiB above loaded provider.
Human, KDF and OS authentication time excluded and reported as unmeasured here.
No retry or unbounded queue; failed thresholds cannot be relaxed retroactively.

## Follow-on gates

KC-02 adds dedicated encrypted personal-vault storage with atomic metadata+value
CAS, unconditional fresh trusted-UI master-password approval, exact-object grants,
daemon lifecycle integration, synthetic native receiver, audit and IPC review.
It must not reuse password entries, service grants or an operator vault. Backup,
DEK rotation, restore and deletion must account for the new object class before
any durable production storage is enabled. No silent sync/export support.

Fresh adversarial review and exact-head green CI are required before merging to
develop. Physical-device qualification and production enablement are separate.
No tag, publication, deployment, live grant or mailbox activation is authorized.
