# KC-01/02 review entry point

Implementation candidate on `feat/personal-custody-contract`, targeting `develop`.
The remote develop head was rechecked against the handoff base
`84c7f58d012b428a4f8635d87ae988e0f1ebfc31` during the retention follow-up.
This document organizes review. Fresh independent automated findings and
corrective review are recorded in [ADVERSARIAL_REVIEW.md](ADVERSARIAL_REVIEW.md);
GitHub code-owner approval remains outstanding.

## Scope and evidence

Read the [contract](../../SANDESHA_USER_KEY_CUSTODY_CONTRACT_2026-10-16.md),
[KC-02 workcard](../../CUSTODY_KC02_WORKCARD.md) and
[implementation/evidence summary](README.md). `validation.json` identifies the
tested source files by SHA-256; `performance.json` contains raw trials and limits.
The KC-01 directory contains generated-binding, native metadata and fuzz evidence.

The production public ports have no public enrollment/source/approval/receiver
constructors. The mobile custody feature is unset. No new secret IPC message,
browser bridge, service grant, OIDC authority or relay mutation was introduced.
The working same-process adapter is exercised through a synthetic trusted native
test harness. Approving this slice does not approve product enrollment or KC-03.

## Review boundaries

| Boundary | Implementation to inspect | Evidence / residual |
| --- | --- | --- |
| Exact owner/reference and bytes | `sentinelpass-protocol/src/custody.rs`, `vault/custody_ops.rs` | Strict metadata, full commitment in SPENV AAD, CAS, tombstones, separate 32-byte purposes. Metadata is visible at rest. |
| Mutation authority | `custody/personal.rs`, `daemon/ipc/stepup.rs` | Private native capabilities, exact operation/source/connection binding and one-use approval; test harness verifies fresh password. Production trusted prompt and authenticated peer enrollment remain unavailable. |
| Read lifecycle | `custody/mod.rs`, `daemon/vault_state.rs` | One-shot leases, eight-handle limits, two durable checks around delivery, close/expiry/revocation cleanup, daemon replacement/drop. Durable grants contain no plaintext field in production. |
| Blocking I/O | `custody/workers.rs` | Local/global limits, cancellation/deadline return, retained permits for abandoned workers, late-result disposal. OS calls cannot be forcibly stopped. |
| Mutation cancellation | `vault/custody_ops.rs`, `custody/workers.rs` | Authorization checks after storage locks and immediately before commit. Accepted commits may finish after cancellation; inspect outcome with fresh authorization before any retry. |
| Persisted integrity | `vault/content_guard.rs`, `activation_ops.rs`, `rekey_ops.rs` | Complete custody rows participate in receipts, backup, restore and rekey. Coordinated database-plus-receipt rollback is outside the existing guard's protection. |
| Audit | `custody/workers.rs`, `audit.rs` | Closed operation/success fields; synthetic canary scans cover actual native outcomes. Audit persistence is bounded best effort, may be dropped on capacity/failure, and does not authenticate a new peer or undo a committed write. |
| Host/native contracts | `sentinelpass-mobile-bridge/src/custody.rs`, generated bindings | Metadata validation only. Host JVM/Swift checks are not physical Android/iOS assurance or inter-app key transfer. |

The author recheck found and removed an unnecessary durable-grant plaintext cache;
`retention-red-first.txt` preserves the failing behavioral test. New tests cover
delivery after closing the preceding lease, full daemon drop/reopen with retained
old capabilities, and audit success/replay denial without secret or authority
canaries. This is author verification, not a fresh independent adversarial audit.

Same-UID privileged IPC access, injected approved processes and root remain outside
the isolation claim. Recovery-loss UX, hidden fallback, historical-key authority,
sync enrollment and physical OS protection still need their later slice reviews.
No handoff acceptance, merge, tag, release or live mailbox activation is implied.
