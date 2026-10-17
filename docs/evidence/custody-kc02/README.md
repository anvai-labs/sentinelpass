# KC-02 implementation progress

2026-10-16, `feat/personal-custody-contract`, based on develop
`84c7f58d012b428a4f8635d87ae988e0f1ebfc31`. Synthetic data only.
This is a tested storage/native-authority implementation candidate, **not an
enabled product adapter or acceptance of the complete custody contract**.
The [review entry point](REVIEW.md) maps implementation boundaries to evidence and
remaining review questions. The [adversarial follow-up](ADVERSARIAL_REVIEW.md)
records the fresh independent automated reviews, confirmed findings and corrections;
GitHub code-owner approval remains separate.

## Implemented

- Schema 14 adds `custody_objects`, separate from entries, service grants and
  sync. The value is one zeroizing 32-byte recovery secret. Metadata remains
  visible at rest; the existing SPENV cipher authenticates a full SHA-256
  commitment over canonical typed scope/reference metadata, vault identity,
  object class, format and tombstone state. No new custody cipher or direct
  dependency; CI-driven transitive security updates are recorded below.
- Native-only storage reads and CAS updates authenticate the current row first.
  Updates retain immutable scope/object identity, advance revision by one and
  cannot decrease the mailbox epoch. Insert can preserve an imported reference's
  revision. Delete removes the encrypted value and seals an empty tombstone;
  deleted object IDs cannot be re-enrolled.
- The existing SQLite transaction and external content receipt cover complete
  custody rows. Failed writes preserve the previous state. Receipt checks detect
  offline row rollback/deletion; coordinated rollback of both database and receipt
  remains outside that existing guard's threat model.
- Deep backup verification, whole-vault restore and fresh-DEK rotation include
  custody. Password listings do not. Relay sync has no custody object support;
  no custody mutation log was added. The receipt-based empty-vault key-adoption
  check also sees custody objects/tombstones.
- `PersonalCustodyAdmin` implements put/remove and exact read authorization.
  Opaque source and approval constructors are private. Every operation consumes
  ADR-013 approval bound to its native connection, vault, scope, expected/target
  references and source registration. Dropping an approval burns it. Sources
  stay in native zeroizing storage; no secret-bearing JSON API was added.
- The synthetic trusted-UI test harness verifies a **fresh full master-password
  open** before minting approval; it shares the daemon KDF gate and lockout path.
  This harness is test-only and is not a shipped password dialog or peer check.
- Repeated grants share one bounded owner/application lease registry. Both sides
  of delivery check the authenticated durable reference as well as local authority.
  Mutations revoke old reads before storage commit, including ambiguous failures.
- Durable grant records contain only scope/reference metadata; their production
  type has no plaintext value field. Grant-time authentication discards the
  temporary recovery value on its worker. Delivery reloads the value and closing
  its lease clears the receiver. Only the synthetic KC-01 test store caches values.
- Daemon lock, replacement, autolock and drop invalidate registered authority,
  sources and reads before releasing the manager. Tests retain an unlocked
  manager Arc to prove that custody cannot survive through that reference.
  Native authority drop and remove also wipe delivered receiver values.
- Audit records contain a closed operation enum and success flag, no owner,
  reference, approval, password or recovery bytes. Existing audit persistence is
  best effort; audit failure does not roll back a committed storage mutation.
- SQLite, receipt locks and audit I/O run on bounded blocking workers without
  holding authority/lifecycle locks. Read work is limited to 8 workers per
  owner/application registry, administrative work to 1, and all custody work to
  64 process-wide. Capacity is rejected immediately; abandoned work keeps its
  permit until it exits. Best-effort asynchronous audit has a separate limit of
  8 workers within the process budget.
- Cancellation, deadlines and daemon lock release waiting callers promptly.
  Late values are discarded and zeroized. Cancellation before the explicit
  pre-commit acceptance rolls back; a write already accepted may finish its
  commit/receipt after the caller departs. Such an outcome requires authenticated
  inspection and fresh approval, never an automatic retry.

## Validation

The initial storage test failed with missing custody methods/private native value
construction, recorded in `red-first.txt`, before implementation. Tests now cover
exact CAS, wrong owner/purpose/reference metadata, unknown versions, ciphertext
substitution, tombstone reuse, injected write failures, file reopen, receipt
deletion, backup verification, restore, rekey, fresh password denial, mismatched
and replayed approval, late delivery after lock, revocation, shared grant capacity
and manager replacement. No recovery secret is printed by these tests.
The scheduling follow-up's initial compile failure is in
`scheduling-red-first.txt`. Its tests hold real database and receipt-file locks
on a single-thread executor, exercise cancellation/future drop/daemon revocation,
retain worker permits after abandonment, dispose late results, and distinguish
rollback from an already accepted commit. The prompt-return checks use a 200 ms
timeout while the storage lock remains held.
`retention-red-first.txt` records a failing behavioral regression for the former
grant plaintext cache. It now passes alongside daemon drop/reopen tests: stored
objects survive, old sources/approvals/read handles do not, and new read approval
is required. Native put/grant/deliver/remove and replay-denial audit records are
checked in an isolated temporary log. Random synthetic canaries (raw, hex and
base64), passwords, approval IDs and owner/object IDs are absent from that log;
all temporary vault/receipt/audit files are also scanned for raw recovery bytes.

Final command results are recorded in `validation.json`. KC-01 golden vectors,
ABI feature negotiation and host binding checks remain applicable and unchanged.
The full `cargo test --workspace` passed (core: 882 passed, 6 intentionally
ignored); workspace Clippy with `-D warnings`, formatting and generated binding
drift checks passed. The first workspace run caught an existing IPC test startup
race: socket-path existence preceded listening. Its setup now probes connection
readiness; the isolated rerun and final workspace run both passed. No approval
assertion or production IPC policy was weakened. A final full workspace run
covers the audit reader's handling of a partially appended final log record.
The checkpoint also passed web typechecking, all 125 TypeScript tests, generated
binding drift checking, and the host JVM (12 checks) and Swift/C (11 checks) probes.
The separate `performance.json` measures the frozen KC-02 warm workload: 1/8
parallel owners, two independent secrets each, 100 load/deliver/close/wipe cycles
and 100 denials per owner, 3 warmups and 30 retained trials. Each trial records
its maximum dispatch/delivery time; p95 is taken over those maxima.

| Owners | p95 of trial maxima | Incremental RSS high-water |
| --- | ---: | ---: |
| 1 | 1.038958 ms | 2,211,840 bytes |
| 8 | 26.397541 ms | 2,113,536 bytes |

Both limits pass (100 ms, 16 MiB), with zero handles after close. The test uses
temporary SQLite files, encrypted values, external receipts and audit file writes.
Delivery audit is now dispatched asynchronously with the bounded best-effort
policy above; warm delivery latency does not wait for audit persistence. Zero
handles means leases/receivers, not a claim that every audit worker has exited.
It installs a random loaded DEK **only in a test fixture**, so an earlier KDF
allocation cannot inflate the RSS baseline and hide custody's incremental cost.
The dummy wraps intentionally cannot reopen; real password/reopen/backup/rekey
paths are covered by the functional tests. Audit writes in this isolated timing
fixture use the existing keyless chain; normal vault tests use the real open path.
Cold fixture initialization is recorded separately; it is not app startup.
Human, KDF and OS interaction time is not measured by this warm benchmark.
After removing the grant cache, test-only delivery correctness comparisons load
an authenticated expected value outside the timed dispatch/delivery interval;
the process memory and wall-time measurements include that validation work.

Reproduce in a fresh process with:

```sh
node scripts/qualify-custody.mjs /tmp/custody-storage-performance.json --storage
```

The KC-01 receipt remains a separate in-memory-engine workload. Neither timing
receipt is physical-device, IPC or production enrollment qualification.

## Remaining gates and integration recipe

Use `cargo test -p sentinelpass-core custody --lib` to exercise the isolated native
adapter with generated synthetic values and temporary vaults. Do not expose the
private test constructors as an application integration shortcut.

Production must supply reviewed personal-vault selection/enrollment, trusted
native source/receiver registration, bounded source/pending-approval enrollment,
fresh trusted-UI password verification and kernel-authenticated connection
binding. An operator/VPS vault, owner CLI token, service grant or OIDC session
cannot substitute. The public Rust types cannot currently be constructed by an
application, and the mobile custody feature remains unset.

Before KC-02 acceptance: retain fresh adversarial audit/IPC review and green
exact-head CI. Two independent automated reviews have inspected the implementation
and corrective diff; see [findings and closure](ADVERSARIAL_REVIEW.md). Blocking OS calls cannot be forcibly interrupted: a stalled worker
can retain its vault reference and native source/result until the call returns,
even though the waiter and local authority have been canceled. The worker limits
bound this retention; these tests do not qualify every filesystem or device.
Automated technical review does not replace required code-owner approval. No merge, tag,
deployment, release or real mailbox activation has occurred.

KC-03 onward still requires Sandesha recovery/fingerprint proof, destination
verification before migration cleanup, approved-device enrollment with distinct
local protection, sync authorization, browser transport and physical OS-store
qualification. Revocation cannot recall keys already possessed by a lost device.

## CI checkpoint and dependency remediation

[Draft PR #269](https://github.com/anvai-labs/sentinelpass/pull/269) targets develop.
The initial checkpoint `1032ed6` passed the local commit hooks but CI found nine
vulnerabilities in pre-existing root-lockfile dependencies. RustSec, the build
security audit and Linux embedded-SBOM verification all reported the same issues.
The aggregate Gate correctly failed; no exception or gate was weakened.

The follow-up pins `quinn-proto` 0.11.18 and `rustls` 0.23.46, the patched releases
identified by [RustSec's QUIC advisory](https://rustsec.org/advisories/RUSTSEC-2026-0340.html)
and [TLS advisory](https://rustsec.org/advisories/RUSTSEC-2026-0347.html). Current
`cargo audit` reports zero vulnerabilities under the unchanged repository policy;
existing warning-class findings remain. `ci-security-remediation.json` records
advisory IDs, log hashes, package/license deltas and the original failing CI links.
The standalone fuzz graph contains neither affected package and is unchanged.

The QUIC patch adds transitive `rand` 0.10.3, `rand_core` 0.10.1, `rand_pcg` 0.10.2,
`chacha20` 0.10.2 and `cpufeatures` 0.3.1. Cargo metadata declares all five and
quinn-proto as `MIT OR Apache-2.0`, Rust 1.85; rustls declares
`Apache-2.0 OR ISC OR MIT`, Rust 1.71. These declared minimums fit the workspace's
Rust 1.89 baseline. This updates the root dependency/SBOM delta; it does not change
the custody envelope or add a direct application dependency. Exact-head CI and
independent audit/IPC review remain acceptance gates.
