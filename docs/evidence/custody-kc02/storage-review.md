# Independent custody persistence/contracts review

Reviewed candidate: `e69bc9bf8838222c2b032e4c414fee9ce5ed0eb9`.
Comparison base: `84c7f58d012b428a4f8635d87ae988e0f1ebfc31` (develop).
Reviewer: separate storage/contracts review agent, 2026-10-17.

This is a technical review of synthetic KC-01/02. It is not GitHub code-owner approval, product enrollment approval, a merge/release decision, or hardware qualification. Repository was read-only for this reviewer; temporary evidence was written only under `/private/tmp`. Parent is now adding regression tests/fixes separately.

## Findings (candidate requires correction)

### P1 — duplicate database identities can hide an old row behind an unchanged current receipt

Location: `sentinelpass-core/src/vault/content_guard.rs:266`, with first-match lookup at `sentinelpass-core/src/vault/custody_ops.rs:90`.

The custody receipt iterator inserts each row into a `BTreeMap` using `custody:{object_id}` and silently replaces an earlier value with the same key. SQLite's primary-key constraint is not an authentication boundary against an offline database writer. An attacker with an old encrypted custody row can replace the table with a schema lacking the primary key, insert the captured old row first and the current row second, preserving every byte of the current external receipt. The snapshot map then contains only the current row's fingerprint and equals the authenticated receipt. `find` uses `query_row`, which selects the first matching row, so the old reference and its authentic encrypted value can be resurrected. Authenticating each row's SPENV cannot distinguish the valid old ciphertext from current state; receipt uniqueness must be enforced independently of schema constraints.

Reproduction sequence:

1. Create a temporary file vault and custody object at revision 1; save its complete encrypted row.
2. Update the object to revision 2 normally. Confirm revision 1 is stale. Leave `.contents` untouched thereafter.
3. Rename `custody_objects`, create a replacement using `CREATE TABLE ... AS SELECT ... WHERE 0` (no PK), insert the saved revision-1 row, then insert the current revision-2 row and drop the temporary renamed table.
4. Request revision 1. The current snapshot receipt collapses the duplicate IDs while first-match lookup sees revision 1.

Independent minimal SQLite reproduction returned `receipt_equal_with_two_rows: True`, `first_row_revision: revision-1`, and `row_count: 2`. A full existing-fixture regression is supplied in `/private/tmp/custody-duplicate-row-regression.rs` for parent execution. At initial report capture the parent full-vault red run is pending. The issue is a current storage integrity blocker, even though production enrollment is intentionally unavailable.

Fix direction: reject duplicate custody identities while constructing/verifying receipts, and do not trust on-disk uniqueness constraints in direct lookup/deep verification. Keep a file-vault regression proving old reads, deep verification, and reopen all fail closed without modifying the receipt. Tombstone/current-plus-live duplicate variants should also remain denied.

### P2 — Rust/native metadata validation accepts positional arrays outside the declared v1 object schema

Location: `sentinelpass-protocol/src/custody.rs:83`.

`Wire::deserialize(d)` uses serde's derived struct visitor, which accepts a positional sequence as well as a map. For example `[1,"sandesha","https://issuer.example","subject-1","mailbox-1","mail-recovery"]` validates as `CustodyScope`. The equivalent positional `ObjectRef` also validates. The shared macro affects `ProviderCapabilities` too. Generated TypeScript explicitly rejects arrays, so the same metadata is accepted by Rust/C/JNI but rejected by TS; Swift/Kotlin DTOs describe object-shaped JSON. This contradicts freezing one strict metadata contract.

Independent host C probe loaded `target/debug/libsentinelpass_mobile_bridge.dylib` and called `sp_custody_validate_metadata(2, kind, bytes, len)`: both object and positional-list forms returned 0/Success for scope and reference. After parent added a negative fixture, `cargo test -p sentinelpass-mobile-bridge --test custody_contract` also failed on `custody_ffi_rejects_positional_array_metadata`, reporting Success where InvalidParam was required. Typed field validation still runs, so this is not a demonstrated authority/secret-access bypass. It is a current protocol-conformance blocker before v1 is accepted.

Fix direction: request map-only deserialization while retaining typed duplicate/unknown-field rejection; add all three positional-array negative golden vectors at Rust and native boundaries and verify TS parity. Do not deserialize through `serde_json::Value`, which would collapse duplicate fields.

### Additional hardening observation — receipt parsing precedes the dedicated row bounds

Location: `sentinelpass-core/src/vault/content_guard.rs:255` and `sentinelpass-core/src/vault/custody_ops.rs:55`.

Receipt construction clones raw metadata strings and envelope bytes before the dedicated custody parser's byte/type limits run. An offline writer bypassing table CHECK constraints can therefore force large owned allocations and JSON fingerprint expansion before the row is rejected. This review did not run a destructive/OOM probe and does not assert a separate confidentiality vulnerability. Reuse bounded borrowed-row checks in receipt construction when fixing duplicate handling. The frozen <=16MiB valid-workload benchmark does not establish a malicious-database allocation bound.

## Boundaries independently checked

- Exact canonical typed scope/reference tuple is SHA-256 committed in full to SPENV AAD, alongside vault identity, object class, envelope schema/crypto version and tombstone state. No truncated digest, new cipher, secret JSON field or raw key export was found.
- Durable reads authenticate before comparing owner/reference; mutations retain exact scope/object identity, advance revision by checked +1, reject epoch decreases and retain authenticated empty tombstones. The u64 overflow path compares `None` against a valid parsed revision and refuses replacement.
- Schema 14 migration creates the dedicated table and updates the metadata version in one immediate SQLite transaction. Existing migration continuation/idempotence test reaches the current version. Historical snapshots without the table are allowed only below version 14; a current-v14 missing table is denied. On ordinary open, migration precedes receipt initialization, and the empty newly added table does not change old receipt maps.
- Custody rows are included in content snapshots, deep backup/restore verification and fresh-DEK rekey with a new vault UUID. File receipt, backup, restored exact bytes, reopen, deletion detection and rekey behavior passed focused tests. Coordinated rollback of database plus authenticated receipt remains the documented external-freshness limitation; this does not excuse the duplicate-row finding, which leaves the current receipt intact.
- Table is separate from generic entries and sync mutation tables. No custody sync capability, OIDC authority, service-grant reuse, browser transport or operator-vault integration was added.
- Metadata C ABI bounds size/null before pointer access, negotiates ABI first, and catches panic. JNI bounds arrays before copying and catches panic; generated Kotlin method declaration matches the exported symbol. Feature bit 8 and mobile relay-sync bit remain unset. Metadata Success does not create authority.
- Rust field declarations drive generated TS/Swift/Kotlin names/types/enums; generator `--check` passes. Native DTOs alone are not validators, accurately documented. The positional-array mismatch is the identified missing negative case.
- Dependency diff is limited to quinn-proto/rustls patch updates and their recorded transitive delta, with existing Tokio test-util dev feature and fuzz-lock alignment. Evidence explicitly distinguishes local synthetic performance/host probes from physical platform proof and records known audit warnings. Parent independently checked exact source/performance hashes and current CI; this reviewer did not rerun the benchmark or audit database fetch.

## Commands/results

- `cargo test -p sentinelpass-core custody_storage -- --test-threads=1`: 4 passed (original-head code).
- `cargo test -p sentinelpass-protocol --test custody_contract`: 4 passed (original-head tests).
- `cargo run -p sentinelpass-protocol --example generate_custody_bindings -- --check`: passed.
- `cargo test -p sentinelpass-core database::migrations::tests::run_migrations_idempotent -- --exact`: 1 passed.
- Independent Python/ctypes host C metadata probe: scope/reference arrays wrongly accepted, as described above (synthetic public metadata only).
- Focused bridge test after parent added red vectors: old positive test passed, positional-array negative failed as expected.
- Independent SQLite duplicate-row/receipt-map reproduction: confirmed map collision and first-row divergence; full Rust vault regression supplied separately.

No full workspace/performance rerun was performed by this reviewer. Cargo's existing `block 0.1.6` future incompatibility warning was observed; it is unrelated to custody changes.

## Remaining scope and acceptance

Resolve the two current-slice findings, rerun relevant negative/integration tests and fresh exact-head CI, and review the corrective diff. Required GitHub code-owner approval remains separate.

Production trusted UI/peer enrollment and source/receiver construction remain intentionally unavailable; independently reviewed runtime authorization, recovery/fingerprint proof, migration destination proof, historical-key authority, mobile synchronization and physical OS stores remain later gates. Same-process trusted-code injection, same-UID privileged observation/root, copied-key revocation and coordinated trust-state rollback remain outside the documented guarantees. This review makes no claim to erase keys already copied by a lost device or to execute imported OpenPGP keys in hardware stores.

## Corrective-diff follow-up review (2026-10-17)

Reviewed the corrective working tree on top of candidate `e69bc9b`, scoped to the file hashes below. Both original findings are now resolved in the reviewed source; **no remaining current-slice blocker was identified in this persistence/contracts review**. Fresh exact-head CI and GitHub code-owner approval are still required before merging. This statement is not broader product or platform qualification.

The parent's real-vault red-first test confirmed the P1 attack, failing with `old reference was resurrected under the unchanged current receipt` (`/private/tmp/custody-review-duplicate-red-first.log`). Its all-three-types protocol red run confirmed P2 (`/private/tmp/custody-review-array-red-first.log`). Thus the original report's pending full-vault reproduction is now confirmed.

Correction review:

- `content_guard::snapshot` now treats a repeated `custody:{object_id}` as an integrity failure instead of returning the overwritten receipt map. This protects ordinary open, custody reads/mutations, backup creation/copy validation and rekey's receipt checks regardless of removed SQLite uniqueness constraints. Repeated identical rows and old-live/current-tombstone pairs also fail.
- `custody_ops::verify` independently rejects duplicate IDs using a set, protecting deep archived-snapshot validation even when no live `.contents` receipt is consulted. Rekey already calls full verification before copying and receipt verification again before operating; restore stages and verifies the snapshot before rebasing freshness. No bypass of these guards was found.
- Shared borrowed-row type/byte bounds now run before the receipt path owns metadata/envelope copies. Valid persisted receipt fingerprints are unchanged. Historical absent-table behavior and schema migration are unchanged; no old legitimate receipt is invalidated by this correction.
- Map-only serde visitation delegates map entries directly into the existing typed `Wire` deserializer, preserving duplicate/unknown-field refusal and field validation. It does not collapse keys through `Value`. Object serialization/golden bytes, generated declarations, ABI version and feature availability are unchanged. Positional sequences were an undocumented accepted form, not a supported object contract that needs to be retained.
- Shared negative vectors cover scope, reference and capabilities through Rust, C, host JNI, Swift/C and TS checks. The duplicate regression now checks both current-live and current-tombstone cases, ordinary read, full-vault verification, direct receipt-independent custody verification, and reopen. Test setup never alters the current `.contents` file.
- Qualification script adds hashes for the three new negative-vector files; performance limits/workloads were not weakened. The separate lifecycle-test strengthening was inspected for collateral changes but is owned by the authority/lifecycle review.

Independent correction validation:

- `cargo test -p sentinelpass-protocol --test custody_contract`: 7 passed, including all positional-array negatives and existing golden/duplicate/unknown/version tests.
- `cargo test -p sentinelpass-core --lib vault::custody_tests::custody_receipts_reject_duplicate_identity_after_offline_schema_tampering -- --exact`: 1 passed, exercising both live and tombstone variants and direct archived-snapshot verification (2.42s).
- `git diff --check`: passed.
- An earlier command used a short name with `--exact` and selected zero tests; it is explicitly not counted as validation. The fully qualified rerun above is the evidence.

Reviewed SHA-256 values:

```json
{
  "sentinelpass-protocol/src/custody.rs": "6aa485900650fcfb8311157066819ccc052c0e43103c3a80e16ac55ab21c2299",
  "sentinelpass-core/src/vault/content_guard.rs": "6647f4b532e139fb78c31c5538af862f2fe69c3bf2b8c2faa0d452cd098e4d47",
  "sentinelpass-core/src/vault/custody_ops.rs": "aae3ef236ce40e7e45a1333f21b661c7e91027344493c80afdd8242d76cec50a",
  "sentinelpass-core/src/vault/custody_tests.rs": "dd4003a14f884773f2bd2e8af834d34c0caf8f649e7129933e6dbe13d310c024",
  "sentinelpass-protocol/tests/custody_contract.rs": "4f4c612fcd22b73392891a7d3f5684dce480587f1aa59f62e98949ef0d4051d9",
  "sentinelpass-mobile-bridge/tests/custody_contract.rs": "f20f968239d27d74f3c6a6b16f3eaa36b6c7635ee45f18859c20cba04a3d2772",
  "tests/custody-contract.test.ts": "1f8d22c1efe2e105d83d58ae1c920e2ad2d5d5d1dd6b887bb94ecef8838dcc69",
  "tests/native/custody/main.swift": "385fe0c14a4ed3591993556248188c7732ddb5f6a21cf4a8e29cb9326d9eea8c",
  "tests/native/custody/com/sentinelpass/custody/CustodyContract.java": "944fd7f150e6c4a613dc3e1bb9cbaa86f5f8bbe3132d6d0ec6d4198bf52ffaeb",
  "bindings/custody/scope.array.invalid.json": "f42148c58bd5bd85f4844a8e2acf4b7af5eabab3cb7456764c36f5b085c1ca50",
  "bindings/custody/reference.array.invalid.json": "0d6d94dc5eea8703aa8ca4c5ed8677568f417a1febcb194fdb09fdc0272d6f7a",
  "bindings/custody/capabilities.array.invalid.json": "44a434cdb7ef7261512476f316867f56ffda2acc49a3238afdbfac37ce966036",
  "scripts/qualify-custody.mjs": "24a6173ce6965ffc8b61c70e50ca0c3bad40b637801de1001e961ce69ad07038"
}
```
