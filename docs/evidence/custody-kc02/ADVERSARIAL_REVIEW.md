# KC-01/02 adversarial review and corrections

Two separate automated reviewers independently inspected candidate
`e69bc9bf8838222c2b032e4c414fee9ce5ed0eb9` against develop
`84c7f58d012b428a4f8635d87ae988e0f1ebfc31` on 2026-10-17. One covered authority,
lifecycle, worker bounds and IPC reachability; the other covered persistence,
backup/rekey, metadata and native contracts. These are technical code reviews,
not GitHub code-owner approval or production/platform qualification.

## Findings and corrections

| Finding | Reproduction and correction |
| --- | --- |
| P1: duplicate-ID receipt rollback | An offline writer can replace SQLite constraints, insert an older authentic row before the current row, and leave the external receipt unchanged. Receipt construction previously collapsed equal IDs while lookup selected the old row. The real temporary-vault regression reproduced the stale-reference read. Receipt construction and independent deep verification now reject duplicates. Live-current and tombstone-current variants test read, archive verification and reopen denial. |
| P2: positional arrays outside the metadata schema | Derived Rust struct decoding accepted field-order arrays for all three metadata types; TS rejected them. All three new Rust negatives failed before correction. Map-only decoding now retains typed duplicate/unknown-field checks. Shared negative vectors exercise Rust, TS, C ABI, JVM/JNI and Swift/C. Valid object serialization is unchanged. |
| Low: a reused invalidated lease masked negative checks | A cross-peer rejection burned the lease before forged-ID and invalidation assertions. Separate fixtures and live-lease preconditions now exercise each denial independently. No authorization bypass was demonstrated. |

The storage review also noted that receipt construction copied database strings
and blobs before applying the custody parser's size/type checks. The same borrowed
row checks now run before those copies. This limits additional owned allocations;
it does not bound SQLite's internal memory or claim whole-database DoS resistance.

The original failing executions are retained in `adversarial-red-first.txt`.
The independent reports retain original findings and hash-scoped corrective review
in `authority-review.md` and `storage-review.md`. `validation.json` records local
validation and exact source hashes; the performance receipts retain raw trials
under the unchanged workload and ceilings. PR #269 records CI for its exact head.

## Compatibility and remaining gates

Valid unique-row receipt serialization, SPENV context/envelopes, metadata object
bytes, schema 14, protocol 1 and ABI 2 remain unchanged. Rejection is stricter for
duplicate database identities and undocumented positional metadata arrays. Existing
vaults containing valid unique custody rows use the same format and backup path.

The earlier candidate's 45 successful CI checks and 7 skips do not validate these
new changes. Fresh committed-head CI is required, as is GitHub code-owner approval.
Independent review did not qualify production source/receiver enrollment, trusted
password UI, peer transport, cross-device sync, recovery/fingerprint proof, browser
transfer, historical-key authority or physical OS stores. Shared per-owner/app
capacity must be enforced when future production authority enrollment is designed.
No service/OIDC authority, hardware claim or product capability was enabled.
