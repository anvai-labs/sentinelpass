# KC-01 implementation candidate and handback

2026-10-16. **Historical KC-01 handback; not a production custody provider.**
KC-02 implementation has since progressed: see [the current handback](../custody-kc02/README.md).
The implementation/validation descriptions below describe the KC-01 slice;
`performance.json` may be regenerated against newer source but measures KC-01 only.
Source base is `84c7f58d012b428a4f8635d87ae988e0f1ebfc31`; work is on
`feat/personal-custody-contract`. Fresh independent adversarial review and exact-head
CI are pending. No merge, tag, publication, deployment, live grant or mail activation.

## Implemented

- Protocol 1 strict Rust scope/reference/capability/error metadata, generated TS
  declarations/validators and Swift/Kotlin DTOs; existing cbindgen C header generation.
  Decimal revision/epoch strings preserve u64 precision. Typed Rust decoding rejects
  unknown/duplicate fields, bad versions, purposes, digests and oversized inputs.
- Separate read/lease/admin Rust ports. Native leases and receivers have private
  registry identity, no Serialize/Clone/Debug and no raw secret accessor. Owned
  32-byte native buffers zeroize on drop. Only test code can construct sessions,
  provision synthetic objects, register receivers or change session authority.
- Exact preauthorized scope/reference reads, eight leases and eight receivers per
  session, one delivery, 120-second expiry, five-second delivery deadline, bounded
  expiry tasks, before/after checks, cancellation/future-drop cleanup and late-output
  disposal. Idle expiry clears receiver state without another request. Application
  lock/revoke/account-change hooks are modeled by the test authority; production
  daemon lifecycle wiring is still KC-02.
- Additive ABI-v2 C/JNI **metadata validation only**, ABI mismatch refusal and an
  unadvertised reserved custody feature bit (8). Mobile relay sync remains unset.
- Shared golden metadata, malformed-input property tests, fuzz target, generated
  binding drift gate, native ABI/JNI declaration tests and host JVM/Swift probes.

No mailbox key generation, new envelope cipher, OS slot, vault row, service grant,
IPC secret delivery, enrollment UI or OIDC integration was added. The synthetic
adapter's in-memory backing objects are test data, not encrypted durable storage.
The public admin trait has no implemented adapter or approval minting path.

## Local validation

| Check | Result / scope |
| --- | --- |
| Red-first Rust contract, native engine and C ABI checks | Failed before implementation; excerpts in `red-first.txt` |
| `cargo test --workspace` | Passed; subsequent idle-expiry/authority-drop changes additionally covered by the final focused core suite |
| `cargo test -p sentinelpass-core custody::tests --lib` | 11 passed, performance test intentionally ignored here and run separately |
| `cargo test -p sentinelpass-protocol` | 51 existing + 4 custody contract tests passed |
| `cargo test -p sentinelpass-mobile-bridge --features jni` | 32 unit + 1 custody FFI + 10 integration + 4 JNI contract tests passed |
| Native secret ownership doctests | 3 compile-fail tests passed (Debug, Clone, Serialize unavailable) |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `npm run web:typecheck` | Passed, including new strict custody config |
| `npm run test:ts` | 124 tests passed, existing coverage thresholds passed |
| `bash scripts/test-custody-native.sh` | Host JVM: 9 checks; host Swift/generated C ABI: 8 checks passed |
| Generated binding drift and formatting | Checked with generator `--check` and `cargo fmt --all -- --check` |
| `cargo +nightly fuzz run fuzz_custody_metadata -- -max_total_time=60 -max_len=8192` | 5,777,483 inputs / 61 seconds, exit 0, no crash; see `fuzz.json` |

The full workspace run exposed an existing-wrapper convention mismatch in the new
C entry point; fixed using the existing wrappers, with the unchanged regression
tests passing afterward. The initial host Swift probe needed an explicit UInt
conversion for the C length. Sandbox compiler-cache failures were rerun with the
required execution permission. These were not relaxed test or security gates.

## Frozen performance evidence

`performance.json` contains raw per-trial timings, source/artifact hashes, compiler
and platform versions, cold provider initialization, fresh test-process wall time,
and process RSS high-water. Reproduce with:

```sh
node scripts/qualify-custody.mjs /tmp/custody-performance.json
```

Each cohort has 3 warmups + 30 trials, 1 or 8 concurrent owner sessions, two
independent 32-byte synthetic secrets per owner, 100 synthetic unlock/deliver/close
cycles and 100 denied requests per owner. A trial records its **maximum** native
dispatch+delivery latency across all owners/cycles; p95 is nearest-rank across
the 30 trial maxima, a stricter aggregate than per-operation p95.

| Owner sessions | p95 of trial maxima | Incremental RSS high-water |
| --- | ---: | ---: |
| 1 | 0.009291 ms | 1,212,416 bytes |
| 8 | 0.756208 ms | 638,976 bytes |

Both frozen limits pass (100 ms, 16 MiB), and zero handles remain after close.
RSS baseline is before warmups with the provider already loaded. These figures
exclude human, KDF, OS prompts and encrypted storage: none were exercised. Cold
provider init is not app/device startup; fresh process wall time includes all
benchmark trials. Native timing is not IPC/browser/mobile/platform parity.

## Qualification and security limits

| Surface | Current custody status |
| --- | --- |
| Native Rust | Synthetic engine only; production constructor unavailable |
| C ABI / Swift host | Metadata validation tested; secret transport unavailable |
| JNI / JVM host | Metadata validation tested; generated Kotlin declaration parity checked |
| Android/iOS device | Custody access, key release and physical-device qualification unavailable |
| Browser / extension / Worker / PRF | Unavailable; no transport added |
| SentinelPass personal vault / OS stores | Unavailable pending KC-02 / per-platform qualification |
| Sync, recovery, migration, archive keys | Not implemented by this slice |

Metadata validation is not proof of owner identity, reference freshness or secret
possession. Same-process code is trusted: opaque handles do not defeat injection,
same-UID privileged observation or root. The fixture does not establish real
transport peer identity. Lifecycle decisions and receiver publication serialize
under one mutex, and pending work checks again before publishing; a future IPC
adapter must document and test its own cross-process revocation race. Already
released/copied material cannot be recalled. Zeroizing owned buffers is not a
physical-memory-erasure, locked-memory or hardware-execution claim.

Official platform references were rechecked: [Apple Security Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
documents P-256 and generated-in-enclave key constraints;
[Android Keystore](https://developer.android.com/privacy-and-security/keystore)
requires inspecting security level and auth-bound key use for hardware claims.
No such claim follows from these metadata tests.

## Remaining ordered work

KC-01 still needs fresh independent review and exact-head CI before acceptance.
KC-02 must implement dedicated authenticated personal-vault storage with atomic
object+binding CAS; unconditional fresh master-password step-up for every mutation
(not the permissive desktop profile); exact-object grants; trusted source/receiver
registration; audit and daemon lifecycle integration; restart/revoke/race tests.
Storage must participate safely in backup/restore, DEK rotation and deletion before
enabling durable data. Service credentials and operator/VPS grants cannot be reused.

KC-03 onward still require unchanged Sandesha recovery bytes and actual proof of
mail-key/certificate possession, verified destination before migration cleanup,
independent-device enrollment with distinct local protection, sync authorization,
reviewed browser transport and physical-device evidence. OIDC login supplies no
decryption, replacement or enrollment authority. Lost-device compromise requires
new future-mail keys; this work does not alter that rule.

## Dependency / license delta

No new runtime library or crypto algorithm. The existing Tokio dependency gains
only its `test-util` dev feature for deterministic idle-expiry testing; root
`Cargo.lock` is unchanged. The detached fuzz lockfile was stale at workspace v0.9:
running the new target refreshed it to the existing v0.17 manifests (including
the existing local `anvai-secure-io` crate, dirs 7, thiserror 2 and tower-http 0.7).
This is fuzz-build dependency alignment, not a production dependency update.
New source and generated SDK files follow the repository Apache-2.0 license.
No private Sandesha adapter was copied or published. Later CI-driven transitive
security updates are recorded in the KC-02 handback; this paragraph describes
the original KC-01 slice.
