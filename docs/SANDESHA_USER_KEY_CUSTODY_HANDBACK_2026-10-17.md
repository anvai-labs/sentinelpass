# SentinelPass KC-01/02 candidate handback and KC-03 entry gates

Producer runtime candidate: `1df027932f08baabf2afebb6a0444bab867fcd12`.
[PR269](https://github.com/anvai-labs/sentinelpass/pull/269) targets develop.
This is an unmerged synthetic implementation candidate, with two completed
independent automated reviews and corrective reviews. Required code-owner
approval remains separate. CI for this exact runtime candidate was still running
when this handback was prepared; consult the PR for its final result. There is
no merged release/tag or production custody adapter to adopt yet.

## Versions and capabilities

Custody protocol1, mobile ABI2, vault schema14. Independent32-byte mail-recovery
and storage-recovery objects. Feature bit8 is reserved and unset; mobile relay
sync is also unset. The unavailable descriptor advertises no runtime transfer,
sync or portable export. OIDC, service grants and operator credentials confer
no personal custody authority.

| Surface | Evidence available | Application boundary |
| --- | --- | --- |
| Rust core | Authenticated storage, exact leases, fresh-password approval harness, CAS/tombstones, backup/restore/rekey and lifecycle negatives | No production enrollment/source/receiver constructor |
| TypeScript | Generated shapes, validators and conformance | No runtime authority or browser bridge |
| Swift/C, JVM/JNI | Host ABI and metadata probes | No secret transfer or physical OS-store qualification |
| Desktop/mobile packages | Existing CI builds and tests | No personal custody enablement or physical-device claim |

## Evidence and reproduction

- [KC-01 receipts](evidence/custody-kc01/README.md): metadata/bindings, conformance,
  fuzz and synthetic timing.
- [KC-02 receipts](evidence/custody-kc02/README.md): real temporary SQLite storage,
  native authority, lifecycle, audit and frozen warm latency/RSS measurements.
- [Adversarial corrections](evidence/custody-kc02/ADVERSARIAL_REVIEW.md): duplicate-ID
  receipt rollback, positional-array metadata acceptance, and masked negative
  coverage corrected; original failures and scoped corrective review retained.
- [Dependency delta](evidence/custody-kc02/ci-security-remediation.json): root
  lockfile TLS/QUIC advisory repairs and license/MSRV records; no new custody cipher.

Local validation: full workspace tests (core882 passed,6 ignored), strict Clippy,
generated bindings, TypeScript typechecking/125 tests, JVM12 and Swift/C11 probes,
4,929,997 fuzz inputs, and unchanged performance/RSS limits passed. These are
candidate-local results, not permission to skip CI or code-owner review.

```sh
cargo test -p sentinelpass-core custody --lib
cargo run -p sentinelpass-protocol --example generate_custody_bindings -- --check
bash scripts/test-custody-native.sh
node --test scripts/check-custody-handoff.test.mjs
node scripts/check-custody-handoff.mjs /path/to/sandesha-checkout
```

## Consumer entry point and remaining design work

Inspected Sandesha snapshot `3b5ca0258d8644c797b160678f32e24b1885280c` contains
native `sandesha_mail_custody::recover` and `RecoveredMailKey`. Reuse that code
for native mail proof; its browser Settings flow does not itself provide an IPC
adapter. The storage recovery path inspected here is WebCrypto-based. Both
purposes need qualified recovery before claiming complete integration.

The [KC-03 workcard](CUSTODY_KC03_WORKCARD.md) defines preparation, isolated native
proof and real macOS transport as distinct slices. In particular, freeze the
canonical `bindingSha256` mapping and vectors before code, qualify the combined
Rust/toolchain/dependency graph, and supply actual native receiver lifecycle and
trusted admission. Mac UID/GID evidence is not application signing identity.

Sandesha's `USER_KEY_CUSTODY_PROVIDERS.md` still describes KC-01/02 as proposed.
Its status can advance to reviewed implementation only after this handback is
accepted; it must not advance to installed/enabled merely because an interface
exists. No sibling files were changed during this preparation.

Recovery keeps the original mailbox epoch and certificate fingerprints; an empty
vault or successful login cannot reset them. Migration verifies the destination
before separately approving source removal. Keep independent recovery-kit access.
Browser transport, cross-device bootstrap, physical OS protection, mobile relay,
key rotation/archive policy and deployment remain later gates. Device revocation
cannot erase an already copied mailbox key.
