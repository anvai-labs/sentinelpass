# KC-03A source and interface preflight

2026-10-17. Preparation only, no runtime integration or enabled capability.
[Workcard](../../CUSTODY_KC03_WORKCARD.md) records the actual native recovery
entry point, storage-runtime gap, macOS peer limitation and ordered acceptance.

The original manifest pins 48 SentinelPass and 13 Sandesha files; current
`inputs.json` additionally pins five package-local canonical metadata fixtures. Producer evidence pins
come from the KC-02 validation receipt, with current transport and contract files
added. Consumer pins cover the inspected recovery interfaces, native sources and
manifest/lockfile. They are not a complete vendor/package provenance inventory.
`source-check.json` records 61 matching files. Its readiness fields deliberately
remain false: passing this check grants no authority and executes no crypto.

```sh
node --test scripts/check-custody-handoff.test.mjs
node scripts/check-custody-handoff.mjs /path/to/sandesha-checkout
```

The checker runs offline, reads no vaults or credentials, and compares current
file bytes with the pinned baseline. It fails on changed/missing pinned files,
empty pin sets, unknown versions and paths escaping the supplied checkout. It
does not require an unchanged Git HEAD: unrelated consumer work may continue,
but matching scoped source bytes must not be described as exact-head CI.
Optional `--output /path/to/new-report.json` refuses to overwrite an existing file.

Five Node tests pass: matching bytes never confer readiness; altered/missing files
fail; empty/unknown manifests refuse; traversal and external symlinks refuse;
Windows parent paths and cross-drive targets refuse. Independent automated review
found that the initial containment check only recognized POSIX separators. The
failing Windows-path regression is retained in `containment-red.log`; the corrected
check uses separator-independent path components. This tests path semantics,
not execution on a Windows host.
These are tooling tests, not new native, mail, browser or device qualification.

The sibling checkout was inspected read-only at
`3b5ca0258d8644c797b160678f32e24b1885280c`. No consumer source, live configuration,
production vault or recovery material was changed. Source hashes do not certify
the behavior of an unreviewed consumer revision or authenticate a manifest obtained
from an untrusted party. Review the pinned manifest through the repository workflow.

Next unresolved gates are concrete: accepted KC-01/02 handback; canonical binding
vectors; combined native dependency qualification; native storage recovery port;
bounded enrollment and trusted UI; macOS application-peer transport. See workcard
KC-03B/C for proof, cancellation, migration and resource requirements.

Release-preparation update: PR269 is merged after clean review and45 green checks;
the [binding vectors](../custody-binding-v1/README.md) and
[native graph preflight](../custody-native-graph/README.md) now have separate receipts.
`inputs-1df0279.json` preserves the original pins. The version preparation captured in `inputs-d354eff.json` refreshes
only Cargo.toml/Cargo.lock for the0.18.0 version bump; eight first-party packages
change version and registry package records are byte-equivalent as parsed TOML.
The before/after hashes and scope are explicit in `versionOnlyRefresh`. All61
version-preparation pins matched. Historical runtime/performance/review receipts still identify
their original candidate; this refresh does not rewrite their measured source.

Publication qualification refresh: `packagingOnlyRefresh` records the generator
and test include-path corrections, plus five canonical fixture pins. Cross-language
fixture copies remain byte-identical and are checked by the generated-binding CI
gate. All66 current pins match; `source-check.json` remains the historical61-file
receipt. The packaged-crate test exercises the archive without workspace parents.
