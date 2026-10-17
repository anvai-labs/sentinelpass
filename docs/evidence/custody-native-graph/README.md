# Combined native dependency preflight

2026-10-17. Isolated default-feature workspace with dependencies on SentinelPass
core and Sandesha mail custody. At graph capture, no application manifest/lockfile
or vendored source was changed. Later release preparation updates eight first-party
versions to0.18.0, with all706 registry/git package records unchanged; this receipt
and its combined lock remain the0.17.0 capture. An empty library supplied the qualification root; no secrets, vault
operations or mail recovery ran. **Compilation feasibility passes; adoption and
distribution are not approved by this receipt.**

## Results

- Cargo resolved406 packages using the existing local cache. Registry identities
  all occur in at least one original producer/consumer resolved baseline. This
  does not mean their newly unified features or call paths were already reviewed.
- Rust1.98.1 macOS arm64 `cargo check --locked --offline` passed. Existing generic
  array deprecations and the block0.1.6 future-incompatibility warning remain.
  No Linux/Windows/mobile compilation, linking, runtime or performance claim.
- Ten packages have feature differences relative to the original consumer graph;
  exact lists, package checksums, declared licenses and Rust requirements are in
  `inventory.json`. The graph includes all resolved target-conditional packages,
  not only those executed by this Mac check. The baseline producer metadata covers
  its full workspace, so removed versions can reflect omitted applications/features.
- Shared serde_json changes1.0.151->1.0.154 and zeroize1.9.0->1.9.1. The isolated
  lock is retained as `Cargo.lock`; these changes were not applied to the producer.
- Sandesha's source verifier passed791 pinned files at upstream019d4cd. Its older
  vendor README still mentions38e86d0/787 files; use the actual verified manifest
  and `consumer-source-check.log`, not that historical prose.

## Advisory and license limits

The initial audit from the producer directory returned zero vulnerabilities under
its existing RUSTSEC-2023-0071 exception. A second scan from the isolated directory
with **no ignored advisories exited1**, reporting rsa0.9.10 / RUSTSEC-2023-0071.
Both reports are retained. Database revision64f92cdc64401fab47baa10e2e11fe382aa57155;
`--no-fetch` was used. JSON database date/revision fields were null, so the Git
revision was queried separately. This is a dated local database check.

The producer's exception covers its established SSH/local call path. Sandesha's
existing source policy excludes RSA private operations, but the combined features
and new recovery call path still need explicit exposure verification before native
adoption. No exception was added, extended or silently transferred. Warning-class
unmaintained/unsound/yanked findings remain visible in the reports.

Declared package licenses are an inventory, not collected license-text closure
or legal approval. The empty nonshipping probe root intentionally has no license
metadata; real packages report their declarations. Final combined notices,
feature-policy negatives, local-source provenance and advisory exposure remain
adoption gates. This graph is not used by any shipped crate.

## Reproduction

Use a producer checkout at1df0279 or the byte-identical squash026d772 (version0.17.0),
and the pinned consumer sources. Pointing this historical combined lock at the later
0.18.0 checkout correctly fails `--locked`; do not silently regenerate it.
Verify the producer/consumer bytes against `inputs-1df0279.json` using the exported
`checkSources` function with those explicit checkout roots, and run the consumer's
`scripts/verify-rust-custody-source.cjs`. In a new temporary directory,
copy `manifest.template.toml` to `Cargo.toml`, replace its two absolute checkout
placeholders, copy the retained lock to `Cargo.lock`, and create an empty
`src/lib.rs`. Then run from that directory:

```sh
cargo +1.98.1 metadata --locked --offline --format-version 1
cargo +1.98.1 check --locked --offline
cargo audit --file Cargo.lock --no-fetch --json
```

The last command is expected to exit1 while the RSA advisory remains. Do not run
it from the producer checkout and mistake that checkout's exception for a new
combined approval. The initial sccache sandbox refusal and authorized resolution
are retained as `sandbox-denial.log` and `resolution.log`. Cache/toolchain setup
is external to this receipt; no download or dependency replacement is implied.
An independent replay retained the RSA finding/settings/database but did not repeat
the original spin0.9.8 yanked warning. Registry/cache metadata can change that warning;
the original audit report is preserved as dated evidence, not byte-identical replay.
