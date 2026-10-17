# Independent native-graph preparation review

Date: 2026-10-17. Reviewer: separate storage/contracts agent. Source checkout at review start: `732b0d883eeddfa414a0957b87906e0d088a69fa`, with the listed preparation files in the working tree. Graph capture uses producer runtime `1df027932f08baabf2afebb6a0444bab867fcd12` (0.17.0), preparation `732b0d8`, consumer inspected head `e84047213473dd8cc8eaf75ce850dd759b208c1f`, and verified upstream vendor revision `019d4cd2d81e2ae21c5b7f9e217a7ff4cb63b438`.

## Conclusion

No security blocker was identified for retaining this **nonshipping dependency-resolution and macOS compile-preflight evidence**. This review does not approve adopting, linking, running, distributing or releasing the combined native dependency graph. Its unfiltered RSA advisory is a real, unresolved adoption gate; neither compilation success nor an existing producer exception closes it. Final combined feature/exposure verification, license notices/source provenance, other platform testing and actual recovery integration remain required.

The concurrent 0.18.0 version-only release-preparation diff introduces no combined dependency or new runtime authority. Clean exact-head CI and the user's explicitly authorized release/merge procedure remain the parent agent's responsibility; this technical review itself is not a merge operation or a waiver of native adoption gates.

## Findings and clarification

No hidden advisory waiver or false runtime-success claim was found. The receipt clearly distinguishes compile feasibility from adoption, and records both the exception-filtered scan and the failing unfiltered scan. `runtimeIntegrationApproved` and `distributionApproved` are false.

The reproduction clarification requested during review has been resolved in the final README: the retained graph lock captures path packages at 0.17.0, so reproduction must use its pinned 0.17.0 producer checkout and inspected consumer sources, not arbitrary current checkout paths. `--locked` should fail if those local manifests have moved to 0.18.0. Likewise, 'no application manifest/lockfile changed' describes the graph-capture action, not the later release-version refresh. The final README explicitly requires producer 1df0279 or the byte-identical 026d772 squash and the historical inputs-1df0279 source pins through checkSources with explicit roots. It says a later 0.18.0 checkout correctly fails --locked and forbids silently regenerating this historical lock. This closes the documentation issue.

The retained unfiltered scan contains a yanked warning for spin 0.9.8. The independent re-scan returned the identical RSA vulnerability object, database/settings and other warning classes, but omitted that yanked warning. Therefore the report is correctly treated as dated local evidence, not byte-for-byte reproducible registry-yank state. The original warning must stay retained; no downgrade of the RSA failure is justified.

## Independent checks

- Reconciled every one of the 406 inventory packages against `/private/tmp/custody-combined-metadata.json` and retained `Cargo.lock`: identity, version, source, registry checksum, declared license, declared Rust requirement and resolved features all matched exactly. Inventory, resolved metadata and lock each contain 406 packages.
- Recomputed the consumer feature differences: exactly 10, matching the retained list. Recomputed producer version-list differences: exactly 38, matching the retained list. Every registry identity appears in at least one producer/consumer baseline. This does not imply newly unified features or call paths were previously reviewed.
- Producer baseline covers 716 workspace packages; consumer baseline covers 146. Differences from the full producer workspace legitimately include omitted applications and target-conditional dependencies. The inventory does not claim all resolved packages executed on macOS.
- The combined graph has seven local packages: the empty qualification root, sentinelpass-core, sentinelpass-protocol, anvai-secure-io, sandesha-mail-custody, anvai-openpgp, and vendored pgp. Local source identity is not established by a crates.io checksum; separate source pins remain necessary.
- At graph review start, both shipping lockfiles matched the capture hashes, and the retained combined lock was byte-identical to `/private/tmp/custody-native-graph-ZmUGo4/Cargo.lock`. The shipping producer lock subsequently changed only for the requested release versions, as detailed below.
- Independently reran `node scripts/check-custody-handoff.mjs /private/tmp/sandesha-rust-assets-pilot-20261016`: pass, 61 source pins (before the release-version bump; independent output `/private/tmp/custody-native-graph-review-source-check.json`).
- Independently reran the consumer `node scripts/verify-rust-custody-source.cjs`: verified true, 791 files, upstream `019d4cd2d81e2ae21c5b7f9e217a7ff4cb63b438`. The historical README's older revision/file count was not used as evidence.
- Independently reran `cargo +1.98.1 check --locked --offline` from the actual isolated probe using its existing cache before the release-version bump: exit 0, 0.58s cached check. Existing generic-array deprecation and block 0.1.6 future-compatibility warnings remained. This was type checking only; it exercised no vault, recovery operation, key generation, native linkage artifact, mobile target or performance scenario.
- Independently reran `cargo audit --file Cargo.lock --no-fetch --json` from the isolated probe: exit 1; `ignore=[]`; one vulnerability, rsa 0.9.10 / RUSTSEC-2023-0071. Output is `/private/tmp/custody-native-graph-review-audit.json`. The advisory Git database was independently checked at `64f92cdc64401fab47baa10e2e11fe382aa57155`. JSON null revision/date fields are not being treated as proof of freshness.
- The existing producer audit config explicitly scopes its RSA waiver to established SSH/local exposure and contains no newly added exception. The combined graph newly unifies rsa/sha2 relative to the consumer; the receipt lists it, and calls for new exposure verification. Inspected consumer policy/framing and negative-test source support the claim that its existing policy excludes RSA, but this review does not substitute source inspection for combined runtime negative tests.
- Every real inventory package has a license declaration. Only the empty nonshipping qualification root lacks one, as documented. Declared SPDX strings are not a completed redistribution-notices inventory or legal clearance.
- Read resolution, compile, sandbox-denial and consumer-verifier logs. The sandbox failure was retained, followed by successful authorized compilation. Raw `.log` files are ignored by repository defaults; parent was reminded to stage them explicitly if committing the receipt.

## Version-only release-preparation addendum

Reviewed the concurrent diff against `732b0d8`:

- Workspace version and Tauri app version change from 0.17.0 to 0.18.0 only. Rust baseline remains 1.89 and edition remains 2021; the graph probe's separate 1.98.1 requirement is not adopted into the shipping workspace.
- Exactly eight first-party lock package version fields change: CLI, core, daemon, host, mobile bridge, protocol, relay and UI. No local package dependency arrays or package names change.
- All 706 registry/git lock package objects compare exactly equal before/after; no third-party version, checksum, source or dependency edge changed.
- The root manifests do not add Sandesha, vendored OpenPGP, a qualification workspace member or production custody enablement. The graph's 0.17.0 capture hash remains historical; its combined lock must not be presented as a qualified 0.18.0 runtime graph.

## Reviewed hashes

These hashes identify the evidence and release-version files read. Metadata files are temporary reviewer inputs, not proposed shipping artifacts. Historical graph lock hash remains `8f9eb81822b81eef1ab9ab595eebb7e7ac204abbfdc126283cb14eb86158f7fe`; historical producer lock hash remains `0a4f044720cc2b23475c088cb3f98b7cab0e9e477b58119c511560c8f015e06d`.

```json
{
  "docs/evidence/custody-native-graph/Cargo.lock": "8f9eb81822b81eef1ab9ab595eebb7e7ac204abbfdc126283cb14eb86158f7fe",
  "docs/evidence/custody-native-graph/README.md": "50eb2b42c4774fa81f712e328ce63fc8b75ebe5c68cb923b6a5e6ce5b88de165",
  "docs/evidence/custody-native-graph/audit-with-producer-policy.json": "006c5c865d0d51f695d55a22bbac5078cc5b8a175d3b5e915334ad3f24d785a7",
  "docs/evidence/custody-native-graph/audit-without-exceptions.json": "66f887887d656a2f643f5f18809df52fa75a146c5ef5db537f2a175b1e7b2a09",
  "docs/evidence/custody-native-graph/compile.log": "b7e51b63bdb28ed066fe0ef66c2cd42a5c10748f4f551d4d7b1ca0f8c642b4d8",
  "docs/evidence/custody-native-graph/consumer-source-check.log": "f249e737f6502bc1a787486f43975b9a10522bd0e81638d9f5f3800312f7c025",
  "docs/evidence/custody-native-graph/inventory.json": "14c7a3ab70b287868a24662aa64f560271dcae336a817fafd779a04926394c5f",
  "docs/evidence/custody-native-graph/manifest.template.toml": "7ac8895270335c390bd3072da200144b964d794e8b03c12e3e16e4f5cc5c7397",
  "docs/evidence/custody-native-graph/resolution.log": "3a5454ff0bddff33d013714224d1e53be5581f81c72dbf9dccb074d17c713989",
  "docs/evidence/custody-native-graph/sandbox-denial.log": "7e6ce9d34fbabdf3731194c19e3f09aa0b2da0eb123b3b156a63ea11893cb281",
  "Cargo.toml": "35cd8d8a5cdb3fc4a14670a6ec3ec996bcbcb2862af8e30b737a56b739bbd385",
  "Cargo.lock": "27cd090b1ab7d12ad54e2f6661950ec9e9ac500895be12ad460370e3955c38d2",
  "sentinelpass-ui/tauri.conf.json": "20823272345675e83cea9fc674aa444a00db4a84c9151f9d3b0afaf011c5b9fb",
  "/private/tmp/custody-producer-metadata.json": "e82ddc1b08879c6fec4e104a744638653b8572a89ee4d88cdc24723911804340",
  "/private/tmp/custody-consumer-metadata.json": "9d68ea363e254995dfa658b64b1b97334245950fe793388b23e204de5ecaee53",
  "/private/tmp/custody-combined-metadata.json": "74fd9ca3e287ad535d16b76575471fa54d09d409e051cf19f91413e5f747755e"
}
```

Final disposition: **no remaining blocker for this documentation-only graph evidence or the reviewed version-only preparation changes**. RSA exposure, unified feature policy and distribution notices remain explicit native-adoption blockers. The review does not authorize shipping the combined graph. Final README and release-version hashes above supersede the earlier working-tree capture.

Whitespace-only finalization: removed one extra terminal newline from `docs/evidence/custody-native-graph/sandbox-denial.log`. Adding exactly that newline reproduces the prior reviewed SHA-256. All other reviewed file hashes remain unchanged; substantive log content and review disposition are unchanged.
