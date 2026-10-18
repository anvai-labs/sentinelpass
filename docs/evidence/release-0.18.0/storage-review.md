# SentinelPass 0.18.0 promotion storage/dependency review

Reviewed 2026-10-17, independently and read-only. Promotion base: `b7b9f5c3c886cdb0532fe5e60dec39e1d07ce061` (origin/main). Checkout HEAD: `d354eff5a2afbde4313c8953a31e676cf4b25733` plus the corrective working-tree files identified by SHA-256 below. This is a tree-diff review, not a commit-count review or an exact-head CI receipt. The unrelated untracked IPC probe handoff was not touched.

## Disposition

No remaining blocker found in this review's scoped source/dependency/packaging delta after the corrections below. The parent must still checkpoint these exact bytes, obtain clean reviews and green CI for the exact submitted head, and satisfy tag-time gates before publication. This report neither grants code-owner approval nor transfers any native dependency exception or platform qualification.

## Findings and verified corrections

1. **Release blocker, corrected: detached fuzz lock was stale.** The 0.18.0 manifests still had three 0.17.0 first-party records in fuzz/Cargo.lock. Independent `RUSTC_WRAPPER= cargo metadata --manifest-path fuzz/Cargo.toml --locked --offline --format-version 1` failed explicitly because the lock needed updating. Correction changes only sentinelpass-core/protocol/relay to 0.18.0; no registry record changes occur in this corrective delta. Parent subsequently ran online `--locked` successfully after downloading missing already-locked dependencies. The resulting `/private/tmp/custody-018-fuzz-metadata.json` was independently parsed and contains all three expected 0.18.0 packages.

2. **Release packaging blocker, corrected: packaged protocol tests referenced files outside the crate.** `sentinelpass-protocol/tests/custody_contract.rs` previously included five `../../bindings/custody/` files omitted from the archive. Independent `cargo package --list` retained the test and omitted all five fixtures. Fixtures are now canonical under `tests/fixtures`; test includes resolve inside the published package. The generator includes those package-local bytes and its existing `--check` mode verifies mirrored cross-language copies. All five mirrors were independently byte-compared, and generator `--check` passed. `scripts/test-protocol-package.sh:10-18` creates and extracts the actual archive, then runs custody integration tests and the binding example against its manifest with `--locked`. Independent execution passed: 30 packaged files, 7 custody tests, 17 valid / 38 refused binding vectors. Rust CI invokes the script in its clippy prerequisite job, so the regular release-build matrix cannot pass that prerequisite if packaged fixtures regress. This test does not grant runtime authority.

3. **Inherited publication ordering gap, corrected before tagging.** The crates.io job previously waited on audit jobs but could publish before desktop feature and installer gates finished. `.github/workflows/release.yml:688` now also requires bundle-smoke, native-installer-smoke and feature-matrix, matching the GitHub release's substantive gates. Tag-only conditions, security and npm audit gates, manifest/tag equality and the locked publish invocation remain intact. Failures/skips in required jobs do not bypass the default success dependency condition.

Observed pre-correction evidence is retained in `/private/tmp/custody-018-promotion-red-evidence.md`; the original package listing is `/private/tmp/custody-018-protocol-package-list.txt`. This report does not claim an independently run pre-fix extracted-crate compiler failure: the package listing and external include paths established that defect. Parent's separate red logs may provide further evidence.

## Dependency and version boundaries

- Root manifest, eight first-party lock records and Tauri application version align at 0.18.0. Relative to the preceding prepared producer lock, those version-only changes preserve all 706 registry/git package objects as parsed TOML. Relative to main, earlier develop updates must also be counted: libc 0.2.189→0.2.190, tauri 2.12.0→2.12.1, tauri-plugin-dialog 2.8.0→2.8.1, uuid 1.26.1→1.27.0, direct tower-http 0.6→0.7 (locked 0.7.1), and reqwest's retained tower-http line 0.6.8→0.6.11. The reviewed custody security remediation updates quinn-proto 0.11.15→0.11.18 and rustls 0.23.45→0.23.46 with their new random/chacha transitive records.
- Relay use is confined to trace and request body limiting in the inspected source. The tower-http 0.7 breaking areas reviewed in the cached changelog do not produce a concrete regression in those call sites. Existing relay code did not change in this promotion dependency delta. This is source inspection, not an independent full relay/platform regression run.
- Root npm changes are development tooling: Vitest/coverage/mocker/spy 5.0.2→5.0.3, Vite 8.3.1→8.3.2, Rolldown 1.2.11→1.2.12 and optional native variants, OXC types 0.151→0.152, source-map-js 1.2.1→1.2.2, why-is-node-running 3.2.2→3.2.1, plus lock metadata. E2E updates @types/node 26.6.3→26.6.4. Production esbuild remains 0.28.2. Manifest dependency maps match their lockfile roots; both `npm ls --package-lock-only --all --json` passed. Resolved package locations remain the public npm registry; no added file/git/alternate-registry dependency was found.
- Detached fuzz lock alignment includes the earlier custody changes and local shared IO dependency, but is not a second shipping workspace. Current corrective fuzz changes are only the three local versions described above. Scheduled/manual fuzz execution does not establish production enrollment or physical device acceptance.
- The isolated native graph remains documentation/evidence only. No Sandesha native crate, anvai-openpgp or pgp dependency was imported into the shipping root manifest/lock. Historical graph capture remains pinned to the 0.17.0 producer state; its lock must not be silently regenerated against the 0.18.0 checkout. Its unfiltered RSA audit failure, non-transferable producer exception, feature/license/notice gates and absent runtime adoption are accurately retained.

## Provenance and unchanged authority

`git diff 1df0279 -- sentinelpass-core/src sentinelpass-protocol/src sentinelpass-mobile-bridge/src` is empty: production source remains the previously reviewed corrected custody implementation. Packaging changes affect examples, tests, fixture copies, CI and evidence; no new provider, native transport, enrollment or release-time runtime capability is added.

The refreshed preflight manifest preserves the exact prior `inputs.json` bytes as `inputs-d354eff.json`. Only generator/test pins change, five canonical fixture pins are added, and `packagingOnlyRefresh` records exact before/after hashes. All 53 producer pins independently match local files; 13 consumer pins are unchanged. The README explicitly distinguishes current 66 pins from historical 61-file source-check evidence. Historic runtime/performance and graph receipts are not rewritten to claim measurement of a new candidate.

## Validation and residual limits

Independent focused validation in this review: pre-fix locked fuzz metadata failure; pre-fix package listing; corrected extracted-package custody tests and binding example; five fixture byte comparisons; generated bindings `--check`; npm locked tree checks; parsed dependency/version/provenance comparisons; release workflow dependency inspection; `git diff --check`. Parent supplied successful locked fuzz resolution, whose metadata was independently inspected. No full workspace, physical platform, live vault, remote enrollment or publication exercise was repeated by this reviewer.

Rust-version declaration remains 1.89, while both the old main Tauri 2.12.0/dialog 2.8.0 and updated 2.12.1/2.8.1 declare Rust 1.90. This is inherited; a narrow shared-IO MSRV check must not be represented as full-workspace Rust 1.89 qualification. Existing release platform assurance limits also remain: source tests do not establish signing/notarization, updater provenance or physical mobile acceptance. Mobile acceptance workflows must target the actual release tag according to the checklist. OIDC/operator/service credentials do not grant personal custody authority. The package/gate corrections do not waive native RSA, feature or notice review.

## Reviewed SHA-256 files

- `Cargo.toml`: `35cd8d8a5cdb3fc4a14670a6ec3ec996bcbcb2862af8e30b737a56b739bbd385`
- `Cargo.lock`: `27cd090b1ab7d12ad54e2f6661950ec9e9ac500895be12ad460370e3955c38d2`
- `fuzz/Cargo.toml`: `321b2959bd021324312a6f6ea816a3036e12b2d885d0048ad1d4fb69976e3487`
- `fuzz/Cargo.lock`: `39969e2390f93c675d5210f2873ac921059255e90064a6b998424f8fc81b7518`
- `package.json`: `051345427b897c175e75967258ec98fb3680e487a6bd7fec20d768d01715fdcc`
- `package-lock.json`: `c106a2b48b6a02321992ed00bc00ae51abd664a2e352dd42d72d61ee89499cb6`
- `browser-extension/e2e/package.json`: `86b919f0fbedef03f276ee8492db7d37320c525eeb249bf3dd67e8bce01d3703`
- `browser-extension/e2e/package-lock.json`: `84c6a1298bf62451ef7092cb0c967066c9049cb78f671794a8d64d91aa30a572`
- `sentinelpass-core/Cargo.toml`: `c7280f38bb2e839b6295a447637d9fdc4c266f7b0180066c0122bee3f4f2ea3d`
- `sentinelpass-protocol/Cargo.toml`: `92d7b4de1dff3453f708c278cf6c6202a99e278abf54189fd42fb578930f2799`
- `sentinelpass-ui/tauri.conf.json`: `20823272345675e83cea9fc674aa444a00db4a84c9151f9d3b0afaf011c5b9fb`
- `.github/workflows/release.yml`: `b60eacda8ffe76a0dc7ecf88c8ebe0056bc8c63b9fad16b346c7ae04e5de2e1e`
- `.github/workflows/rust.yml`: `eb48bc75787a6ea548628c94cb13ad3007d0e847d0ac256c9d4c55f5bd67c3c3`
- `.github/workflows/android.yml`: `37cd4b3c5a1035b34a9b1cfdf32e5a15062a20d965542eabfda83621a758fe86`
- `.github/workflows/fuzz.yml`: `082f7a56ed566cc1c3229454264a3c664b3eb09c5d27a649b941e9e9d0e70ae9`
- `scripts/test-protocol-package.sh`: `ede0cfcde88c5a0ddac530e831a4b2131cfd50b6c1d0dbd898132dd667fa5a9b`
- `sentinelpass-protocol/examples/generate_custody_bindings.rs`: `dcbcb07b7a87fa5d13bc17e54d55a93252cc57b929398bd2e48b2513dd659622`
- `sentinelpass-protocol/tests/custody_contract.rs`: `1dc303b3c98e24da56a792df77e9a40c051c2a7dc134fc169240e4ae20928851`
- `docs/RELEASE_0.18.0.md`: `d2eeb2a665d5a2cba7d6e425d300fd090a5337b05802bf677bfa3b7c3ebff3ce`
- `docs/evidence/custody-kc03-preflight/README.md`: `55600917916921a7d9c2b23a227c5b1869dd341d0085226915bc9d969893aab0`
- `docs/evidence/custody-kc03-preflight/inputs.json`: `5bd3bfb7c515f02c8c7e9fe39106aef3361b474c3c668b0f53f41b3e63e6f9b2`
- `docs/evidence/custody-kc03-preflight/inputs-d354eff.json`: `2035fd5d6e1f71e8162d2a1de6ffb9fedb321f487628fe6f2e316e02f89cded5`
- `docs/evidence/custody-native-graph/README.md`: `50eb2b42c4774fa81f712e328ce63fc8b75ebe5c68cb923b6a5e6ce5b88de165`
- `docs/evidence/custody-native-graph/Cargo.lock`: `8f9eb81822b81eef1ab9ab595eebb7e7ac204abbfdc126283cb14eb86158f7fe`
- `sentinelpass-protocol/tests/fixtures/scope.golden.json`: `5e840c042ef7e4da2253a2c6377295e5a4a9a621b4c204908f2bd3ae30fded1f`
- `sentinelpass-protocol/tests/fixtures/reference.golden.json`: `7c6a19673fd1231ffb96848f403deb47d675fa6831a21b94512c976bec31e93a`
- `sentinelpass-protocol/tests/fixtures/scope.array.invalid.json`: `f42148c58bd5bd85f4844a8e2acf4b7af5eabab3cb7456764c36f5b085c1ca50`
- `sentinelpass-protocol/tests/fixtures/reference.array.invalid.json`: `0d6d94dc5eea8703aa8ca4c5ed8677568f417a1febcb194fdb09fdc0272d6f7a`
- `sentinelpass-protocol/tests/fixtures/capabilities.array.invalid.json`: `44a434cdb7ef7261512476f316867f56ffda2acc49a3238afdbfac37ce966036`
