# SentinelPass 0.18.0 promotion-scope authority review

Base tree: `origin/main` = `b7b9f5c3c886cdb0532fe5e60dec39e1d07ce061`.
Candidate: current staged/working files over local HEAD
`732b0d883eeddfa414a0957b87906e0d088a69fa`, identified by hashes below.
This review compares trees, not historical commit counts. Runtime custody source
was already reviewed separately at the PR269 candidate and its corrections.

## Disposition

No additional authority/security blocker identified in this promotion tree.
No previously unreviewed production custody enablement or gate weakening was
found. Clean review is conditional on the identified files; it does not assert
the final promotion commit has completed CI. The user's conditional admin-merge
authorization still requires clean review plus green exact-head CI. Release
tagging, tag-time security/platform gates and publication evidence remain separate.

## Beyond the prior custody review

- Main-to-develop-base source comparison for core, mobile, relay and desktop
  runtime code revealed no additional pre-custody runtime implementation delta.
  The larger historical develop ancestry is not additional executable scope.
- The additional Cargo manifest change is relay tower-http 0.6 to 0.7, preserving
  the cors/trace/limit feature list. The lockfile resolves relay tower-http 0.7.1
  and reqwest's tower-http 0.6.11. Inspected the installed upstream changelog and
  the used middleware source against 0.6.8: RequestBodyLimit's implementation is
  unchanged except an added response-body Default implementation and a doc typo;
  relay still installs HTTP TraceLayer and its configured payload limit. The
  source installs no new CORS layer, authentication bypass, filesystem middleware
  or redirect policy. Trace callback changes inspected associate events with
  their supplied span; no new relay secret logging path was found.
- Other pre-custody root lock updates include libc 0.2.190, uuid 1.27.0, tauri
  2.12.1 and tauri-plugin-dialog 2.8.1. The previously reviewed rustls/quinn-proto
  repairs and associated random-number dependencies remain present. Sources
  remain registry packages with checksums; this inspection is not a full source
  audit of every updated upstream crate. Existing security/feature-matrix gates
  must still run on the final release candidate.
- Node lock changes update Vitest/coverage/mocker/spy to 5.0.3, Vite 8.3.2,
  Rolldown 1.2.12 and its platform packages, OXC types 0.152.0, source-map-js
  1.2.2, and the tool dependency why-is-node-running to its pinned 3.2.1.
  All 24 root version-changed package records are dev tooling and retain npm
  registry URLs/integrities. Browser E2E's separate Node types changes from
  26.6.3 to 26.6.4. No browser runtime permissions or code change accompanies
  those updates.
- The version-preparation delta changes Cargo/Tauri to 0.18.0 and exactly eight
  first-party lock records. This latest bump adds no registry graph change;
  that statement is distinct from the broader main-to-candidate dependency
  changes above.

## CI, admission and release claims

- Only Android, fuzz and Rust workflow files differ from main. Changes add
  custody JNI-symbol validation, a metadata fuzz target, generated binding
  drift checking, host JVM/Swift metadata tests and binding-vector conformance.
  No existing mandatory check is removed or marked continue-on-error. Android's
  local build script adds the same metadata-symbol requirement.
- Aggregate Gate, release/security workflows, shared setup actions, audit policy
  and code-owner definitions are unchanged in this tree comparison. No added
  audit exception or weakened signing/release condition was found.
- `web:typecheck` adds custody checking; core's new Tokio test-util feature is
  a dev dependency. The new Rust binding example and packaged vectors are
  qualification tools, with no production enrollment constructor.
- Mobile ABI stays v2. `feature_flags()` still returns only BASE and
  PLATFORM_KEYSTORE; custody and mobile relay bits remain unset. The metadata
  C/JNI surface and host tests do not advertise secret transfer or hardware
  execution.
- Release notes explicitly preserve disabled personal enrollment, browser
  transfer, cross-device/mobile custody and hardware claims. The graph preflight
  is isolated evidence, with unresolved adoption/notice/advisory gates. The
  dated handback separates prior actual merge, automated technical review and
  owner's conditional admin authorization; it does not invent a code-owner
  approval or completed 0.18.0 publication.
- Historical v0.17.0 handback is dated as historical; it does not re-enable the
  retired native-autofill prototype. No change to that runtime surface appears
  in the promotion tree.

## Verification and limits

Read-only inspection included `git diff origin/main`, manifest/lock comparison,
selected installed upstream middleware sources, CI and capability paths, and
the already reviewed release/preflight metadata. No additional full workspace
test was launched while the parent ran final validation.

`git diff --check origin/main` reports two whitespace-only diagnostic lines in
the previously retained raw `containment-red.log` (lines 20 and 22). These are
preserved failure-output evidence, not source formatting or authority defects;
the parent explicitly chose to retain the raw log unchanged. No other diff-check
diagnostic was reported.

The review does not certify upstream package internals, physical devices,
signing/notarization, complete recovery integration or same-UID/root isolation.
Candidate CI and tag-time security scans remain live release conditions.

## Candidate file SHA-256

| File | SHA-256 |
| --- | --- |
| `.github/workflows/android.yml` | `37cd4b3c5a1035b34a9b1cfdf32e5a15062a20d965542eabfda83621a758fe86` |
| `.github/workflows/fuzz.yml` | `082f7a56ed566cc1c3229454264a3c664b3eb09c5d27a649b941e9e9d0e70ae9` |
| `.github/workflows/rust.yml` | `2157d1eae19c5c0a83eb1960927c67383d924cf31c31aec0b903441dd21361e1` |
| `Cargo.toml` | `35cd8d8a5cdb3fc4a14670a6ec3ec996bcbcb2862af8e30b737a56b739bbd385` |
| `Cargo.lock` | `27cd090b1ab7d12ad54e2f6661950ec9e9ac500895be12ad460370e3955c38d2` |
| `package.json` | `051345427b897c175e75967258ec98fb3680e487a6bd7fec20d768d01715fdcc` |
| `package-lock.json` | `c106a2b48b6a02321992ed00bc00ae51abd664a2e352dd42d72d61ee89499cb6` |
| `browser-extension/e2e/package.json` | `86b919f0fbedef03f276ee8492db7d37320c525eeb249bf3dd67e8bce01d3703` |
| `browser-extension/e2e/package-lock.json` | `84c6a1298bf62451ef7092cb0c967066c9049cb78f671794a8d64d91aa30a572` |
| `fuzz/Cargo.toml` | `321b2959bd021324312a6f6ea816a3036e12b2d885d0048ad1d4fb69976e3487` |
| `fuzz/Cargo.lock` | `8f1580291176931a60fbf42bb15efd95edd7164e24af66797eb3dc632c1d8636` |
| `scripts/build-android.sh` | `11c57ab9d5329479ffb0021fe34c44fa902bceaf6ee7b0fc5a367b9ffb6b1849` |
| `scripts/test-custody-native.sh` | `810eaf91d1bf9dd552543399e1ce81038c9924993437db8f4b150030dc3d4042` |
| `docs/RELEASE_0.18.0.md` | `ba8875bbcf82374311563c94668361c795e09237345ba70b4e4da59d1cd8ff2c` |
| `sentinelpass-mobile-bridge/src/abi.rs` | `45b804e98a6ae0061f9eb16bc46909d129368b674e16ce117e7245b4f6969ec0` |

Other reviewed binding/release-preflight file hashes are recorded in
`/private/tmp/custody-binding-review.md`. Any subsequent security-sensitive diff
requires a corresponding review before applying this disposition to promotion.

## Packaging and publication-gate corrective review

Reviewed corrections over `d354eff5a2afbde4313c8953a31e676cf4b25733` after the
independent release reviewer found three packaging/publication issues. The
earlier authority-focused clean disposition did not identify those defects;
this addendum explicitly includes their corrections. No blocker found in the
corrected scope inspected here.

- Detached fuzz lock now updates its three first-party package versions to
  0.18.0. The inspected diff has no registry-package changes.
- Five canonical metadata fixtures now reside inside the protocol crate and
  protocol tests include those local files. The generator uses those same
  canonical bytes for existing cross-language copies and checks their equality
  in `--check` mode. All five local/cross-language pairs were compared directly
  and are byte-identical. Generated-binding `--check` passed independently.
- `scripts/test-protocol-package.sh` uses strict shell error handling, packages
  the crate with `--locked`, extracts the actual archive to an isolated temporary
  directory, and tests its custody integration suite and binding example through
  the extracted manifest. `--no-verify` only avoids Cargo's redundant default
  verification build; the subsequent extracted compilation/tests are mandatory.
  Target artifact reuse does not provide missing source fixture paths. The CI
  step runs the script without dirty-tree overrides. `bash -n` passed. I did not
  repeat the separate release reviewer's already successful archive execution
  (7 tests, 17 positive and 38 negative binding vectors).
- `crates-publish` now depends on bundle smoke, native-installer smoke and the
  feature matrix in addition to its existing security/setup gates. Its existing
  tag-push condition and success-only publish-step condition remain. There is no
  `always()` override or new continue-on-error bypass; a failed dependency
  prevents publication. This strengthens the existing graph and matches the
  GitHub release job's desktop prerequisites. The previous statement that the
  release workflow was unchanged is superseded by this reviewed strengthening.
- Release notes and qualification README accurately identify these changes as
  packaging/gate corrections without enabling custody. Current manifest refresh
  is explicit, preserves the historical version-only manifest byte-for-byte as
  `inputs-d354eff.json`, updates generator/test pins and adds five fixture pins.
  I recomputed **66 matching pins**, with both readiness flags **false**. The
  historical 61-file receipt remains labeled historical; no measured runtime
  evidence was rewritten as qualification of a new source revision.
- `git diff --check HEAD` passed for this corrective diff. The earlier raw-log
  whitespace exception remains historical and unchanged. Runtime metadata and
  custody authority code are not altered by these corrections.

Corrective SHA-256 values (superseding earlier hashes for changed files):

| File | SHA-256 |
| --- | --- |
| `.github/workflows/release.yml` | `b60eacda8ffe76a0dc7ecf88c8ebe0056bc8c63b9fad16b346c7ae04e5de2e1e` |
| `.github/workflows/rust.yml` | `eb48bc75787a6ea548628c94cb13ad3007d0e847d0ac256c9d4c55f5bd67c3c3` |
| `fuzz/Cargo.lock` | `39969e2390f93c675d5210f2873ac921059255e90064a6b998424f8fc81b7518` |
| `scripts/test-protocol-package.sh` | `ede0cfcde88c5a0ddac530e831a4b2131cfd50b6c1d0dbd898132dd667fa5a9b` |
| `sentinelpass-protocol/examples/generate_custody_bindings.rs` | `dcbcb07b7a87fa5d13bc17e54d55a93252cc57b929398bd2e48b2513dd659622` |
| `sentinelpass-protocol/tests/custody_contract.rs` | `1dc303b3c98e24da56a792df77e9a40c051c2a7dc134fc169240e4ae20928851` |
| `docs/RELEASE_0.18.0.md` | `d2eeb2a665d5a2cba7d6e425d300fd090a5337b05802bf677bfa3b7c3ebff3ce` |
| `docs/evidence/custody-kc03-preflight/inputs.json` | `5bd3bfb7c515f02c8c7e9fe39106aef3361b474c3c668b0f53f41b3e63e6f9b2` |
| `docs/evidence/custody-kc03-preflight/inputs-d354eff.json` | `2035fd5d6e1f71e8162d2a1de6ffb9fedb321f487628fe6f2e316e02f89cded5` |
| `docs/evidence/custody-kc03-preflight/README.md` | `55600917916921a7d9c2b23a227c5b1869dd341d0085226915bc9d969893aab0` |
| `docs/evidence/release-0.18.0/README.md` | `ceb0740a54446b5b824292a948b65f4ac1b63eb590eb29a9cd7ea1327aabd3c9` |

Final exact-head CI and tag-time gates remain mandatory; this review neither
reports them completed nor grants runtime activation.
