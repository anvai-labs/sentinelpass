# OSS Release Checklist (Apache-2.0)

## Governance

| Item | Status target |
| --- | --- |
| `LICENSE` contains Apache-2.0 text | Required |
| `NOTICE` file present | Required |
| `CONTRIBUTING.md` present | Required |
| `CODE_OF_CONDUCT.md` present | Recommended |
| `SECURITY.md` present | Required |

## Metadata

| Item | Location |
| --- | --- |
| Rust license metadata | `Cargo.toml` workspace + crates |
| Repo URL/homepage | `Cargo.toml` workspace |
| CI release automation | `.github/workflows/release.yml` |

## Release Hygiene

| Gate | Command |
| --- | --- |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| TS typecheck | `npm run web:typecheck` |
| TS tests | `npm run test:ts` |
| Security scan | `.github/workflows/security.yml` |

## Artifacts

| Platform | Expected installer path |
| --- | --- |
| Windows | `sentinelpass-installer-<tag>-windows.zip` |
| macOS | `sentinelpass-installer-<tag>-macos.tar.gz` |
| Linux | `sentinelpass-installer-<tag>-linux.tar.gz` |

All installers should default to user-level install paths and avoid admin requirements.

### macOS DMG acceptance

Validate the **final published DMG**, not just the pre-bundle staging directory. Record these checks with the release evidence:

- Download the DMG and its checksum manifest from the same release; verify the exact asset's SHA-256 and `hdiutil verify` result.
- Mount read-only and confirm `CFBundleShortVersionString` matches the tag, the architecture matches the advertised platform, and the UI plus **both** daemon and native-host helpers are nonempty and executable.
- Verify the complete app with `codesign --verify --deep --strict --verbose=2`, inspect its Developer ID identity, and require successful `spctl --assess --type execute --verbose=4` plus notarization/stapling evidence under [ADR-010](decisions/adr/ADR-010-release-assurance-and-provenance.md).
- Test a browser-downloaded copy with normal quarantine metadata on a clean Mac. Copy into Applications, eject the DMG, launch normally, unlock, and verify browser integration. Repeat with an older app/default vault, including the documented legacy-permission refusal and repair.
- Confirm native-host manifests point to the installed bundle, and check coexistence with the Homebrew CLI and any existing daemon service.

These are manual acceptance checks until enforced in release CI. The `0.11.0` DMG passed download/payload checks but **failed signature/Gatekeeper assessment** ([#148](https://github.com/anvai-labs/sentinelpass/issues/148)); a launch from a CLI download does not satisfy the browser-origin check. The user-facing procedure and observed limitations are in [MACOS_INSTALL.md](MACOS_INSTALL.md). Do not overwrite existing published assets to disguise a packaging defect; ship a corrected version when the signing prerequisites are available.

## Tag-time CI prerequisites (TD-REL-01)

The `release` job in `.github/workflows/release.yml` fails closed unless ALL
of the following are green at the tag — nothing publishes past a red gate:

| Gate | Mode |
| --- | --- |
| RustSec audit (governed policy) + npm audits (root, extension e2e) | Automatic — `release.yml` WBS-901 jobs |
| Feature/platform matrix: `cargo build --release --locked --workspace` × {default, `--no-default-features`, `--features sync`} on Linux/macOS/Windows | Automatic — `release.yml` `feature-matrix` job (WBS-902) |
| Native installers carry daemon/host sidecars; packaged CLI executes with `--version` matching the tag (daemon/host/UI asserted present + executable) | Automatic — `release.yml` `native-installer-smoke` job (WBS-905) |
| Mobile: Android all-ABI JNI builds + exported-symbol gate; iOS bridge builds + contract tests | **Manual** — dispatch `android.yml` / `ios.yml` (Actions tab → Run workflow) against the tag ref; both accept `workflow_dispatch` |

The mobile step is manual because mobile CI is PR-path-filtered and
deliberately outside the desktop feature matrix (WBS-902 scope); it does not
run automatically on tag pushes.

## Supply chain / SBOM (WBS-908)

Release binaries are built with **`cargo auditable`** (release.yml): every
shipped binary embeds its exact dependency list (crate name, version,
checksum) in a compressed blob.

**Why this form over a standalone SBOM file (syft / CycloneDX / SPDX):** the
SBOM travels inside the artifact, so it cannot drift from the binary the way
a sidecar file can; consumers and auditors can recover it offline with
`cargo audit bin ./sentinelpass`; and the same data feeds vulnerability
matching without extra publishing infrastructure. If a standalone
CycloneDX/SPDX document is ever required (e.g. for regulatory consumers), it
can be generated from the embedded data without changing the release build.

**Verification (also run as a Linux gate in release.yml):**
```sh
cargo audit bin target/release/sentinelpass
```
The gate fails the release if the embedded SBOM is missing or if a
dependency inside the binary matches a known advisory. Dependency EXCEPTION
policy lives in `docs/DEPENDENCY_EXCEPTIONS.md` (WBS-909); signing and
provenance remain open under TD-REL-02/ADR-010 (WBS-906/907).
