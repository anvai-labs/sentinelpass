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

