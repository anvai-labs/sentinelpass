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

