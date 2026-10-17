# v0.18.0 promotion qualification

Preparation evidence, 2026-10-17. Publication is conditional on clean review and
green exact-head PR CI, followed by the tag-time gates. These local results do
not assert that promotion or publication has completed.

The full main-to-candidate review found three release issues beyond the scoped
custody reviews. The observed failures are retained in `red-evidence.md`:

- Fuzz's detached lockfile retained three local 0.17.0 package records. They now
  match 0.18.0. Registry package objects are unchanged; locked Cargo metadata
  resolves successfully after fetching missing cached packages.
- Published protocol tests referenced five files outside the crate. Canonical
  fixtures now live inside the crate; the binding generator mirrors them to the
  existing cross-language paths, and its `--check` mode rejects drift. The CI
  archive test extracts the actual package outside the repository and passes
  seven custody tests plus all 17 valid / 38 invalid binding vectors.
- The existing crates.io job waited only for security audits. It now also waits
  for bundle smoke, native-installer smoke and the feature/platform matrix,
  matching the desktop gates on GitHub release publication.

`source-check.json` records 66 matching scoped pins with both readiness flags
false. Original 61-file manifests/receipts remain historical; the current
manifest explicitly records version and packaging refreshes. Runtime custody
source and generated metadata bytes are unchanged by these corrections.

Before these packaging corrections, `cargo test --workspace --verbose` passed,
including 882 core tests (six intentionally ignored), and required commit hooks
passed Rust formatting/lint/tests plus all 125 TypeScript tests. The corrected
archive was then tested independently by the release reviewer. Exact-head CI
must validate the eventual committed candidate across platforms.

Physical mobile acceptance, signing/notarization and complete workspace MSRV
qualification are not implied. Mobile workflows must be dispatched on the tag;
the existing 1.89 Shared I/O check covers that crate, not every dependency in the
desktop workspace. The isolated OpenPGP graph remains nonshipping evidence.
