# SentinelPass 0.18.0

Release preparation: promote develop to main through a single squash commit only
after clean adversarial review and green CI for the exact PR head. The owner has
explicitly authorized admin bypass of code-owner approval under those conditions.
Tag main only after promotion; tag-time release security, feature matrix and
installer gates remain required. This file does not assert publication has occurred.

## Changes

- Add versioned personal recovery-secret custody contracts, generated metadata
  bindings and authenticated schema14 storage. Exact-object leases, fresh-password
  administrative approval, cancellation, revocation and backup/restore/rekey paths
  have synthetic qualification. Application enrollment remains unavailable.
- Reject duplicate custody identities during receipt/deep verification and reject
  positional-array metadata at native ports. Fresh independent reviews include
  retained failing regressions and verified corrections.
- Patch root-lockfile TLS/QUIC advisories with quinn-proto0.11.18 and rustls0.23.46.
  Existing governed audit policy is unchanged.
- Freeze Sandesha recovery binding bytes with independent Node/Rust conformance,
  source-drift tooling and native integration workcards. The combined OpenPGP graph
  is isolated evidence only; it adds no shipping runtime dependency or capability.

- Make protocol crate test fixtures self-contained and check the extracted archive
  in CI. Align the fuzz lockfile local versions and require the desktop feature
  and packaging gates before crates.io publication as well as GitHub release.

## Limits

This release does not enable Sandesha recovery enrollment, browser secret transfer,
cross-device custody, mobile relay sync or hardware-backed OpenPGP operations.
OIDC and operator/service credentials grant no personal custody authority. Native
storage integration, trusted UI/application-peer transport and physical device
qualification remain open. The combined graph's RSA advisory/feature/notice review
is not waived by the producer's existing exception.

Existing pre-1.0 platform assurance limits remain: signing/notarization, updater
provenance and physical mobile acceptance are not established by source tests.
Follow the OSS release checklist and platform installation documentation. Do not
describe this as the completed end-to-end encrypted-mail product.

## Evidence

Runtime PR269: candidate1df0279, merged026d772;45 successful checks/7 skips.
See `evidence/custody-kc02/ci-1df0279.json` and independent review reports.
Follow-up binding/preflight CI and tag-time release evidence must be linked in
the promotion PR/release record when complete. Mobile workflows must also be
dispatched against the actual tag, as required by the release checklist.
