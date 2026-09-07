# ADR-010: Release Assurance and Provenance

| Field | Value |
|-------|-------|
| Status | Proposed (rev 2, 2026-09-07 — folds adversarial review round 1; awaiting owner acceptance) |
| Date | 2026-09-07 |
| Owners | Release maintainer, security lead, technical lead |
| Related | ADR-003; ADR-009; OSS release checklist |

## Summary

Require security CI, platform signing, signed checksums and update metadata,
SBOM/provenance, recovery drills, and independent review as production release gates.

## Context

Current CI has useful lint, test, dependency, and scanning workflows, but release jobs
do not yet prove every security feature combination, platform behavior, signature,
notarization, provenance, or restoration path. Mobile default builds can omit JNI.

## Decision

Tag releases depend directly on required security workflows; enforcement evaluates the
tagged commit itself (the release workflow re-runs the required security jobs at the
tag SHA), never inherited PR results. The chrome-v* Web Store publishing tag namespace
is inside the gated release process. The matrix includes all security-relevant Cargo
features, mobile ABIs, browser variants, migrations, restore fixtures, IPC negative
tests, sync model/chaos tests, dependency and secret scanning, and platform package
smoke tests.

Official artifacts carry signed checksums, an SBOM, provenance attestation, platform
signatures, and macOS notarization; for browser extensions, store signing is the
extension's signed channel. 1.0 artifacts additionally carry signed update metadata;
when an in-app update channel ships, its metadata must be signed and
version-monotonic, with downgrades refused absent explicit user recovery action. The
release maintainer owns signing credentials: CI secrets now, with an isolated
signer/HSM as the target custody. If a platform signing credential cannot be procured
by RC, that gate may be waived only via a superseding ADR recording the accepted
risk. Every dependency vulnerability exception records owner, exposure, mitigation,
expiry, and review date.

A 1.0 release additionally requires an independent review covering cryptography use,
recovery, sync, IPC, browser, desktop, Android, and iOS, with all critical/high findings
closed.

## Options Considered

- Checksums published beside unsigned artifacts: rejected as inadequate provenance.
- Best-effort platform signing after release: rejected for official security software.
- Security workflow, provenance, signing, and audit as release gates: proposed.

## Threat Model

Addresses compromised build inputs, artifact substitution, unsigned update channels,
untested optional features, dependency regressions, and discrepancies between source
and official packages. It cannot by itself make a compromised CI control plane safe;
key isolation, least privilege, and review remain necessary.

## MVP vs. Later

- MVP: gated CI, feature matrix, signing/notarization, SBOM, provenance, signed
  checksums and update metadata, vulnerability-exception governance.
- Later: the in-app update channel (signed, version-monotonic, downgrade-refusing),
  reproducible-build comparison, and independent multi-party release approval.

## Migration and Rollout

Add non-blocking evidence generation first, then make each control required after its
credentials and platform runners are stable. Between acceptance and 1.0, tagged
releases run the workflows that exist at the tag with remaining controls advisory; the
full Decision binds at 1.0/RC. No 1.0 tag is cut while a required gate is advisory or
skipped. Existing inline audit ignores (e.g. RUSTSEC-2023-0071) migrate into the
governed exception lifecycle (WBS-909), and published sha256sum verification guidance
updates when signed checksums land.

## Consequences

Releases become slower and require secure key/credential operations. Until
reproducible builds land, provenance attests the build process, not binary-to-source
equivalence. Users gain a verifiable chain from reviewed source to installed package
and update.
