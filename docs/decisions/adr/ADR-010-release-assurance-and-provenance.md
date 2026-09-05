# ADR-010: Release Assurance and Provenance

| Field | Value |
|-------|-------|
| Status | Proposed |
| Date | 2026-09-04 |
| Owners | Release maintainer, security lead, technical lead |
| Related | ADR-003; OSS release checklist |

## Summary

Require security CI, platform signing, updater verification, SBOM/provenance, recovery
drills, and independent review as production release gates.

## Context

Current CI has useful lint, test, dependency, and scanning workflows, but release jobs
do not yet prove every security feature combination, platform behavior, signature,
notarization, provenance, or restoration path. Mobile default builds can omit JNI.

## Decision

Tag releases depend directly on required security workflows. The matrix includes all
security-relevant Cargo features, mobile ABIs, browser variants, migrations, restore
fixtures, IPC negative tests, sync model/chaos tests, dependency and secret scanning,
and platform package smoke tests.

Official artifacts carry signed checksums, an SBOM, provenance attestation, platform
signatures, macOS notarization, and signed updater metadata verified before update.
Every dependency vulnerability exception records owner, exposure, mitigation, expiry,
and review date.

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

- MVP: gated CI, feature matrix, signing/notarization, SBOM, provenance, updater
  signatures, vulnerability-exception governance.
- Later: reproducible-build comparison and independent multi-party release approval.

## Migration and Rollout

Add non-blocking evidence generation first, then make each control required after its
credentials and platform runners are stable. No 1.0 tag is cut while a required gate is
advisory or skipped.

## Consequences

Releases become slower and require secure key/credential operations. Users gain a
verifiable chain from reviewed source to installed package and update.
