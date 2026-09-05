# ADR-003: Security Baseline and Release Gates

| Field | Value |
|-------|-------|
| Status | Accepted (rev 3, 2026-09-04 — owner decision after three adversarial review rounds) |
| Date | 2026-09-04 |
| Owners | Security lead, technical lead |
| Related | Strategic remediation plan; security status matrix |

## Summary

Define the adversaries SentinelPass addresses, the limits it communicates, and the
evidence required before a security control or release is called production-ready.

## Context

The repository contains strong security intent, but some documentation describes a
target state while implementations remain partial. A password manager needs an
explicit boundary between design, implementation, verification, and shipped claims.

## Decision

SentinelPass will maintain one reviewed threat model covering offline read/write vault
access, malicious local peers, malicious sites, compromised relays/networks, lost
devices, forgotten passwords, stale devices, rollback, and interrupted operations.

Controls use these states:

- `Planned`: design intent only.
- `Experimental`: reachable implementation without production assurance.
- `Partial`: useful control with documented gaps.
- `Implemented`: code plus relevant positive and negative automated evidence.
- `Verified`: implemented control reviewed through release or independent assurance.

A 1.0 release requires zero unresolved critical/high trust-boundary findings,
successful recovery/restore drills, a **compromise-rotation drill** (full-DEK
rotation with relay re-baselining per ADR-004 rev 2 — the plan's verification matrix
names it; this gate makes it blocking), signed artifacts/updater metadata, sync chaos
evidence, mobile platform evidence, and closure of an independent audit cycle.

Supported defenses do not claim to defeat root/administrator compromise, injection
into an unlocked process, or revocation of previously copied offline vault snapshots.

### Same-user malicious code (rev 2, from adversarial review)

**Malicious code running as the local user is an explicit, documented non-goal** for
the 0.9–1.0 line: the IPC token file is same-UID readable by design, and no
same-user process boundary exists on current desktop platforms — a same-UID process
can read any credential the user can. This is stated publicly rather than implied by
the root/injected-process non-claims. Capability scoping (ADR-007, WBS-504/505) is
nevertheless designed *against* this adversary as damage limitation: it removes the
ambient "any token-bearing process can request any browser credential" surface, so
the attacker needs per-operation capability material rather than one file read — a
hardening boundary, not a defense. The status matrix's Release Interpretation and
the README security notes carry this non-claim (updated in the same change as this
ADR's acceptance).

### Status downgrades (rev 2)

When evidence for an `Implemented`/`Verified` control is contradicted (finding,
regression, broken test), the security lead flips the matrix row to `Partial` (or
lower) **before the next release cut**, records the reason as a register input
(regenerated from the TD tables per WBS-005 — never hand-edited), and the
critical-gate checklist consumes the regenerated register — a stale register entry
blocks the release rather than passing silently. Downgrade decisions are reviewable
like any other evidence change.

## Options Considered

- Continue narrative security claims: rejected because status is ambiguous.
- Treat passing unit tests as sufficient: rejected because platform and operational
  boundaries need negative and integration evidence.
- Use explicit status and release gates: proposed.

## Threat Model

The baseline must distinguish confidentiality from integrity and availability, and
read-only theft from an attacker able to alter storage or protocol traffic. Residual
risk is documented beside each control rather than hidden in general disclaimers.

## MVP vs. Later

- MVP: consolidated threat model, status vocabulary, release checklist, evidence links.
- Later: formal assurance cases, reproducible-build measurements, and periodic external
  reassessment.

## Migration and Rollout

Audit all public and repository security claims, update the status matrix, then make
the release workflow consume a machine-checkable critical-gate checklist.

## Consequences

Feature delivery may pause when evidence is incomplete. In return, product claims,
engineering priorities, and release decisions become reviewable and defensible.
