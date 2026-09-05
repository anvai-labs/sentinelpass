# Architecture Decision Records

ADRs capture significant architectural decisions for SentinelPass: the context they were
made in, the options considered, and the consequences. They are the design-first gate for
large features — no implementation lands before the governing ADR is accepted.

## Conventions

- **Location:** `docs/decisions/adr/ADR-NNN-kebab-case-slug.md`
- **Numbering:** Sequential, never reused. `ADR-000` is not used; numbering starts at 001.
- **Status lifecycle:** `Proposed` → `Accepted` | `Rejected`. An accepted ADR is immutable
  except for its status header; changes to a decision require a new ADR that supersedes
  the old one (`Superseded by ADR-NNN`).
- **Required sections:** Summary, Context, Decision (with the scoping questions it settles,
  options considered, and rationale), Threat model (when security-relevant), MVP vs. later
  split, Migration/rollout path, Consequences.
- **No code in a Proposed ADR.** Implementation follows acceptance, sliced per the ADR's
  rollout section.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](ADR-001-credential-registry-by-logical-entity.md) | Credential registry by logical entity | Accepted (P1 shipped v0.8.1; P2 dashboard on `develop`) |
| [ADR-002](ADR-002-master-password-rotation.md) | Master password rotation via DEK re-wrap | Accepted (shipped v0.8.1) |
| [ADR-003](ADR-003-security-baseline-and-release-gates.md) | Security baseline and release gates | Accepted (rev 3, 2026-09-04) |
| [ADR-004](ADR-004-recovery-key-slots-and-revocation.md) | Recovery key slots and revocation | Accepted (rev 4, 2026-09-04) |
| [ADR-005](ADR-005-authenticated-vault-envelope-v2.md) | Authenticated vault envelope v2 | Accepted (rev 4, 2026-09-04) |
| [ADR-006](ADR-006-sync-protocol-v2.md) | Transactional sync protocol v2 | Proposed |
| [ADR-007](ADR-007-daemon-authority-and-ipc-capabilities.md) | Daemon authority and IPC capabilities | Proposed |
| [ADR-008](ADR-008-authenticated-backup-and-verified-restore.md) | Authenticated backup and verified restore | Proposed |
| [ADR-009](ADR-009-mobile-abi-and-platform-keystore.md) | Mobile ABI and platform-keystore boundary | Proposed |
| [ADR-010](ADR-010-release-assurance-and-provenance.md) | Release assurance and provenance | Proposed |
