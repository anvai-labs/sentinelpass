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
| [ADR-006](ADR-006-sync-protocol-v2.md) | Transactional sync protocol v2 | Accepted (rev 2) |
| [ADR-007](ADR-007-daemon-authority-and-ipc-capabilities.md) | Daemon authority and IPC capabilities | Accepted (rev 2) |
| [ADR-008](ADR-008-authenticated-backup-and-verified-restore.md) | Authenticated backup and verified restore | Accepted (rev 2) |
| [ADR-009](ADR-009-mobile-abi-and-platform-keystore.md) | Mobile ABI and platform-keystore boundary | Accepted (rev 2) |
| [ADR-010](ADR-010-release-assurance-and-provenance.md) | Release assurance and provenance | Accepted (rev 2) |
| [ADR-011](ADR-011-service-credentials-systemd.md) | Restart-safe service credentials via systemd | Accepted |
| [ADR-012](ADR-012-shared-private-file-custody.md) | Shared private-file custody | Accepted |
| [ADR-013](ADR-013-admin-step-up.md) | Master-password administrative step-up (SP-0) | Accepted |
| [ADR-014](ADR-014-service-grants-v2.md) | Exact-entry service grants (SP-1) | Accepted |
| [ADR-015](ADR-015-trusted-peer-context.md) | Trusted peer context (SP-2) | Accepted |
| [ADR-016](ADR-016-executable-policy.md) | Linux executable policy (SP-3) | Accepted |
