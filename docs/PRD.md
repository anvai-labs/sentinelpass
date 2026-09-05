# SentinelPass Product Requirements Document (PRD)

**Version:** 1.0 (gap-reset baseline)  
**Date:** 2026-02-26  
**Status:** Active working PRD

## 1. Product Vision

SentinelPass is a local-first password manager with transparent, auditable security and optional encrypted sync, designed to be trustworthy enough for security-conscious individuals and extensible enough to become a business-grade secrets and credential platform.

## 2. Problem Statement

Most password managers force users to choose between:

- convenience and cloud lock-in,
- self-hosting and poor UX,
- strong security claims and opaque implementation details.

SentinelPass aims to provide:

- a strong local-first default,
- open and inspectable trust-critical components,
- optional sync and premium features as additive services.

## 3. Target Users

## Primary personas (12-month focus)

### P1. Security-conscious individual

- Wants local control of data.
- Uses browser autofill heavily.
- Needs TOTP and SSH key storage.
- May self-host sync or avoid cloud entirely.

### P2. Developer / power user

- Uses SSH keys, multiple devices, and CLI workflows.
- Values self-hostability and protocol transparency.
- Wants import/export and reliable sync conflict handling.

### P3. Privacy-focused professional

- Needs strong docs and clear security claims.
- Cares about auditability and minimal data collection.
- May pay for convenience (hosted relay, support) but not opaque security.

## Secondary personas (post-hardening)

- Small teams
- IT admins
- Compliance-driven organizations

## 4. Product Principles

1. **Local-first by default**
2. **Trust-critical code remains auditable**
3. **Security claims must map to implemented controls**
4. **Paid features are additive, not hidden dependencies**
5. **Cross-platform parity matters (desktop, browser, mobile)**
6. **Operational simplicity for self-hosters**

## 5. In-Scope (Next 12 Months)

## Core security and reliability

- Harden daemon IPC on Windows.
- Harden relay authz/rate limiting/cleanup/config enforcement.
- Tighten extension origin validation and release logging behavior.
- Add tests around trust-boundary code.

## Product completeness (individual users)

- Browser extension popup parity (search/add/settings).
- Password health baseline (local analysis, reuse/weak detection).
- Import/export (KeePass, Bitwarden priority).
- Mobile autofill completion (iOS + Android).

## Commercial packaging foundations

- Define free vs paid tier boundaries.
- Establish public OSS repo + private commercial repo operating model.
- Add entitlement/capability architecture without weakening OSS core.

## 6. Out of Scope (for this cycle)

- Enterprise SSO/SCIM before relay/IPC hardening is complete.
- Shared/team vaults before individual-user product completeness baseline.
- Closed-source cryptography, vault format, or sync protocol changes.
- Mandatory cloud dependency for core product usage.

## 7. Key Differentiators

- Local-first and optional sync (not cloud-mandatory)
- Open-source trust surfaces (core crypto/vault/protocol/client path)
- Self-hostable E2E relay with documented protocol
- Desktop + browser + mobile path with shared Rust core
- Security posture transparency (implemented vs planned controls)

## 8. Free / Paid Tier Product Packaging (Proposed)

## Community / OSS (source + self-build)

- Core vault and crypto
- CLI
- Desktop app
- Browser extension
- Native host + daemon
- Sync protocol + self-host relay
- TOTP and SSH key storage
- Basic import/export (at least open/common formats)

## Free Official Tier (signed binaries, no paid subscription)

- Official desktop builds and extension releases
- Local-first use with no account required
- Self-host relay compatibility
- Baseline password health (local-only)

## Paid Personal (Pro)

- Managed encrypted relay hosting
- Advanced health and breach monitoring integrations
- Priority support / recovery workflows (without access to plaintext secrets)
- Convenience services (device management UX, hosted notifications where relevant)

## Paid Teams / Business (later)

- Shared vaults, RBAC, policies
- SSO/SCIM
- Admin console, audit export, compliance tooling

## 9. Success Metrics

## Security and quality

- 0 known critical unresolved issues in core trust-boundary paths for a release.
- Relay crate has automated tests covering auth/replay/pairing/push-pull flows.
- Security docs include status markers for all major controls.

## Product completeness

- Users can perform daily workflow on desktop + browser without missing baseline PM features.
- Mobile autofill works on iOS and Android.
- Import success rate for top priority formats meets acceptance targets.

## Product adoption

- OSS users can self-host successfully using documented paths.
- Conversion to paid tier is driven by convenience/admin features, not core security access.

## 10. Risks and Dependencies

## Risks

- Shipping premium features before hardening core trust boundaries damages trust.
- Two-repo split without stable interfaces will create a long-lived fork problem.
- Overstated security docs can undermine credibility during audits or launch.

## Dependencies

- Stable extension/native host/daemon protocol contracts
- Relay hardening and test coverage
- Mobile autofill platform integration work
- Capability/entitlement interface design in public repo

## 11. Traceability

- Gap review source: `docs/GAP_REVIEW_2026-02-26.md`
- Current security evidence: `docs/SECURITY_STATUS_MATRIX.md`
- Requirements: `docs/REQUIREMENTS.md`
- Design: `docs/SOLUTION_DESIGN.md`
- Active execution plan: `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`
- Historical execution plan: `docs/IMPLEMENTATION_PLAN.md`
- Roadmap: `ROADMAP.md`
- OSS/private strategy: `docs/OSS_COMMERCIAL_STRATEGY.md`
