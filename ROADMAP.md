# SentinelPass Roadmap

**Last Updated:** 2026-02-26
**Workspace Version (Cargo):** 0.1.0
**Roadmap Status:** Active (gap-driven reset)

## Purpose

This roadmap replaces feature-first planning with a gap-driven plan based on the current codebase and docs state as of 2026-02-26.

Planning principles:

- Separate `implemented`, `partial`, and `planned` states.
- Prioritize security posture and trust-boundary hardening before net-new premium features.
- Keep open-source trust surfaces auditable (crypto, vault, sync protocol, client logic).
- Build paid tiers as additive capabilities, not hidden changes to core security behavior.

## Current State Snapshot (2026-02-26)

### Strong

- Local-first Rust core with encrypted vault, lockout, audit logging, TOTP, SSH key storage.
- Desktop app + daemon + browser extension architecture in place.
- Optional E2E sync protocol and self-hosted relay implemented.
- Mobile bridge and native iOS/Android scaffolds exist.
- Browser save-prompt and extension reliability work has already landed.

### Critical Gaps

- Windows daemon IPC still uses localhost TCP and transmits sensitive IPC payloads as plaintext JSON.
- Relay production hardening is incomplete (config knobs exist but several are not enforced; cleanup/rate limit wiring missing).
- Browser extension background trusts message payload domain values without sender URL validation.
- Security/docs posture is overstated in places (target-state mitigations documented as if already implemented).
- Product planning artifacts are fragmented and stale (roadmap vs technical debt vs prompt text diverge).
- No explicit OSS/free/paid boundary and no two-repo operating strategy documented.

## 2026 Strategic Priorities

1. **Security Truthfulness + Hardening**
2. **Core Product Completeness (browser + import/export + health)**
3. **Mobile Autofill Completion**
4. **Commercial Packaging (free vs paid)**
5. **Enterprise Foundations (after hardening)**

## Phased Roadmap

## Phase 1 (0-45 days): Security Hardening and Planning Convergence

### Goals

- Eliminate the highest-risk local and relay trust-boundary gaps.
- Align docs with reality and establish a single planning source of truth.

### Deliverables

- Windows IPC hardening design chosen and implemented:
  - Preferred: named pipes with per-user ACLs.
  - Interim fallback (if needed): authenticated message encryption on loopback.
- Browser extension sender validation in background worker:
  - validate `sender.tab.url`, scheme, frame context, and claimed domain.
- Relay hardening wiring:
  - spawn cleanup task,
  - apply rate limiting,
  - consume `pairing_ttl_secs`, `max_active_pairings`, `nonce_window_secs`,
  - tighten CORS defaults.
- Relay authz review for device registration and pairing endpoints.
- Relay test baseline:
  - unit tests for auth and pairing handlers,
  - integration tests for push/pull and replay protection.
- Security documentation split into:
  - `implemented now`,
  - `partial`,
  - `planned target state`.

### Exit Criteria

- Critical review findings in `docs/GAP_REVIEW_2026-02-26.md` are either fixed or tracked with owners and dates.
- `sentinelpass-relay` has non-zero automated test coverage.

## Phase 2 (45-120 days): Product Completeness Baseline (Free/OSS-first)

### Goals

- Make SentinelPass feel complete for individual users before enterprise expansion.

### Deliverables

- Browser extension popup parity improvements:
  - search,
  - add credential,
  - settings,
  - better unlock UX.
- Password health baseline (local analysis first):
  - weak/reused password detection,
  - age indicators,
  - local security score.
  - *Status:* delivered by the credential registry (ADR-001) — reuse clusters
    and rotation posture in the CLI and desktop UI, shipped from v0.8.1 — plus
    master password rotation (ADR-002, v0.8.1). Local security score remains
    open.
- Import/export improvements:
  - KeePass and Bitwarden first,
  - conflict and validation UX.
- UX polish:
  - pagination/virtualization for large vaults,
  - stronger error recovery flows,
  - release/debug log gating in extension and desktop UI.

### Exit Criteria

- Free local-first desktop + extension experience covers the common password-manager baseline for a single user.

## Phase 3 (Q2-Q3 2026): Mobile Autofill and Sync Quality

### Goals

- Complete mobile usability and make sync trustworthy at scale.

### Deliverables

- iOS and Android autofill integrations.
- Mobile CRUD + bridge test coverage.
- Sync conflict UX beyond silent LWW-only behavior.
- Device management UX (revocation visibility, sync health indicators).
- Hosted relay compatibility profile (same protocol as OSS relay).

### Exit Criteria

- Mobile clients are usable as daily drivers with autofill and optional sync.

## Phase 4 (Q3-Q4 2026): Commercial Packaging and Paid Tier Foundations

### Goals

- Ship a clear free tier and paid tier without splitting trust-critical core code paths.

### Deliverables

- Capability tiering and entitlement model (documented + implemented).
- Private repo established for paid/hosted features with compatibility contract.
- Hosted relay operations stack (private) with billing/admin integrations.
- Premium personal features (candidate set):
  - managed encrypted sync hosting,
  - advanced password health/breach monitoring,
  - priority support.

### Exit Criteria

- OSS repo remains sufficient to self-host and verify core security claims.
- Paid features are additive and optional.

## Phase 5 (2027): Teams and Enterprise

### Goals

- Add collaborative and policy features only after personal-product security and completeness are stable.

### Deliverables

- Shared vaults and role-based access.
- Admin policy engine.
- SSO/SCIM and directory sync.
- Audit export and SIEM integrations.
- Compliance-oriented deployment packaging.

## Active Workstreams (Now / Next / Later)

### Now

- Relay hardening and config wiring
- Windows IPC channel hardening
- Extension sender validation
- Docs convergence (PRD / requirements / design / plan)
- OSS/private repo strategy

### Next

- Browser popup parity features
- Local password health dashboard
- Import/export expansion
- Mobile autofill

### Later

- Managed sync hosting
- Team/admin capabilities
- Enterprise integrations

## Quality and Security Gates (All Phases)

- No major security claims in docs without an `implementation status` marker.
- New trust-boundary code requires:
  - unit tests,
  - negative-path tests,
  - threat-model update.
- Release builds should gate or strip verbose credential-flow logs.
- Public protocol changes require versioning + compatibility notes.

## OSS / Paid Packaging Direction (Summary)

See `docs/OSS_COMMERCIAL_STRATEGY.md` for the full model.

High-level decisions:

- **Open-source and free core:** vault, crypto, CLI, desktop client, extension, native host, daemon, sync protocol, self-host relay.
- **Paid/private add-ons:** hosted relay operations, billing/licensing, premium breach/monitoring integrations, team/admin/SSO/policy features.
- **Two repos:** public repo for core + protocols, private repo for additive commercial layers and hosted service operations.

## Related Planning Docs

- `docs/GAP_REVIEW_2026-02-26.md`
- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/SOLUTION_DESIGN.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/OSS_COMMERCIAL_STRATEGY.md`
