# SentinelPass Implementation Plan (90-Day)

**Version:** 1.0

**Date:** 2026-02-26

**Status:** Superseded on 2026-09-04

> This 2026-02-26 90-day plan is retained as historical planning context. The active
> execution source is
> [STRATEGIC_REMEDIATION_PLAN_2026-09-04.md](STRATEGIC_REMEDIATION_PLAN_2026-09-04.md),
> with milestone status summarized in [ROADMAP.md](../ROADMAP.md).

This plan operationalizes the gap review and requirements into a 90-day sequence. It is intentionally security-first.

## 1. Outcomes for This 90-Day Window

By the end of this plan, SentinelPass should have:

- materially improved local and relay trust boundaries,
- automated tests in the relay,
- accurate planning/security docs with requirement traceability,
- a documented OSS/free/paid and public/private repo strategy,
- a clearer path to product-complete personal usage.

## 2. Workstreams

## WS1: Relay Hardening (Critical)

### Scope

- Wire runtime config values into auth/pairing behavior
- Start cleanup task on boot
- Enforce rate limits
- Tighten CORS default behavior
- Add public endpoint abuse controls (initial baseline)
- Add relay tests

### Requirements covered

- `FR-SYNC-001`, `FR-SYNC-002`, `FR-SYNC-003`
- `SR-RELAY-001`, `SR-RELAY-003`
- `TV-001`, `TV-002`

### Deliverables

- Code changes in `sentinelpass-relay/`
- Relay test suite (unit + integration minimum baseline)
- Updated `docs/SYNC.md` with accurate config behavior

### Exit criteria

- Config values demonstrably affect runtime
- Non-zero relay tests in CI
- Replay and pairing behavior covered by tests

## WS2: Windows IPC and Extension Boundary Hardening (Critical)

### Scope

- Decide and implement Windows IPC hardening path (named pipes preferred)
- Add extension background sender validation (`sender.tab.url` / frame checks)
- Reduce release logging in extension (and optionally UI)

### Requirements covered

- `SR-IPC-001`, `SR-IPC-002`
- `FR-BROWSER-002`, `FR-BROWSER-004`
- `SR-EXT-001`, `SR-EXT-002`
- `TV-001`

### Deliverables

- Updated IPC transport code and docs
- Extension shared validation utility
- Background worker tests for mismatch rejects
- Release/debug logging profile split

### Exit criteria

- Sensitive requests cannot be forwarded from mismatched sender URL/domain contexts
- Windows release path no longer depends on plaintext loopback TCP (or clearly documented temporary fallback with mitigation and target removal date)

## WS3: Planning and Security Claim Governance (High)

### Scope

- Maintain a current gap review
- Keep PRD/requirements/design/plan/roadmap aligned
- Add status labels for security controls

### Requirements covered

- `SR-DOCS-001`, `SR-DOCS-002`
- `RG-003`
- `TV-004`

### Deliverables

- Planning docs in `docs/`
- Security status matrix (either embedded in existing docs or standalone)
- Release checklist updates

### Exit criteria

- Core security claims in docs are status-labeled and traceable

## WS4: Product Completeness Baseline Prep (High)

### Scope

- Browser popup parity backlog definition (search/add/settings)
- Password health local-only MVP design
- Import/export priority formats (KeePass, Bitwarden)
- Mobile autofill completion plan

### Requirements covered

- `FR-BROWSER-003`
- `FR-IMPORT-001`, `FR-IMPORT-002`
- `FR-MOBILE-001`, `FR-MOBILE-002`

### Deliverables

- Shippable backlog slices with acceptance criteria
- Implementation specs for next phase
- Test strategy for import and mobile bridge flows

### Exit criteria

- Next-phase feature work can start without reopening architecture questions

## WS5: OSS / Free / Paid and Two-Repo Foundation (High)

### Scope

- Finalize component boundary decisions
- Define public/private repo ownership and release flow
- Define compatibility contract and versioning policy

### Requirements covered

- `CM-001`, `CM-002`, `CM-003`, `CM-004`
- `RG-001`, `RG-002`

### Deliverables

- `docs/OSS_COMMERCIAL_STRATEGY.md`
- Compatibility checklist for public/private integration
- Initial package names/crates/interfaces list for extension points

### Exit criteria

- Team can start private repo work without forking core code paths

## 3. Sequencing (Weeks)

## Weeks 1-2

- WS1 design decisions and test harness setup
- WS2 Windows IPC decision (named pipes vs staged fallback)
- WS3 docs alignment baseline (done in this planning reset)

## Weeks 3-5

- Implement relay config wiring + cleanup + rate limiting
- Add relay auth/pairing tests
- Implement extension sender validation

## Weeks 6-8

- Implement Windows IPC hardening or staged transport abstraction
- Add extension log gating and tests
- Update docs/SYNC and security status labeling

## Weeks 9-10

- Close remaining critical findings
- Run hardening test pass and regression pass
- Freeze next-phase backlog (browser parity / password health / imports / mobile autofill)

## Weeks 11-12

- Stabilization, documentation, release readiness review
- Publish updated roadmap and milestone outcomes

## 4. Owners (Role-Based)

- `Security Lead`: WS1 and WS2 threat-boundary decisions, reviews, test requirements
- `Core/Rust Engineer`: daemon IPC, relay runtime changes, tests
- `Extension Engineer`: sender validation and logging profile changes
- `Product Engineer`: browser popup parity backlog and password health/import UX definitions
- `Mobile Engineer`: autofill integration plan and bridge test strategy
- `Tech Lead / Founder`: OSS/private repo boundaries, licensing, roadmap decisions

## 5. Verification Plan

## Automated

- Relay unit tests for auth parsing and signature verification failures
- Relay integration tests for replay, pairing, sequence monotonicity, revocation
- Extension background tests for sender URL/domain mismatch rejection
- IPC tests for Windows transport behavior (where CI permits)

## Manual / exploratory

- End-to-end browser autofill and save prompts across common login flows
- Daemon unlock/lock flows and extension retry behavior when vault locked
- Self-host relay deployment sanity test behind TLS reverse proxy

## Documentation verification

- Every new/updated security claim reviewed against code and tests
- Status labels updated to `Implemented/Partial/Planned`

## 6. Risks and Mitigations

- **Risk:** Named pipes on Windows take longer than expected.
  - Mitigation: implement transport abstraction first and ship staged hardening with explicit temporary status.

- **Risk:** Relay hardening introduces protocol/behavior regressions.
  - Mitigation: add integration tests before tightening defaults; version changes explicitly.

- **Risk:** Two-repo split starts before interfaces are stable.
  - Mitigation: freeze public contracts first; private repo consumes tagged releases only.

## 7. Definition of Done (for this plan window)

- Critical findings from `docs/GAP_REVIEW_2026-02-26.md` are closed or downgraded with evidence.
- Relay has automated tests and enforced runtime controls matching docs.
- Windows IPC risk has a production-safe path and documented status.
- Extension validates sender context before credential operations.
- OSS/free/paid and public/private strategy is documented and adopted.
