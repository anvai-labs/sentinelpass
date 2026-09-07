# SentinelPass Solution Design (Gap-Closing Architecture)

**Version:** 1.0  
**Date:** 2026-02-26  
**Status:** Historical design response to `docs/GAP_REVIEW_2026-02-26.md`

> The active security-architecture response is
> `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md` and Proposed ADR-003 through
> ADR-010. This document remains useful for the earlier OSS/commercial and boundary
> decisions but does not override the current security status matrix.

## 1. Design Goals

1. Close current trust-boundary gaps without rewriting the product.
2. Make security claims auditable and status-based.
3. Preserve open-source trust-critical code paths.
4. Enable paid features through additive modules and services.
5. Avoid a long-lived fork between OSS and private codebases.

## 2. Current Trust Boundaries (Observed)

## A. Browser -> Extension Background -> Native Host -> Daemon -> Vault

Risk focus:

- Origin/domain validation happens across multiple layers.
- Background worker currently trusts message payload domain values too much.
- Windows IPC transport security is weaker than Unix domain socket path.

## B. Device -> Relay (Sync)

Risk focus:

- Relay auth is implemented (Ed25519 + nonce + timestamp), but operational hardening is incomplete.
- Public endpoints (`register`, `pairing`) need stronger abuse controls and clearer trust proofs.
- Config and docs imply controls that are not consistently enforced in runtime.

## 3. Security Posture Status Model (Required for docs)

All security and design docs should use:

- `Implemented`: code and tests present
- `Partial`: code exists but gaps remain (missing tests, config wiring, platform asymmetry, etc.)
- `Planned`: target-state only

Recommended implementation:

- Add a status matrix section to security docs or a dedicated `docs/SECURITY_STATUS_MATRIX.md`.
- Link each `Implemented` control to code and tests.
- Link each `Partial` control to requirement IDs and roadmap phase.

## 4. Browser Extension / Native Host / Daemon Hardening Design

## 4.1 Background Worker Validation Pipeline (new central guard)

Add a single request-validation path in the extension background worker before any native messaging call:

1. Extract sender context:
   - `sender.tab.url`
   - `sender.frameId`
   - `sender.id`
2. Normalize sender URL hostname using shared hostname utility.
3. Normalize claimed request domain.
4. Reject on mismatch (except tightly-scoped legacy fallback with explicit logging and metrics).
5. Enforce context rules:
   - deny `chrome://`, `about:`, `file://` (unless explicitly supported)
   - deny background-page-originated credential requests without active-tab context
   - default deny iframe autofill for cross-origin frames
6. Attach validated context to native messaging request metadata (for audit/logging only, not trust transfer).

Design notes:

- The daemon should continue domain matching, but extension background must not rely solely on content script claims.
- Keep sender validation logic in one file shared by Chrome/Firefox builds to avoid drift.

## 4.2 Logging Profile Split (extension and UI)

Introduce build-time log profiles:

- `debug`: verbose logs (dev only)
- `release`: minimal logs, no URL/password-flow details

Implementation pattern:

- Wrap logging calls in `if (DEBUG_LOGS)` gates or build-time dead-code-eliminated helper.
- Prohibit password length and credential-capture event logs in release builds.

## 4.3 Windows IPC Hardening (preferred path)

### Target design

- Replace localhost TCP with Windows named pipes.
- Apply per-user ACLs so only the current user can connect.
- Keep existing token auth as defense-in-depth until confidence is established.

### Transition strategy

Phase A (short term):

- Add transport abstraction (`UnixSocket`, `WindowsNamedPipe`, `TcpLoopbackLegacy`).
- Mark TCP loopback as legacy and disabled by default for release builds.

Phase B:

- Enable named pipes as default on Windows.
- Add compatibility fallback only for debug/developer mode.

Phase C:

- Remove legacy TCP path once installer/host/daemon compatibility is stable.

### Interim fallback (only if named pipes must be delayed)

- Add message-level authenticated encryption for IPC envelopes on Windows.
- This is not a substitute for OS-native access controls, only a temporary reduction in exposure.

## 5. Relay Hardening Design

## 5.1 Runtime Wiring and Config Truthfulness

Required changes:

- Start cleanup task at boot using configured retention.
- Apply rate-limiting middleware or handler guards using `rate_limit_per_minute`.
- Replace hardcoded:
  - pairing TTL,
  - max active pairings,
  - nonce freshness window
  with values from config.
- Default CORS should be disabled or restricted; do not use permissive CORS for server-to-server sync APIs by default.

## 5.2 Public Endpoint Abuse Controls

### Pairing bootstrap endpoints

- Apply IP/device-token rate limits.
- Store pairing token hashes, not raw tokens.
- Enforce payload size and structured validation for bootstrap fields.

### Device registration

Current issue:

- Registration is public and creates or joins vault state with minimal proof.

Target design:

- Split registration into two flows:
  - `bootstrap_register_first_device` (initialization flow)
  - `register_paired_device` (requires pairing proof/challenge)
- Require proof tied to pairing material for secondary devices.
- Reject registrations for existing vaults without proof of authorization.

## 5.3 Hosted vs Self-Hosted Deployment Boundary

- OSS relay remains self-hostable and protocol-compatible.
- Hosted relay (private) may add:
  - abuse detection,
  - CAPTCHA/risk scoring for public endpoints,
  - multi-tenant ops and observability,
  - billing/account layers.

Important:

- Hosted additions must not change protocol semantics in a way that breaks self-host compatibility without versioning.

## 5.4 Relay Testing Strategy (minimum baseline)

Add tests for:

- auth header parse and signature verification failures
- nonce replay rejection
- timestamp freshness enforcement
- pairing TTL and single-use consumption
- public endpoint throttling
- sync push/pull sequencing and device revocation

## 6. Product Capability and Tiering Architecture

## 6.1 Capability boundaries (public contracts, private implementations)

Define public interfaces for optional features:

- `SyncProvider` (self-host relay / hosted relay / cloud storage variants)
- `BreachProvider` (HIBP or enterprise feeds)
- `EntitlementProvider` (signed entitlements verification client-side)
- `PolicyProvider` (team policy engine)
- `TelemetrySink` (opt-in diagnostics only)

Public repo responsibilities:

- interface definitions
- default OSS implementations (or no-op stubs)
- capability flags and UX hooks
- protocol/schema definitions

Private repo responsibilities:

- premium provider implementations
- hosted services
- billing/admin APIs
- enterprise connectors (SSO/SCIM, SIEM exports)

## 6.2 Feature Gating Model

Principle:

- Gate premium UX/capabilities, not cryptographic correctness.

Pattern:

- Backend/daemon exposes a signed capability manifest.
- UI/extension query capability manifest and hide/disable premium actions.
- Core vault operations remain identical for free and paid users.

## 7. Repo Split Design (technical seams)

## 7.1 Public repo (`sentinelpass`)

Contains:

- `sentinelpass-core`
- `sentinelpass-cli`
- `sentinelpass-daemon`
- `sentinelpass-host`
- `sentinelpass-ui` (free/core UX)
- `browser-extension`
- `sentinelpass-relay` (self-host community relay)
- protocol docs, threat model, schemas, migration docs

## 7.2 Private repo (`sentinelpass-enterprise` or `sentinelpass-pro`)

Contains:

- hosted relay control plane and multi-tenant ops
- billing/licensing services
- enterprise admin console and policy engine
- SSO/SCIM connectors
- premium monitoring integrations
- compatibility tests against public repo release tags

## 7.3 Integration mechanism (recommended)

- Public repo is upstream source of truth.
- Private repo consumes public crates/packages by tag or commit pin.
- Avoid copying public code into private repo except generated artifacts or test fixtures.
- If shared UI extension points are needed, define plugin seams in public repo first.

## 8. Documentation and Planning Governance Design

## 8.1 Single planning stack

Required documents and roles:

- `docs/GAP_REVIEW_*`: evidence snapshot (security/product review)
- `docs/PRD.md`: product intent and scope
- `docs/REQUIREMENTS.md`: traceable requirements and acceptance criteria
- `docs/SOLUTION_DESIGN.md`: architectural response
- `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md`: active execution plan
- `docs/IMPLEMENTATION_PLAN.md`: superseded historical 90-day plan
- `ROADMAP.md`: milestone/phasing summary

## 8.2 Update policy

For any major initiative:

1. update gap review (or add deltas)
2. update requirements IDs
3. update design if trust boundaries change
4. update implementation plan and roadmap

This avoids stale roadmap-only planning.

## 9. Security and Trust Invariants (must remain true across tiers)

1. Local vault decryption is client-side only.
2. Relay stores encrypted blobs only.
3. Core cryptography, vault format, and sync protocol remain publicly inspectable.
4. Paid services cannot require plaintext secret access.
5. Security claims are status-labeled and evidence-backed.
