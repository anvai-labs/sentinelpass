# Security Remediation — Scope of Work and Completion Record

**Program window:** 2026-09-04 → 2026-09-17 · **Plan:** `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md` · **Claim inventory:** `docs/SECURITY_STATUS_MATRIX.md` · **Review commissioning brief:** `docs/SECURITY_REVIEW_BRIEF.md`

This document records the scope of work of the 2026-09 security-remediation
program: what was in scope, what was delivered, how each deliverable was
verified, and what remains for the owner. It is the auditor-facing summary;
the per-control claim inventory lives in the security status matrix.

## 1. Program Objectives

1. Close every trust-boundary finding from the 2026-09-04 security review
   (envelope crypto, key hierarchy, daemon authority, sync protocol,
   browser surface, mobile).
2. Bring the codebase to the ADR-003 1.0 gate: drills executed, chaos
   evidence recorded, platform evidence on all three OSes, artifacts
   traceable to reviewed sources, and a completed external review.
3. Do so with the same verification bar as the product: every security
   control lands with tests, every claim lands with evidence, and every
   adversarial review round is addressed before merge.

## 2. Work Breakdown Structure — Delivered

| Phase | Scope | Delivered via | Verification |
| --- | --- | --- | --- |
| Phase 0+1 | Remediation foundation: containment, recovery core, schema v5-v8, registry (ADR-001) | #100-#104 | Full workspace suite; ADR review |
| 0.9 security core | WBS-404 envelope migration, WBS-305 portable wire formats, registry MAC (ADR-004) | #104 | Golden vectors, legacy-blob tests |
| 0.10 cycle | WBS-405/406/407 verification+activation, WBS-414/415 audit chain, WBS-412/413/708 file hardening | #107 | Fault injection, adversarial review |
| Write-path | WBS-409 trigger removal, WBS-411 tx units + fault injection, WBS-410 NULL discipline | #121 (main), develop | 749 core tests |
| Phase 2 | WBS-416/417/418 authenticated backup/restore (`.spbackup`, ADR-008) | #126 | MAC-first restore, fault-injection sweeps, v6/v7/v8 fixture restores |
| Desktop hardening | WBS-706/707/709/710 (biometric Hello, least-privilege, expiring clipboard) | #126, #133, #134 | Unit suites; #134 E2E |
| Phase 3 | Daemon authority (ADR-007): service boundary, exclusive maintenance, WBS-502 service routing, WBS-504/505/507/508 capability gate + IPC hardening | #128, #129 | Capability/origin/peer-eUID negative suites |
| Phase 4 | Sync v2 protocol (ADR-006): CAS push, durable idempotency, epoch gates, lineage high-water, conflict preservation, dead-letter, v1 retirement, pairing v2 | #130-#132 | Deterministic convergence tests, tamper dead-letter tests |
| Phase 5 | Browser surface: WBS-711 default-deny HTTP autofill, WBS-712 origin binding, WBS-713/714/715 field safety + chooser, WBS-716 session-secret TTLs, WBS-717/718/719 build pipeline + E2E | #133, #134, #162-era | Real-Chrome E2E 6-0, drift gates |
| Phase 6 | Mobile: FFI contract, Android Keystore slot, real AutofillService, iOS Keychain slot, lifecycle hardening, CI matrices | #136-era | JNI symbol gates, device matrix |
| Phase 7 | 1.0 assurance: WBS-901 tag-time audits, WBS-902 matrix builds, WBS-903 fuzz targets, WBS-905 drills, WBS-908 SBOM, WBS-909 exception register, WBS-910 relay timing tests | #135, #137, #150-#164 | Tag-time gates, drills green, fuzz crash-free |
| Toolchain | Node 24 + vitest 5 across CI (#160, #161), runner-fleet noble rebuild + pool-spec compliance, billing guardrails | #160, #161, #163, #166 | Hosted CI green; smoke GREEN on rebuilt pool |

## 3. Reviews and Findings Disposition

- Every slice landed through adversarial review (fresh-context reviewer per
  slice; two rounds when findings warranted). Falsified or overstated claims
  were reverted and re-landed (documented in the session log).
- The WBS-911 proxy external review (2026-09-16/17, three fresh-context
  domain agents covering crypto/vault/sync, daemon/IPC/relay, client
  surfaces + supply chain) produced **no Critical findings**. Confirmed
  findings: relay binary dead-on-arrival (WAL pragma + missing
  ConnectInfo — both fixed with end-to-end boot evidence), stale shipped
  extension artifacts + release pipeline not building from source (fixed:
  canonical rebuild in the release workflow, 0.7.0, unforgeable Firefox
  GUID), PLAIN IPC default-on (env-gated as the third announced legacy
  window), capability-store umask window (born-0600), site-permission
  lock never taken (serialized), argv-borne CLI secrets (documented
  exposure), plus LOW/INFO consistency items — all addressed or recorded
  as residuals in the matrix.
- Findings deliberately deferred with owner visibility: Windows console
  window (S4U principal design), log retention cap follow-ups, relay
  storage row caps, IDNA/punycode normalization (ADR-005 rev 4 —
  fail-closed residual recorded), dead `windows_frame`/`AutoLockManager`
  modules.

## 4. Verification Evidence Summary

- **Tests:** 749 core + 30 CLI + 5 daemon + 45 protocol + 71 relay +
  mobile-bridge/JNI suites — all green on Node 24 / Rust stable, three OSes.
- **Drills (WBS-905):** recovery 21/0, backup-restore 35/0,
  compromise-rotation 15/0 — against installed AND release binaries,
  transcripts archived; CI-wired on tags.
- **Fuzz (WBS-903):** envelope, sync mutation, IPC frame, import/export
  targets — crash-free smoke runs, nightly schedule.
- **E2E (WBS-719):** real-daemon + real-Chrome suite 6-0 after the
  extension repair.
- **Reviews:** ADR-001..010 multi-round adversarial review (all accepted);
  per-slice fresh reviewers; WBS-911 three-domain proxy review.

## 5. Remaining for the Owner (outside agent-reachable scope)

1. Code-signing credentials (Apple Developer ID, Windows Authenticode) —
   WBS-906/907; the secret-gated workflow scaffolding is in place.
2. Independent external security review commissioning — WBS-911; the
   brief is `docs/SECURITY_REVIEW_BRIEF.md` (a three-domain proxy review
   has already executed its scope; findings dispositioned as above).
3. Windows Hello hardware validation session — WBS-710's determinism
   premise needs one physical Hello-capable machine.
4. WBS-401 decision: block vault opens when no backup exists (policy).
5. Chrome Web Store publishing account — the release pipeline is ready.
6. Runner-fleet image upgrade on dataserver3 (needs interactive sudo;
   dataserver2 done — runbook in the session record). Until then, Linux
   CI routes to GitHub-hosted runners (#156).

## 6. Branch State

- `main` @ release 0.11.0 + rustls fix + android CI fix + hosted routing +
  Node 24 + dependency wave (promotions through #160).
- `develop` @ `e850112`+docs — carries the service-parity/log-hygiene
  slice (#162/#163), the drill-evidence record (#164), this document, and
  the proxy-review docs refresh (#165); promotion to `main` is the next
  release PR.
