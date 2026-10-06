# SentinelPass 0.17.0 — Sandesha hand-back

Date: 2026-10-05. Successor to `docs/SANDESHA_V0160_HANDOFF_2026-10-04.md`.

## Version and provenance

- **Version:** 0.17.0 — tag `v0.17.0` → main `b7b9f5c3c886cdb0532fe5e60dec39e1d07ce061`
- **Promotion:** PR #259 (develop → main, single squash), CI fully green
- **Release run:** 37397908823 SUCCESS — 15 assets, all installer/smoke jobs
  green on linux/macos/windows
- **crates.io:** `sentinelpass-protocol` 0.17.0
- **Homebrew:** tap formula 0.17.0 (PR #94, SHAs verified against
  downloaded bytes and the release manifest, merged)
- **Key checksums** (full list: `sha256sums.txt` on the release page):
  - `sentinelpass-0.17.0-macos.dmg` / `SentinelPass_0.17.0_aarch64.dmg`: `fe208d385d0b7565a60b4974cc19ea63236999ce35fd78f0832920f6255bc8c6`
  - `sentinelpass-installer-0.17.0-macos.tar.gz`: `e622372527c458e64767a2eb29b9eb8e8369c0ef5ae54104f5b11955a2a4ec42`
  - `sentinelpass-installer-0.17.0-linux.tar.gz`: `3814d315849cbe5506c9db243d9d479707ef16ddbfe4ac1e8e18799cec31d6d4`
  - `sentinelpass-installer-0.17.0-windows.zip`: `9da72efa0d20ce4cf1361c65ecb865e00cfdf7a8e55ffc0aaf84028b5382b57e`
- **Source guard:** rerun `check_source.py` against `b7b9f5c`. Intentional
  deltas vs the 0.16.x baseline: `daemon/ipc/server.rs` (audited
  sensitive/bulk reads + honest containment), `daemon/service_grants.rs`
  (vault-key authentication of the persisted store, #252), the retired
  `autofill/*` prototype (#253), CI gate aggregation.

## What shipped since 0.16.0

| Item | PR | Note |
| --- | --- | --- |
| Cross-repo security review M1–M5 remediations | #250 | audited sensitive/bulk reads with peer provenance + REAL success flags (EntryGet/TotpCode/SshKeyGet/ExportAll/HealthReport/RegistryOverview-with-strength); `--expires-in` multi-byte panic fixed in BOTH parsers; `store_error` no longer reads as "denied" (a failed revoke said "denied" while the grant stayed live); enrollment-begin audited on all paths; the audit-view spoof vector closed unforgeably (`client_id.is_none()` conjunct) |
| Persisted service grants authenticated with the vault key | #252 | grant store is integrity-protected at rest |
| Unsafe native-autofill prototype RETIRED | #253 | credential search / clipboard / input-injection / hotkey paths removed on all platforms; retained signatures fail closed BEFORE vault or desktop access; Windows keeps diagnostic-only title reading on generated bindings (never an origin assertion); x11 dependency removed, feature flag a documented no-op |
| CI Gate sibling-exclusion hardening | #254 | two Gate runs on one SHA can no longer deadlock each other |

**Preserved surfaces (verified by fresh adversarial review, blocker-level
guards):** the Tauri desktop UI, explicit Copy actions (clipboard
tracker, 6/6 tests), and browser-extension autofill are unchanged.
**Native-application autofill is DELIBERATELY DISABLED** — re-introduction
requires the authorization/destination-binding gates documented in
`docs/NATIVE_AUTOFILL_RETIREMENT_2026-10-05.md`.

## Validation results

- Full workspace suite: 1,113+ tests green; release feature-matrix
  3 OS × {default, sync, no-default} green; RustSec/npm audits green at
  tag time
- Bundle + native-installer smoke green on linux/macos/windows
  (packaged binaries executed, sidecars verified)
- Local Mac upgraded to 0.17.0 (app + CLI + host + UI): daemon restarted
  under LaunchAgent, reachable + locked, vault intact (schema 13);
  `service-grant` command tree verified live in the installed binary
- Merge chain: #250 (3 review rounds, CLEAN), #253 (fresh adversarial
  review, CLEAN; merged on the owner's explicit authorization with the
  clean review as proxy), #254 (live-verified), #259 promotion fully green

## For Sandesha adoption

Everything in the 0.16.0 hand-back remains valid. New in 0.17.0: the
grant store on disk is now authenticated (tampering is detected instead
of silently parsed), and the strict-profile containment semantics are
documented honestly (policy-forcing against the legacy surface; the
owner CLI/UI read ops remain same-UID reachable and are now audited with
peer provenance — `vault_read:*` rows; TD-SEC-10 per-service UID
isolation remains the tracked boundary fix).
