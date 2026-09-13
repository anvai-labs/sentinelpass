# Release-Blocker Register

**Generated from:** `TECHNICAL_DEBT.md` (2026-09-04 reset section) and
`docs/SECURITY_STATUS_MATRIX.md`.
**Reconciled 2026-09-13 against `TECHNICAL_DEBT.md`** (statuses mirror the TD
reset table row-for-row at this baseline; the 2026-09-04 generation date above
is preserved).
**Governance:** ADR-003 (release gates). A blocker is closed only when its WBS
package reaches `Done` **and** the evidence links below point at merged tests or
review artifacts. Do not hand-edit statuses without updating the TD table in the
same change.

**Status vocabulary:** `Open` → `In progress` → `Closed (evidence)` · `Accepted-risk`
(P0/P1 items may never be closed this way without an ADR recording the decision).

## P0 — Release-blocking security architecture

| Blocker | TD | WBS | Owner | Target | Status | Evidence |
|---|---|---|---|---|---|---|
| Local fields lack semantic AAD | TD-SEC-01 | 303/304/404 | CM | 0.9 | Closed (evidence) — TD row flipped Closed same-change 2026-09-13 | Typed AAD builder `crypto/aad.rs` with golden vectors (WBS-303); SPENV v2 envelopes for all durable classes via `vault/envelope_ops.rs` (WBS-304); post-unlock v1→v2 sweep + `format_version=2` activation gate `vault/activation_ops.rs` (WBS-404/405/406, PRs #102/#104/#107); ADR-005 **Accepted rev 4** |
| Sync metadata unauthenticated end to end | TD-SEC-02 | 612 | CM | 0.11 | Closed (evidence) | TD row, Closed 2026-09-10 (sync v2, WBS-601/612): every mutation carries a DEK-derived HMAC-SHA256 over the canonical shared metadata (identity, type, versions, epoch, origin, tombstone, payload hash — one PRF domain, distinct from the ADR-005 envelope); clients verify MAC + deterministic-id recomputation before applying ANY foreign mutation (tamper dead-lettered, `relay_metadata_tamper_is_dead_lettered`); the relay stores the MAC opaquely |
| No forgotten-password recovery | TD-SEC-03 | 302/310–312 | CM | 0.9 | Closed (evidence) | TD row, Done after adversarial review (2026-09-05): slot registry with registry-MAC (WBS-302); 256-bit checksummed recovery key with exhaustive single-char-error rejection (WBS-310); verified onboarding, raw-wrap + full AAD binding (WBS-311); recover-without-old-password flow — verify-before-write, all prior slots revoked, epoch advance, single-use slot (WBS-312); CLI `recovery setup/recover/status`; ADR-004 Accepted rev 5. Residuals: desktop-UI flows (WBS-1001); routine drills (WBS-905 — `scripts/drills/drill-recovery.sh` lands with this register update) |
| Rotation adopts key before commit | TD-SEC-04 | 309 | CM | 0.9 | Closed (evidence) | TD row, Done (WBS-309, 2026-09-04): stage→verify→commit→adopt, adopt-after-commit, stale-epoch UPDATE guard, commit-failure test with lock injector; rotation tests in `vault/mod.rs` |
| Epoch does not revoke sync authority | TD-SEC-05 | 312/314/614 | CM | 0.11 | Partial (evidence) — TD row reconciled from a stale `Open` 2026-09-13 (ADR-004 Accepted rev 5, ADR-006 Accepted rev 2) | Matrix row "Sync device epoch/revocation": v2 relay rejects mutations below the vault's forward-only epoch high-water (bounded jump); clients dead-letter pulled mutations below their local vault epoch (WBS-614); password rotation revokes ongoing stale-key sync at both ends. REMAINS: relay-side epoch advance is client-asserted (bounded) — authenticated epoch publication is a later-stage option; revocation notification to remaining devices deferred (ADR-004 rev 5) |
| Browser IPC self-asserted origin | TD-SEC-06 | 101 (containment) / 504–506 | CM | 0.10 | Closed (evidence) | TD row, Closed (WBS-504/505/506, 2026-09): browser-surface ops require a valid `native-host` installation capability presented on the envelope (hashed at rest in `ipc-capabilities.json` 0600, expiry + revocation supported, host secret `native_host.capability` 0600 provisioned by the daemon); a general client claiming NativeHost without the material is denied (unit + e2e tests); originless denied by default; legacy self-asserted/originless windows are explicit announced env opt-outs removed in 1.0; external-secret grants (audience-bound, token-enforced) retained |
| Six-digit pairing offline-guessable | TD-SEC-07 | 615/616 | CM | 0.11 | Closed (evidence) | TD row, Closed 2026-09-10 (sync v2, WBS-615/616): pairing root is a 256-bit CSPRNG secret (base64url/QR) — bootstrap encrypted under HKDF(secret), relay stores only Argon2id(secret) and gates retrieval on knowledge of the secret (POST body, one-use, TTL, attempt-limited); the six-digit value is demoted to a derived transcript-comparison aid that never encrypts material; HMAC-challenge over a PAKE reviewed and documented per ADR-006; v1 pairing retired (WBS-624) |
| Mobile placeholder security functions | TD-SEC-08 | 104 (labels) / 807 | ME | 0.8.x/0.12 | Closed (evidence) — TD row flipped Closed same-change 2026-09-13 (Phase 6, PR #136) | No release-reachable placeholder scaffolds remain: WBS-807 (CloudKit/Drive placeholders removed), WBS-812 Android Keystore slot + WBS-813 real AutofillService + WBS-814-816 lifecycle/backup hardening + WBS-821 iOS Keychain slot (TD-MOB rows Closed 2026-09-12); ADR-009 Accepted rev 2. Feature residuals (not placeholders): iOS slot enrollment deferred; device matrix evidence (WBS-818) |
| Security-critical key material drawn from `thread_rng()` | TD-SEC-09 | — (WBS-909 adversarial review) | CM | 0.11 | Closed (evidence) — TD row flipped Closed same-change 2026-09-13 | All production secret/key generation sourced from `rand::rngs::OsRng`: `crypto/password.rs:148,275`, `vault/recovery.rs:92` (false doc comment now true), `sync/device.rs:21`, `sync/pairing.rs:20,94` (pairing secret is HKDF-derived from code+salt); every remaining `thread_rng`/`rand::random` hit re-classified test-only (`sync/auth.rs`, `vault/recovery.rs`, `crypto/kdf.rs` tests). Verified: fmt + clippy `-D warnings` + full workspace tests + `--features sync` green |

## P1 — Data integrity, availability, privacy

TD-ROB-01…16 → WBS 408–418 / 500-series / 602–610; TD-NET-01…07 → WBS 603…622;
TD-CLIENT-01…09 → WBS 700-series; TD-MOB-01…10 → WBS 800-series;
TD-REL-01…07 → WBS 900-series. Full mapping: `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md`
Appendix A. Notable containment progress:

| Blocker | TD | WBS | Status | Evidence |
|---|---|---|---|---|
| Arbitrary HTTP relay URLs accepted | TD-NET-02 | 103 / 617 | In progress — 0.8.x half closed (TD row); the redirect half has landed per the matrix and awaits the TD-row flip | `sync/config.rs::validate_relay_url` enforces HTTPS / loopback-only HTTP (`SENTINELPASS_ALLOW_LOOPBACK_RELAY=1`) / no userinfo at init and client construction, with negative tests; matrix row "Relay transport policy" records the v2 client's bounded same-origin redirect policy (max 3 hops, TLS-downgrade and cross-origin refusals, target re-validation — WBS-617) as Implemented |
| Sync experimental labeling | plan §Phase 0 | 102 | Closed (0.8.x): CLI banner + README + docs/SYNC.md status note | `sync.rs` init output |
| Mobile prototype labeling | TD-SEC-08 | 104 | Closed (0.8.x): build-guide banners + README platform row | doc headers |
| No authenticated portable backup and verified restore contract | TD-ROB-12 | 416/417/418 | Closed (evidence) — TD row, Closed 2026-09-08 (PR #126) | `.spbackup` bundles: VACUUM INTO snapshot, HKDF-over-DEK manifest MAC (constant-time, MAC-first restore), digest/identity/epoch/slot binding, bounds-before-allocation; restore = staged validation + single-rename swap + sequenced sidecar re-baseline with fail-closed flags and the retained `.pre-restore` net; fault-injection sweeps prove complete-old/complete-new. Routine drill residual: `scripts/drills/drill-backup-restore.sh` (WBS-905) |
| Dependency-exception lifecycle | TD-REL-04 | 909 | Closed (evidence) — TD row, Closed 2026-09-11 (WBS-909) | `.cargo/audit.toml` holds only the failing advisory with owner/exposure/expiry metadata; full register in `docs/DEPENDENCY_EXCEPTIONS.md`; security.yml inline `--ignore` dropped (config file is the single audit-policy source) |
| Relay timing tests ignored | TD-REL-06 | 910 | Closed (evidence) — TD row, Closed 2026-09-11 (WBS-910) | rate-limiter window math clock-injected (`rate_limit.rs` `Clock` trait); window-reset tests run UNIGNORED on all CI platforms via a forward-only fake clock; relay suite 67 passed / 0 ignored |
| Release smoke tests lack real unlock/round-trip/restore | TD-REL-05 | 905 | Partial (evidence) — TD row Partial 2026-09-13 | Packaged-binary execution smoke: release.yml `native-installer-smoke` extracts the portable archive per platform and asserts presence/executability + a real CLI `--version` tagged-version match; functional drills: `scripts/drills/` (recovery, backup-restore, compromise-rotation — fail-closed negatives verified locally) wired into `.github/workflows/drills.yml` (tag + dispatch). REMAINS: functional unlock/round-trip/restore smoke against INSTALLED artifacts (native installers) |

## 1.0 gate (ADR-003)

1.0 requires: zero unresolved critical/high trust-boundary findings (TD-REL-07, WBS-911/912),
recovery/restore drills (SR-RECOVERY/SR-DATA-005), sync chaos evidence (TV-006),
mobile platform evidence (TV-007), signed artifacts/updater/SBOM/provenance (TD-REL-02/03),
and closed register rows for every P0 above.
