# Release-Blocker Register

**Generated from:** `TECHNICAL_DEBT.md` (2026-09-04 reset section) and
`docs/SECURITY_STATUS_MATRIX.md`.
**Governance:** ADR-003 (release gates). A blocker is closed only when its WBS
package reaches `Done` **and** the evidence links below point at merged tests or
review artifacts. Do not hand-edit statuses without updating the TD table in the
same change.

**Status vocabulary:** `Open` → `In progress` → `Closed (evidence)` · `Accepted-risk`
(P0/P1 items may never be closed this way without an ADR recording the decision).

## P0 — Release-blocking security architecture

| Blocker | TD | WBS | Owner | Target | Status | Evidence |
|---|---|---|---|---|---|---|
| Local fields lack semantic AAD | TD-SEC-01 | 303/304/404 | CM | 0.9 | Open | ADR-005 Proposed |
| Sync metadata unauthenticated end to end | TD-SEC-02 | 612 | CM | 0.11 | Open | ADR-006 Proposed |
| No forgotten-password recovery | TD-SEC-03 | 302/310–312 | CM | 0.9 | Open | ADR-004 Proposed |
| Rotation adopts key before commit | TD-SEC-04 | 309 | CM | 0.9 | Open | — |
| Epoch does not revoke sync authority | TD-SEC-05 | 312/314/614 | CM | 0.11 | Open | ADR-004/006 Proposed |
| Browser IPC self-asserted origin | TD-SEC-06 | 101 (containment) / 504–505 | CM | 0.10 | In progress (containment closed: `browser_surface_allowed` + tests; see matrix row) | `ipc/server.rs`; unit tests |
| Six-digit pairing offline-guessable | TD-SEC-07 | 615 | CM | 0.11 | Open | ADR-006 Proposed |
| Mobile placeholder security functions | TD-SEC-08 | 104 (labels) / 807 | ME | 0.8.x/0.12 | In progress (labels landed in docs; placeholders remain until 807) | mobile doc banners |

## P1 — Data integrity, availability, privacy

TD-ROB-01…16 → WBS 408–418 / 500-series / 602–610; TD-NET-01…07 → WBS 603…622;
TD-CLIENT-01…09 → WBS 700-series; TD-MOB-01…10 → WBS 800-series;
TD-REL-01…07 → WBS 900-series. Full mapping: `docs/WBS_SECURITY_REMEDIATION_2026-09-04.md`
Appendix A. Notable containment progress:

| Blocker | TD | WBS | Status | Evidence |
|---|---|---|---|---|
| Arbitrary HTTP relay URLs accepted | TD-NET-02 | 103 / 617 | In progress — 0.8.x half closed: `sync/config.rs::validate_relay_url` + tests; client redirect rules remain | unit tests in `sync/config.rs` |
| Sync experimental labeling | plan §Phase 0 | 102 | Closed (0.8.x): CLI banner + README + docs/SYNC.md status note | `sync.rs` init output |
| Mobile prototype labeling | TD-SEC-08 | 104 | Closed (0.8.x): build-guide banners + README platform row | doc headers |

## 1.0 gate (ADR-003)

1.0 requires: zero unresolved critical/high trust-boundary findings (TD-REL-07, WBS-911/912),
recovery/restore drills (SR-RECOVERY/SR-DATA-005), sync chaos evidence (TV-006),
mobile platform evidence (TV-007), signed artifacts/updater/SBOM/provenance (TD-REL-02/03),
and closed register rows for every P0 above.
