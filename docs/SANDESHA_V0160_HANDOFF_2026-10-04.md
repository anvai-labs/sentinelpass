# SentinelPass 0.16.0 — Sandesha / AnvaiOps hand-back (VPS + service-IDM integration)

Date: 2026-10-04. Successor to `docs/SANDESHA_V015_1_HANDOFF.md` and the
PR #238 verification follow-up. Everything below is shipped on `main`
(tag `v0.16.0`) and qualified live on dataserver3 (Ubuntu, kernel 7.0).

## Version and provenance

- **Version:** 0.16.0 — tag `v0.16.0` → main `7f03ac5`
- **Artifacts:** 15 release assets; `sha256sums.txt` on the release page
  (macOS dmg `8c2fa663…`, installer-linux `63f21479…`,
  installer-macos `f4487c63…`, installer-windows `ec314040…`)
- **crates.io:** `sentinelpass-protocol` 0.16.0; **Homebrew:** tap
  formula 0.16.0 (SHA-verified against the manifest)
- **AnvaiOps source guard:** re-run `check_source.py` against `7f03ac5`.
  It WILL report intentional deltas vs the 0.15.1 baseline — review
  before refreshing: `sentinelpass-core/src/daemon/enrollment.rs` (two
  real gpg fixes, see below), `daemon/ipc/server.rs` (F2 strict gate +
  perf-evidence tests), `sentinelpass-cli` (service-grant + entry-id
  surfaces). These are the reviewed, adversarially-audited changes this
  release exists to ship — not regressions.

## What shipped since your 0.15.1 verification

| Item | Status | Where |
| --- | --- | --- |
| P1a exact-entry CLI (`service-grant create/get/revoke`, `enrollment begin/complete`) | **DONE** | #241 |
| F2 authoritative strict-profile legacy disablement (daemon refuses `GetExternalSecret` even with a valid grant + token) | **DONE, proven live on the VPS host** | #241 + dataserver3 qualification |
| F3 exact-entry provisioning (`service-credential install/verify --entry-id`) | **DONE** | #242 |
| P2 measured production-path performance (real primitives, real socket, real gpg) | **DONE, both platforms** | #243, `docs/SP7_PERFORMANCE_EVIDENCE_2026-10-04.md` |
| OpenPGP enrollment on modern gpg | **FIXED** — verification was dead on gpg ≥ 2.4 (keyring perms) and on long-TMPDIR macOS (agent-socket path); both fixed + owner-only work dirs | #243 |

Behavior changes to plan around (release notes): (1) re-issue legacy
grants as service grants BEFORE enabling `SENTINELPASS_REQUIRE_STEPUP=1`;
(2) shells exporting BOTH `SENTINELPASS_CLIENT_TOKEN` and
`SENTINELPASS_SERVICE_TOKEN` fail closed in `service-credential` until
scoped; (3) retrieval-side commands never prompt or unlock a locked
daemon (typed failure instead).

## Your acceptance checklist — status

| Your item (verification followup §Acceptance) | Status |
| --- | --- |
| Correct release provenance | ✅ tag/commit/hashes above; guard rerun expected PASS after baseline review |
| Exact-entry CLI | ✅ qualified live: create (step-up, one connection), get byte-exact (`--no-newline`), wrong-token/wrong-entry denied, revoke immediate |
| Authoritative strict mutation policy | ✅ **proven on the VPS host**: a fully valid legacy grant + client token, staged through the real CLI, is refused by the strict daemon with migration guidance |
| Real-socket step-up tests | ✅ in-tree (`step_up_real_client_keeps_approval_connection`), green in CI and on dataserver3 |
| Provider-scoped rotation ceremony | ✅ rotation = `create` a new grant (new one-time token) + `revoke` the old; enroll-fingerprinted grants rotate-in-place via re-enrollment |
| Per-service Linux/Docker read isolation | ⚠️ **partial** — same-UID boundary only; per-service users / credential-file mount adapter remains deferred (your F1c) |
| Locked vault + stopped daemon + three service restarts | ✅ locked → typed failure (qualified); stopped daemon → no retrieval path at all (fail-closed by architecture); the three-restart drill is your systemd-unit operational test — runbook below |
| No secret in logs/argv | ✅ tokens via env (`SENTINELPASS_SERVICE_TOKEN`); byte-exact pipe for provisioning; audit events carry opaque ids |
| Rollback before revoking working keys | procedural — your side; the mechanics (revoke is instant, re-mint shows a fresh token once) are qualified |
| OpenPGP optional enrollment | ✅ now actually works on modern gpg; 29–578 ms per verification (host-dependent), well under the 1 s budget |
| Perf targets (handoff §7) | ✅ measured: unpinned retrieval round-trip p95 1.10 ms (macOS) / 1.52 ms (Linux) vs 10 ms budget. **Honest exception: exe-PINNED grants pay a per-check `/proc/<pid>/exe` hash — 56–90 ms on dataserver3 (I/O-bound by binary size) — over the 10 ms budget; per-pid digest caching is the filed follow-up. Pin only when binary-identity assurance is worth that latency, and prefer small service binaries.** |

## Integration runbook (VPS + service IDM)

Identity model: one `client_id` per service identity; one grant per
(entry, service); per-grant one-time token (`SENTINELPASS_SERVICE_TOKEN`);
optional factors = exe pins (Linux, with the latency note) and OpenPGP
fingerprint (enrollment ceremony binds the service's key).

```bash
# OWNER MACHINE (0.16.0) — grant ceremony (prompts for the master password):
sentinelpass service-grant create --client-id sandesha-svc \
  --entry-id 42 --fields password --expires-in 30d
#   [--exe-sha256 <64hex>]  — pin approved binaries (Linux; see latency note)
#   [--key-fingerprint <40hex>] — grant stays PENDING until:
sentinelpass service-grant enrollment begin --client-id sandesha-svc
#   → client signs the transcript with their OpenPGP key, then:
sentinelpass service-grant enrollment complete --client-id sandesha-svc \
  --nonce <n> --signature sig.asc --public-key pub.asc

# DELIVERY to the VPS (host-bound, F4 procedure — encrypt ON the target
# with the target's own host key; plaintext only over authenticated SSH):
sentinelpass service-grant get --client-id sandesha-svc \
  --entry-id 42 --field password --no-newline |
  ssh user@vps 'sudo systemd-creds encrypt --with-key=host \
    --name=sandesha.provider.key /dev/stdin \
    /etc/credstore.encrypted/sandesha.provider.key'

# SAME-HOST provisioning (token via env, never root argv):
sudo --preserve-env=SENTINELPASS_SERVICE_TOKEN sentinelpass \
  service-credential install --client-id sandesha-svc \
  --entry-id 42 --field password --cred-name sandesha.provider.key \
  --protection host-key

# Rotation: create the new grant FIRST, re-provision, then revoke the old:
sentinelpass service-grant revoke --grant-id <old-uuid>

# Audit: denials and retrievals land in the daemon audit log
# (service_get:* / CredentialViewed events; opaque ids).
```

Unit wiring: `LoadCredentialEncrypted=sandesha.provider.key`; the
service reads `$CREDENTIALS_DIRECTORY/sandesha.provider.key`. Restart
drill: `systemctl restart` ×3 with the vault LOCKED — the credential
still decrypts (PID 1, host key) while NEW provisioning correctly fails
closed.

## Qualification evidence (this release)

- **dataserver3 synthetic ceremony (2026-10-04, binaries built from the
  tag on the host):** create ✓ (single-connection step-up), get ✓
  (byte-exact), wrong-token ✓ denied, wrong-entry ✓ denied (exact-entry
  enforcement), revoke ✓, post-revoke ✓ denied, and the F2 live proof
  (valid legacy grant refused by the strict daemon).
- **Perf:** drill transcripts on both hosts; doc
  `docs/SP7_PERFORMANCE_EVIDENCE_2026-10-04.md` (macOS + Linux columns,
  methodology, the exe-pin finding).
- **Host-key round-trip on the VPS host: DONE (owner-executed,
  2026-10-04)** — `systemd-creds encrypt --with-key=host` then `decrypt`
  on dataserver3 returned the synthetic value byte-exact (the
  unencrypted-media warning is the documented host-key caveat:
  disk-snapshot access ≈ plaintext access).
- **Deployment note (umask-002 hosts like dataserver3):** config/runtime
  dirs must be `chmod -R go-rwx` — the ADR-012 birth-mode check refuses
  group-accessible parents (hit and resolved during qualification).

## Incident disclosure

During SP-7 drill development (before isolation was added), one
synthetic grant was written to the DEVELOPMENT Mac's real grant store
and 600 synthetic audit events were appended to its real audit log
(2026-10-04 ~05:57 UTC). The bogus grant was removed; the append-only
audit chain was NOT rewritten and stands as the incident record. Shipped
drills pin all platform dirs and cannot recur this. Disclosed here so
your forensic review of ANY SentinelPass audit chain knows what these
entries are.

## Known limits carried forward

1. Per-service UID isolation (F1c) — deferred; same-UID boundary today
2. Exe-pin per-check hashing latency — per-pid digest caching filed
3. Remote mTLS retrieval (SP-5) — deferred; owner-mediated delivery only
4. Linux exe-policy column exists; Windows/macOS deny fail-closed
   (EvidenceUnavailable) by design
