# SentinelPass 0.15.1 — Sandesha adoption hand-back

Date: 2026-10-03. Response to `docs/SANDESHA_V015_ADOPTION_HANDOFF_2026-10-02.md`.

## Fixed version and verification

- **Version:** 0.15.1
- **Source:** PR #238 merged to `develop` (`7ba930c`), promoted to `main` by the release PR that carries this document
- **Tag:** `v0.15.1` is cut on the promoted `main` commit (the earlier tag that peeled to the 0.15.0 commit `5125a3d` — verification doc F1 — was deleted and re-cut correctly)
- **Artifact hashes:** see the GitHub release page `sha256sums.txt` for `v0.15.1`

## P0 — Step-up transport defect: FIXED

**Root cause:** the CLI's step-up flow opened TWO `IpcClient::send()` calls, each
creating a FRESH secured connection. The server correctly binds each step-up
receipt to the minting connection's identity, so the second connection (the
mutation) was always denied. Handler-level tests missed this because they inject
the same `PeerContext` into both calls.

**Fix:** `IpcClient::call_service_with_step_up(op, master_password)` authorizes
AND executes the exact operation on **one** secured connection. The CLI prompts
for the password BEFORE opening the connection (no idle socket during human
input). No transparent retry after mutation/connection failure (a lost response
may mean the mutation already committed). A real Unix-socket test proves:
cross-connection receipt denial (old bug), wrong-password denial,
same-connection success, and exactly one mutation.

**CLI behavior under strict mode:**
```bash
# Any mutation op (add, edit, delete, totp-add, etc.) now works:
sentinelpass add --title "test" --username "user"
# Prompts: "SentinelPass: this change needs the master password: "
# Entering the correct password → mutation succeeds on one connection
```

## P1b — Legacy admin gate: FIXED

`secret allow`, `secret revoke`, and `secret token mint/rotate/revoke` write
`external-secret-access.json` directly, outside the daemon's step-up boundary.
Under `SENTINELPASS_REQUIRE_STEPUP=1` (strict profile), these now REFUSE:

```bash
SENTINELPASS_REQUIRE_STEPUP=1 sentinelpass secret allow mytool --domain example.com
# Error: strict provisioning profile is active: legacy 'secret allow/revoke/token'
# write the grants file directly, outside the master-password step-up boundary.
# Use the step-up-gated 'service-grant' commands (ADR-014), or unset
# SENTINELPASS_REQUIRE_STEPUP on the daemon and restart.
```

Read/list/audit commands remain available (they don't mutate policy).

## P2 — Performance evidence: CORRECTED

`docs/SP7_PERFORMANCE_EVIDENCE_2026-10-02.md` no longer claims PASS on targets
measured with simplified primitives (FNV-1a instead of SHA-256/HMAC). Targets
are now **PROVISIONAL** with the methodology limitation stated. Production-path
benchmarks with real primitives, real executable hashing, real daemon IPC, and
real gpg enrollment remain follow-up work.

## P1a — Service-grant CLI surface: NOT YET COMPLETE (known gap)

The SP-1 grant operations (`ServiceGrantCreate`, `ServiceGetSecret`,
`ServiceGrantRevoke`, `ServiceEnrollmentBegin`, `ServiceEnrollmentComplete`)
exist in the protocol and daemon but are **not yet exposed through CLI
commands**. The step-up transport fix (P0) is a prerequisite — now landed.
The service-grant CLI commands are the next feature release (0.16.0).

Until then, provisioning uses the existing legacy grant surface (which works
under strict mode with the P0 fix):
```bash
# On the owner machine (strict daemon), legacy grant creation is gated.
# For the initial provisioning profile, use a non-strict daemon for grant
# setup, then switch to strict for steady-state:
SENTINELPASS_DAEMON_ARGS="" sentinelpass-daemon &  # non-strict
sentinelpass secret allow sandesha-svc --domain sandhi:provider:key --field password
# ... then restart the daemon with SENTINELPASS_REQUIRE_STEPUP=1
```

## Supported custody topology

```
Trusted owner machine (Mac/Linux):
  - Master vault + daemon (strict profile)
  - Step-up-gated administration (CLI + interactive password)
  - service-credential install (encrypts → systemd-creds)

OVH VPS:
  - Encrypted systemd credentials ONLY (host-key mode, no TPM)
  - No daemon, no vault, no master password
  - Service units load via LoadCredentialEncrypted= (PID 1 decrypts at start)
  - One dedicated UNIX user per service (recommended)
```

## Integration commands (existing, verified with P0 fix)

```bash
# On the owner machine:
sentinelpass secret allow sandesha-svc --domain sandhi:provider:key --field password
# Note the minted client token (shown once)

# Provision into systemd credential (owner machine, sudo/root):
sudo sentinelpass service-credential install \
  --client-id sandesha-svc --domain sandhi:provider:key \
  --cred-name sandesha.provider.key \
  --protection host-key
# Prompts for master password (P0 fix: single connection)

# On the VPS, the service unit:
# [Service]
# LoadCredentialEncrypted=sandesha.provider.key
# ExecStart=/app/bin/service  # reads $CREDENTIALS_DIRECTORY/sandesha.provider.key
```

## Remaining explicit limits

1. **Service-grant CLI** not yet exposed (P1a — next release)
2. **Cross-UID service socket** deferred (SP-1 Later; same-UID owner IPC only)
3. **Remote mTLS** deferred (SP-5; no public SentinelPass listener)
4. **Performance benchmarks** with real primitives remain follow-up work
5. **Production-path gpg enrollment** qualification (custody, network denial,
   timeout/output bounds, revoked keys, nonce replay) remains follow-up work
6. **Host-key mode** defeated by full disk snapshot (no TPM on target)
7. **Android emulator matrix** optional (continue-on-error; results visible
   but non-blocking)

## Evidence

- Real Unix-socket step-up test (P0): `step_up_real_client_keeps_approval_connection`
- Full workspace suite: 1,064 tests green
- 16 adversarial review rounds across SP-0..SP-4 (see ADRs 013-017)
- Reproduction evidence: `docs/evidence/sandesha-v015-adoption-20261002/`
