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

Until then, provisioning uses the existing legacy grant surface. Under the
strict profile (`SENTINELPASS_REQUIRE_STEPUP=1`) the CLI's legacy
`secret allow/revoke/token` commands refuse (P1b), so grant setup happens
on a daemon running WITHOUT the strict profile. **This gate is a CLI-side
courtesy check, not daemon enforcement** (verification follow-up F2): a
caller that unsets the variable or edits `external-secret-access.json`
directly is bounded only by same-UID file ownership. Authoritative
daemon-side disablement of legacy mutations ships with the service-grant
release.

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

## Integration commands (existing surface; constraints per F3/F4)

The `service-credential install` path still retrieves via the legacy
token-enforced `GetExternalSecret` — it does **not** use master-password
step-up (F3). Host-key encryption must run **on the target VPS with that
host's own host key** (F4): a credential encrypted on the owner machine
with the owner's host key is NOT decryptable on the VPS. Do not copy
owner-encrypted blobs or export host keys; deliver approved plaintext to
the target over authenticated SSH stdin and encrypt in place:

```bash
# Owner machine: create the token-enforced grant (non-strict daemon; see F2 above)
sentinelpass secret allow sandesha-svc --domain sandhi:provider:key --field password
# Note the minted client token (shown once)

# Owner machine → target: deliver plaintext over SSH stdin (not argv/env/files)
sentinelpass secret get --client-id sandesha-svc --domain sandhi:provider:key \
  --field password --token "$SENTINELPASS_CLIENT_TOKEN" |
  ssh vsingh@dataserver3 'sudo systemd-creds encrypt --with-key=host \
    --name=sandesha.provider.key /dev/stdin \
    /etc/credstore.encrypted/sandesha.provider.key'

# On the VPS, the service unit:
# [Service]
# LoadCredentialEncrypted=sandesha.provider.key
# ExecStart=/app/bin/service  # reads $CREDENTIALS_DIRECTORY/sandesha.provider.key
```

## Remaining explicit limits

1. **Service-grant CLI** not yet exposed (P1a — next release)
2. **P1b strict gate is CLI-side only** (F2): daemon-side enforcement of
   legacy grant mutations, plus fail-closed when the daemon is stopped, is
   follow-up; same-UID file ownership is the current boundary
3. **Install path is not step-up'd** (F3): `service-credential install` uses
   legacy `GetExternalSecret`; typed exact-entry retrieval and owner-authorized
   provisioning/removal come with the service-grant release
4. **Host-key credentials are host-bound** (F4): encrypt on the target with
   the target's host key; owner-encrypted blobs are not portable
5. **Cross-UID service socket** deferred (SP-1 Later; same-UID owner IPC only)
6. **Remote mTLS** deferred (SP-5; no public SentinelPass listener)
7. **Performance benchmarks** with real primitives remain follow-up work
8. **Production-path gpg enrollment** qualification (custody, network denial,
   timeout/output bounds, revoked keys, nonce replay) remains follow-up work
9. **Host-key mode** defeated by full disk snapshot (no TPM on target)
10. **Android emulator matrix** optional (continue-on-error; results visible
    but non-blocking)

## Evidence

- Real Unix-socket step-up test (P0): `step_up_real_client_keeps_approval_connection`
- Full workspace suite: 1,064 tests green
- 16 adversarial review rounds across SP-0..SP-4 (see ADRs 013-017)
- Reproduction evidence: `docs/evidence/sandesha-v015-adoption-20261002/`
