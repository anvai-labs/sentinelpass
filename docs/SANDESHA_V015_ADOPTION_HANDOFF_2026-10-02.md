# Sandesha adoption handoff: SentinelPass 0.15.0

Date: October 2, 2026 (America/Chicago). Owner requested this handoff so the
SentinelPass session can resolve defects, usage gaps and release the qualified fix.
This supplements, and does not overwrite, `SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md`.

## Verified release and integration state

- Released **v0.15.0**, source `5125a3da68a4bcfe9316023f60c4a8c2aff6a205`,
  release PR #232. Published 2026-10-03T02:03:29Z.
- Linux asset: `sentinelpass-0.15.0-linux.tar.gz`, GitHub-published SHA-256
  `f4c3c46abcb5aad8a58e03cbaae8bf911a6a5c8c0dc804054ce674af7c9da73b`.
  This is the release metadata digest, not a claim that we downloaded/installed it.
- Sibling checkout `/Users/vijaysingh/code/sentinelpass` was fast-forwarded to
  that commit. Its existing untracked handoff documents were preserved.
- Sandesha candidate pin: `../anvaiops/infra/ovh/sandesha/sentinelpass/pin.json`.
  `productionApproved` deliberately remains false. Review/design:
  `../anvaiops/infra/ovh/sandesha/sentinelpass/INTEGRATION.md`.
- Installed Mac CLI and existing OVH qualifier CLI were still **0.14.2** when
  inspected. No real credential rotation, grant, vault mutation, service-user
  change, daemon upgrade or VPS credential cutover occurred during this review.
- Existing mail and backups continue. Do not ask repeatedly to unlock the owner
  vault: the blockers below are integration/code issues, not an unlock problem.

## P0 — Confirmed real-socket CLI step-up defect

**Trigger:** enable strict mode on an unlocked daemon; use the CLI to mutate an
entry; enter the correct master password when the fresh-authorization prompt appears.

**Cause:** released `sentinelpass-protocol/src/client.rs::IpcClient::send` creates
and negotiates a fresh connection on every call. CLI
`sentinelpass-cli/src/commands/service_client.rs::step_up_interactive` calls `send`
for `StepUpAuthorize`, then `Backend::call` calls `call_service_with_approval`, which
calls `send` again. Server `IpcServer::run` generates a random connection ID on each
accept, and its step-up store correctly binds the receipt to that ID.

**Result, reproduced against real protocol/client/server with a synthetic vault:**

```
Err(Service("step_up_required",
  "step-up approval denied: approval was issued on a different connection"))
```

The existing handler tests inject the same `PeerContext` into both calls and do
not cover this client transport lifetime. The daemon is failing closed; this is a
functional blocker, not evidence that unauthorized mutations succeeded.

### Proposed narrow patch supplied

- Patch: `docs/evidence/sandesha-v015-adoption-20261002/stepup-transport-fix.patch`.
- Isolated working clone: `/private/tmp/sentinelpass-stepup-transport-20261002`,
  branch `fix/stepup-client-connection`, based on the release commit.
- Refactors client transport connection/exchange into private reusable helpers.
- Adds `IpcClient::call_service_with_step_up(op, master_password)` that authorizes
  and executes the exact operation using **one** secured connection.
- Prompts for the password before opening that connection; avoids keeping an idle
  socket across human interaction. No transparent retry after mutation/connection
  failure, because a lost response may mean the mutation already committed.
- CLI retry uses this combined method. Server binding/TTL/single-use checks remain
  unchanged. The old one-shot receipt method remains for compatibility but its
  documentation warns that receipts obtained by a separate `send` cannot work.
- Adds a real Unix-socket test that verifies old cross-connection receipt denial,
  wrong-password denial, the fixed successful mutation, and exactly one added entry.

The test uses only ephemeral synthetic vaults. Socket-directory mode must be 0700;
using a default TempDir without explicitly making it private initially prevented
listening, which was a harness setup issue and was corrected before reproducing
this defect. Test result-variant typos were also corrected during patch development.
See the accompanying validation record for the final status. No full workspace,
CLI interactive, Windows or Linux release qualification is implied by this patch.

**Required completion:** review and land via a feature/fix PR to `develop`, not
`main`; follow AGENTS.md CI/review/promotion process. Add a real CLI PTY test with
an already-unlocked strict daemon; assert both denied and correct-password writes,
locked daemon handling, wrong/expired/reused approval, operation substitution,
server restart and connection loss. Retain handler-level negative tests. Qualify
Unix and Windows named-pipe paths. Review whether the old receipt-only helper
should be deprecated to prevent another consumer making the same mistake.

## P1 — New grants are not wired into the service installer

Released `service-credential install` still calls
`resolve_secret_bytes` → `get_secret_from_daemon` → legacy `GetExternalSecret`.
It does not call `VaultOp::ServiceGetSecret`, and thus does not consume exact-entry,
executable-pin or OpenPGP-enrolled service grants. New operations exist in the
protocol/daemon, but no service-grant/enrollment CLI commands were found.

Implement a reviewed adapter using existing protocol and core APIs, not new crypto:

- Exact entry ID, selected field and authenticated token are mandatory; reject
  domain ambiguity, unsupported policy versions and absent mandatory identity.
- Grant create/revoke and enrollment begin use fresh master-password step-up,
  even with an unlocked daemon. Expose the complete policy for owner review.
- Scoped tokens must not appear in argv, environment dumps, diagnostics, issue
  bodies or command transcripts. Prefer protected stdin/FD/file input and secure
  output custody for one-time enrollment results.
- Reuse `install_credential` / `SystemdCredsTool` atomic encrypt/verify/publish;
  preserve the prior installed ciphertext on failure. Do not use `--no-verify`.
- Provider rotation and broker grant revocation are different actions. Explicitly
  test that old provider credentials stop working after the approved rotation.
- Clearly distinguish trusted owner-side provisioning from untrusted runtime
  retrieval. Do not give a VPS app an owner daemon token just to reach a typed op.

## P1 — Legacy policy administration is outside daemon step-up

`sentinelpass-cli/src/commands/secret.rs::allow_external_secret`, revoke and token
administration write `external-secret-access.json` directly. They do not dispatch
step-up-gated VaultOps. `SENTINELPASS_REQUIRE_STEPUP=1` does not protect those local
file mutations, and `service-credential install/remove` also publishes/removes
local files without a fresh master-password check.

This matters to the owner's requirement that **all administrative changes require
fresh master-password authorization**, while approved retrieval/restarts do not.
It is not a claim that step-up can defend against root or the owner UID directly
editing its own policy file. Define custody and migrate supported legacy CLI
administration through an authorized owner flow or explicitly refuse it in the
strict provisioning profile. Do not advertise strict mode as covering every
mutation while these administrative tools bypass it. Test unlocked/no-password
legacy grant/token changes as well as new service-grant paths.

## P1 — Runtime isolation and delivery choices

The ADRs explicitly defer cross-UID service sockets and remote mTLS. Same-UID owner
IPC still exposes broad reads to owner-token holders. Exe hashes constrain a tool,
but do not turn that owner socket into a safe public/per-workload broker.

**Chosen Sandesha delivery:** keep the master vault/admin token on a trusted owner
machine; install only workload-specific encrypted systemd credentials onto OVH;
restart unattended with vault locked and daemon stopped. No public SentinelPass
listener and no permanent master password on the VPS.

Existing Sandesha systemd units are root-owned Docker launchers; engine/web execute
as container UIDs 2000/1001. Do not merely rename a grant or add Docker group access
and claim per-host-user isolation. Qualify separate service users or an explicit,
reviewed per-container credential-file mount adapter (read-only, proper ownership,
no shared credential directory, no Docker socket in the workload). The current
launcher expects private S3 files; any RAM-staging adapter needs failure cleanup,
restart, backup and rollback tests before removing the working source files.

Scope inventory is in the AnvaiOps integration contract: mail runtime S3 user 49711
is limited to `mail/v1/`; recovery writer/reader are distinct roles. Webmail OIDC
client/session keys are distinct from a human SSO password. Never provision the
owner's Kanidm password as an app credential or describe it as an isolated test user.

## P2 — OpenPGP and performance qualification

OpenPGP in 0.15.0 is **enrollment-time signing-key possession**, not an encrypted
remote broker transport and not a per-request replacement for tokens. GnuPG is an
external isolated-keyring verifier. Its absolute executable path is not itself a
cryptographic executable-digest pin. Preserve source-stated limits and verify the
actual configured verifier custody, network denial, timeout/output bounds,
revoked/expired signing keys, nonce replay and concurrent grant revocation before
claiming the full deployment profile qualified. These are required follow-up checks,
not findings that all such cases are currently vulnerable.

`docs/SP7_PERFORMANCE_EVIDENCE_2026-10-02.md` explicitly says its simplified
benchmarks substitute FNV-1a for cryptographic primitives yet labels full target
compliance PASS. Those samples do not establish production SHA-256/HMAC, real
executable hashing, daemon IPC or GPG enrollment latency. Correct the claims and
benchmark the real pinned path: baseline/token/exe/enrollment, p50/p95/p99, binary
size, cold/warm, CPU/memory, concurrency and denial cases; include reproducible
harness, toolchain and source/artifact hashes.

## Hand back to Sandesha

Provide the fixed reviewed release/version + source/artifact hashes; exact CLI/SDK
commands for step-up, exact-entry grants, enrollment, scoped installation and
revocation; supported custody topology; real transport/CLI/restart/denial evidence;
remaining explicit limits. The strict daemon flag must be present in the actual
service definition, not just documentation. After that, Sandesha can execute the
owner-approved provider rotation and credential cutover. Do not weaken the daemon,
use a direct-vault compatibility bypass, or downgrade to legacy grants to pass tests.
