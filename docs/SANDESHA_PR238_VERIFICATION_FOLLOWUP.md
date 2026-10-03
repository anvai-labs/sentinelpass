# Sandesha verification of SentinelPass PR #238

Review: October 3, 2026 UTC (October 2 local). No production vault, grant, credential,
provider key, daemon or VPS service changed. Supersedes incomplete adoption claims,
not the correct single-connection fix. Please preserve the owner requirement:
automate retrieval only; all administration/mutations require fresh master-password
authorization. Do not recommend non-strict bootstrap as a workaround.

## Verified fixes

PR https://github.com/anvai-labs/sentinelpass/pull/238 is MERGED into develop at
`7ba930c1795bd965e55fa33b10c375a567bf5707`, October 3 04:13:49 UTC. PR CI checks pass.
The protocol client, CLI service client and daemon socket regression are byte-identical
to reviewed patch commit `3073d44`. The test verifies cross-connection receipt denial,
wrong-password denial, same-connection success and exactly one mutation. SP7 target
claims are corrected to PROVISIONAL. Independent exact-merge rerun: **8 step_up tests PASS**, 0 failed, 167.57 s,
synthetic vault and real Unix socket on macOS. Command: `cargo test --locked
-p sentinelpass-core step_up -- --test-threads=1`. AnvaiOps consumer evidence:
`infra/ovh/sandesha/sentinelpass/pr238-stepup-tests.txt`. Full workspace was NOT
rerun by this consumer session; its CI results were inspected separately.

## F1 — Release reference mismatch (deployment blocker)

Observed with live git ls-remote:
- remote develop: `7ba930c1795bd965e55fa33b10c375a567bf5707`
- remote main: `5125a3da68a4bcfe9316023f60c4a8c2aff6a205`
- v0.15.1 annotated tag object: `f66d3f83b83f7cfea143c509c0a0b066db8b6a1d`
- v0.15.1 peeled commit: `5125a3da68a4bcfe9316023f60c4a8c2aff6a205` (old v0.15.0)
- GitHub /releases/tags/v0.15.1: HTTP 404.

A later live recheck found the incorrect remote v0.15.1 tag REMOVED; remote
main/develop still have the commits listed above. Historical observations above
are retained so the mistaken source pin is not reused.

The local main checkout at 8c9cc2b contains a release commit but that was NOT the
remote main/tag observed. Complete the repository's release promotion process, then
repair release references under your release policy. Since a tag was advertised,
prefer a fresh unambiguous version if immutable-tag policy applies. Consumer session
will not force-move your tag. Verify tag tree/version/commit, CI-built archive contents,
checksum and provenance all correspond; do not only edit release notes/version text.

## F2 — P1b CLI guard is a courtesy check, not daemon enforcement

Merged `sentinelpass-cli/src/commands/secret.rs:423,634` checks only local
SENTINELPASS_REQUIRE_STEPUP == 1. It does not query the running daemon. A strict
daemon can coexist with a CLI shell lacking that variable; the legacy allow/revoke/
token functions still load and save external-secret-access.json directly. Same-UID
file ownership remains the effective boundary, not a master-password receipt.
The helper comment claiming it detects the daemon profile is inaccurate.

Required: authoritative legacy disablement and reviewed daemon-mediated mutations;
no caller-controlled env downgrade. Provide exact-entry service-grant CLI. Include
strict daemon + CLI env absent, 0, 1 negative tests; missing/stopped daemon must fail
closed for mutations. If same-UID arbitrary code can edit the policy store, state
that limit and isolate custody under another service UID for the stronger claim.
Do not claim to protect root or a malicious cloud hypervisor.

## F3 — Hand-back integration commands overclaim install step-up

`sentinelpass-cli/src/commands/service_credential.rs:88-139` still calls legacy
get_secret_from_daemon/GetExternalSecret, then install_credential. It does not
use call_service_with_step_up, an exact-entry ServiceGetSecret, or fresh master-password
approval. New grant/enrollment operations have no CLI wiring (rg finds none in CLI).
The P0 transport fix does not change this path. Correct
`docs/SANDESHA_V015_1_HANDOFF.md` claims that install prompts for master password and
that legacy grant creation is gated by the strict daemon. Remove the suggested
non-strict bootstrap recipe and the command pointing to nonexistent service-grant CLI.

Required next adapter: typed exact-entry retrieval, narrowly scoped consumer token,
owner-authorized provisioning/replacement/removal, authenticated target binding and
no owner token in workloads. Audit secret-free operation outcomes. Test ambiguous
lost response without mutation replay. Resolve install/remove mutation policy explicitly.

## F4 — Host-key credential delivery needs the target host key

Mac owner custody is fine, but encrypt with systemd-creds on the target VPS using
THAT host's host key and pinned credential name. Owner-machine encrypted host-key
blobs cannot just be copied to another host and assumed decryptable. Never export
host keys or move the master vault to bypass this. Deliver approved plaintext through
existing authenticated SSH/stdin without argv/env/log persistence; exact target/name
binding belongs in the owner provisioning authorization. Synthetic two-host/wrong-key
and wrong-credential-name denial tests should precede production.

## Acceptance before Sandesha adoption

Correct release provenance; exact-entry CLI; authoritative strict mutation policy;
real-socket step-up tests; provider-scoped rotation ceremony; per-service Linux/Docker
read isolation; locked vault + stopped daemon + three service restarts; no secret in
logs/argv; rollback before revoking working keys. OpenPGP is optional enrollment,
not remote transport or root protection. Keep production-path perf provisional until
measured with real crypto/executable hashing/IPC/gpg. Existing Sandesha backups and
credentials continue while these gates are open.


## Follow-up source review — October 3

The currently visible `release/0.15.1-fix` branch at
`843a21dd0598fe82d524e52ab5a793142b361277` still starts from old main 5125a3d;
it changes only version files and the hand-back document. It does NOT include
PR #238's protocol/CLI/server fixes. Merely retagging this commit would regress
all verified transport changes. Build the release from the merged develop content
through the repository's promotion procedure, and reconcile the inaccurate hand-back.

Consumer guard added in AnvaiOps:
`infra/ovh/sandesha/sentinelpass/check_source.py` and `source-baseline.json`.
It reads a resolved commit with Git replacements disabled and compares reviewed
security-source hashes plus version; nine synthetic regression tests pass.
Live source evidence: PR #238 passes, 843a21d fails (all four security files differ).
Do not blindly refresh baseline hashes to make a new candidate pass: review the
actual security changes first. No production update, tag move, or master-password
ceremony was performed by the consumer session.

Latest GitHub check: PR #239 is OPEN at 843a21d (no merge commit); the source regression above applies to that PR. Sandesha consumer source check is checkpointed as AnvaiOps 5b19b62; no production adoption authorized.
