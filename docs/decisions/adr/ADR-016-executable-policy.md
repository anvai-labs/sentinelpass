# ADR-016: Linux Executable Policy (SP-3)

| Field | Value |
|-------|-------|
| Status | Accepted (owner-directed via the Sandesha handoff 2026-10-02 §4; adversarial review rides the PR) |
| Date | 2026-10-02 |
| Owners | Core maintainer, security lead |
| Related | ADR-014 (SP-1 exact-entry grants — the policy rides grants), ADR-015 (SP-2 PeerContext — the seam), [#194](https://github.com/anvai-labs/sentinelpass/issues/194), `docs/SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md` §4 |

## Summary

Service grants gain an OPTIONAL mandatory executable policy: when a grant
carries `required_exe_sha256` values, `ServiceGetSecret` additionally
requires that the kernel-attributed peer process's `/proc/<pid>/exe`
(the kernel-referenced executable, opened through the proc handle — never
a caller path or a later `readlink`) hashes to one of the approved
digests. Unavailable evidence DENIES (fail-closed), never degrades to
token-only.

## Context

Handoff §4: stolen service tokens must face "token AND local executable
policy; deny on unknown identity." SP-2 threaded the kernel peer
identity; this slice reads it. The handoff's honest framing applies in
full: an executable digest is an **additional constraint**, not remote
attestation, not a same-UID sandbox — a same-UID attacker can run the
approved binary, read same-UID material, or modify policy; scripts pin
their interpreter when only `/proc/PID/exe` is measured; shared
libraries/plugins/injected code remain relevant even for a pinned ELF.

## Decision

1. **Grant schema v1 extension (additive)** — `ServiceGrant` gains
   `required_exe_sha256: Option<Vec<String>>` (hex SHA-256). `None` =
   no executable requirement (SP-1 behavior unchanged). A non-empty list
   = MANDATORY. `deny_unknown_fields` unchanged: existing stores without
   the field still parse (serde default None) — this is a *new optional
   field on a v1 struct*, safe because v1 consumers that predate it
   never wrote it and the loader's whole-document rejection still fires
   on truly unknown names.
2. **Resolution (Linux only)** — at enforcement time, open
   `/proc/<pid>/exe` by pathname (the kernel-owned numeric pid from
   SP-2's `PeerContext` + kernel-controlled procfs; no O_NOFOLLOW — it
   would ELOOP on procfs magic symlinks, and security rests on the pid
   and procfs both being kernel-owned, not on open flags). The
   connection-time pid is a snapshot: a recycled pid's binary matching
   the pin is precisely the conceded "attacker runs the approved binary"
   case, as is fd-passing/fork-inheritance of the connection — both
   subsumed by the same-UID limitation. Stream-hash the open file
   (SHA-256, bounded, blocking pool). `/proc` unavailable or the open
   fails → DENY (fail-closed, reason `exe_evidence_unavailable`).
3. **Enforcement point** — `service_get_secret`, AFTER token+grant
   validation, BEFORE vault lookup: if the grant's
   `required_exe_sha256` is `Some(list)` and non-empty, resolve the
   digest and require membership (constant-time compare over the hex).
   Mismatch → `denied` with reason `exe_policy_mismatch`; evidence
   unavailable → `denied` with `exe_evidence_unavailable`. The typed
   status lets a legitimate operator distinguish misdeployment from
   attack without leaking which digest was expected.
4. **Non-Linux** — `/proc/<pid>/exe` does not exist; enforcement returns
   `exe_evidence_unavailable` (deny) whenever a grant carries a pin.
   Operators on macOS/Windows simply do not configure pins (the ADR-014
   v1 grant never auto-carries one).
5. **No digest caching** (handoff: not until correctness is proven).
   Upgrade discipline: new binary digest = explicit grant update under
   step-up (the SP-1 unconditional gate), bounded overlap window by
   listing both digests, then removal.
6. **argv/process-name/PID as identity** — explicitly NOT used (handoff
   §2: do not market them as authentication). PID is only the kernel's
   handle to the exe.

## Threat Model

Adds: a stolen service token used by an UNAPPROVED executable is denied
(the handoff's "stolen client token used by an unapproved executable"
row) — damage limitation against token exfiltration to a different
tool/binary on the host. Every denial is AUDITED (mismatch and
evidence-unavailable both leave a forensic trace — handoff §6).

Does NOT add (unchanged from ADR-014/015, stated per handoff §4's
residual-limits discipline): same-UID compromise (the attacker can run
the approved binary, or read the token and the approved binary's
placement — this INCLUDES fd-passing/SCM_RIGHTS and fork-fd-inheritance
of the connection to a different process, and pid recycling onto the
approved binary), root, interpreter-script confusion (pinning
`/bin/bash` pins bash), library/plugin injection into the approved
binary, exec-after-connect within the approved process (the open-pins-
the-inode race: the hash sees the old image while the response rides to
the new one — requires already running the approved binary at open
time, subsumed), and container namespace spoofing. pidfd pinning is a
hard prerequisite for the future cross-UID service socket (handoff §3),
where these races carry real weight; on the same-UID owner socket they
add nothing beyond the same-UID concession.

## MVP vs. Later

- MVP: grant pin field, Linux `/proc/<pid>/exe` resolution, enforcement
  with typed AUDITED denials, step-up-gated grant creation carrying
  pins (with 64-hex validation at mint), pin-listing on the create
  report, unit tests (self-exe resolution + match/mismatch on Linux,
  non-Linux evidence-unavailable, empty-pins no-op, absent pid
  unavailable) and a Linux server-level integration test proving the
  enforcement block denies a pinned grant when the peer pid does not
  resolve to the pinned binary.
- Later: pidfd pinning (`pidfd_open`/`SO_PEERPIDFD`) to tighten the
  connection-lifetime identity; digest caching with full invalidation;
  trusted-custody checks on the exe path; container support matrix.

## Migration

Additive optional field; no existing grant or store changes. The
Sandesha deployment opts in per grant at provisioning time.
