# ADR-012: Shared Private-File Custody (`anvai-secure-io`)

| Field | Value |
|-------|-------|
| Status | Accepted (2026-09-30, after adversarial review; remediation folded into the same change) |
| Date | 2026-09-30 |
| Owners | Core maintainer, security lead |
| Related | ADR-011 (service credentials consume the allowlist broker); ADR-007 (§11 file hygiene lineage, WBS-412/413) |
| Implementation | `anvai-secure-io/` (crate README documents operational limits and recovery) |

## Summary

Extract the bounded Linux private-file-custody contract into an Apache-2.0
workspace crate, `anvai-secure-io`, and adopt it for the external-secret
allowlist on Linux. The crate owns handle-relative traversal, owner/mode and
regular-file checks, bounded zeroizing reads, atomic durable publication, and
advisory locks — with no vault, crypto, database, UI, or networking
dependency, so other Anvai applications can consume a pinned Git revision
without depending on `sentinelpass-core`.

## Context

Sensitive-file hygiene in `platform.rs` (WBS-412/413) grew path-based checks
with two structural weaknesses on Linux: check-then-open TOCTOU (validate by
path, then reopen by path — two resolutions an attacker can race) and a save
path that configured 0600 `OpenOptions` but then called `fs::write`, so
freshly written allowlists inherited umask-default permissions (a real defect
shipped through 0.14.0). A second Anvai product needs the same custody rules;
copying helpers would leave patches divergent.

## Decision

One small, `#![forbid(unsafe_code)]`, `publish = false` crate implements the
Linux contract: `O_NOFOLLOW`-walked ancestor verification (every operation,
not just creation), owner + mode enforcement on files and directories
(group/world bits refused), regular-file/nlink/hardlink/FIFO discipline,
bounded (caller-capped) zeroizing reads, O_EXCL temp + fsync + rename + dir
fsync publication with honest `CommitUncertain` durability reporting, and
cross-process advisory locks. The first SentinelPass consumer is
`ExternalSecretAllowlist` on Linux; JSON, legacy/enforced/revoked token
semantics, and authorization decisions are unchanged — only I/O moves.

Options considered:

- **Keep the helpers in `platform.rs`** — rejected: duplicates the contract
  for the second consumer; the path-based checks carry the TOCTOU and
  umask-birth weaknesses by construction.
- **A universal "common" crate or a direct dependency on core** — rejected:
  conflates unrelated trust boundaries (vault/crypto/DB would drag into a
  leaf product).
- **Copy the helpers per product** — rejected: divergent patches.
- **Extracted leaf crate** — chosen: two independent products share one
  tested contract; security fixes need coordinated version updates and no
  public package depends on private code.

## Threat Model

Strengthens against: symlink/hardlink planting and swap races (handle-relative
walks, single-resolution validate+read on one fd), umask-exposed birth modes,
torn publications (old-or-new only, crash-tested), unbounded reads, and
stale-inode lock retention (a replaced-away inode can never satisfy a lock).

Does not defeat: root (explicitly trusted), user-namespace UID remapping,
NFS/container id-mapped mounts (no claims made), power loss beyond fsync
semantics (crash evidence is not a power-loss certification), or a
compromised same-user process (the OS-user boundary remains the trust root,
as everywhere in this codebase). Windows ACLs and macOS handle/durability
guarantees are unchanged — non-Linux callers keep their existing paths (the
retained save path is improved: it now honors its configured options).

## MVP vs. Later

- **MVP (this change):** Linux allowlist load/save adoption; crate with 13
  adversarial tests (links, permissions, bounds, concurrency, crash
  publication, redaction) plus an MSRV-1.89 CI leg wired into the Gate's
  fail-closed expectation table.
- **Later:** adoption by further core surfaces (vault DB sidecars, receipt
  files — each needs its own failure-mode review); a transactional
  read-modify-write API; Windows ACL and macOS equivalents; possibly
  publishing for external consumers.

## Migration and Rollout

Behavioral drift is fail-closed and must be operator-visible: Linux allowlists
with group/world bits — including those born umask-loose through 0.14.0 — are
now refused instead of warned about and repaired. Operators upgrading Linux
hosts should pre-repair (`chmod 600` the allowlist, `chmod 700` the config
directory); the load error names the remediation, and
`docs/SERVICE_CREDENTIALS.md` carries the upgrade note for the 0.14.0
server-provisioning profile. Tokenless legacy grants are unchanged by this
refactor and remain outside its scope.

## Consequences

One custody contract, doubly consumed and adversarially tested; the cost is a
new workspace member to keep MSRV-clean and a coordinated-updates
responsibility across products. The prior validate-then-read ABA window and
the umask-birth bug are closed on Linux; stricter refusals (writable
ancestors, symlinked homes, dangling links) trade availability for fail-closed
safety by design.
