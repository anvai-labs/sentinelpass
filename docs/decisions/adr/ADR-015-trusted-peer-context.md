# ADR-015: Trusted Peer Context (SP-2)

| Field | Value |
|-------|-------|
| Status | Accepted (owner-directed via the Sandesha handoff 2026-10-02 §4; adversarial review rides the PR) |
| Date | 2026-10-02 |
| Owners | Core maintainer, security lead |
| Related | ADR-007 (IPC authority), ADR-013 (SP-0), ADR-014 (SP-1), [#194](https://github.com/anvai-labs/sentinelpass/issues/194), `docs/SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md` §4 |

## Summary

A server-owned `PeerContext` — kernel-derived connection identity
(effective UID; GID and PID where the platform provides them) captured at
accept time and threaded to request dispatch — recorded as **redacted
provenance** on security-relevant audit events. It is provenance only in
this slice: no authorization decision reads it (that is SP-3's executable
policy, built on this seam). It is NEVER deserialized from client input.

## Context

The daemon already kernel-verifies the peer UID at accept
(WBS-507, `SO_PEERCRED`/`getpeereid`) but discards everything but the
yes/no decision. The handoff §4 requires server-owned peer identity
threaded through accept → connection → frame → authorization dispatch as
the substrate for SP-3's executable policy, with redacted provenance in
audit, while browser/mobile protocol behavior stays unchanged.

## Decision

1. **Capture** — at accept, each platform's transport builds a
   `PeerContext`: Unix returns the kernel's credential view alongside the
   stream (`euid + egid + pid` on Linux via `SO_PEERCRED` `ucred`,
   `euid + egid` on macOS/BSD via `getpeereid`); Windows named pipes have
   no portable peer-credential query, so their context degrades to the
   explicit unknown marker (documented fidelity gap; the uid-equality
   boundary rides the pipe ACL instead). The existing "peer UID must
   equal daemon UID" refusal on Unix is unchanged and remains the
   authorization boundary.
2. **Shape** — `PeerContext { connection_id: u128, uid: u32, gid:
   Option<u32>, pid: Option<u32> }` (platform-neutral, in
   `daemon/transport/mod.rs`), constructed ONLY by the accept paths
   (server-owned; no serde derives — it is never deserialized from any
   wire). It carries the SP-0 `connection_id` that step-up approvals
   bind to, so provenance and step-up authorization share one
   per-connection identity.
3. **Thread** — `run_connection` → `process_frame` → `handle_message`
   → `dispatch_service_call` → the SP-1 handlers carry `&PeerContext`
   as a parameter. There is NO shared state: with up to 16 concurrent
   connections, a server-wide slot would misattribute provenance
   (adversarial review F2); per-connection threading makes correct
   attribution structural (pinned by the isolation test).
4. **Provenance** — the SP-1 service-grant audit events append a
   redacted provenance token (`peer=uid:gid:pid`) to their context lines
   (the request context is threaded end-to-end on that path). The legacy
   external-secret broker events adopt the token with SP-3, when their
   handlers gain the threaded request context; until then their context
   lines are unchanged (they never carried peer data). Static reason
   codes only; no argv, no paths beyond the already-audited ones,
   nothing client-supplied.
5. **Explicit non-goals (this slice)** — no per-message re-verification
   (`SO_PEERCRED` is connection-time truth; SP-3 handles the
   exec-after-connect problem at policy-enforcement time); no
   `/proc/<pid>/exe` hashing (SP-3); no container/namespace unification
   (SP-3's support matrix); no serialized peer context on any wire.

## Threat Model

Improves forensic attribution: audit evidence can state WHICH local
identity class performed a service-grant mutation or secret retrieval,
correlated with the step-up connection. Changes no authorization
boundary. Does not defeat same-UID masquerade (impossible at this layer),
root, or connection hijack after accept (the socket lifetime is the
trust lifetime — unchanged).

## Migration

Additive internal plumbing; wire protocol untouched; no client changes.

## Consequences

SP-3 gets its substrate without protocol churn: executable policy will
read `PeerContext.pid` (Linux) to hash `/proc/<pid>/exe` per privileged
request. macOS/Windows provide provenance-only fidelity — SP-3's policy
will fail closed there unless the executable requirement is left
unconfigured (ADR-013's deny-on-unknown discipline).
