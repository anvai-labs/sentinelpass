# ADR-014: Exact-Entry Service Grants (SP-1)

| Field | Value |
|-------|-------|
| Status | Accepted (owner-directed via the Sandesha handoff 2026-10-02 §3; adversarial review rides the PR) |
| Date | 2026-10-02 |
| Owners | Core maintainer, security lead |
| Related | ADR-013 (step-up: grant administration is step-up-gated), ADR-007, ADR-011, [#194](https://github.com/anvai-labs/sentinelpass/issues/194), `docs/SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md` §3 |

## Summary

A versioned **service grant** store binding an authenticated service
principal to an **exact vault entry** (immutable numeric `entry_id`, never
a mutable domain/title), specific fields, and an expiry — enforced by the
daemon on a retrieval-only service operation with typed locked/denied/
not-found errors. Grant administration is a master-password step-up
operation (SP-0). The separate per-principal service socket is explicitly
deferred per the handoff's own allowance; until it lands, the supported
service delivery path remains ADR-011's systemd credentials.

## Context

The existing broker (`ExternalSecretGrant`) scopes by `client × domain ×
field` — a mutable display-level key with ambiguous lookup (multiple
entries can share a domain; the handoff demands "same-domain duplicate
entries never choose an arbitrary account") and no policy versioning. The
handoff §3 requires `ServiceGrantV2` with: exact immutable entry binding,
no wildcards, read-only, unknown-version/mandatory-field fail-closed,
tokenless impossibility, admin-owned custody outside consumer UIDs, and
serialized crash-safe updates.

## Decision

1. **Schema** (`service-grants.json`, 0600, config dir — owner custody,
   same hygiene as the allowlist): each grant carries
   `policy_version: 1`, `grant_id` (uuid), `client_id`, `entry_id` (i64),
   `fields` (subset of username/password/title), `expires_at` (optional),
   `revoked_at` (optional), `created_at`. Deserialization is fail-closed:
   unknown `policy_version`, missing mandatory fields, or an unknown field
   NAME rejects the whole document (`deny_unknown_fields`) — never a
   silent partial load. Tokenless service grants are unrepresentable
   (`client_token_hash` mandatory; token format mirrors the existing
   `spt_` scheme with its own prefix).
2. **Daemon enforcement** — a new retrieval-only IPC op
   `ServiceGetSecret { client_id, entry_id, field, token }`: verifies the
   token (constant-time against the stored hash), the grant (exact
   `entry_id` + field + not expired/revoked), then serves the field from
   the vault. Typed outcomes distinguish `denied` (no/invalid grant),
   `not_found` (entry absent — AFTER grant validation, so probing requires
   a valid grant first), and `locked` — without leaking entry existence to
   un-granted callers. Ambiguity is structurally impossible: the grant
   names one `entry_id`; there is no domain lookup on this path.
3. **Administration is step-up-gated UNCONDITIONALLY** —
   `ServiceGrantCreate`/`Revoke` are `VaultOp`s classified
   `requires_admin_step_up()` (exhaustive match forces the classification),
   and unlike the transitional SP-0 surface their gate ignores the profile
   flag: a consumed, op-bound approval is required on EVERY daemon (new
   surface, zero legacy clients — nothing to preserve). An unlocked vault
   plus a stolen IPC token can never mint or revoke service grants on any
   profile.
4. **Serialized updates** — the store uses the same
   write-temp/fsync/atomic-rename discipline as the SP-0 manifest, with a
   store-level mutex serializing read-modify-write cycles (the
   lost-revocation race the handoff flags for concurrent grant updates).
5. **Deferred (handoff's allowance)** — the per-principal service-only
   Unix socket with group/ACL access: until it ships, `ServiceGetSecret`
   rides the owner socket (same-UID trust domain, like every existing
   op), and cross-UID retrieval stays **unsupported** — services use
   ADR-011 systemd credentials. `required_local_identity`
   (executable pinning) arrives with SP-3 and is an ignored-unknown until
   then only if `policy_version` explicitly sanctions it — v1 does NOT
   carry it, so a grant with that field fails closed today.

## Threat Model

Reduces: ambiguous-domain credential confusion (exact entry binding);
tokenless/legacy service access (unrepresentable); grant tampering by
consumer processes (owner-custody 0600 + fail-closed schema); grant
minting by stolen IPC tokens (SP-0 step-up); concurrent-update lost
revocations (serialized + atomic publish); schema downgrade/confusion
(version + unknown-field rejection).

Does not defeat: same-UID compromise (the consumer can read what the
owner socket serves — unchanged until the SP-1-later socket); root; and
the granted consumer intentionally leaking its secret (handoff §2: out of
scope for delivery).

## Migration

Additive: a new store file + new IPC messages; the legacy
domain-scoped broker is untouched (human/desktop tooling keeps it;
service principals use v2). Legacy grants are never auto-converted —
conversion is an explicit owner action.

## Consequences

Service access becomes entry-exact and token-enforced by construction,
with administration behind the master-password gate. The deferral means
service isolation still rests on the OS-UID boundary plus systemd
credential delivery — stated, not blurred.
