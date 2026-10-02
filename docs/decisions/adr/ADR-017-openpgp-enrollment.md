# ADR-017: OpenPGP Enrollment (SP-4)

| Field | Value |
|-------|-------|
| Status | Accepted (owner-directed via the Sandesha handoff 2026-10-02 §5; adversarial review rides the PR) |
| Date | 2026-10-02 |
| Owners | Core maintainer, security lead |
| Related | ADR-014 (SP-1 grants — enrollment publishes grants), ADR-016 (SP-3 exe policy — enrollment carries pins), [#194](https://github.com/anvai-labs/sentinelpass/issues/194), `docs/SANDESHA_SERVICE_IDENTITY_HANDOFF_2026-10-02.md` §5 |

## Summary

An **offline-capable, local** enrollment flow: a service principal proves
possession of a dedicated OpenPGP signing key by signing a canonical
challenge transcript, and the daemon (after owner step-up activation)
issues an exact-entry service grant with a scoped `sps_` token. The
OpenPGP signature is an ENROLLMENT-time factor: it does not create usable
grants by itself (activation requires the owner's master-password
step-up) and it is NOT a session token (per-request auth is the existing
grant + token + exe policy).

## Context

Handoff §5: use OpenPGP for enrollment signatures and pinned key
possession — not a bespoke encrypted socket protocol. Keep it
offline-capable/local initially. RFC 9580 is the format reference. The
handoff explicitly warns: the registration signature cannot be replayed
as a session token; both OpenPGP and exe policy can be configured
mandatory — unavailable evidence must deny.

## Decision

1. **No new dependency** (initial slice): the handoff mandates evaluating
   the `pgp` crate first but requires audit/advisory review, license
   verification, and interop tests before adoption. For this slice, the
   daemon shells out to a **pinned `gpg` binary** (absolute path,
   `--homedir` isolated, `--no-default-keyring`, `--with-colons`
   machine-readable output, `--status-fd` for signature verification, no
   network). This matches the handoff's "GnuPG may be an optional
   external interoperability signer" provision while the crate evaluation
   proceeds in parallel. If `gpg` is not present at the configured path,
   enrollment is unavailable (deny, not degrade).
2. **Enrollment sequence** (handoff §5.1-6, adapted to the SP-0/1
   architecture):
   - **Owner** (via step-up-gated `ServiceGrantCreate`) pre-approves the
     full policy: client_id, entry_id, fields, expiry, exe pins, AND the
     `registration_key_fingerprint` (full 40-hex-char OpenPGP primary key
     fingerprint). The fingerprint rides the grant store.
   - **Enrollment challenge**: a new step-up-gated op
     `ServiceEnrollmentBegin { client_id }` generates a 256-bit random
     nonce and returns a **canonical transcript** (versioned JSON,
     deterministic field order): domain separator
     `sentinelpass/service-enrollment/v1`, nonce, client_id, entry_id,
     fields, exe-policy digest, registration fingerprint, expiry.
   - **Client** signs the transcript bytes with its OpenPGP key
     (detached cleartext signature).
   - **Verification + activation**: `ServiceEnrollmentComplete { client_id,
     nonce, signature_armored }` — the daemon verifies via the pinned gpg:
     (a) the signing key's full primary fingerprint matches the
     pre-approved grant's `registration_key_fingerprint`; (b) the
     signature covers exactly the canonical transcript bytes for this
     nonce; (c) the nonce is single-use (in-memory consumption;
     restart-safe because enrollment challenges are also in-memory).
     On success: the grant's token is MINTED and shown ONCE (the client
     already proved possession; the token is the ongoing credential).
3. **Grant schema extension (v1 additive)**: `ServiceGrant` gains
   `registration_key_fingerprint: Option<String>` (serde default) —
   grants WITHOUT it work exactly as SP-1/SP-3 (no enrollment factor);
   grants WITH it require the enrollment flow to mint the token.
4. **Canonical transcript**: deterministic `serde_json` with sorted keys,
   no whitespace — byte-identical on any platform. Domain separator
   prevents cross-protocol replay. The nonce is 256-bit random,
   single-use, with a bounded TTL (5 minutes, matching the handoff).
5. **Fail-closed**: if the exe policy is configured on the grant, the
   enrollment transcript includes its digest (so the client knows what
   it's agreeing to) and the grant's exe enforcement applies from the
   first ServiceGetSecret. If gpg verification fails for ANY reason
   (unknown key, wrong fingerprint, bad signature, expired nonce,
   replay), the enrollment is denied with a typed reason and the nonce
   is consumed (burned on attempt).

## Threat Model

Adds: proof that the entity requesting the grant possesses the
pre-approved OpenPGP key at enrollment time — the handoff's "pinned key
possession" factor. Combined with the owner's step-up activation and the
SP-3 exe policy, a stolen service token faces token + executable + (at
enrollment time) key possession.

Does NOT add: per-session key possession (the token IS the session
credential after enrollment); protection against the key and token being
stored together under a compromised UID (handoff §5 explicitly notes
this); protection against the enrolled principal intentionally leaking
its secret; or remote/mTLS transport security (SP-5, separately
qualified). The gpg subprocess is the trusted verifier — a compromised
gpg binary at the pinned path subverts enrollment (same-host trust
concession).

## Migration

Additive: new optional field, two new VaultOps (classified step-up in the
exhaustive match), no changes to existing grants or flows. Existing
grants without fingerprints work unchanged.

## Consequences

Enrollment becomes a two-party ceremony (owner approves policy + client
proves key possession), with the daemon as the verifier. The `pgp` crate
evaluation for an in-process verifier proceeds separately; the external
gpg adapter is the bridge that ships today.
