# Authenticated service-grant storage

Implementation candidate, October 5, 2026. Builds on PR #250. This is not a
published release or authorization to replace a production grant store.

## Decision

Store the complete grant policy in a version-2 authenticated envelope. Derive a
32-byte key with the existing HKDF-SHA256 implementation from the active vault
DEK, using the dedicated `sentinelpass-service-grants-integrity-v2` purpose.
Authenticate the exact payload bytes with HMAC-SHA256 and a separate envelope
domain. Existing token, entry, field, expiry, revocation, executable and enrollment
checks remain mandatory. The payload contains policy metadata and token hashes,
not secret values; this envelope supplies integrity, not metadata encryption.

Every service-grant read and mutation verifies the envelope before parsing policy.
An unsigned legacy document, wrong vault key, edited policy, unknown format or
invalid MAC fails closed. Unknown fields and duplicate grant IDs still reject the
whole policy. Reads are bounded to 1 MiB, refuse non-regular files and Unix symlinks,
and use nonblocking open to avoid hanging on a substituted FIFO. Writes keep the
existing owner-only atomic publication. Unix parent-directory open/fsync failures
now return an error rather than acknowledging durability. On Windows, replacement
uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` and no cross-volume copy fallback.
A post-publication error is reported as `store_error`; the new policy may already
be visible, so inspect/retry under owner authorization instead of rolling back to
old grants. These are OS-level durability requests, not a physical power-loss
qualification of every filesystem/device. No new dependencies or crypto primitives.

The authentication key is held in a short-lived zeroizing wrapper; no second
key file is written. Retrieval drops it before executable/entry-fetch awaits,
and enrollment drops it before external GPG verification. New requests to a
locked vault cannot authenticate/serve grants; already in-flight operations are
not synchronously canceled by lock. Lock state is
checked again after external enrollment verification, before its policy update.
Fresh, operation-bound password step-up continues to guard grant creation,
revocation and enrollment initiation. The existing enrollment completion proof
remains bound to the owner-approved challenge. Retrieval never unlocks the vault.

## Migration and recovery

There is deliberately **no automatic signing/import of legacy JSON**: that would
approve whatever an attacker edited before the upgrade. First inventory and
review desired entries/fields and consumers. During an owner-controlled maintenance
window, stop provisioning, retain a private reference copy of the legacy store,
and remove it from the active path. Reissue the reviewed grants individually
through `service-grant create` with fresh password step-up; complete any configured
OpenPGP enrollment. New tokens replace old tokens; do not reuse legacy hashes.

Existing systemd-delivered credentials keep working while the provisioning broker
is unavailable. Stage and verify replacements before revoking provider keys.
Do not downgrade to an unsigned-store release to bypass a failed integrity check.
A vault DEK replacement invalidates old envelopes: reissue grants after rekey.
Ordinary password rewrapping preserves the DEK and therefore the envelope key.
Recovery must review and reissue grants, not reactivate stale policy from backups.

## Explicit limits and deployment choice

- Replaying the grant file alone can reactivate an old revoked grant if the vault
  DEK is unchanged and its old token is still known. This change does not provide
  a rollback-resistant external monotonic counter. Never treat a restored grant
  file as approved current policy; rotate provider credentials to invalidate
  previously delivered values as well.
- A compromised unlocked daemon/root/hypervisor can obtain keys, replace the
  verifier, or observe plaintext. This is not a hardware trust boundary.
- The owner IPC socket still exposes broader reads under the existing same-UID
  model. Authenticating this store does not make that socket safe for untrusted
  service accounts. Do not give services its IPC token or access to that socket.
- Executable hashing identifies bytes, not the human launching them; it does not
  measure injected runtime code or confer exclusive ownership of a public binary.
- A read-only vault grant does not make the retrieved S3 credential read-only.
  Provider-side permission boundaries must be separately tested.

For Sandesha, keep the owner vault and mutation authority on trusted infrastructure.
Deliver only approved service fields over pinned SSH into target-host-encrypted
systemd credentials; consumer units receive only their own files. Qualify locked-
vault restarts on OVH. Do not place the personal vault or its master password there.
Future resistance to cloud administrators requires separately evaluated attested
execution or moving the sensitive operation off-host; client-held E2EE keys are
required for the corresponding mailbox confidentiality goal.

## Evaluation

Required: authenticated roundtrip; wrong vault; edits to every authorization field;
unsigned/version downgrade; duplicate/schema rejection inside an authenticated
payload; oversized file; symlink/FIFO refusal; daemon retrieval of a valid grant,
refusal after well-formed policy tampering, locked-vault refusal; existing step-up,
token/entry/revocation/enrollment tests; workspace tests; real-socket performance.
Results and remaining deployment gates belong in the PR, not inferred from this spec.
