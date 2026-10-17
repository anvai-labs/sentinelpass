# Sandesha → SentinelPass: user-owned cross-device custody

Owner request, 2026-10-16. Implement from
[the full proposed contract](SANDESHA_USER_KEY_CUSTODY_CONTRACT_2026-10-16.md).
This is distinct from Sandesha's VPS service-credential integration.

## Start here

1. Read AGENTS.md, SECURITY_ARCHITECTURE.md and SECURITY_STATUS_MATRIX.md;
   reconcile current develop with the inspected `84c7f58d012b428a4f8635d87ae988e0f1ebfc31`.
   Preserve unrelated work and use a feature branch targeting develop.
2. Review the contract's alternatives/threat model; freeze KC-01 as the first workcard
   and add failing conformance tests before code. Reuse the existing Rust protocol,
   ABI/feature negotiation, authenticated envelope and step-up code. Generate TS/native
   bindings; no Go/Python runtime and no duplicate crypto in Swift/Kotlin.
3. Drive KC-01 then KC-02 with synthetic data only. Keep browser, mobile sync and
   hardware assurance unavailable until their own gates pass. Do not skip ahead to
   a broad `getSecret` API or pass SentinelPass's vault DEK to Sandesha.
4. Obtain a fresh adversarial review and green exact-head CI before merging develop.
   Return the requested handback artifacts; publishing/release and Sandesha activation
   are separate decisions. No real keys, grants, credentials or accounts are changed
   by this handoff.

## Decisions to preserve

- One logical mail identity/epoch across approved devices initially; distinct local
  device protection and device identities. Current provider has one encryption subkey;
  per-device mail subkeys are future work, not a flag to turn on.
- Optional personal SentinelPass vault or qualified OS adapter; no mandatory vault,
  operator escrow, administrator recovery bypass or secret derivation from OIDC.
- Protect existing independent 32-byte mail and storage recovery secrets as scoped
  objects. Preserve Sandesha envelope/reference/profile semantics and recovery proof.
- Separate mutation port with fresh master-password step-up; routine exact-object
  reads have bounded leases. User verification must authorize the crypto operation.
- Current mobile ABI advertises platform keystore, **not relay sync v2**. Existing
  mobile UI, passkey references and service-client PGP enrollment do not close this gap.
- Browser native transport needs its own reviewed design; no DOM/autofill plaintext
  secret, no localhost trust based on CORS, and no same-origin malware/root-proof claim.
- Audit actual Android security level and iOS slot enrollment. No TEE/Secure Enclave
  claim from source comments or emulator UI alone. Respect current sync step-up policy.
- Lost-device revocation cannot claw back keys; compromise requires new future-mail
  identity/epoch. Historical decryption and independent recovery remain separate gates.

## Return to Sandesha

Merged source/tag; generated schema/API versions; platform capability table;
conformance/security/performance receipts and raw data; dependencies/notices delta;
remaining gaps; isolated native/browser integration recipe. Keep the status explicit:
contract design, tested adapter, physical-device qualification and production enablement
are four different milestones.

Sandesha active checkout at handoff: `/private/tmp/sandesha-rust-assets-pilot-20261016`.
Source reference: `anvai-labs/sandesha-client`, develop `19b1b4a74be39e34535747e8b15f778071787ec7`
plus the protected-delivery workcard branch. Sandesha is continuing protected content
binding/delivery planning independently; this optional provider is not a prerequisite
for the recovery-kit-only implementation or permission to enable invitations.
