# Passkey Product Design

**Status:** Design gate before implementation
**Last reviewed:** 2026-05-08

This document defines SentinelPass passkey scope before implementation. Passkeys are WebAuthn/FIDO credentials, not password strings. A relying party stores a public key, while the private key remains inside an authenticator and signs origin-scoped challenges.

## Product Decision

SentinelPass will support passkeys in phases. The first implementation surface is metadata/reference management through the existing `passkey_reference` credential type. SentinelPass does not store passkey private keys in generic encrypted vault entries.

The product boundary is:

- SentinelPass may store passkey metadata that helps users find, audit, and launch the correct platform passkey.
- SentinelPass may integrate with platform passkey APIs when acting in an app/browser-compatible flow.
- SentinelPass must not claim to be a passkey authenticator or credential provider until that architecture is explicitly designed and tested.

## Non-Goals

- Do not store WebAuthn private keys as encrypted text secrets.
- Do not implement a custom passkey vault format.
- Do not export passkeys through password/CSV/KeePass flows.
- Do not sync raw authenticator private material through the existing vault sync protocol.
- Do not bypass platform user verification such as Touch ID, Face ID, passcode, Windows Hello, or authenticator PIN.

## Data Model

`passkey_reference` entries are metadata-only records. They identify an external/platform credential and provide enough context for display, search, audit, and future platform handoff.

Recommended metadata:

- `relying_party_id`: WebAuthn RP ID, for example `example.com`.
- `account_label`: user-facing account label, often username or email.
- `credential_id_hint`: opaque credential identifier or truncated display-safe fingerprint when available.
- `platform`: source platform, for example `icloud_keychain`, `windows_hello`, `android`, `security_key`, or `unknown`.
- `sync_source`: where the credential is expected to live, for example `icloud_keychain` or `external_authenticator`.
- `created_at`: known creation time if available.
- `last_used_at`: optional display/audit hint.
- `notes`: user notes; must not contain private key material.

Current core storage uses `CredentialType::PasskeyReference` and stores a reference string in the existing secret field until a dedicated metadata table is added. That reference must be treated as a locator, not a private key.

## User Flows

Phase 1 user flows:

- Add passkey reference: user records RP ID, account label, platform/source, optional credential hint, and notes.
- View passkey reference: UI shows the passkey as a reference and clearly states that authentication still happens through the platform/authenticator.
- Search and audit: references appear alongside other credentials but are type-labeled as passkeys.
- Delete reference: removes SentinelPass metadata only; it does not delete the platform passkey unless a future platform API supports an explicit delete action.

Future user flows:

- Launch platform sign-in: SentinelPass can open the RP URL or invoke an app flow that relies on WebAuthn / AuthenticationServices.
- Import/export metadata: only metadata moves unless FIDO Credential Exchange support is explicitly implemented.
- Credential provider mode: a separate architecture may allow SentinelPass to act as a platform credential provider, subject to stronger security gates.

## Platform Strategy

macOS and iOS:

- Prefer AuthenticationServices for app/browser-compatible passkey registration and assertion flows.
- Require associated domains where the platform requires them.
- Keep private key custody in iCloud Keychain or platform authenticators unless SentinelPass becomes an approved credential provider.

Windows:

- Prefer Windows Hello and platform WebAuthn APIs for assertion flows.
- Store only metadata/reference records in SentinelPass until a Windows credential-provider design exists.

Browser extension:

- Treat passkey references as metadata for discovery and launch, not autofillable passwords.
- Do not inject passkey private material into pages.
- Keep extension sender/domain validation as a prerequisite for any passkey handoff.

Interchange:

- Evaluate FIDO Credential Exchange before any import/export of passkey material.
- Metadata-only import/export may happen earlier if it cannot be confused with private key export.

## Security Constraints

- SentinelPass does not store passkey private keys in generic vault entries.
- All passkey operations must preserve WebAuthn origin/RP ID scoping.
- User verification must remain platform/authenticator enforced.
- `passkey_reference` data must be clearly labeled to prevent users from treating it as a recoverable private key backup.
- Sync may carry metadata references, but must not carry raw passkey private keys.
- Audit logs should distinguish viewing a passkey reference from performing a passkey assertion.
- Any future credential-provider mode must define key custody, biometric gating, export semantics, and recovery behavior before code lands.

## Implementation Phases

1. Metadata foundation: keep `passkey_reference` as a typed credential and add dedicated metadata fields/table when needed.
2. Product surfaces: add UI/CLI display and creation flows that clearly label references as metadata-only.
3. Platform handoff: integrate with AuthenticationServices, WebAuthn, or Windows platform APIs only for flows where SentinelPass is not taking private key custody.
4. Interoperability evaluation: evaluate FIDO Credential Exchange for standards-aligned import/export.
5. Credential provider evaluation: decide whether SentinelPass should become a credential provider; if yes, produce a separate security architecture before implementation.

## Acceptance Gates

Before any passkey implementation beyond metadata/reference storage:

- Product copy states that `passkey_reference` is metadata only.
- Tests prove passkey references are not returned by password-only secret lookup flows. Current daemon coverage gates `GetCredential`, authorized `GetExternalSecret`, and fillable domain credential listing to password/API-key entries only.
- Import/export tests prevent passkey references from being serialized as generic password backups unless explicitly metadata-only. Current JSON, CSV, and KeePass password-backup exports exclude `passkey_reference` entries.
- Platform integration has origin/RP ID validation tests.
- Security review confirms no raw passkey private key material is stored in generic vault entries.
- `docs/SECURITY_STATUS_MATRIX.md` is updated with the implemented status and residual risks.

## Open Questions

- Should SentinelPass expose a dedicated passkey metadata table instead of storing reference data in the existing secret field?
- Which platforms should be first for launch handoff: macOS/iOS AuthenticationServices or browser extension discovery?
- What UI language best prevents confusing passkey references with passkey backups?
- Should metadata-only passkey references sync by default, or require opt-in because they reveal account/RP relationships?
