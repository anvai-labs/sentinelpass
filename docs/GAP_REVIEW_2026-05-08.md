# SentinelPass Gap Review (2026-05-08)

## Scope

This review covers product vision, architecture, feature set, security design, implementation maturity, Victor integration, and passkey/biometric opportunities. It builds on `docs/GAP_REVIEW_2026-02-26.md` and reflects the current workspace state.

## Executive Summary

SentinelPass has a credible local-first foundation: Rust core, encrypted vault, daemon/native-host path, TOTP, SSH keys, optional sync relay, mobile bridge scaffolding, and biometric unlock. The next leverage points are not more surfaces; they are tighter trust boundaries, clearer secret access contracts, and reducing gaps between documentation claims and implemented controls.

The most valuable near-term addition is an external-tool secret retrieval contract for developer workflows. `victor auth` should be able to ask SentinelPass for one named provider key, with daemon unlock state and optional biometric unlock handling, without reading the vault file or managing plaintext key storage itself.

## What Is Strong

- Local-first architecture remains the right product center of gravity.
- CLI, daemon, native host, desktop UI, extension, relay, and mobile bridge are already separated into coherent crates/directories.
- Core vault encryption, TOTP, SSH key storage, password health, imports/exports, and sync primitives are present.
- Daemon IPC now has a useful shape for external consumers: a single process can hold the unlocked vault and answer constrained requests.
- The docs already contain evidence-based planning artifacts instead of only aspirational roadmap text.

## Top Improvement Areas

## 1. External Secret Access Needs a First-Class Contract

### Gap

Developer tools currently use environment variables, local config files, or OS keyring directly. That splits secret storage between Victor and SentinelPass and makes SentinelPass less useful as a developer credential hub.

### Recommendation

Treat SentinelPass as a local secrets broker for developer tools:

- Store provider keys as normal vault credentials, for example `url=anthropic` or `url=api.anthropic.com`, `username=ANTHROPIC_API_KEY`, `password=<key>`.
- Use daemon-mediated retrieval for automation, not direct vault DB reads.
- Require an unlocked daemon or explicit biometric unlock.
- Return one requested field only.
- Audit secret access separately from browser autofill.

### Current implementation step

`sentinelpass secret-get --domain <domain> --field password [--biometric-unlock]` now provides a narrow CLI contract Victor can call.

`../codingagent` now has an opt-in SentinelPass resolver path and `victor auth add --source sentinelpass`, storing the SentinelPass lookup reference rather than the API key.

Suggested Victor resolution order:

1. Environment variable.
2. SentinelPass, if enabled in Victor config.
3. Victor keyring.
4. Victor file fallback.

## 2. Biometric Unlock Should Continue Moving Toward Platform-Native Key Wrapping

### Current State

The biometric unlock path no longer stores the master password as the long-term secret. Enrollment validates the supplied master password, unwraps the vault DEK, and stores DEK material behind the OS keyring reference used for biometric unlock. Biometric unlock retrieves the DEK and unlocks the in-memory key hierarchy without re-deriving from or exposing the master password.

### Remaining Gap

The remaining gap is moving from generic keyring-backed DEK storage to a stricter platform-native key hierarchy:

- macOS: Keychain item or Secure Enclave-backed key with `SecAccessControl` requiring Touch ID / device owner authentication.
- Windows: DPAPI or Windows Hello-protected key material.
- Store only a wrapped vault DEK or key-encryption-key reference where the platform supports non-exportable material.
- Invalidate biometric unlock when biometric enrollment changes where the platform supports that policy.

This is now a defense-in-depth hardening item rather than a master-password exposure blocker.

## 3. Passkeys Are a Product Opportunity, But Not a Simple "Store Password Field" Feature

### Constraint

Passkeys are WebAuthn/FIDO credentials. A relying party stores the public key, while the private key remains in an authenticator and signs server challenges scoped to the relying party origin. SentinelPass should not model passkeys as decryptable password strings.

### macOS path

The practical macOS strategy is phased:

- Phase 1: Document passkey metadata only: relying party ID, account label, credential ID, creation time, sync source, and notes.
- Phase 2: Integrate with system passkeys via AuthenticationServices where SentinelPass is acting in an app/browser-compatible flow.
- Phase 3: Evaluate credential provider extension support and emerging FIDO Credential Exchange Format / Protocol for import/export.
- Phase 4: If SentinelPass becomes a credential provider, store passkey private material only in a platform-authenticator-compatible, biometric-gated storage path.

Do not implement a custom passkey vault format until the product has a clear authenticator/provider boundary and interoperability story.

## 4. Architecture Should Separate Credential Types Explicitly

### Gap

Passwords, TOTP, SSH keys, sync device keys, API keys, and future passkeys have different lifecycle and access rules. Today, API keys can fit into generic entries, but that is implicit.

### Recommendation

Add a typed credential model:

- `password`: website/app login.
- `api_key`: provider/service key, CLI-safe lookup, optional environment variable alias.
- `totp`: attached second factor.
- `ssh_key`: agent-loadable private key.
- `passkey_reference`: metadata/reference to platform credential, not raw private key.
- `sync_device_key`: internal-only, never user-exported as a generic secret.

Typed credentials would let UI, CLI, extension, and external tools enforce different access policies without guessing from title/URL conventions.

## 5. Documentation Claims Need Code-Linked Status

### Gap

Some security docs still mix implemented controls with target-state controls. This is high-risk for a password manager because users will reasonably treat docs as security claims.

### Recommendation

Add `docs/SECURITY_STATUS_MATRIX.md` with rows for each control:

- status: Implemented, Partial, Planned.
- code location.
- test location.
- residual risk.
- next action.

Priority controls to status-label:

- biometric storage model,
- memory locking / zeroization claims,
- Windows IPC named pipes and ACLs,
- extension sender validation,
- relay abuse controls,
- passkey support state.

## 6. Extension and Daemon Permission Model Should Support Non-Browser Clients

### Gap

The daemon IPC model currently assumes browser/native-host use cases. Victor integration introduces a new client class: local developer tools requesting API keys.

### Recommendation

Add client categories and access policy:

- `browser_extension`: domain-scoped credential and TOTP access.
- `desktop_ui`: full user-approved vault operations.
- `cli_user`: direct user invocation.
- `local_tool`: named secret retrieval only, no list-all or bulk export.

For `local_tool`, default to:

- no bulk listing,
- no save/update unless explicitly enabled,
- audit every successful secret read,
- optional allowlist of domains/provider names.

## 7. Product Completeness Remains Secondary to Trust Boundary Closure

### Gaps

- Browser popup parity is still incomplete relative to mature password managers.
- Mobile autofill is scaffolded but not product-complete.
- Import/export breadth can expand.
- Sync UX still needs device-management polish.

### Recommendation

Keep the next product slices small and trust-boundary-aligned:

- API key management for developers.
- Password health local-only.
- Browser popup search/add/settings parity.
- Mobile autofill completion.
- Passkey metadata/reference support before authenticator support.

## Victor Integration Design

## SentinelPass Side

Use:

```bash
sentinelpass secret-get --domain anthropic --field password
sentinelpass secret-get --domain anthropic --field password --biometric-unlock
```

Expected behavior:

- Connects to the local daemon via the existing IPC token and socket.
- Fails if the daemon is locked unless `--biometric-unlock` is supplied.
- Prints only the requested field to stdout.
- Does not prompt for the master password.
- Emits daemon audit events for credential secret lookup and biometric unlock attempts.

Recommended future additions:

- `--purpose victor-auth` for audit labeling.
- `--client-id victor` and a local client allowlist.
- `secret allow victor --domain anthropic --field password` for least-privilege authorization.
- JSON output only when needed; plaintext stdout is useful for shell integration but should be opt-in in docs.

## Victor Side

Implemented in `../codingagent/victor/providers/resolution.py`:

- Adds a SentinelPass backend after env vars and before Victor keyring/file fallback.
- Supports `VICTOR_SENTINELPASS_ENABLED=true`.
- Supports provider-specific domain overrides through `VICTOR_SENTINELPASS_DOMAIN_<PROVIDER>`.
- Invokes `sentinelpass secret-get --domain <domain> --field password`.
- Never log stdout or command details containing returned values.
- Cache only in memory for the current process, using existing secret masking.

Implemented in `../codingagent/victor/ui/commands/auth.py` and account config:

- Adds `--source sentinelpass` to `victor auth add`.
- Adds `--sentinelpass-domain` for explicit lookup naming.
- Stores only the SentinelPass lookup reference in Victor config, not the API key.

## Passkey Direction

Relevant platform facts:

- Apple passkeys use iCloud Keychain public-key credentials; private keys remain with the authenticator and authentication is authorized with Touch ID, Face ID, passcode, or macOS confirmation.
- Apple apps need associated domains for direct passkey registration/assertion requests.
- Browser-app passkey flows use AuthenticationServices / WebAuthn request handling.
- FIDO Credential Exchange Format and Protocol are the right import/export standards to track for password-manager portability.

Decision:

- Do not store passkeys as generic encrypted text secrets.
- Add `passkey_reference` metadata first.
- Consider raw passkey custody only after a credential-provider architecture exists.

References:

- Apple AuthenticationServices passkeys: https://developer.apple.com/documentation/authenticationservices/supporting-passkeys
- Apple passkeys in browser apps: https://developer.apple.com/documentation/authenticationservices/authenticating-people-by-using-passkeys-in-browser-apps
- Apple AuthenticationServices updates, including passkey PRF and credential provider notes: https://developer.apple.com/documentation/updates/authenticationservices
- MDN passkeys / WebAuthn overview: https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys
- FIDO Credential Exchange Format: https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html

## Recommended Next 30 Days

1. Add `api_key` and `passkey_reference` credential types to the schema/model.
2. Create `docs/SECURITY_STATUS_MATRIX.md`.
3. Add passkey product design doc before implementation.
4. Add platform-native biometric DEK wrapping and biometric-enrollment invalidation where supported.
5. Add least-privilege local-tool authorization, for example `secret allow victor --domain anthropic`.
6. Add broader integration tests covering daemon startup plus Victor SentinelPass lookup.
