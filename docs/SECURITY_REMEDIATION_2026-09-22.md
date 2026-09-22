# At-rest security remediation — 2026-09-22

This change addresses the findings from the local encryption review. It is not an independent cryptographic audit or a claim that arbitrary vulnerabilities have been eliminated. Validation uses synthetic vaults; it does not unlock, rekey, or modify an installed user vault.

## Corrected security claims

The SQLite container is readable. Sensitive entry columns carry individual AES-256-GCM envelopes, with fresh random 96-bit nonces and 128-bit tags. A vault has one DEK, wrapped by an Argon2id-derived master key; entry keys are not independently derived. Password rotation rewraps that same DEK. Random nonce collision probability is nonzero; different AAD does not make reuse safe. Absence of two chosen canary strings is evidence about those strings, not proof that every secret or artifact is encrypted.

The previous summary/secret purposes permitted substitutions between fields in the same class. Schema 2 assigns each of title, username, password, URL and notes its own authenticated purpose. TOTP issuer/account metadata has distinct purposes too; the upgrade seals legacy plaintext metadata and verifies it before activation. Legacy coarse-purpose envelopes and bincode rows are accepted by the migration reader only; ordinary entry reads require column binding. Vault format 3 gates older readers. The SPENV document version remains 2; these version numbers serve different purposes. Unknown AAD context keys are rejected.

## Freshness and durability

`vault.db.contents` authenticates the active entry set and each entry's encrypted fields, identity, type, timestamps and favorite flag with an HKDF-separated HMAC key. NULL and empty optional values differ. A write holds a receipt-file lock and a SQLite immediate transaction, authenticates the old state, durably records old/new candidate snapshots, commits SQLite with synchronous FULL, then durably acknowledges the new receipt. Crash recovery accepts only the complete old or new transaction. Acknowledged updates reject older valid ciphertext and whole-row replay. Normal entry reads, registry reads, outgoing credential sync, backup snapshots and rekey snapshots verify receipts.

Keep `.contents` with the database. A missing or forged receipt after enrollment fails closed; use authenticated backup restore to deliberately reset freshness. Backup bundles authenticate their contained snapshot and supervised restore rebaselines receipts. The first upgrade of a legacy vault establishes a trust-on-first-use baseline; it cannot retroactively detect preexisting replay. In-memory databases have no external receipt. This mechanism protects entry rows, not every SQLite table. Coordinated rollback/removal of the database and its external security state is not prevented by a local sidecar. Strong protection against an attacker controlling all user files requires a trusted monotonic hardware/service anchor. Epoch sidecars retain their separate key-slot rollback role. Empty-vault pairing publishes a receipt authenticated by both the old and incoming DEKs before committing key adoption; either crash outcome remains readable, and the next ordinary commit removes the old MAC. Nonempty vaults cannot use this handoff.

## Compromise recovery

`sentinelpass --vault <source> rekey --output-dir <new-directory>` creates a replacement vault under a newly prompted master password and fresh random DEK. The output directory must not exist. The operation authenticates the source, copies it, re-encrypts entries, SSH private keys/comments, TOTP secrets/metadata, registry entities/membership labels and domain mappings, verifies the replacement, rebuilds DEK-derived indexes, and compacts it before publication. Unresolved sync conflicts/dead letters block rekey. The source remains available.

The replacement has a new vault identity, password slot and epoch. Recovery slots, biometrics and sync devices must be enrolled again. Point clients at the replacement only after verifying its contents. Old backups and retained source files still contain old-key ciphertext. Rekey cannot revoke data already read by an attacker; rotate exposed credentials at their providers. File deletion/compaction is not a guarantee of physical SSD or snapshot erasure.

## Diagnostics and memory

Credential diagnostics in the daemon/native messaging boundary no longer emit domains, usernames, credentials, client-supplied triggers or error text containing request values. A captured-tracing regression checks canaries at all levels. Existing diagnostic logs are not rewritten; handle them as sensitive metadata and expire them according to retention policy. Structured security audit tokens retain their existing keyed design.

Argon2 uses explicitly zeroizing work memory, derived output and temporary master-key buffers, preserving the historical derivation for all supported output lengths. Export/import buffers and exported passwords have shorter guarded lifetimes. Desktop/CLI/daemon/native-host startup disables Unix core dumps; Linux also disables process dumpability. The helper is a no-op on Windows. These controls do not establish universal memory safety: keys are not page-locked, swap/hibernation and privileged process inspection remain risks, and UI/mobile/foreign-runtime copies need separate platform assurance.

SQLite files are created owner-only before SQLite opens them; its Unix VFS inherits those permissions for WAL/SHM. Socket creation relies on its verified 0700 parent and explicit 0600 socket mode. Neither path temporarily changes the process-wide umask, avoiding cross-thread permission races.

## API key entries

Username is optional. Missing usernames deserialize to empty strings in core/service/import DTOs. JSON exports retain credential type, so an API key does not become a password entry during round-trip. The existing UI and CLI optional-username behavior is retained.

## Regression evidence

Tests exercise all directed entry-field substitutions, unknown identity keys, legacy migration, acknowledged replay, NULL/empty/deletion tampering, forged/missing receipts, old/new crash recovery, authenticated backup restore, fresh-DEK recovery, KDF byte compatibility, request-log canaries, Unix dump limits, and API-key username omission. Validation commands: `cargo test --workspace --all-features --release -- --test-threads=4`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, `npm run web:typecheck`, and `npm run test:ts`. Cross-platform runtime behavior and an independent security review remain release-assurance work.

Validation result on the development macOS host: the full Rust workspace suite passed (772 core tests), all 121 TypeScript tests passed, and formatting, Clippy with warnings denied, and web type checking passed. Compiler-cache permission failures required an unrestricted test run with `RUSTC_WRAPPER=`; no checks were disabled. Windows/Linux runtime validation is not claimed.
