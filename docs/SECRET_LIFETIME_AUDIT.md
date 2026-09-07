# Secret Lifetime Audit — WBS-308 (SR-CRYPTO-004 / TD-ROB-08 second half)

**Status:** delivered in the WBS-308 pass (branch `feat/envelope-v2-adoption` line).
**Acceptance (WBS):** P — this table, committed. N — no owned secret buffer in
crypto/KDF intermediate paths or new paths left without a zeroizing type.

**Method:** every owned secret-bearing type in the scoped areas was traced from
creation to last consumption. "Zeroized?" answers whether the buffer's memory
is wiped when the owning value is dropped (or explicitly before an error
return), not whether the value is encrypted at rest — all values here are
plaintext-in-memory by design while the vault is unlocked.

**Policy baseline (CLAUDE.md):** owned secret buffers use `Zeroizing`;
borrowed `&[u8]`/`&str` are the caller's responsibility. `mlock`/`memsec` was
removed deliberately — NOTHING in this table claims swap or memory-locking
protection. `Zeroizing` defends heap buffers on drop; it cannot chase compiler
temporaries or stack copies, and it is best-effort defense-in-depth, not a
guarantee against a compromised process.

Legend: **YES** = zeroized on drop; **NO** = dropped unzeroized;
**PARTIAL** = zeroized on some paths only; **N/A** = not secret material
(ciphertext, salt, identity metadata).

---

## 1. Core crypto — `crypto/kdf.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `Vec<u8>` Argon2 output intermediate (`hash_bytes`) | `derive_master_key` (argon2 `hash_password` output) | copied into the returned `[u8; 32]` | was **NO** — dropped unzeroized (TD-ROB-08) | **FIXED**: `Zeroizing<Vec<u8>>` |
| `argon2::PasswordHash` / `password_hash::Output` | `derive_master_key` | internal `Output` holds the same 32 bytes | **NO** — upstream type, no mutable access to its internal buffer | **Follow-up FU-01** (upstream `password-hash` crate); stack-lifetime only |
| `[u8; 32]` `derived_key` in `verify_master_password` | `derive_master_key` | `ct_eq` against expected key | was **NO** — lived past the comparison on both return paths | **FIXED**: explicit `.zeroize()` before both returns |
| `[u8; 32]` return of `derive_master_key` (public API) | `derive_master_key` | every in-repo caller wraps it into `MasterKey` (ZeroizeOnDrop) immediately | **PARTIAL** — safe in-repo; a bare array is a leaky public shape | **Follow-up FU-02** (public API shape change) |
| `KdfParams.salt`, `SaltString` | vault metadata / RNG | Argon2 input | **N/A** — salt is not secret | — |
| `password: &[u8]` parameters | caller | borrowed | **N/A** — caller-owned per policy | — |

## 2. Core crypto — `crypto/keyring.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `MasterKey.key: [u8; 32]` | `MasterKey::from_bytes` (unlock/initialize/rotation) | DEK wrap/unwrap | **YES** (`#[derive(ZeroizeOnDrop)]`, pre-existing) | — |
| `DataEncryptionKey.key: [u8; 32]` | `DataEncryptionKey::new` / `from_bytes` / unwrap | all entry encryption | **YES** (`Drop` impl; `from_bytes` zeroes the caller's buffer; `into_bytes` returns `Zeroizing`, pre-existing) | — |
| `Vec<u8>` `dek_bytes` — unwrapped DEK plaintext | `unwrap_dek_under_key` (GCM decrypt) | copied into `[u8; 32]` → `DataEncryptionKey::from_bytes` | was **NO** — `Vec::try_into([u8; 32])` copies and drops the buffer unzeroized, including on the length-error path | **FIXED**: `Zeroizing<Vec<u8>>` + explicit `copy_from_slice`; `from_bytes` zeroes the stack array |
| `ciphertext_with_tag`, `wrapped_dek` | unwrap/wrap paths | GCM input/output | **N/A** — ciphertext | — |
| `Zeroizing<Vec<u8>>` registry equality key | `derive_equality_key` (HKDF over DEK) | registry tags | **YES** (pre-existing) | — |

## 3. Core crypto — `crypto/cipher.rs` (v1 field encryption, still the dual-read path)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `decrypt_entry` return: `Vec<u8>` | GCM decrypt of any v1 field | vault field opens, SSH/TOTP decrypt | was **NO** — owned plaintext dropped unzeroized at the caller | **FIXED**: returns `Zeroizing<Vec<u8>>` |
| `decrypt_to_string` return: `String` | `decrypt_entry` + UTF-8 | legacy field opens | was **NO** | **FIXED**: returns `Zeroizing<String>` (byte copy is moved into the String; guarded original zeroized) |
| `ciphertext`, `ciphertext_only`, `ciphertext_with_tag` locals | encrypt/decrypt | GCM | **N/A** — ciphertext | — |
| `encrypt_entry`/`encrypt_string` `plaintext` parameters | caller | borrowed | **N/A** — caller-owned | — |

## 4. Core crypto — `crypto/envelope.rs` (v2 envelopes)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `open_envelope` / `open_envelope_relaxed_epoch` return | GCM open | all v2 field opens | **YES** — pre-existing `Zeroizing<Vec<u8>>`; now pinned by a type-guard test (`open_envelope_returns_zeroizing_plaintext`) | — |
| `ct_with_tag`, `ct`, `nonce_vec`, `tag` locals | decode/open | GCM | **N/A** — ciphertext | — |
| `seal_envelope` plaintext parameter | caller | borrowed | **N/A** | — |

## 5. Core crypto — `crypto/aad.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `AadContext`, `to_bytes() -> Vec<u8>` | builders at seal/open | GCM associated data | **N/A** — vault/object UUIDs, purposes, versions, epochs: identity metadata, not secret | — |

## 6. Recovery — `vault/recovery.rs` (WBS-309/310 recovery key + unwrap input)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `RecoveryKey.bytes: [u8; 32]` | `generate` / `from_bytes` (parse) | recovery-slot key wrap | **YES** (pre-existing `Zeroizing`) | — |
| `to_display_string` return | derived from `bytes` | shown once to user | **YES** (pre-existing `Zeroizing<String>`) | — |
| `normalized: Vec<u8>` display-symbol buffer | `parse_recovery_key` | symbol decode | was **NO** — the display form IS the key material (module docs) | **FIXED**: `Zeroizing<Vec<u8>>` |
| `values: [u8; 54]` 5-bit symbol slices | `parse_recovery_key` | body reconstruction | was **NO** (plain stack array dropped unzeroized, incl. on three error paths) | **FIXED**: explicit `.zeroize()` before every return |
| `bytes: [u8; 32]` reconstructed body | `parse_recovery_key` | checksum verify; wrapped into `RecoveryKey` | was **PARTIAL** (unzeroized on the checksum-mismatch return) | **FIXED**: zeroized on the error path; success path moves into the `Zeroizing` struct |

## 7. TOTP — `totp.rs` and `vault/totp_ops.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `decrypt_totp_secret` return: `String` seed | `decrypt_to_string` + normalize | code generation, sync payload build | was **NO** (prior-review finding) | **FIXED**: returns `Zeroizing<String>`; type-guard test added |
| `normalize_secret` return: `String` | trim/normalize | encrypt/decrypt paths | was **NO** | **FIXED**: returns `Zeroizing<String>` |
| `decode_secret` return: raw decoded seed bytes | base32 decode | HMAC key in `generate_totp_code` | was **NO** — raw HMAC entropy dropped unzeroized | **FIXED**: returns `Zeroizing<Vec<u8>>` |
| `ParsedTotpUri.secret_base32: String` | `parse_otpauth_uri` | UI (`sentinelpass-ui`) and CLI totp-add | **NO** — public field shape consumed cross-crate; transient (parse → encrypt immediately) | **Follow-up FU-05**; explicit boundary conversion inside `parse_otpauth_uri` |
| `digest` (HMAC output) in `generate_totp_code` | HMAC over counter | truncated into 6/8-digit code | **NO** — accepted: short-lived derivative, value shrinks to the displayed code | documented residual |
| `encrypt_totp_secret` plaintext parameter | caller | borrowed | **N/A** | — |

## 8. SSH — `ssh.rs` and `vault/ssh_ops.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `decrypt_private_key` return: PEM `String` | v1 GCM decrypt | sync payloads, re-seal, export | was **NO** (prior-review finding, analogous to TOTP) | **FIXED**: returns `Zeroizing<String>` |
| `export_ssh_private_key` return: `String` | dual-read open | CLI output path (user-requested export) | **NO at the boundary** — deliberate: the export consumer owns the plaintext from there; all internal intermediates are now zeroized | documented boundary; CLI-side handling in **FU-04** |
| `SshKey.create_encrypted` `private_key: String` parameter | caller | encrypted immediately | **N/A** — caller-owned input (policy) | — |
| `SshKeyPayload.private_key` (sync) | sync payload build | DEK-encrypted transport | **YES** (pre-existing `Zeroizing<String>` + hand-redacted `Debug`) | — |

## 9. Vault paths — `vault/mod.rs` entry field handling

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `Entry.password: Zeroizing<String>` | `open_entry_field` (dual-read open) | CLI/UI display, IPC responses, native messaging | **YES** (pre-existing) — BUT the derived `Debug` printed it (`Zeroizing`'s `Debug` is transparent and emits the inner string) | **FIXED**: hand-written redacted `Debug` (`[REDACTED]`), regression test `entry_debug_never_contains_the_password` |
| `Entry.title` / `username` / `url` | field opens | UI/CLI | **NO** — identity metadata; needed unredacted for debugging; documented choice | — |
| `Entry.notes: Option<String>` | field open | UI/CLI | **NO** — user free text that MAY embed secrets; redacting would change existing debug/display behavior | **Follow-up FU-03** (product decision) |
| `open_object_field` / `open_entry_field*` returns | v2 envelope open + v1 fallback | all vault/sync field consumers | **YES** (`Zeroizing<String>`; the v1 branch now returns the zeroizing buffer directly instead of re-wrapping) | — |
| seal-path plaintexts (`seal_entry_fields` input) | `Entry` fields (borrowed) | GCM seal | **N/A** — borrowed | — |

## 10. Sync payloads — `sync/models.rs`, `sync/crypto.rs`, `sync/change_tracker.rs`, `sync/engine.rs`, `sync/device.rs`

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `CredentialPayload.password: String` | push collector / pull apply | re-seal, registry equality, transport | was **NO** (prior-review finding) AND derived `Debug` printed it | **FIXED**: `Zeroizing<String>` + hand-written redacted `Debug`; wire shape pinned byte-compatible by `credential_password_serializes_as_plain_wire_string` (v0.8.x peers unaffected) |
| `CredentialPayload.title` / `username` / `url` | push collector | transport | **NO** — identity metadata; documented choice (same rationale as §9) | — |
| `CredentialPayload.notes` | push collector | transport | **NO** — may embed secrets | **Follow-up FU-03** |
| `SshKeyPayload.private_key`, `TotpPayload.secret` | sync collectors | transport | **YES** (pre-existing `Zeroizing` + redacted `Debug`) | — |
| `decrypt_from_sync` return: full payload JSON | `encrypt_for_sync` counterpart | payload deserialization (credential/SSH/TOTP/device key/bootstrap) | was **NO** — owned plaintext JSON (contains the password) dropped unzeroized | **FIXED**: returns `Zeroizing<Vec<u8>>` |
| `unpad_payload` return | padding strip | payload decode | was **NO** | **FIXED**: returns `Zeroizing<Vec<u8>>` |
| `payload_json` locals in the three change_tracker collectors | `serde_json::to_vec(payload)` | `encrypt_for_sync` | was **NO** — plaintext (password/PEM/seed) held in the clear until encryption | **FIXED**: wrapped in `Zeroizing` |
| `resolve_sync_secret` v1-decryptor closures | engine apply paths | legacy-triplet fallback | was `Result<String>` (unguarded) | **FIXED**: closure type now `Result<Zeroizing<String>>` |
| `signing_key_bytes` (Ed25519 seed) in `device.rs` | `decrypt_from_sync` | `try_into` `[u8; 32]` → `SigningKey` | was **NO** — buffer dropped unzeroized after the copy | **FIXED** (via `Zeroizing` return + explicit slice copy) |
| `SyncEntryBlob.encrypted_payload`, tombstone JSON | collectors | transport | **N/A** — ciphertext | — |
| `VaultBootstrap.kdf_params_blob` / `wrapped_dek_blob` | pairing export | pairing key decryption | **N/A** — KDF params + ciphertext wrapped under the master key (salt inside is not secret) | — |

## 11. Daemon / IPC secret transit (audit + follow-ups; protocol shapes are out of scope for this pass)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `daemon/ipc/server.rs` unlock master password | IPC request | `vault.unlock` | **YES** (pre-existing `zeroize()` after use) | — |
| `vault_state::CredentialResponse.password: String` (incl. the external-secret `value` path) | `get_credential` — `entry.password.as_str().to_string()` | IPC + external-secret responses | **NO** — plain `String` projection of the zeroizing `Entry.password` | **Follow-up FU-06** |
| `sentinelpass-protocol` `IpcMessage::GetCredentialResponse { password: Option<String> }` (and sibling variants) | daemon | serialization to host/UI | **NO** — wire protocol structs; `Zeroizing<String>` would serialize identically but the change ripples through host/daemon/UI crates | **Follow-up FU-06** (wire-adjacent; coordinated change) |
| `daemon/native_messaging.rs` `SaveCredential.password: String`, response payloads | browser request/response | length-prefixed JSON stdio | **NO** — protocol structs + JSON serialization copies | **Follow-up FU-06** |
| `daemon/vault_state.rs` `entry.password.as_str().to_string()` into native-messaging responses | entry read | browser autofill response | **NO** — transient plain `String` copy per response | **Follow-up FU-06** |

## 12. Biometric wrapper — `biometric.rs` (+ `vault/biometric_ops.rs` consumers)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| Windows store path `encoded` (base64 DEK) | `encode_vault_dek` | `keyring.set_password` | **YES** (pre-existing zeroize on the store path) | — |
| Windows load path `encoded` | `keyring.get_password` | `decode_vault_dek` | was **PARTIAL** — the `?` on decode returned BEFORE `encoded.zeroize()`, leaking the base64 DEK on the decode-failure path | **FIXED**: decode result captured, buffer zeroized on both paths |
| `decode_vault_dek_bytes` `decoded: Vec<u8>` | base64 decode (Windows) / CFData copy (macOS) | `[u8; 32]` → `DataEncryptionKey` | was **NO** — `try_into` dropped the buffer unzeroized; error path also leaked | **FIXED**: explicit length check + `copy_from_slice` + zeroize on both paths |
| macOS keychain `CFData` buffer | Security.framework | `data.bytes().to_vec()` (now zeroized downstream) | **PARTIAL** — the CFData copy handed to Rust is now zeroized; the framework-side buffer is outside Rust's control | FFI internals are a separate WP — **FU-07** |

## 13. Registry equality tags (Supervisor B's area — read-only reference here)

| Type | Created | Consumed | Zeroized? | Action |
|---|---|---|---|---|
| `registry::deserialize_tag_cipher` return: tag hex `String` | `decrypt_to_string` | posture aggregation | was unguarded end-to-end; the decrypt boundary is now `Zeroizing`, this function explicitly unguards to keep the registry API shapes untouched (one-line compile adaptation) | **Follow-up FU-08** (registry stream owns widening) |

---

## Verification for the "N" criterion (automated evidence)

- `cipher.rs::decrypt_boundaries_return_zeroizing_buffers` — type-shape guard for `decrypt_entry`/`decrypt_to_string`.
- `envelope.rs::open_envelope_returns_zeroizing_plaintext` — type-shape guard for both epoch modes.
- `totp.rs::decrypted_totp_seed_is_zeroizing` — type-shape guard for `decrypt_totp_secret`.
- `vault/tests.rs::entry_password_field_is_zeroizing` — type-shape guard on `Entry.password`.
- `vault/tests.rs::entry_debug_never_contains_the_password` — redaction regression guard.
- `sync/models.rs::credential_payload_debug_redacts_password` — redaction regression guard.
- `sync/models.rs::credential_password_serializes_as_plain_wire_string` — pins that `Zeroizing<String>` emits the byte-identical v0.8.x wire shape (both directions).

## Follow-up tickets

| ID | Area | Description |
|---|---|---|
| FU-01 | upstream `password-hash` | `argon2::PasswordHash`'s `Output` buffer cannot be zeroized from outside the crate (no mutable access). Track upstream or vendor a zeroizing wrapper if the exposure is judged material. Stack-lifetime only today. |
| FU-02 | `crypto/kdf.rs` public API | `derive_master_key` returns a bare `[u8; 32]`. Widening to a guarded type (or returning `MasterKey`) is a public API change across crates. All current callers wrap immediately. |
| FU-03 | `Entry.notes`, `CredentialPayload.notes` | Notes are user free text that may embed secrets. Decide product behavior (redact in `Debug`? zeroizing type?) — display/debug flows depend on it today. |
| FU-04 | CLI / `export_ssh_private_key` | Export hands a plain `String` to the output path by design (user-requested export). CLI-side handling (prompt, file mode bits) should be reviewed as part of export hardening. |
| FU-05 | `ParsedTotpUri.secret_base32` | Public field is `String`; consumed by UI (`src-tauri/main.rs`) and CLI (`commands/totp.rs`). Widen to `Zeroizing<String>` in a coordinated API-shape change. |
| FU-06 | daemon/native-messaging/protocol | `IpcMessage` response variants, native-messaging request/response structs, and the `vault_state.rs` response assembly all move secrets as plain `String` before JSON serialization. `Zeroizing<String>` serializes identically; the change spans sentinelpass-protocol, daemon, host, and UI and must be coordinated (wire-compatible). |
| FU-07 | biometric FFI internals | macOS Security.framework `CFData` and Windows keyring-side buffers are outside Rust's zeroization reach; the Rust-side copies are covered. Track under the FFI/mobile WPs. |
| FU-08 | registry (ADR-001) | Equality-tag hex strings are unguarded after `deserialize_tag_cipher`; the registry stream should widen the return type when convenient (boundary conversion is explicit today). |

## Explicitly out of scope (unchanged by this pass)

- Wire formats, database schemas, envelope documents (other streams).
- FFI/mobile internals (separate WPs).
- `import_export.rs` plaintext assembly (not in the WBS-308 scope list; its
  outputs are user-requested exports — recommend a future audit row).
- Swap/memory-locking protections: `mlock`/`memsec` was removed deliberately;
  nothing here claims residual-memory immunity beyond `Drop`-time zeroization.
