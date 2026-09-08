# Durable Wire Formats

**Status:** Normative format contract (WBS-305 / SR-CRYPTO-002; ADR-005 rev 4)
**Owner:** security lead + core maintainer
**Rust source of truth:** `sentinelpass-core/src/crypto/dbwire.rs` (KDF/wrap/nonce
documents), `sentinelpass-core/src/crypto/envelope.rs` (SPENV envelope v2),
`sentinelpass-core/src/crypto/aad.rs` (AAD canonical bytes)

This document specifies, at the byte level, every durable serialization a
SentinelPass vault database may contain for key-material metadata: the current
document formats, the authenticated envelope, and the legacy bincode shapes
that older vaults still carry. Any change to a CURRENT format is a new
version, never a silent edit; golden-vector tests pin each format's exact
bytes and any encoder change breaks them by design.

## 0. The canonical JSON profile (applies to every document below)

ADR-005 rev 2 makes "language-neutral and bounded" normative. All documents
in sections 1–2 are UTF-8 JSON obeying ONE profile:

| Rule | Writer contract | Reader enforcement |
|---|---|---|
| Encoding | Compact UTF-8, no whitespace, no BOM | Any JSON-legal whitespace tolerated on read (semantic, not byte, checking) | — READER TOLERANCE BEGINS AFTER THE FIXED MAGIC PREFIX: the first bytes must be the exact canonical magic; canonicalization (whitespace, key order) applies only to the remainder of the document.
| Field order | Declaration order shown in each table (part of the frozen contract) | JSON-object order irrelevant on read |
| Numbers | Integers only, plain decimal spelling | Floats (`3.0`), exponent spellings, and string-typed numbers are REJECTED by the typed decode |
| Binary fields | Standard base64 (`RFC 4648`, `+`/`/`, WITH `=` padding) | URL-safe or unpadded variants are rejected; fixed-size fields get an exact declared-length check BEFORE decoding |
| Object keys | Exactly the keys in the field table, in order | Unknown keys (`deny_unknown_fields`) AND duplicate keys fail structurally (typed-struct decode; never through `serde_json::Value` or any dynamic map) |
| Versioning | `v` field; bump on ANY shape change | Unknown `v` fails closed with a typed `UnsupportedCryptoVersion` error — no downgrade path, no auto-conversion |
| Size bound | Writer output sits far under the cap | Total input capped at **4096 bytes** BEFORE any parse; nesting depth capped at 4 (byte-level pre-scan) |

Writer byte-canonicality is conformance-tested by golden vectors (section 4);
reader acceptance is deliberately STRUCTURAL, not byte-level: these metadata
documents are unauthenticated by design (their integrity is anchored by the
epoch-guard digest and the slot-registry MAC over the stored bytes, and the
wrap's GCM tag is the cryptographic boundary), so a parse-preserving
respelling accepted by a reader is correct behavior, while a writer that
cannot reproduce the golden bytes is non-conformant.

## 1. `db_metadata` key-material documents (current format, since WBS-305)

The `db_metadata` row's three key-material columns — `kdf_params`,
`wrapped_dek`, `dek_nonce` — are written as the documents below by every
writer since WBS-305 (vault create, master-password rotation, pair-join
adoption, recovery rewrap; all encode through `dbwire::encode_metadata_blobs`).
Readers dispatch **per column** on the FULL magic byte prefix:

- blob starts with the column's magic (e.g. `{"magic":"SPKDF"`) → document path;
  any parse/validation failure inside the document path is a typed error with
  NO fallback (a blob that claims the magic is committed to being a document);
- anything else → legacy bincode path (section 3), decoded under the same
  4096-byte limit, so every vault written before the switch stays readable
  forever.

Dispatch never uses a bare leading `{`: a legacy `bincode(KdfParams)` blob
begins with 16 random salt bytes (and a legacy nonce blob with 12 random
nonce bytes), so it starts with `{` (0x7B) with probability ~1/256 — a
first-byte sniff would misroute ~0.4% of real legacy vaults. A random collision
with the full magic prefix is negligible (exact 0 for the 12-byte nonce vs the 18-byte SPNONCE prefix; ~2^-128 for random 16-byte salts vs the 16-byte SPKDF prefix); only a deliberate forgery could
arrange it, and a writer that forges DB rows already controls the vault.
The two encodings may legally coexist across columns and across time (e.g. a
legacy `kdf_params` next to a post-rotation document `wrapped_dek`); each
column dispatches independently.

### 1.1 KDF parameters document — `SPKDF` (`db_metadata.kdf_params`)

Decodes into the in-memory `KdfParams` type (unchanged by the format work).

| # | JSON key | Type | Constraint |
|---|---|---|---|
| 1 | `magic` | string | exactly `"SPKDF"` |
| 2 | `v` | int | exactly `1` (`DBWIRE_VERSION`) |
| 3 | `alg` | string | exactly `"ARGON2ID"` (fail-closed; agility only via a version bump) |
| 4 | `salt` | base64 | exactly 16 raw bytes (24 base64 chars) |
| 5 | `mem_cost` | int (u32) | range-checked at USE, not decode: 64 000..=1 048 576 KiB (SR-CRYPTO-003) |
| 6 | `time_cost` | int (u32) | 1..=20 at use |
| 7 | `parallelism` | int (u32) | 1..=16 at use |
| 8 | `output_length` | int (u32) | 32..=1024 bytes at use |

Golden example (141 bytes exactly; the fixed salt is 16 zero bytes):

```json
{"magic":"SPKDF","v":1,"alg":"ARGON2ID","salt":"AAAAAAAAAAAAAAAAAAAAAA==","mem_cost":262144,"time_cost":3,"parallelism":4,"output_length":32}
```

Deliberate decode/runtime split: decoding is structural; the cost ranges are
enforced by `KdfParams::validate` inside `derive_master_key` (pure integer
comparison before any Argon2 work), exactly as for legacy bincode rows.

### 1.2 Wrapped-DEK document — `SPWRAP` (`db_metadata.wrapped_dek`)

Decodes into the in-memory `WrappedKey` type (unchanged).

| # | JSON key | Type | Constraint |
|---|---|---|---|
| 1 | `magic` | string | exactly `"SPWRAP"` |
| 2 | `v` | int | exactly `1` |
| 3 | `alg` | string | exactly `"A256GCM"` (AES-256-GCM, 96-bit nonce, 128-bit tag) |
| 4 | `wrapped_dek` | base64 | ciphertext (tag EXCLUDED); length-capped at 96 raw bytes (`MAX_WRAPPED_DEK_BYTES`; a 32-byte DEK wraps to exactly 32 bytes of ciphertext) |
| 5 | `nonce` | base64 | exactly 12 raw bytes (16 chars) |
| 6 | `auth_tag` | base64 | exactly 16 raw bytes (24 chars) |
| 7 | `epoch_bound` | boolean | JSON `true`/`false` — the integer `1`/`0` is rejected; `true` means the wrap binds its key epoch as GCM associated data (ADR-002) |

Golden example (185 bytes exactly; deterministic fields):

```json
{"magic":"SPWRAP","v":1,"alg":"A256GCM","wrapped_dek":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=","nonce":"AAECAwQFBgcICQoL","auth_tag":"EREREREREREREREREREREQ==","epoch_bound":true}
```

The wrap's GCM tag authenticates the DEK ciphertext under the master key
(and, when `epoch_bound`, under the epoch); the document wrapper adds no
authentication of its own — see the canonicalization note in section 0.

### 1.3 Standalone DEK-nonce document — `SPNONCE` (`db_metadata.dek_nonce`)

The column mirrors the nonce already inside `WrappedKey` (historical schema
redundancy, kept because the epoch-guard digest and slot mirrors anchor it).

| # | JSON key | Type | Constraint |
|---|---|---|---|
| 1 | `magic` | string | exactly `"SPNONCE"` |
| 2 | `v` | int | exactly `1` |
| 3 | `nonce` | base64 | exactly 12 raw bytes (16 chars) |

Golden example (52 bytes exactly):

```json
{"magic":"SPNONCE","v":1,"nonce":"AAECAwQFBgcICQoL"}
```

### 1.4 Schema interaction

No schema-version bump was needed or made: these columns are opaque BLOBs to
SQLite, dual-read needs no migration, and `CURRENT_SCHEMA_VERSION` is
untouched. A vault written by a pre-WBS-305 binary and a post-WBS-305 binary
differ only in column bytes, readable by the dual dispatch above. A binary
from BEFORE WBS-305 cannot read document columns — expected and desired
(ADR-005: old clients fail loudly, no downgrade path).

## 2. Authenticated envelope v2 — `SPENV` (WBS-304)

Entry/entity/SSH/TOTP field ciphertexts are sealed as SPENV envelope
documents. Full conformance (identity AAD binding, substitution negatives,
caps, golden vector with fixed DEK+nonce) lives in
`sentinelpass-core/src/crypto/envelope.rs` and its tests; this section is a
shape summary for cross-language readers.

Field table (top level, wire order):

| # | JSON key | Type | Constraint |
|---|---|---|---|
| 1 | `magic` | string | exactly `"SPENV"` (byte prefix `{"magic":"SPENV"` pre-scanned) |
| 2 | `envelope_version` | int | exactly `2` |
| 3 | `crypto_version` | int | exactly `1` (`SUPPORTED_CRYPTO_VERSION`); must equal the context's authenticated copy |
| 4 | `alg` | string | exactly `"A256GCM"` |
| 5 | `context` | object | the `AadContext` document (below); its canonical bytes are the GCM AAD |
| 6 | `nonce` | base64 | exactly 12 raw bytes (16 chars) |
| 7 | `ct` | base64 | ciphertext, capped at 3 MiB raw (`MAX_CIPHERTEXT_BYTES`) |
| 8 | `tag` | base64 | exactly 16 raw bytes (24 chars) |

`context` (wire order): `v` (int, `AAD_VERSION`), `vault` (UUID string),
`object` (UUID string), `purpose` (enum string, snake_case:
`summary`|`secret`), `type` (enum string, snake_case:
`password`|`api_key`|`passkey_reference`|`ssh_key`|`totp_secret`|
`registry_entity`|`key_slot`|`domain_mapping`),
`schema_version` (int), `crypto_version` (int), `epoch` (int), `tombstone`
(boolean, present when applicable).

Byte-exact golden vector (fixed DEK + nonce): see the
`golden_vector_byte_exact_with_fixed_nonce_and_key` test in `envelope.rs` —
it is the seal-side parity reference for cross-language implementations.

## 3. Legacy bincode shapes (frozen reference for old vaults)

All shapes below were written by plain `bincode::serialize` — fixed-width
LITTLE-ENDIAN integers, no self-description, no magic. They remain readable
through the dual-read fallbacks and must stay decodable by any future
implementation that claims to open historical vaults.

### 3.1 `bincode(KdfParams)` — 32 bytes

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 16 | `salt` | raw bytes |
| 16 | 4 | `mem_cost` | u32 LE (KiB) |
| 20 | 4 | `time_cost` | u32 LE |
| 24 | 4 | `parallelism` | u32 LE |
| 28 | 4 | `output_length` | u32 LE (bytes) |

### 3.2 `bincode(WrappedKey)` — current 4-field shape, 37+N bytes

| Offset | Size | Field | Encoding |
|---|---|---|---|
| 0 | 8 | `wrapped_dek` length prefix | u64 LE (always 32 for a 32-byte DEK; `N` below) |
| 8 | N | `wrapped_dek` ciphertext (tag excluded) | raw bytes |
| 8+N | 12 | `nonce` | raw bytes |
| 20+N | 16 | `auth_tag` | raw bytes |
| 36+N | 1 | `epoch_bound` | byte `0x00`/`0x01` |

69 bytes for the common 32-byte-DEK case (N=32 → 69 bytes including the
flag). Decode accepts the length prefix only under a 4096-byte size limit
(WBS-307: a hostile prefix must fail cleanly, never allocate).

### 3.3 `bincode(WrappedKey)` — legacy <= v0.8.0 3-field shape, 36+N bytes

Identical to 3.2 without the trailing `epoch_bound` byte; decodes with
`epoch_bound = false` (pre-ADR-002 semantics: no epoch binding in the wrap).

### 3.4 `bincode([u8; 12])` — 12 bytes

The `dek_nonce` column's legacy content: 12 raw nonce bytes, nothing else.

## 4. Deliberately unchanged (scope boundaries)

- **`key_slots` table** — slot rows keep the legacy bincode shapes of
  sections 3.1–3.3 for their `kdf_params` / `wrapped_dek` / `dek_nonce`
  columns. Slot recovery depends on the current shapes; converting them is a
  follow-up format decision that must ship its own versioned migration and
  is NOT covered by the WBS-305 documents. The `db_metadata` writers mirror
  bincode (not documents) into `key_slots` for exactly this reason, and the
  pre-bootstrap byte-mirror invariant keeps working because every
  NULL-MAC vault predates the format switch (both sides bincode).
- **Pairing-bootstrap transport** (`VaultBootstrap.kdf_params_blob` /
  `wrapped_dek_blob`) — stays bincode so an updated origin device cannot
  strand an older joining device. Joiners decode through the bounded
  dual-read decoders, so a future document-emitting transport is accepted
  without a compatibility break; switching the transport is a coordinated
  cross-version follow-up.
- **SPENV-sealed object columns** (entry/entity/SSH/TOTP) — owned by
  envelope v2 (section 2) and its re-encryption workstream, not by WBS-305.

## 5. Golden vectors and negative conformance

Pinned in `sentinelpass-core/src/crypto/dbwire.rs` (`crypto::dbwire::tests`):

- `golden_vector_kdf_document_byte_exact`,
  `golden_vector_wrap_document_byte_exact`,
  `golden_vector_nonce_document_byte_exact` — the section 1 examples above,
  byte-for-byte;
- `writer_is_deterministic_and_epoch_bound_flag_is_wired`,
  `legacy_bincode_blobs_remain_readable`,
  `legacy_three_field_wrap_remains_readable`, `columns_decode_independently_of_each_other`;
- negatives (all typed, all rejected before allocation):
  `oversized_blob_is_rejected_before_parsing`, `truncated_document_is_rejected`,
  `empty_blob_is_rejected`, `unknown_document_version_fails_closed_typed`,
  `wrong_blob_class_is_rejected`, `unknown_top_level_keys_are_rejected`,
  `duplicate_keys_are_rejected_structurally`, `float_integer_fields_are_rejected`,
  `wrong_length_base64_is_rejected_before_decode`, `invalid_base64_and_invalid_utf8_are_rejected`,
  `depth_bomb_is_rejected`, `hostile_legacy_length_prefix_is_rejected_not_allocated`,
  `alg_field_is_fail_closed`, `magic_field_mismatch_is_enforced_post_parse`.

End-to-end adoption evidence (which columns carry which format after each
writer) lives in `sentinelpass-core/src/vault/tests.rs`, module
`wbs305_durable_wire`.

## 6. Portable backup bundle — `SPBACKUP` (WBS-416/417, ADR-008)

**Rust source of truth:** `sentinelpass-core/src/vault/backup_ops.rs`
(bundle container, manifest, MAC), snapshot produced by SQLite
`VACUUM INTO` (a consistent WAL-inclusive read snapshot; standalone
file, no sidecars).

A `.spbackup` bundle is ONE file with THREE consecutive parts:

| Offset | Size | Content |
|---|---|---|
| 0 | 22 | Fixed magic line `SENTINELPASS-BACKUP/1` + `\n` (byte-exact) |
| 22 | variable | Manifest: compact UTF-8 JSON, exactly one line (no interior `\n`), ≤ **16384 bytes** (`MAX_MANIFEST_BYTES`), terminated by `\n` |
| — | exact | Snapshot payload: exactly `manifest.snapshot.len` bytes; the file MUST end there (trailing bytes are rejected) |

Reader bounds run BEFORE any parse/allocation: the manifest line is
rejected past its cap, `snapshot.len` is rejected past **1 GiB**
(`MAX_SNAPSHOT_BYTES`) before the buffer is allocated, and truncation
and trailing bytes are both hard refusals.

### 6.1 Manifest field table (wire order = declaration order)

The manifest obeys the canonical JSON profile (section 0): compact
UTF-8, integers only, standard padded base64 for binary fields, unknown
keys AND duplicate keys rejected structurally, nesting depth ≤ 4, and
the typed version gate — `v` other than `1` fails closed with
`UnsupportedCryptoVersion`. Reader acceptance is structural (not
byte-level); AUTHENTICATION is over field values (below), so a
parse-preserving respelling is still fully authenticated.

| # | JSON key | Type | Constraint |
|---|---|---|---|
| 1 | `magic` | string | exactly `"SPBACKUP"` |
| 2 | `v` | int | exactly `1` (`BACKUP_MANIFEST_VERSION`) |
| 3 | `backup_id` | string | random UUID minted per bundle; the audit trail's opaque reference |
| 4 | `created_at` | int | Unix seconds (creation metadata) |
| 5 | `app_version` | string | creating binary's package version (creation metadata) |
| 6 | `vault_uuid` | string | stable vault identity (WBS-301) |
| 7 | `epoch` | int | master-password key epoch at backup time |
| 8 | `schema_version` | int | snapshot's SQLite schema version |
| 9 | `vault_format_version` | int | snapshot's envelope format (`db_metadata.format_version`) |
| 10 | `entry_count` | int | usable (non-deleted) entry count — visible operational metadata (ADR-008) |
| 11 | `tombstone_count` | int | soft-deleted entry count |
| 12 | `kdf_params` | base64 | EXACT `db_metadata.kdf_params` column bytes (SPKDF document or legacy bincode — decoded at restore through the bounded dual-read decoders of section 1) |
| 13 | `wrapped_dek` | base64 | EXACT `db_metadata.wrapped_dek` column bytes |
| 14 | `dek_nonce` | base64 | EXACT `db_metadata.dek_nonce` column bytes |
| 15 | `slot_registry_mac` | base64 or `null` | EXACT `db_metadata.slot_registry_mac` column bytes; `null` = pre-bootstrap vault |
| 16 | `slots` | array | usable key-slot inventory; each entry: `slot_uuid` (string), `slot_type` (string), `key_epoch` (int), `revoked` (boolean, always `false` in v1 — only usable slots are recorded) |
| 17 | `snapshot` | object | `sha256` (hex, lowercase) and `len` (int bytes) of the payload that follows |
| 18 | `mac` | base64 | HMAC-SHA256 (32 raw bytes) — see 6.2 |

The manifest contains NO plaintext entry content (titles, usernames,
URLs, notes, secrets) — pinned by test.

### 6.2 Bundle MAC

Key: `HKDF-SHA256(DEK, info="sentinelpass-backup-manifest-mac-v1")`,
32 bytes — the key-slot registry MAC precedent (`SLOT_REGISTRY_MAC_INFO`),
key-separated from every other HKDF consumer. Backup therefore requires
the unlocked DEK.

MAC input: every field 1–17 above, in declaration order, each
length-prefixed (`u64` LE length + bytes); array fields feed a `u64`
element count then each element's fields in order. The `mac` field is
never an input. Comparisons are constant-time (`subtle`).

Verification order is normative (ADR-008, fail closed): parse/bounds →
version gate → snapshot SHA-256 digest → Argon2id + unwrap of the
manifest `wrapped_dek` (the password check; `epoch` is the AEAD AAD for
epoch-bound wraps) → MAC verify. NOTHING may touch any vault state
before all of it passes; restore additionally validates a staged copy
(identity, inventory, schema-migration path, registry MAC, full
decryption) before the single-rename swap (WBS-417).

### 6.3 Golden example (shape; `mac`/`snapshot` abbreviated)

```json
{"magic":"SPBACKUP","v":1,"backup_id":"0b9f…","created_at":1789000000,
 "app_version":"0.11.0","vault_uuid":"…","epoch":3,"schema_version":9,
 "vault_format_version":2,"entry_count":42,"tombstone_count":3,
 "kdf_params":"eyJtYWdpYyI6IlNQS0RGI…","wrapped_dek":"eyJtYWdpYyI6IlNQV1JBUC…",
 "dek_nonce":"eyJtYWdpYyI6IlNQTk9OQ0Ui…","slot_registry_mac":"…",
 "slots":[{"slot_uuid":"…","slot_type":"password","key_epoch":3,"revoked":false}],
 "snapshot":{"sha256":"…","len":123456},"mac":"…"}
```

(Shown pretty for readability; the wire form is one compact line.)

### 6.4 Conformance tests

Pinned in `sentinelpass-core/src/vault/backup_ops.rs` (`mod tests`):
layout exactness and no-plaintext-content
(`bundle_layout_is_exact_and_manifest_has_no_plaintext_entry_content`),
MAC determinism + per-field sensitivity
(`manifest_mac_is_deterministic_and_input_sensitive`), key purpose
separation, and negatives: snapshot-byte tamper → digest refusal;
manifest-field tamper → MAC refusal; cross-bundle splice → digest
refusal; truncation; trailing bytes; hostile snapshot length refused
pre-allocation; oversized manifest line; unknown/duplicate keys;
unknown version (typed); wrong password; raw live-file copy rejected at
the magic gate; depth bomb rejected pre-parse.
