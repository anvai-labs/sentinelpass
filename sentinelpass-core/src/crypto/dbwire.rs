//! Durable `db_metadata` wire documents (WBS-305 / SR-CRYPTO-002 / ADR-005
//! rev 4).
//!
//! The `db_metadata` columns `kdf_params`, `wrapped_dek`, and `dek_nonce`
//! historically stored opaque Rust-shaped `bincode` blobs — `bincode(
//! KdfParams)`, `bincode(WrappedKey)`, `bincode([u8; 12])`. Bincode is
//! neither self-describing nor language-neutral and had no hard decode
//! limits on two of the three shapes, so these three columns move to the
//! same document discipline as the SPENV envelope (WBS-304): a small,
//! versioned, bounded JSON document with an explicit magic, algorithm
//! identifier, integers only, and typed-struct decode. The in-memory types
//! ([`KdfParams`], [`WrappedKey`]) are UNCHANGED — this module only owns
//! their durable encoding.
//!
//! ```json
//! {"magic":"SPKDF","v":1,"alg":"ARGON2ID","salt":"<b64 16B>",
//!  "mem_cost":262144,"time_cost":3,"parallelism":4,"output_length":32}
//! {"magic":"SPWRAP","v":1,"alg":"A256GCM","wrapped_dek":"<b64>",
//!  "nonce":"<b64 12B>","auth_tag":"<b64 16B>","epoch_bound":true}
//! {"magic":"SPNONCE","v":1,"nonce":"<b64 12B>"}
//! ```
//!
//! # Dual-read compatibility (read-old forever, write-new)
//!
//! Reads DISPATCH on the FULL magic byte prefix — never on a bare `{`:
//! a legacy `bincode(KdfParams)` blob begins with 16 random salt bytes and
//! a legacy `bincode([u8;12])` blob begins with 12 random nonce bytes, so
//! either starts with `{` (0x7B) with probability ~1/256 per vault — a
//! first-byte sniff would misroute ~0.4% of real legacy vaults to the JSON
//! parser and break "old vaults stay readable". A collision with the FULL
//! 13-16 byte magic requires the random leading material to BE the magic
//! (~2^-100; only a deliberate forgery could arrange it, and a writer that
//! forges DB rows already controls the vault). Within the document branch
//! there is NO fallback to bincode: a blob that claims the magic and then
//! fails to parse is corrupt or hostile, and reinterpreting it as bincode
//! would be format confusion — it fails closed with a typed error. A blob
//! without the magic goes to the bounded legacy bincode path, so every
//! vault ever written remains readable.
//!
//! The two encodings may legally coexist ACROSS columns (each column
//! dispatches independently) and across time (legacy rows keep their bytes
//! until the next metadata write); the epoch guard digests the raw stored
//! bytes and the slot-registry MAC covers the slot rows, so mixed states
//! are internally consistent by construction.
//!
//! # Bounded decode (attacker-controlled input — these blobs are disk-read)
//!
//! Ordered gates before any allocation or parsing: empty-blob check, raw
//! length cap ([`MAX_DBWIRE_BYTES`], enforced BEFORE the magic scan), the
//! magic pre-scan itself (a wrong blob class fails in microseconds), a
//! byte-level nesting-depth pre-scan (shared `aad::json_depth_exceeds` —
//! one copy of the escape-tracking logic, WBS-304 finding 9), typed-struct
//! decode (`deny_unknown_fields`: unknown keys and duplicate keys fail
//! structurally; integers only — serde_json rejects float and string
//! spellings in integer fields; never through `serde_json::Value`), a
//! fail-closed version gate ([`DBWIRE_VERSION`], typed
//! `UnsupportedCryptoVersion`), post-parse magic and algorithm checks, and
//! exact/declared-length base64 checks BEFORE decoding. The legacy bincode
//! path is decoded under the same `with_limit(4096) + fixint +
//! reject_trailing` options as `WrappedKey::from_bincode_bytes` — fixint +
//! reject-trailing restores byte-for-byte compatibility with what plain
//! `bincode::serialize` wrote; only the limit is new.
//!
//! # Canonicalization split (writer-pinned, reader-structural)
//!
//! Writer output is a frozen contract pinned byte-exact by golden-vector
//! tests: compact UTF-8 JSON, field order = declaration order, standard
//! padded base64 (`data_encoding::BASE64`), integer spellings. Readers are
//! deliberately SEMANTIC (whitespace and JSON-object ordering are
//! tolerated) because byte-canonicality is not a security dependency
//! here — these documents are unauthenticated metadata whose integrity is
//! anchored externally (the epoch-guard digest and slot-registry MAC cover
//! the stored bytes; the wrap's GCM tag is the crypto boundary). A
//! cross-language writer that fails the golden vectors is non-conformant;
//! a reader that accepts structurally-valid respellings is correct.
//!
//! # Scope boundary
//!
//! Only the `db_metadata` columns move to documents. The `key_slots`
//! table's wrap format deliberately STAYS legacy bincode (slot recovery
//! depends on the current shape — conversion is a documented follow-up in
//! `docs/DURABLE_WIRE_FORMATS.md`), and the pairing-bootstrap TRANSPORT
//! blobs stay bincode so an updated origin device cannot strand an older
//! joining device (joiners dual-read both).

use super::kdf::KdfParams;
use super::keyring::WrappedKey;
use super::{CryptoError, Result};
use bincode::Options as _;
use serde::{Deserialize, Serialize};

/// Current document version for all three `db_metadata` documents. Any
/// change to any document shape bumps this (all three share one version
/// counter — they are one format decision) and older readers fail closed
/// with `UnsupportedCryptoVersion`. There is no downgrade path.
pub const DBWIRE_VERSION: i32 = 1;

/// Magic FIELD value of the KDF-parameters document (embedded in the byte
/// prefix const below).
pub const KDF_MAGIC_STR: &str = "SPKDF";
/// Magic FIELD value of the wrapped-DEK document.
pub const WRAP_MAGIC_STR: &str = "SPWRAP";
/// Magic FIELD value of the standalone DEK-nonce document.
pub const NONCE_MAGIC_STR: &str = "SPNONCE";

/// Raw byte prefix of every v1 KDF-parameters document. Checked BEFORE any
/// JSON parsing so a wrong-blob-class input (legacy bincode, random data)
/// fails in microseconds without allocation.
pub const KDF_MAGIC: &[u8] = br#"{"magic":"SPKDF""#;
/// Raw byte prefix of every v1 wrapped-DEK document.
pub const WRAP_MAGIC: &[u8] = br#"{"magic":"SPWRAP""#;
/// Raw byte prefix of every v1 standalone DEK-nonce document.
pub const NONCE_MAGIC: &[u8] = br#"{"magic":"SPNONCE""#;

/// KDF algorithm identifier of the v1 KDF document. Only Argon2id is
/// defined; anything else fails closed. Agility exists only through a
/// `(DBWIRE_VERSION, alg)` bump — never by accepting new strings silently.
pub const ALG_ARGON2ID: &str = "ARGON2ID";

/// Total blob size cap (bytes), enforced BEFORE the magic scan and any
/// parsing, on BOTH the document and the legacy bincode path. The largest
/// legitimate blob is the wrap document (185 bytes with a 32-byte DEK);
/// 4 KiB matches the decode limit `WrappedKey::from_bincode_bytes` has
/// used since WBS-307 and the AAD size contract — one size class for all
/// key-material metadata.
pub const MAX_DBWIRE_BYTES: usize = 4096;

/// Declared-length cap for the `wrapped_dek` base64 field (raw bytes, pre-
/// base64). The ciphertext of the 32-byte DEK is exactly 32 bytes; 96 is
/// 3x headroom for a future larger key class — going beyond that is a new
/// `DBWIRE_VERSION`, not a silent widening.
pub const MAX_WRAPPED_DEK_BYTES: usize = 96;

/// Nesting cap for the documents (flat objects; generous headroom for a
/// future structured field). Checked by the shared byte-level scanner.
const MAX_DBWIRE_DEPTH: usize = 4;

/// The durable v1 KDF-parameters document. Field order IS wire order
/// (derived `Serialize` emits declaration order — deterministic, no map
/// types). Field names mirror [`KdfParams`] exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfDocument {
    magic: String,
    v: i32,
    alg: String,
    /// 16-byte KDF salt, standard padded base64 (exactly 24 chars).
    salt: String,
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_length: u32,
}

/// The durable v1 wrapped-DEK document. Field names mirror [`WrappedKey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrapDocument {
    magic: String,
    v: i32,
    /// AES-256-GCM (same identifier as the SPENV envelope).
    alg: String,
    /// Wrapped DEK ciphertext (tag excluded), standard padded base64,
    /// length-capped at [`MAX_WRAPPED_DEK_BYTES`].
    wrapped_dek: String,
    /// 96-bit GCM nonce, base64 (exactly 16 chars).
    nonce: String,
    /// 128-bit GCM tag, base64 (exactly 24 chars).
    auth_tag: String,
    /// True when the wrap binds its key epoch as GCM associated data
    /// (ADR-002). A JSON boolean — the integers-only rule applies to
    /// NUMBERS; `1`/`0` are rejected by the typed decode.
    epoch_bound: bool,
}

/// The durable v1 standalone DEK-nonce document (the redundant
/// `dek_nonce` column mirrors [`WrappedKey`]'s inner nonce).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceDocument {
    magic: String,
    v: i32,
    /// 96-bit GCM nonce, base64 (exactly 16 chars).
    nonce: String,
}

/// Shared document-path gates AFTER the caller's magic pre-scan: size cap,
/// depth pre-scan, typed decode. Never through `serde_json::Value`.
fn parse_document<T: serde::de::DeserializeOwned>(blob: &[u8], magic_str: &str) -> Result<T> {
    if super::aad::json_depth_exceeds(blob, MAX_DBWIRE_DEPTH) {
        return Err(CryptoError::DecryptionFailed(format!(
            "{magic_str} document exceeds the maximum nesting depth ({MAX_DBWIRE_DEPTH})"
        )));
    }
    serde_json::from_slice(blob)
        .map_err(|e| CryptoError::DecryptionFailed(format!("malformed {magic_str} document: {e}")))
}

/// Fail-closed version gate shared by all three document readers.
fn check_version(found: i32) -> Result<()> {
    if found != DBWIRE_VERSION {
        return Err(CryptoError::UnsupportedCryptoVersion {
            found,
            supported: DBWIRE_VERSION,
        });
    }
    Ok(())
}

/// Post-parse magic-field invariant (the pre-scan makes a wrong value
/// unparseable today, but the invariant is ENFORCED rather than left
/// incidental to the pre-scan's exact length — same discipline as the
/// SPENV envelope's post-parse magic check).
fn check_magic_field(found: &str, expected: &str) -> Result<()> {
    if found != expected {
        return Err(CryptoError::DecryptionFailed(format!(
            "document magic field mismatch (expected {expected:?}, found {found:?})"
        )));
    }
    Ok(())
}

/// Fail-closed algorithm gate (same discipline as the envelope's `alg`).
fn check_alg_field(found: &str, expected: &str) -> Result<()> {
    if found != expected {
        return Err(CryptoError::DecryptionFailed(format!(
            "unsupported document algorithm {found:?} (fail-closed; only {expected:?} is defined)"
        )));
    }
    Ok(())
}

/// Decode a base64 field that must be EXACTLY `expected_len` raw bytes,
/// with the declared-length pre-check BEFORE decoding (12 B -> 16 chars,
/// 16 B -> 24 chars, 16 B salt -> 24 chars).
fn decode_exact_b64(s: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let expected_chars = expected_len.div_ceil(3) * 4;
    if s.len() != expected_chars {
        return Err(CryptoError::DecryptionFailed(format!(
            "document field {field:?} must be exactly {expected_len} bytes \
             ({expected_chars} base64 chars), got {} chars",
            s.len()
        )));
    }
    let decoded = data_encoding::BASE64.decode(s.as_bytes()).map_err(|_| {
        CryptoError::DecryptionFailed(format!("document field {field:?} is not valid base64"))
    })?;
    if decoded.len() != expected_len {
        return Err(CryptoError::DecryptionFailed(format!(
            "document field {field:?} decoded to {} bytes, expected {expected_len}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Decode a length-CAPPED base64 field with the declared-length pre-check
/// BEFORE decoding, so a hostile document cannot buy an oversized buffer.
fn decode_capped_b64(s: &str, max_len: usize, field: &str) -> Result<Vec<u8>> {
    let max_chars = max_len.div_ceil(3) * 4;
    if s.len() > max_chars {
        return Err(CryptoError::DecryptionFailed(format!(
            "document field {field:?} exceeds the cap ({max_len} bytes)"
        )));
    }
    let decoded = data_encoding::BASE64.decode(s.as_bytes()).map_err(|_| {
        CryptoError::DecryptionFailed(format!("document field {field:?} is not valid base64"))
    })?;
    if decoded.len() > max_len {
        return Err(CryptoError::DecryptionFailed(format!(
            "document field {field:?} decoded to {} bytes, cap is {max_len}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// The bounded legacy-bincode decode options: byte-compatible with plain
/// `bincode::serialize` (fixint little-endian, no trailing slack) plus the
/// 4 KiB limit so no collection length is trusted before checking. Same
/// restore as `WrappedKey::from_bincode_bytes` (WBS-307).
fn legacy_bincode_options() -> impl bincode::Options {
    bincode::options()
        .with_limit(MAX_DBWIRE_BYTES as u64)
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

/// Shared input gates for every decode: empty check and the raw length
/// cap, both BEFORE the magic scan or any parsing.
fn check_input_bounds(blob: &[u8], class: &str) -> Result<()> {
    if blob.is_empty() {
        return Err(CryptoError::DecryptionFailed(format!("empty {class} blob")));
    }
    if blob.len() > MAX_DBWIRE_BYTES {
        return Err(CryptoError::DecryptionFailed(format!(
            "{class} blob exceeds the size cap ({MAX_DBWIRE_BYTES} bytes)"
        )));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// KDF parameters
// --------------------------------------------------------------------------

/// Encode [`KdfParams`] as the v1 `SPKDF` document (the durable write
/// format for the `db_metadata.kdf_params` column from WBS-305 on).
pub fn encode_kdf_params(params: &KdfParams) -> Result<Vec<u8>> {
    let doc = KdfDocument {
        magic: KDF_MAGIC_STR.to_string(),
        v: DBWIRE_VERSION,
        alg: ALG_ARGON2ID.to_string(),
        salt: data_encoding::BASE64.encode(&params.salt),
        mem_cost: params.mem_cost,
        time_cost: params.time_cost,
        parallelism: params.parallelism,
        output_length: params.output_length,
    };
    serde_json::to_vec(&doc)
        .map_err(|e| CryptoError::EncryptionFailed(format!("kdf document encode failed: {e}")))
}

/// Decode the `kdf_params` column: `SPKDF` document (new writes) or legacy
/// `bincode(KdfParams)` (every vault written before WBS-305 — readable
/// forever). Range validation is deliberately NOT done here (parity with
/// the legacy path): decode is structural; `derive_master_key` runs
/// `KdfParams::validate` before any Argon2 work.
pub fn decode_kdf_params(blob: &[u8]) -> Result<KdfParams> {
    check_input_bounds(blob, "kdf_params")?;
    if blob.starts_with(KDF_MAGIC) {
        let doc = parse_document::<KdfDocument>(blob, KDF_MAGIC_STR)?;
        check_version(doc.v)?;
        check_magic_field(&doc.magic, KDF_MAGIC_STR)?;
        check_alg_field(&doc.alg, ALG_ARGON2ID)?;
        let salt = decode_exact_b64(&doc.salt, 16, "salt")?;
        let mut salt_arr = [0u8; 16];
        salt_arr.copy_from_slice(&salt);
        Ok(KdfParams {
            salt: salt_arr,
            mem_cost: doc.mem_cost,
            time_cost: doc.time_cost,
            parallelism: doc.parallelism,
            output_length: doc.output_length,
        })
    } else {
        legacy_bincode_options()
            .deserialize::<KdfParams>(blob)
            .map_err(|e| {
                CryptoError::DecryptionFailed(format!(
                    "kdf_params blob is neither an {KDF_MAGIC_STR} document nor legacy \
                     bincode: {e}"
                ))
            })
    }
}

// --------------------------------------------------------------------------
// Wrapped DEK
// --------------------------------------------------------------------------

/// Encode [`WrappedKey`] as the v1 `SPWRAP` document (the durable write
/// format for the `db_metadata.wrapped_dek` column from WBS-305 on).
pub fn encode_wrapped_key(wrapped: &WrappedKey) -> Result<Vec<u8>> {
    let doc = WrapDocument {
        magic: WRAP_MAGIC_STR.to_string(),
        v: DBWIRE_VERSION,
        alg: super::ALG_A256GCM.to_string(),
        wrapped_dek: data_encoding::BASE64.encode(&wrapped.wrapped_dek),
        nonce: data_encoding::BASE64.encode(&wrapped.nonce),
        auth_tag: data_encoding::BASE64.encode(&wrapped.auth_tag),
        epoch_bound: wrapped.epoch_bound,
    };
    serde_json::to_vec(&doc)
        .map_err(|e| CryptoError::EncryptionFailed(format!("wrap document encode failed: {e}")))
}

/// Decode the `wrapped_dek` column: `SPWRAP` document (new writes) or
/// legacy bincode — both the current 4-field shape and the <= v0.8.0
/// 3-field shape, via the same size-limited decoder
/// `WrappedKey::from_bincode_bytes` has used since WBS-307.
pub fn decode_wrapped_key(blob: &[u8]) -> Result<WrappedKey> {
    check_input_bounds(blob, "wrapped_dek")?;
    if blob.starts_with(WRAP_MAGIC) {
        let doc = parse_document::<WrapDocument>(blob, WRAP_MAGIC_STR)?;
        check_version(doc.v)?;
        check_magic_field(&doc.magic, WRAP_MAGIC_STR)?;
        check_alg_field(&doc.alg, super::ALG_A256GCM)?;
        let wrapped_dek =
            decode_capped_b64(&doc.wrapped_dek, MAX_WRAPPED_DEK_BYTES, "wrapped_dek")?;
        let nonce = decode_exact_b64(&doc.nonce, 12, "nonce")?;
        let auth_tag = decode_exact_b64(&doc.auth_tag, 16, "auth_tag")?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(&auth_tag);
        Ok(WrappedKey {
            wrapped_dek,
            nonce: nonce_arr,
            auth_tag: tag_arr,
            epoch_bound: doc.epoch_bound,
        })
    } else {
        WrappedKey::from_bincode_bytes(blob).map_err(|e| {
            CryptoError::DecryptionFailed(format!(
                "wrapped_dek blob is neither an {WRAP_MAGIC_STR} document nor legacy bincode: {e}"
            ))
        })
    }
}

// --------------------------------------------------------------------------
// Standalone DEK nonce
// --------------------------------------------------------------------------

/// Encode the 96-bit DEK nonce as the v1 `SPNONCE` document (the durable
/// write format for the `db_metadata.dek_nonce` column from WBS-305 on).
pub fn encode_dek_nonce(nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let doc = NonceDocument {
        magic: NONCE_MAGIC_STR.to_string(),
        v: DBWIRE_VERSION,
        nonce: data_encoding::BASE64.encode(nonce),
    };
    serde_json::to_vec(&doc)
        .map_err(|e| CryptoError::EncryptionFailed(format!("nonce document encode failed: {e}")))
}

/// Decode the `dek_nonce` column: `SPNONCE` document (new writes) or
/// legacy `bincode([u8; 12])` (readable forever).
pub fn decode_dek_nonce(blob: &[u8]) -> Result<[u8; 12]> {
    check_input_bounds(blob, "dek_nonce")?;
    if blob.starts_with(NONCE_MAGIC) {
        let doc = parse_document::<NonceDocument>(blob, NONCE_MAGIC_STR)?;
        check_version(doc.v)?;
        check_magic_field(&doc.magic, NONCE_MAGIC_STR)?;
        let nonce = decode_exact_b64(&doc.nonce, 12, "nonce")?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);
        Ok(nonce_arr)
    } else {
        legacy_bincode_options()
            .deserialize::<[u8; 12]>(blob)
            .map_err(|e| {
                CryptoError::DecryptionFailed(format!(
                    "dek_nonce blob is neither an {NONCE_MAGIC_STR} document nor legacy \
                     bincode: {e}"
                ))
            })
    }
}

// --------------------------------------------------------------------------
// Single store helper for the three columns
// --------------------------------------------------------------------------

/// Encode all three `db_metadata` key-material columns in one call — THE
/// write path for these columns (WBS-305): every writer of
/// `db_metadata.kdf_params` / `wrapped_dek` / `dek_nonce` (vault create,
/// password rotation, pair-join adoption, recovery rewrap) encodes through
/// here so the durable format has exactly one owner. The `key_slots`
/// mirror is deliberately NOT covered: that table keeps the frozen legacy
/// bincode slot format (scope boundary, documented in the module docs).
pub fn encode_metadata_blobs(
    kdf_params: &KdfParams,
    wrapped: &WrappedKey,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    Ok((
        encode_kdf_params(kdf_params)?,
        encode_wrapped_key(wrapped)?,
        encode_dek_nonce(&wrapped.nonce)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed KDF params for golden vectors: zero salt, desktop profile
    /// costs. b64([0u8; 16]) = "AAAAAAAAAAAAAAAAAAAAAA==".
    fn golden_kdf() -> KdfParams {
        KdfParams {
            salt: [0u8; 16],
            mem_cost: 262_144,
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }

    /// Fixed wrap for golden vectors: epoch-bound, deterministic fields.
    fn golden_wrap() -> WrappedKey {
        WrappedKey {
            wrapped_dek: vec![0xAB; 32],
            nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            auth_tag: [0x11; 16],
            epoch_bound: true,
        }
    }

    // --- P: golden vectors (byte-exact writer contract) -------------------

    #[test]
    fn golden_vector_kdf_document_byte_exact() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let expected = "{\"magic\":\"SPKDF\",\"v\":1,\"alg\":\"ARGON2ID\",\
\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"mem_cost\":262144,\"time_cost\":3,\
\"parallelism\":4,\"output_length\":32}";
        assert_eq!(
            doc,
            expected.as_bytes(),
            "SPKDF byte encoding changed — frozen format contract; ship a new \
             DBWIRE_VERSION instead of editing this vector. got: {}",
            String::from_utf8_lossy(&doc)
        );
        let back = decode_kdf_params(&doc).unwrap();
        assert_eq!(back.salt, golden_kdf().salt);
        assert_eq!(back.mem_cost, 262_144);
        assert_eq!(back.time_cost, 3);
        assert_eq!(back.parallelism, 4);
        assert_eq!(back.output_length, 32);
    }

    #[test]
    fn golden_vector_wrap_document_byte_exact() {
        let doc = encode_wrapped_key(&golden_wrap()).unwrap();
        let expected = "{\"magic\":\"SPWRAP\",\"v\":1,\"alg\":\"A256GCM\",\
\"wrapped_dek\":\"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\",\
\"nonce\":\"AAECAwQFBgcICQoL\",\"auth_tag\":\"EREREREREREREREREREREQ==\",\
\"epoch_bound\":true}";
        assert_eq!(
            doc,
            expected.as_bytes(),
            "SPWRAP byte encoding changed — frozen format contract; ship a new \
             DBWIRE_VERSION instead of editing this vector. got: {}",
            String::from_utf8_lossy(&doc)
        );
        let back = decode_wrapped_key(&doc).unwrap();
        assert_eq!(back.wrapped_dek, golden_wrap().wrapped_dek);
        assert_eq!(back.nonce, golden_wrap().nonce);
        assert_eq!(back.auth_tag, golden_wrap().auth_tag);
        assert!(back.epoch_bound);
    }

    #[test]
    fn golden_vector_nonce_document_byte_exact() {
        let doc = encode_dek_nonce(&golden_wrap().nonce).unwrap();
        let expected = "{\"magic\":\"SPNONCE\",\"v\":1,\"nonce\":\"AAECAwQFBgcICQoL\"}";
        assert_eq!(
            doc,
            expected.as_bytes(),
            "SPNONCE byte encoding changed — frozen format contract; ship a new \
             DBWIRE_VERSION instead of editing this vector. got: {}",
            String::from_utf8_lossy(&doc)
        );
        assert_eq!(decode_dek_nonce(&doc).unwrap(), golden_wrap().nonce);
    }

    #[test]
    fn writer_is_deterministic_and_epoch_bound_flag_is_wired() {
        let wrap_false = WrappedKey {
            epoch_bound: false,
            ..golden_wrap()
        };
        let a = encode_wrapped_key(&golden_wrap()).unwrap();
        let b = encode_wrapped_key(&golden_wrap()).unwrap();
        assert_eq!(a, b, "encoder must be deterministic");
        assert_ne!(
            a,
            encode_wrapped_key(&wrap_false).unwrap(),
            "epoch_bound must be encoded (the flag drives AAD verification)"
        );
        assert!(
            !decode_wrapped_key(&encode_wrapped_key(&wrap_false).unwrap())
                .unwrap()
                .epoch_bound
        );
    }

    // --- P: dual-read (legacy bincode readable forever) -------------------

    #[test]
    fn legacy_bincode_blobs_remain_readable() {
        let kdf = golden_kdf();
        let wrap = golden_wrap();
        let legacy_kdf = bincode::serialize(&kdf).unwrap();
        let legacy_wrap = bincode::serialize(&wrap).unwrap();
        let legacy_nonce = bincode::serialize(&wrap.nonce).unwrap();

        // All three are legacy-shaped (no document magic) and decode to the
        // exact typed values.
        assert!(!legacy_kdf.starts_with(KDF_MAGIC));
        let back_kdf = decode_kdf_params(&legacy_kdf).unwrap();
        assert_eq!(back_kdf.salt, kdf.salt);
        assert_eq!(back_kdf.mem_cost, kdf.mem_cost);
        let back_wrap = decode_wrapped_key(&legacy_wrap).unwrap();
        assert_eq!(back_wrap.wrapped_dek, wrap.wrapped_dek);
        assert_eq!(back_wrap.epoch_bound, wrap.epoch_bound);
        assert_eq!(decode_dek_nonce(&legacy_nonce).unwrap(), wrap.nonce);

        // Byte-stability: legacy -> decode -> legacy re-encode is identity,
        // which is what the old vault rows keep meaning.
        assert_eq!(bincode::serialize(&back_kdf).unwrap(), legacy_kdf);
        assert_eq!(bincode::serialize(&back_wrap).unwrap(), legacy_wrap);
    }

    #[test]
    fn legacy_three_field_wrap_remains_readable() {
        // A <= v0.8.0 blob: bincode without epoch_bound. Decode must map it
        // to epoch_bound=false (the ADR-002 legacy semantic), not fail.
        #[derive(serde::Serialize)]
        struct Legacy {
            wrapped_dek: Vec<u8>,
            nonce: [u8; 12],
            auth_tag: [u8; 16],
        }
        let blob = bincode::serialize(&Legacy {
            wrapped_dek: vec![1, 2, 3],
            nonce: [9u8; 12],
            auth_tag: [7u8; 16],
        })
        .unwrap();
        let parsed = decode_wrapped_key(&blob).unwrap();
        assert!(!parsed.epoch_bound);
        assert_eq!(parsed.wrapped_dek, vec![1, 2, 3]);
        assert_eq!(parsed.nonce, [9u8; 12]);
        assert_eq!(parsed.auth_tag, [7u8; 16]);
    }

    #[test]
    fn columns_decode_independently_of_each_other() {
        // Mixed storage (e.g. a legacy kdf column next to a new wrap
        // column after a rotation) is legal: each column dispatches on its
        // own magic. The rotation test in vault/tests.rs produces this
        // state end-to-end; here it is pinned at the codec level.
        let legacy_kdf = bincode::serialize(&golden_kdf()).unwrap();
        let doc_wrap = encode_wrapped_key(&golden_wrap()).unwrap();
        let legacy_nonce = bincode::serialize(&golden_wrap().nonce).unwrap();
        assert!(decode_kdf_params(&legacy_kdf).is_ok());
        assert!(decode_wrapped_key(&doc_wrap).is_ok());
        assert!(decode_dek_nonce(&legacy_nonce).is_ok());
    }

    // --- N: bounds, truncation, hostile input (typed, pre-allocation) -----

    #[test]
    fn oversized_blob_is_rejected_before_parsing() {
        let mut blob = KDF_MAGIC.to_vec();
        blob.resize(MAX_DBWIRE_BYTES + 1, b'a');
        let err = decode_kdf_params(&blob).unwrap_err();
        assert!(err.to_string().contains("size cap"), "{err}");
        let err = decode_wrapped_key(&blob).unwrap_err();
        assert!(err.to_string().contains("size cap"), "{err}");
        let err = decode_dek_nonce(&blob).unwrap_err();
        assert!(err.to_string().contains("size cap"), "{err}");
    }

    #[test]
    fn truncated_document_is_rejected() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        for cut in [doc.len() / 2, doc.len() - 1, KDF_MAGIC.len()] {
            let err = decode_kdf_params(&doc[..cut]).unwrap_err();
            assert!(
                err.to_string().contains("malformed") || err.to_string().contains("neither"),
                "cut at {cut}: expected a typed parse refusal, got: {err}"
            );
        }
    }

    #[test]
    fn empty_blob_is_rejected() {
        assert!(decode_kdf_params(&[]).is_err());
        assert!(decode_wrapped_key(&[]).is_err());
        assert!(decode_dek_nonce(&[]).is_err());
    }

    #[test]
    fn unknown_document_version_fails_closed_typed() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let text = String::from_utf8(doc).unwrap();
        let bumped = text.replacen(r#""v":1"#, r#""v":2"#, 1);
        assert_ne!(bumped, text);
        match decode_kdf_params(bumped.as_bytes()) {
            Err(CryptoError::UnsupportedCryptoVersion {
                found: 2,
                supported: 1,
            }) => {}
            other => panic!("version 2 must fail closed typed, got {other:?}"),
        }

        let wrap_text = String::from_utf8(encode_wrapped_key(&golden_wrap()).unwrap()).unwrap();
        match decode_wrapped_key(wrap_text.replacen(r#""v":1"#, r#""v":3"#, 1).as_bytes()) {
            Err(CryptoError::UnsupportedCryptoVersion { found: 3, .. }) => {}
            other => panic!("wrap version 3 must fail closed typed, got {other:?}"),
        }

        let nonce_text =
            String::from_utf8(encode_dek_nonce(&golden_wrap().nonce).unwrap()).unwrap();
        match decode_dek_nonce(nonce_text.replacen(r#""v":1"#, r#""v":9"#, 1).as_bytes()) {
            Err(CryptoError::UnsupportedCryptoVersion { found: 9, .. }) => {}
            other => panic!("nonce version 9 must fail closed typed, got {other:?}"),
        }
    }

    #[test]
    fn wrong_blob_class_is_rejected() {
        // Each decoder refuses the other documents' magic (no cross-class
        // acceptance, before any parsing).
        let kdf_doc = encode_kdf_params(&golden_kdf()).unwrap();
        let wrap_doc = encode_wrapped_key(&golden_wrap()).unwrap();
        let nonce_doc = encode_dek_nonce(&golden_wrap().nonce).unwrap();

        let kdf_err = decode_wrapped_key(&kdf_doc).unwrap_err();
        assert!(kdf_err.to_string().contains("neither"), "{kdf_err}");
        let wrap_err = decode_kdf_params(&wrap_doc).unwrap_err();
        assert!(wrap_err.to_string().contains("neither"), "{wrap_err}");
        assert!(decode_dek_nonce(&kdf_doc).is_err());
        assert!(decode_wrapped_key(&nonce_doc).is_err());
    }

    #[test]
    fn unknown_top_level_keys_are_rejected() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let text = String::from_utf8(doc).unwrap();
        let injected = text.replacen(
            r#""magic":"SPKDF""#,
            r#""magic":"SPKDF","injected":"metadata""#,
            1,
        );
        assert!(decode_kdf_params(injected.as_bytes()).is_err());
    }

    #[test]
    fn duplicate_keys_are_rejected_structurally() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let text = String::from_utf8(doc).unwrap();
        let dup = text.replacen(
            r#""alg":"ARGON2ID""#,
            r#""alg":"ARGON2ID","alg":"ARGON2ID""#,
            1,
        );
        assert!(decode_kdf_params(dup.as_bytes()).is_err());
    }

    #[test]
    fn float_integer_fields_are_rejected() {
        // ADR-005 rev 2: integers only — a cross-language writer that
        // round-tripped the costs through double must not decode here.
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let text = String::from_utf8(doc).unwrap();
        let floated = text.replacen(r#""time_cost":3"#, r#""time_cost":3.0"#, 1);
        assert_ne!(floated, text);
        assert!(decode_kdf_params(floated.as_bytes()).is_err());

        let wrap_text = String::from_utf8(encode_wrapped_key(&golden_wrap()).unwrap()).unwrap();
        let one_is_not_bool = wrap_text.replacen(r#""epoch_bound":true"#, r#""epoch_bound":1"#, 1);
        assert_ne!(one_is_not_bool, wrap_text);
        assert!(decode_wrapped_key(one_is_not_bool.as_bytes()).is_err());
    }

    #[test]
    fn wrong_length_base64_is_rejected_before_decode() {
        // nonce short by one byte (11 bytes -> would be 16 chars; 15-char
        // value must be refused on declared length).
        let wrap_text = String::from_utf8(encode_wrapped_key(&golden_wrap()).unwrap()).unwrap();
        let short_nonce = wrap_text.replacen(
            r#""nonce":"AAECAwQFBgcICQoL""#,
            r#""nonce":"AAECAwQFBgcICQo""#,
            1,
        );
        assert_ne!(short_nonce, wrap_text);
        let err = decode_wrapped_key(short_nonce.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("exactly 12 bytes"), "{err}");

        // Salt declared as 15 bytes (20 chars): refused before decode.
        let kdf_text = String::from_utf8(encode_kdf_params(&golden_kdf()).unwrap()).unwrap();
        let short_salt = kdf_text.replacen(
            r#""salt":"AAAAAAAAAAAAAAAAAAAAAA==""#,
            r#""salt":"AAAAAAAAAAAAAAAAAAAA"#,
            1,
        );
        assert_ne!(short_salt, kdf_text);
        assert!(decode_kdf_params(short_salt.as_bytes()).is_err());

        // wrapped_dek over the declared cap: refused on declared length.
        let big = WrappedKey {
            wrapped_dek: vec![0xAB; MAX_WRAPPED_DEK_BYTES + 1],
            ..golden_wrap()
        };
        let blob = encode_wrapped_key(&big).unwrap();
        let err = decode_wrapped_key(&blob).unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
    }

    #[test]
    fn invalid_base64_and_invalid_utf8_are_rejected() {
        let doc = encode_kdf_params(&golden_kdf()).unwrap();
        let text = String::from_utf8(doc).unwrap();
        let bad_b64 = text.replacen(
            r#""salt":"AAAAAAAAAAAAAAAAAAAAAA==""#,
            r#""salt":"!!!!!!!!!!!!!!!!!!!!!!==""#,
            1,
        );
        assert!(decode_kdf_params(bad_b64.as_bytes()).is_err());

        // A document prefix that passes the magic scan but is not UTF-8.
        let mut not_utf8 = KDF_MAGIC.to_vec();
        not_utf8.extend_from_slice(&[0xFF, 0xFE, 0xFF]);
        assert!(decode_kdf_params(&not_utf8).is_err());
    }

    #[test]
    fn depth_bomb_is_rejected() {
        let mut bomb = KDF_MAGIC.to_vec();
        bomb.extend(std::iter::repeat_n(b'[', MAX_DBWIRE_DEPTH + 8));
        bomb.extend(std::iter::repeat_n(b']', MAX_DBWIRE_DEPTH + 8));
        let err = decode_kdf_params(&bomb).unwrap_err();
        assert!(err.to_string().contains("nesting depth"), "{err}");
    }

    #[test]
    fn hostile_legacy_length_prefix_is_rejected_not_allocated() {
        // Legacy-path discipline (WBS-307 regression through the new
        // dispatcher): a bincode Vec length prefix claiming 2^40 must
        // return a typed error, never allocate or panic.
        let mut hostile: Vec<u8> = Vec::new();
        hostile.extend_from_slice(&1u64.wrapping_shl(40).to_le_bytes());
        hostile.extend_from_slice(&[0xAB; 8]);
        assert!(decode_wrapped_key(&hostile).is_err());
        // Also through the check gates: the blob is tiny, so the size cap
        // is not what saved us — the bincode SizeLimit was.
        assert!(hostile.len() < MAX_DBWIRE_BYTES);
    }

    #[test]
    fn alg_field_is_fail_closed() {
        let kdf_text = String::from_utf8(encode_kdf_params(&golden_kdf()).unwrap()).unwrap();
        let bad_alg = kdf_text.replacen(r#""alg":"ARGON2ID""#, r#""alg":"ARGON2ID-X""#, 1);
        let err = decode_kdf_params(bad_alg.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported document algorithm"),
            "{err}"
        );

        let wrap_text = String::from_utf8(encode_wrapped_key(&golden_wrap()).unwrap()).unwrap();
        let bad_wrap_alg = wrap_text.replacen(r#""alg":"A256GCM""#, r#""alg":"CHACHA""#, 1);
        assert!(decode_wrapped_key(bad_wrap_alg.as_bytes()).is_err());
    }

    #[test]
    fn magic_field_mismatch_is_enforced_post_parse() {
        // The byte pre-scan embeds the closing quote of the magic VALUE, so
        // no JSON document can pass the scan yet disagree on the parsed
        // field — the check is defense-in-depth (same rationale as the
        // envelope's). Pinned directly at the gate: a document that parses
        // but claims another class's magic is refused by the FIELD check,
        // not just by the pre-scan.
        let spoofed = r#"{"magic":"SPWRAP","v":1,"alg":"ARGON2ID","salt":"AAAAAAAAAAAAAAAAAAAAAA==","mem_cost":262144,"time_cost":3,"parallelism":4,"output_length":32}"#;
        let doc: KdfDocument = parse_document(spoofed.as_bytes(), KDF_MAGIC_STR).unwrap();
        assert!(check_magic_field(&doc.magic, KDF_MAGIC_STR).is_err());
        assert!(check_magic_field(KDF_MAGIC_STR, KDF_MAGIC_STR).is_ok());
    }
}
