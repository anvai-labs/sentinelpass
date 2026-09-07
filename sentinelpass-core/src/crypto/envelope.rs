//! Authenticated vault envelope v2 (WBS-304 / ADR-005 rev 4).
//!
//! Today's `encrypt_entry`/`decrypt_entry` are context-free: a valid
//! ciphertext for one field, record, vault, type, or epoch is a valid
//! ciphertext everywhere — a storage writer can exchange blobs and nothing
//! notices. Envelope v2 binds every ciphertext to its full semantic
//! identity using the typed AAD context from [`super::aad`], and wraps it
//! in a self-describing, bounded, language-neutral document:
//!
//! ```json
//! {"magic":"SPENV","envelope_version":2,"crypto_version":1,"alg":"A256GCM",
//!  "context":{...AadContext, authenticated as the GCM AAD...},
//!  "nonce":"<b64 12B>","ct":"<b64>","tag":"<b64 16B>"}
//! ```
//!
//! Security model:
//! - `context` carries the exact [`AadContext`] whose canonical bytes are
//!   the GCM associated data. `open_envelope` takes the EXPECTED context
//!   (from the caller's trusted DB row) and derives the AAD from it, so a
//!   whole-envelope relocation between rows/objects fails structurally —
//!   and any edit to the document's identity SEMANTICS (vault, object,
//!   purpose, type, epoch, versions, tombstone) yields a different
//!   context than expected and is refused. The guarantee is SEMANTIC
//!   identity binding, not byte-canonicality: a parse-preserving respelling
//!   (e.g. a `\u0073` escape in a string) parses to the same context and
//!   still opens — success is not a byte-level "untouched" signal. The
//!   document tolerates no unknown top-level keys (`deny_unknown_fields`)
//!   and no duplicate keys, so it cannot carry side-channel metadata
//!   without a version bump.
//! - Absence of a value is a DB-level NULL — never an empty ciphertext.
//!   `seal` accepts zero-length plaintext (a present-but-empty field),
//!   which is a different state than absence.
//! - Bounded decode: a cheap magic pre-scan before parsing, a total size
//!   cap, a nesting-depth cap, exact base64 length checks for nonce/tag,
//!   an explicit ciphertext cap, and typed-struct JSON decode (duplicate
//!   keys fail structurally, integers only). Unknown `envelope_version`
//!   or `alg` fail closed with a typed error.
//!
//! The canonical field order of this document is part of the frozen
//! format contract (same discipline as the AAD bytes): golden-vector
//! tests pin exact output. Changing the shape or order is a new
//! `envelope_version`, never a silent edit.

use super::aad::AadContext;
use super::{CryptoError, DataEncryptionKey, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Magic prefix of every v2 envelope document. Checked as raw bytes BEFORE
/// any JSON parsing so a wrong-blob-class input (a v1 `EncryptedEntry`
/// bincode blob, random data) fails in microseconds without allocation.
pub const ENVELOPE_MAGIC: &[u8] = br#"{"magic":"SPENV""#;

/// Current envelope document version. Bumped on ANY change to the
/// document shape; older versions fail closed on open (no downgrade path).
pub const ENVELOPE_VERSION: i32 = 2;

/// Crypto algorithm identifier for AES-256-GCM with 96-bit nonces and
/// 128-bit tags. Agility exists only through new `(envelope_version, alg)`
/// pairs — never by silently accepting new strings.
pub const ALG_A256GCM: &str = "A256GCM";

/// The ONLY crypto_version this build understands (ADR-005 fail-closed:
/// newer unsupported crypto versions refuse, and so do older ones — there
/// is no downgrade path). The authenticated copy lives inside the
/// context; this gate runs on BOTH seal and open so a future scheme bump
/// cannot be silently consumed by an old binary.
pub const SUPPORTED_CRYPTO_VERSION: i32 = 1;

/// The magic FIELD value (the byte-prefix const below embeds it).
pub const ENVELOPE_MAGIC_STR: &str = "SPENV";

/// Total document size cap before parsing (bytes). A real summary/secret
/// envelope is well under 100 KiB even for large SSH keys and notes; this
/// leaves headroom while bounding parse cost for hostile input.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

/// Ciphertext cap (bytes, pre-base64). Sized so the field-class policy
/// ceilings (2 MiB secrets) are genuinely reachable — a cap below the
/// policy would be dead rules (adoption review) — while bounding a
/// hostile blob's allocation (2 MiB ct ≈ 2.7 MiB base64, well under the
/// 4 MiB document cap).
pub const MAX_CIPHERTEXT_BYTES: usize = 3 * 1024 * 1024;

/// Base64 exponent for length arithmetic (3 raw bytes ↔ 4 b64 chars,
/// standard alphabet, with padding).
const B64_UNIT: usize = 4;

/// The durable v2 envelope document. Field order IS wire order (derived
/// `Serialize` emits declaration order for flat structs — deterministic,
/// no map types).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Always `"SPENV"` (enforced post-parse). A JSON key (not an
    /// offset-0 binary magic) so the document is plain JSON end to end;
    /// the raw-byte pre-scan in [`open_envelope`] still rejects wrong
    /// classes before parsing.
    pub magic: String,
    pub envelope_version: i32,
    pub crypto_version: i32,
    /// Algorithm identifier. Only [`ALG_A256GCM`] is defined; anything
    /// else fails closed.
    pub alg: String,
    /// The authenticated identity context — its canonical bytes are the
    /// GCM AAD (WBS-303).
    pub context: AadContext,
    /// 96-bit GCM nonce, base64 (exactly 16 chars).
    pub nonce: String,
    /// Ciphertext (tag excluded), base64, length-capped.
    pub ct: String,
    /// 128-bit GCM tag, base64 (exactly 24 chars).
    pub tag: String,
}

/// Seal plaintext into a v2 envelope document under `dek`, authenticated
/// against `context`'s canonical bytes as the GCM AAD.
///
/// `expected_max_plaintext` bounds the payload this caller considers
/// legitimate for its field class (defense in depth under
/// [`MAX_CIPHERTEXT_BYTES`]) — e.g. a TOTP-secret sealer passes a much
/// smaller bound than a notes sealer, so an oversized substitution is
/// also caught by policy, not just by the tag.
pub fn seal_envelope(
    dek: &DataEncryptionKey,
    context: AadContext,
    plaintext: &[u8],
    expected_max_plaintext: usize,
) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    seal_envelope_with_nonce(dek, context, plaintext, expected_max_plaintext, nonce_bytes)
}

/// [`seal_envelope`] with a CALLER-SUPPLIED nonce: exists solely so the
/// durable format has a deterministic sealing path for golden vectors and
/// cross-language conformance files (WBS-305). Production callers must
/// use [`seal_envelope`] — a reused nonce under the same key with the
/// same AAD is the one catastrophic AES-GCM misuse, and only the OS
/// CSPRNG gives the no-reuse guarantee.
pub fn seal_envelope_with_nonce(
    dek: &DataEncryptionKey,
    context: AadContext,
    plaintext: &[u8],
    expected_max_plaintext: usize,
    nonce_bytes: [u8; 12],
) -> Result<Vec<u8>> {
    if context.crypto_version != SUPPORTED_CRYPTO_VERSION {
        return Err(CryptoError::UnsupportedCryptoVersion {
            found: context.crypto_version,
            supported: SUPPORTED_CRYPTO_VERSION,
        });
    }
    if plaintext.len() > expected_max_plaintext {
        return Err(CryptoError::EncryptionFailed(format!(
            "plaintext ({} bytes) exceeds this field's declared maximum ({expected_max_plaintext})",
            plaintext.len()
        )));
    }
    if plaintext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(CryptoError::EncryptionFailed(format!(
            "plaintext exceeds the envelope ciphertext cap ({MAX_CIPHERTEXT_BYTES} bytes)"
        )));
    }

    let cipher = Aes256Gcm::new(dek.as_bytes().into());

    let ct_with_tag = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &context.to_bytes(),
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(format!("envelope seal failed: {e}")))?;

    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

    let envelope = Envelope {
        magic: "SPENV".to_string(),
        envelope_version: ENVELOPE_VERSION,
        crypto_version: context.crypto_version,
        alg: ALG_A256GCM.to_string(),
        context,
        nonce: data_encoding::BASE64.encode(&nonce_bytes),
        ct: data_encoding::BASE64.encode(ct),
        tag: data_encoding::BASE64.encode(tag),
    };

    serde_json::to_vec(&envelope)
        .map_err(|e| CryptoError::EncryptionFailed(format!("envelope encode failed: {e}")))
}

/// Open a v2 envelope document against the EXPECTED identity — the
/// context derived from the caller's TRUSTED DB row (vault uuid, object
/// uuid, purpose, type, epoch, versions).
///
/// The GCM AAD is derived from `expected`, NOT from the document: a
/// whole-envelope relocation (copy entry A's self-consistent blob into
/// entry B's row) authenticates under A's identity and fails under B's
/// expected AAD — the relocation attack ADR-005's threat model names is
/// closed by this SIGNATURE, not by caller diligence (review round 1,
/// finding 2). After the tag verifies, the parsed document context must
/// EQUAL `expected` (belt-and-braces: GCM proves the payload was sealed
/// under the expected AAD; this proves the document still CLAIMS the
/// identity it was sealed with).
pub fn open_envelope(
    dek: &DataEncryptionKey,
    expected: AadContext,
    document: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    open_envelope_impl(dek, expected, document, EpochExpectation::Strict)
}

/// [`open_envelope`] with the epoch expectation taken from the
/// AUTHENTICATED document context instead of the caller's row.
///
/// This exists for object classes whose DEK is rotation-INVARIANT: entry
/// envelopes survive master-password rotation unchanged (only the wrap
/// re-derives), so an entry sealed at epoch 1 must still open at epoch 3.
/// The epoch remains fully tag-bound — editing it in a document breaks
/// authentication — but a reader cannot require the CURRENT epoch without
/// forcing rotation-time re-encryption of every entry (the WBS-314
/// full-DEK-rotation class of feature; deliberately not built yet). All
/// OTHER identity fields (vault, object, purpose, type, versions,
/// tombstone) still come from the caller's trusted row and are enforced
/// structurally, so cross-row/entry/vault relocation stays refused.
/// Rotation-variant classes (key slots, whose wraps are epoch-bound) MUST
/// use strict [`open_envelope`].
pub fn open_envelope_relaxed_epoch(
    dek: &DataEncryptionKey,
    expected: AadContext,
    document: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    open_envelope_impl(dek, expected, document, EpochExpectation::FromDocument)
}

/// Where the epoch component of the expected context comes from.
enum EpochExpectation {
    /// Row-supplied: the sealed epoch MUST equal the caller's current
    /// epoch (key slots, sync payloads — anything whose material changes
    /// with the epoch).
    Strict,
    /// Document-supplied: the sealed epoch is authenticated but may lag
    /// the current one (entry envelopes under a rotation-invariant DEK).
    FromDocument,
}

fn open_envelope_impl(
    dek: &DataEncryptionKey,
    mut expected: AadContext,
    document: &[u8],
    epoch_expectation: EpochExpectation,
) -> Result<Zeroizing<Vec<u8>>> {
    // Cheap class check before any parsing/allocation.
    if !document.starts_with(ENVELOPE_MAGIC) {
        return Err(CryptoError::DecryptionFailed(
            "not an SPENV v2 envelope document".to_string(),
        ));
    }
    if document.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope document exceeds the size cap ({MAX_ENVELOPE_BYTES} bytes)"
        )));
    }

    // Typed decode: duplicate keys fail structurally, integers only,
    // depth-capped via the same byte-level pre-scan discipline as the
    // AAD module.
    if super::aad::json_depth_exceeds(document, MAX_ENVELOPE_DEPTH) {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope document exceeds the maximum nesting depth ({MAX_ENVELOPE_DEPTH})"
        )));
    }
    let envelope: Envelope = serde_json::from_slice(document)
        .map_err(|e| CryptoError::DecryptionFailed(format!("malformed envelope: {e}")))?;

    if envelope.envelope_version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedCryptoVersion {
            found: envelope.envelope_version,
            supported: ENVELOPE_VERSION,
        });
    }
    if envelope.alg != ALG_A256GCM {
        return Err(CryptoError::DecryptionFailed(format!(
            "unsupported envelope algorithm {:?} (fail-closed; only {ALG_A256GCM:?} is defined)",
            envelope.alg
        )));
    }
    // Post-parse magic invariant (review round 1, finding 10): the
    // pre-scan makes a wrong magic value unparseable today, but the
    // documented invariant is ENFORCED here rather than left incidental
    // to the pre-scan's exact length.
    if envelope.magic != ENVELOPE_MAGIC_STR {
        return Err(CryptoError::DecryptionFailed(
            "envelope magic field mismatch".to_string(),
        ));
    }
    // The AUTHENTICATED crypto_version (inside `context`, tag-bound via
    // the AAD) must be one this build understands — checked BEFORE the
    // pairwise drift check so an unsupported scheme gets the typed
    // UnsupportedCryptoVersion error, not a generic disagreement
    // (review round 1, finding 1: equality alone would let a future
    // scheme bump be silently consumed by this build).
    if envelope.context.crypto_version != SUPPORTED_CRYPTO_VERSION {
        return Err(CryptoError::UnsupportedCryptoVersion {
            found: envelope.context.crypto_version,
            supported: SUPPORTED_CRYPTO_VERSION,
        });
    }
    // The top-level copy is informational; the two must agree (a document
    // where they drift is malformed by construction — silently honoring
    // either copy would let an unauthenticated field override an
    // authenticated one).
    if envelope.crypto_version != envelope.context.crypto_version {
        return Err(CryptoError::DecryptionFailed(
            "envelope crypto_version disagrees with the authenticated context — refusing"
                .to_string(),
        ));
    }

    // Exact base64 length checks BEFORE decode (a hostile blob can claim
    // megabytes inside a short b64 string only by lying about length —
    // these checks make the declared shape impossible to satisfy).
    let nonce_vec = decode_exact_b64(&envelope.nonce, 12, "nonce")?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    let tag = decode_exact_b64(&envelope.tag, 16, "tag")?;
    // The ct cap uses declared-length discipline like nonce/tag (review
    // round 1, finding 7: the old shape decoded first and capped after —
    // up to a ~3 MiB allocation from a document that passed the size
    // gates).
    let max_ct_b64 = (MAX_CIPHERTEXT_BYTES.div_ceil(3)) * B64_UNIT;
    if envelope.ct.len() > max_ct_b64 {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope ciphertext exceeds the cap ({MAX_CIPHERTEXT_BYTES} bytes)"
        )));
    }
    let ct = data_encoding::BASE64
        .decode(envelope.ct.as_bytes())
        .map_err(|_| {
            CryptoError::DecryptionFailed("envelope ciphertext is not valid base64".to_string())
        })?;
    if ct.len() > MAX_CIPHERTEXT_BYTES {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope ciphertext exceeds the cap ({MAX_CIPHERTEXT_BYTES} bytes)"
        )));
    }
    // Epoch expectation (see EpochExpectation): for relaxed classes the
    // authenticated document epoch defines the expected value — it stays
    // tag-bound (editing it changes the AAD and breaks authentication),
    // it is simply not required to equal the reader's current epoch.
    // MUST run before the AAD is derived (this exact ordering bug was
    // caught by the rotation-survival adoption test: the AAD silently
    // carried the reader's current epoch and every rotated-vault read
    // failed authentication).
    if matches!(epoch_expectation, EpochExpectation::FromDocument) {
        expected.epoch = envelope.context.epoch;
    }
    // The format's own AAD size contract applies on this path too (review
    // round 1, finding 7): a bloated context string re-encodes to a bloated
    // AAD buffer on every attempt unless capped like every other field.
    let aad = expected.to_bytes();
    if aad.len() > super::aad::MAX_AAD_BYTES {
        return Err(CryptoError::DecryptionFailed(
            "expected context exceeds the AAD size contract".to_string(),
        ));
    }
    // Structural cross-check (review round 1, finding 2): the document
    // must CLAIM the identity the caller expects, with a precise error —
    // before any GCM work.
    if envelope.context != expected {
        return Err(CryptoError::DecryptionFailed(
            "envelope identity does not match the record it was opened against — \
             the blob may have been moved or swapped"
                .to_string(),
        ));
    }

    let cipher = Aes256Gcm::new(dek.as_bytes().into());
    let mut ct_with_tag = ct;
    ct_with_tag.extend_from_slice(&tag);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(nonce),
                aes_gcm::aead::Payload {
                    msg: ct_with_tag.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    Ok(plaintext)
}

/// Nesting cap for envelope documents (context is one level down).
const MAX_ENVELOPE_DEPTH: usize = 8;

/// Decode a base64 field that must be EXACTLY `expected_len` raw bytes.
fn decode_exact_b64(s: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    // Cheap declared-length pre-check: base64 of `expected_len` bytes is
    // exactly 4*ceil(expected/3) chars; anything else is rejected without
    // decoding. (12 B -> 16 chars, 16 B -> 24 chars.)
    let expected_chars = (expected_len.div_ceil(3)) * B64_UNIT;
    if s.len() != expected_chars {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope {field} must be exactly {expected_len} bytes ({expected_chars} base64 chars), got {} chars",
            s.len()
        )));
    }
    let decoded = data_encoding::BASE64.decode(s.as_bytes()).map_err(|_| {
        CryptoError::DecryptionFailed(format!("envelope {field} is not valid base64"))
    })?;
    if decoded.len() != expected_len {
        return Err(CryptoError::DecryptionFailed(format!(
            "envelope {field} decoded to {} bytes, expected {expected_len}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aad::{AadContextBuilder, EnvelopePurpose, ObjectType};
    use uuid::Uuid;

    fn ctx(purpose: EnvelopePurpose) -> AadContext {
        AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(purpose)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap()
    }

    // --- P: roundtrip + golden vectors ------------------------------------

    #[test]
    fn seal_open_roundtrip_summary_and_secret() {
        let dek = DataEncryptionKey::new().unwrap();
        for purpose in [EnvelopePurpose::Summary, EnvelopePurpose::Secret] {
            let doc = seal_envelope(&dek, ctx(purpose), b"hunter2", 1024).unwrap();
            let plaintext = open_envelope(&dek, ctx(purpose), &doc).unwrap();
            assert_eq!(plaintext.as_slice(), b"hunter2");
        }
    }

    /// WBS-308 / SR-CRYPTO-004 type-level guard: `open_envelope` (both
    /// epoch modes) must return a zeroizing plaintext buffer. Relaxing the
    /// signature to a bare `Vec<u8>` stops this test from compiling.
    #[test]
    fn open_envelope_returns_zeroizing_plaintext() {
        fn require_zeroing_vec(_: &Zeroizing<Vec<u8>>) {}

        let dek = DataEncryptionKey::new().unwrap();
        let doc = seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"guard", 64).unwrap();
        require_zeroing_vec(&open_envelope(&dek, ctx(EnvelopePurpose::Secret), &doc).unwrap());
        require_zeroing_vec(
            &open_envelope_relaxed_epoch(&dek, ctx(EnvelopePurpose::Secret), &doc).unwrap(),
        );
    }

    #[test]
    fn empty_plaintext_is_present_not_absent() {
        // A zero-length plaintext round-trips — it models a field that IS
        // set but empty, distinct from absence (a DB NULL carries no
        // envelope at all). Pins that seal() never special-cases emptiness
        // into a sentinel.
        let dek = DataEncryptionKey::new().unwrap();
        let doc = seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"", 16).unwrap();
        let plaintext = open_envelope(&dek, ctx(EnvelopePurpose::Secret), &doc).unwrap();
        assert!(plaintext.is_empty());
    }

    #[test]
    fn document_pins_field_order_key_names_and_lengths() {
        // GCM's nonce is random, so byte-exact output needs the fixed-nonce
        // golden below; this pins the DETERMINISTIC parts on the random
        // path: field order, key names, magic, b64 lengths.
        let dek = DataEncryptionKey::new().unwrap();
        let doc = seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"x", 1024).unwrap();
        let text = String::from_utf8(doc).unwrap();

        assert!(text.starts_with(r#"{"magic":"SPENV","envelope_version":2,"#));
        let keys_in_order = [
            r#""magic":"SPENV""#,
            r#""envelope_version":2"#,
            r#""crypto_version":1"#,
            r#""alg":"A256GCM""#,
            r#""context":{"#,
            r#""nonce":""#,
            r#""ct":""#,
            r#""tag":""#,
        ];
        let mut last = 0;
        for key in keys_in_order {
            let pos = text.find(key).unwrap_or_else(|| {
                panic!("envelope document missing key {key} — wire format changed")
            });
            assert!(
                pos >= last,
                "key {key} out of order — the document's field order is a frozen contract"
            );
            last = pos;
        }
        let nonce_val = text
            .split(r#""nonce":""#)
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(nonce_val.len(), 16, "nonce must be exactly 16 b64 chars");
        let tag_val = text
            .split(r#""tag":""#)
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(tag_val.len(), 24, "tag must be exactly 24 b64 chars");
    }

    /// A true byte-exact golden vector (review round 1, finding 6): fixed
    /// DEK + fixed nonce make the whole document deterministic, so ANY
    /// encoder change (escaping, integer formatting, field order, b64
    /// alphabet) breaks this test — and WBS-305's cross-language golden
    /// files can reproduce seal-side byte parity.
    #[test]
    fn golden_vector_byte_exact_with_fixed_nonce_and_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let dek = DataEncryptionKey::from_bytes(&mut key_bytes);
        let nonce = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ];
        let doc =
            seal_envelope_with_nonce(&dek, ctx(EnvelopePurpose::Secret), b"hunter2", 64, nonce)
                .unwrap();

        // Fixed-input sealing is fully deterministic.
        let doc2 =
            seal_envelope_with_nonce(&dek, ctx(EnvelopePurpose::Secret), b"hunter2", 64, nonce)
                .unwrap();
        assert_eq!(doc, doc2);

        // The exact bytes (generated once from this same code path, then
        // pinned — an encoder change breaks this assert):
        let expected = "{\"magic\":\"SPENV\",\"envelope_version\":2,\"crypto_version\":1,\"alg\":\"A256GCM\",\"context\":{\"v\":1,\"vault\":\"11111111-1111-1111-1111-111111111111\",\"object\":\"22222222-2222-2222-2222-222222222222\",\"purpose\":\"secret\",\"type\":\"password\",\"schema_version\":7,\"crypto_version\":1,\"epoch\":3},\"nonce\":\"8OHSw7Sllod4aVpL\",\"ct\":\"h6DVk8HhsQ==\",\"tag\":\"cal0eRNtryAhupqrSRSuXA==\"}";
        assert_eq!(
            doc.as_slice(),
            expected.as_bytes(),
            "envelope byte encoding changed — frozen format contract; ship a new \
             envelope_version instead of editing this vector. got: {}",
            String::from_utf8_lossy(&doc)
        );

        // The pinned vector opens back to the exact plaintext.
        let pt = open_envelope(&dek, ctx(EnvelopePurpose::Secret), &doc).unwrap();
        assert_eq!(pt.as_slice(), b"hunter2");
    }

    // --- N: identity substitution all fails closed ------------------------

    /// THE WBS-304 acceptance property: cross-field/record/vault/type/
    /// purpose/tombstone/version/epoch substitution of a VALID envelope
    /// must fail. Keyed needles throughout (review round 1, finding 5:
    /// bare values match the first occurrence document-wide — correct
    /// only by fixture coincidence).
    #[test]
    fn every_identity_substitution_fails_closed() {
        let dek = DataEncryptionKey::new().unwrap();
        let doc = seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"hunter2", 1024).unwrap();

        let substitutions: Vec<(&str, String, String)> = vec![
            (
                "vault",
                r#""vault":"11111111-1111-1111-1111-111111111111""#.into(),
                r#""vault":"99999999-9999-9999-9999-999999999999""#.into(),
            ),
            (
                "object",
                r#""object":"22222222-2222-2222-2222-222222222222""#.into(),
                r#""object":"88888888-8888-8888-8888-888888888888""#.into(),
            ),
            (
                "purpose",
                r#""purpose":"secret""#.into(),
                r#""purpose":"summary""#.into(),
            ),
            (
                "type",
                r#""type":"password""#.into(),
                r#""type":"api_key""#.into(),
            ),
            (
                "schema_version",
                r#""schema_version":7"#.into(),
                r#""schema_version":8"#.into(),
            ),
            ("epoch", r#""epoch":3"#.into(), r#""epoch":4"#.into()),
            (
                "tombstone-added",
                r#""epoch":3"#.into(),
                r#""epoch":3,"tombstone":true"#.into(),
            ),
        ];

        for (field, from, to) in substitutions {
            let text = String::from_utf8(doc.clone()).unwrap();
            let mutated = text.replacen(&from, &to, 1);
            assert_ne!(
                mutated, text,
                "{field}: substitution did not change the document"
            );
            assert!(
                open_envelope(&dek, ctx(EnvelopePurpose::Secret), mutated.as_bytes()).is_err(),
                "{field}: substituted envelope must be refused"
            );
        }

        // Top-level format fields fail closed (not auth):
        for (label, from, to) in [
            (
                "envelope_version",
                r#""envelope_version":2"#,
                r#""envelope_version":3"#,
            ),
            (
                "crypto_version-top",
                r#""crypto_version":1,"#,
                r#""crypto_version":2,"#,
            ),
            ("alg", r#""alg":"A256GCM""#, r#""alg":"A256GCM-X""#),
        ] {
            let text = String::from_utf8(doc.clone()).unwrap();
            let mutated = text.replacen(from, to, 1);
            assert!(
                open_envelope(&dek, ctx(EnvelopePurpose::Secret), mutated.as_bytes()).is_err(),
                "{label}: must fail closed"
            );
        }

        // The AUTHENTICATED context crypto_version (not the top-level copy
        // — which comes first in field order) is gated against the
        // supported set (review round 1, finding 1).
        // Mutate BOTH copies to 2: pairwise equality then holds, so this
        // proves the supported-version GATE fires (the typed error) rather
        // than accidentally tripping the drift check.
        let text = String::from_utf8(doc.clone()).unwrap();
        let mutated = text.replace(r#""crypto_version":1"#, r#""crypto_version":2"#);
        assert_ne!(mutated, text);
        match open_envelope(&dek, ctx(EnvelopePurpose::Secret), mutated.as_bytes()) {
            Err(CryptoError::UnsupportedCryptoVersion {
                found: 2,
                supported: 1,
            }) => {}
            other => {
                panic!("context crypto_version 2 must fail closed as unsupported, got {other:?}")
            }
        }

        // And an ONLY-top-level mutation (context left at 1) passes the
        // gate (the authenticated copy is still supported) and trips the
        // pairwise DRIFT check — fail closed, with the drift error.
        let text = String::from_utf8(doc.clone()).unwrap();
        let mutated = text.replacen(
            r#""crypto_version":1,"alg""#,
            r#""crypto_version":2,"alg""#,
            1,
        );
        assert_ne!(mutated, text);
        match open_envelope(&dek, ctx(EnvelopePurpose::Secret), mutated.as_bytes()) {
            Err(e) => assert!(
                e.to_string().contains("disagrees"),
                "expected the drift refusal, got: {e}"
            ),
            Ok(_) => panic!("drifted crypto_version must be refused"),
        }

        // Payload tamper: flip one ct char.
        let text = String::from_utf8(doc.clone()).unwrap();
        let mut chars: Vec<char> = text.chars().collect();
        let ct_pos = text.find(r#""ct":""#).unwrap() + 7;
        chars[ct_pos] = if chars[ct_pos] == 'A' { 'B' } else { 'A' };
        let mutated: String = chars.into_iter().collect();
        match open_envelope(&dek, ctx(EnvelopePurpose::Secret), mutated.as_bytes()) {
            Err(CryptoError::AuthenticationFailed) => {}
            other => panic!("ct tamper must fail authentication, got {other:?}"),
        }

        // Wrong DEK.
        let other_dek = DataEncryptionKey::new().unwrap();
        match open_envelope(&other_dek, ctx(EnvelopePurpose::Secret), &doc) {
            Err(CryptoError::AuthenticationFailed) => {}
            other => panic!("wrong DEK must fail authentication, got {other:?}"),
        }
    }

    /// THE structural property of the expected-context API (review round
    /// 1, finding 2): a whole-envelope relocation — entry A's valid,
    /// self-consistent blob dropped into entry B's row — is refused by
    /// the SIGNATURE, not by caller diligence.
    #[test]
    fn relocated_envelope_is_refused_by_the_expected_context() {
        let dek = DataEncryptionKey::new().unwrap();
        let entry_a = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap();
        let entry_b = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("55555555-5555-5555-5555-555555555555").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap();

        let a_doc = seal_envelope(&dek, entry_a.clone(), b"a-password", 64).unwrap();
        assert!(open_envelope(&dek, entry_a.clone(), &a_doc).is_ok());

        // Relocated to B's row: the blob is untouched and self-consistent —
        // only the expected identity differs. Refused BEFORE any GCM work,
        // with the relocation-specific error.
        match open_envelope(&dek, entry_b, &a_doc) {
            Err(e) => assert!(
                e.to_string().contains("moved or swapped"),
                "expected the relocation refusal, got: {e}"
            ),
            Ok(_) => panic!("relocated envelope must be refused"),
        }
    }

    // --- N: bounds + fail-closed decode -----------------------------------

    #[test]
    fn wrong_blob_class_is_rejected_before_parsing() {
        let dek = DataEncryptionKey::new().unwrap();
        let err = open_envelope(
            &dek,
            ctx(EnvelopePurpose::Secret),
            b"\x03\x00\x00\x00not-json-at-all",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not an SPENV"));
    }

    #[test]
    fn oversized_document_is_rejected_before_parsing() {
        let dek = DataEncryptionKey::new().unwrap();
        let mut blob = ENVELOPE_MAGIC.to_vec();
        blob.extend(std::iter::repeat_n(b'a', MAX_ENVELOPE_BYTES + 1));
        let err = open_envelope(&dek, ctx(EnvelopePurpose::Secret), &blob).unwrap_err();
        assert!(err.to_string().contains("size cap"));
    }

    #[test]
    fn declared_wrong_length_nonce_is_rejected() {
        // The exact-length gate: a nonce b64 value of 15 chars (not the
        // required 16) must be rejected by the declared-length check
        // before decode, regardless of content.
        let dek = DataEncryptionKey::new().unwrap();
        let text =
            String::from_utf8(seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"x", 8).unwrap())
                .unwrap();
        let marker = r#""nonce":""#;
        let start = text.find(marker).unwrap() + marker.len();
        let end = text[start..].find('"').unwrap() + start;
        let truncated = format!(
            "{}{}{}",
            &text[..start],
            &text[start..end - 1], // drop one b64 char -> 15 chars
            &text[end..]
        );
        let err =
            open_envelope(&dek, ctx(EnvelopePurpose::Secret), truncated.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("exactly 12 bytes"),
            "expected the exact-length refusal, got: {err}"
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_structurally() {
        let dek = DataEncryptionKey::new().unwrap();
        let text =
            String::from_utf8(seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"x", 8).unwrap())
                .unwrap();
        let dup = text.replacen(
            r#""alg":"A256GCM""#,
            r#""alg":"A256GCM","alg":"A256GCM""#,
            1,
        );
        assert!(open_envelope(&dek, ctx(EnvelopePurpose::Secret), dup.as_bytes()).is_err());
    }

    /// Unknown top-level keys are rejected (review round 1, finding 8):
    /// open success means the document is exactly the canonical shape —
    /// it cannot double as a metadata side-channel without a version bump.
    #[test]
    fn unknown_top_level_keys_are_rejected() {
        let dek = DataEncryptionKey::new().unwrap();
        let text =
            String::from_utf8(seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"x", 8).unwrap())
                .unwrap();
        let injected = text.replacen(
            r#""magic":"SPENV""#,
            r#""magic":"SPENV","injected":"metadata""#,
            1,
        );
        assert!(open_envelope(&dek, ctx(EnvelopePurpose::Secret), injected.as_bytes()).is_err());
    }

    #[test]
    fn depth_bomb_is_rejected() {
        let dek = DataEncryptionKey::new().unwrap();
        let mut bomb = ENVELOPE_MAGIC.to_vec();
        bomb.extend(std::iter::repeat_n(b'[', MAX_ENVELOPE_DEPTH + 4));
        bomb.extend(std::iter::repeat_n(b']', MAX_ENVELOPE_DEPTH + 4));
        let err = open_envelope(&dek, ctx(EnvelopePurpose::Secret), &bomb).unwrap_err();
        assert!(err.to_string().contains("nesting depth"));
    }

    #[test]
    fn field_max_plaintext_policy_is_enforced_at_seal() {
        let dek = DataEncryptionKey::new().unwrap();
        let err = seal_envelope(&dek, ctx(EnvelopePurpose::Secret), b"0123456789", 8).unwrap_err();
        assert!(err.to_string().contains("declared maximum"));
    }
}
