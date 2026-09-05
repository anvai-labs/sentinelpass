//! Typed AAD (associated authenticated data) builder for the vault envelope
//! (WBS-303 / ADR-005 rev 4).
//!
//! GCM's authentication tag covers ciphertext AND associated data — binding
//! a blob to its semantic identity (which vault, which object, what kind of
//! envelope, what type, under which crypto epoch and format versions) turns
//! "valid ciphertext" into "valid ciphertext FOR THIS EXACT CONTEXT". A
//! storage-level attacker who copies or exchanges otherwise-valid blobs
//! between vaults, objects, purposes, types, or epochs is caught by GCM's
//! authentication failure, not by application-level bookkeeping.
//!
//! [`AadContext::to_bytes`] is the encode side both encrypt and decrypt call
//! independently — they must derive byte-identical AAD from the same
//! semantic facts, or GCM refuses to open. That byte sequence is a frozen
//! contract (ADR-005 rev 3): the golden-vector tests below pin exact output
//! for known inputs, and the input-perturbation test proves every field is
//! actually load-bearing. Any future change to the encoding is a breaking
//! change to every envelope ever written and must ship as a new
//! `crypto_version`, never a silent format tweak.
//!
//! Canonical JSON profile (ADR-005): integers only (no float coercion),
//! strict UTF-8, duplicate object keys rejected, a bounded nesting depth.
//! [`AadContext::from_bytes`] decodes directly into the typed struct —
//! **never** through `serde_json::Value` — so duplicate keys fail
//! structurally (serde's derived struct `Visitor` errors on a repeated
//! field; an untyped `Value`'s map would silently keep the last one).

use crate::{PasswordManagerError, Result};
use serde::{Deserialize, Serialize};

/// Maximum object nesting depth accepted by [`AadContext::from_bytes`],
/// enforced BEFORE the JSON is handed to serde (own explicit contract, not
/// serde_json's internal, undocumented recursion guard). `AadContext` itself
/// is flat (depth 1); the generous headroom exists so this check is a real,
/// meaningful gate rather than reject-everything, and stays valid if a
/// future field ever nests one level.
const MAX_JSON_DEPTH: usize = 8;

/// What role this envelope plays for its object (ADR-005: "separately
/// versioned summary and secret envelopes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopePurpose {
    /// Listing/search fields (title, username) — decrypted eagerly.
    Summary,
    /// The sensitive payload (password, key material) — decrypted on demand.
    Secret,
}

/// What kind of object this envelope belongs to. Deliberately covers every
/// envelope-bearing object family in the vault, not just password entries —
/// consumers (WBS-304+) pick the variant that matches their record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Password,
    ApiKey,
    PasskeyReference,
    SshKey,
    TotpSecret,
    RegistryEntity,
    KeySlot,
}

/// Typed AAD inputs: every field GCM's tag will bind this envelope to.
///
/// Field order below IS the wire order (struct-field declaration order is
/// what `serde_json`'s struct `Serialize` impl emits, deterministically —
/// no `HashMap`, no ambiguity). Changing the order, renaming a JSON key, or
/// adding/removing a field changes every future AAD byte sequence; that is
/// exactly why the golden vectors below exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AadContext {
    /// AAD encoding format version — independent of `crypto_version` (the
    /// envelope's algorithm/format) and `schema_version` (the database
    /// schema). Bumped only if this struct's shape or encoding changes.
    #[serde(rename = "v")]
    pub aad_version: u32,
    pub vault: String,
    pub object: String,
    pub purpose: EnvelopePurpose,
    #[serde(rename = "type")]
    pub object_type: ObjectType,
    pub schema_version: i32,
    pub crypto_version: i32,
    pub epoch: i64,
    /// Sync tombstone state, where applicable. Omitted (not `null`) when
    /// the object type has no tombstone concept — keeps golden vectors
    /// minimal for the common case and avoids a magic `null` sentinel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone: Option<bool>,
}

/// Current AAD encoding format version.
pub const AAD_VERSION: u32 = 1;

/// Hard cap on `from_bytes` input, checked before any parsing (review round
/// 1, finding 3): a real `AadContext` is well under 300 bytes (see the
/// golden vectors); this leaves generous headroom while still bounding
/// allocation/CPU cost for a function that takes `&[u8]` from a caller and
/// may someday see less-trusted input (debugging tools, stored-metadata
/// introspection). ADR-005's "hard decode limits" applies here too, not
/// just to the durable envelope format WBS-305 will define.
const MAX_AAD_BYTES: usize = 4096;

impl AadContext {
    /// Encode to the canonical AAD bytes fed to AES-256-GCM as associated
    /// data. Deterministic: identical fields always produce identical
    /// bytes, on any platform, forever (frozen contract — see module docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        // `serde_json::to_vec` on a plain struct (no HashMap fields) always
        // writes fields in declaration order — this is not an incidental
        // library detail, it's how `Serializer::serialize_struct` /
        // `serialize_field` compose for derived impls, and it is what makes
        // this deterministic without hand-rolling a JSON writer.
        //
        // `.expect()` here is provably unreachable, not merely unlikely:
        // `AadContext`'s fields are `String`/`u32`/`i32`/`i64`/`bool`/
        // unit-variant enums only — none of `serde_json`'s failure modes
        // (non-finite floats, non-string map keys, a `Serialize` impl that
        // itself returns an error) apply to this shape. Returning
        // `Result<Vec<u8>, _>` instead would push a never-actually-taken
        // error path onto every future caller for no real safety gain
        // (review round 1, finding 5 — kept as `.expect()` deliberately).
        serde_json::to_vec(self).expect("AadContext fields are always JSON-serializable")
    }

    /// Decode from AAD bytes. Exists for conformance testing and any future
    /// introspection/debugging need — the crypto protocol itself never
    /// needs to decode AAD (both encrypt and decrypt independently BUILD
    /// the same context from context they already have and compare
    /// implicitly via the GCM tag).
    ///
    /// Decodes directly into `AadContext` — never through `serde_json::Value`
    /// — so a duplicate JSON key is a structural decode error (serde's
    /// derived `Visitor::visit_map` rejects a second occurrence of an
    /// already-seen field), not silently last-wins as an untyped `Value`'s
    /// map would produce.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_AAD_BYTES {
            return Err(PasswordManagerError::InvalidInput(format!(
                "AAD context exceeds the maximum size ({MAX_AAD_BYTES} bytes)"
            )));
        }
        reject_if_too_deep(bytes, MAX_JSON_DEPTH)?;
        serde_json::from_slice(bytes)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("malformed AAD context: {e}")))
    }
}

/// Builds an [`AadContext`] via named setter calls instead of a positional
/// constructor (review round 1, finding 1): `AadContext::new` originally
/// took 8 positional arguments including two adjacent same-typed `i32`
/// fields (`schema_version`, `crypto_version`) — a future call site could
/// transpose them and the compiler would accept it silently (both are
/// `i32`); the failure would surface later as a GCM authentication error
/// (data unreadable) or, if BOTH paths transposed identically, no error at
/// all. Every field here is set by a distinctly-named method, so swapping
/// the ORDER of calls is harmless and swapping the METHOD itself is a
/// visible, self-describing mistake rather than a silent one.
#[derive(Default)]
pub struct AadContextBuilder {
    vault: Option<uuid::Uuid>,
    object: Option<uuid::Uuid>,
    purpose: Option<EnvelopePurpose>,
    object_type: Option<ObjectType>,
    schema_version: Option<i32>,
    crypto_version: Option<i32>,
    epoch: Option<i64>,
    tombstone: Option<bool>,
}

impl AadContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The vault this envelope belongs to.
    pub fn vault(mut self, vault: uuid::Uuid) -> Self {
        self.vault = Some(vault);
        self
    }

    /// The stable object (entry/key-slot/registry-entity/...) UUID.
    pub fn object(mut self, object: uuid::Uuid) -> Self {
        self.object = Some(object);
        self
    }

    pub fn purpose(mut self, purpose: EnvelopePurpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    pub fn object_type(mut self, object_type: ObjectType) -> Self {
        self.object_type = Some(object_type);
        self
    }

    pub fn schema_version(mut self, schema_version: i32) -> Self {
        self.schema_version = Some(schema_version);
        self
    }

    pub fn crypto_version(mut self, crypto_version: i32) -> Self {
        self.crypto_version = Some(crypto_version);
        self
    }

    pub fn epoch(mut self, epoch: i64) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// Sync tombstone state. CONTRACT (review round 1, finding 2): for any
    /// object type that has a tombstone concept at all, callers must call
    /// this with `Some`-producing intent on EVERY construction path for
    /// that type — never leave it unset on some paths and set on others.
    /// Leaving it unset (`None`) is reserved exclusively for object types
    /// with NO tombstone concept whatsoever. Mixing "unset because not
    /// applicable" and "unset because the caller forgot" for the SAME
    /// object type produces two different AAD byte sequences for what
    /// should be identical semantic state, and GCM will refuse to open one
    /// against material sealed under the other. This module cannot enforce
    /// that contract (it doesn't know WBS-304's object-type-to-tombstone
    /// mapping) — it is written down here so WBS-304 must not learn it the
    /// hard way.
    pub fn tombstone(mut self, tombstone: bool) -> Self {
        self.tombstone = Some(tombstone);
        self
    }

    /// UUID fields are typed (`uuid::Uuid`), not raw strings: canonical
    /// lowercase-hyphenated form is guaranteed by the type itself, so two
    /// callers building the same context from differently-formatted UUID
    /// input (uppercase, no hyphens) still produce byte-identical AAD.
    pub fn build(self) -> Result<AadContext> {
        fn missing(field: &str) -> PasswordManagerError {
            PasswordManagerError::InvalidInput(format!(
                "AadContextBuilder: required field '{field}' was not set"
            ))
        }
        Ok(AadContext {
            aad_version: AAD_VERSION,
            vault: self.vault.ok_or_else(|| missing("vault"))?.to_string(),
            object: self.object.ok_or_else(|| missing("object"))?.to_string(),
            purpose: self.purpose.ok_or_else(|| missing("purpose"))?,
            object_type: self.object_type.ok_or_else(|| missing("object_type"))?,
            schema_version: self
                .schema_version
                .ok_or_else(|| missing("schema_version"))?,
            crypto_version: self
                .crypto_version
                .ok_or_else(|| missing("crypto_version"))?,
            epoch: self.epoch.ok_or_else(|| missing("epoch"))?,
            tombstone: self.tombstone,
        })
    }
}

/// Pre-parse structural depth guard (ADR-005's "fixed depth cap"): counts
/// `{`/`[` vs `}`/`]` nesting outside of JSON string literals (backslash
/// escapes respected so a brace inside a quoted string never counts).
/// Rejects before any JSON parsing/allocation happens, independent of
/// whatever internal recursion guard `serde_json` itself may or may not
/// apply — this cap is OUR contract, not an implementation detail borrowed
/// from a dependency.
fn reject_if_too_deep(bytes: &[u8], max_depth: usize) -> Result<()> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return Err(PasswordManagerError::InvalidInput(format!(
                        "AAD context exceeds the maximum nesting depth ({max_depth})"
                    )));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn baseline() -> AadContext {
        AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap()
    }

    // --- P: deterministic encoding golden vectors ------------------------

    #[test]
    fn golden_vector_no_tombstone() {
        let ctx = baseline();
        let bytes = ctx.to_bytes();
        let expected = br#"{"v":1,"vault":"11111111-1111-1111-1111-111111111111","object":"22222222-2222-2222-2222-222222222222","purpose":"secret","type":"password","schema_version":7,"crypto_version":1,"epoch":3}"#;
        assert_eq!(
            bytes,
            expected,
            "AAD byte encoding changed — this is a frozen contract; every \
             existing envelope was authenticated under the OLD bytes. A \
             deliberate change must ship as a new AAD_VERSION, not a silent \
             edit to this test. got: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn golden_vector_with_tombstone() {
        let mut ctx = baseline();
        ctx.tombstone = Some(true);
        let bytes = ctx.to_bytes();
        let expected = br#"{"v":1,"vault":"11111111-1111-1111-1111-111111111111","object":"22222222-2222-2222-2222-222222222222","purpose":"secret","type":"password","schema_version":7,"crypto_version":1,"epoch":3,"tombstone":true}"#;
        assert_eq!(bytes, expected, "got: {}", String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn encoding_is_deterministic_across_repeated_calls() {
        let ctx = baseline();
        let a = ctx.to_bytes();
        let b = ctx.to_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn round_trips_through_decode() {
        let ctx = baseline();
        let bytes = ctx.to_bytes();
        let decoded = AadContext::from_bytes(&bytes).unwrap();
        assert_eq!(ctx, decoded);

        let mut with_tombstone = baseline();
        with_tombstone.tombstone = Some(false);
        let bytes2 = with_tombstone.to_bytes();
        let decoded2 = AadContext::from_bytes(&bytes2).unwrap();
        assert_eq!(with_tombstone, decoded2);
    }

    // --- N: every field perturbation changes the AAD bytes ---------------

    #[test]
    fn every_field_perturbation_changes_the_aad_bytes() {
        let base = baseline();
        let base_bytes = base.to_bytes();

        let other_vault = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let other_object = Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap();

        let variants: Vec<AadContext> = vec![
            AadContext {
                vault: other_vault.to_string(),
                ..base.clone()
            },
            AadContext {
                object: other_object.to_string(),
                ..base.clone()
            },
            AadContext {
                purpose: EnvelopePurpose::Summary,
                ..base.clone()
            },
            AadContext {
                object_type: ObjectType::ApiKey,
                ..base.clone()
            },
            AadContext {
                schema_version: base.schema_version + 1,
                ..base.clone()
            },
            AadContext {
                crypto_version: base.crypto_version + 1,
                ..base.clone()
            },
            AadContext {
                epoch: base.epoch + 1,
                ..base.clone()
            },
            AadContext {
                tombstone: Some(true),
                ..base.clone()
            },
            AadContext {
                aad_version: base.aad_version + 1,
                ..base.clone()
            },
        ];

        assert_eq!(
            variants.len(),
            9,
            "one variant per field on AadContext — update this test if a field is added/removed"
        );

        let mut seen = std::collections::HashSet::new();
        seen.insert(base_bytes.clone());
        for (i, variant) in variants.iter().enumerate() {
            let bytes = variant.to_bytes();
            assert_ne!(
                bytes, base_bytes,
                "variant {i} did not change the AAD bytes — that field is not \
                 actually bound by GCM's tag"
            );
            assert!(
                seen.insert(bytes),
                "variant {i} collided with a previously seen AAD encoding"
            );
        }
    }

    // --- Canonical JSON profile conformance (ADR-005 rev 3) --------------

    #[test]
    fn decode_rejects_duplicate_keys_structurally() {
        // Two "epoch" keys with different values. A `serde_json::Value`
        // decode would silently keep the LAST one; decoding straight into
        // the typed struct must instead fail (serde's derived struct
        // Visitor errors on a repeated field).
        let malformed = br#"{"v":1,"vault":"11111111-1111-1111-1111-111111111111","object":"22222222-2222-2222-2222-222222222222","purpose":"secret","type":"password","schema_version":7,"crypto_version":1,"epoch":3,"epoch":99}"#;
        let err = AadContext::from_bytes(malformed)
            .expect_err("duplicate key must be rejected, not last-wins accepted");
        // Prove it is genuinely the duplicate that is rejected, not some
        // unrelated parse failure: a version WITHOUT the duplicate decodes
        // fine with the exact same shape otherwise.
        let well_formed = br#"{"v":1,"vault":"11111111-1111-1111-1111-111111111111","object":"22222222-2222-2222-2222-222222222222","purpose":"secret","type":"password","schema_version":7,"crypto_version":1,"epoch":3}"#;
        AadContext::from_bytes(well_formed).expect("the non-duplicate sibling must decode");
        let _ = err;
    }

    #[test]
    fn decode_rejects_float_in_an_integer_field() {
        // epoch is i64; a JSON float token there must be a decode error,
        // not silently truncated/coerced — no arbitrary_precision feature
        // is enabled, so serde_json's integer visitors reject a decimal
        // point outright.
        let malformed = br#"{"v":1,"vault":"11111111-1111-1111-1111-111111111111","object":"22222222-2222-2222-2222-222222222222","purpose":"secret","type":"password","schema_version":7,"crypto_version":1,"epoch":3.0}"#;
        AadContext::from_bytes(malformed)
            .expect_err("a float token in an integer field must be rejected");
    }

    #[test]
    fn decode_rejects_excessive_nesting_depth() {
        // AadContext is flat; this proves the pre-parse depth guard fires
        // independently of type-mismatch errors serde would raise anyway.
        let mut deeply_nested = String::new();
        for _ in 0..(MAX_JSON_DEPTH + 5) {
            deeply_nested.push('[');
        }
        for _ in 0..(MAX_JSON_DEPTH + 5) {
            deeply_nested.push(']');
        }
        let err = AadContext::from_bytes(deeply_nested.as_bytes())
            .expect_err("excessive nesting must be rejected before parsing");
        assert!(
            err.to_string().contains("nesting depth"),
            "expected the depth-guard error, got: {err}"
        );
    }

    #[test]
    fn depth_guard_ignores_braces_inside_string_literals() {
        // A string VALUE containing literal brace characters must not be
        // miscounted as structural nesting. The guard operates on raw
        // bytes before any field-level validation, so a hand-built payload
        // (not a real AadContext — vault/object only ever hold canonical
        // UUID strings) exercises it directly.
        let payload = br#"{"note":"{{{{{{{{{{{{"}"#;
        assert!(reject_if_too_deep(payload, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn purpose_and_type_serialize_as_snake_case_tags() {
        let ctx = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Summary)
            .object_type(ObjectType::PasskeyReference)
            .schema_version(1)
            .crypto_version(1)
            .epoch(1)
            .build()
            .unwrap();
        let json = String::from_utf8(ctx.to_bytes()).unwrap();
        assert!(json.contains(r#""purpose":"summary""#));
        assert!(json.contains(r#""type":"passkey_reference""#));
    }

    // --- Builder correctness (review round 1, finding 1) -----------------

    #[test]
    fn builder_produces_the_same_context_as_direct_construction() {
        let via_builder = baseline();
        let via_literal = AadContext {
            aad_version: AAD_VERSION,
            vault: "11111111-1111-1111-1111-111111111111".to_string(),
            object: "22222222-2222-2222-2222-222222222222".to_string(),
            purpose: EnvelopePurpose::Secret,
            object_type: ObjectType::Password,
            schema_version: 7,
            crypto_version: 1,
            epoch: 3,
            tombstone: None,
        };
        assert_eq!(via_builder, via_literal);
    }

    #[test]
    fn builder_reorders_calls_without_changing_the_result() {
        // The whole point of named setters: call ORDER must not matter,
        // unlike positional arguments.
        let a = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap();
        let b = AadContextBuilder::new()
            .epoch(3)
            .crypto_version(1)
            .schema_version(7)
            .object_type(ObjectType::Password)
            .purpose(EnvelopePurpose::Secret)
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .build()
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn builder_refuses_to_build_with_a_required_field_unset() {
        let err = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            // epoch deliberately left unset
            .build()
            .expect_err("build() must refuse when a required field was never set");
        assert!(err.to_string().contains("epoch"));
    }

    #[test]
    fn builder_tombstone_defaults_to_unset() {
        let ctx = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Secret)
            .object_type(ObjectType::Password)
            .schema_version(7)
            .crypto_version(1)
            .epoch(3)
            .build()
            .unwrap();
        assert_eq!(ctx.tombstone, None);
    }

    // --- Size cap before parsing (review round 1, finding 3) -------------

    #[test]
    fn decode_rejects_oversized_input_before_parsing() {
        let oversized = vec![b'0'; MAX_AAD_BYTES + 1];
        let err = AadContext::from_bytes(&oversized)
            .expect_err("input over the size cap must be rejected before parsing");
        assert!(
            err.to_string().contains("maximum size"),
            "expected the size-cap error, got: {err}"
        );
    }

    #[test]
    fn decode_accepts_input_at_exactly_the_size_cap_if_otherwise_valid() {
        // The cap itself must not be off-by-one against a real, maximally
        // padded-out context (long enum names, max i32/i64 digit counts).
        let ctx = AadContextBuilder::new()
            .vault(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
            .object(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap())
            .purpose(EnvelopePurpose::Summary)
            .object_type(ObjectType::PasskeyReference)
            .schema_version(i32::MAX)
            .crypto_version(i32::MAX)
            .epoch(i64::MAX)
            .tombstone(true)
            .build()
            .unwrap();
        let bytes = ctx.to_bytes();
        assert!(
            bytes.len() < MAX_AAD_BYTES,
            "a realistic worst-case context ({} bytes) must fit comfortably under the cap \
             ({MAX_AAD_BYTES} bytes) — otherwise the cap is too tight for real use",
            bytes.len()
        );
        assert_eq!(AadContext::from_bytes(&bytes).unwrap(), ctx);
    }
}
