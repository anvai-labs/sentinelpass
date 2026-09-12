//! Fuzz target: vault envelope v2 OPEN path (WBS-903 / TV-003).
//!
//! `open_envelope` is the parser every durable ciphertext in the vault goes
//! through: magic pre-scan → size/depth caps → typed JSON decode (duplicate
//! and unknown keys rejected) → version/alg gates → exact base64 length
//! checks → AES-256-GCM open under the EXPECTED AAD context. The invariant:
//! arbitrary bytes must always produce either plaintext or a typed error —
//! never a panic, never an unbounded allocation.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinelpass_core::crypto::{AadContext, DataEncryptionKey, EnvelopePurpose, ObjectType, AAD_VERSION, envelope};

/// Fixed fuzz DEK (never used for real data; lets the fuzzer reach the GCM
/// layer and the identity-binding checks deterministically).
const FUZZ_DEK: [u8; 32] = [0x42u8; 32];

fn expected_context() -> AadContext {
    AadContext {
        aad_version: AAD_VERSION,
        vault: "11111111-1111-1111-1111-111111111111".to_string(),
        object: "22222222-2222-2222-2222-222222222222".to_string(),
        purpose: EnvelopePurpose::Secret,
        object_type: ObjectType::Password,
        schema_version: 8,
        crypto_version: 1,
        epoch: 3,
        tombstone: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut key = FUZZ_DEK;
    let dek = DataEncryptionKey::from_bytes(&mut key);

    // The whole point: any error is fine, panics are not.
    let _ = envelope::open_envelope(&dek, expected_context(), data);

    // The rotation-invariant variant walks a different epoch-expectation
    // branch; it must be equally panic-free.
    let _ = envelope::open_envelope_relaxed_epoch(&dek, expected_context(), data);
});
