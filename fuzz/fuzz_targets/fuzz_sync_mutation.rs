//! Fuzz target: sync protocol v2 mutation parse (WBS-903 / TV-003).
//!
//! Covers BOTH ends of the v2 wire:
//! - relay side: serde decode of a `PushRequestV2` from untrusted JSON plus
//!   the static `validate_shape` gate (id/entry-type/version-step/epoch
//!   bounds, base64 payload, 32-byte MAC length);
//! - client side: decode into `sentinelpass_core::sync::v2::MutationV2`
//!   (typed `SyncEntryType`, base64-typed fields) and the metadata-MAC
//!   verification path under a fixed fuzz key.
//!
//! Invariants: decode/validate may REJECT, never panic; per-mutation static
//! validation is stateless so rejection of one mutation must not affect the
//! verdict on others.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinelpass_core::sync::v2 as client_v2;
use sentinelpass_relay::handlers::sync_v2::PushRequestV2;

/// Fixed fuzz MAC key (test-only material for `verify_mutation_mac`).
const FUZZ_MAC_KEY: [u8; 32] = [0x5au8; 32];

fuzz_target!(|data: &[u8]| {
    // Relay side: untrusted JSON -> typed request -> static shape gate.
    if let Ok(req) = serde_json::from_slice::<PushRequestV2>(data) {
        for m in &req.mutations {
            let _ = sentinelpass_relay::handlers::sync_v2::validate_shape(m);
        }
    }

    // Client side: the same wire decoded into the client's typed structs,
    // then the MAC verification path (which itself base64-decodes).
    if let Ok(mutations) = serde_json::from_slice::<Vec<client_v2::MutationV2>>(data) {
        for m in &mutations {
            let _ = client_v2::verify_mutation_mac(&FUZZ_MAC_KEY, m);
        }
    }
});
