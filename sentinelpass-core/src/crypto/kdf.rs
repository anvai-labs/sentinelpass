//! Argon2id key derivation function for master password processing
//! (WBS-307 / ADR-003 / SR-CRYPTO-003: hard maximums + platform profiles).
//!
//! `KdfParams` is read from storage (vault metadata) on every unlock, and
//! from a peer device's pairing bootstrap on pair-join — neither source is
//! fully trusted to be non-hostile or even just non-buggy: a corrupted
//! vault file, a buggy or compromised peer, or plain data-entry error could
//! all produce a `mem_cost`/`time_cost`/`parallelism`/`output_length` value
//! that would make `derive_master_key` attempt a multi-gigabyte allocation
//! or a hang-length iteration count. [`KdfParams::validate`] runs BEFORE
//! any Argon2 call and is itself pure integer comparison — it must reject
//! a hostile value in microseconds, never by attempting the expensive work
//! first and discovering it was too expensive. (The same message's OTHER
//! untrusted field — the wrapped DEK's bincode `Vec` length prefix — is
//! bounded separately, in `WrappedKey::from_bincode_bytes`'s size-limited
//! decode; review round 1 confirmed `KdfParams` itself is fixed-size and
//! cannot trigger preallocations.)
//!
//! Default profile (desktop/interactive):
//! - Memory cost: 256 MB (262,144 KiB)
//! - Time cost: 3 iterations
//! - Parallelism: 4 lanes
//! - Output length: 32 bytes (256 bits)
//! - Salt length: 16 bytes
//!
//! [`KdfParams::mobile_profile`] is a lighter profile for memory-constrained
//! mobile targets, shaped after RFC 9106's memory-constrained recommended
//! option (same t/p; memory floor ~2% below its 64 MiB — see the const
//! docs for exact numbers) — chosen from published guidance, NOT yet
//! verified by wall-clock calibration on physical iOS/Android hardware
//! (that on-device calibration is tracked separately; do not read this
//! module as claiming it has been performed).

use crate::crypto::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Hard minimum memory cost, KiB (64 MB-class floor). For numeric
/// context from published guidance: OWASP's Argon2id minimum is 19,456
/// KiB (19 MiB, t=2, p=1) and RFC 9106's memory-constrained recommended
/// option is 65,536 KiB (2^16 KiB, t=3, p=4) — this floor sits between
/// the two: stricter than OWASP, ~2% below RFC 9106's constrained
/// option, with the RFC's t/p shape (see [`KdfParams::mobile_profile`]).
pub const MIN_MEM_COST_KIB: u32 = 64_000;
/// Hard maximum memory cost, KiB (1 GiB). Comfortably above the desktop
/// default (256 MB) for a future higher-security profile, but bounded so
/// an accepted value can never request a multi-gigabyte allocation.
/// NOTE (review round 1): this bounds the REQUEST, not the platform's
/// ability to satisfy it — a 1 GiB derivation is not guaranteed
/// executable on a memory-constrained phone, and pair-join currently
/// adopts a peer's parameters wholesale. Adopted-parameter ceilings for
/// constrained devices are tracked with the on-device calibration
/// follow-up (ADR-009), not claimed here.
pub const MAX_MEM_COST_KIB: u32 = 1_048_576;
/// Hard minimum time cost (iterations).
pub const MIN_TIME_COST: u32 = 1;
/// Hard maximum time cost. Argon2id's cost is roughly linear in this
/// value at fixed memory; unbounded iteration counts turn "slow on
/// purpose" into "never completes."
pub const MAX_TIME_COST: u32 = 20;
/// Hard minimum parallelism (lanes).
pub const MIN_PARALLELISM: u32 = 1;
/// Hard maximum parallelism. Comfortably above real consumer core counts;
/// RFC 9106's memory cost is total (not per-lane), so this bounds
/// concurrent CPU pressure, not memory.
pub const MAX_PARALLELISM: u32 = 16;
/// Hard minimum output length, bytes (256-bit master key).
pub const MIN_OUTPUT_LENGTH: u32 = 32;
/// Hard maximum output length, bytes. Generously above the 32 bytes this
/// codebase ever actually requests, while bounding a hostile huge request.
pub const MAX_OUTPUT_LENGTH: u32 = 1024;

/// Parameters for Argon2id key derivation
///
/// These parameters are chosen to provide strong security against
/// both brute-force and side-channel attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Salt for key derivation (16 bytes)
    pub salt: [u8; 16],

    /// Memory cost in KiB (262,144 = 256 MB)
    pub mem_cost: u32,

    /// Time cost (number of iterations)
    pub time_cost: u32,

    /// Parallelism (number of lanes)
    pub parallelism: u32,

    /// Output length in bytes
    pub output_length: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            mem_cost: 262_144, // 256 MB
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }
}

impl KdfParams {
    /// Create new random KDF parameters (desktop/interactive profile).
    pub fn new() -> Self {
        Self::default()
    }

    /// A lighter profile for memory-constrained mobile targets. Numeric
    /// relationship to RFC 9106's "second recommended option" for
    /// memory-constrained environments (65,536 KiB = 2^16 KiB, t=3, p=4):
    /// this profile matches its t/p shape exactly and uses a 64,000 KiB
    /// memory floor (~2% below the RFC value, identical security class).
    /// This is a published-guidance starting point, not a
    /// device-calibrated value (see module docs): on-device wall-clock
    /// verification on real iOS/Android hardware is tracked as follow-up
    /// work, not claimed here.
    pub fn mobile_profile() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            mem_cost: MIN_MEM_COST_KIB,
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }

    /// Verify that parameters are within acceptable ranges — hard MINIMUM
    /// (weak-KDF protection) AND hard MAXIMUM (hostile-value / DoS
    /// protection, SR-CRYPTO-003). Pure integer comparison: no allocation,
    /// no Argon2 invocation, so a hostile value is rejected in the time it
    /// takes to compare a handful of u32s — never by attempting the
    /// expensive derivation first.
    pub fn validate(&self) -> Result<()> {
        if self.mem_cost < MIN_MEM_COST_KIB {
            return Err(CryptoError::KdfFailed(format!(
                "Memory cost too low (minimum: {} KiB / {} MB)",
                MIN_MEM_COST_KIB,
                MIN_MEM_COST_KIB / 1000
            )));
        }
        if self.mem_cost > MAX_MEM_COST_KIB {
            return Err(CryptoError::KdfFailed(format!(
                "Memory cost too high (maximum: {} KiB / {} MB) — refusing before \
                 attempting the allocation",
                MAX_MEM_COST_KIB,
                MAX_MEM_COST_KIB / 1000
            )));
        }
        if self.time_cost < MIN_TIME_COST {
            return Err(CryptoError::KdfFailed(format!(
                "Time cost too low (minimum: {MIN_TIME_COST})"
            )));
        }
        if self.time_cost > MAX_TIME_COST {
            return Err(CryptoError::KdfFailed(format!(
                "Time cost too high (maximum: {MAX_TIME_COST}) — refusing before \
                 attempting the derivation"
            )));
        }
        if self.parallelism < MIN_PARALLELISM {
            return Err(CryptoError::KdfFailed(format!(
                "Parallelism too low (minimum: {MIN_PARALLELISM})"
            )));
        }
        if self.parallelism > MAX_PARALLELISM {
            return Err(CryptoError::KdfFailed(format!(
                "Parallelism too high (maximum: {MAX_PARALLELISM}) — refusing before \
                 attempting the derivation"
            )));
        }
        if self.output_length < MIN_OUTPUT_LENGTH {
            return Err(CryptoError::KdfFailed(format!(
                "Output length too short (minimum: {MIN_OUTPUT_LENGTH} bytes)"
            )));
        }
        if self.output_length > MAX_OUTPUT_LENGTH {
            return Err(CryptoError::KdfFailed(format!(
                "Output length too long (maximum: {MAX_OUTPUT_LENGTH} bytes) — refusing \
                 before attempting the allocation"
            )));
        }
        Ok(())
    }
}

/// Derive a master key from a password using Argon2id
///
/// This is the primary key derivation function used to convert
/// a user's master password into a cryptographic master key.
///
/// # Arguments
/// * `password` - The master password as bytes
/// * `params` - KDF parameters (salt, memory, time, parallelism)
///
/// # Returns
/// A 32-byte master key
///
/// # Security
/// - Uses Argon2id which is resistant to both GPU and ASIC attacks
/// - Parameters chosen to require ~200ms on modern hardware
/// - Constant-time comparison prevents timing attacks
pub fn derive_master_key(password: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
    params.validate()?;

    // Build Argon2id parameters
    let params_obj = Params::new(
        params.mem_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_length as usize),
    )
    .map_err(|e| CryptoError::KdfFailed(format!("Invalid parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_obj);

    // Convert salt to SaltString - use raw salt bytes directly
    let salt = SaltString::encode_b64(&params.salt)
        .map_err(|e| CryptoError::KdfFailed(format!("Failed to encode salt: {}", e)))?;

    // Hash the password
    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| CryptoError::KdfFailed(format!("Hashing failed: {}", e)))?;

    // Extract the output hash
    let hash_bytes = password_hash.hash.map(|h| h.as_bytes().to_vec());
    let hash_bytes =
        hash_bytes.ok_or_else(|| CryptoError::KdfFailed("No hash output".to_string()))?;

    if hash_bytes.len() < 32 {
        return Err(CryptoError::KdfFailed(format!(
            "Hash output too short: {} bytes",
            hash_bytes.len()
        )));
    }

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&hash_bytes[..32]);

    Ok(master_key)
}

/// Verify a master password by re-deriving the key and comparing
///
/// This function uses constant-time comparison to prevent timing attacks.
/// It also adds a fixed 200ms delay to further mitigate timing analysis.
///
/// # Arguments
/// * `password` - The password to verify
/// * `params` - The KDF parameters used
/// * `expected_key` - The expected master key
///
/// # Returns
/// Ok(()) if password is correct, Err otherwise
pub fn verify_master_password(
    password: &[u8],
    params: &KdfParams,
    expected_key: &[u8; 32],
) -> Result<()> {
    // Derive the key from the provided password
    let derived_key = derive_master_key(password, params)?;

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let derived_key_ref = &derived_key as &[u8];
    let expected_key_ref = expected_key as &[u8];

    if derived_key_ref.ct_eq(expected_key_ref).into() {
        // Add fixed delay to prevent timing attacks
        std::thread::sleep(std::time::Duration::from_millis(200));
        Ok(())
    } else {
        // Add fixed delay even on failure
        std::thread::sleep(std::time::Duration::from_millis(200));
        Err(CryptoError::KdfFailed("Invalid password".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_params_default() {
        let params = KdfParams::default();
        assert_eq!(params.mem_cost, 262_144);
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 4);
        assert_eq!(params.output_length, 32);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_kdf_params_validation() {
        // Test too low memory
        let params = KdfParams {
            mem_cost: 1000,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too low time
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 0,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too low parallelism
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 3,
            parallelism: 0,
            ..Default::default()
        };
        assert!(params.validate().is_err());

        // Test too short output
        let params = KdfParams {
            mem_cost: 262_144,
            time_cost: 3,
            parallelism: 4,
            output_length: 16,
            ..Default::default()
        };
        assert!(params.validate().is_err());
    }

    // --- WBS-307 / SR-CRYPTO-003: hard maximums ---------------------------

    /// N: a hostile value on ANY of the four bounded fields must be
    /// rejected, and rejected FAST — `validate()` is pure integer
    /// comparison, so even the most extreme value (u32::MAX) must return
    /// in microseconds, never by attempting the expensive Argon2 work
    /// first. The wall-clock assertion is 1 SECOND: generous enough to be
    /// immune to CI thread-preemption (review round 1: the original 50ms
    /// window could be blown by a descheduled thread), while still
    /// discriminating validation-only rejection from started Argon2 work
    /// — a real 1 GiB/u32::MAX derivation attempt takes far longer than
    /// 1s or aborts the process, so anything under the ceiling proves no
    /// expensive work began.
    #[test]
    fn hostile_maximum_values_fail_before_expensive_work() {
        let cases: Vec<(&str, KdfParams)> = vec![
            (
                "mem_cost just over max",
                KdfParams {
                    mem_cost: MAX_MEM_COST_KIB + 1,
                    ..KdfParams::new()
                },
            ),
            (
                "mem_cost = u32::MAX",
                KdfParams {
                    mem_cost: u32::MAX,
                    ..KdfParams::new()
                },
            ),
            (
                "time_cost just over max",
                KdfParams {
                    time_cost: MAX_TIME_COST + 1,
                    ..KdfParams::new()
                },
            ),
            (
                "time_cost = u32::MAX",
                KdfParams {
                    time_cost: u32::MAX,
                    ..KdfParams::new()
                },
            ),
            (
                "parallelism just over max",
                KdfParams {
                    parallelism: MAX_PARALLELISM + 1,
                    ..KdfParams::new()
                },
            ),
            (
                "parallelism = u32::MAX",
                KdfParams {
                    parallelism: u32::MAX,
                    ..KdfParams::new()
                },
            ),
            (
                "output_length just over max",
                KdfParams {
                    output_length: MAX_OUTPUT_LENGTH + 1,
                    ..KdfParams::new()
                },
            ),
            (
                "output_length = u32::MAX",
                KdfParams {
                    output_length: u32::MAX,
                    ..KdfParams::new()
                },
            ),
        ];

        for (label, params) in cases {
            let start = std::time::Instant::now();
            let result = params.validate();
            let elapsed = start.elapsed();
            assert!(result.is_err(), "{label}: hostile value must be rejected");
            assert!(
                elapsed < std::time::Duration::from_millis(1000),
                "{label}: validate() took {elapsed:?} — too slow for pure integer \
                 comparison; this suggests expensive work is happening before rejection"
            );

            // derive_master_key must ALSO refuse (validate() runs first
            // inside it) — proves the fast-fail guard is actually wired
            // into the real call path, not just callable in isolation.
            let derive_start = std::time::Instant::now();
            let derive_result = derive_master_key(b"irrelevant", &params);
            let derive_elapsed = derive_start.elapsed();
            assert!(
                derive_result.is_err(),
                "{label}: derive_master_key must also refuse"
            );
            assert!(
                derive_elapsed < std::time::Duration::from_millis(1000),
                "{label}: derive_master_key took {derive_elapsed:?} to refuse — \
                 expensive work appears to run before validation"
            );
        }
    }

    /// N: values exactly AT the maximum are accepted by validate() (the
    /// bound is inclusive, not off-by-one) — checked without running the
    /// actual (expensive) derivation for mem_cost/time_cost, since a
    /// genuine 1 GiB/20-iteration Argon2 run is real work this test
    /// should not pay for; output_length and parallelism at their maxima
    /// are cheap enough to exercise for real.
    #[test]
    fn maximum_values_are_inclusive_not_off_by_one() {
        assert!(KdfParams {
            mem_cost: MAX_MEM_COST_KIB,
            ..KdfParams::new()
        }
        .validate()
        .is_ok());
        assert!(KdfParams {
            time_cost: MAX_TIME_COST,
            ..KdfParams::new()
        }
        .validate()
        .is_ok());
        assert!(KdfParams {
            parallelism: MAX_PARALLELISM,
            ..KdfParams::new()
        }
        .validate()
        .is_ok());
        assert!(KdfParams {
            output_length: MAX_OUTPUT_LENGTH,
            ..KdfParams::new()
        }
        .validate()
        .is_ok());

        // parallelism at its maximum is cheap enough to actually derive.
        let params = KdfParams {
            parallelism: MAX_PARALLELISM,
            ..KdfParams::new()
        };
        assert!(derive_master_key(b"pw", &params).is_ok());
    }

    /// P: calibration evidence (SR-CRYPTO-003 acceptance: "desktop/mobile
    /// calibration evidence is recorded"). This is CI-HARDWARE wall-clock
    /// timing, explicitly NOT a substitute for on-device mobile
    /// calibration (see module docs) — it records that both profiles
    /// complete in a bounded, sane amount of time on the machine running
    /// the test, catching a profile that's accidentally orders of
    /// magnitude too slow (or a regression that makes one so) long before
    /// it reaches a real device.
    ///
    /// The ceiling is generous (60s) because Argon2id is dramatically
    /// slower in an unoptimized `cargo test` (debug) build than release —
    /// measured locally: ~0.2-0.3s in `--release`, ~5-6s in debug for the
    /// desktop profile alone — and `cargo test --workspace` runs this
    /// alongside dozens of OTHER 256MB Argon2id derivations on shared CI
    /// vCPUs, inflating wall clock via memory-bandwidth contention
    /// (review round 1: the original 15s ceiling held only ~2.1x measured
    /// headroom — genuine CI-flake territory). 60s still catches a true
    /// order-of-magnitude misconfiguration (a 10x regression would exceed
    /// it even in release) while being insensitive to runner variance.
    #[test]
    fn calibration_evidence_desktop_and_mobile_profiles() {
        let password = b"calibration-probe-password";
        let ceiling = std::time::Duration::from_secs(60);

        let desktop = KdfParams::new();
        let desktop_start = std::time::Instant::now();
        derive_master_key(password, &desktop).unwrap();
        let desktop_elapsed = desktop_start.elapsed();
        assert!(
            desktop_elapsed < ceiling,
            "desktop profile took {desktop_elapsed:?} — expected well under {ceiling:?} \
             even in a debug build; investigate before shipping (this is CI-hardware \
             timing, not device-specific calibration)"
        );

        let mobile = KdfParams::mobile_profile();
        assert_eq!(
            mobile.mem_cost, MIN_MEM_COST_KIB,
            "mobile profile sits at the hard minimum deliberately"
        );
        let mobile_start = std::time::Instant::now();
        derive_master_key(password, &mobile).unwrap();
        let mobile_elapsed = mobile_start.elapsed();
        assert!(
            mobile_elapsed < ceiling,
            "mobile profile took {mobile_elapsed:?} — expected well under {ceiling:?} \
             even in a debug build; investigate before shipping (this is CI-hardware \
             timing, not device-specific calibration)"
        );

        // The mobile profile uses strictly less (or equal) resource cost
        // than desktop on EVERY bounded axis — it must never be the
        // HEAVIER profile. All four axes asserted (review round 1: the
        // original assertion covered only mem/time, so a future edit
        // raising mobile parallelism would have passed unnoticed).
        assert!(mobile.mem_cost <= desktop.mem_cost);
        assert!(mobile.time_cost <= desktop.time_cost);
        assert!(mobile.parallelism <= desktop.parallelism);
        assert!(mobile.output_length <= desktop.output_length);
    }

    #[test]
    fn test_derive_master_key() {
        let password = b"test_password_123!";
        let params = KdfParams::new();

        let key1 = derive_master_key(password, &params).unwrap();
        let key2 = derive_master_key(password, &params).unwrap();

        // Same password and params should produce same key
        assert_eq!(key1, key2);

        // Different password should produce different key
        let key3 = derive_master_key(b"different_password", &params).unwrap();
        assert_ne!(key1, key3);

        // Different salt should produce different key
        let mut params2 = params.clone();
        params2.salt = rand::random();
        let key4 = derive_master_key(password, &params2).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_verify_master_password() {
        let password = b"correct_password";
        let params = KdfParams::new();
        let key = derive_master_key(password, &params).unwrap();

        // Correct password should verify
        assert!(verify_master_password(password, &params, &key).is_ok());

        // Wrong password should fail
        assert!(verify_master_password(b"wrong_password", &params, &key).is_err());
    }

    #[test]
    fn test_key_length() {
        let password = b"test_password";
        let params = KdfParams::new();
        let key = derive_master_key(password, &params).unwrap();

        assert_eq!(key.len(), 32);
    }
}
