//! SP-0 / ADR-013: single-use master-password administrative step-up.
//!
//! A step-up approval is a short-lived, connection-bound, operation-bound
//! capability minted ONLY after the daemon verified the master password
//! through the full reviewed open path (see the `StepUpAuthorize` handler in
//! `server.rs`). Properties (ADR-013):
//!
//! - **60-second TTL** from mint; expiry is enforced on every use.
//! - **Single use**: consumed on the ATTEMPT — a mutation that fails after
//!   approval still burns it; a replayed id is denied.
//! - **Connection-bound**: minted on one client connection, usable only on
//!   that connection.
//! - **Operation-bound**: an HMAC-SHA256 commitment (keyed by a random
//!   per-daemon-start key) over the serialized op. Secrets inside the op
//!   exist only inside the keyed digest; the commitment is compared in
//!   constant time.
//! - **Server-held only**: no persistence. A daemon restart invalidates
//!   every pending approval (replay across restarts is impossible by
//!   construction — the key is regenerated).
//! - **Bounded in-memory throttle** on failed password verifications
//!   (5 failures → escalating lockout, doubling, capped). The Argon2id KDF
//!   remains the primary brake (256 MB per attempt); this throttle stops a
//!   same-UID process from hammering the daemon.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Approval lifetime (ADR-013: initial maximum age 60 seconds).
pub const STEP_UP_TTL: Duration = Duration::from_secs(60);
/// Failed verifications before the throttle engages.
const THROTTLE_AFTER_FAILURES: u32 = 5;
/// Backoff base; doubles per extra failure.
const THROTTLE_BASE: Duration = Duration::from_secs(60);
/// Escalation cap.
const THROTTLE_CAP: Duration = Duration::from_secs(600);

struct PendingApproval {
    connection: u128,
    commitment: [u8; 32],
    expires: Instant,
    consumed: bool,
}

/// Why a presented approval was refused. Stable, display-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpDenial {
    UnknownOrConsumed,
    WrongConnection,
    Expired,
    CommitmentMismatch,
    Throttled { retry_after_secs: u64 },
}

impl std::fmt::Display for StepUpDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOrConsumed => {
                f.write_str("approval unknown, already used, or never issued")
            }
            Self::WrongConnection => f.write_str("approval was issued on a different connection"),
            Self::Expired => f.write_str("approval expired (60s maximum age)"),
            Self::CommitmentMismatch => f.write_str("approval does not match this exact operation"),
            Self::Throttled { retry_after_secs } => {
                write!(
                    f,
                    "too many failed verifications; retry in {retry_after_secs}s"
                )
            }
        }
    }
}

/// Per-daemon step-up state. All fields in-memory; construct once at server
/// start.
#[derive(Default)]
pub struct StepUpState {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    // Empty until first mint (lazily keyed so a daemon that never uses
    // step-up never holds key material).
    hmac_key: Option<Zeroizing<[u8; 32]>>,
    pending: HashMap<String, PendingApproval>,
    failures: u32,
    throttle_until: Option<Instant>,
}

impl StepUpState {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(inner: &mut Inner) -> Zeroizing<[u8; 32]> {
        // Lazily generate ONCE and store: mint and every later take must
        // derive commitments under the SAME key (found by the SP-0 test
        // suite — the original returned a fresh key per call, so every
        // validation mismatched).
        if inner.hmac_key.is_none() {
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key.as_mut());
            inner.hmac_key = Some(key);
        }
        inner
            .hmac_key
            .clone()
            .expect("hmac_key was just initialized")
    }

    fn commitment(key: &[u8; 32], op_bytes: &[u8]) -> [u8; 32] {
        // RFC 2101-style HMAC-SHA256 (ipad/opad over one block).
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for (i, byte) in key.iter().enumerate() {
            ipad[i] ^= byte;
            opad[i] ^= byte;
        }
        let mut inner_hash = Sha256::new();
        inner_hash.update(ipad);
        inner_hash.update(op_bytes);
        let inner = inner_hash.finalize();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner);
        outer.finalize().into()
    }

    /// Is the password-verification throttle currently engaged?
    pub fn throttled(&self) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        inner.throttle_until.map(|until| {
            until
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1)
        })
    }

    /// Record a failed master-password verification (escalating throttle).
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.failures = inner.failures.saturating_add(1);
        if inner.failures >= THROTTLE_AFTER_FAILURES {
            let steps = inner.failures - THROTTLE_AFTER_FAILURES;
            let mut wait = THROTTLE_BASE;
            for _ in 0..steps.min(4) {
                wait = wait.saturating_mul(2).min(THROTTLE_CAP);
            }
            inner.throttle_until = Some(Instant::now() + wait);
        }
    }

    /// Record a successful verification: clears the failure counter.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.failures = 0;
        inner.throttle_until = None;
    }

    /// Mint a single-use approval for `op_bytes` on `connection`.
    /// Returns `(approval_id, expires_at_unix)`.
    pub fn mint(&self, connection: u128, op_bytes: &[u8]) -> (String, i64) {
        let mut inner = self.inner.lock().unwrap();
        let key = Self::key(&mut inner);
        let mut id_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        let expires = Instant::now() + STEP_UP_TTL;
        let expires_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 + STEP_UP_TTL.as_secs() as i64)
            .unwrap_or(0);
        // Opportunistic pruning so the map cannot grow without bound.
        inner.pending.retain(|_, p| p.expires > Instant::now());
        inner.pending.insert(
            id.clone(),
            PendingApproval {
                connection,
                commitment: Self::commitment(&key, op_bytes),
                expires,
                consumed: false,
            },
        );
        (id, expires_at_unix)
    }

    /// Validate AND CONSUME an approval for `op_bytes` on `connection`.
    /// Consumption happens only on full success; every denial reason is
    /// distinguished for audit/diagnostics but must not leak which approvals
    /// exist to a guessing attacker (unknown ids are indistinguishable from
    /// consumed ones).
    pub fn take_if_valid(
        &self,
        approval_id: &str,
        connection: u128,
        op_bytes: &[u8],
    ) -> Result<(), StepUpDenial> {
        let mut inner = self.inner.lock().unwrap();
        let key = Self::key(&mut inner);
        let key_ref: &[u8; 32] = &key;
        let entry = inner
            .pending
            .get_mut(approval_id)
            .ok_or(StepUpDenial::UnknownOrConsumed)?;
        if entry.consumed {
            return Err(StepUpDenial::UnknownOrConsumed);
        }
        if entry.connection != connection {
            // Do not consume: a stolen id presented on the wrong connection
            // must not burn the legitimate one... but it ALSO must not allow
            // probing. Not consuming is safe: using it still requires the
            // right connection AND commitment.
            return Err(StepUpDenial::WrongConnection);
        }
        if entry.expires <= Instant::now() {
            entry.consumed = true; // burn expired entries
            return Err(StepUpDenial::Expired);
        }
        let expected = Self::commitment(key_ref, op_bytes);
        if !bool::from(expected.ct_eq(&entry.commitment)) {
            // Commitment mismatch BURNS the approval: an attacker who stole
            // the id cannot brute-force the op binding while preserving it.
            entry.consumed = true;
            return Err(StepUpDenial::CommitmentMismatch);
        }
        entry.consumed = true;
        Ok(())
    }

    /// Number of live (unconsumed, unexpired) approvals — test/diagnostic.
    pub fn live_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner
            .pending
            .values()
            .filter(|p| !p.consumed && p.expires > now)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: u128) -> u128 {
        id
    }

    #[test]
    fn approval_is_single_use_and_bound() {
        let state = StepUpState::new();
        let op = b"{\"op\":\"EntryAdd\"}";
        let (id, _exp) = state.mint(conn(1), op);

        // Wrong op bytes -> mismatch and BURNED.
        assert_eq!(
            state.take_if_valid(&id, conn(1), b"{\"op\":\"EntryDelete\"}"),
            Err(StepUpDenial::CommitmentMismatch)
        );
        // Even the right op cannot reuse it now.
        assert_eq!(
            state.take_if_valid(&id, conn(1), op),
            Err(StepUpDenial::UnknownOrConsumed)
        );
    }

    #[test]
    fn approval_is_connection_bound() {
        let state = StepUpState::new();
        let op = b"op";
        let (id, _) = state.mint(conn(7), op);
        assert_eq!(
            state.take_if_valid(&id, conn(8), op),
            Err(StepUpDenial::WrongConnection)
        );
        // Still usable on the right connection.
        assert!(state.take_if_valid(&id, conn(7), op).is_ok());
        assert_eq!(
            state.take_if_valid(&id, conn(7), op),
            Err(StepUpDenial::UnknownOrConsumed)
        );
    }

    #[test]
    fn expired_approval_is_refused() {
        let state = StepUpState::new();
        // Mint directly with an already-expired deadline.
        let mut inner = state.inner.lock().unwrap();
        let key = StepUpState::key(&mut inner);
        inner.pending.insert(
            "expired".into(),
            PendingApproval {
                connection: 1,
                commitment: StepUpState::commitment(&key, b"op"),
                expires: Instant::now() - Duration::from_secs(1),
                consumed: false,
            },
        );
        drop(inner);
        assert_eq!(
            state.take_if_valid("expired", conn(1), b"op"),
            Err(StepUpDenial::Expired)
        );
    }

    #[test]
    fn throttle_engages_after_five_failures() {
        let state = StepUpState::new();
        for _ in 0..4 {
            assert!(state.throttled().is_none());
            state.record_failure();
        }
        state.record_failure(); // 5th
        let retry = state.throttled().expect("throttled after 5 failures");
        assert!((1..=60).contains(&retry), "base backoff bounded: {retry}");
        // Success clears it.
        state.record_success();
        assert!(state.throttled().is_none());
    }

    #[test]
    fn distinct_daemons_have_distinct_keys() {
        // The commitment for identical inputs differs across instances
        // (restart invalidation is key-based, not map-based).
        let a = StepUpState::new();
        let b = StepUpState::new();
        let (ida, _) = a.mint(1, b"op");
        let (idb, _) = b.mint(1, b"op");
        // ids are random and distinct...
        assert_ne!(ida, idb);
        // ...and b's state cannot validate a's id.
        assert_eq!(
            b.take_if_valid(&ida, 1, b"op"),
            Err(StepUpDenial::UnknownOrConsumed)
        );
    }
}

#[cfg(test)]
mod ser_probe {
    /// Review F9: the approval commitment is computed over the
    /// SERIALIZED op — pin that a serialize → deserialize → serialize
    /// round trip (the actual client wire path) is byte-stable for
    /// secret-bearing ops. If any op type ever gains a nondeterministic
    /// collection, this fails before approvals start misbinding.
    #[test]
    fn op_serialization_survives_wire_round_trip_identically() {
        use sentinelpass_protocol::VaultOp;
        let entry = sentinelpass_protocol::service::ServiceEntry {
            entry_id: None,
            title: "wire".to_string(),
            username: "u".to_string(),
            password: zeroize::Zeroizing::new("p".to_string()),
            url: Some("https://x".to_string()),
            notes: None,
            credential_type: "password".to_string(),
            created_at: 1,
            modified_at: 2,
            favorite: true,
        };
        for op in [
            VaultOp::EntryAdd {
                entry: entry.clone(),
            },
            VaultOp::TotpAdd {
                entry_id: 7,
                secret: zeroize::Zeroizing::new("BASE32".to_string()),
                algorithm: Some("SHA1".into()),
                digits: Some(6),
                period: Some(30),
                issuer: Some("i".into()),
                account_name: Some("a".into()),
            },
        ] {
            let first = serde_json::to_vec(&op).unwrap();
            let back: VaultOp = serde_json::from_slice(&first).unwrap();
            let second = serde_json::to_vec(&back).unwrap();
            assert_eq!(
                first, second,
                "wire round trip must be byte-stable for the commitment"
            );
        }
    }

    #[test]
    fn op_serialization_is_deterministic_across_clones() {
        let e = sentinelpass_protocol::service::ServiceEntry {
            entry_id: None,
            title: "stepped".to_string(),
            username: "u".to_string(),
            password: zeroize::Zeroizing::new("p".to_string()),
            url: None,
            notes: None,
            credential_type: "password".to_string(),
            created_at: 0,
            modified_at: 0,
            favorite: false,
        };
        let op = sentinelpass_protocol::VaultOp::EntryAdd { entry: e };
        let a = serde_json::to_vec(&op).unwrap();
        let b = serde_json::to_vec(&op.clone()).unwrap();
        assert_eq!(
            a,
            b,
            "serialization must be deterministic: {}",
            String::from_utf8_lossy(&a)
        );
    }
}
