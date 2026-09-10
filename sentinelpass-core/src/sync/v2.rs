//! Sync protocol v2 wire schema (ADR-006, WBS-601).
//!
//! A v2 mutation carries vault UUID/epoch, stable object UUID/type, expected
//! and resulting versions, origin device, mutation idempotency key,
//! authenticated tombstone state, the encrypted payload, and a DEK-derived
//! MAC over the canonical shared metadata. Three counters that v1 mixed into
//! one `u64` are DISTINCT newtypes here (WBS-602 / SR-SYNC-002):
//! [`DeviceSequence`] (per-device push framing), [`ObjectVersion`] (per-object
//! monotonic version), and [`ServerCursor`] (relay-side vault log cursor).
//! No `From` conversion exists between them, so cross-assignment is a
//! compile-time error and the serde payload names each field distinctly.
//!
//! IDENTITY-DOMAIN SPLIT (WBS-612 preview, documented here because the field
//! exists from v1 of this module): the metadata MAC is derived from the DEK
//! over the CANONICAL SHARED metadata (vault/object UUIDs, versions, epoch,
//! tombstone state) and is a *protocol/wire* authentication — every paired
//! device can compute and verify it, and it travels with the routing
//! metadata so a relay cannot rewrite identity, type, versions, epoch, or
//! tombstone state undetected. It is deliberately DISTINCT from the ADR-005
//! per-device *storage* envelope, which binds a ciphertext to the LOCAL
//! vault identity (vault UUID + object identity + purpose + envelope schema)
//! for at-rest integrity and is never present on the wire. Wire objects
//! never carry another device's storage envelope.

use crate::crypto::cipher::DataEncryptionKey;
use crate::crypto::CryptoError;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// HKDF `info` label binding the sync metadata MAC key to its purpose
/// (ADR-006 / WBS-612). One PRF key per input domain: this label is distinct
/// from every `crypto::keyring` label so the wire-MAC domain never shares
/// key material with the registry-equality, domain-tag, audit, or ADR-005
/// storage-envelope domains.
pub const METADATA_MAC_KEY_INFO: &[u8] = b"sentinelpass-sync-metadata-mac-v2";

/// Canonical metadata version tag included verbatim at the head of the MAC
/// input so a future metadata canonicalization cannot be replayed against
/// this one.
const METADATA_MAC_VERSION: &[u8] = b"sp-sync-v2-meta/1";

/// The canonical wire tag for an entry type — pinned here (not delegated to
/// serde) because the MAC canonicalization must not move if the wire format
/// ever re-renames.
fn object_type_tag(t: crate::sync::models::SyncEntryType) -> &'static str {
    match t {
        crate::sync::models::SyncEntryType::Credential => "credential",
        crate::sync::models::SyncEntryType::SshKey => "ssh_key",
        crate::sync::models::SyncEntryType::TotpSecret => "totp_secret",
    }
}

/// Derive the DEK-bound sync metadata MAC key (WBS-612).
///
/// Deterministic for a given DEK — every paired device sharing the DEK
/// computes the same key, which is what makes the MAC verifiable end to end.
/// The returned buffer is zeroized on drop and must not be cached across
/// lock.
pub fn derive_metadata_mac_key(
    dek: &DataEncryptionKey,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, dek.as_bytes());
    let mut okm = zeroize::Zeroizing::new(vec![0u8; 32]);
    hk.expand(METADATA_MAC_KEY_INFO, okm.as_mut_slice())
        .map_err(|e| {
            CryptoError::KdfFailed(format!("sync metadata MAC key derivation failed: {}", e))
        })?;
    Ok(okm)
}

/// The canonical shared metadata a v2 mutation authenticates (ADR-006:
/// vault/object UUIDs, versions, epoch, tombstone state — plus origin device
/// and mutation id so replay of a MAC onto a different mutation fails).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationMetadata<'a> {
    pub vault_id: Uuid,
    pub object_id: Uuid,
    pub object_type: crate::sync::models::SyncEntryType,
    pub expected_version: u64,
    pub resulting_version: u64,
    pub key_epoch: i64,
    pub origin_device_id: Uuid,
    pub is_tombstone: bool,
    pub mutation_id: Uuid,
    pub payload_sha256: &'a [u8],
}

impl MutationMetadata<'_> {
    /// Canonical, deterministic wire-independent encoding of the metadata.
    ///
    /// Field-position, delimiter-separated, fixed version tag first: cheap,
    /// unambiguous, and stable across serde versions (the canonical form is
    /// deliberately NOT JSON so no serializer behavior change can silently
    /// invalidate stored MACs).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(METADATA_MAC_VERSION);
        out.push(b'|');
        out.extend_from_slice(self.vault_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.object_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(object_type_tag(self.object_type).as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.expected_version.to_be_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.resulting_version.to_be_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.push(b'|');
        out.extend_from_slice(self.origin_device_id.as_bytes());
        out.push(b'|');
        out.push(u8::from(self.is_tombstone));
        out.push(b'|');
        out.extend_from_slice(self.mutation_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.payload_sha256);
        out
    }

    /// Compute the DEK-derived MAC over the canonical metadata.
    pub fn mac(&self, mac_key: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
            .map_err(|e| CryptoError::KdfFailed(format!("sync metadata MAC init failed: {}", e)))?;
        mac.update(&self.canonical_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    /// Verify a metadata MAC in constant time (`hmac::Mac::verify_slice`).
    pub fn verify_mac(&self, mac_key: &[u8], mac: &[u8]) -> Result<bool, CryptoError> {
        let mut verifier = Hmac::<Sha256>::new_from_slice(mac_key)
            .map_err(|e| CryptoError::KdfFailed(format!("sync metadata MAC init failed: {}", e)))?;
        verifier.update(&self.canonical_bytes());
        Ok(verifier.verify_slice(mac).is_ok())
    }
}

// ---------------------------------------------------------------------------
// WBS-602: distinct sequence/version/cursor types
// ---------------------------------------------------------------------------

/// Per-device push framing counter. Diagnostic ordering metadata only in v2 —
/// correctness comes from mutation idempotency keys and per-object CAS, so a
/// lost checkpoint can never wedge a device (the v1 strictly-increasing gate
/// is gone; see [`super::engine`]). Deliberately NOT interchangeable with
/// [`ObjectVersion`] or [`ServerCursor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceSequence(pub u64);

/// Per-object monotonic version. The ONLY counter that gates acceptance
/// (relay CAS: a mutation applies iff `expected_version` equals the stored
/// current version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectVersion(pub u64);

impl ObjectVersion {
    pub const INITIAL: ObjectVersion = ObjectVersion(0);
    /// The version this mutation produces from an expected version.
    ///
    /// Checked: `ObjectVersion` arithmetic never silently wraps (WBS-602 —
    /// v1 mixed these domains with plain `u64` addition).
    pub fn next(self) -> Option<ObjectVersion> {
        self.0.checked_add(1).map(ObjectVersion)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ObjectVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Relay-side vault log cursor (pagination + lineage high-water domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServerCursor(pub u64);

impl ServerCursor {
    /// True when `self` is AT OR BELOW a previously trusted high-water —
    /// i.e. the relay offered a lineage that moves the client backwards
    /// (suspected rollback / wrong vault; WBS-613).
    pub fn at_or_below(self, high_water: ServerCursor) -> bool {
        self <= high_water
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Wire objects
// ---------------------------------------------------------------------------

/// A single v2 mutation (client → relay).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MutationV2 {
    /// Idempotency key: stable across retries of the SAME mutation
    /// (deterministically derived — see [`mutation_id_for`]), unique per
    /// distinct edit.
    pub mutation_id: Uuid,
    /// Vault this mutation belongs to (routing + epoch scope).
    pub vault_id: Uuid,
    /// Stable object identity (the v1 `sync_id`).
    pub object_id: Uuid,
    pub object_type: crate::sync::models::SyncEntryType,
    /// Version the sender believes the relay currently stores. The relay
    /// applies iff this equals the stored current version (CAS; 0 = create).
    pub expected_version: ObjectVersion,
    /// Version this mutation produces (> expected; the sender's new local
    /// version).
    pub resulting_version: ObjectVersion,
    /// Vault key epoch at mutation-creation time (ADR-004/ADR-006: stale
    /// devices holding a pre-rotation DEK are rejected).
    pub key_epoch: i64,
    pub origin_device_id: Uuid,
    /// Authenticated tombstone state (covered by the MAC — a relay cannot
    /// flip a delete to a live entry undetected).
    pub is_tombstone: bool,
    /// `nonce(12) || ciphertext || tag`, DEK-encrypted. Tombstones carry the
    /// canonical tombstone marker document (same as v1).
    #[serde(with = "crate::sync::models::base64_bytes")]
    pub encrypted_payload: Vec<u8>,
    /// Base64 HMAC-SHA256 over the canonical shared metadata under the
    /// DEK-derived MAC key (WBS-612).
    #[serde(with = "base64_mac")]
    pub metadata_mac: [u8; 32],
}

/// Base64 serde for the fixed-width metadata MAC.
mod base64_mac {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(mac: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        base64::engine::general_purpose::STANDARD
            .encode(mac)
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("metadata MAC must be exactly 32 bytes"))
    }
}

/// Why the relay rejected a mutation (durable — replayed verbatim to
/// duplicate retries of the same `mutation_id`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum RejectionReason {
    /// CAS failure: the relay stores a different version than
    /// `expected_version`. A concurrent edit on another device won; the
    /// sender keeps its local alternative as a conflict (WBS-611) rather
    /// than overwriting.
    VersionConflict { current_version: ObjectVersion },
    /// The mutation's `key_epoch` is below the vault's current epoch —
    /// suspected stale/revoked-key device (ADR-004 rev 4 / WBS-614).
    StaleEpoch { vault_epoch: i64 },
    /// Static validation failed (shape, size, type whitelist). Terminal.
    Malformed,
}

/// The durable per-object result of one mutation (SR-SYNC-001).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MutationResult {
    pub mutation_id: Uuid,
    pub object_id: Uuid,
    pub outcome: MutationOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum MutationOutcome {
    /// Applied (or a duplicate of a mutation that was applied — the ORIGINAL
    /// result is returned, per ADR-006; duplicates are indistinguishable
    /// from first-time acks by design).
    Applied {
        resulting_version: ObjectVersion,
        server_sequence: ServerCursor,
    },
    Rejected {
        reason: RejectionReason,
    },
}

impl MutationOutcome {
    /// True only for a first-time-or-replayed `Applied` ack.
    pub fn is_applied(&self) -> bool {
        matches!(self, MutationOutcome::Applied { .. })
    }
}

/// Request body for `POST /api/v2/sync/push`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequestV2 {
    /// Distinct framing counter (WBS-602). Recorded, never gated on: v2
    /// retries intentionally re-send the same counter, and idempotency —
    /// not monotonicity — deduplicates them.
    pub device_sequence: DeviceSequence,
    pub mutations: Vec<MutationV2>,
}

/// Response for `POST /api/v2/sync/push`: one durable result per mutation,
/// in request order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponseV2 {
    /// The vault log's current head after this push.
    pub server_cursor: ServerCursor,
    pub results: Vec<MutationResult>,
}

/// Request body for `POST /api/v2/sync/pull`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestV2 {
    /// Client's server-log cursor (last seen `server_sequence`).
    pub since: ServerCursor,
    pub limit: Option<u32>,
}

/// One appended mutation in the vault's server log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationLogEntry {
    pub server_sequence: ServerCursor,
    pub mutation: MutationV2,
}

/// Response for `POST /api/v2/sync/pull`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponseV2 {
    pub entries: Vec<MutationLogEntry>,
    /// Pagination cursor = the last returned `server_sequence` (unchanged
    /// from the request cursor for an empty page).
    pub cursor: ServerCursor,
    pub has_more: bool,
}

/// Deterministic namespace for v2 mutation ids (random UUID pinned once —
/// any fixed value works; it only separates this id space from other v5 uses).
const MUTATION_ID_NAMESPACE: Uuid = Uuid::from_u128(0x7370_5f73_796e_635f_7632_0000_0000_0001);

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::VersionConflict { current_version } => {
                write!(f, "version conflict (relay holds v{current_version})")
            }
            RejectionReason::StaleEpoch { vault_epoch } => {
                write!(f, "stale key epoch (vault epoch {vault_epoch})")
            }
            RejectionReason::Malformed => write!(f, "malformed mutation"),
        }
    }
}

/// Derive the idempotency key for a mutation deterministically (WBS-603).
///
/// The key is (vault, object, resulting_version): every LOCAL edit bumps the
/// row's `sync_version` monotonically (repository update rule), so these
/// three coordinates are unique per distinct mutation attempt, and a RETRY
/// of the same attempt — re-collected from the still-pending row — derives
/// the SAME id even though the payload re-encrypts under a fresh GCM nonce.
/// (The payload bytes are deliberately NOT part of the id: they are
/// per-encryption randomized.) The id is a UUIDv5-shaped digest: SHA-256
/// over (namespace || canonical inputs), truncated, with version/variant
/// bits set — no dependency on serde or time.
pub fn mutation_id_for(vault_id: Uuid, object_id: Uuid, resulting_version: ObjectVersion) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_ID_NAMESPACE.as_bytes());
    hasher.update(vault_id.as_bytes());
    hasher.update(object_id.as_bytes());
    hasher.update(resulting_version.0.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122: version 5 (SHA-1 namespace shape, reused for SHA-256 here —
    // the version nibble is an id-space marker, not a security claim) and
    // the RFC 4122 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Everything `build_mutation` needs, named (no positional-argument
/// transposition risk — the ADR-005 `AadContextBuilder` lesson).
#[derive(Debug, Clone)]
pub struct MutationInput {
    pub vault_id: Uuid,
    pub object_id: Uuid,
    pub object_type: crate::sync::models::SyncEntryType,
    pub expected_version: ObjectVersion,
    pub resulting_version: ObjectVersion,
    pub key_epoch: i64,
    pub origin_device_id: Uuid,
    pub is_tombstone: bool,
    pub encrypted_payload: Vec<u8>,
}

/// Build a [`MutationV2`] from its parts, computing the deterministic
/// mutation id and the metadata MAC.
pub fn build_mutation(mac_key: &[u8], input: &MutationInput) -> Result<MutationV2, CryptoError> {
    let mutation_id = mutation_id_for(input.vault_id, input.object_id, input.resulting_version);
    let payload_sha256 = Sha256::digest(&input.encrypted_payload);
    let metadata = MutationMetadata {
        vault_id: input.vault_id,
        object_id: input.object_id,
        object_type: input.object_type,
        expected_version: input.expected_version.0,
        resulting_version: input.resulting_version.0,
        key_epoch: input.key_epoch,
        origin_device_id: input.origin_device_id,
        is_tombstone: input.is_tombstone,
        mutation_id,
        payload_sha256: &payload_sha256,
    };
    let metadata_mac = metadata.mac(mac_key)?;
    Ok(MutationV2 {
        mutation_id,
        vault_id: input.vault_id,
        object_id: input.object_id,
        object_type: input.object_type,
        expected_version: input.expected_version,
        resulting_version: input.resulting_version,
        key_epoch: input.key_epoch,
        origin_device_id: input.origin_device_id,
        is_tombstone: input.is_tombstone,
        encrypted_payload: input.encrypted_payload.clone(),
        metadata_mac,
    })
}

/// Recompute/verify a mutation's metadata MAC on the receiving side.
pub fn verify_mutation_mac(mac_key: &[u8], mutation: &MutationV2) -> Result<bool, CryptoError> {
    let payload_sha256 = Sha256::digest(&mutation.encrypted_payload);
    let metadata = MutationMetadata {
        vault_id: mutation.vault_id,
        object_id: mutation.object_id,
        object_type: mutation.object_type,
        expected_version: mutation.expected_version.0,
        resulting_version: mutation.resulting_version.0,
        key_epoch: mutation.key_epoch,
        origin_device_id: mutation.origin_device_id,
        is_tombstone: mutation.is_tombstone,
        mutation_id: mutation.mutation_id,
        payload_sha256: &payload_sha256,
    };
    metadata.verify_mac(mac_key, &mutation.metadata_mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::models::SyncEntryType;

    fn test_dek() -> DataEncryptionKey {
        DataEncryptionKey::new().unwrap()
    }

    fn sample_mutation(dek: &DataEncryptionKey) -> MutationV2 {
        let mac_key = derive_metadata_mac_key(dek).unwrap();
        build_mutation(
            &mac_key,
            &MutationInput {
                vault_id: Uuid::from_u128(1),
                object_id: Uuid::from_u128(2),
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(3),
                resulting_version: ObjectVersion(4),
                key_epoch: 1,
                origin_device_id: Uuid::from_u128(3),
                is_tombstone: false,
                encrypted_payload: vec![1, 2, 3, 4, 5],
            },
        )
        .unwrap()
    }

    // --- WBS-602: distinct counter domains ---------------------------------

    /// The three counter types serialize under DISTINCT field names in the
    /// v2 wire objects; a cursor can never masquerade as a version or a
    /// device sequence because the types do not unify (no `From` impls —
    /// this test additionally pins the serde shapes).
    #[test]
    fn counter_types_have_distinct_wire_fields() {
        let req = PushRequestV2 {
            device_sequence: DeviceSequence(7),
            mutations: vec![],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["device_sequence"], 7);
        assert!(json.get("server_cursor").is_none());

        let pull = PullRequestV2 {
            since: ServerCursor(9),
            limit: Some(10),
        };
        let json = serde_json::to_value(pull).unwrap();
        assert_eq!(json["since"], 9);

        let outcome = MutationOutcome::Applied {
            resulting_version: ObjectVersion(4),
            server_sequence: ServerCursor(11),
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["resulting_version"], 4);
        assert_eq!(json["server_sequence"], 11);
    }

    /// Cursor ordering semantics used by the client high-water check.
    #[test]
    fn server_cursor_lineage_comparisons() {
        let high = ServerCursor(42);
        assert!(ServerCursor(41).at_or_below(high));
        assert!(ServerCursor(42).at_or_below(high));
        assert!(!ServerCursor(43).at_or_below(high));
    }

    #[test]
    fn object_version_next_is_checked() {
        assert_eq!(ObjectVersion(3).next(), Some(ObjectVersion(4)));
        assert_eq!(ObjectVersion(u64::MAX).next(), None);
        assert_eq!(ObjectVersion::INITIAL, ObjectVersion(0));
    }

    // --- WBS-601: mutation schema + MAC ------------------------------------

    #[test]
    fn mutation_roundtrips_through_json() {
        let dek = test_dek();
        let mutation = sample_mutation(&dek);
        let json = serde_json::to_string(&mutation).unwrap();
        let back: MutationV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(mutation, back);
    }

    #[test]
    fn metadata_mac_is_deterministic_and_verifies() {
        let dek = test_dek();
        let mac_key = derive_metadata_mac_key(&dek).unwrap();
        let m1 = sample_mutation(&dek);
        let m2 = sample_mutation(&dek);
        assert_eq!(m1.metadata_mac, m2.metadata_mac, "deterministic build");
        assert!(verify_mutation_mac(&mac_key, &m1).unwrap());

        // A different DEK derives a different MAC key.
        let other_key = derive_metadata_mac_key(&test_dek()).unwrap();
        assert!(!verify_mutation_mac(&other_key, &m1).unwrap());
    }

    /// THE metadata-tamper negatives (SR-SYNC-004 core): every
    /// relay-writable metadata field is MAC-covered — flipping any one of
    /// them (identity, type, versions, epoch, origin, tombstone, payload)
    /// breaks verification.
    #[test]
    fn metadata_mac_covers_every_shared_field() {
        let dek = test_dek();
        let mac_key = derive_metadata_mac_key(&dek).unwrap();
        let base = sample_mutation(&dek);
        assert!(verify_mutation_mac(&mac_key, &base).unwrap());

        let mut tampered = base.clone();
        tampered.vault_id = Uuid::from_u128(999);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "vault_id"
        );

        let mut tampered = base.clone();
        tampered.object_id = Uuid::from_u128(999);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "object_id"
        );

        let mut tampered = base.clone();
        tampered.object_type = SyncEntryType::SshKey;
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "object_type"
        );

        let mut tampered = base.clone();
        tampered.expected_version = ObjectVersion(2);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "expected_version"
        );

        let mut tampered = base.clone();
        tampered.resulting_version = ObjectVersion(5);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "resulting_version"
        );

        let mut tampered = base.clone();
        tampered.key_epoch = 7;
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "key_epoch"
        );

        let mut tampered = base.clone();
        tampered.origin_device_id = Uuid::from_u128(999);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "origin_device_id"
        );

        let mut tampered = base.clone();
        tampered.is_tombstone = true;
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "is_tombstone"
        );

        let mut tampered = base.clone();
        tampered.mutation_id = Uuid::from_u128(999);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "mutation_id"
        );

        let mut tampered = base.clone();
        tampered.encrypted_payload.push(0xFF);
        assert!(
            !verify_mutation_mac(&mac_key, &tampered).unwrap(),
            "payload bytes"
        );

        // Truncated / substituted MACs fail closed.
        assert!(!metadata_verify_truncated(&mac_key, &base).unwrap());
    }

    fn metadata_verify_truncated(mac_key: &[u8], m: &MutationV2) -> Result<bool, CryptoError> {
        let payload_sha256 = Sha256::digest(&m.encrypted_payload);
        let metadata = MutationMetadata {
            vault_id: m.vault_id,
            object_id: m.object_id,
            object_type: m.object_type,
            expected_version: m.expected_version.0,
            resulting_version: m.resulting_version.0,
            key_epoch: m.key_epoch,
            origin_device_id: m.origin_device_id,
            is_tombstone: m.is_tombstone,
            mutation_id: m.mutation_id,
            payload_sha256: &payload_sha256,
        };
        metadata.verify_mac(mac_key, &m.metadata_mac[..31])
    }

    // --- WBS-603: deterministic idempotency keys ---------------------------

    #[test]
    fn mutation_id_is_stable_across_retries() {
        let a = mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(2), ObjectVersion(4));
        let b = mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(2), ObjectVersion(4));
        assert_eq!(a, b, "the same mutation retried must reuse its id");
    }

    #[test]
    fn mutation_id_diverges_per_object_and_version_and_vault() {
        let base = mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(2), ObjectVersion(4));
        assert_ne!(
            base,
            mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(2), ObjectVersion(5)),
            "the next local edit (bumped version) is a NEW mutation"
        );
        assert_ne!(
            base,
            mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(77), ObjectVersion(4)),
        );
        assert_ne!(
            base,
            mutation_id_for(Uuid::from_u128(88), Uuid::from_u128(2), ObjectVersion(4)),
        );
    }

    #[test]
    fn mutation_id_is_uuid_shaped() {
        let id = mutation_id_for(Uuid::from_u128(1), Uuid::from_u128(2), ObjectVersion(1));
        assert_eq!(id.get_version_num(), 5, "id must be UUID-shaped");
        assert_ne!(id, Uuid::nil());
    }
}
