//! Sync data models: wire format, entry types, and device identity.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CredentialType;

/// Type of syncable entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncEntryType {
    Credential,
    SshKey,
    TotpSecret,
}

/// Sync state of a local entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Synced,
    Pending,
    Conflict,
}

impl SyncState {
    /// Convert sync state to its string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Pending => "pending",
            Self::Conflict => "conflict",
        }
    }

    /// Parse a sync state from its string representation.
    pub fn parse(s: &str) -> Self {
        match s {
            "synced" => Self::Synced,
            "conflict" => Self::Conflict,
            _ => Self::Pending,
        }
    }
}

/// A single entry blob for sync transport.
///
/// The `encrypted_payload` is `nonce(12) || ciphertext || auth_tag(16)`,
/// encrypted with the vault DEK via AES-256-GCM. Domain mappings are
/// included inside credential payloads (never sent separately).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntryBlob {
    /// Stable identifier across devices (not local entry_id).
    pub sync_id: Uuid,
    /// Entry type discriminator.
    pub entry_type: SyncEntryType,
    /// Monotonic per-entry version counter.
    pub sync_version: u64,
    /// Unix timestamp (cleartext hint for LWW ordering).
    pub modified_at: i64,
    /// `nonce(12) || ciphertext || auth_tag(16)` encrypted with DEK.
    #[serde(with = "base64_bytes")]
    pub encrypted_payload: Vec<u8>,
    /// Whether this entry has been soft-deleted.
    pub is_tombstone: bool,
    /// Device that last modified this entry.
    pub origin_device_id: Uuid,
}

/// Decrypted credential data transported over sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPayload {
    pub title: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub credential_type: CredentialType,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub domains: Vec<DomainPayload>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Domain mapping within a credential sync payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPayload {
    pub domain: String,
    pub is_primary: bool,
}

/// Decrypted SSH key data transported over sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyPayload {
    pub name: String,
    pub comment: Option<String>,
    pub key_type: String,
    pub key_size: Option<i64>,
    pub public_key: String,
    pub private_key_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub fingerprint: String,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Decrypted TOTP secret data transported over sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpPayload {
    pub secret_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub created_at: i64,
    /// The sync_id of the parent credential (so the receiving device
    /// can re-link `totp_secrets.entry_id`).
    pub parent_credential_sync_id: Option<Uuid>,
}

/// Bootstrap blob sent during device pairing (encrypted with pairing key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBootstrap {
    /// KDF parameters (salt, mem_cost, etc.) so new device can derive master key.
    pub kdf_params_blob: Vec<u8>,
    /// Wrapped DEK blob (encrypted with master key).
    pub wrapped_dek_blob: Vec<u8>,
    /// Relay server URL.
    pub relay_url: String,
    /// Vault identifier on the relay.
    pub vault_id: Uuid,
    /// Master-password key epoch (ADR-002) of the exporting vault at the
    /// time of export. Required to unwrap an epoch-bound `wrapped_dek_blob`
    /// (produced after a rotation) — the wrap binds `key_epoch` as AEAD
    /// associated data, so importing without it fails GCM authentication.
    /// Defaults to 1 (the un-rotated epoch) so bootstraps produced by
    /// binaries that predate this field still deserialize.
    #[serde(default = "default_key_epoch")]
    pub key_epoch: i64,
}

fn default_key_epoch() -> i64 {
    1
}

/// Current sync status summary for the local device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub enabled: bool,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub relay_url: Option<String>,
    pub last_sync_at: Option<i64>,
    pub pending_changes: u64,
}

/// Information about a registered sync device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDeviceInfo {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub public_key: Vec<u8>,
    pub registered_at: i64,
    pub last_sync: Option<i64>,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
}

/// Request body for pushing local changes to the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub device_sequence: u64,
    pub entries: Vec<SyncEntryBlob>,
}

/// Relay response after a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub server_sequence: u64,
}

/// Request body for pulling remote changes from the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub since_sequence: u64,
    pub limit: Option<u64>,
}

/// Relay response containing pulled entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub entries: Vec<SyncEntryBlob>,
    /// Pagination cursor: the last returned server sequence in this page.
    pub server_sequence: u64,
    pub has_more: bool,
}

/// Custom base64 serialization for `Vec<u8>`.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_state_roundtrip() {
        for state in [SyncState::Synced, SyncState::Pending, SyncState::Conflict] {
            assert_eq!(SyncState::parse(state.as_str()), state);
        }
    }

    #[test]
    fn sync_entry_blob_serialization() {
        let blob = SyncEntryBlob {
            sync_id: Uuid::new_v4(),
            entry_type: SyncEntryType::Credential,
            sync_version: 1,
            modified_at: 1700000000,
            encrypted_payload: vec![1, 2, 3, 4, 5],
            is_tombstone: false,
            origin_device_id: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: SyncEntryBlob = serde_json::from_str(&json).unwrap();

        assert_eq!(blob.sync_id, deserialized.sync_id);
        assert_eq!(blob.sync_version, deserialized.sync_version);
        assert_eq!(blob.encrypted_payload, deserialized.encrypted_payload);
    }

    #[test]
    fn credential_payload_serialization() {
        let payload = CredentialPayload {
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            credential_type: CredentialType::Password,
            url: Some("https://example.com".to_string()),
            notes: None,
            favorite: false,
            domains: vec![DomainPayload {
                domain: "example.com".to_string(),
                is_primary: true,
            }],
            created_at: 1700000000,
            modified_at: 1700000000,
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: CredentialPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.title, deserialized.title);
        assert_eq!(payload.domains.len(), deserialized.domains.len());
    }
}
