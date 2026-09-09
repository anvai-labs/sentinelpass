//! Application-service contract (WBS-408, ADR-007).
//!
//! This module is the single call shape every daemon client uses for vault
//! operations: one request enum ([`VaultOp`]), one result enum
//! ([`VaultOpResult`]), and one typed error ([`ServiceError`]). UI, CLI, and
//! native-host clients reach vault data ONLY by sending
//! `IpcMessage::ServiceCall` over IPC and receiving
//! `IpcMessage::ServiceResult`; the daemon is the sole DEK owner and vault
//! writer (ADR-007).
//!
//! Layering: this crate must not depend on `sentinelpass-core`, so the
//! service surface uses its own wire DTOs ([`ServiceEntry`],
//! [`ServiceEntrySummary`], ...). Conversions to/from the core types live in
//! `sentinelpass_core::daemon::service`.
//!
//! Compatibility: every new field must be `#[serde(default)]` so an older
//! client's frames still parse on a newer daemon and vice versa (same rule
//! as the rest of the protocol crate).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Wire DTO for one vault entry. `password` is plaintext on the IPC surface
/// — the same trust level as the pre-existing `GetCredential` response — and
/// is `Zeroizing` on both ends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    #[serde(default)]
    pub entry_id: Option<i64>,
    pub title: String,
    pub username: String,
    #[serde(default)]
    pub password: Zeroizing<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// `password | api_key | passkey_reference` (core `CredentialType`).
    #[serde(default = "default_credential_type")]
    pub credential_type: String,
    /// Unix epoch seconds.
    #[serde(default)]
    pub created_at: i64,
    /// Unix epoch seconds.
    #[serde(default)]
    pub modified_at: i64,
    #[serde(default)]
    pub favorite: bool,
}

fn default_credential_type() -> String {
    "password".to_string()
}

/// Wire DTO for one entry summary (no password — bulk listings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntrySummary {
    pub entry_id: i64,
    pub title: String,
    pub username: String,
    pub credential_type: String,
    pub favorite: bool,
}

/// Wire DTO for TOTP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTotpMetadata {
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

/// Wire DTO for an SSH key (decrypted view; `private_key` present only when
/// explicitly requested and authorized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSshKey {
    pub key_id: i64,
    pub name: String,
    pub comment: Option<String>,
    pub key_type: String,
    pub public_key: String,
    #[serde(default)]
    pub private_key: Option<Zeroizing<String>>,
    pub fingerprint: String,
    pub created_at: i64,
}

/// Wire DTO for an SSH key listing row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSshKeySummary {
    pub key_id: i64,
    pub name: String,
    pub comment: Option<String>,
    pub key_type: String,
    pub fingerprint: String,
}

/// Wire DTO for one registry entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntity {
    pub entity_id: String,
    pub name: String,
    /// Entity kind label (core `EntityKind` as_str).
    pub kind: String,
    /// Criticality label (core `Criticality` as_str).
    pub criticality: String,
    pub notes: Option<String>,
    pub rotation_interval_days_override: Option<i64>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Wire DTO for one sync device row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSyncDeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub revoked: bool,
}

/// Wire DTO for vault status as seen by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVaultStatus {
    pub unlocked: bool,
    /// Master-password rotation generation (0 = unknown/locked).
    pub key_epoch: i64,
    /// True while the daemon serves only bootstrap/maintenance operations
    /// (no vault exists yet). serde default keeps older clients parsing.
    #[serde(default)]
    pub maintenance: bool,
}

/// Wire DTO for biometric unlock status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBiometricStatus {
    pub method_name: String,
    pub available: bool,
    pub enrolled: bool,
    pub configured: bool,
}

/// One application-service request.
///
/// Ops the DAEMON executes asynchronously by design (relay network I/O:
/// `SyncPairStart`, `SyncPairJoin`) are dispatched by the daemon's async
/// handler; everything else executes against the live vault on the blocking
/// pool via `sentinelpass_core::daemon::service::LiveVaultService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultOp {
    // --- lifecycle -------------------------------------------------------
    /// Create a vault. Valid only while the daemon is in maintenance mode
    /// (no vault exists) or in offline maintenance; the caller must hold the
    /// exclusive maintenance lock (WBS-501/503).
    VaultCreate {
        master_password: Zeroizing<String>,
    },
    VaultStatus,

    // --- entries ---------------------------------------------------------
    EntryAdd {
        entry: ServiceEntry,
    },
    EntryGet {
        entry_id: i64,
    },
    EntryList,
    EntryUpdate {
        entry_id: i64,
        entry: ServiceEntry,
    },
    EntryDelete {
        entry_id: i64,
    },

    // --- TOTP ------------------------------------------------------------
    TotpAdd {
        entry_id: i64,
        secret: Zeroizing<String>,
        algorithm: Option<String>,
        digits: Option<u8>,
        period: Option<u32>,
        issuer: Option<String>,
        account_name: Option<String>,
    },
    TotpCode {
        entry_id: i64,
    },
    TotpMetadata {
        entry_id: i64,
    },
    TotpRemove {
        entry_id: i64,
    },

    // --- SSH keys ---------------------------------------------------------
    SshKeyAdd {
        name: String,
        comment: Option<String>,
        key_type: String,
        public_key: String,
        private_key: Zeroizing<String>,
        fingerprint: String,
    },
    SshKeyList,
    SshKeyGet {
        key_id: i64,
        include_private: bool,
    },
    SshKeyDelete {
        key_id: i64,
    },

    // --- credential registry (ADR-001) ------------------------------------
    RegistryOverview {
        include_strength: bool,
    },
    RegistrySweep,
    EntityList,
    EntityAdd {
        name: String,
        kind: String,
        criticality: String,
        notes: Option<String>,
        rotation_interval_days: Option<i64>,
    },
    EntityDelete {
        name: String,
    },
    EntryAssign {
        entry_id: i64,
        entity: String,
        label: Option<String>,
    },
    EntryUnassign {
        entry_id: i64,
    },
    EntryMarkRotated {
        entry_id: i64,
    },
    EntrySetExpiresAt {
        entry_id: i64,
        expires_at: Option<i64>,
    },

    // --- health / audit ----------------------------------------------------
    /// Vault password health report (summary + per-entry findings), as JSON.
    HealthReport,
    /// Verify the audit hash chain (WBS-415), as JSON.
    AuditVerify,

    // --- biometric ----------------------------------------------------------
    BiometricStatusGet,
    BiometricEnable {
        master_password: Zeroizing<String>,
    },
    BiometricDisable,

    // --- import/export -------------------------------------------------------
    /// Full decrypted dump (client renders JSON/CSV/KeePass locally).
    ExportAll,
    /// Bulk insert from an import file parse. Returns created ids.
    ImportEntries {
        entries: Vec<ServiceEntry>,
    },

    // --- sync (daemon-executed; local vault writes) --------------------------
    SyncInit {
        relay_url: String,
        device_name: Option<String>,
    },
    SyncDisable,
    SyncDeviceList,
    SyncDeviceRevoke {
        device_id: String,
    },

    // --- sync pairing (daemon-async: relay network I/O) -----------------------
    /// Upload this vault's bootstrap under a fresh pairing code.
    SyncPairStart,
    /// Fetch a bootstrap with a pairing code and adopt it (creating the
    /// local vault when none exists — daemon bootstrap path).
    SyncPairJoin {
        relay_url: String,
        code: String,
        salt: String,
    },
}

/// Successful outcome of one [`VaultOp`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultOpResult {
    Ok,
    EntryId(i64),
    Entry(Box<ServiceEntry>),
    EntryList(Vec<ServiceEntrySummary>),
    Entries(Vec<ServiceEntry>),
    /// Ids created by a bulk import.
    Imported(Vec<i64>),
    TotpCode {
        code: String,
        seconds_remaining: u32,
    },
    TotpMetadata(Option<ServiceTotpMetadata>),
    SshKey(Box<ServiceSshKey>),
    SshKeyList(Vec<ServiceSshKeySummary>),
    Entity(Box<ServiceEntity>),
    EntityList(Vec<ServiceEntity>),
    /// Report-shaped payloads (registry overview, sweep, health, audit
    /// verification) as pre-serialized JSON; clients deserialize into the
    /// core report types they already link.
    Report(serde_json::Value),
    Status(ServiceVaultStatus),
    Biometric(ServiceBiometricStatus),
    SyncDevices(Vec<ServiceSyncDeviceInfo>),
}

/// Typed service error. `code` is a stable machine-readable label; `message`
/// is human-facing and MUST NOT contain secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceError {
    pub code: String,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Outcome envelope for `IpcMessage::ServiceResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServiceOutcome {
    Ok { result: VaultOpResult },
    Err { error: ServiceError },
}

impl From<VaultOpResult> for ServiceOutcome {
    fn from(result: VaultOpResult) -> Self {
        Self::Ok { result }
    }
}

impl From<ServiceError> for ServiceOutcome {
    fn from(error: ServiceError) -> Self {
        Self::Err { error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_entry_round_trips_with_defaults() {
        let entry = ServiceEntry {
            entry_id: Some(7),
            title: "Example".to_string(),
            username: "user@example.com".to_string(),
            password: Zeroizing::new("secret".to_string()),
            url: Some("https://example.com".to_string()),
            notes: None,
            credential_type: "api_key".to_string(),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_001,
            favorite: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ServiceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_id, Some(7));
        assert_eq!(back.password.as_str(), "secret");
        assert_eq!(back.credential_type, "api_key");
    }

    /// An old client's entry frame (no credential_type / timestamps) must
    /// parse on a newer endpoint with serde defaults.
    #[test]
    fn legacy_service_entry_parses_with_defaults() {
        let legacy = r#"{"title":"T","username":"u","password":"p"}"#;
        let entry: ServiceEntry = serde_json::from_str(legacy).unwrap();
        assert_eq!(entry.credential_type, "password");
        assert_eq!(entry.entry_id, None);
        assert!(!entry.favorite);
    }

    #[test]
    fn vault_op_and_result_round_trip() {
        let op = VaultOp::TotpAdd {
            entry_id: 3,
            secret: Zeroizing::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Some("sha256".to_string()),
            digits: Some(8),
            period: Some(60),
            issuer: Some("Example".to_string()),
            account_name: None,
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: VaultOp = serde_json::from_str(&json).unwrap();
        match back {
            VaultOp::TotpAdd {
                entry_id, digits, ..
            } => {
                assert_eq!(entry_id, 3);
                assert_eq!(digits, Some(8));
            }
            other => panic!("unexpected op: {other:?}"),
        }

        let result = VaultOpResult::Report(serde_json::json!({ "ok": true }));
        let json = serde_json::to_string(&result).unwrap();
        let back: VaultOpResult = serde_json::from_str(&json).unwrap();
        match back {
            VaultOpResult::Report(v) => assert_eq!(v["ok"], serde_json::json!(true)),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn service_outcome_is_tagged_and_both_branches_round_trip() {
        let ok = ServiceOutcome::from(VaultOpResult::EntryId(11));
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"status\":\"ok\""), "tagged: {json}");
        let back: ServiceOutcome = serde_json::from_str(&json).unwrap();
        match back {
            ServiceOutcome::Ok {
                result: VaultOpResult::EntryId(id),
            } => assert_eq!(id, 11),
            other => panic!("unexpected outcome: {other:?}"),
        }

        let err = ServiceOutcome::from(ServiceError::new("vault_locked", "vault is locked"));
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"status\":\"err\""), "tagged: {json}");
        let back: ServiceOutcome = serde_json::from_str(&json).unwrap();
        match back {
            ServiceOutcome::Err { error } => {
                assert_eq!(error.code, "vault_locked");
                assert_eq!(error.message, "vault is locked");
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
}
