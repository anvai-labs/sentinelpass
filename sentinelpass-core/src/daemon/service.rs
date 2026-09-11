//! Application-service boundary (WBS-408, ADR-007).
//!
//! The daemon exposes ONE call shape for vault operations:
//! [`VaultApplicationService::execute`] taking a protocol [`VaultOp`] and
//! returning a protocol [`VaultOpResult`]. [`LiveVaultService`] implements
//! it against an unlocked [`VaultManager`]; the daemon dispatches each
//! `IpcMessage::ServiceCall` here (on the blocking pool — every op touches
//! SQLite and crypto), and IPC clients use
//! `sentinelpass_protocol::IpcClient::call_service`. Direct
//! `VaultManager` use in UI/CLI is the flagged compatibility path only
//! (ADR-007 migration window).
//!
//! This module also owns the wire-DTO ↔ core-type conversions so both the
//! daemon handlers and the clients share one mapping.

use crate::registry::{Criticality, EntityKind};
use crate::vault::Entry;
use crate::{PasswordManagerError, Result, VaultManager};
use sentinelpass_protocol::service::{
    ServiceBiometricStatus, ServiceEntity, ServiceEntry, ServiceEntrySummary, ServiceError,
    ServiceOutcome, ServiceSshKey, ServiceSshKeySummary, ServiceSyncDeviceInfo, ServiceSyncStatus,
    ServiceTotpMetadata, ServiceVaultStatus, VaultOp, VaultOpResult,
};
use zeroize::Zeroizing;

/// Stable machine-readable error codes for [`ServiceError`].
pub mod codes {
    pub const VAULT_LOCKED: &str = "vault_locked";
    pub const LOCKED_OUT: &str = "locked_out";
    pub const NOT_FOUND: &str = "not_found";
    pub const INVALID_INPUT: &str = "invalid_input";
    pub const EPOCH_ROLLBACK: &str = "epoch_rollback";
    pub const SLOT_REGISTRY_TAMPERED: &str = "slot_registry_tampered";
    pub const UNSUPPORTED_FORMAT: &str = "unsupported_format";
    pub const CRYPTO: &str = "crypto";
    pub const DATABASE: &str = "database";
    pub const IO: &str = "io";
    pub const INTERNAL: &str = "internal";
    /// Daemon has no vault yet: only bootstrap/status ops are served.
    pub const MAINTENANCE_MODE: &str = "maintenance_mode";
    /// Bootstrap create refused because a vault already exists.
    pub const VAULT_EXISTS: &str = "vault_exists";
    /// Op exists in the contract but is intentionally not served by the
    /// daemon (pairing is exclusive offline CLI maintenance in this release).
    pub const OP_NOT_SERVED: &str = "op_not_served";
}

impl From<PasswordManagerError> for ServiceError {
    fn from(err: PasswordManagerError) -> Self {
        let code = match &err {
            PasswordManagerError::VaultLocked => codes::VAULT_LOCKED,
            PasswordManagerError::LockedOut(_) => codes::LOCKED_OUT,
            PasswordManagerError::NotFound(_) => codes::NOT_FOUND,
            PasswordManagerError::InvalidInput(_) => codes::INVALID_INPUT,
            PasswordManagerError::EpochRollback { .. } => codes::EPOCH_ROLLBACK,
            PasswordManagerError::SlotRegistryTampered => codes::SLOT_REGISTRY_TAMPERED,
            PasswordManagerError::Crypto(_) => codes::CRYPTO,
            PasswordManagerError::Database(_) => codes::DATABASE,
            PasswordManagerError::Io(_) => codes::IO,
            _ => codes::INTERNAL,
        };
        // The Display of every variant is human-facing prose; none embeds
        // secret material (entry titles/domains appear only in
        // NotFound/InvalidInput messages the caller itself supplied).
        ServiceError::new(code, err.to_string())
    }
}

/// The single call shape the daemon exposes for vault operations
/// (ADR-007: "UI, CLI, and native host use application-service IPC").
pub trait VaultApplicationService {
    /// Execute one operation. Errors are typed service errors; conversion
    /// from the core error type is lossless via [`From`].
    fn execute(&self, op: &VaultOp) -> std::result::Result<VaultOpResult, ServiceError>;
}

/// Executor bound to one unlocked [`VaultManager`] — the daemon-side
/// implementation of the service boundary.
pub struct LiveVaultService<'a> {
    vault: &'a VaultManager,
}

impl<'a> LiveVaultService<'a> {
    pub fn new(vault: &'a VaultManager) -> Self {
        Self { vault }
    }
}

impl VaultApplicationService for LiveVaultService<'_> {
    fn execute(&self, op: &VaultOp) -> std::result::Result<VaultOpResult, ServiceError> {
        // Pairing is exclusive offline CLI maintenance in this release
        // (review F3: the contract previously advertised daemon dispatch
        // that did not exist). Fail with the typed code, never silently.
        if matches!(op, VaultOp::SyncPairStart | VaultOp::SyncPairJoin { .. }) {
            return Err(ServiceError::new(
                codes::OP_NOT_SERVED,
                "pairing is exclusive offline maintenance (CLI under the vault lock); \
                 the daemon does not serve it over IPC",
            ));
        }
        self.execute_op(op).map_err(ServiceError::from)
    }
}

impl LiveVaultService<'_> {
    fn execute_op(&self, op: &VaultOp) -> Result<VaultOpResult> {
        let vault = self.vault;
        match op {
            VaultOp::VaultCreate { .. } => Err(PasswordManagerError::InvalidInput(
                "vault creation is a maintenance/bootstrap operation; it is not valid against \
                 a live unlocked vault"
                    .to_string(),
            )),
            VaultOp::VaultStatus => {
                // Metadata read: a real DB failure must NOT masquerade as
                // "0 = unknown" (review finding) — propagate it.
                let key_epoch = vault.key_epoch()?;
                Ok(VaultOpResult::Status(ServiceVaultStatus {
                    unlocked: vault.is_unlocked(),
                    key_epoch,
                    maintenance: false,
                }))
            }

            VaultOp::EntryAdd { entry } => {
                let id = vault.add_entry(&entry_from_wire(entry)?)?;
                Ok(VaultOpResult::EntryId(id))
            }
            VaultOp::EntryGet { entry_id } => Ok(VaultOpResult::Entry(Box::new(entry_to_wire(
                &vault.get_entry(*entry_id)?,
            )?))),
            VaultOp::EntryList => Ok(VaultOpResult::EntryList(
                vault
                    .list_entries()?
                    .into_iter()
                    .map(entry_summary_to_wire)
                    .collect(),
            )),
            VaultOp::EntryUpdate { entry_id, entry } => {
                let mut updated = entry_from_wire(entry)?;
                updated.entry_id = Some(*entry_id);
                vault.update_entry(*entry_id, &updated)?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::EntryDelete { entry_id } => {
                vault.delete_entry(*entry_id)?;
                Ok(VaultOpResult::Ok)
            }

            VaultOp::TotpAdd {
                entry_id,
                secret,
                algorithm,
                digits,
                period,
                issuer,
                account_name,
            } => {
                let algorithm = match algorithm.as_deref().filter(|v| !v.trim().is_empty()) {
                    Some(raw) => raw.parse::<crate::totp::TotpAlgorithm>()?,
                    None => crate::totp::TotpAlgorithm::Sha1,
                };
                vault.add_totp_secret(
                    *entry_id,
                    secret.as_str(),
                    algorithm,
                    digits.unwrap_or(6),
                    period.unwrap_or(30),
                    issuer.as_deref(),
                    account_name.as_deref(),
                )?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::TotpCode { entry_id } => {
                let code = vault.generate_totp_code(*entry_id)?;
                Ok(VaultOpResult::TotpCode {
                    code: code.code,
                    seconds_remaining: code.seconds_remaining,
                })
            }
            VaultOp::TotpMetadata { entry_id } => match vault.get_totp_metadata(*entry_id) {
                Ok(meta) => Ok(VaultOpResult::TotpMetadata(Some(ServiceTotpMetadata {
                    algorithm: meta.algorithm.to_string(),
                    digits: meta.digits,
                    period: meta.period,
                    issuer: meta.issuer,
                    account_name: meta.account_name,
                }))),
                Err(PasswordManagerError::NotFound(_)) => Ok(VaultOpResult::TotpMetadata(None)),
                Err(e) => Err(e),
            },
            VaultOp::TotpRemove { entry_id } => {
                vault.remove_totp_secret(*entry_id)?;
                Ok(VaultOpResult::Ok)
            }

            VaultOp::SshKeyAdd {
                name,
                comment,
                key_type,
                public_key,
                private_key,
                fingerprint,
            } => {
                let key_type = ssh_key_type_from_wire(key_type)?;
                let key_id = vault.add_ssh_key_plaintext(
                    name.clone(),
                    comment.clone(),
                    key_type,
                    None,
                    public_key.clone(),
                    private_key.as_str().to_string(),
                    fingerprint.clone(),
                )?;
                Ok(VaultOpResult::EntryId(key_id))
            }
            VaultOp::SshKeyList => Ok(VaultOpResult::SshKeyList(
                vault
                    .list_ssh_keys()?
                    .into_iter()
                    .map(|k| ServiceSshKeySummary {
                        key_id: k.key_id,
                        name: k.name,
                        comment: k.comment,
                        key_type: ssh_key_type_to_wire(&k.key_type),
                        fingerprint: k.fingerprint,
                    })
                    .collect(),
            )),
            VaultOp::SshKeyGet {
                key_id,
                include_private,
            } => {
                let key = vault.get_ssh_key(*key_id)?;
                let private_key = if *include_private {
                    Some(Zeroizing::new(vault.export_ssh_private_key(*key_id)?))
                } else {
                    None
                };
                Ok(VaultOpResult::SshKey(Box::new(ServiceSshKey {
                    key_id: key.key_id.unwrap_or(*key_id),
                    name: key.name,
                    comment: key.comment,
                    key_type: ssh_key_type_to_wire(&key.key_type),
                    public_key: key.public_key,
                    private_key,
                    fingerprint: key.fingerprint,
                    created_at: key.created_at.timestamp(),
                })))
            }
            VaultOp::SshKeyDelete { key_id } => {
                vault.delete_ssh_key(*key_id)?;
                Ok(VaultOpResult::Ok)
            }

            VaultOp::RegistryOverview { include_strength } => {
                if vault.registry_backfill_needed()? {
                    vault.sweep_registry_index()?;
                }
                let overview = vault.registry_overview(*include_strength)?;
                report(serde_json::to_value(overview))
            }
            VaultOp::RegistrySweep => report(serde_json::to_value(vault.sweep_registry_index()?)),
            VaultOp::EntityList => Ok(VaultOpResult::EntityList(
                vault
                    .list_entities()?
                    .into_iter()
                    .map(entity_to_wire)
                    .collect(),
            )),
            VaultOp::EntityAdd {
                name,
                kind,
                criticality,
                notes,
                rotation_interval_days,
            } => {
                let kind = EntityKind::parse(kind)?;
                let criticality = Criticality::parse(criticality)?;
                let entity = vault.create_entity(
                    name,
                    kind,
                    criticality,
                    notes.as_deref(),
                    *rotation_interval_days,
                )?;
                Ok(VaultOpResult::Entity(Box::new(entity_to_wire(entity))))
            }
            VaultOp::EntityDelete { name } => {
                let entity = resolve_entity(vault, name)?;
                vault.delete_entity(&entity.entity_id)?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::EntryAssign {
                entry_id,
                entity,
                label,
            } => {
                let entity = resolve_entity(vault, entity)?;
                vault.assign_entry(*entry_id, &entity.entity_id, label.as_deref())?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::EntryUnassign { entry_id } => {
                vault.unassign_entry(*entry_id)?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::EntryMarkRotated { entry_id } => {
                vault.mark_entry_rotated(*entry_id)?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::EntrySetExpiresAt {
                entry_id,
                expires_at,
            } => {
                vault.set_expires_at(*entry_id, *expires_at)?;
                Ok(VaultOpResult::Ok)
            }

            VaultOp::HealthReport => {
                let summary = vault.get_vault_health_summary()?;
                let passwords = vault.get_password_health_report()?;
                report(serde_json::to_value(serde_json::json!({
                    "summary": summary,
                    "passwords": passwords,
                })))
            }
            VaultOp::AuditVerify => {
                let rep = vault.verify_audit_trail()?;
                report(Ok(serde_json::json!({
                    "ok": rep.is_ok(),
                    "total_records": rep.total_records,
                    "chained_records": rep.chained_records,
                    "legacy_records": rep.legacy_records,
                    "suspected_splices": rep.suspected_splices,
                    "unsealed_records": rep.unsealed_records,
                    "malformed_lines": rep.malformed_lines,
                    "report": rep.to_string(),
                })))
            }

            VaultOp::BiometricStatusGet => Ok(VaultOpResult::Biometric(ServiceBiometricStatus {
                method_name: crate::BiometricManager::get_method_name().to_string(),
                available: crate::BiometricManager::is_available(),
                enrolled: crate::BiometricManager::is_enrolled(),
                configured: vault.biometric_unlock_enabled()?,
            })),
            VaultOp::BiometricEnable { master_password } => {
                vault.enable_biometric_unlock(master_password.as_bytes())?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::BiometricDisable => {
                vault.disable_biometric_unlock()?;
                Ok(VaultOpResult::Ok)
            }

            VaultOp::ExportAll => {
                // Export parity (review finding): every built-in export path
                // (JSON/CSV/KeePass) skips non-exportable types
                // (`passkey_reference`); the wire op encodes the same policy
                // instead of leaking it to every client.
                let entries = vault
                    .list_entries()?
                    .into_iter()
                    .filter(|summary| summary.credential_type.is_generic_password_exportable())
                    .map(|summary| vault.get_entry(summary.entry_id))
                    .collect::<std::result::Result<Vec<Entry>, _>>()?;
                let mut wire = Vec::with_capacity(entries.len());
                for entry in &entries {
                    wire.push(entry_to_wire(entry)?);
                }
                Ok(VaultOpResult::Entries(wire))
            }
            VaultOp::ImportEntries { entries } => {
                let mut ids = Vec::with_capacity(entries.len());
                for entry in entries {
                    ids.push(vault.add_entry(&entry_from_wire(entry)?)?);
                }
                Ok(VaultOpResult::Imported(ids))
            }

            VaultOp::SyncInit {
                relay_url,
                device_name,
            } => {
                let status = vault.get_sync_status()?;
                if status.enabled {
                    return Err(PasswordManagerError::InvalidInput(
                        "sync is already initialized for this vault".to_string(),
                    ));
                }
                // CLI parity: default to the machine hostname, not a
                // timestamp (review finding).
                let device_name = device_name.clone().unwrap_or_else(|| {
                    hostname::get()
                        .map(|h| h.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".to_string())
                });
                let identity = crate::sync::device::DeviceIdentity::generate(&device_name);
                let device_id = identity.device_id.to_string();
                let vault_id = uuid::Uuid::new_v4();
                vault.init_sync(relay_url, &device_name, vault_id, &identity)?;
                Ok(VaultOpResult::Report(serde_json::json!({
                    "device_id": device_id,
                    "vault_id": vault_id.to_string(),
                    "relay_url": relay_url,
                })))
            }
            VaultOp::SyncDisable => {
                vault.disable_sync()?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::SyncDeviceList => {
                ensure_sync_enabled(vault)?;
                Ok(VaultOpResult::SyncDevices(
                    vault
                        .list_sync_devices()?
                        .into_iter()
                        .map(|d| ServiceSyncDeviceInfo {
                            device_id: d.device_id.to_string(),
                            device_name: d.device_name,
                            device_type: d.device_type,
                            revoked: d.revoked,
                        })
                        .collect(),
                ))
            }
            VaultOp::SyncDeviceRevoke { device_id } => {
                ensure_sync_enabled(vault)?;
                vault.revoke_sync_device(device_id)?;
                Ok(VaultOpResult::Ok)
            }
            VaultOp::SyncStatus => {
                let status = vault.get_sync_status()?;
                Ok(VaultOpResult::SyncStatus(ServiceSyncStatus {
                    enabled: status.enabled,
                    device_id: status.device_id.map(|d| d.to_string()),
                    device_name: status.device_name,
                    relay_url: status.relay_url,
                    last_sync_at: status.last_sync_at,
                    pending_changes: status.pending_changes,
                    conflicts: status.conflict_count,
                }))
            }
            VaultOp::SyncConflictList => {
                let rows = vault.list_sync_conflicts()?;
                let value = serde_json::to_value(&rows).map_err(|e| {
                    PasswordManagerError::InvalidInput(format!(
                        "conflict serialization failed: {e}"
                    ))
                })?;
                Ok(VaultOpResult::Report(value))
            }
            #[cfg(feature = "sync")]
            VaultOp::SyncConflictResolve {
                ref object_id,
                take_remote,
            } => {
                let object_id = uuid::Uuid::parse_str(object_id).map_err(|_| {
                    PasswordManagerError::InvalidInput(
                        "conflict object id must be a UUID".to_string(),
                    )
                })?;
                vault.resolve_sync_conflict(&object_id, *take_remote)?;
                Ok(VaultOpResult::Ok)
            }
            #[cfg(not(feature = "sync"))]
            VaultOp::SyncConflictResolve { .. } => Err(PasswordManagerError::NotImplemented(
                "conflict resolution requires the sync feature".to_string(),
            )),

            VaultOp::SyncDeadLetterList => {
                let rows = vault.list_sync_dead_letter()?;
                let value = serde_json::to_value(&rows).map_err(|e| {
                    PasswordManagerError::InvalidInput(format!(
                        "dead-letter serialization failed: {e}"
                    ))
                })?;
                Ok(VaultOpResult::Report(value))
            }
            VaultOp::SyncDeadLetterPurge {
                ref server_sequence,
            } => {
                let purged = vault.purge_sync_dead_letter(*server_sequence)?;
                let value = serde_json::json!({ "purged": purged });
                Ok(VaultOpResult::Report(value))
            }

            #[cfg(feature = "sync")]
            VaultOp::SyncMigrateAuthoritative {
                ref new_relay_vault,
            } => {
                let new_vault = uuid::Uuid::parse_str(new_relay_vault).map_err(|_| {
                    PasswordManagerError::InvalidInput(
                        "new relay vault id must be a UUID".to_string(),
                    )
                })?;
                vault.migrate_sync_authoritative(&new_vault)?;
                Ok(VaultOpResult::Ok)
            }
            #[cfg(not(feature = "sync"))]
            VaultOp::SyncMigrateAuthoritative { .. } => Err(PasswordManagerError::NotImplemented(
                "migration requires the sync feature".to_string(),
            )),

            VaultOp::SyncMigrateClaim => Err(PasswordManagerError::NotImplemented(
                "SyncMigrateClaim awaits relay HTTP and is executed by the CLI's sync \
                 client directly (the daemon is not required for the claim POST)"
                    .to_string(),
            )),

            // Relay network I/O — the daemon's async dispatcher owns
            // `SyncNow` (see `daemon/ipc/server.rs`); the blocking executor
            // never runs it. Pairing never reaches this match (intercepted
            // in `execute` with the typed op_not_served code).
            VaultOp::SyncNow => Err(PasswordManagerError::NotImplemented(
                "SyncNow awaits relay HTTP and is executed by the daemon's async dispatcher"
                    .to_string(),
            )),

            // Unreachable via `execute` (intercepted above) but the match
            // must stay exhaustive.
            VaultOp::SyncPairStart | VaultOp::SyncPairJoin { .. } => Err(
                PasswordManagerError::NotImplemented("pairing is not daemon-served".to_string()),
            ),
        }
    }
}

fn report(value: serde_json::Result<serde_json::Value>) -> Result<VaultOpResult> {
    // Serialization of core-owned serde types is an internal concern; a
    // failure surfaces as an IPC/database transport error, not invalid_input
    // (review finding).
    let value = value.map_err(|e| {
        PasswordManagerError::Database(crate::DatabaseError::Ipc(format!(
            "failed to serialize report: {}",
            e
        )))
    })?;
    Ok(VaultOpResult::Report(value))
}

/// CLI parity (review finding): device ops refuse when sync is not
/// initialized instead of silently reading empty tables.
fn ensure_sync_enabled(vault: &VaultManager) -> Result<()> {
    let status = vault.get_sync_status()?;
    if !status.enabled {
        return Err(PasswordManagerError::InvalidInput(
            "sync is not initialized. Use 'sentinelpass sync init' first.".to_string(),
        ));
    }
    Ok(())
}

/// Resolve an entity by unique name (CLI parity; encrypted names cannot
/// enforce a SQL UNIQUE constraint, so matching is app-level).
fn resolve_entity(vault: &VaultManager, name: &str) -> Result<crate::registry::Entity> {
    let entities = vault.list_entities()?;
    entities
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| PasswordManagerError::NotFound(format!("entity '{}'", name)))
}

// ---------------------------------------------------------------------------
// wire ↔ core conversions
// ---------------------------------------------------------------------------

/// Map a wire SSH key type label (core serde name: `rsa`, `ed25519`, ...)
/// onto the core enum.
fn ssh_key_type_from_wire(
    value: &str,
) -> std::result::Result<crate::ssh::SshKeyType, PasswordManagerError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "rsa" => Ok(crate::ssh::SshKeyType::Rsa),
        "ed25519" => Ok(crate::ssh::SshKeyType::Ed25519),
        "ecdsa" => Ok(crate::ssh::SshKeyType::Ecdsa),
        "ecdsa-sha2-nistp256" => Ok(crate::ssh::SshKeyType::EcdsaSha256),
        "ecdsa-sha2-nistp384" => Ok(crate::ssh::SshKeyType::EcdsaSha384),
        "ecdsa-sha2-nistp521" => Ok(crate::ssh::SshKeyType::EcdsaSha521),
        other => Err(PasswordManagerError::InvalidInput(format!(
            "unsupported SSH key type: {}",
            other
        ))),
    }
}

/// Map the core SSH key type onto its wire label (serde name).
fn ssh_key_type_to_wire(key_type: &crate::ssh::SshKeyType) -> String {
    serde_json::to_value(key_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Convert a wire entry into the core `Entry`.
pub fn entry_from_wire(entry: &ServiceEntry) -> Result<Entry> {
    let credential_type = crate::vault::CredentialType::parse(&entry.credential_type)?;
    Ok(Entry {
        entry_id: entry.entry_id,
        title: entry.title.clone(),
        username: entry.username.clone(),
        password: entry.password.as_str().to_string().into(),
        url: entry.url.clone(),
        notes: entry.notes.clone(),
        credential_type,
        created_at: chrono::DateTime::from_timestamp(entry.created_at, 0)
            .unwrap_or_else(chrono::Utc::now),
        modified_at: chrono::DateTime::from_timestamp(entry.modified_at, 0)
            .unwrap_or_else(chrono::Utc::now),
        favorite: entry.favorite,
    })
}

/// Convert a core `Entry` into the wire DTO.
pub fn entry_to_wire(entry: &Entry) -> Result<ServiceEntry> {
    Ok(ServiceEntry {
        entry_id: entry.entry_id,
        title: entry.title.clone(),
        username: entry.username.clone(),
        password: Zeroizing::new(entry.password.as_str().to_string()),
        url: entry.url.clone(),
        notes: entry.notes.clone(),
        credential_type: entry.credential_type.as_str().to_string(),
        created_at: entry.created_at.timestamp(),
        modified_at: entry.modified_at.timestamp(),
        favorite: entry.favorite,
    })
}

/// Convert a core `EntrySummary` into the wire DTO.
pub fn entry_summary_to_wire(summary: crate::vault::EntrySummary) -> ServiceEntrySummary {
    ServiceEntrySummary {
        entry_id: summary.entry_id,
        title: summary.title,
        username: summary.username,
        credential_type: summary.credential_type.as_str().to_string(),
        favorite: summary.favorite,
    }
}

/// Convert a wire entry summary back into the core type (client side).
pub fn entry_summary_from_wire(
    summary: &ServiceEntrySummary,
) -> Result<crate::vault::EntrySummary> {
    Ok(crate::vault::EntrySummary {
        entry_id: summary.entry_id,
        title: summary.title.clone(),
        username: summary.username.clone(),
        credential_type: crate::vault::CredentialType::parse(&summary.credential_type)?,
        favorite: summary.favorite,
    })
}

/// Convert a core `Entity` into the wire DTO.
pub fn entity_to_wire(entity: crate::registry::Entity) -> ServiceEntity {
    ServiceEntity {
        entity_id: entity.entity_id,
        name: entity.name,
        kind: entity.kind.as_str().to_string(),
        criticality: entity.criticality.as_str().to_string(),
        notes: entity.notes,
        rotation_interval_days_override: entity.rotation_interval_days_override,
        created_at: entity.created_at,
        modified_at: entity.modified_at,
    }
}

/// Convert a wire entity back into the core type (client side).
pub fn entity_from_wire(entity: &ServiceEntity) -> Result<crate::registry::Entity> {
    Ok(crate::registry::Entity {
        entity_id: entity.entity_id.clone(),
        name: entity.name.clone(),
        kind: EntityKind::parse(&entity.kind)?,
        criticality: Criticality::parse(&entity.criticality)?,
        notes: entity.notes.clone(),
        rotation_interval_days_override: entity.rotation_interval_days_override,
        created_at: entity.created_at,
        modified_at: entity.modified_at,
    })
}

/// Wrap a [`ServiceOutcome`] result branch for the daemon's response.
pub fn outcome(result: Result<VaultOpResult>) -> ServiceOutcome {
    match result {
        Ok(result) => ServiceOutcome::from(result),
        Err(err) => ServiceOutcome::from(ServiceError::from(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelpass_protocol::service::ServiceOutcome;
    use std::path::PathBuf;

    fn wire_entry(title: &str, password: &str, credential_type: &str) -> ServiceEntry {
        ServiceEntry {
            entry_id: None,
            title: title.to_string(),
            username: "user@example.com".to_string(),
            password: Zeroizing::new(password.to_string()),
            url: Some("https://example.com/login".to_string()),
            notes: None,
            credential_type: credential_type.to_string(),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_000,
            favorite: false,
        }
    }

    fn temp_vault() -> (tempfile::TempDir, PathBuf, &'static str) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("vault.db");
        let password = "test_password_123!";
        (tmp, path, password)
    }

    #[test]
    fn service_error_mapping_carries_stable_codes() {
        let locked = ServiceError::from(PasswordManagerError::VaultLocked);
        assert_eq!(locked.code, codes::VAULT_LOCKED);

        let not_found = ServiceError::from(PasswordManagerError::NotFound("entry 5".to_string()));
        assert_eq!(not_found.code, codes::NOT_FOUND);

        let locked_out = ServiceError::from(PasswordManagerError::LockedOut(42));
        assert_eq!(locked_out.code, codes::LOCKED_OUT);
        assert!(!locked_out.message.contains("secret"));

        // The outcome envelope maps both branches.
        assert!(matches!(
            outcome(Ok(VaultOpResult::Ok)),
            ServiceOutcome::Ok { .. }
        ));
        assert!(matches!(
            outcome(Err(PasswordManagerError::VaultLocked)),
            ServiceOutcome::Err { .. }
        ));
    }

    #[test]
    fn entry_crud_round_trips_through_service_boundary() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        let added = service.execute(&VaultOp::EntryAdd {
            entry: wire_entry("Example", "secret-value", "password"),
        });
        let entry_id = match added.unwrap() {
            VaultOpResult::EntryId(id) => id,
            other => panic!("expected EntryId, got {other:?}"),
        };

        let listed = service.execute(&VaultOp::EntryList).unwrap();
        let summaries = match listed {
            VaultOpResult::EntryList(list) => list,
            other => panic!("expected EntryList, got {other:?}"),
        };
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].entry_id, entry_id);
        assert_eq!(summaries[0].title, "Example");
        // Summaries never carry the secret.
        let raw = serde_json::to_string(&summaries).unwrap();
        assert!(!raw.contains("secret-value"));

        let got = service.execute(&VaultOp::EntryGet { entry_id }).unwrap();
        match got {
            VaultOpResult::Entry(entry) => {
                assert_eq!(entry.password.as_str(), "secret-value");
                assert_eq!(entry.credential_type, "password");
            }
            other => panic!("expected Entry, got {other:?}"),
        }

        let mut updated = wire_entry("Example (edited)", "rotated-value", "password");
        updated.entry_id = Some(entry_id);
        let result = service
            .execute(&VaultOp::EntryUpdate {
                entry_id,
                entry: updated,
            })
            .unwrap();
        assert!(matches!(result, VaultOpResult::Ok));

        let got = service.execute(&VaultOp::EntryGet { entry_id }).unwrap();
        match got {
            VaultOpResult::Entry(entry) => assert_eq!(entry.password.as_str(), "rotated-value"),
            other => panic!("expected Entry, got {other:?}"),
        }

        let result = service.execute(&VaultOp::EntryDelete { entry_id }).unwrap();
        assert!(matches!(result, VaultOpResult::Ok));

        let missing = service
            .execute(&VaultOp::EntryGet { entry_id })
            .unwrap_err();
        assert_eq!(missing.code, codes::NOT_FOUND);
    }

    #[test]
    fn locked_vault_op_maps_to_vault_locked_code() {
        let (_tmp, path, password) = temp_vault();
        let mut vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        vault.lock();
        let service = LiveVaultService::new(&vault);

        let err = service
            .execute(&VaultOp::EntryList)
            .expect_err("locked vault must refuse");
        assert_eq!(err.code, codes::VAULT_LOCKED);
    }

    #[test]
    fn vault_create_refused_against_live_vault() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        let err = service
            .execute(&VaultOp::VaultCreate {
                master_password: Zeroizing::new("whatever".to_string()),
            })
            .expect_err("creation is a bootstrap op");
        assert_eq!(err.code, codes::INVALID_INPUT);
    }

    #[test]
    fn totp_and_status_flow_through_service_boundary() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        let entry_id = match service
            .execute(&VaultOp::EntryAdd {
                entry: wire_entry("Totp Entry", "pw", "password"),
            })
            .unwrap()
        {
            VaultOpResult::EntryId(id) => id,
            other => panic!("expected EntryId, got {other:?}"),
        };

        let result = service
            .execute(&VaultOp::TotpAdd {
                entry_id,
                secret: Zeroizing::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Some("sha1".to_string()),
                digits: Some(6),
                period: Some(30),
                issuer: Some("Example".to_string()),
                account_name: Some("user@example.com".to_string()),
            })
            .unwrap();
        assert!(matches!(result, VaultOpResult::Ok));

        let result = service.execute(&VaultOp::TotpCode { entry_id }).unwrap();
        match result {
            VaultOpResult::TotpCode {
                code,
                seconds_remaining,
            } => {
                assert_eq!(code.len(), 6);
                assert!(seconds_remaining <= 30);
            }
            other => panic!("expected TotpCode, got {other:?}"),
        }

        let result = service
            .execute(&VaultOp::TotpMetadata { entry_id })
            .unwrap();
        match result {
            VaultOpResult::TotpMetadata(Some(meta)) => {
                assert_eq!(meta.digits, 6);
                assert_eq!(meta.period, 30);
                assert_eq!(meta.issuer.as_deref(), Some("Example"));
            }
            other => panic!("expected TotpMetadata, got {other:?}"),
        }

        let result = service.execute(&VaultOp::VaultStatus).unwrap();
        match result {
            VaultOpResult::Status(status) => {
                assert!(status.unlocked);
                assert!(!status.maintenance);
                assert!(status.key_epoch >= 1);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn registry_ops_flow_through_service_boundary() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        let entry_id = match service
            .execute(&VaultOp::EntryAdd {
                entry: wire_entry("Broker Key", "pw", "api_key"),
            })
            .unwrap()
        {
            VaultOpResult::EntryId(id) => id,
            other => panic!("expected EntryId, got {other:?}"),
        };

        let result = service
            .execute(&VaultOp::EntityAdd {
                name: "trading-postgres".to_string(),
                kind: "database".to_string(),
                criticality: "high".to_string(),
                notes: Some("prod cluster".to_string()),
                rotation_interval_days: Some(30),
            })
            .unwrap();
        let entity = match result {
            VaultOpResult::Entity(entity) => entity,
            other => panic!("expected Entity, got {other:?}"),
        };
        assert_eq!(entity.kind, "database");

        let result = service
            .execute(&VaultOp::EntryAssign {
                entry_id,
                entity: "trading-postgres".to_string(),
                label: Some("prod".to_string()),
            })
            .unwrap();
        assert!(matches!(result, VaultOpResult::Ok));

        // Unknown entity names resolve to NOT_FOUND, not silent success.
        let err = service
            .execute(&VaultOp::EntryAssign {
                entry_id,
                entity: "does-not-exist".to_string(),
                label: None,
            })
            .unwrap_err();
        assert_eq!(err.code, codes::NOT_FOUND);

        let result = service
            .execute(&VaultOp::RegistryOverview {
                include_strength: false,
            })
            .unwrap();
        match result {
            VaultOpResult::Report(value) => {
                assert_eq!(value["entities"][0]["entity"]["name"], "trading-postgres");
                assert_eq!(value["unassigned_entries"], 0);
            }
            other => panic!("expected Report, got {other:?}"),
        }

        let result = service
            .execute(&VaultOp::EntityDelete {
                name: "trading-postgres".to_string(),
            })
            .unwrap();
        assert!(matches!(result, VaultOpResult::Ok));
    }

    #[test]
    fn export_import_round_trips_through_service_boundary() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        service
            .execute(&VaultOp::EntryAdd {
                entry: wire_entry("Exported", "export-secret", "api_key"),
            })
            .unwrap();

        let entries = match service.execute(&VaultOp::ExportAll).unwrap() {
            VaultOpResult::Entries(entries) => entries,
            other => panic!("expected Entries, got {other:?}"),
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password.as_str(), "export-secret");
        assert_eq!(entries[0].credential_type, "api_key");

        // Re-import the export (duplicate titles allowed, new ids minted).
        let result = service
            .execute(&VaultOp::ImportEntries {
                entries: entries.clone(),
            })
            .unwrap();
        match result {
            VaultOpResult::Imported(ids) => assert_eq!(ids.len(), 1),
            other => panic!("expected Imported, got {other:?}"),
        }

        let summaries = match service.execute(&VaultOp::EntryList).unwrap() {
            VaultOpResult::EntryList(list) => list,
            other => panic!("expected EntryList, got {other:?}"),
        };
        assert_eq!(summaries.len(), 2);
    }

    #[test]
    fn sync_init_reports_identity_and_refuses_reinit() {
        let (_tmp, path, password) = temp_vault();
        let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
        let service = LiveVaultService::new(&vault);

        let result = service
            .execute(&VaultOp::SyncInit {
                relay_url: "https://relay.example.com".to_string(),
                device_name: Some("test-device".to_string()),
            })
            .unwrap();
        match result {
            VaultOpResult::Report(value) => {
                assert!(value["device_id"].as_str().is_some());
                assert_eq!(value["relay_url"], "https://relay.example.com");
            }
            other => panic!("expected Report, got {other:?}"),
        }

        let err = service
            .execute(&VaultOp::SyncInit {
                relay_url: "https://relay.example.com".to_string(),
                device_name: None,
            })
            .unwrap_err();
        assert_eq!(err.code, codes::INVALID_INPUT);

        let result = service.execute(&VaultOp::SyncDisable).unwrap();
        assert!(matches!(result, VaultOpResult::Ok));
    }
}
