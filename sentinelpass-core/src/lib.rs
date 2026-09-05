//! Password Manager Core Library
//!
//! This library provides the core functionality for the password manager,
//! including cryptographic operations, database management, and IPC.

pub mod audit;
pub mod autofill;
pub mod biometric;
pub mod crypto;
pub mod daemon;
pub mod database;
pub mod external_secret_access;
pub mod import_export;
pub mod keepass;
pub mod lockout;
pub mod platform;
pub mod registry;
pub mod ssh;
pub mod sync;
pub mod totp;
pub mod vault;

pub use audit::{get_audit_log_dir, get_audit_log_path, AuditEntry, AuditEventType, AuditLogger};
pub use biometric::{BiometricManager, BiometricResult};
pub use crypto::cipher::{decrypt_to_string, encrypt_string};
pub use crypto::{
    decrypt_entry, derive_master_key, encrypt_entry, verify_master_password, CryptoError,
    CryptoResult, DataEncryptionKey, EncryptedEntry, KdfParams, KeyHierarchy, MasterKey,
    WrappedKey,
};
pub use external_secret_access::{
    ClientTokenRecord, ClientTokenStatus, ExternalSecretAllowlist, ExternalSecretField,
    ExternalSecretGrant,
};
pub use import_export::{
    export_to_csv, export_to_json, import_from_csv, import_from_json, ExportEntry,
};
pub use keepass::{export_to_keepass_xml, import_from_keepass_xml, KeePassEntry};
pub use lockout::{LockoutConfig, LockoutManager, DEFAULT_MAX_ATTEMPTS};
pub use platform::{
    ensure_config_dir, ensure_data_dir, get_arch, get_binary_name, get_config_dir, get_data_dir,
    get_default_vault_path, get_platform,
};
pub use registry::{
    compute_equality_tag, Criticality, Entity, EntityKind, EntitySummary, EntryPosture,
    LifecycleSource, RegistryOverview, ReuseCluster, RotationStatus, SweepReport, TagUpsert,
};
pub use ssh::{SshAgentClient, SshKey, SshKeyGenerator, SshKeyImporter, SshKeySummary, SshKeyType};
pub use totp::{parse_otpauth_uri, ParsedTotpUri, TotpAlgorithm, TotpCode, TotpSecretMetadata};
pub use vault::{
    CredentialType, Entry, EntrySummary, PaginatedResult, PaginationParams, VaultManager,
    VaultMetadataInfo,
};

// Re-export common types
use thiserror::Error;

/// Result type for password manager operations
pub type Result<T> = std::result::Result<T, PasswordManagerError>;

/// Structured error type for database and I/O operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Lock error: {0}")]
    LockPoisoned(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("File I/O error: {0}")]
    FileIo(String),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Schema mismatch: expected {expected}, found {found}")]
    SchemaMismatch { expected: i32, found: i32 },

    #[error("{0}")]
    Other(String),
}

/// General error type for password manager operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PasswordManagerError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault is locked out due to too many failed attempts. Try again in {0} seconds")]
    LockedOut(i64),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error(
        "Vault epoch rollback suspected: on-disk epoch {on_disk} is older than the \
         recorded high-water mark {high_water}. The vault database may have been \
         rolled back or restored from an older backup. Refusing to open \
         (ADR-004: epoch high-water enforcement). If this restore is intentional, \
         delete the vault's `.epoch` sidecar file next to the vault database to \
         re-base rollback protection (a supervised restore flow arrives with \
         backup/restore work)."
    )]
    EpochRollback { on_disk: i64, high_water: i64 },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error(
        "slot registry failed integrity verification — a key slot may have been \
         added, edited, or restored without the vault's authority. Refusing to \
         open; repair is verified restore only"
    )]
    SlotRegistryTampered,

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod documentation_status_tests {
    use std::path::Path;

    #[test]
    fn security_status_matrix_exists_with_required_controls() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let matrix_path = manifest_dir.join("../docs/SECURITY_STATUS_MATRIX.md");
        let contents = std::fs::read_to_string(&matrix_path)
            .expect("docs/SECURITY_STATUS_MATRIX.md must exist");

        for required in [
            // Matrix format (2026-09-04 rewrite, ADR-003 vocabulary):
            "| Control | Status | Current evidence | Residual risk / missing evidence | Target |",
            // Evidence rule for the `Implemented` state — the vocabulary must
            // stay evidence-bound, not code-existence-bound.
            "`Implemented`: code exists and has relevant positive and negative automated evidence.",
            // Security-critical controls that must never silently disappear
            // from the matrix:
            "Forgotten-password recovery",
            "Recovery/device/platform key slots",
            "Native-host/browser IPC authorization",
            "Windows named-pipe boundary",
            "Extension sender validation",
            "Relay request authentication/replay controls",
            "Sync delivery correctness",
            "Authenticated portable backup and restore",
            "Passkey support",
            "Desktop biometric unlock: Windows",
            "Android native bridge",
            "iOS native bridge and biometric",
            "Artifact signing, updater trust, SBOM, provenance",
            // Experimental surfaces must stay clearly fenced off:
            "not approved for production credentials",
        ] {
            assert!(
                contents.contains(required),
                "security status matrix is missing required content: {}",
                required
            );
        }
    }

    #[test]
    fn passkey_product_design_exists_with_required_boundaries() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let design_path = manifest_dir.join("../docs/PASSKEY_PRODUCT_DESIGN.md");
        let contents = std::fs::read_to_string(&design_path)
            .expect("docs/PASSKEY_PRODUCT_DESIGN.md must exist before passkey implementation");

        for required in [
            "# Passkey Product Design",
            "## Product Decision",
            "## Non-Goals",
            "## Data Model",
            "## User Flows",
            "## Platform Strategy",
            "## Security Constraints",
            "## Implementation Phases",
            "## Acceptance Gates",
            "passkey_reference",
            "SentinelPass does not store passkey private keys",
            "WebAuthn",
            "AuthenticationServices",
            "FIDO Credential Exchange",
        ] {
            assert!(
                contents.contains(required),
                "passkey product design is missing required content: {}",
                required
            );
        }
    }
}
