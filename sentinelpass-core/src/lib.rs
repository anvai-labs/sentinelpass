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
pub use ssh::{SshAgentClient, SshKey, SshKeyGenerator, SshKeyImporter, SshKeySummary, SshKeyType};
pub use totp::{parse_otpauth_uri, ParsedTotpUri, TotpAlgorithm, TotpCode, TotpSecretMetadata};
pub use vault::{
    CredentialType, Entry, EntrySummary, PaginatedResult, PaginationParams, VaultManager,
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

    #[error("Not found: {0}")]
    NotFound(String),

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
            "| Control | Status | Code Location | Test Location | Residual Risk | Next Action |",
            "Biometric Storage Model",
            "Memory Locking / Zeroization",
            "Windows IPC Named Pipes and ACLs",
            "Extension Sender Validation",
            "Relay Abuse Controls",
            "Passkey Support State",
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
