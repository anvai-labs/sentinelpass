// Error types for the mobile bridge

use std::fmt;
use thiserror::Error;

/// Error codes that can be returned to mobile platforms
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Success = 0,
    InvalidParam = -1,
    VaultLocked = -2,
    NotFound = -3,
    Crypto = -4,
    Database = -5,
    Io = -6,
    AlreadyUnlocked = -7,
    InvalidPassword = -8,
    NotInitialized = -9,
    Biometric = -10,
    Totp = -11,
    Sync = -12,
    OutOfMemory = -13,
    AbiUnsupported = -14,
    /// A Rust panic was contained at the FFI/JNI boundary (WBS-805). The
    /// operation did NOT complete; out-params are undefined.
    Panic = -15,
    Unknown = -99,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Success => write!(f, "Success"),
            ErrorCode::InvalidParam => write!(f, "Invalid parameter"),
            ErrorCode::VaultLocked => write!(f, "Vault is locked"),
            ErrorCode::NotFound => write!(f, "Entry not found"),
            ErrorCode::Crypto => write!(f, "Cryptographic operation failed"),
            ErrorCode::Database => write!(f, "Database operation failed"),
            ErrorCode::Io => write!(f, "I/O operation failed"),
            ErrorCode::AlreadyUnlocked => write!(f, "Vault is already unlocked"),
            ErrorCode::InvalidPassword => write!(f, "Invalid master password"),
            ErrorCode::NotInitialized => write!(f, "Vault not initialized"),
            ErrorCode::Biometric => write!(f, "Biometric operation failed"),
            ErrorCode::Totp => write!(f, "TOTP operation failed"),
            ErrorCode::Sync => write!(f, "Sync operation failed"),
            ErrorCode::OutOfMemory => write!(f, "Out of memory"),
            ErrorCode::AbiUnsupported => {
                write!(f, "ABI version not supported by this bridge build")
            }
            ErrorCode::Panic => write!(f, "Internal panic contained at the bridge boundary"),
            ErrorCode::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl std::error::Error for ErrorCode {}

/// Bridge-specific error type
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("Invalid parameter: {0}")]
    InvalidParam(String),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("PasswordManager error: {0}")]
    PasswordManager(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("TOTP error: {0}")]
    Totp(String), // Totp functions return PasswordManagerError

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("NUL byte in string")]
    NulError(#[from] std::ffi::NulError),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Biometric error: {0}")]
    Biometric(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("ABI unsupported: {0}")]
    AbiUnsupported(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

// Implement From conversions for core error types
//
// WBS-806: the old catch-all (`PasswordManager → VaultLocked`) flattened
// distinguishable outcomes — a missing entry or a wrong master password were
// reported identically to a locked vault, so mobile UIs could neither show
// "not found" nor "wrong password". Core variants now map precisely; the
// residual falls to Unknown rather than masquerading as VaultLocked.
impl From<sentinelpass_core::PasswordManagerError> for BridgeError {
    fn from(e: sentinelpass_core::PasswordManagerError) -> Self {
        use sentinelpass_core::PasswordManagerError as E;
        match e {
            E::VaultLocked => BridgeError::Vault("Vault is locked".to_string()),
            E::NotFound(msg) => BridgeError::NotFound(msg),
            E::InvalidInput(msg) => BridgeError::InvalidParam(msg),
            E::Crypto(err) => BridgeError::Crypto(err.to_string()),
            E::Database(err) => BridgeError::Database(err.to_string()),
            E::Io(err) => BridgeError::Io(err),
            other => BridgeError::PasswordManager(other.to_string()),
        }
    }
}

impl From<sentinelpass_core::crypto::CryptoError> for BridgeError {
    fn from(e: sentinelpass_core::crypto::CryptoError) -> Self {
        BridgeError::Crypto(e.to_string())
    }
}

impl From<sentinelpass_core::DatabaseError> for BridgeError {
    fn from(e: sentinelpass_core::DatabaseError) -> Self {
        BridgeError::Database(e.to_string())
    }
}

impl BridgeError {
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            BridgeError::InvalidParam(_) => ErrorCode::InvalidParam,
            BridgeError::Vault(_) => ErrorCode::VaultLocked,
            BridgeError::NotFound(_) => ErrorCode::NotFound,
            BridgeError::Crypto(_) => ErrorCode::Crypto,
            BridgeError::Database(_) => ErrorCode::Database,
            BridgeError::Totp(_) => ErrorCode::Totp,
            BridgeError::Io(_) => ErrorCode::Io,
            BridgeError::Biometric(_) => ErrorCode::Biometric,
            BridgeError::Sync(_) => ErrorCode::Sync,
            BridgeError::NotInitialized => ErrorCode::NotInitialized,
            BridgeError::AbiUnsupported(_) => ErrorCode::AbiUnsupported,
            // Residual core errors (LockedOut, EpochRollback,
            // SlotRegistryTampered, MaintenanceLockHeld, …) surface honestly
            // as Unknown instead of masquerading as VaultLocked.
            _ => ErrorCode::Unknown,
        }
    }
}

/// Result type alias for bridge operations
pub type BridgeResult<T> = Result<T, BridgeError>;
