//! Cryptographic primitives for the password manager.
//!
//! This module provides:
//! - Argon2id key derivation
//! - AES-256-GCM encryption/decryption
//! - Secure key management
//! - Zeroization utilities
//! - Password generation
//! - Password strength analysis
//! - Password health assessment

pub mod cipher;
pub mod health;
pub mod kdf;
pub mod keyring;
pub mod password;
pub mod strength;

pub use cipher::{decrypt_entry, encrypt_entry, DataEncryptionKey, EncryptedEntry};
pub use health::{
    HealthScore, PasswordHealth, PasswordHealthAnalyzer, PasswordStrengthInfo,
    StrengthDistribution, VaultHealthSummary, WeakPasswordEntry,
};
pub use kdf::{derive_master_key, verify_master_password, KdfParams};
pub use keyring::{
    derive_equality_key, rotate_master_password, KeyHierarchy, MasterKey, WrappedKey,
};
pub use password::{
    generate_passphrase, generate_password, generate_simple_password, CharacterSets,
    PasswordGeneratorConfig,
};
pub use strength::{
    analyze_password, calculate_shannon_entropy, PasswordAnalysis, PasswordStrength,
};

use thiserror::Error;

/// Errors that can occur in cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KdfFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Authentication failed - data may have been tampered with")]
    AuthenticationFailed,

    #[error("Random number generation failed: {0}")]
    RandomFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;
/// Alias for Result for backward compatibility
pub type CryptoResult<T> = Result<T>;
