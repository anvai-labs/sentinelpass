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

pub mod aad;
pub mod cipher;
pub mod dbwire;
pub mod envelope;
pub mod health;
pub mod kdf;
pub mod keyring;
pub mod password;
pub mod strength;

pub use aad::{AadContext, AadContextBuilder, EnvelopePurpose, ObjectType, AAD_VERSION};
pub use cipher::{decrypt_entry, encrypt_entry, DataEncryptionKey, EncryptedEntry};
pub use dbwire::{
    decode_dek_nonce, decode_kdf_params, decode_wrapped_key, encode_dek_nonce, encode_kdf_params,
    encode_metadata_blobs, encode_wrapped_key, ALG_ARGON2ID, DBWIRE_VERSION, KDF_MAGIC,
    KDF_MAGIC_STR, MAX_DBWIRE_BYTES, NONCE_MAGIC, NONCE_MAGIC_STR, WRAP_MAGIC, WRAP_MAGIC_STR,
};
pub use envelope::{
    open_envelope, open_envelope_relaxed_epoch, seal_envelope, seal_envelope_with_nonce, Envelope,
    ALG_A256GCM, ENVELOPE_MAGIC, ENVELOPE_MAGIC_STR, ENVELOPE_VERSION, MAX_CIPHERTEXT_BYTES,
    MAX_ENVELOPE_BYTES, SUPPORTED_CRYPTO_VERSION,
};
pub use health::{
    HealthScore, PasswordHealth, PasswordHealthAnalyzer, PasswordStrengthInfo,
    StrengthDistribution, VaultHealthSummary, WeakPasswordEntry,
};
pub use kdf::{
    derive_master_key, verify_master_password, KdfParams, MAX_MEM_COST_KIB, MAX_OUTPUT_LENGTH,
    MAX_PARALLELISM, MAX_TIME_COST, MIN_MEM_COST_KIB, MIN_OUTPUT_LENGTH, MIN_PARALLELISM,
    MIN_TIME_COST,
};
pub use keyring::{
    derive_audit_chain_key, derive_audit_id_key, derive_domain_tag_key, derive_equality_key,
    rotate_master_password, KeyHierarchy, MasterKey, WrappedKey, AUDIT_CHAIN_KEY_INFO,
    AUDIT_ID_KEY_INFO, DOMAIN_TAG_KEY_INFO,
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

    #[error(
        "Unsupported format version (found {found}, this build supports exactly \
         {supported}) — the data was written by a different version of \
         SentinelPass. Fail-closed per ADR-005: no automatic conversion exists \
         in either direction; repair is verified restore only"
    )]
    UnsupportedCryptoVersion { found: i32, supported: i32 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;
/// Alias for Result for backward compatibility
pub type CryptoResult<T> = Result<T>;
