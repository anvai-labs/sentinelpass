//! Database models for password entries.

use chrono::{DateTime, Utc};

use crate::CredentialType;

/// A password entry stored in the database
#[derive(Debug, Clone)]
pub struct Entry {
    pub entry_id: Option<i64>,
    pub vault_id: i64,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub credential_type: CredentialType,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub favorite: bool,
}

/// A domain mapping for autofill lookup
#[derive(Debug, Clone)]
pub struct DomainMapping {
    pub mapping_id: Option<i64>,
    pub entry_id: i64,
    pub domain: String,
    pub is_primary: bool,
}

/// Encrypted TOTP secret configuration linked to an entry
#[derive(Debug, Clone)]
pub struct TotpSecret {
    pub totp_id: Option<i64>,
    pub entry_id: i64,
    pub secret_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub created_at: DateTime<Utc>,
}
