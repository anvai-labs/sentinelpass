-- Initial database schema for Password Manager
-- Version: 1

-- Database metadata table
-- Stores the vault encryption parameters and wrapped DEK
CREATE TABLE IF NOT EXISTS db_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_params BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    dek_nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_modified INTEGER NOT NULL,
    biometric_ref TEXT
);

-- Password entries table
-- Stores encrypted credential data
CREATE TABLE IF NOT EXISTS entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    title BLOB NOT NULL,
    username BLOB NOT NULL,
    password BLOB NOT NULL,
    url BLOB,
    notes BLOB,
    credential_type TEXT NOT NULL DEFAULT 'password'
        CHECK (credential_type IN ('password', 'api_key', 'passkey_reference')),
    entry_nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    favorite INTEGER NOT NULL DEFAULT 0
);

-- Domain mappings table
-- Stores plaintext domain mappings for autofill lookups
CREATE TABLE IF NOT EXISTS domain_mappings (
    mapping_id INTEGER PRIMARY KEY,
    entry_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

-- TOTP secrets table
-- Stores encrypted TOTP seed and algorithm settings for entries
CREATE TABLE IF NOT EXISTS totp_secrets (
    totp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL UNIQUE,
    secret_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    period INTEGER NOT NULL DEFAULT 30,
    issuer TEXT,
    account_name TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_entries_vault_id ON entries(vault_id);
CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(favorite);
CREATE INDEX IF NOT EXISTS idx_entries_credential_type ON entries(credential_type);
CREATE INDEX IF NOT EXISTS idx_domain_mappings_entry_id ON domain_mappings(entry_id);
CREATE INDEX IF NOT EXISTS idx_domain_mappings_domain ON domain_mappings(domain);
CREATE INDEX IF NOT EXISTS idx_totp_secrets_entry_id ON totp_secrets(entry_id);

-- Trigger to update last_modified timestamp
CREATE TRIGGER IF NOT EXISTS update_db_metadata_timestamp
AFTER UPDATE ON db_metadata
FOR EACH ROW
BEGIN
    UPDATE db_metadata SET last_modified = (strftime('%s', 'now')) WHERE id = 1;
END;

-- Trigger to update entry modified timestamp
CREATE TRIGGER IF NOT EXISTS update_entry_modified_timestamp
AFTER UPDATE ON entries
FOR EACH ROW
BEGIN
    UPDATE entries SET modified_at = (strftime('%s', 'now')) WHERE entry_id = NEW.entry_id;
END;
