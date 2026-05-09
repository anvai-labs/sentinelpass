//! Change tracking: query pending changes, create sync blobs, mark synced.

use crate::crypto::cipher::DataEncryptionKey;
use crate::sync::crypto::encrypt_for_sync;
use crate::sync::models::{
    CredentialPayload, DomainPayload, SshKeyPayload, SyncEntryBlob, SyncEntryType, TotpPayload,
};
use crate::{CredentialType, DatabaseError, PasswordManagerError, Result};
use rusqlite::Connection;
use uuid::Uuid;

/// Query all entries with `sync_state = 'pending'` and build sync blobs.
pub fn collect_pending_credential_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT entry_id, sync_id, sync_version, modified_at, is_deleted,
                    title, username, password, url, notes, credential_type, favorite, created_at
             FROM entries
             WHERE sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,             // entry_id
                row.get::<_, String>(1)?,          // sync_id
                row.get::<_, i64>(2)?,             // sync_version
                row.get::<_, i64>(3)?,             // modified_at
                row.get::<_, bool>(4)?,            // is_deleted
                row.get::<_, Vec<u8>>(5)?,         // title (encrypted blob)
                row.get::<_, Vec<u8>>(6)?,         // username
                row.get::<_, Vec<u8>>(7)?,         // password
                row.get::<_, Option<Vec<u8>>>(8)?, // url
                row.get::<_, Option<Vec<u8>>>(9)?, // notes
                row.get::<_, String>(10)?,         // credential_type
                row.get::<_, bool>(11)?,           // favorite
                row.get::<_, i64>(12)?,            // created_at
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            entry_id,
            sync_id_str,
            sync_version,
            modified_at,
            is_deleted,
            title_blob,
            username_blob,
            password_blob,
            url_blob,
            notes_blob,
            credential_type,
            favorite,
            created_at,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            // Tombstone: empty encrypted payload
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::Credential,
                sync_version: sync_version as u64,
                modified_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        // Load domain mappings for this entry
        let domains = load_domain_mappings(conn, entry_id)?;

        // Build credential payload from raw encrypted blobs
        // Note: we re-serialize the raw blobs as-is since they're already
        // encrypted locally. For sync, we need the *logical* plaintext to
        // re-encrypt under the sync wire format. But since the DEK is the
        // same, we decrypt locally and re-encrypt for transport.
        let title = decrypt_blob(dek, &title_blob)?;
        let username = decrypt_blob(dek, &username_blob)?;
        let password = decrypt_blob(dek, &password_blob)?;
        let url = url_blob
            .filter(|b| !b.is_empty())
            .map(|b| decrypt_blob(dek, &b))
            .transpose()?;
        let notes = notes_blob
            .filter(|b| !b.is_empty())
            .map(|b| decrypt_blob(dek, &b))
            .transpose()?;

        let payload = CredentialPayload {
            title,
            username,
            password,
            credential_type: CredentialType::parse(&credential_type)?,
            url,
            notes,
            favorite,
            domains,
            created_at,
            modified_at,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::Credential,
            sync_version: sync_version as u64,
            modified_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Query pending SSH key changes and build sync blobs.
pub fn collect_pending_ssh_key_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT key_id, sync_id, sync_version, modified_at, is_deleted,
                    name, comment, key_type, key_size, public_key,
                    private_key_encrypted, nonce, auth_tag, fingerprint, created_at
             FROM ssh_keys
             WHERE sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,         // sync_id
                row.get::<_, i64>(2)?,            // sync_version
                row.get::<_, i64>(3)?,            // modified_at
                row.get::<_, bool>(4)?,           // is_deleted
                row.get::<_, String>(5)?,         // name
                row.get::<_, Option<String>>(6)?, // comment
                row.get::<_, String>(7)?,         // key_type
                row.get::<_, Option<i64>>(8)?,    // key_size
                row.get::<_, String>(9)?,         // public_key
                row.get::<_, Vec<u8>>(10)?,       // private_key_encrypted
                row.get::<_, Vec<u8>>(11)?,       // nonce
                row.get::<_, Vec<u8>>(12)?,       // auth_tag
                row.get::<_, String>(13)?,        // fingerprint
                row.get::<_, i64>(14)?,           // created_at
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            sync_id_str,
            sync_version,
            modified_at,
            is_deleted,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::SshKey,
                sync_version: sync_version as u64,
                modified_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        let payload = SshKeyPayload {
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at,
            modified_at,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::SshKey,
            sync_version: sync_version as u64,
            modified_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Query pending TOTP secret changes and build sync blobs.
pub fn collect_pending_totp_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT t.totp_id, t.sync_id, t.sync_version, t.created_at, t.is_deleted,
                    t.entry_id, t.secret_encrypted, t.nonce, t.auth_tag,
                    t.algorithm, t.digits, t.period, t.issuer, t.account_name,
                    e.sync_id as parent_sync_id
             FROM totp_secrets t
             LEFT JOIN entries e ON t.entry_id = e.entry_id
             WHERE t.sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,          // sync_id
                row.get::<_, i64>(2)?,             // sync_version
                row.get::<_, i64>(3)?,             // created_at (used as modified_at)
                row.get::<_, bool>(4)?,            // is_deleted
                row.get::<_, Vec<u8>>(6)?,         // secret_encrypted
                row.get::<_, Vec<u8>>(7)?,         // nonce
                row.get::<_, Vec<u8>>(8)?,         // auth_tag
                row.get::<_, String>(9)?,          // algorithm
                row.get::<_, u8>(10)?,             // digits
                row.get::<_, u32>(11)?,            // period
                row.get::<_, Option<String>>(12)?, // issuer
                row.get::<_, Option<String>>(13)?, // account_name
                row.get::<_, Option<String>>(14)?, // parent_sync_id
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            sync_id_str,
            sync_version,
            created_at,
            is_deleted,
            secret_encrypted,
            nonce,
            auth_tag,
            algorithm,
            digits,
            period,
            issuer,
            account_name,
            parent_sync_id_str,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| PasswordManagerError::InvalidInput(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::TotpSecret,
                sync_version: sync_version as u64,
                modified_at: created_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        let parent_credential_sync_id = parent_sync_id_str.and_then(|s| Uuid::parse_str(&s).ok());

        let payload = TotpPayload {
            secret_encrypted,
            nonce,
            auth_tag,
            algorithm,
            digits,
            period,
            issuer,
            account_name,
            created_at,
            parent_credential_sync_id,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::TotpSecret,
            sync_version: sync_version as u64,
            modified_at: created_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Mark entries as synced after successful push.
pub fn mark_entries_synced(conn: &Connection, sync_ids: &[Uuid]) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    for sync_id in sync_ids {
        let id_str = sync_id.to_string();
        conn.execute(
            "UPDATE entries SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;

        conn.execute(
            "UPDATE ssh_keys SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;

        conn.execute(
            "UPDATE totp_secrets SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    Ok(())
}

/// Mark a tombstone as pushed.
pub fn mark_tombstone_pushed(conn: &Connection, sync_id: &Uuid) -> Result<()> {
    conn.execute(
        "UPDATE sync_tombstones SET pushed = 1 WHERE sync_id = ?1",
        [sync_id.to_string()],
    )
    .map_err(DatabaseError::Sqlite)?;

    Ok(())
}

/// Count pending changes across all entry types.
pub fn count_pending_changes(conn: &Connection) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM entries WHERE sync_state = 'pending') +
                (SELECT COUNT(*) FROM ssh_keys WHERE sync_state = 'pending') +
                (SELECT COUNT(*) FROM totp_secrets WHERE sync_state = 'pending')",
            [],
            |row| row.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;

    Ok(count as u64)
}

// --- Helpers ---

fn load_domain_mappings(conn: &Connection, entry_id: i64) -> Result<Vec<DomainPayload>> {
    let mut stmt = conn
        .prepare("SELECT domain, is_primary FROM domain_mappings WHERE entry_id = ?1")
        .map_err(DatabaseError::Sqlite)?;

    let domains = stmt
        .query_map([entry_id], |row| {
            Ok(DomainPayload {
                domain: row.get(0)?,
                is_primary: row.get(1)?,
            })
        })
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    Ok(domains)
}

/// Decrypt a bincode-serialized EncryptedEntry blob to a String.
fn decrypt_blob(dek: &DataEncryptionKey, blob: &[u8]) -> Result<String> {
    let encrypted: crate::crypto::EncryptedEntry =
        bincode::deserialize(blob).map_err(|e| DatabaseError::Serialization(e.to_string()))?;
    crate::crypto::cipher::decrypt_to_string(dek, &encrypted)
        .map_err(crate::PasswordManagerError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::database::Database;

    fn setup_db_with_sync_schema() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        db
    }

    /// Insert a pending credential entry with encrypted fields and return its sync_id.
    fn insert_pending_credential(
        conn: &Connection,
        dek: &DataEncryptionKey,
        title: &str,
        username: &str,
        password: &str,
        is_deleted: bool,
    ) -> Uuid {
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let title_enc = crate::encrypt_string(dek, title).unwrap();
        let username_enc = crate::encrypt_string(dek, username).unwrap();
        let password_enc = crate::encrypt_string(dek, password).unwrap();

        let title_blob = bincode::serialize(&title_enc).unwrap();
        let username_blob = bincode::serialize(&username_enc).unwrap();
        let password_blob = bincode::serialize(&password_enc).unwrap();
        let nonce_blob = bincode::serialize(&title_enc.nonce).unwrap();
        let auth_tag_blob = bincode::serialize(&title_enc.auth_tag).unwrap();

        conn.execute(
            "INSERT INTO entries (
                vault_id, title, username, password, url, notes, credential_type,
                entry_nonce, auth_tag, created_at, modified_at, favorite,
                sync_id, sync_version, sync_state, is_deleted
            ) VALUES (1, ?1, ?2, ?3, X'', X'', 'password', ?4, ?5, ?6, ?7, 0, ?8, 1, 'pending', ?9)",
            rusqlite::params![
                title_blob,
                username_blob,
                password_blob,
                nonce_blob,
                auth_tag_blob,
                now,
                now,
                sync_id.to_string(),
                is_deleted,
            ],
        )
        .unwrap();

        sync_id
    }

    /// Insert a pending SSH key entry and return its sync_id.
    fn insert_pending_ssh_key(conn: &Connection, name: &str, is_deleted: bool) -> Uuid {
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO ssh_keys (
                name, comment, key_type, key_size, public_key,
                private_key_encrypted, nonce, auth_tag, fingerprint,
                created_at, modified_at,
                sync_id, sync_version, sync_state, is_deleted
            ) VALUES (?1, NULL, 'ed25519', 256, 'ssh-ed25519 AAAA...', X'deadbeef', X'aabb', X'ccdd', 'SHA256:test',
                      ?2, ?3, ?4, 1, 'pending', ?5)",
            rusqlite::params![name, now, now, sync_id.to_string(), is_deleted],
        )
        .unwrap();

        sync_id
    }

    /// Insert a pending TOTP entry and return its sync_id.
    fn insert_pending_totp(conn: &Connection, entry_id: i64, is_deleted: bool) -> Uuid {
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO totp_secrets (
                entry_id, secret_encrypted, nonce, auth_tag,
                algorithm, digits, period, issuer, account_name, created_at,
                sync_id, sync_version, sync_state, is_deleted
            ) VALUES (?1, X'deadbeef', X'aabbccddeeff', X'00112233445566778899aabbccddeeff',
                      'SHA1', 6, 30, 'Test', 'user@test.com', ?2, ?3, 1, 'pending', ?4)",
            rusqlite::params![entry_id, now, sync_id.to_string(), is_deleted],
        )
        .unwrap();

        sync_id
    }

    #[test]
    fn count_pending_empty() {
        let db = setup_db_with_sync_schema();
        let count = count_pending_changes(db.conn()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn count_pending_with_entries() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();

        insert_pending_credential(conn, &dek, "Site A", "user1", "pass1", false);
        insert_pending_credential(conn, &dek, "Site B", "user2", "pass2", false);
        let sync_id_ssh = insert_pending_ssh_key(conn, "my-key", false);

        let count = count_pending_changes(conn).unwrap();
        assert_eq!(count, 3);

        // Mark one as synced and verify count decreases
        mark_entries_synced(conn, &[sync_id_ssh]).unwrap();
        let count = count_pending_changes(conn).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn mark_entries_synced_updates_all_tables() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();

        let cred_id = insert_pending_credential(conn, &dek, "Test", "user", "pass", false);
        let ssh_id = insert_pending_ssh_key(conn, "key1", false);

        assert_eq!(count_pending_changes(conn).unwrap(), 2);

        mark_entries_synced(conn, &[cred_id, ssh_id]).unwrap();

        assert_eq!(count_pending_changes(conn).unwrap(), 0);

        // Verify sync_state is 'synced' in entries table
        let state: String = conn
            .query_row(
                "SELECT sync_state FROM entries WHERE sync_id = ?1",
                [cred_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "synced");

        // Verify last_synced_at is set
        let synced_at: Option<i64> = conn
            .query_row(
                "SELECT last_synced_at FROM ssh_keys WHERE sync_id = ?1",
                [ssh_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(synced_at.is_some());
    }

    #[test]
    fn mark_tombstone_pushed_updates_flag() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO sync_tombstones (sync_id, entry_type, sync_version, deleted_at, origin_device_id, pushed)
             VALUES (?1, 'credential', 1, ?2, ?3, 0)",
            rusqlite::params![sync_id.to_string(), now, Uuid::new_v4().to_string()],
        )
        .unwrap();

        mark_tombstone_pushed(conn, &sync_id).unwrap();

        let pushed: bool = conn
            .query_row(
                "SELECT pushed FROM sync_tombstones WHERE sync_id = ?1",
                [sync_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(pushed);
    }

    #[test]
    fn collect_pending_credential_blobs_empty_db() {
        let db = setup_db_with_sync_schema();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let blobs = collect_pending_credential_blobs(db.conn(), &dek, device_id).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn collect_pending_credential_blobs_returns_blobs() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let sync_id =
            insert_pending_credential(conn, &dek, "GitHub", "dev@gh.com", "s3cret", false);

        let blobs = collect_pending_credential_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].sync_id, sync_id);
        assert_eq!(blobs[0].entry_type, SyncEntryType::Credential);
        assert!(!blobs[0].is_tombstone);
        assert_eq!(blobs[0].origin_device_id, device_id);
        assert!(!blobs[0].encrypted_payload.is_empty());
    }

    #[test]
    fn collect_pending_credential_blobs_tombstone() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let sync_id = insert_pending_credential(conn, &dek, "Deleted", "u", "p", true);

        let blobs = collect_pending_credential_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].sync_id, sync_id);
        assert!(blobs[0].is_tombstone);
    }

    #[test]
    fn collect_pending_credential_with_domain_mappings() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        insert_pending_credential(conn, &dek, "Multi Domain", "user", "pass", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries ORDER BY entry_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'example.com', 1)",
            [entry_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'www.example.com', 0)",
            [entry_id],
        )
        .unwrap();

        let blobs = collect_pending_credential_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);

        // Decrypt and verify domain mappings are included
        let payload_json =
            crate::sync::crypto::decrypt_from_sync(&dek, &blobs[0].encrypted_payload).unwrap();
        let payload: CredentialPayload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.domains.len(), 2);
        assert_eq!(payload.domains[0].domain, "example.com");
        assert!(payload.domains[0].is_primary);
    }

    #[test]
    fn collect_pending_ssh_key_blobs_empty_db() {
        let db = setup_db_with_sync_schema();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let blobs = collect_pending_ssh_key_blobs(db.conn(), &dek, device_id).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn collect_pending_ssh_key_blobs_returns_blobs() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let sync_id = insert_pending_ssh_key(conn, "deploy-key", false);

        let blobs = collect_pending_ssh_key_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].sync_id, sync_id);
        assert_eq!(blobs[0].entry_type, SyncEntryType::SshKey);
        assert!(!blobs[0].is_tombstone);
    }

    #[test]
    fn collect_pending_ssh_key_blobs_tombstone() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let sync_id = insert_pending_ssh_key(conn, "revoked-key", true);

        let blobs = collect_pending_ssh_key_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].is_tombstone);
        assert_eq!(blobs[0].sync_id, sync_id);
    }

    #[test]
    fn collect_pending_totp_blobs_empty_db() {
        let db = setup_db_with_sync_schema();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let blobs = collect_pending_totp_blobs(db.conn(), &dek, device_id).unwrap();
        assert!(blobs.is_empty());
    }

    #[test]
    fn collect_pending_totp_blobs_returns_blobs() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        // Insert a parent credential first
        let cred_sync_id = insert_pending_credential(conn, &dek, "TOTP Site", "u", "p", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries WHERE sync_id = ?1",
                [cred_sync_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        let totp_sync_id = insert_pending_totp(conn, entry_id, false);

        let blobs = collect_pending_totp_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].sync_id, totp_sync_id);
        assert_eq!(blobs[0].entry_type, SyncEntryType::TotpSecret);
        assert!(!blobs[0].is_tombstone);

        // Verify the parent_credential_sync_id is set in the payload
        let payload_json =
            crate::sync::crypto::decrypt_from_sync(&dek, &blobs[0].encrypted_payload).unwrap();
        let payload: TotpPayload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.parent_credential_sync_id, Some(cred_sync_id));
    }

    #[test]
    fn collect_pending_totp_blobs_tombstone() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let cred_sync_id = insert_pending_credential(conn, &dek, "X", "u", "p", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries WHERE sync_id = ?1",
                [cred_sync_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();

        let sync_id = insert_pending_totp(conn, entry_id, true);

        let blobs = collect_pending_totp_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].is_tombstone);
        assert_eq!(blobs[0].sync_id, sync_id);
    }

    #[test]
    fn load_domain_mappings_empty() {
        let db = setup_db_with_sync_schema();
        let domains = load_domain_mappings(db.conn(), 999).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn load_domain_mappings_returns_entries() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();

        insert_pending_credential(conn, &dek, "Test", "u", "p", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries ORDER BY entry_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'a.com', 1)",
            [entry_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO domain_mappings (entry_id, domain, is_primary) VALUES (?1, 'b.com', 0)",
            [entry_id],
        )
        .unwrap();

        let domains = load_domain_mappings(conn, entry_id).unwrap();
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn mixed_pending_count() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();

        insert_pending_credential(conn, &dek, "Cred1", "u", "p", false);
        insert_pending_ssh_key(conn, "key1", false);

        let cred2_sync = insert_pending_credential(conn, &dek, "Cred2", "u2", "p2", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries WHERE sync_id = ?1",
                [cred2_sync.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        insert_pending_totp(conn, entry_id, false);

        assert_eq!(count_pending_changes(conn).unwrap(), 4);
    }
}
