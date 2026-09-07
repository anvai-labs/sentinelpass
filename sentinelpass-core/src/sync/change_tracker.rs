//! Change tracking: query pending changes, create sync blobs, mark synced.

use crate::crypto::cipher::DataEncryptionKey;
use crate::sync::crypto::encrypt_for_sync;
use crate::sync::models::{
    CredentialPayload, DomainPayload, SshKeyPayload, SyncEntryBlob, SyncEntryType, TotpPayload,
};
use crate::{CredentialType, DatabaseError, PasswordManagerError, Result};
use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

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

    // Vault identity for v2 envelope opens (adoption review, finding 1:
    // this collector decrypted v1-only, so every v2 entry — what add_entry
    // now writes — permanently aborted the whole push). Fetched once;
    // v1 rows don't need it.
    let (vault_uuid, _epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

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

        // Load domain mappings for this entry (dual-read, WBS-306: the
        // sealed domain opens; legacy plaintext rows pass through).
        let domains = load_domain_mappings(conn, dek, &vault_uuid, entry_id)?;

        // Build credential payload from raw encrypted blobs
        // Note: we re-serialize the raw blobs as-is since they're already
        // encrypted locally. For sync, we need the *logical* plaintext to
        // re-encrypt under the sync wire format. But since the DEK is the
        // same, we decrypt locally and re-encrypt for transport.
        // Dual-read, SKIP-AND-WARN per unreadable row (adoption review):
        // one corrupt/tampered pending row must not permanently wedge the
        // whole push (the row stays pending; every other change still
        // syncs).
        let cred = match CredentialType::parse(&credential_type) {
            Ok(cred) => cred,
            Err(e) => {
                tracing::warn!(entry_id, error = %e, "push: skipping entry with invalid type");
                continue;
            }
        };
        let identity = Some(crate::vault::envelope_ops::EntryFieldIdentity {
            vault_uuid: &vault_uuid,
            sync_id: &sync_id_str,
            cred,
        });
        let open = |purpose, blob: &Vec<u8>| {
            // Zeroizing plaintext straight from the envelope open (WBS-308);
            // identity metadata fields are unguarded explicitly below.
            crate::vault::envelope_ops::open_entry_field_with_identity(dek, identity, purpose, blob)
        };
        let (title, username, password) = match (
            open(crate::crypto::aad::EnvelopePurpose::Summary, &title_blob),
            open(crate::crypto::aad::EnvelopePurpose::Summary, &username_blob),
            open(crate::crypto::aad::EnvelopePurpose::Secret, &password_blob),
        ) {
            (Ok(t), Ok(u), Ok(p)) => (t.to_string(), u.to_string(), p),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                tracing::warn!(entry_id, error = %e, "push: skipping unreadable entry");
                continue;
            }
        };
        // Optional fields: skip-and-warn per row (same containment as the
        // required fields above) — a corrupt url/notes blob skips the
        // WHOLE row (partial application would silently lose fields).
        let url = url_blob
            .filter(|b| !b.is_empty())
            .map(|b| open(crate::crypto::aad::EnvelopePurpose::Secret, &b).map(|z| z.to_string()))
            .transpose();
        let notes = notes_blob
            .filter(|b| !b.is_empty())
            .map(|b| open(crate::crypto::aad::EnvelopePurpose::Secret, &b).map(|z| z.to_string()))
            .transpose();
        let (url, notes) = match (url, notes) {
            (Ok(u), Ok(n)) => (u, n),
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!(entry_id, error = %e, "push: skipping entry (unreadable url/notes)");
                continue;
            }
        };

        let payload = CredentialPayload {
            title,
            username,
            password,
            credential_type: cred,
            url,
            notes,
            favorite,
            domains,
            created_at,
            modified_at,
        };

        // The serialized payload carries the plaintext secret(s) until
        // encryption — zeroized on drop (WBS-308 / SR-CRYPTO-004).
        let payload_json = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
        );

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
                row.get::<_, String>(1)?,                         // sync_id
                row.get::<_, i64>(2)?,                            // sync_version
                row.get::<_, i64>(3)?,                            // modified_at
                row.get::<_, bool>(4)?,                           // is_deleted
                row.get::<_, String>(5)?,                         // name
                row.get::<_, Option<rusqlite::types::Value>>(6)?, // comment (envelope BLOB or legacy TEXT)
                row.get::<_, String>(7)?,                         // key_type
                row.get::<_, Option<i64>>(8)?,                    // key_size
                row.get::<_, String>(9)?,                         // public_key
                row.get::<_, Vec<u8>>(10)?,                       // private_key_encrypted
                row.get::<_, Vec<u8>>(11)?,                       // nonce
                row.get::<_, Vec<u8>>(12)?,                       // auth_tag
                row.get::<_, String>(13)?,                        // fingerprint
                row.get::<_, i64>(14)?,                           // created_at
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    // Fetched ONCE per push (fail-closed) — hoisted from the per-row loop.
    let (vault_uuid, _epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

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

        // Decrypt the local private-key blob for the wire payload
        // (class-aware dual-read, WBS-304): the whole payload is
        // re-encrypted for transport, so it must carry PLAINTEXT — the
        // peer seals under ITS OWN identity on apply. Passing the local
        // v2 envelope through would transplant it with the wrong
        // identity. v1 rows are the SSH three-part shape (ct + separate
        // nonce/tag columns). Per-row skip-and-warn: one unreadable row
        // must not wedge the whole push.
        let private_key = if crate::vault::envelope_ops::is_envelope_blob(&private_key_encrypted) {
            crate::vault::envelope_ops::open_object_field(
                dek,
                Some(vault_uuid.as_str()),
                Some(&sync_id_str),
                crate::crypto::aad::ObjectType::SshKey,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &private_key_encrypted,
            )
        } else {
            crate::ssh::SshKey::decrypt_private_key(dek, &private_key_encrypted, &nonce, &auth_tag)
        };
        let private_key = match private_key {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!(
                    sync_id = %sync_id_str,
                    error = %e,
                    "push: skipping unreadable SSH key (row stays pending)"
                );
                continue;
            }
        };

        // v0.8.x peers require the OLD wire fields (required Vec<u8>s, no
        // defaults): emit a context-free v1-style encryption of the same
        // plaintext so mixed fleets keep working in BOTH directions. New
        // peers prefer `private_key` and ignore these.
        let legacy_enc = crate::crypto::cipher::encrypt_string(dek, private_key.as_str())
            .map_err(crate::PasswordManagerError::Crypto)?;

        // Identity metadata dual-read (WBS-306): the sealed comment opens
        // against the row's identity; legacy plaintext passes through.
        let comment = crate::vault::envelope_ops::open_metadata_text_field(
            dek,
            Some(vault_uuid.as_str()),
            Some(&sync_id_str),
            crate::crypto::aad::ObjectType::SshKey,
            comment,
        )?;

        let payload = SshKeyPayload {
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key,
            private_key_encrypted: Some(legacy_enc.ciphertext),
            legacy_nonce: Some(legacy_enc.nonce.to_vec()),
            legacy_auth_tag: Some(legacy_enc.auth_tag.to_vec()),
            fingerprint,
            created_at,
            modified_at,
        };

        // The serialized payload carries the plaintext secret(s) until
        // encryption — zeroized on drop (WBS-308 / SR-CRYPTO-004).
        let payload_json = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
        );

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
                row.get::<_, String>(1)?,                          // sync_id
                row.get::<_, i64>(2)?,                             // sync_version
                row.get::<_, i64>(3)?,     // created_at (used as modified_at)
                row.get::<_, bool>(4)?,    // is_deleted
                row.get::<_, Vec<u8>>(6)?, // secret_encrypted
                row.get::<_, Vec<u8>>(7)?, // nonce
                row.get::<_, Vec<u8>>(8)?, // auth_tag
                row.get::<_, String>(9)?,  // algorithm
                row.get::<_, u8>(10)?,     // digits
                row.get::<_, u32>(11)?,    // period
                row.get::<_, Option<rusqlite::types::Value>>(12)?, // issuer (envelope BLOB or legacy TEXT)
                row.get::<_, Option<rusqlite::types::Value>>(13)?, // account_name
                row.get::<_, Option<String>>(14)?,                 // parent_sync_id
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    // Fetched ONCE per push (fail-closed) — hoisted from the per-row loop.
    let (vault_uuid, _epoch) = crate::vault::envelope_ops::read_local_identity(conn)?;

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

        // Decrypt for the wire payload (dual-read, WBS-304 — see SSH).
        // Class-aware dual-read (see SSH above): TOTP v1 rows are
        // ct + separate nonce/tag columns. Per-row skip-and-warn: one
        // unreadable row must not wedge the whole push. (Identity was
        // fetched once above the loop, with the SSH collector.)
        let secret = if crate::vault::envelope_ops::is_envelope_blob(&secret_encrypted) {
            crate::vault::envelope_ops::open_object_field(
                dek,
                Some(vault_uuid.as_str()),
                Some(&sync_id_str),
                crate::crypto::aad::ObjectType::TotpSecret,
                crate::crypto::aad::EnvelopePurpose::Secret,
                &secret_encrypted,
            )
        } else {
            crate::totp::decrypt_totp_secret(dek, &secret_encrypted, &nonce, &auth_tag)
        };
        let secret = match secret {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    sync_id = %sync_id_str,
                    error = %e,
                    "push: skipping unreadable TOTP secret (row stays pending)"
                );
                continue;
            }
        };

        // v0.8.x peers require the OLD wire fields — emit a context-free
        // v1-style encryption of the same plaintext (see SSH collector).
        let legacy_enc = crate::crypto::cipher::encrypt_string(dek, secret.as_str())
            .map_err(crate::PasswordManagerError::Crypto)?;

        // Identity metadata dual-read (WBS-306): sealed envelopes open
        // against the row's identity; legacy plaintext passes through.
        let issuer = crate::vault::envelope_ops::open_metadata_text_field(
            dek,
            Some(vault_uuid.as_str()),
            Some(&sync_id_str),
            crate::crypto::aad::ObjectType::TotpSecret,
            issuer,
        )?;
        let account_name = crate::vault::envelope_ops::open_metadata_text_field(
            dek,
            Some(vault_uuid.as_str()),
            Some(&sync_id_str),
            crate::crypto::aad::ObjectType::TotpSecret,
            account_name,
        )?;

        let payload = TotpPayload {
            secret,
            secret_encrypted: Some(legacy_enc.ciphertext),
            legacy_nonce: Some(legacy_enc.nonce.to_vec()),
            legacy_auth_tag: Some(legacy_enc.auth_tag.to_vec()),
            algorithm,
            digits,
            period,
            issuer,
            account_name,
            created_at,
            parent_credential_sync_id,
        };

        // The serialized payload carries the plaintext secret(s) until
        // encryption — zeroized on drop (WBS-308 / SR-CRYPTO-004).
        let payload_json = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
        );

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

/// Load a credential's domain mappings for the wire payload (dual-read,
/// WBS-306): the sealed `domain_enc` envelope opens against the mapping
/// row's identity; rows not yet backfilled pass their legacy plaintext
/// domain through. The wire payload carries PLAINTEXT domains — the whole
/// payload is re-encrypted for transport, and the peer seals under ITS OWN
/// identity on apply.
fn load_domain_mappings(
    conn: &Connection,
    dek: &DataEncryptionKey,
    vault_uuid: &str,
    entry_id: i64,
) -> Result<Vec<DomainPayload>> {
    let mut stmt = conn
        .prepare(
            "SELECT domain, is_primary, domain_enc, sync_id
             FROM domain_mappings WHERE entry_id = ?1",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([entry_id], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<rusqlite::types::Value>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    let mut domains = Vec::with_capacity(rows.len());
    for (mapping_index, (legacy_domain, is_primary, domain_enc, sync_id)) in
        rows.into_iter().enumerate()
    {
        let domain = match domain_enc {
            Some(blob) => {
                // Per-mapping skip-and-warn (containment parity with the
                // pending-row collectors): one tampered/corrupt mapping
                // must not wedge the whole push. The open still FAILS —
                // tamper is never honored — it is just not allowed to
                // take unrelated mappings down with it.
                match crate::vault::envelope_ops::open_metadata_text_field(
                    dek,
                    Some(vault_uuid),
                    sync_id.as_deref(),
                    crate::crypto::aad::ObjectType::DomainMapping,
                    Some(blob),
                ) {
                    Ok(domain) => domain,
                    Err(e) => {
                        tracing::warn!(
                            entry_id,
                            mapping_index,
                            error = %e,
                            "push: skipping unreadable domain mapping"
                        );
                        continue;
                    }
                }
            }
            None => legacy_domain,
        };
        let Some(domain) = domain else {
            continue; // sealed column empty AND no legacy value: nothing to push
        };
        domains.push(DomainPayload { domain, is_primary });
    }

    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::DataEncryptionKey;
    use crate::database::Database;

    fn setup_db_with_sync_schema() -> Database {
        fn seed_identity(db: &Database) {
            db.conn()
                .execute(
                    "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified, vault_uuid, format_version, key_epoch)
                     VALUES (1, 7, X'00', X'00', X'00', strftime('%s','now'), strftime('%s','now'), '11111111-1111-1111-1111-111111111111', 1, 1)",
                    [],
                )
                .unwrap();
        }

        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        seed_identity(&db);
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
    fn insert_pending_ssh_key(
        conn: &Connection,
        dek: &DataEncryptionKey,
        name: &str,
        is_deleted: bool,
    ) -> Uuid {
        // Real v1-encrypted private key material, sealed under the SAME
        // DEK the collector will decrypt with.
        let enc = crate::crypto::cipher::encrypt_string(
            dek,
            "-----BEGIN OPENSSH PRIVATE KEY-----fixture-----END-----",
        )
        .unwrap();
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO ssh_keys (
                name, comment, key_type, key_size, public_key,
                private_key_encrypted, nonce, auth_tag, fingerprint,
                created_at, modified_at,
                sync_id, sync_version, sync_state, is_deleted
            ) VALUES (?1, NULL, 'ed25519', 256, 'ssh-ed25519 AAAA...', ?2, ?3, ?4, 'SHA256:test',
                      ?5, ?6, ?7, 1, 'pending', ?8)",
            rusqlite::params![
                name,
                enc.ciphertext,
                enc.nonce.to_vec(),
                enc.auth_tag.to_vec(),
                now,
                now,
                sync_id.to_string(),
                is_deleted
            ],
        )
        .unwrap();

        sync_id
    }

    /// Insert a pending TOTP entry and return its sync_id.
    fn insert_pending_totp(
        conn: &Connection,
        dek: &DataEncryptionKey,
        entry_id: i64,
        is_deleted: bool,
    ) -> Uuid {
        // Real v1-encrypted TOTP secret under the collector's DEK.
        let (ct, nonce, auth_tag) =
            crate::totp::encrypt_totp_secret(dek, "JBSWY3DPEHPK3PXP").unwrap();
        let sync_id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO totp_secrets (
                entry_id, secret_encrypted, nonce, auth_tag,
                algorithm, digits, period, issuer, account_name, created_at,
                sync_id, sync_version, sync_state, is_deleted
            ) VALUES (?1, ?2, ?3, ?4,
                      'SHA1', 6, 30, 'Test', 'user@test.com', ?5,
                      ?6, 1, 'pending', ?7)",
            rusqlite::params![
                entry_id,
                ct,
                nonce,
                auth_tag,
                now,
                sync_id.to_string(),
                is_deleted
            ],
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
        let sync_id_ssh = insert_pending_ssh_key(conn, &dek, "my-key", false);

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
        let ssh_id = insert_pending_ssh_key(conn, &dek, "key1", false);

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

        let sync_id = insert_pending_ssh_key(conn, &dek, "deploy-key", false);

        let blobs = collect_pending_ssh_key_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].sync_id, sync_id);
        assert_eq!(blobs[0].entry_type, SyncEntryType::SshKey);
        assert!(!blobs[0].is_tombstone);

        // Gate-review finding 6: the EMITTED wire payload must carry BOTH
        // shapes — the current plaintext (for upgraded peers) AND the
        // populated legacy triplet (for v0.8.x peers, whose structs
        // require these fields). A collector refactor dropping either
        // shape fails here instead of wedging a mixed fleet.
        let payload_json =
            crate::sync::crypto::decrypt_from_sync(&dek, &blobs[0].encrypted_payload).unwrap();
        let payload: SshKeyPayload = serde_json::from_slice(&payload_json).unwrap();
        assert!(!payload.private_key.is_empty(), "plaintext must be present");
        let legacy = payload
            .private_key_encrypted
            .expect("legacy triplet must be emitted for v0.8.x peers");
        assert!(!legacy.is_empty());
        assert!(payload
            .legacy_nonce
            .as_deref()
            .map(|n| n.len() == 12)
            .unwrap_or(false));
        assert!(payload
            .legacy_auth_tag
            .as_deref()
            .map(|t| t.len() == 16)
            .unwrap_or(false));
    }

    #[test]
    fn collect_pending_ssh_key_blobs_tombstone() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();
        let device_id = Uuid::new_v4();

        let sync_id = insert_pending_ssh_key(conn, &dek, "revoked-key", true);

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

        let totp_sync_id = insert_pending_totp(conn, &dek, entry_id, false);

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

        let sync_id = insert_pending_totp(conn, &dek, entry_id, true);

        let blobs = collect_pending_totp_blobs(conn, &dek, device_id).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].is_tombstone);
        assert_eq!(blobs[0].sync_id, sync_id);
    }

    #[test]
    fn load_domain_mappings_empty() {
        let db = setup_db_with_sync_schema();
        let dek = DataEncryptionKey::new().unwrap();
        let domains =
            load_domain_mappings(db.conn(), &dek, "11111111-1111-1111-1111-111111111111", 999)
                .unwrap();
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

        let domains =
            load_domain_mappings(conn, &dek, "11111111-1111-1111-1111-111111111111", entry_id)
                .unwrap();
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn mixed_pending_count() {
        let db = setup_db_with_sync_schema();
        let conn = db.conn();
        let dek = DataEncryptionKey::new().unwrap();

        insert_pending_credential(conn, &dek, "Cred1", "u", "p", false);
        insert_pending_ssh_key(conn, &dek, "key1", false);

        let cred2_sync = insert_pending_credential(conn, &dek, "Cred2", "u2", "p2", false);
        let entry_id: i64 = conn
            .query_row(
                "SELECT entry_id FROM entries WHERE sync_id = ?1",
                [cred2_sync.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        insert_pending_totp(conn, &dek, entry_id, false);

        assert_eq!(count_pending_changes(conn).unwrap(), 4);
    }
}
