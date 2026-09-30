use super::{content_guard, envelope_ops, VaultManager};
use crate::crypto::aad::{EnvelopePurpose, ObjectType};
use crate::crypto::{DataEncryptionKey, KeyHierarchy};
use crate::{DatabaseError, PasswordManagerError, Result};
use std::path::{Path, PathBuf};

impl VaultManager {
    /// Create an independent vault with a fresh DEK and password. The source
    /// remains available; recovery slots, biometric enrollment and sync pairing
    /// must be established again for the new vault.
    pub fn rekey_to(&self, destination: &Path, new_password: &[u8]) -> Result<PathBuf> {
        let old_dek = self.key_hierarchy.dek()?;
        if new_password.len() < 12 {
            return Err(PasswordManagerError::InvalidInput(
                "new master password must be at least 12 bytes".into(),
            ));
        }
        if !self.verify_vault_envelopes()?.is_clean() {
            return Err(PasswordManagerError::InvalidInput(
                "verify and migrate all vault envelopes before data-key rotation".into(),
            ));
        }
        // Exclusive creation: an existing directory (even empty) is refused.
        std::fs::create_dir(destination)?;
        let mut cleanup = DestinationCleanup(Some(destination.to_path_buf()));
        crate::platform::set_owner_only_mode(destination, true)?;
        let staged_path = destination.join(".rekey-staging.db");
        drop(crate::platform::create_owner_only_file(&staged_path)?);
        {
            let db = self.lock_db()?;
            content_guard::verify_snapshot(db.conn(), old_dek)?;
            let unresolved: i64 = db.conn().query_row(
                "SELECT (SELECT count(*) FROM sync_conflicts) + (SELECT count(*) FROM sync_dead_letter)",
                [], |r| r.get(0)).map_err(DatabaseError::Sqlite)?;
            if unresolved != 0 {
                return Err(PasswordManagerError::InvalidInput(
                    "resolve sync conflicts and dead letters before data-key rotation".into(),
                ));
            }
            db.conn()
                .execute("VACUUM INTO ?1", [staged_path.to_string_lossy().as_ref()])
                .map_err(DatabaseError::Sqlite)?;
        }
        let db = crate::database::Database::open(&staged_path)?;
        content_guard::verify_copy(self.lock_db()?.conn(), db.conn(), old_dek)?;
        let mut hierarchy = KeyHierarchy::new();
        let (params, wrapped) = hierarchy.initialize_vault(new_password)?;
        let new_dek = hierarchy.dek()?;
        let new_uuid = uuid::Uuid::new_v4().to_string();
        let tx = db
            .conn()
            .unchecked_transaction()
            .map_err(DatabaseError::Sqlite)?;
        let context = RekeyContext {
            old: old_dek,
            new: new_dek,
            old_uuid: self.vault_uuid_str()?,
            new_uuid: &new_uuid,
        };
        use EnvelopePurpose::*;
        // Explicit inventory: no unknown blob is silently copied under a new
        // key. Stable object ids, associations, timestamps and policy survive.
        for (column, purpose) in [
            ("title", EntryTitle),
            ("username", EntryUsername),
            ("password", EntryPassword),
            ("url", EntryUrl),
            ("notes", EntryNotes),
        ] {
            rekey_column(
                &tx,
                &context,
                Column {
                    table: "entries",
                    id: "entry_id",
                    identity: "sync_id",
                    column,
                    kind: None,
                    purpose,
                    plaintext_legacy: false,
                },
            )?;
        }
        for spec in [
            Column {
                table: "ssh_keys",
                id: "key_id",
                identity: "sync_id",
                column: "private_key_encrypted",
                kind: Some(ObjectType::SshKey),
                purpose: Secret,
                plaintext_legacy: false,
            },
            Column {
                table: "ssh_keys",
                id: "key_id",
                identity: "sync_id",
                column: "comment",
                kind: Some(ObjectType::SshKey),
                purpose: Summary,
                plaintext_legacy: true,
            },
            Column {
                table: "totp_secrets",
                id: "totp_id",
                identity: "sync_id",
                column: "secret_encrypted",
                kind: Some(ObjectType::TotpSecret),
                purpose: Secret,
                plaintext_legacy: false,
            },
            Column {
                table: "totp_secrets",
                id: "totp_id",
                identity: "sync_id",
                column: "issuer",
                kind: Some(ObjectType::TotpSecret),
                purpose: TotpIssuer,
                plaintext_legacy: true,
            },
            Column {
                table: "totp_secrets",
                id: "totp_id",
                identity: "sync_id",
                column: "account_name",
                kind: Some(ObjectType::TotpSecret),
                purpose: TotpAccount,
                plaintext_legacy: true,
            },
            Column {
                table: "entities",
                id: "entity_id",
                identity: "entity_id",
                column: "name",
                kind: Some(ObjectType::RegistryEntity),
                purpose: Summary,
                plaintext_legacy: false,
            },
            Column {
                table: "entities",
                id: "entity_id",
                identity: "entity_id",
                column: "notes",
                kind: Some(ObjectType::RegistryEntity),
                purpose: Secret,
                plaintext_legacy: false,
            },
            Column {
                table: "domain_mappings",
                id: "mapping_id",
                identity: "sync_id",
                column: "domain_enc",
                kind: Some(ObjectType::DomainMapping),
                purpose: Summary,
                plaintext_legacy: false,
            },
        ] {
            rekey_column(&tx, &context, spec)?;
        }
        // Membership labels use the legacy encrypted-string format, with no
        // embedded identity. Preserve their format while replacing the key.
        {
            let mut stmt = tx
                .prepare(
                    "SELECT membership_id,label FROM entity_memberships WHERE label IS NOT NULL",
                )
                .map_err(DatabaseError::Sqlite)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
                .map_err(DatabaseError::Sqlite)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(DatabaseError::Sqlite)?;
            drop(stmt);
            for (id, blob) in rows {
                let old: crate::crypto::EncryptedEntry = bincode::deserialize(&blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let plaintext = crate::crypto::cipher::decrypt_to_string(old_dek, &old)?;
                let new = crate::crypto::cipher::encrypt_string(new_dek, &plaintext)?;
                let blob = bincode::serialize(&new)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                tx.execute(
                    "UPDATE entity_memberships SET label=?1 WHERE membership_id=?2",
                    rusqlite::params![blob, id],
                )
                .map_err(DatabaseError::Sqlite)?;
            }
        }
        let (kdf, wrap, nonce) = crate::crypto::dbwire::encode_metadata_blobs(&params, &wrapped)?;
        tx.execute("UPDATE db_metadata SET kdf_params=?1, wrapped_dek=?2, dek_nonce=?3,
            vault_uuid=?4, key_epoch=1, biometric_ref=NULL, slot_registry_mac=NULL, format_version=1",
            rusqlite::params![kdf,wrap,nonce,new_uuid]).map_err(DatabaseError::Sqlite)?;
        tx.execute_batch("DELETE FROM key_slots; DELETE FROM sync_metadata; DELETE FROM sync_devices;
            DELETE FROM sync_tombstones; DELETE FROM failed_attempts; DELETE FROM secret_equality_index;
            DELETE FROM domain_mapping_tags; DELETE FROM registry_state;
            UPDATE domain_mappings SET domain='';
            UPDATE entries SET sync_state='pending',sync_acked_version=0,last_synced_at=NULL;
            UPDATE ssh_keys SET sync_state='pending',sync_acked_version=0,last_synced_at=NULL;
            UPDATE totp_secrets SET sync_state='pending',sync_acked_version=0,last_synced_at=NULL;")
            .map_err(DatabaseError::Sqlite)?;
        Self::ensure_password_slot(
            &tx,
            &bincode::serialize(&params)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
            &bincode::serialize(&wrapped)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
            &bincode::serialize(&wrapped.nonce)
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?,
            1,
        )?;
        Self::commit_slot_registry(&hierarchy, &tx, &Self::load_key_slots(&tx)?)?;
        tx.commit().map_err(DatabaseError::Sqlite)?;
        drop(db);
        // Reopen under the new password, rebuild all DEK-derived indexes and
        // authenticate the finished vault before publishing it.
        let replacement = Self::open(&staged_path, new_password)?;
        if !replacement.verify_vault_envelopes()?.is_clean() {
            return Err(PasswordManagerError::InvalidInput(
                "re-keyed vault verification failed".into(),
            ));
        }
        replacement
            .lock_db()?
            .conn()
            .execute_batch("PRAGMA secure_delete=ON; VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(DatabaseError::Sqlite)?;
        drop(replacement);
        let final_path = destination.join("vault.db");
        for suffix in [".epoch", ".contents"] {
            std::fs::rename(
                PathBuf::from(format!("{}{suffix}", staged_path.display())),
                PathBuf::from(format!("{}{suffix}", final_path.display())),
            )?;
        }
        // Hard-link publication never overwrites a pre-existing file.
        std::fs::hard_link(&staged_path, &final_path)?;
        std::fs::remove_file(&staged_path)?;
        let _ = std::fs::remove_file(destination.join(".rekey-staging.db.contents.lock"));
        #[cfg(unix)]
        std::fs::File::open(destination)?.sync_all()?;
        cleanup.0 = None;
        Ok(final_path)
    }
}

struct DestinationCleanup(Option<PathBuf>);
impl Drop for DestinationCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

struct RekeyContext<'a> {
    old: &'a DataEncryptionKey,
    new: &'a DataEncryptionKey,
    old_uuid: &'a str,
    new_uuid: &'a str,
}
struct Column {
    table: &'static str,
    id: &'static str,
    identity: &'static str,
    column: &'static str,
    kind: Option<ObjectType>,
    purpose: EnvelopePurpose,
    plaintext_legacy: bool,
}

fn rekey_column(conn: &rusqlite::Connection, ctx: &RekeyContext<'_>, spec: Column) -> Result<()> {
    let kind_column = if spec.kind.is_none() {
        "credential_type"
    } else {
        "'password'"
    };
    let sql = format!(
        "SELECT CAST({} AS TEXT),{}, {},{} FROM {} WHERE {} IS NOT NULL",
        spec.id, spec.identity, spec.column, kind_column, spec.table, spec.column
    );
    let mut stmt = conn.prepare(&sql).map_err(DatabaseError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, rusqlite::types::Value>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;
    drop(stmt);
    for (id, identity, value, kind) in rows {
        let kind = match spec.kind {
            Some(kind) => kind,
            None => envelope_ops::envelope_object_type(crate::CredentialType::parse(&kind)?),
        };
        let plaintext = match value {
            rusqlite::types::Value::Text(s) if spec.plaintext_legacy => zeroize::Zeroizing::new(s),
            rusqlite::types::Value::Blob(blob) => envelope_ops::open_object_field(
                ctx.old,
                Some(ctx.old_uuid),
                Some(&identity),
                kind,
                spec.purpose,
                &blob,
            )?,
            _ => {
                return Err(PasswordManagerError::InvalidInput(
                    "unexpected encrypted column storage type".into(),
                ))
            }
        };
        let sealed = envelope_ops::seal_object_field(
            ctx.new,
            ctx.new_uuid,
            &identity,
            kind,
            spec.purpose,
            &plaintext,
            1,
        )?;
        let reopened = envelope_ops::open_object_field(
            ctx.new,
            Some(ctx.new_uuid),
            Some(&identity),
            kind,
            spec.purpose,
            &sealed,
        )?;
        use subtle::ConstantTimeEq;
        if !bool::from(plaintext.as_bytes().ct_eq(reopened.as_bytes())) {
            return Err(PasswordManagerError::InvalidInput(
                "re-key verification failed".into(),
            ));
        }
        conn.execute(
            &format!(
                "UPDATE {} SET {}=?1 WHERE {}=?2",
                spec.table, spec.column, spec.id
            ),
            rusqlite::params![sealed, id],
        )
        .map_err(DatabaseError::Sqlite)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CredentialType, Entry};

    #[test]
    fn rekey_preserves_data_and_old_dek_cannot_open_new_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let master = uuid::Uuid::new_v4().to_string();
        let replacement = uuid::Uuid::new_v4().to_string();
        let original =
            VaultManager::create(tmp.path().join("original.db"), master.as_bytes()).unwrap();
        let entry = Entry {
            entry_id: None,
            title: "service".into(),
            username: String::new(),
            password: uuid::Uuid::new_v4().to_string().into(),
            url: None,
            notes: Some("note".into()),
            credential_type: CredentialType::ApiKey,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            favorite: true,
        };
        let id = original.add_entry(&entry).unwrap();
        {
            let db = original.lock_db().unwrap();
            let dek = original.key_hierarchy.dek().unwrap();
            let tag_key = crate::crypto::keyring::derive_domain_tag_key(dek).unwrap();
            let ctx = crate::vault::domain_ops::MappingSealCtx {
                dek,
                vault_uuid: original.vault_uuid_str().unwrap(),
                epoch: original.session_epoch(),
                tag_key: &tag_key,
            };
            let tx = content_guard::ContentTransaction::begin(db.conn(), dek).unwrap();
            crate::vault::domain_ops::insert_sealed_domain_mapping(
                &tx,
                &ctx,
                id,
                "rekey.example.invalid",
                true,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let ssh_material = uuid::Uuid::new_v4().to_string();
        let ssh_id = original
            .add_ssh_key_plaintext(
                "key".into(),
                Some("comment".into()),
                crate::ssh::SshKeyType::Ed25519,
                None,
                "synthetic public".into(),
                ssh_material.clone(),
                "synthetic fingerprint".into(),
            )
            .unwrap();
        let totp_secret = data_encoding::BASE32_NOPAD.encode(uuid::Uuid::new_v4().as_bytes());
        original
            .add_totp_secret(
                id,
                &totp_secret,
                crate::totp::TotpAlgorithm::Sha1,
                6,
                30,
                Some("issuer"),
                Some("account"),
            )
            .unwrap();
        let entity = original
            .create_entity(
                "entity",
                crate::registry::EntityKind::Application,
                crate::registry::Criticality::Medium,
                Some("entity note"),
                None,
            )
            .unwrap();
        original
            .assign_entry(id, &entity.entity_id, Some("membership"))
            .unwrap();
        let destination = tmp.path().join("replacement");
        let path = original
            .rekey_to(&destination, replacement.as_bytes())
            .unwrap();
        let rotated = VaultManager::open(&path, replacement.as_bytes()).unwrap();
        assert_eq!(
            rotated.get_entry(id).unwrap().password.as_str(),
            entry.password.as_str()
        );
        assert!(rotated.get_entry(id).unwrap().username.is_empty());
        assert_eq!(
            rotated
                .find_entries_by_domain("rekey.example.invalid")
                .unwrap()[0]
                .entry_id,
            Some(id)
        );
        assert_eq!(
            rotated.export_ssh_private_key(ssh_id).unwrap(),
            ssh_material
        );
        let totp = rotated.get_totp_metadata(id).unwrap();
        assert_eq!(totp.issuer.as_deref(), Some("issuer"));
        assert_eq!(totp.account_name.as_deref(), Some("account"));
        assert_eq!(rotated.list_entities().unwrap()[0].name, "entity");
        assert_eq!(rotated.registry_overview(false).unwrap().entities.len(), 1);

        assert_ne!(
            original.key_hierarchy.dek().unwrap().as_bytes(),
            rotated.key_hierarchy.dek().unwrap().as_bytes()
        );
        assert_eq!(
            original.get_entry(id).unwrap().password.as_str(),
            entry.password.as_str()
        );
        assert!(original
            .rekey_to(&destination, replacement.as_bytes())
            .is_err());
        let blob: Vec<u8> = rotated
            .lock_db()
            .unwrap()
            .conn()
            .query_row(
                "SELECT password FROM entries WHERE entry_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        let doc: crate::crypto::Envelope = serde_json::from_slice(&blob).unwrap();
        assert!(crate::crypto::open_envelope(
            original.key_hierarchy.dek().unwrap(),
            doc.context,
            &blob
        )
        .is_err());
        drop(rotated);
        assert!(VaultManager::open(&path, master.as_bytes()).is_err());
    }
}
