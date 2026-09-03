use super::*;
use crate::database::Database;
use tempfile::TempDir;

#[test]
fn test_vault_create_and_open() {
    let temp_path = ":memory:"; // Use in-memory database for testing

    // Create vault
    let password = b"test_password_123!";
    let vault = VaultManager::create(temp_path, password);
    assert!(vault.is_ok());
    assert!(vault.unwrap().is_unlocked());

    // Opening with :memory: creates a new database each time, so we can't test reopening
    // In a real test, we'd use a temp file
}

#[test]
fn test_vault_add_and_get_entry() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "Test Entry".to_string(),
        username: "user@example.com".to_string(),
        password: "secret123".to_string().into(),
        url: Some("https://example.com".to_string()),
        notes: Some("Test notes".to_string()),
        credential_type: CredentialType::Password,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry_id = vault.add_entry(&entry).unwrap();
    assert!(entry_id > 0);

    let retrieved = vault.get_entry(entry_id).unwrap();
    assert_eq!(retrieved.title, "Test Entry");
    assert_eq!(retrieved.username, "user@example.com");
    assert_eq!(retrieved.password.as_str(), "secret123");
    assert_eq!(retrieved.url, Some("https://example.com".to_string()));
    assert_eq!(retrieved.notes, Some("Test notes".to_string()));
}

#[test]
fn test_vault_add_and_get_api_key_entry_type() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "Anthropic API".to_string(),
        username: "anthropic".to_string(),
        password: "sk-ant-test".to_string().into(),
        url: Some("https://console.anthropic.com".to_string()),
        notes: None,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
        credential_type: CredentialType::ApiKey,
    };

    let entry_id = vault.add_entry(&entry).unwrap();
    let retrieved = vault.get_entry(entry_id).unwrap();

    assert_eq!(retrieved.credential_type, CredentialType::ApiKey);
    assert_eq!(retrieved.password.as_str(), "sk-ant-test");
}

#[test]
fn test_vault_add_and_get_passkey_reference_entry_type() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "Example Passkey".to_string(),
        username: "user@example.com".to_string(),
        password: "passkey-ref:example.com:user@example.com"
            .to_string()
            .into(),
        url: Some("https://example.com".to_string()),
        notes: Some("Reference only; no WebAuthn private key material".to_string()),
        credential_type: CredentialType::PasskeyReference,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry_id = vault.add_entry(&entry).unwrap();
    let retrieved = vault.get_entry(entry_id).unwrap();

    assert_eq!(retrieved.credential_type, CredentialType::PasskeyReference);
    assert_eq!(
        retrieved.password.as_str(),
        "passkey-ref:example.com:user@example.com"
    );
}

#[test]
fn test_vault_list_entries() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry1 = Entry {
        entry_id: None,
        title: "Alpha Entry".to_string(),
        username: "user1@example.com".to_string(),
        password: "pass1".to_string().into(),
        url: None,
        notes: None,
        credential_type: CredentialType::Password,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry2 = Entry {
        entry_id: None,
        title: "Zeta Entry".to_string(),
        username: "user2@example.com".to_string(),
        password: "pass2".to_string().into(),
        url: None,
        notes: None,
        credential_type: CredentialType::Password,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: true,
    };

    vault.add_entry(&entry1).unwrap();
    vault.add_entry(&entry2).unwrap();

    let entries = vault.list_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].title, "Alpha Entry");
    assert_eq!(entries[1].title, "Zeta Entry");
}

#[test]
fn test_vault_lock() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let mut vault = VaultManager::create(temp_path, password).unwrap();
    assert!(vault.is_unlocked());

    vault.lock();
    assert!(!vault.is_unlocked());
}

#[test]
fn test_vault_locked_operations_fail() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let mut vault = VaultManager::create(temp_path, password).unwrap();
    vault.lock();

    assert!(vault
        .add_entry(&Entry {
            entry_id: None,
            title: "Test".to_string(),
            username: "test".to_string(),
            password: "test".to_string().into(),
            url: None,
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        })
        .is_err());

    assert!(vault.get_entry(1).is_err());
    assert!(vault.list_entries().is_err());
}

#[test]
fn test_vault_lockout_after_repeated_failed_unlocks() {
    let tmp = TempDir::new().unwrap();
    let temp_path = tmp.path().join("vault.db");
    let password = b"test_password";

    let vault = VaultManager::create(&temp_path, password).unwrap();
    drop(vault);

    for _ in 0..(DEFAULT_MAX_ATTEMPTS - 1) {
        let result = VaultManager::open(&temp_path, b"wrong_password");
        assert!(matches!(result, Err(PasswordManagerError::Crypto(_))));
    }

    let lockout_trigger = VaultManager::open(&temp_path, b"wrong_password");
    assert!(matches!(
        lockout_trigger,
        Err(PasswordManagerError::LockedOut(_))
    ));

    let still_locked_with_correct_password = VaultManager::open(&temp_path, password);
    assert!(matches!(
        still_locked_with_correct_password,
        Err(PasswordManagerError::LockedOut(_))
    ));
}

#[test]
fn test_totp_add_generate_remove() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let entry = Entry {
        entry_id: None,
        title: "TOTP Entry".to_string(),
        username: "user@example.com".to_string(),
        password: "secret123".to_string().into(),
        url: Some("https://example.com".to_string()),
        notes: None,
        credential_type: CredentialType::Password,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };

    let entry_id = vault.add_entry(&entry).unwrap();

    let totp_id = vault
        .add_totp_secret(
            entry_id,
            "JBSWY3DPEHPK3PXP",
            crate::totp::TotpAlgorithm::Sha1,
            6,
            30,
            Some("SentinelPass"),
            Some("user@example.com"),
        )
        .unwrap();
    assert!(totp_id > 0);

    let metadata = vault.get_totp_metadata(entry_id).unwrap();
    assert_eq!(metadata.entry_id, entry_id);
    assert_eq!(metadata.algorithm, crate::totp::TotpAlgorithm::Sha1);
    assert_eq!(metadata.digits, 6);
    assert_eq!(metadata.period, 30);

    let code = vault.generate_totp_code(entry_id).unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.seconds_remaining >= 1 && code.seconds_remaining <= 30);

    vault.remove_totp_secret(entry_id).unwrap();
    assert!(vault.generate_totp_code(entry_id).is_err());
}

#[test]
fn test_ssh_key_encrypt_decrypt_roundtrip() {
    use crate::crypto::DataEncryptionKey;

    let dek = DataEncryptionKey::new().unwrap();
    let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest private key content\n-----END OPENSSH PRIVATE KEY-----";

    // Test encryption
    let (encrypted, nonce, auth_tag) =
        crate::ssh::SshKey::encrypt_private_key(&dek, private_key).unwrap();

    assert!(!encrypted.is_empty());
    assert_eq!(nonce.len(), 12);
    assert_eq!(auth_tag.len(), 16);

    // Test decryption
    let decrypted =
        crate::ssh::SshKey::decrypt_private_key(&dek, &encrypted, &nonce, &auth_tag).unwrap();

    assert_eq!(decrypted, private_key);
}

#[test]
fn test_vault_add_and_list_ssh_keys() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create an encrypted SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "test-key".to_string(),
        Some("test comment".to_string()),
        crate::ssh::SshKeyType::Ed25519,
        Some(256),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKeyButValidFormat test@example.com"
            .to_string(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----"
            .to_string(),
        "SHA256:abcdefghijklmnopqrstuvwxyz123456=".to_string(),
    )
    .unwrap();

    // Add the key
    let key_id = vault.add_ssh_key(&ssh_key).unwrap();
    assert!(key_id > 0);

    // List keys
    let summaries = vault.list_ssh_keys().unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].name, "test-key");
    assert_eq!(summaries[0].key_type, crate::ssh::SshKeyType::Ed25519);
}

#[test]
fn test_import_pairing_bootstrap_into_empty_vault() {
    let password = b"pairing-password";
    let relay_url = "https://relay.example.com";
    let source_vault_id = uuid::Uuid::new_v4();

    let source = VaultManager::create(":memory:", password).unwrap();
    let source_identity = crate::sync::device::DeviceIdentity::generate("Source Device");
    source
        .init_sync(
            relay_url,
            "Source Device",
            source_vault_id,
            &source_identity,
        )
        .unwrap();
    let bootstrap = source.export_pairing_bootstrap().unwrap();

    let mut target = VaultManager::create(":memory:", password).unwrap();
    {
        let db = target.db.lock().unwrap();
        db.conn()
            .execute(
                "INSERT INTO sync_devices (device_id, device_name, device_type, public_key, registered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    "Stale Device",
                    "desktop",
                    vec![1u8; 32],
                    Utc::now().timestamp()
                ],
            )
            .unwrap();
    }
    target
        .import_pairing_bootstrap(password, &bootstrap)
        .expect("pairing bootstrap import should succeed for empty vault");

    let target_db = target.db.lock().unwrap();
    let (target_kdf, target_wrapped, _target_epoch) =
        VaultManager::load_vault_metadata(&target_db).unwrap();
    let target_kdf_blob = bincode::serialize(&target_kdf).unwrap();
    let target_wrapped_blob = bincode::serialize(&target_wrapped).unwrap();
    let sync_device_count: i64 = target_db
        .conn()
        .query_row("SELECT COUNT(*) FROM sync_devices", [], |row| row.get(0))
        .unwrap();
    drop(target_db);

    assert_eq!(target_kdf_blob, bootstrap.kdf_params_blob);
    assert_eq!(target_wrapped_blob, bootstrap.wrapped_dek_blob);
    assert_eq!(sync_device_count, 0);
    assert!(target.key_hierarchy.dek().is_ok());
}

#[test]
fn test_import_pairing_bootstrap_rejects_non_empty_vault() {
    let password = b"pairing-password";

    let source = VaultManager::create(":memory:", password).unwrap();
    let source_identity = crate::sync::device::DeviceIdentity::generate("Source Device");
    source
        .init_sync(
            "https://relay.example.com",
            "Source Device",
            uuid::Uuid::new_v4(),
            &source_identity,
        )
        .unwrap();
    let bootstrap = source.export_pairing_bootstrap().unwrap();

    let mut target = VaultManager::create(":memory:", password).unwrap();
    let entry = Entry {
        entry_id: None,
        title: "Local data".to_string(),
        username: "user".to_string(),
        password: "pass".to_string().into(),
        url: None,
        notes: None,
        credential_type: CredentialType::Password,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        favorite: false,
    };
    target.add_entry(&entry).unwrap();

    let err = target
        .import_pairing_bootstrap(password, &bootstrap)
        .expect_err("non-empty vault should be rejected");
    match err {
        PasswordManagerError::InvalidInput(msg) => {
            assert!(msg.contains("must be empty"));
        }
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn test_vault_get_and_export_ssh_key() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create and add an SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let original_private_key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "export-test".to_string(),
        None,
        crate::ssh::SshKeyType::Rsa,
        Some(4096),
        "ssh-rsa AAAAB3NzaC1yc2E... test@example.com".to_string(),
        original_private_key.to_string(),
        "SHA256:abcdef123456=".to_string(),
    )
    .unwrap();

    let key_id = vault.add_ssh_key(&ssh_key).unwrap();

    // Get the full key
    let retrieved_key = vault.get_ssh_key(key_id).unwrap();
    assert_eq!(retrieved_key.name, "export-test");
    assert_eq!(retrieved_key.key_type, crate::ssh::SshKeyType::Rsa);

    // Export and verify private key matches
    let exported_private_key = vault.export_ssh_private_key(key_id).unwrap();
    assert_eq!(exported_private_key, original_private_key);
}

#[test]
fn test_vault_delete_ssh_key() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Create and add an SSH key
    let dek = vault.key_hierarchy.dek().unwrap();
    let ssh_key = crate::ssh::SshKey::create_encrypted(
        dek,
        "to-delete".to_string(),
        None,
        crate::ssh::SshKeyType::Ed25519,
        Some(256),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKey test@example.com".to_string(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----".to_string(),
        "SHA256:deleted=".to_string(),
    )
    .unwrap();

    let key_id = vault.add_ssh_key(&ssh_key).unwrap();

    // Verify it exists
    let keys = vault.list_ssh_keys().unwrap();
    assert_eq!(keys.len(), 1);

    // Delete the key
    vault.delete_ssh_key(key_id).unwrap();

    // Verify it's gone
    let keys = vault.list_ssh_keys().unwrap();
    assert_eq!(keys.len(), 0);

    // Trying to get it should fail
    assert!(vault.get_ssh_key(key_id).is_err());
}

#[test]
fn test_ssh_key_wrong_password_fails() {
    use crate::crypto::DataEncryptionKey;

    let dek1 = DataEncryptionKey::new().unwrap();
    let dek2 = DataEncryptionKey::new().unwrap();

    let private_key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

    // Encrypt with dek1
    let (encrypted, nonce, auth_tag) =
        crate::ssh::SshKey::encrypt_private_key(&dek1, private_key).unwrap();

    // Try to decrypt with dek2 (should fail)
    let result = crate::ssh::SshKey::decrypt_private_key(&dek2, &encrypted, &nonce, &auth_tag);
    assert!(result.is_err());
}

#[test]
fn test_biometric_ref_metadata_roundtrip() {
    let db = Database::in_memory().unwrap();
    db.initialize_schema().unwrap();

    let mut key_hierarchy = KeyHierarchy::new();
    let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(b"test_password").unwrap();
    VaultManager::store_vault_metadata(&db, &kdf_params, &wrapped_dek).unwrap();

    assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);

    VaultManager::set_biometric_ref(&db, Some("vault-biometric-ref")).unwrap();
    assert_eq!(
        VaultManager::load_biometric_ref(&db).unwrap().as_deref(),
        Some("vault-biometric-ref")
    );

    VaultManager::set_biometric_ref(&db, None).unwrap();
    assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);
}

#[test]
fn test_pagination_first_page() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Add 75 entries
    for i in 0..75 {
        let entry = Entry {
            entry_id: None,
            title: format!("Entry {:03}", i),
            username: format!("user{}@example.com", i),
            password: format!("pass{}", i).into(),
            url: Some(format!("https://example{}.com", i)),
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: i % 2 == 0,
        };
        vault.add_entry(&entry).unwrap();
    }

    // Request first page with 25 items
    let pagination = PaginationParams::new(0, 25);
    let result = vault.list_entries_paginated(pagination).unwrap();

    assert_eq!(result.items.len(), 25);
    assert_eq!(result.total_count, 75);
    assert!(result.has_more);
}

#[test]
fn test_pagination_second_page() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Add 60 entries
    for i in 0..60 {
        let entry = Entry {
            entry_id: None,
            title: format!("Site {:03}", i),
            username: "user@example.com".to_string(),
            password: "secret".to_string().into(),
            url: None,
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };
        vault.add_entry(&entry).unwrap();
    }

    // Request second page with 25 items
    let pagination = PaginationParams::new(1, 25);
    let result = vault.list_entries_paginated(pagination).unwrap();

    assert_eq!(result.items.len(), 25);
    assert_eq!(result.total_count, 60);
    assert!(result.has_more);
}

#[test]
fn test_pagination_last_page() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Add 30 entries
    for i in 0..30 {
        let entry = Entry {
            entry_id: None,
            title: format!("Item {:03}", i),
            username: "user@example.com".to_string(),
            password: "pass".to_string().into(),
            url: None,
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };
        vault.add_entry(&entry).unwrap();
    }

    // Request second page with 25 items (should only have 5 items)
    let pagination = PaginationParams::new(1, 25);
    let result = vault.list_entries_paginated(pagination).unwrap();

    assert_eq!(result.items.len(), 5);
    assert_eq!(result.total_count, 30);
    assert!(!result.has_more); // No more pages
}

#[test]
fn test_pagination_large_page_size_capped() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    // Add 50 entries
    for i in 0..50 {
        let entry = Entry {
            entry_id: None,
            title: format!("Test {}", i),
            username: "user@example.com".to_string(),
            password: "pass".to_string().into(),
            url: None,
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };
        vault.add_entry(&entry).unwrap();
    }

    // Request page size of 2000 (should be capped to 1000)
    let pagination = PaginationParams::new(0, 2000);
    let result = vault.list_entries_paginated(pagination).unwrap();

    assert_eq!(result.items.len(), 50); // All 50 entries returned
    assert_eq!(result.total_count, 50);
    assert!(!result.has_more);
}

#[test]
fn test_pagination_empty_vault() {
    let temp_path = ":memory:";
    let password = b"test_password";

    let vault = VaultManager::create(temp_path, password).unwrap();

    let pagination = PaginationParams::default();
    let result = vault.list_entries_paginated(pagination).unwrap();

    assert_eq!(result.items.len(), 0);
    assert_eq!(result.total_count, 0);
    assert!(!result.has_more);
}

#[test]
fn test_pagination_default_params() {
    let params = PaginationParams::default();
    assert_eq!(params.page, 0);
    assert_eq!(params.page_size, 50);
    assert_eq!(params.offset(), 0);
    assert_eq!(params.limit(), 50);
}

fn add_test_ssh_key(vault: &VaultManager, name: &str) -> i64 {
    vault
        .add_ssh_key_plaintext(
            name.to_string(),
            None,
            crate::ssh::SshKeyType::Ed25519,
            None,
            "ssh-ed25519 AAAA test".to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
            format!("SHA256:{}", name),
        )
        .unwrap()
}

#[test]
fn test_ssh_pagination_first_page() {
    let vault = VaultManager::create(":memory:", b"test_password").unwrap();
    for i in 0..30 {
        add_test_ssh_key(&vault, &format!("key_{:03}", i));
    }

    let result = vault
        .list_ssh_keys_paginated(PaginationParams::new(0, 10))
        .unwrap();

    assert_eq!(result.items.len(), 10);
    assert_eq!(result.total_count, 30);
    assert!(result.has_more);
}

#[test]
fn test_ssh_pagination_last_page() {
    let vault = VaultManager::create(":memory:", b"test_password").unwrap();
    for i in 0..25 {
        add_test_ssh_key(&vault, &format!("key_{:03}", i));
    }

    // Page 2 of page_size=10 → items 20-24 (5 items)
    let result = vault
        .list_ssh_keys_paginated(PaginationParams::new(2, 10))
        .unwrap();

    assert_eq!(result.items.len(), 5);
    assert_eq!(result.total_count, 25);
    assert!(!result.has_more);
}

#[test]
fn test_ssh_pagination_empty() {
    let vault = VaultManager::create(":memory:", b"test_password").unwrap();

    let result = vault
        .list_ssh_keys_paginated(PaginationParams::default())
        .unwrap();

    assert_eq!(result.items.len(), 0);
    assert_eq!(result.total_count, 0);
    assert!(!result.has_more);
}

#[test]
fn test_ssh_pagination_sorted_by_name() {
    let vault = VaultManager::create(":memory:", b"test_password").unwrap();
    // Insert in reverse order
    for i in (0..5).rev() {
        add_test_ssh_key(&vault, &format!("key_{:03}", i));
    }

    let result = vault
        .list_ssh_keys_paginated(PaginationParams::new(0, 10))
        .unwrap();

    let names: Vec<&str> = result.items.iter().map(|k| k.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "results should be sorted by name");
}

#[test]
fn test_ssh_pagination_locked_vault_fails() {
    let mut vault = VaultManager::create(":memory:", b"test_password").unwrap();
    vault.lock();

    let err = vault
        .list_ssh_keys_paginated(PaginationParams::default())
        .unwrap_err();
    assert!(
        matches!(err, PasswordManagerError::VaultLocked),
        "expected VaultLocked"
    );
}

#[test]
fn master_password_rotation_rewraps_without_touching_entries() {
    use crate::CredentialType;

    let dir = tempfile::TempDir::new().unwrap();
    let vault_path = dir.path().join("rotate.db");
    let old_pw = b"old-master-password-1";
    let new_pw = b"new-master-password-2";

    let mut vault = VaultManager::create(&vault_path, old_pw).unwrap();
    vault
        .add_entry(&crate::vault::Entry {
            entry_id: None,
            title: "Anthropic".to_string(),
            username: "ops".to_string(),
            password: "sk-ant-before-rotation".to_string().into(),
            url: Some("anthropic".to_string()),
            notes: None,
            credential_type: CredentialType::ApiKey,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            favorite: false,
        })
        .unwrap();

    // Same-password rotation is rejected.
    assert!(vault.change_master_password(old_pw, old_pw).is_err());
    // Short new password is rejected.
    assert!(vault.change_master_password(old_pw, b"short").is_err());

    vault.change_master_password(old_pw, new_pw).unwrap();

    // Old password must no longer open the vault...
    drop(vault);
    assert!(VaultManager::open(&vault_path, old_pw).is_err());

    // ...and the new password opens it with the pre-rotation entry intact
    // (same DEK — ciphertexts untouched).
    let mut reopened = VaultManager::open(&vault_path, new_pw).unwrap();
    let summaries = reopened.list_entries().unwrap();
    assert_eq!(summaries.len(), 1);
    let entry = reopened.get_entry(summaries[0].entry_id).unwrap();
    assert_eq!(entry.password.as_str(), "sk-ant-before-rotation");

    // Rotation again from the reopened vault keeps working (epoch increments).
    reopened
        .change_master_password(new_pw, b"third-master-password")
        .unwrap();
}
