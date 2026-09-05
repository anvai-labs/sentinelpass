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
    VaultManager::store_vault_metadata(
        &db,
        &kdf_params,
        &wrapped_dek,
        "00000000-0000-0000-0000-000000000001",
    )
    .unwrap();

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

#[test]
fn pair_join_from_a_rotated_source_vault_succeeds_and_persists_epoch() {
    // Regression test for the exact flow `sentinelpass passwd` tells users
    // to run after rotation ("paired sync devices must re-pair"): the
    // source vault rotates its master password (epoch 1 -> 2, wrap becomes
    // epoch-bound), exports a pairing bootstrap under the NEW password, and
    // a fresh device imports it. Import must (a) succeed — an epoch-bound
    // wrap requires the epoch-aware unlock, not the legacy one — and (b)
    // persist the imported epoch, or the joined vault would be unopenable
    // on its very next `open()`.
    let dir = tempfile::TempDir::new().unwrap();
    let source_path = dir.path().join("source.db");
    let target_path = dir.path().join("target.db");
    let old_pw = b"source-old-password-1";
    let new_pw = b"source-new-password-2";

    let mut source = VaultManager::create(&source_path, old_pw).unwrap();
    source.change_master_password(old_pw, new_pw).unwrap();

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
    assert_eq!(
        bootstrap.key_epoch, 2,
        "bootstrap must carry the post-rotation epoch"
    );

    // The target vault's own pre-import password is irrelevant — import
    // replaces its KDF params, wrap, and epoch outright — but the caller
    // must supply the ORIGIN's current password to unwrap the bootstrap.
    let mut target = VaultManager::create(&target_path, b"target-throwaway-password").unwrap();
    target
        .import_pairing_bootstrap(new_pw, &bootstrap)
        .expect("pair-join from a rotated source vault must succeed");
    assert_eq!(target.key_epoch().unwrap(), 2);
    drop(target);

    // The real regression: without persisting the imported epoch, this
    // reopen would fail (joiner recorded epoch 1 against a wrap bound to 2).
    let reopened = VaultManager::open(&target_path, new_pw)
        .expect("joined vault must reopen with the origin's rotated password");
    assert_eq!(reopened.key_epoch().unwrap(), 2);

    // The DEK carried over from the source vault, so a value encrypted
    // under it there is decryptable here too (sanity: no source data was
    // asserted, so instead confirm the vault is genuinely unlocked and
    // functional post pair-join).
    let summaries = reopened.list_entries().unwrap();
    assert!(summaries.is_empty());
    reopened
        .add_entry(&Entry {
            entry_id: None,
            title: "post-pairjoin".to_string(),
            username: "user".to_string(),
            password: "secret".to_string().into(),
            url: None,
            notes: None,
            credential_type: CredentialType::Password,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        })
        .unwrap();
}

#[test]
fn pair_join_rejects_when_local_entities_are_not_empty() {
    // A local entity's name/notes are encrypted under this vault's DEK;
    // import_pairing_bootstrap replaces that DEK outright, which would
    // leave any existing entity permanently undecryptable. The "must be
    // empty" guard has to cover entities, not just entries/ssh_keys/totp.
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
    target
        .create_entity(
            "pre-existing-entity",
            crate::registry::EntityKind::Other,
            crate::registry::Criticality::Medium,
            None,
            None,
        )
        .unwrap();

    let err = target
        .import_pairing_bootstrap(password, &bootstrap)
        .expect_err("non-empty (entity) vault should be rejected");
    match err {
        PasswordManagerError::InvalidInput(msg) => {
            assert!(msg.contains("must be empty"));
        }
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn pair_join_from_legacy_unrotated_bootstrap_still_works() {
    // A bootstrap exported by a vault that has never been rotated has
    // key_epoch's serde default (1) exercised implicitly here via a normal
    // (non-rotated) export/import cycle, and the wrap is NOT epoch-bound —
    // confirming the epoch-aware unlock path is fully backward compatible
    // with un-rotated vaults (the common case).
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
    assert_eq!(bootstrap.key_epoch, 1);

    let mut target = VaultManager::create(":memory:", password).unwrap();
    target
        .import_pairing_bootstrap(password, &bootstrap)
        .expect("pair-join from an unrotated source vault must succeed");
    assert_eq!(target.key_epoch().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// WBS-301: vault identity, format version, and the epoch high-water sidecar.
// ---------------------------------------------------------------------------

mod wbs301_epoch_and_identity {
    use crate::{PasswordManagerError, VaultManager};
    use std::fs;

    fn temp_vault(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sp-wbs301-{}-{}.db",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
        path
    }

    fn cleanup(vault: &std::path::Path) {
        let _ = fs::remove_file(vault);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(vault));
    }

    /// The vault UUID is durable identity: minted at creation, stable across
    /// reopen.
    #[test]
    fn vault_uuid_is_stable_across_reopen() {
        let path = temp_vault("uuid");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let uuid = vault.vault_uuid().expect("uuid at create").to_string();
        drop(vault);

        let reopened = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        assert_eq!(reopened.vault_uuid(), Some(uuid.as_str()));
        drop(reopened);
        cleanup(&path);
    }

    /// Rotation advances the durable epoch AND the sidecar; the vault reopens
    /// at the new epoch without tripping the guard.
    #[test]
    fn rotation_advances_epoch_and_sidecar_then_reopens() {
        let path = temp_vault("rotate");
        let mut vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let vault_uuid_str = vault.vault_uuid().expect("uuid").to_string();
        assert_eq!(vault.key_epoch().unwrap(), 1);
        vault
            .change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42")
            .unwrap();
        assert_eq!(vault.key_epoch().unwrap(), 2);
        drop(vault);

        // Pin the sidecar CONTENT after rotation (not just the reopen result,
        // which would self-heal a missing bump via the one-step-lag path —
        // adversarial-review finding on tautological tests).
        let sidecar = fs::read_to_string(crate::vault::epoch_guard::sidecar_path(&path))
            .expect("rotation must follow the sidecar forward");
        let lines: Vec<&str> = sidecar.lines().collect();
        assert_eq!(lines[1], vault_uuid_str, "sidecar binds the vault uuid");
        assert_eq!(lines[2], "2", "sidecar records the advanced epoch");

        let reopened = VaultManager::open(&path, b"staple-anchor-quantum-42").unwrap();
        assert_eq!(reopened.key_epoch().unwrap(), 2);
        drop(reopened);
        cleanup(&path);
    }

    /// Whole-file rollback detection: after the epoch advanced to 2 (sidecar
    /// at 2), restoring the pre-rotation database leaves the on-disk epoch at
    /// 1 — and the pre-rotation wrap is NOT epoch-bound, so the old password
    /// would otherwise unlock silently. The sidecar must refuse first.
    #[test]
    fn rolled_back_epoch_refuses_open_before_unlock() {
        let path = temp_vault("rollback");
        let mut vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        vault
            .change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42")
            .unwrap();
        drop(vault);

        // Simulate the rollback: the DB claims the pre-rotation epoch.
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute("UPDATE db_metadata SET key_epoch = 1 WHERE id = 1", [])
                .unwrap();
        }

        // The OLD password is correct for the rolled-back wrap — the guard
        // must refuse before that unlock can succeed.
        match VaultManager::open(&path, b"correct-horse-battery") {
            Err(PasswordManagerError::EpochRollback {
                on_disk,
                high_water,
            }) => {
                assert_eq!((on_disk, high_water), (1, 2));
            }
            Err(other) => panic!("expected EpochRollback, got {other:?}"),
            Ok(_) => panic!("rolled-back epoch must refuse to open"),
        }
        cleanup(&path);
    }

    /// Trust-on-first-use: a missing sidecar (new machine, bundle restore)
    /// mints from the current DB epoch and opens — never a hard failure.
    #[test]
    fn absent_sidecar_mints_and_opens() {
        let path = temp_vault("tofu");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        drop(vault);

        fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path)).unwrap();
        let reopened = VaultManager::open(&path, b"correct-horse-battery")
            .expect("absent sidecar must be trust-on-first-use, not fatal");
        assert_eq!(reopened.key_epoch().unwrap(), 1);
        drop(reopened);
        cleanup(&path);
    }

    /// Migration path: a vault whose identity was stripped back to the v5
    /// shape gains a UUID on first open via the migration runner.
    #[test]
    fn legacy_vault_gains_identity_on_open() {
        let path = temp_vault("legacy");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        drop(vault);

        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute_batch(
                    "UPDATE db_metadata SET vault_uuid = NULL, format_version = 1, version = 5;",
                )
                .unwrap();
        }
        // A true v5 vault predates sidecars entirely — remove ours so the
        // first v6 open follows the real legacy path: migrate identity, then
        // trust-on-first-use mint the sidecar under the migrated UUID.
        fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path)).unwrap();
        let reopened = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        let uuid = reopened.vault_uuid().expect("uuid minted by migration");
        assert!(uuid::Uuid::parse_str(uuid).is_ok());
        drop(reopened);
        cleanup(&path);
    }
}

/// WBS-309 negative: if the durable commit fails mid-rotation, the old
/// password must remain fully usable and the epoch unchanged — staging must
/// never leak into memory or disk. Failure is injected with a second
/// connection holding an exclusive write lock, so the rotation's UPDATE
/// cannot commit.
#[test]
fn rotation_commit_failure_leaves_old_password_intact() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs309-commitfail-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let mut vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
    assert_eq!(vault.key_epoch().unwrap(), 1);

    // A concurrent exclusive writer makes the rotation's durable UPDATE fail.
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker
        .busy_timeout(std::time::Duration::from_millis(0))
        .unwrap();
    blocker
        .execute_batch(
            "BEGIN EXCLUSIVE; UPDATE db_metadata SET last_modified = last_modified WHERE id = 1;",
        )
        .unwrap();

    let result =
        vault.change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42");
    assert!(result.is_err(), "rotation must fail while the db is locked");

    blocker.execute_batch("ROLLBACK;").unwrap();
    drop(blocker);
    drop(vault);

    // Old password fully usable, epoch unchanged.
    let reopened = VaultManager::open(&path, b"correct-horse-battery")
        .expect("old password must remain fully usable after a failed rotation");
    assert_eq!(reopened.key_epoch().unwrap(), 1, "epoch must be unchanged");
    drop(reopened);

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

/// Adversarial-review finding: a NULL vault_uuid must NOT silently disable
/// the epoch guard — that would resurrect rolled-back vaults with a single
/// UPDATE by a DB-writable attacker.
#[test]
fn nulled_vault_uuid_refuses_to_open() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs301-nulluuid-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
    drop(vault);

    {
        let db = crate::database::Database::open(&path).unwrap();
        db.conn()
            .execute("UPDATE db_metadata SET vault_uuid = NULL WHERE id = 1", [])
            .unwrap();
    }

    match VaultManager::open(&path, b"correct-horse-battery") {
        Err(crate::PasswordManagerError::InvalidInput(msg)) => {
            assert!(msg.contains("vault_uuid"), "got: {msg}");
        }
        Err(other) => panic!("expected identity error, got {other:?}"),
        Ok(_) => panic!("NULL vault_uuid must fail closed, not skip the guard"),
    }
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

/// Adversarial-review finding: the rotation UPDATE must be guarded against
/// a stale epoch (concurrent CLI + UI rotations stage at the same next epoch
/// and would otherwise silently clobber each other). The guard is the
/// `WHERE id = 1 AND key_epoch = ?expected` clause; `change_master_password`
/// reloads metadata at call time, so the guarded window is its internal
/// read → UPDATE — exercised here at the SQL level.
#[test]
fn rotation_update_is_guarded_against_stale_epoch() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs309-concurrent-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let mut vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
    vault
        .change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42")
        .unwrap();
    drop(vault);

    // The guarded UPDATE shape: a writer expecting the OLD epoch (1) must
    // affect zero rows now that the durable epoch is 2.
    let db = crate::database::Database::open(&path).unwrap();
    let rows = db
        .conn()
        .execute(
            "UPDATE db_metadata SET last_modified = last_modified \
             WHERE id = 1 AND key_epoch = 1",
            [],
        )
        .unwrap();
    assert_eq!(rows, 0, "stale-epoch rotation commit must be a no-op");
    let rows = db
        .conn()
        .execute(
            "UPDATE db_metadata SET last_modified = last_modified \
             WHERE id = 1 AND key_epoch = 2",
            [],
        )
        .unwrap();
    assert_eq!(rows, 1);
    drop(db);

    // And the pre-guard API behavior: a stale manager using the old password
    // against the committed rotation is refused (authentication failure).
    let mut stale = VaultManager::open(&path, b"staple-anchor-quantum-42").unwrap();
    let result = stale.change_master_password(b"correct-horse-battery", b"another-password-42");
    assert!(result.is_err());

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

/// Adversarial-review finding (round 2): a joining device whose origin vault
/// rotated more than once must not be locked out by the at-most-+1 epoch rule
/// — pair-join deliberately adopts the origin's epoch and must rebase the
/// high-water sidecar to it.
#[test]
fn pair_join_from_a_multi_rotated_source_rebases_the_sidecar() {
    use crate::VaultManager;
    use std::fs;

    let dir = std::env::temp_dir().join(format!("sp-pairjoin-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("source.db");
    let target_path = dir.join("target.db");

    // Rotate the origin twice: epoch 3 (beyond the +1 lag allowance).
    let mut source = VaultManager::create(&source_path, b"password-one-a").unwrap();
    source
        .change_master_password(b"password-one-a", b"password-two-b")
        .unwrap();
    source
        .change_master_password(b"password-two-b", b"password-three-c")
        .unwrap();
    assert_eq!(source.key_epoch().unwrap(), 3);

    let identity = crate::sync::device::DeviceIdentity::generate("S");
    source
        .init_sync(
            "https://relay.example.com",
            "S",
            uuid::Uuid::new_v4(),
            &identity,
        )
        .unwrap();
    let bootstrap = source.export_pairing_bootstrap().unwrap();
    assert_eq!(bootstrap.key_epoch, 3);
    drop(source);

    let mut target = VaultManager::create(&target_path, b"target-throwaway-password").unwrap();
    target
        .import_pairing_bootstrap(b"password-three-c", &bootstrap)
        .expect("pair-join from a multi-rotated source must succeed");
    drop(target);

    // The joiner reopens cleanly at the adopted epoch — no jump refusal.
    let reopened = VaultManager::open(&target_path, b"password-three-c")
        .expect("joining device must reopen after adopting a multi-rotated bootstrap");
    assert_eq!(reopened.key_epoch().unwrap(), 3);
    drop(reopened);

    let _ = fs::remove_dir_all(&dir);
}

/// Adversarial-review finding: pair-join's registry MAC is bound to the
/// IMPORTED DEK (`sync_password_slot_after_material_change` derives it from
/// `imported_hierarchy`), so a partial rollback that reverts only
/// `db_metadata` on a post-commit sidecar-rebase failure desyncs the wrap
/// (original DEK) from the registry MAC (imported DEK) — a permanent brick.
/// The fix commits metadata+registry as one transaction and never partially
/// reverts it; a later sidecar failure is surfaced as an error but the
/// on-disk vault stays internally consistent and opens (after deleting the
/// stale sidecar, exactly as its own error message instructs).
#[cfg(unix)]
#[test]
fn pair_join_sidecar_failure_leaves_a_consistent_not_bricked_vault() {
    use crate::VaultManager;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "sp-pairjoin-sidecarfail-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&dir).unwrap();
    let source_path = dir.join("source.db");
    let target_path = dir.join("target.db");

    let mut source = VaultManager::create(&source_path, b"password-one-a").unwrap();
    source
        .change_master_password(b"password-one-a", b"password-two-b")
        .unwrap();
    let identity = crate::sync::device::DeviceIdentity::generate("S");
    source
        .init_sync(
            "https://relay.example.com",
            "S",
            uuid::Uuid::new_v4(),
            &identity,
        )
        .unwrap();
    let bootstrap = source.export_pairing_bootstrap().unwrap();
    assert_eq!(bootstrap.key_epoch, 2);
    drop(source);

    let mut target = VaultManager::create(&target_path, b"target-throwaway-password").unwrap();

    // Force the post-commit sidecar rebase to fail: make the vault directory
    // read-only so the sidecar's temp-file create (and any rename) cannot
    // happen. The dir mode is restored before cleanup regardless of outcome.
    let dir_mode = fs::metadata(&dir).unwrap().permissions().mode();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();

    let import_result = target.import_pairing_bootstrap(b"password-two-b", &bootstrap);

    fs::set_permissions(&dir, fs::Permissions::from_mode(dir_mode)).unwrap();

    assert!(
        import_result.is_err(),
        "the sidecar rebase must fail under a read-only directory"
    );
    drop(target);

    // The critical assertion: despite the surfaced error, db_metadata's wrap
    // and the key-slot registry MAC are consistent (both reflect the
    // IMPORTED state) — deleting the now-stale sidecar (exactly what the
    // refusal error instructs) must let the vault open with the IMPORTED
    // password. A buggy partial-revert would make this open fail with a
    // registry integrity error even after the sidecar is removed.
    fs::remove_file(crate::vault::epoch_guard::sidecar_path(&target_path)).unwrap();
    let reopened = VaultManager::open(&target_path, b"password-two-b").expect(
        "vault must remain internally consistent and openable with the imported password \
         after a sidecar-rebase failure — a partial DB-level revert would desync the wrap \
         from the registry MAC and brick it permanently",
    );
    assert_eq!(reopened.key_epoch().unwrap(), 2);
    assert_eq!(reopened.list_key_slots().unwrap().len(), 1);
    drop(reopened);

    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(dir_mode));
    let _ = fs::remove_dir_all(&dir);
}

/// Round-4 convergence finding: `biometric_ref` legitimately toggles at a
/// constant epoch, so it must NOT be part of the anchored material digest —
/// anchoring it false-refused every biometric toggle at the next open. This
/// test pins the exclusion: toggling the column and reopening must succeed.
#[test]
fn biometric_ref_toggle_does_not_trip_the_epoch_guard() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs301-biotoggle-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
    drop(vault);

    // Simulate enable -> disable (column-level; platform auth is out of scope
    // here — the guard must not care about this column at all).
    {
        let db = crate::database::Database::open(&path).unwrap();
        VaultManager::set_biometric_ref(&db, Some("vault-deadbeef")).unwrap();
        VaultManager::set_biometric_ref(&db, None).unwrap();
    }

    let reopened = VaultManager::open(&path, b"correct-horse-battery")
        .expect("biometric toggle must not trip the epoch guard");
    drop(reopened);

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

// ---------------------------------------------------------------------------
// WBS-302: key-slot registry — MAC integrity, lifecycle, final-slot guard.
// ---------------------------------------------------------------------------

mod wbs302_slot_registry {
    use crate::{PasswordManagerError, VaultManager};
    use std::fs;
    use std::path::PathBuf;

    fn temp_vault(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sp-wbs302-{}-{}.db",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
        path
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
    }

    #[test]
    fn password_slot_minted_and_registry_verified_at_open() {
        let path = temp_vault("mint");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let slots = vault.list_key_slots().unwrap();
        assert_eq!(slots.len(), 1, "exactly the password slot at creation");
        assert_eq!(
            slots[0].slot_type,
            crate::vault::slot_ops::SlotType::Password
        );
        assert!(slots[0].usable);
        drop(vault);

        // Reopen: MAC is present (created at vault creation) and verifies.
        let reopened = VaultManager::open(&path, b"correct-horse-battery")
            .expect("registry MAC must verify on a clean vault");
        assert_eq!(reopened.list_key_slots().unwrap().len(), 1);
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn slot_row_tamper_fails_closed_at_open() {
        let path = temp_vault("tamper");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        drop(vault);

        // Attacker edits a slot's wrapped material without the MAC key.
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "UPDATE key_slots SET wrapped_dek = X'0102' WHERE slot_type = 'password'",
                    [],
                )
                .unwrap();
        }

        match VaultManager::open(&path, b"correct-horse-battery") {
            Err(PasswordManagerError::SlotRegistryTampered) => {}
            Err(other) => panic!("expected registry integrity failure, got {other:?}"),
            Ok(_) => panic!("tampered slot registry must fail closed"),
        }
        cleanup(&path);
    }

    #[test]
    fn slot_resurrection_and_deletion_fail_closed() {
        let path = temp_vault("resurrect");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        drop(vault);
        {
            let db = crate::database::Database::open(&path).unwrap();
            // Resurrect: flip a revoked timestamp... none revoked yet — use
            // un-revocation shape via NULL on a copy; here: delete a row.
            db.conn()
                .execute("DELETE FROM key_slots WHERE slot_type = 'password'", [])
                .unwrap();
        }
        match VaultManager::open(&path, b"correct-horse-battery") {
            Err(PasswordManagerError::SlotRegistryTampered) => {}
            Err(other) => panic!("expected registry integrity failure, got {other:?}"),
            Ok(_) => panic!("row removal must fail closed"),
        }
        cleanup(&path);
    }

    #[test]
    fn rotation_keeps_registry_and_sidecar_consistent() {
        let path = temp_vault("rotate");
        let mut vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        vault
            .change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42")
            .unwrap();
        drop(vault);

        let reopened = VaultManager::open(&path, b"staple-anchor-quantum-42")
            .expect("rotated vault must reopen: slot mirror + MAC + sidecar all updated");
        let slots = reopened.list_key_slots().unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].key_epoch, 2, "password slot mirrors the new epoch");
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn final_usable_slot_revocation_is_refused() {
        let path = temp_vault("finalslot");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let slots = vault.list_key_slots().unwrap();
        let err = vault.revoke_key_slot(&slots[0].slot_uuid).unwrap_err();
        match err {
            PasswordManagerError::InvalidInput(msg) => {
                assert!(msg.contains("final usable"), "got: {msg}");
            }
            other => panic!("expected final-slot refusal, got {other:?}"),
        }
        drop(vault);
        // Vault still opens (the refusal changed nothing).
        let reopened = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        assert_eq!(reopened.list_key_slots().unwrap().len(), 1);
        drop(reopened);
        cleanup(&path);
    }

    /// Pre-registry vault (migration path): MAC bootstraps at first open,
    /// and the sidecar digest is re-anchored so the SECOND open passes.
    #[test]
    fn legacy_vault_bootstraps_registry_mac_at_first_open() {
        let path = temp_vault("bootstrap");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        drop(vault);

        // Strip the registry state to the migrated-but-unbootstrapped shape:
        // slot row present, MAC NULL, and a pre-/3 sidecar (the v6-era file
        // fails the new magic and re-mints via TOFU at first open — the
        // realistic migration path; a /3 sidecar minted WITH the MAC plus a
        // NULLed MAC is tampering and is correctly refused).
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute_batch("UPDATE db_metadata SET slot_registry_mac = NULL;")
                .unwrap();
        }
        fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path)).unwrap();

        // First open bootstraps (mints nothing — slot exists; computes MAC;
        // rebases sidecar digest) and succeeds.
        let first = VaultManager::open(&path, b"correct-horse-battery")
            .expect("first open must bootstrap the registry MAC");
        drop(first);

        // Second open verifies fail-closed and succeeds.
        let second = VaultManager::open(&path, b"correct-horse-battery")
            .expect("second open must verify the bootstrapped MAC");
        assert_eq!(second.list_key_slots().unwrap().len(), 1);
        drop(second);
        cleanup(&path);
    }
}

/// Review round 1, finding 3: during the NULL-MAC bootstrap window, a
/// DB-only writer may swap the slot row's key material — count/type/epoch
/// checks pass, so the old invariant MAC-blessed the tampered row forever.
/// The byte-compare invariant must refuse it.
#[test]
fn bootstrap_refuses_a_tampered_slot_row_during_the_null_mac_window() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs302-nullwindow-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
    drop(vault);

    {
        let db = crate::database::Database::open(&path).unwrap();
        // Enter the NULL-MAC window and tamper the slot's wrapped material.
        db.conn()
            .execute_batch(
                "UPDATE db_metadata SET slot_registry_mac = NULL;
                 UPDATE key_slots SET wrapped_dek = X'DEADBEEF';",
            )
            .unwrap();
    }
    // The pre-/3 sidecar fails the new magic → TOFU re-mint at open (the
    // realistic migration path), so remove it like the migration leaves it.
    fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path)).unwrap();

    match VaultManager::open(&path, b"correct-horse-battery") {
        Err(crate::PasswordManagerError::InvalidInput(msg)) => {
            assert!(
                msg.contains("pre-bootstrap state"),
                "expected the byte-compare invariant refusal, got: {msg}"
            );
        }
        Err(other) => panic!("expected invariant refusal, got {other:?}"),
        Ok(_) => panic!("a tampered slot row must not be MAC-blessed at bootstrap"),
    }
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

/// Review round 1, finding 7: revoking an ALREADY-revoked slot is
/// idempotent, but must still re-follow the sidecar — a prior attempt may
/// have committed the revoke and then failed its anchor update, and the
/// next open would false-refuse as 'material rollback'.
#[test]
fn revoke_retry_on_an_already_revoked_slot_refollows_the_sidecar() {
    use crate::VaultManager;
    use std::fs;

    let path = std::env::temp_dir().join(format!(
        "sp-wbs302-revokeretry-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));

    let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();

    // A second usable slot (SQL + a MAC recompute over both rows, exactly
    // the shape WBS-310 will produce for recovery slots).
    {
        let db = vault.lock_db().unwrap();
        db.conn()
            .execute(
                "INSERT INTO key_slots
                    (slot_uuid, slot_type, kdf_params, wrapped_dek, dek_nonce,
                     key_epoch, created_at, revoked_at, format_version)
                 SELECT '00000000-0000-0000-0000-00000000aaaa', 'recovery',
                        kdf_params, wrapped_dek, dek_nonce, key_epoch,
                        strftime('%s','now'), NULL, 1
                 FROM db_metadata WHERE id = 1",
                [],
            )
            .unwrap();
        let slots = VaultManager::load_key_slots(db.conn()).unwrap();
        VaultManager::commit_slot_registry(&vault.key_hierarchy, db.conn(), &slots).unwrap();
        // Follow the sidecar over the changed MAC (constant epoch).
        let uuid = vault.vault_uuid().unwrap().to_string();
        let sidecar = crate::vault::epoch_guard::sidecar_path(&path);
        let digest = crate::vault::epoch_guard::material_digest(db.conn()).unwrap();
        let epoch = db
            .conn()
            .query_row(
                "SELECT COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        crate::vault::epoch_guard::rebase(&sidecar, &uuid, epoch, &digest).unwrap();
    }

    // Fresh revoke of the recovery slot: commits, MAC updates, sidecar follows.
    vault
        .revoke_key_slot("00000000-0000-0000-0000-00000000aaaa")
        .expect("revoking a non-final slot must succeed");

    // Simulate the failed-anchor state: rewind the sidecar digest to a stale
    // value (as if the revoke's rebase had failed after the DB commit).
    let sidecar = crate::vault::epoch_guard::sidecar_path(&path);
    {
        let db = vault.lock_db().unwrap();
        let stale_digest = [0x55u8; 32];
        let epoch = db
            .conn()
            .query_row(
                "SELECT COALESCE(key_epoch, 1) FROM db_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        crate::vault::epoch_guard::rebase(
            &sidecar,
            vault.vault_uuid().unwrap(),
            epoch,
            &stale_digest,
        )
        .unwrap();
    }

    // Idempotent retry: must re-follow the anchor rather than returning Ok
    // with the stale sidecar in place.
    vault
        .revoke_key_slot("00000000-0000-0000-0000-00000000aaaa")
        .expect("idempotent revoke must succeed and re-follow the sidecar");

    // The sidecar now records the CURRENT digest (proves the re-follow ran).
    drop(vault);
    let reopened = VaultManager::open(&path, b"correct-horse-battery").expect(
        "open must succeed — a stale sidecar digest here would false-refuse as \
             'material rollback' (the exact bug the retry re-follow closes)",
    );
    assert_eq!(reopened.list_key_slots().unwrap().len(), 2);
    drop(reopened);

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
}

// ---------------------------------------------------------------------------
// WBS-310/311: recovery key generation, encoding, and verified onboarding.
// ---------------------------------------------------------------------------

mod wbs310_recovery {
    use crate::vault::recovery::{parse_recovery_key, RecoveryKey};
    use crate::VaultManager;
    use std::fs;
    use std::path::PathBuf;

    fn temp_vault(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sp-wbs311-{}-{}.db",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
        path
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
    }

    /// The full onboarding contract (SR-RECOVERY-002): generate → display →
    /// user re-enters → parse validates → slot created. After onboarding
    /// the vault still opens normally, the registry MAC covers TWO slots,
    /// the sidecar followed at the constant epoch, and the wrap round-trips.
    #[test]
    fn recovery_onboarding_creates_a_verifiable_slot() {
        let path = temp_vault("onboard");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();

        // "User re-enters": parse the displayed form like a human would.
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display_string();
        let retyped = parse_recovery_key(&display).expect("checksum validates re-entry");

        vault.create_recovery_slot(&retyped).unwrap();

        // Registry now holds password + recovery, MAC verifies on reopen.
        drop(vault);
        let reopened = VaultManager::open(&path, b"correct-horse-battery")
            .expect("vault must reopen after onboarding (MAC + sidecar consistent)");
        let slots = reopened.list_key_slots().unwrap();
        assert_eq!(slots.len(), 2);
        assert_eq!(
            slots
                .iter()
                .filter(|s| s.slot_type == crate::vault::slot_ops::SlotType::Recovery)
                .count(),
            1
        );
        drop(reopened);
        cleanup(&path);
    }

    /// The wrap seam: unwrap via the recovery key yields the SAME DEK the
    /// password path uses; a wrong key fails the GCM tag; the AAD binds the
    /// slot identity (unwrapping under another slot's uuid fails).
    #[test]
    fn recovery_slot_wrap_round_trips_and_binds_its_context() {
        let path = temp_vault("wrap");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();

        let key = RecoveryKey::generate().unwrap();
        let retyped = parse_recovery_key(&key.to_display_string()).unwrap();
        vault.create_recovery_slot(&retyped).unwrap();

        let db = vault.lock_db().unwrap();
        let slots = VaultManager::load_key_slots(db.conn()).unwrap();
        let recovery = slots
            .iter()
            .find(|s| s.slot_type == crate::vault::slot_ops::SlotType::Recovery)
            .unwrap();
        let epoch = recovery.key_epoch;
        let vault_uuid = vault.vault_uuid().unwrap().to_string();
        let slot_uuid = recovery.slot_uuid.clone();
        let nonce: [u8; 12] = bincode::deserialize(&recovery.dek_nonce).unwrap();
        drop(db);

        // Right key + right context → the vault's DEK.
        let dek = VaultManager::unwrap_dek_via_recovery_slot(
            &recovery.wrapped_dek,
            &nonce,
            &retyped,
            &vault_uuid,
            &slot_uuid,
            epoch,
        )
        .unwrap();
        assert_eq!(
            dek.as_bytes(),
            vault.key_hierarchy.dek().unwrap().as_bytes(),
            "recovery unwrap must yield the vault's DEK"
        );

        // Wrong key → GCM tag failure.
        let wrong = RecoveryKey::generate().unwrap();
        assert!(VaultManager::unwrap_dek_via_recovery_slot(
            &recovery.wrapped_dek,
            &nonce,
            &wrong,
            &vault_uuid,
            &slot_uuid,
            epoch,
        )
        .is_err());

        // Transplanted context (different slot uuid) → AAD failure.
        let other_uuid = uuid::Uuid::new_v4().to_string();
        assert!(VaultManager::unwrap_dek_via_recovery_slot(
            &recovery.wrapped_dek,
            &nonce,
            &retyped,
            &vault_uuid,
            &other_uuid,
            epoch,
        )
        .is_err());

        // Replayed epoch → AAD failure.
        assert!(VaultManager::unwrap_dek_via_recovery_slot(
            &recovery.wrapped_dek,
            &nonce,
            &retyped,
            &vault_uuid,
            &slot_uuid,
            epoch + 1,
        )
        .is_err());
        drop(vault);
        cleanup(&path);
    }

    /// Re-running onboarding REPLACES the recovery slot (old row revoked,
    /// history kept in the registry) and the vault keeps opening.
    #[test]
    fn recovery_re_onboarding_replaces_the_slot_with_history() {
        let path = temp_vault("replace");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();

        let first =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&first).unwrap();
        let second =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&second).unwrap();

        let slots = vault.list_key_slots().unwrap();
        let recovery: Vec<_> = slots
            .iter()
            .filter(|s| s.slot_type == crate::vault::slot_ops::SlotType::Recovery)
            .collect();
        assert_eq!(recovery.len(), 2, "history kept");
        assert_eq!(
            recovery.iter().filter(|s| s.usable).count(),
            1,
            "exactly one usable recovery slot"
        );
        drop(vault);

        let reopened = VaultManager::open(&path, b"correct-horse-battery")
            .expect("vault reopens after replacement (MAC followed)");
        drop(reopened);
        cleanup(&path);
    }

    /// The recovery slot cannot be revoked as the FINAL usable slot while
    /// the password slot is also revocable — and revoking the recovery slot
    /// alone leaves the password path intact (the 313 guard on both sides).
    #[test]
    fn revoking_the_recovery_slot_keeps_the_password_slot_usable() {
        let path = temp_vault("revoke");
        let vault = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let key =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&key).unwrap();

        let recovery_slot = vault
            .list_key_slots()
            .unwrap()
            .into_iter()
            .find(|s| s.slot_type == crate::vault::slot_ops::SlotType::Recovery)
            .unwrap();
        vault.revoke_key_slot(&recovery_slot.slot_uuid).unwrap();

        // One usable slot remains (password) — and revoking IT is refused.
        let slots = vault.list_key_slots().unwrap();
        assert_eq!(slots.iter().filter(|s| s.usable).count(), 1);
        let password_slot = slots.iter().find(|s| s.usable).unwrap();
        assert!(vault.revoke_key_slot(&password_slot.slot_uuid).is_err());
        drop(vault);
        cleanup(&path);
    }
}

// ---------------------------------------------------------------------------
// WBS-312: recovery without the old master password.
// ---------------------------------------------------------------------------

mod wbs312_recover {
    use crate::vault::recovery::{parse_recovery_key, RecoveryKey};
    use crate::{PasswordManagerError, VaultManager};
    use std::fs;
    use std::path::PathBuf;

    fn temp_vault(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sp-wbs312-{}-{}.db",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
        path
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
    }

    fn onboard(path: &std::path::Path) -> RecoveryKey {
        let vault = VaultManager::create(path, b"correct-horse-battery").unwrap();
        let key =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&key).unwrap();
        drop(vault);
        key
    }

    /// THE scenario: forgot the master password → recover with the key →
    /// new password opens, OLD password never works again, epoch advanced,
    /// all prior slots revoked, registry and sidecar consistent.
    #[test]
    fn recovery_without_old_password_establishes_a_new_one() {
        let path = temp_vault("main");
        let key = onboard(&path);
        assert_eq!(
            VaultManager::open(&path, b"correct-horse-battery")
                .unwrap()
                .key_epoch()
                .unwrap(),
            1
        );

        VaultManager::recover_access(&path, &key, b"a-brand-new-password-42")
            .expect("recovery must succeed without the old password");

        // New password opens; old password is refused (and not merely
        // shadowed: the wrap is gone).
        let recovered = VaultManager::open(&path, b"a-brand-new-password-42")
            .expect("new password must open the recovered vault");
        assert_eq!(recovered.key_epoch().unwrap(), 2, "epoch advanced");
        let slots = recovered.list_key_slots().unwrap();
        assert_eq!(
            slots.len(),
            3,
            "history kept: old password + old recovery + new password"
        );
        assert_eq!(
            slots.iter().filter(|s| s.usable).count(),
            1,
            "only the new password slot is usable"
        );
        drop(recovered);

        assert!(
            VaultManager::open(&path, b"correct-horse-battery").is_err(),
            "the old password must never work again"
        );
        cleanup(&path);
    }

    /// Wrong recovery key: refused BEFORE any write — the vault still opens
    /// with the old password and the registry/epoch are untouched.
    #[test]
    fn wrong_recovery_key_changes_nothing() {
        let path = temp_vault("wrong");
        let _key = onboard(&path);
        let wrong =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();

        let err = VaultManager::recover_access(&path, &wrong, b"attacker-password-42");
        assert!(err.is_err(), "wrong key must be refused");
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("did not open this vault"));

        let vault = VaultManager::open(&path, b"correct-horse-battery")
            .expect("old password still works; nothing was written");
        assert_eq!(vault.key_epoch().unwrap(), 1);
        drop(vault);
        cleanup(&path);
    }

    /// A tampered registry must refuse recovery — never be minted into a
    /// fresh epoch with fresh authority (the verify-before-write rule).
    #[test]
    fn tampered_registry_refuses_recovery() {
        let path = temp_vault("tampered");
        let key = onboard(&path);
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "UPDATE key_slots SET wrapped_dek = X'01' WHERE slot_type = 'recovery'",
                    [],
                )
                .unwrap();
        }

        let err = VaultManager::recover_access(&path, &key, b"new-password-after-tamper");
        assert!(err.is_err(), "tampered registry must refuse recovery");
        assert!(matches!(
            err.unwrap_err(),
            PasswordManagerError::InvalidInput(_)
        ));
        cleanup(&path);
    }

    /// Recovery is single-use for the slot: after recovering, the old
    /// recovery slot is revoked (a stolen copy of the key cannot re-recover
    /// over the new password).
    #[test]
    fn used_recovery_slot_is_revoked() {
        let path = temp_vault("single");
        let key = onboard(&path);
        VaultManager::recover_access(&path, &key, b"first-new-password-1").unwrap();

        // The SAME recovery key must not open it again.
        let err = VaultManager::recover_access(&path, &key, b"second-new-password");
        assert!(err.is_err(), "revoked recovery slot must not re-recover");
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("no usable recovery slot"),
            "the refusal should name the missing slot"
        );

        // And the first new password still works.
        assert!(VaultManager::open(&path, b"first-new-password-1").is_ok());
        cleanup(&path);
    }

    /// A vault with no recovery slot refuses with actionable guidance.
    #[test]
    fn recovery_without_a_slot_is_refused_cleanly() {
        let path = temp_vault("noslot");
        let _ = VaultManager::create(&path, b"correct-horse-battery").unwrap();
        let key =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();

        let err = VaultManager::recover_access(&path, &key, b"some-new-password-42");
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("no usable recovery slot"));
        // And the original password still works.
        assert!(VaultManager::open(&path, b"correct-horse-battery").is_ok());
        cleanup(&path);
    }
}

// ---------------------------------------------------------------------------
// Recovery review round-1 test gaps: the MAC-refusal path, resurrection,
// and rollback-during-recovery refusal.
// ---------------------------------------------------------------------------

mod wbs312_review_gaps {
    use crate::vault::recovery::{parse_recovery_key, RecoveryKey};
    use crate::VaultManager;
    use std::fs;
    use std::path::PathBuf;

    fn temp_vault(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sp-wbs312rg-{}-{}.db",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(&path));
        path
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(crate::vault::epoch_guard::sidecar_path(path));
    }

    fn onboard(path: &std::path::Path) -> RecoveryKey {
        let vault = VaultManager::create(path, b"correct-horse-battery").unwrap();
        let key =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&key).unwrap();
        drop(vault);
        key
    }

    /// Review finding: the earlier tamper test corrupted the RECOVERY row,
    /// so unwrap failed first and the registry-MAC refusal path was never
    /// exercised. This tampers a NON-recovery row — MAC verification is the
    /// ONLY detector, so deleting verify_slot_registry breaks this test.
    #[test]
    fn recovery_refuses_when_a_non_recovery_row_is_tampered() {
        let path = temp_vault("mactamper");
        let key = onboard(&path);
        {
            let db = crate::database::Database::open(&path).unwrap();
            // Corrupt the (revoked-history-free) password slot's metadata —
            // the recovery row stays valid, unwrap succeeds, and ONLY the
            // registry MAC can catch this.
            db.conn()
                .execute(
                    "UPDATE key_slots SET created_at = created_at + 1 WHERE slot_type = 'password'",
                    [],
                )
                .unwrap();
        }

        let err = VaultManager::recover_access(&path, &key, b"some-new-password-42");
        assert!(err.is_err(), "registry tamper must refuse recovery");
        assert!(
            err.unwrap_err().to_string().contains("integrity"),
            "the refusal must come from the registry MAC path"
        );
        // Nothing was written, and the tampered registry blocks every
        // surface equally: the password open ALSO fails closed (this is
        // the fail-closed rule, not a recovery-specific behavior).
        match VaultManager::open(&path, b"correct-horse-battery") {
            Err(e) => assert!(e.to_string().contains("integrity")),
            Ok(_) => panic!("tampered registry must fail closed on open too"),
        }
        cleanup(&path);
    }

    /// Resurrection: un-revoking the used recovery row after a recovery
    /// must be caught (MAC covers revoked_at) — a stolen key cannot
    /// re-recover by restoring revoked_at = NULL.
    #[test]
    fn resurrected_recovery_row_refuses_recovery() {
        let path = temp_vault("resurrect");
        let key = onboard(&path);
        VaultManager::recover_access(&path, &key, b"first-new-password-1").unwrap();

        // "Attacker" resurrects the revoked recovery row by SQL.
        {
            let db = crate::database::Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "UPDATE key_slots SET revoked_at = NULL WHERE slot_type = 'recovery'",
                    [],
                )
                .unwrap();
        }

        let err = VaultManager::recover_access(&path, &key, b"second-new-password");
        assert!(err.is_err(), "resurrected row must fail the MAC check");
        assert!(err.unwrap_err().to_string().contains("integrity"));
        // The attacker did NOT gain a recovery: the resurrection broke the
        // MAC, so every surface (including the password open) fails closed
        // until verified restore — the vault is not attacker-openable.
        assert!(VaultManager::open(&path, b"first-new-password-1").is_err());
        cleanup(&path);
    }

    /// THE critical review finding: recovery must refuse a ROLLED-BACK vault
    /// (an old file copy + a revoked/leaked recovery key must not launder
    /// the rollback through recovery).
    #[test]
    fn recovery_refuses_a_rolled_back_vault_file() {
        let dir =
            std::env::temp_dir().join(format!("sp-wbs312rb-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        let _sidecar = crate::vault::epoch_guard::sidecar_path(&path);

        // Epoch 2 with a recovery slot.
        let key = onboard(&path);
        let mut vault = VaultManager::open(&path, b"correct-horse-battery").unwrap();
        vault
            .change_master_password(b"correct-horse-battery", b"staple-anchor-quantum-42")
            .unwrap();
        drop(vault);

        // Attacker snapshots the epoch-2 file, then the legitimate epoch
        // advances (another rotation) and the recovery key is REVOKED by
        // re-onboarding with a fresh key (the old one is now dead).
        let snapshot_copy = dir.join("old-copy.db");
        fs::copy(&path, &snapshot_copy).unwrap();
        let mut vault = VaultManager::open(&path, b"staple-anchor-quantum-42").unwrap();
        vault
            .change_master_password(b"staple-anchor-quantum-42", b"third-password-xyz-9")
            .unwrap();
        let fresh =
            parse_recovery_key(&RecoveryKey::generate().unwrap().to_display_string()).unwrap();
        vault.create_recovery_slot(&fresh).unwrap(); // revokes the old key's slot
        drop(vault);

        // Rollback: restore the old copy over the live file. The sidecar
        // still anchors epoch 3 while the DB is back at epoch 2.
        fs::copy(&snapshot_copy, &path).unwrap();

        // open() refuses (the anchor sees the rollback)…
        assert!(VaultManager::open(&path, b"correct-horse-battery").is_err());

        // …and recovery with the LEAKED key must refuse too — not launder
        // the rollback into a fresh epoch under the attacker's password.
        let err = VaultManager::recover_access(&path, &key, b"attacker-password-42");
        assert!(
            err.is_err(),
            "recovery must refuse a rolled-back vault file"
        );
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("rollback") || msg.contains("jump") || msg.contains("material"),
            "refusal should name the anchor conflict: {msg}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
