use super::*;
use crate::custody::NativeSecret;
use sentinelpass_protocol::custody::{CustodyScope, ObjectRef};

fn scope() -> CustodyScope {
    serde_json::from_str(include_str!("../../../bindings/custody/scope.golden.json")).unwrap()
}
fn reference() -> ObjectRef {
    serde_json::from_str(include_str!(
        "../../../bindings/custody/reference.golden.json"
    ))
    .unwrap()
}
fn secret() -> NativeSecret {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    NativeSecret(bytes)
}

#[test]
fn custody_storage_exact_cas_and_tombstone_prevent_reuse() {
    let password = uuid::Uuid::new_v4().to_string();
    let vault = VaultManager::create(":memory:", password.as_bytes()).unwrap();
    let (scope, first, value) = (scope(), reference(), secret());
    vault.custody_put(&scope, None, &first, &value).unwrap();
    assert!(vault.list_entries().unwrap().is_empty());
    assert!(vault.custody_read(&scope, &first).is_ok());
    assert!(vault.custody_put(&scope, None, &first, &value).is_err());
    let mut wrong_owner = scope.clone();
    wrong_owner.subject.push('x');
    assert!(vault.custody_read(&wrong_owner, &first).is_err());
    let mut next = first.clone();
    next.revision = (first.revision.parse::<u64>().unwrap() + 1).to_string();
    vault
        .custody_put(&scope, Some(&first), &next, &value)
        .unwrap();
    assert!(vault.custody_read(&scope, &first).is_err());
    assert!(vault.custody_remove(&scope, &first).is_err());
    vault.custody_remove(&scope, &next).unwrap();
    assert!(vault.custody_read(&scope, &next).is_err());
    assert!(vault.custody_put(&scope, None, &first, &value).is_err());
    assert!(vault.verify_vault_envelopes().unwrap().is_clean());
}

#[test]
fn custody_storage_rejects_metadata_swaps_and_unknown_formats() {
    let password = uuid::Uuid::new_v4().to_string();
    let vault = VaultManager::create(":memory:", password.as_bytes()).unwrap();
    let (scope, reference, value) = (scope(), reference(), secret());
    vault.custody_put(&scope, None, &reference, &value).unwrap();
    let original: String = vault
        .lock_db()
        .unwrap()
        .conn()
        .query_row("SELECT scope_json FROM custody_objects", [], |r| r.get(0))
        .unwrap();
    for field in [
        "namespace",
        "issuer",
        "subject",
        "mailboxId",
        "purpose",
        "version",
    ] {
        let mut changed: serde_json::Value = serde_json::from_str(&original).unwrap();
        changed[field] = if field == "version" {
            2.into()
        } else {
            "substituted".into()
        };
        vault
            .lock_db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE custody_objects SET scope_json=?1",
                [changed.to_string()],
            )
            .unwrap();
        assert!(vault.custody_read(&scope, &reference).is_err(), "{field}");
        assert!(vault.verify_vault_envelopes().is_err());
    }
    vault
        .lock_db()
        .unwrap()
        .conn()
        .execute("UPDATE custody_objects SET scope_json=?1", [&original])
        .unwrap();
    for field in ["objectId", "revision", "keyEpoch", "bindingSha256"] {
        let mut changed = serde_json::to_value(&reference).unwrap();
        changed[field] = if field == "bindingSha256" {
            "a".repeat(64).into()
        } else {
            "2".into()
        };
        vault
            .lock_db()
            .unwrap()
            .conn()
            .execute(
                "UPDATE custody_objects SET reference_json=?1",
                [changed.to_string()],
            )
            .unwrap();
        assert!(vault.custody_read(&scope, &reference).is_err(), "{field}");
    }
    vault
        .lock_db()
        .unwrap()
        .conn()
        .execute(
            "UPDATE custody_objects SET reference_json=?1",
            [serde_json::to_string(&reference).unwrap()],
        )
        .unwrap();
    let second = ObjectRef {
        object_id: "object-2".into(),
        ..reference.clone()
    };
    vault.custody_put(&scope, None, &second, &secret()).unwrap();
    vault.lock_db().unwrap().conn().execute(
        "UPDATE custody_objects SET envelope=(SELECT envelope FROM custody_objects WHERE object_id=?1) WHERE object_id=?2",
        [&second.object_id, &reference.object_id]).unwrap();
    assert!(vault.custody_read(&scope, &reference).is_err());
}

#[test]
fn custody_storage_faults_preserve_complete_old_state() {
    use crate::database::fault_injection::{clear_write_fault, install_write_fault};
    let password = uuid::Uuid::new_v4().to_string();
    let vault = VaultManager::create(":memory:", password.as_bytes()).unwrap();
    let (scope, first, value) = (scope(), reference(), secret());
    vault.custody_put(&scope, None, &first, &value).unwrap();
    let next = ObjectRef {
        revision: "2".into(),
        binding_sha256: "a".repeat(64),
        ..first.clone()
    };
    let mut succeeded = false;
    for fail_at in 0..12 {
        let fault = install_write_fault(vault.lock_db().unwrap().conn(), fail_at);
        let result = vault.custody_put(&scope, Some(&first), &next, &secret());
        clear_write_fault(vault.lock_db().unwrap().conn());
        if fault.seen() > fail_at {
            assert!(result.is_err());
            assert!(vault.custody_read(&scope, &first).is_ok());
            assert!(vault.custody_read(&scope, &next).is_err());
        } else {
            result.unwrap();
            assert!(vault.custody_read(&scope, &next).is_ok());
            succeeded = true;
            break;
        }
    }
    assert!(succeeded);
}

#[test]
fn custody_storage_file_receipts_backup_and_rekey_preserve_exact_values() {
    use subtle::ConstantTimeEq;
    let dir = tempfile::tempdir().unwrap();
    let password = Zeroizing::new(uuid::Uuid::new_v4().to_string());
    let path = dir.path().join("personal.db");
    let vault = VaultManager::create(&path, password.as_bytes()).unwrap();
    let (scope, first, value) = (scope(), reference(), secret());
    vault.custody_put(&scope, None, &first, &value).unwrap();
    let bundle = dir.path().join("personal.spbackup");
    vault.create_backup(&bundle).unwrap();
    VaultManager::verify_bundle_file(&bundle, password.as_bytes(), true).unwrap();
    let restored_path = dir.path().join("restored.db");
    VaultManager::restore_bundle(
        &restored_path,
        &bundle,
        password.as_bytes(),
        &backup_ops::RestoreOptions::default(),
    )
    .unwrap();
    let restored = VaultManager::open(&restored_path, password.as_bytes()).unwrap();
    assert!(bool::from(value.0.as_slice().ct_eq(
        restored.custody_read(&scope, &first).unwrap().0.as_slice()
    )));
    drop(restored);
    let replacement = vault
        .rekey_to(&dir.path().join("rekey"), password.as_bytes())
        .unwrap();
    let rotated = VaultManager::open(&replacement, password.as_bytes()).unwrap();
    let read = rotated.custody_read(&scope, &first).unwrap();
    assert!(bool::from(value.0.as_slice().ct_eq(read.0.as_slice())));
    assert_ne!(rotated.vault_uuid(), vault.vault_uuid());
    drop(rotated);
    drop(vault);
    let reopened = VaultManager::open(&path, password.as_bytes()).unwrap();
    assert!(bool::from(value.0.as_slice().ct_eq(
        reopened.custody_read(&scope, &first).unwrap().0.as_slice()
    )));
    // A legitimate ciphertext with stale metadata is caught by the external
    // transaction receipt, including wholesale row deletion.
    reopened
        .lock_db()
        .unwrap()
        .conn()
        .execute("DELETE FROM custody_objects", [])
        .unwrap();
    assert!(reopened.custody_read(&scope, &first).is_err());
    drop(reopened);
    assert!(VaultManager::open(&path, password.as_bytes()).is_err());
}
