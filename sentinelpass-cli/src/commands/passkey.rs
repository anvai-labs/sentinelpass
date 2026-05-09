use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::{CredentialType, Entry as VaultEntry};
use std::path::PathBuf;

use crate::commands::credentials::{require_non_empty, trim_optional};

pub fn build_passkey_reference_entry(
    relying_party_id: &str,
    account_label: &str,
    platform: &str,
    credential_id_hint: Option<&str>,
    sync_source: Option<&str>,
    notes: Option<&str>,
    favorite: bool,
) -> Result<VaultEntry> {
    let relying_party_id = require_non_empty(relying_party_id, "relying party ID")?;
    let account_label = require_non_empty(account_label, "account label")?;
    let platform = require_non_empty(platform, "platform")?;
    let credential_id_hint = trim_optional(credential_id_hint);
    let sync_source = trim_optional(sync_source);
    let notes = trim_optional(notes);
    let now = chrono::Utc::now();

    let reference = serde_json::to_string(&serde_json::json!({
        "kind": "passkey_reference",
        "relying_party_id": relying_party_id,
        "account_label": account_label,
        "platform": platform,
        "credential_id_hint": credential_id_hint,
        "sync_source": sync_source,
        "metadata_only": true,
    }))
    .map_err(|e| anyhow::anyhow!("Failed to render passkey reference metadata: {}", e))?;

    Ok(VaultEntry {
        entry_id: None,
        title: format!("Passkey reference: {}", relying_party_id),
        username: account_label,
        password: reference.into(),
        url: Some(relying_party_id),
        notes,
        credential_type: CredentialType::PasskeyReference,
        created_at: now,
        modified_at: now,
        favorite,
    })
}

pub fn handle_passkey_add(
    vault_path: PathBuf,
    relying_party_id: &str,
    account_label: &str,
    platform: &str,
    credential_id_hint: Option<&str>,
    sync_source: Option<&str>,
    notes: Option<&str>,
    favorite: bool,
) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password to unlock vault: ")?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    let entry = build_passkey_reference_entry(
        relying_party_id,
        account_label,
        platform,
        credential_id_hint,
        sync_source,
        notes,
        favorite,
    )?;

    let entry_id = vault.add_entry(&entry)?;
    println!("✓ Passkey reference created with ID: {}", entry_id);
    println!("This is metadata only. Authentication remains with the platform authenticator.");
    Ok(())
}
