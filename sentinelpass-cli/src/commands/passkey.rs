use crate::commands::service_client as sc;
use anyhow::Result;
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

#[allow(clippy::too_many_arguments)]
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

    let entry = build_passkey_reference_entry(
        relying_party_id,
        account_label,
        platform,
        credential_id_hint,
        sync_source,
        notes,
        favorite,
    )?;

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let entry_id = match backend.call(sentinelpass_protocol::service::VaultOp::EntryAdd {
        entry: sentinelpass_protocol::service::ServiceEntry {
            entry_id: None,
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.as_str().to_string().into(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            credential_type: entry.credential_type.as_str().to_string(),
            created_at: entry.created_at.timestamp(),
            modified_at: entry.modified_at.timestamp(),
            favorite: entry.favorite,
        },
    })? {
        sentinelpass_protocol::service::VaultOpResult::EntryId(id) => id,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    println!("✓ Passkey reference created with ID: {}", entry_id);
    println!("This is metadata only. Authentication remains with the platform authenticator.");
    Ok(())
}
