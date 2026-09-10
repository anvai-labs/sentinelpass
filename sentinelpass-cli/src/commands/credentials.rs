use crate::commands::service_client as sc;
use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::daemon::service::entry_summary_from_wire;
use sentinelpass_core::{CredentialType, EntrySummary};
use sentinelpass_protocol::service::{VaultOp, VaultOpResult};
use std::path::PathBuf;
use tracing::error;

pub fn credential_type_label(credential_type: CredentialType) -> &'static str {
    match credential_type {
        CredentialType::Password => "password",
        CredentialType::ApiKey => "api_key",
        CredentialType::PasskeyReference => "passkey_reference",
    }
}

pub fn secret_value_label(credential_type: CredentialType) -> &'static str {
    match credential_type {
        CredentialType::Password => "Password",
        CredentialType::ApiKey => "API key",
        CredentialType::PasskeyReference => "Reference",
    }
}

pub fn require_non_empty(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{} must not be empty", label);
    }
    Ok(trimmed.to_string())
}

pub fn trim_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

/// Wire summaries -> core summaries (one conversion point for renders).
fn to_core_summaries(result: VaultOpResult) -> Result<Vec<EntrySummary>> {
    match result {
        VaultOpResult::EntryList(list) => list
            .iter()
            .map(entry_summary_from_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!(e.to_string())),
        other => Err(anyhow::anyhow!("expected entry list, got {other:?}")),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_add(
    vault_path: PathBuf,
    title: &str,
    username: &str,
    password: Option<&str>,
    credential_type: CredentialType,
    url: Option<String>,
    notes: Option<String>,
    favorite: bool,
) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let password_str = match password {
        Some(p) => p.to_string(),
        None => prompt_password(format!(
            "Enter {} for entry: ",
            secret_value_label(credential_type)
        ))?,
    };

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let entry = sentinelpass_protocol::service::ServiceEntry {
        entry_id: None,
        title: title.to_string(),
        username: username.to_string(),
        password: password_str.into(),
        url,
        notes,
        credential_type: credential_type.as_str().to_string(),
        created_at: chrono::Utc::now().timestamp(),
        modified_at: chrono::Utc::now().timestamp(),
        favorite,
    };

    match backend.call(VaultOp::EntryAdd { entry })? {
        VaultOpResult::EntryId(entry_id) => {
            println!("✓ Entry created with ID: {}", entry_id);
        }
        other => {
            error!("Failed to add entry: {:?}", other);
            anyhow::bail!("Failed to add entry");
        }
    }
    Ok(())
}

pub fn handle_list(vault_path: PathBuf, show_passwords: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let entries = to_core_summaries(backend.call(VaultOp::EntryList)?)?;

    if entries.is_empty() {
        println!("No entries found. Add one with 'sentinelpass add'");
        return Ok(());
    }

    println!();
    println!(
        "{:<5} {:<16} {:<30} {:<30} Fav",
        "ID", "Type", "Title", "Username"
    );
    println!("{}", "-".repeat(96));
    for entry in &entries {
        let fav = if entry.favorite { "⭐" } else { "" };
        println!(
            "{:<5} {:<16} {:<30} {:<30} {}",
            entry.entry_id,
            credential_type_label(entry.credential_type),
            entry.title,
            entry.username,
            fav
        );
    }
    println!();
    println!("Total: {} entries", entries.len());

    if show_passwords {
        println!();
        println!("WARNING: Showing passwords (be careful of shoulder surfing!)");
        println!();
        for summary in &entries {
            if let VaultOpResult::Entry(entry) = backend.call(VaultOp::EntryGet {
                entry_id: summary.entry_id,
            })? {
                let credential_type = wire_credential_type(&entry.credential_type)?;
                println!("--- ID {} ---", summary.entry_id);
                println!(
                    "{}: {}",
                    secret_value_label(credential_type),
                    entry.password.as_str()
                );
            }
        }
    }
    Ok(())
}

fn wire_credential_type(label: &str) -> Result<CredentialType> {
    CredentialType::parse(label).map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub fn handle_get(vault_path: PathBuf, id: i64) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    match backend.call(VaultOp::EntryGet { entry_id: id })? {
        VaultOpResult::Entry(entry) => {
            let credential_type = wire_credential_type(&entry.credential_type)?;
            println!();
            println!("Title: {}", entry.title);
            println!("Type: {}", credential_type_label(credential_type));
            println!("Username: {}", entry.username);
            println!(
                "{}: {}",
                secret_value_label(credential_type),
                entry.password.as_str()
            );
            if let Some(url) = entry.url {
                println!("URL: {}", url);
            }
            if let Some(notes) = entry.notes {
                println!("Notes: {}", notes);
            }
            let created = chrono::DateTime::from_timestamp(entry.created_at, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| entry.created_at.to_string());
            println!("Created: {}", created);
            if entry.favorite {
                println!("⭐ Favorite");
            }
            println!();
        }
        other => {
            error!("Failed to get entry: {:?}", other);
            anyhow::bail!(
                "Entry {} not found. Use 'sentinelpass list' to see all entries",
                id
            );
        }
    }
    Ok(())
}

pub fn handle_search(vault_path: PathBuf, query: &str) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let entries = to_core_summaries(backend.call(VaultOp::EntryList)?)?;

    let query_lower = query.to_lowercase();
    let filtered: Vec<EntrySummary> = entries
        .into_iter()
        .filter(|e| {
            e.title.to_lowercase().contains(&query_lower)
                || e.username.to_lowercase().contains(&query_lower)
        })
        .collect();

    if filtered.is_empty() {
        println!("No entries found matching '{}'", query);
        return Ok(());
    }

    println!();
    println!("Found {} entries matching '{}':", filtered.len(), query);
    println!();
    println!(
        "{:<5} {:<16} {:<30} {:<30}",
        "ID", "Type", "Title", "Username"
    );
    println!("{}", "-".repeat(88));
    for entry in filtered {
        println!(
            "{:<5} {:<16} {:<30} {:<30}",
            entry.entry_id,
            credential_type_label(entry.credential_type),
            entry.title,
            entry.username
        );
    }
    Ok(())
}

pub fn handle_delete(vault_path: PathBuf, id: i64, force: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    // Get entry details for confirmation
    let entry = match backend.call(VaultOp::EntryGet { entry_id: id })? {
        VaultOpResult::Entry(entry) => entry,
        other => anyhow::bail!("Entry {} not found: {:?}", id, other),
    };

    if !force {
        println!("Entry to delete:");
        println!("  Title: {}", entry.title);
        println!("  Username: {}", entry.username);
        println!();
        print!("Are you sure you want to delete this entry? [y/N]: ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        if !confirmation.trim().to_lowercase().starts_with('y') {
            println!("Delete cancelled");
            return Ok(());
        }
    }

    backend.call(VaultOp::EntryDelete { entry_id: id })?;
    println!("Entry deleted successfully");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_edit(
    vault_path: PathBuf,
    id: i64,
    title: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    new_password: bool,
    url: Option<String>,
    notes: Option<String>,
    favorite: Option<bool>,
) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    // Get existing entry
    let existing_entry = match backend.call(VaultOp::EntryGet { entry_id: id })? {
        VaultOpResult::Entry(entry) => entry,
        other => anyhow::bail!("Entry {} not found: {:?}", id, other),
    };

    // Determine new values (use existing if not provided)
    let new_title = title.unwrap_or(existing_entry.title.as_str()).to_string();
    let new_username = username
        .unwrap_or(existing_entry.username.as_str())
        .to_string();

    // Handle password
    let new_password_value = if new_password {
        prompt_password("Enter new password: ")?
    } else {
        password
            .unwrap_or_else(|| existing_entry.password.as_str())
            .to_string()
    };

    let new_url = url.or_else(|| existing_entry.url.clone());
    let new_notes = notes.or_else(|| existing_entry.notes.clone());
    let new_favorite = favorite.unwrap_or(existing_entry.favorite);

    let updated_entry = sentinelpass_protocol::service::ServiceEntry {
        entry_id: Some(id),
        title: new_title,
        username: new_username,
        password: new_password_value.into(),
        url: new_url,
        notes: new_notes,
        credential_type: existing_entry.credential_type.clone(),
        created_at: existing_entry.created_at,
        modified_at: chrono::Utc::now().timestamp(),
        favorite: new_favorite,
    };

    backend.call(VaultOp::EntryUpdate {
        entry_id: id,
        entry: updated_entry,
    })?;
    println!("Entry updated successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_type_labels_match_wire_labels() {
        // The renders translate wire labels back to display labels; the
        // labels must round-trip through CredentialType::parse.
        for value in ["password", "api_key", "passkey_reference"] {
            assert!(CredentialType::parse(value).is_ok());
        }
    }
}
