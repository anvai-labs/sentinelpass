use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::{CredentialType, Entry as VaultEntry, EntrySummary};
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

    let master_password = prompt_password("Enter master password to unlock vault: ")?;

    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    let entry = VaultEntry {
        entry_id: None,
        title: title.to_string(),
        username: username.to_string(),
        password: password_str.into(),
        url,
        notes,
        credential_type,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        favorite,
    };

    match vault.add_entry(&entry) {
        Ok(entry_id) => {
            println!("✓ Entry created with ID: {}", entry_id);
        }
        Err(e) => {
            error!("Failed to add entry: {}", e);
            anyhow::bail!("Failed to add entry: {}", e);
        }
    }
    Ok(())
}

pub fn handle_list(vault_path: PathBuf, show_passwords: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;

    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    match vault.list_entries() {
        Ok(entries) => {
            if entries.is_empty() {
                println!("No entries found. Add one with 'sentinelpass add'");
            } else {
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
                        if let Ok(entry) = vault.get_entry(summary.entry_id) {
                            println!("--- ID {} ---", summary.entry_id);
                            println!(
                                "{}: {}",
                                secret_value_label(entry.credential_type),
                                entry.password.as_str()
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to list entries: {}", e);
            anyhow::bail!("Failed to list entries: {}", e);
        }
    }
    Ok(())
}

pub fn handle_get(vault_path: PathBuf, id: i64) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;

    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    match vault.get_entry(id) {
        Ok(entry) => {
            println!();
            println!("Title: {}", entry.title);
            println!("Type: {}", credential_type_label(entry.credential_type));
            println!("Username: {}", entry.username);
            println!(
                "{}: {}",
                secret_value_label(entry.credential_type),
                entry.password.as_str()
            );
            if let Some(url) = entry.url {
                println!("URL: {}", url);
            }
            if let Some(notes) = entry.notes {
                println!("Notes: {}", notes);
            }
            println!(
                "Created: {}",
                entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if entry.favorite {
                println!("⭐ Favorite");
            }
            println!();
        }
        Err(e) => {
            error!("Failed to get entry: {}", e);
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

    let master_password = prompt_password("Enter master password: ")?;

    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;

    match vault.list_entries() {
        Ok(entries) => {
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
            } else {
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
            }
        }
        Err(e) => {
            error!("Failed to search entries: {}", e);
            anyhow::bail!("Failed to search entries: {}", e);
        }
    }
    Ok(())
}

pub fn handle_delete(vault_path: PathBuf, id: i64, force: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    // Get entry details for confirmation
    let entry = vault.get_entry(id)?;

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

    vault.delete_entry(id)?;
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

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    // Get existing entry
    let existing_entry = vault.get_entry(id)?;

    // Determine new values (use existing if not provided)
    let new_title = title.unwrap_or(existing_entry.title.as_str()).to_string();
    let new_username = username
        .unwrap_or(existing_entry.username.as_str())
        .to_string();

    // Handle password
    let new_password = if new_password {
        prompt_password("Enter new password: ")?
    } else {
        password
            .unwrap_or_else(|| existing_entry.password.as_str())
            .to_string()
    };

    let new_url = url.or_else(|| existing_entry.url.clone());
    let new_notes = notes.or_else(|| existing_entry.notes.clone());
    let new_favorite = favorite.unwrap_or(existing_entry.favorite);

    // Create updated entry
    use chrono::Utc;
    let updated_entry = VaultEntry {
        entry_id: Some(id),
        title: new_title,
        username: new_username,
        password: new_password.into(),
        url: new_url,
        notes: new_notes,
        credential_type: existing_entry.credential_type,
        created_at: existing_entry.created_at,
        modified_at: Utc::now(),
        favorite: new_favorite,
    };

    vault.update_entry(id, &updated_entry)?;
    println!("Entry updated successfully");
    Ok(())
}
