use crate::commands::service_client as sc;
use anyhow::Result;
use sentinelpass_core::daemon::service::entry_from_wire;
use sentinelpass_core::{parse_passkey_reference_entry, PasskeyReferenceMetadata};
use sentinelpass_protocol::service::{VaultOp, VaultOpResult};
use std::path::PathBuf;

use crate::commands::credentials::{require_non_empty, trim_optional};

/// CLI-facing builder kept for backward compatibility with the existing
/// dispatch tests; delegates to the typed core model.
#[allow(clippy::too_many_arguments)]
pub fn build_passkey_reference_entry(
    relying_party_id: &str,
    account_label: &str,
    platform: &str,
    credential_id_hint: Option<&str>,
    sync_source: Option<&str>,
    notes: Option<&str>,
    favorite: bool,
) -> Result<sentinelpass_core::Entry> {
    let relying_party_id = require_non_empty(relying_party_id, "relying party ID")?;
    let account_label = require_non_empty(account_label, "account label")?;
    let platform = require_non_empty(platform, "platform")?;
    let metadata = PasskeyReferenceMetadata::new(
        &relying_party_id,
        &account_label,
        &platform,
        trim_optional(credential_id_hint).as_deref(),
        trim_optional(sync_source).as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    sentinelpass_core::build_passkey_reference_entry(
        &metadata,
        trim_optional(notes).as_deref(),
        favorite,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn connect_backend(vault_path: &PathBuf) -> Result<sc::Backend> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }
    sc::connect(vault_path, || crate::prompt_master_password(false))
}

fn entry_from_backend(backend: &sc::Backend, entry_id: i64) -> Result<sentinelpass_core::Entry> {
    match backend.call(VaultOp::EntryGet { entry_id })? {
        VaultOpResult::Entry(wire) => {
            entry_from_wire(&wire).map_err(|e| anyhow::anyhow!(e.to_string()))
        }
        other => anyhow::bail!("Entry {} not found: {:?}", entry_id, other),
    }
}

fn reference_metadata_or_none(
    entry: &sentinelpass_core::Entry,
) -> Option<PasskeyReferenceMetadata> {
    parse_passkey_reference_entry(entry).ok()
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
    let entry = build_passkey_reference_entry(
        relying_party_id,
        account_label,
        platform,
        credential_id_hint,
        sync_source,
        notes,
        favorite,
    )?;

    let backend = connect_backend(&vault_path)?;

    let entry_id = match backend.call(VaultOp::EntryAdd {
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
        VaultOpResult::EntryId(id) => id,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    println!("✓ Passkey reference created with ID: {}", entry_id);
    println!("This is metadata only. Authentication remains with the platform authenticator.");
    Ok(())
}

/// List every passkey-reference entry with its parsed metadata fields.
pub fn handle_passkey_list(vault_path: PathBuf) -> Result<()> {
    let backend = connect_backend(&vault_path)?;

    let summaries = match backend.call(VaultOp::EntryList)? {
        VaultOpResult::EntryList(list) => list,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    let mut rows = Vec::new();
    for summary in &summaries {
        if summary.credential_type != "passkey_reference" {
            continue;
        }
        let entry = entry_from_backend(&backend, summary.entry_id)?;
        let metadata = reference_metadata_or_none(&entry);
        rows.push((summary.entry_id, entry, metadata));
    }

    if rows.is_empty() {
        println!("No passkey references found. Add one with 'sentinelpass passkey add'");
        return Ok(());
    }

    println!(
        "{:<6} {:<28} {:<30} {:<16} PLATFORM",
        "ID", "RP ID", "ACCOUNT", "SYNC SOURCE"
    );
    for (id, entry, metadata) in rows {
        match metadata {
            Some(m) => println!(
                "{:<6} {:<28} {:<30} {:<16} {}",
                id,
                truncate(&m.relying_party_id, 28),
                truncate(&m.account_label, 30),
                truncate(m.sync_source.as_deref().unwrap_or("-"), 16),
                m.platform,
            ),
            None => println!(
                "{:<6} {:<28} {:<30} {:<16} (unparseable reference)",
                id,
                truncate(&entry.title, 28),
                truncate(&entry.username, 30),
                "-",
            ),
        }
    }
    Ok(())
}

/// Show one passkey-reference entry as typed metadata (never the raw
/// reference payload).
pub fn handle_passkey_get(vault_path: PathBuf, id: i64) -> Result<()> {
    let backend = connect_backend(&vault_path)?;
    let entry = entry_from_backend(&backend, id)?;

    let metadata = reference_metadata_or_none(&entry);
    println!();
    println!("Title: {}", entry.title);
    println!("Type: Passkey reference (metadata only)");
    match &metadata {
        Some(m) => {
            println!("Relying party ID: {}", m.relying_party_id);
            println!("Account: {}", m.account_label);
            println!("Platform: {}", m.platform);
            if let Some(hint) = &m.credential_id_hint {
                println!("Credential hint: {}", hint);
            }
            if let Some(source) = &m.sync_source {
                println!("Sync source: {}", source);
            }
        }
        None => {
            println!("Reference payload: (present but unparseable as metadata)");
        }
    }
    if let Some(notes) = &entry.notes {
        println!("Notes: {}", notes);
    }
    let created = chrono::DateTime::from_timestamp(entry.created_at.timestamp(), 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| entry.created_at.to_string());
    println!("Created: {}", created);
    if entry.favorite {
        println!("⭐ Favorite");
    }
    println!();
    println!(
        "This is metadata only — authentication happens through the platform authenticator \
         (e.g. iCloud Keychain, Windows Hello)."
    );
    Ok(())
}

/// Delete a passkey reference entry, making clear that only the SentinelPass
/// metadata record is removed — the platform passkey itself is untouched.
pub fn handle_passkey_delete(vault_path: PathBuf, id: i64, force: bool) -> Result<()> {
    let backend = connect_backend(&vault_path)?;

    let entry = entry_from_backend(&backend, id)?;
    if entry.credential_type != sentinelpass_core::CredentialType::PasskeyReference {
        anyhow::bail!(
            "Entry {} is not a passkey reference (use 'sentinelpass entry delete' for it)",
            id
        );
    }

    if !force {
        println!("Passkey reference to delete:");
        println!("  Title: {}", entry.title);
        println!("  Username: {}", entry.username);
        println!();
        println!(
            "Only the SentinelPass metadata record is removed. The platform passkey \
             itself (iCloud Keychain / Windows Hello / security key) is NOT deleted."
        );
        print!("Are you sure you want to delete this reference? [y/N]: ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        if !confirmation.trim().to_lowercase().starts_with('y') {
            println!("Delete cancelled");
            return Ok(());
        }
    }

    match backend.call(VaultOp::EntryDelete { entry_id: id })? {
        VaultOpResult::Ok => {
            println!("✓ Passkey reference {} deleted", id);
        }
        other => anyhow::bail!("Failed to delete entry {}: {:?}", id, other),
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_delegates_to_core_and_round_trips() {
        let entry = build_passkey_reference_entry(
            "  example.com  ",
            " alice@example.com ",
            "windows-hello",
            Some("  hint  "),
            None,
            Some("  notes  "),
            false,
        )
        .unwrap();
        let metadata = parse_passkey_reference_entry(&entry).unwrap();
        assert_eq!(metadata.relying_party_id, "example.com");
        assert_eq!(metadata.account_label, "alice@example.com");
        assert_eq!(metadata.platform, "windows-hello");
        assert_eq!(metadata.credential_id_hint.as_deref(), Some("hint"));
        assert_eq!(metadata.sync_source, None);
        assert_eq!(entry.notes.as_deref(), Some("notes"));
    }

    #[test]
    fn builder_rejects_blank_required_fields() {
        assert!(build_passkey_reference_entry("", "a", "p", None, None, None, false).is_err());
        assert!(build_passkey_reference_entry("x.com", "", "p", None, None, None, false).is_err());
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("short", 10), "short");
        assert!(truncate("abcdefghij", 5).chars().count() <= 5);
        assert!(truncate("héllo wörld", 6).chars().count() <= 6);
    }
}
