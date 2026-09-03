//! `sentinelpass registry` — credential registry posture commands (ADR-001).

use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::registry::policy::RotationStatus;
use sentinelpass_core::{Criticality, EntityKind, VaultManager};
use std::path::PathBuf;

use crate::RegistryCommands;

pub fn handle_registry_command(vault_path: PathBuf, command: &RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::EntityAdd {
            name,
            kind,
            criticality,
            notes,
            rotation_interval_days,
        } => handle_entity_add(
            vault_path,
            name,
            kind,
            criticality.as_str(),
            notes.as_deref(),
            *rotation_interval_days,
        ),
        RegistryCommands::EntityList => handle_entity_list(vault_path),
        RegistryCommands::EntityDelete { name } => handle_entity_delete(vault_path, name),
        RegistryCommands::Assign {
            entry_id,
            entity,
            label,
        } => handle_assign(vault_path, *entry_id, entity, label.as_deref()),
        RegistryCommands::MarkRotated { entry_id } => handle_mark_rotated(vault_path, *entry_id),
        RegistryCommands::Status => handle_status(vault_path),
        RegistryCommands::Report { only_issues } => handle_report(vault_path, *only_issues),
    }
}

fn open_vault(vault_path: PathBuf) -> Result<VaultManager> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }
    let master_password = prompt_password("Master password: ")?;
    let vault = VaultManager::open(&vault_path, master_password.as_bytes())?;
    Ok(vault)
}

fn parse_kind(value: &str) -> Result<EntityKind> {
    EntityKind::parse(value).map_err(|e| anyhow::anyhow!("{}", e))
}

fn parse_criticality(value: &str) -> Result<Criticality> {
    Criticality::parse(value).map_err(|e| anyhow::anyhow!("{}", e))
}

fn handle_entity_add(
    vault_path: PathBuf,
    name: &str,
    kind: &str,
    criticality: &str,
    notes: Option<&str>,
    rotation_interval_days: Option<i64>,
) -> Result<()> {
    let kind = parse_kind(kind)?;
    let criticality = parse_criticality(criticality)?;
    let vault = open_vault(vault_path)?;
    let entity = vault.create_entity(
        name.trim(),
        kind,
        criticality,
        notes.map(str::trim).filter(|value| !value.is_empty()),
        rotation_interval_days,
    )?;
    println!("Entity registered: {} ({})", entity.name, entity.entity_id);
    println!(
        "  kind={} criticality={} rotation-interval={}",
        entity.kind.as_str(),
        entity.criticality.as_str(),
        entity
            .rotation_interval_days_override
            .map(|days| format!("{}d (override)", days))
            .unwrap_or_else(|| "policy default".to_string())
    );
    Ok(())
}

fn handle_entity_list(vault_path: PathBuf) -> Result<()> {
    let vault = open_vault(vault_path)?;
    let overview = vault.registry_overview(false)?;

    if overview.entities.is_empty() {
        println!("No entities registered. Use 'sentinelpass registry entity-add' to create one.");
        return Ok(());
    }

    println!(
        "{:<28} {:<16} {:<10} {:<10} {:>10}",
        "NAME", "KIND", "CRITICALITY", "INTERVAL", "CREDENTIALS"
    );
    for summary in &overview.entities {
        let interval = summary
            .entity
            .rotation_interval_days_override
            .map(|days| format!("{}d*", days))
            .unwrap_or_else(|| "default".to_string());
        println!(
            "{:<28} {:<16} {:<10} {:<10} {:>10}",
            summary.entity.name,
            summary.entity.kind.as_str(),
            summary.entity.criticality.as_str(),
            interval,
            summary.credential_count
        );
    }
    println!("\n(* = entity-level override; policy defaults otherwise)");
    Ok(())
}

fn handle_entity_delete(vault_path: PathBuf, name: &str) -> Result<()> {
    let vault = open_vault(vault_path)?;
    let entity = resolve_entity(&vault, name)?;
    vault.delete_entity(&entity.entity_id)?;
    println!("Entity deleted: {}", entity.name);
    Ok(())
}

fn handle_assign(
    vault_path: PathBuf,
    entry_id: i64,
    entity_name: &str,
    label: Option<&str>,
) -> Result<()> {
    let vault = open_vault(vault_path)?;
    let entity = resolve_entity(&vault, entity_name)?;
    vault.assign_entry(entry_id, &entity.entity_id, label)?;
    println!("Entry {} assigned to {}", entry_id, entity.name);
    Ok(())
}

fn handle_mark_rotated(vault_path: PathBuf, entry_id: i64) -> Result<()> {
    let vault = open_vault(vault_path)?;
    vault.mark_entry_rotated(entry_id)?;
    println!(
        "Entry {} marked as rotated (password_rotated_at = now)",
        entry_id
    );
    Ok(())
}

fn handle_status(vault_path: PathBuf) -> Result<()> {
    let vault = open_vault(vault_path)?;
    ensure_index(&vault)?;
    let overview = vault.registry_overview(false)?;

    let findings = overview
        .posture
        .iter()
        .filter(|entry| entry.status != RotationStatus::Ok)
        .count();

    println!("Registry posture");
    println!(
        "  entities: {} | entries assigned: {} | unassigned: {}",
        overview.entities.len(),
        overview
            .entities
            .iter()
            .map(|summary| summary.credential_count)
            .sum::<i64>(),
        overview.unassigned_entries
    );
    println!("  reuse clusters: {}", overview.reuse_clusters.len());
    println!("  rotation findings: {}", findings);

    if !overview.reuse_clusters.is_empty() {
        println!("\nReuse clusters (same secret across entries):");
        for cluster in &overview.reuse_clusters {
            println!(
                "  [{}] {}",
                cluster.size,
                cluster
                    .entry_ids
                    .iter()
                    .zip(cluster.titles.iter())
                    .map(|(id, title)| format!("#{} \"{}\"", id, title))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    print_findings(&overview.posture, false);
    Ok(())
}

fn handle_report(vault_path: PathBuf, only_issues: bool) -> Result<()> {
    let vault = open_vault(vault_path)?;
    ensure_index(&vault)?;
    let overview = vault.registry_overview(true)?;

    println!(
        "Registry report ({} entries, strength analysis included)",
        overview.posture.len()
    );
    print_findings(&overview.posture, only_issues);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_entity(vault: &VaultManager, name: &str) -> Result<sentinelpass_core::Entity> {
    let entities = vault.list_entities()?;
    entities
        .into_iter()
        .find(|entity| entity.name == name.trim())
        .ok_or_else(|| anyhow::anyhow!("No entity named '{}'", name.trim()))
}

/// Repair the equality index before reading posture from it.
fn ensure_index(vault: &VaultManager) -> Result<()> {
    if vault.registry_backfill_needed()? {
        let report = vault.sweep_registry_index()?;
        eprintln!(
            "Registry index swept: {} scanned, {} inserted, {} rotated, {} orphans pruned",
            report.scanned, report.inserted, report.rotated, report.orphans_pruned
        );
    }
    Ok(())
}

fn status_label(status: RotationStatus) -> &'static str {
    match status {
        RotationStatus::Ok => "OK     ",
        RotationStatus::DueSoon => "DUE    ",
        RotationStatus::Weak => "WEAK   ",
        RotationStatus::Reused => "REUSED ",
        RotationStatus::Overdue => "OVERDUE",
    }
}

fn print_findings(posture: &[sentinelpass_core::EntryPosture], only_issues: bool) {
    let rows: Vec<_> = posture
        .iter()
        .filter(|entry| !only_issues || entry.status != RotationStatus::Ok)
        .collect();

    if rows.is_empty() {
        println!("\nNo findings.");
        return;
    }

    println!();
    for entry in rows {
        println!(
            "[{}] #{} \"{}\"{}",
            status_label(entry.status),
            entry.entry_id,
            entry.title,
            entry
                .entity_name
                .as_deref()
                .map(|name| format!(" (entity: {})", name))
                .unwrap_or_default()
        );
        println!(
            "         interval={}d age={}d{}{}",
            entry.resolved_interval_days,
            entry.days_since_rotation.unwrap_or(0),
            if entry.tool_managed {
                " tool-managed"
            } else {
                ""
            },
            if let Some(expires_at) = entry.expires_at {
                format!(" expires={}", expires_at)
            } else {
                String::new()
            }
        );
        for reason in &entry.reasons {
            println!("         - {}", reason);
        }
    }
}
