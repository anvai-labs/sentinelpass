use crate::commands::service_client::{self as sc, Backend};
use crate::RegistryCommands;
use anyhow::Result;
use sentinelpass_core::registry::{Criticality, EntityKind, RegistryOverview, RotationStatus};
use sentinelpass_protocol::service::VaultOp;
use std::path::PathBuf;

pub fn handle_registry_command(
    vault_path: PathBuf,
    command: &crate::RegistryCommands,
) -> Result<()> {
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
        RegistryCommands::Unassign { entry_id } => handle_unassign(vault_path, *entry_id),
        RegistryCommands::ExpiresAt {
            entry_id,
            timestamp,
        } => handle_expires_at(vault_path, *entry_id, *timestamp),
        RegistryCommands::Status => handle_status(vault_path),
        RegistryCommands::Report { only_issues } => handle_report(vault_path, *only_issues),
    }
}

fn parse_kind(value: &str) -> Result<EntityKind> {
    EntityKind::parse(value).map_err(|e| anyhow::anyhow!("{}", e))
}

fn parse_criticality(value: &str) -> Result<Criticality> {
    Criticality::parse(value).map_err(|e| anyhow::anyhow!("{}", e))
}

/// Fetch the registry overview through the service backend and decode into
/// the core render type (one conversion point for all registry renders).
fn fetch_overview(backend: &Backend, include_strength: bool) -> Result<RegistryOverview> {
    let value = sc::expect_report(backend.call(VaultOp::RegistryOverview { include_strength })?)?;
    serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("failed to decode registry overview: {}", e))
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
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let entity = match backend.call(VaultOp::EntityAdd {
        name: name.trim().to_string(),
        kind: kind.as_str().to_string(),
        criticality: criticality.as_str().to_string(),
        notes: notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        rotation_interval_days,
    })? {
        sentinelpass_protocol::service::VaultOpResult::Entity(entity) => entity,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    println!("Entity registered: {} ({})", entity.name, entity.entity_id);
    println!(
        "  kind={} criticality={} rotation-interval={}",
        entity.kind,
        entity.criticality,
        entity
            .rotation_interval_days_override
            .map(|days| format!("{}d (override)", days))
            .unwrap_or_else(|| "policy default".to_string())
    );
    Ok(())
}

fn handle_entity_list(vault_path: PathBuf) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let overview = fetch_overview(&backend, false)?;

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
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::EntityDelete {
        name: name.trim().to_string(),
    })?;
    println!("Entity deleted: {}", name.trim());
    Ok(())
}

fn handle_assign(
    vault_path: PathBuf,
    entry_id: i64,
    entity_name: &str,
    label: Option<&str>,
) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::EntryAssign {
        entry_id,
        entity: entity_name.trim().to_string(),
        label: label.map(str::to_string),
    })?;
    println!("Entry {} assigned to {}", entry_id, entity_name.trim());
    Ok(())
}

fn handle_mark_rotated(vault_path: PathBuf, entry_id: i64) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::EntryMarkRotated { entry_id })?;
    println!(
        "Entry {} marked as rotated (password_rotated_at = now)",
        entry_id
    );
    Ok(())
}

fn handle_unassign(vault_path: PathBuf, entry_id: i64) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::EntryUnassign { entry_id })?;
    println!("Entry {} unassigned from its entity", entry_id);
    Ok(())
}

fn handle_expires_at(vault_path: PathBuf, entry_id: i64, timestamp: Option<i64>) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::EntrySetExpiresAt {
        entry_id,
        expires_at: timestamp,
    })?;
    match timestamp {
        Some(ts) => println!("Entry {} expiry set to unix timestamp {}", entry_id, ts),
        None => println!("Entry {} expiry cleared", entry_id),
    }
    Ok(())
}

fn handle_status(vault_path: PathBuf) -> Result<()> {
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let overview = fetch_overview(&backend, false)?;

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
    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let overview = fetch_overview(&backend, true)?;

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
