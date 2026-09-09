use crate::commands::service_client as sc;
use anyhow::Result;
use sentinelpass_core::keepass::xml::{generate_keepass_xml, parse_keepass_xml};
use sentinelpass_core::Entry;
use sentinelpass_core::{
    parse_csv_import, parse_json_import, render_csv_export, render_json_export, ExportEntry,
    KeePassEntry,
};
use sentinelpass_protocol::service::{ServiceEntry, VaultOp, VaultOpResult};
use std::path::{Path, PathBuf};

/// Wire entry -> core `Entry` (for the export renderers that consume core
/// types). One conversion point for the export paths.
fn wire_to_entry(entry: &ServiceEntry) -> Result<Entry> {
    sentinelpass_core::daemon::service::entry_from_wire(entry)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn core_to_wire(entry: &Entry) -> Result<ServiceEntry> {
    sentinelpass_core::daemon::service::entry_to_wire(entry)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

/// Fetch every exportable entry through the service backend (the executor
/// applies the same exportable-type filter as every built-in export path).
fn fetch_export_entries(backend: &sc::Backend) -> Result<Vec<Entry>> {
    match backend.call(VaultOp::ExportAll)? {
        VaultOpResult::Entries(entries) => entries.iter().map(wire_to_entry).collect(),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub fn handle_export(vault_path: PathBuf, output: &Path, format: &str) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let entries = fetch_export_entries(&backend)?;

    match format {
        "json" => {
            let export_entries: Vec<ExportEntry> =
                entries.clone().into_iter().map(ExportEntry::from).collect();
            render_json_export(&export_entries, output)?;
            println!(
                "Exported {} entries to {}",
                export_entries.len(),
                output.display()
            );
        }
        "csv" => {
            render_csv_export(&entries, output)?;
            println!("Exported {} entries to {}", entries.len(), output.display());
        }
        "keepass" => {
            let ke_entries: Vec<KeePassEntry> = entries
                .clone()
                .into_iter()
                .map(KeePassEntry::from)
                .collect();
            let xml = generate_keepass_xml(&ke_entries)?;
            let mut file = sentinelpass_core::platform::create_owner_only_file(output)
                .map_err(|e| anyhow::anyhow!("Failed to create export file: {}", e))?;
            use std::io::Write;
            file.write_all(xml.as_bytes())?;
            println!("Exported vault entries to {}", output.display());
            println!("Note: This file contains unencrypted passwords. Handle with care!");
        }
        _ => anyhow::bail!(
            "Unsupported format: {}. Use 'json', 'csv', or 'keepass'",
            format
        ),
    }
    Ok(())
}

fn import_entries_via_backend(backend: &sc::Backend, entries: Vec<Entry>) -> Result<usize> {
    let mut wire = Vec::with_capacity(entries.len());
    for entry in &entries {
        wire.push(core_to_wire(entry)?);
    }
    match backend.call(VaultOp::ImportEntries { entries: wire })? {
        VaultOpResult::Imported(ids) => Ok(ids.len()),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub fn handle_import(vault_path: PathBuf, input: &Path, format: &str) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    match format {
        "json" => {
            let entries = parse_json_import(input)?;
            let count = import_entries_via_backend(&backend, entries)?;
            println!("Imported {} entries from {}", count, input.display());
        }
        "csv" => {
            let entries = parse_csv_import(input)?;
            let count = import_entries_via_backend(&backend, entries)?;
            println!("Imported {} entries from {}", count, input.display());
        }
        "keepass" => {
            let count = import_keepass(&backend, input)?;
            println!("Imported {} entries from {}", count, input.display());
            println!("Note: Groups/tags have been preserved in the notes field.");
        }
        _ => anyhow::bail!(
            "Unsupported format: {}. Use 'json', 'csv', or 'keepass'",
            format
        ),
    }
    Ok(())
}

pub fn handle_keepass_import(vault_path: PathBuf, input: &Path) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let count = import_keepass(&backend, input)?;
    println!("Imported {} entries from {}", count, input.display());
    println!("Note: Groups/tags have been preserved in the notes field.");
    Ok(())
}

fn import_keepass(backend: &sc::Backend, input: &Path) -> Result<usize> {
    let ke_entries = parse_keepass_xml(input)?;
    let mut wire = Vec::with_capacity(ke_entries.len());
    for ke_entry in ke_entries {
        let entry = Entry::from(ke_entry);
        wire.push(core_to_wire(&entry)?);
    }
    match backend.call(VaultOp::ImportEntries { entries: wire })? {
        VaultOpResult::Imported(ids) => Ok(ids.len()),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub fn handle_keepass_export(vault_path: PathBuf, output: &Path) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let entries = fetch_export_entries(&backend)?;

    let ke_entries: Vec<KeePassEntry> = entries.into_iter().map(KeePassEntry::from).collect();
    let xml = generate_keepass_xml(&ke_entries)?;
    let mut file = sentinelpass_core::platform::create_owner_only_file(output)
        .map_err(|e| anyhow::anyhow!("Failed to create export file: {}", e))?;
    use std::io::Write;
    file.write_all(xml.as_bytes())?;
    println!("Exported vault entries to {}", output.display());
    println!("Note: This file contains unencrypted passwords. Handle with care!");
    Ok(())
}
