use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::{
    export_to_csv, export_to_json, export_to_keepass_xml, import_from_csv, import_from_json,
    import_from_keepass_xml,
};
use std::path::PathBuf;

pub fn handle_export(vault_path: PathBuf, output: &PathBuf, format: &str) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    match format {
        "json" => {
            export_to_json(&vault, output)?;
            println!(
                "Exported {} entries to {}",
                vault.list_entries()?.len(),
                output.display()
            );
        }
        "csv" => {
            export_to_csv(&vault, output)?;
            println!(
                "Exported {} entries to {}",
                vault.list_entries()?.len(),
                output.display()
            );
        }
        _ => anyhow::bail!("Unsupported format: {}. Use 'json' or 'csv'", format),
    }
    Ok(())
}

pub fn handle_import(vault_path: PathBuf, input: &PathBuf, format: &str) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let mut vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    match format {
        "json" => {
            let count = import_from_json(&mut vault, input)?;
            println!("Imported {} entries from {}", count, input.display());
        }
        "csv" => {
            let count = import_from_csv(&mut vault, input)?;
            println!("Imported {} entries from {}", count, input.display());
        }
        "keepass" => {
            let count = import_from_keepass_xml(&mut vault, input)?;
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

pub fn handle_keepass_import(vault_path: PathBuf, input: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let mut vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    let count = import_from_keepass_xml(&mut vault, input)?;
    println!("Imported {} entries from {}", count, input.display());
    println!("Note: Groups/tags have been preserved in the notes field.");
    Ok(())
}

pub fn handle_keepass_export(vault_path: PathBuf, output: &PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    export_to_keepass_xml(&vault, output)?;
    println!("Exported vault entries to {}", output.display());
    println!("Note: This file contains unencrypted passwords. Handle with care!");
    Ok(())
}
