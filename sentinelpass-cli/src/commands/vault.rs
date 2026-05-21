use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::VaultManager;
use std::path::PathBuf;
use tracing::error;

pub fn handle_init(vault_path: PathBuf, dev: bool) -> Result<()> {
    println!("Initializing new SentinelPass vault...");
    if dev {
        println!("Running in development mode (in-memory database)");
    }

    // Check if vault already exists
    if !dev && vault_path.exists() {
        anyhow::bail!("Vault already exists at: {:?}", vault_path);
    }

    let password = crate::prompt_master_password(true)?;

    // Create vault
    let vault = VaultManager::create(&vault_path, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to create vault: {}", e))?;

    println!("✓ Vault created successfully at: {:?}", vault_path);
    println!("✓ Your vault is now unlocked and ready to use");
    println!();
    println!("Next steps:");
    println!("  sentinelpass add --title 'GitHub' --username 'user@example.com'");
    println!("  sentinelpass list");

    // Vault is dropped here, which locks it
    drop(vault);
    Ok(())
}

pub fn handle_unlock(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!(
            "No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault",
            vault_path
        );
    }

    let password = prompt_password("Enter master password: ")?;

    match crate::open_vault_with_password(&vault_path, password.as_bytes()) {
        Ok(vault) => {
            println!("✓ Vault unlocked successfully");
            drop(vault);
        }
        Err(e) => {
            error!("Failed to unlock vault: {}", e);
            return Err(e);
        }
    }
    Ok(())
}

pub fn handle_lock() -> Result<()> {
    println!("Vault locks automatically when the process exits.");
    println!("The vault is only kept in memory during operations.");
    Ok(())
}

pub fn handle_biometric_status(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let configured = VaultManager::is_biometric_unlock_enabled(&vault_path)?;
    let method_name = sentinelpass_core::BiometricManager::get_method_name();
    let available = sentinelpass_core::BiometricManager::is_available();
    let enrolled = sentinelpass_core::BiometricManager::is_enrolled();

    println!("Biometric method: {}", method_name);
    println!("Available: {}", if available { "yes" } else { "no" });
    println!("Enrolled: {}", if enrolled { "yes" } else { "no" });
    println!(
        "Configured for vault: {}",
        if configured { "yes" } else { "no" }
    );
    Ok(())
}

pub fn handle_biometric_enable(vault_path: PathBuf, master_password: Option<&str>) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = match master_password {
        Some(value) => value.to_string(),
        None => prompt_password("Enter master password: ")?,
    };
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    vault.enable_biometric_unlock(master_password.as_bytes())?;
    println!("Biometric unlock enabled for this vault.");
    Ok(())
}

pub fn handle_biometric_disable(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let vault = crate::open_vault_with_password(&vault_path, master_password.as_bytes())?;
    vault.disable_biometric_unlock()?;
    println!("Biometric unlock disabled for this vault.");
    Ok(())
}

pub fn handle_unlock_biometric(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let reason = "Unlock SentinelPass vault";
    match VaultManager::open_with_biometric(&vault_path, reason) {
        Ok(vault) => {
            println!("✓ Vault unlocked successfully via biometric authentication");
            drop(vault);
        }
        Err(e) => {
            error!("Failed biometric unlock: {}", e);
            anyhow::bail!("Biometric unlock failed: {}", e);
        }
    }
    Ok(())
}
