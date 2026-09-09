use crate::commands::service_client as sc;
use anyhow::Result;
use base64::Engine;
use sentinelpass_core::{SshAgentClient, SshKeyImporter};
use sentinelpass_protocol::service::{VaultOp, VaultOpResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn default_public_key_path(
    private_key_path: &Path,
    explicit_public_key: Option<&PathBuf>,
) -> PathBuf {
    explicit_public_key.cloned().unwrap_or_else(|| {
        let path_str = private_key_path.to_string_lossy();
        PathBuf::from(format!("{}.pub", path_str))
    })
}

pub fn extract_public_key_comment(public_key_line: &str) -> Option<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts.next()?;
    let _key_data = parts.next()?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    if comment.is_empty() {
        None
    } else {
        Some(comment)
    }
}

pub fn compute_ssh_fingerprint(public_key_line: &str) -> Result<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key type"))?;
    let key_data_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key data"))?;

    let key_data = base64::engine::general_purpose::STANDARD
        .decode(key_data_b64)
        .map_err(|e| anyhow::anyhow!("Invalid base64 in public key: {}", e))?;
    let digest = Sha256::digest(&key_data);
    let fingerprint_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);

    Ok(format!("SHA256:{}", fingerprint_b64))
}

pub fn handle_ssh_agent_status() -> Result<()> {
    let client = SshAgentClient::new()?;
    let available = client.is_available();
    println!(
        "SSH agent available: {}",
        if available { "yes" } else { "no" }
    );
    if !available {
        println!("Hint: ensure `ssh-add` is installed and your SSH agent service is running.");
    }
    Ok(())
}

pub fn handle_ssh_agent_add(key_path: &Path) -> Result<()> {
    let client = SshAgentClient::new()?;
    client
        .add_identity(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to add key to SSH agent: {}", e))?;
    println!("Added SSH key to agent: {}", key_path.display());
    Ok(())
}

pub fn handle_ssh_agent_add_stored(vault_path: PathBuf, id: i64) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    // The agent protocol needs the PEM in THIS process; fetch it over the
    // service boundary (typed SshKey with private material), then clear it.
    let private_key = match backend.call(VaultOp::SshKeyGet {
        key_id: id,
        include_private: true,
    })? {
        VaultOpResult::SshKey(key) => match key.private_key {
            Some(private_key) => private_key,
            None => anyhow::bail!("daemon did not return the private key"),
        },
        other => anyhow::bail!("unexpected response: {other:?}"),
    };
    let mut private_key = private_key.to_string();

    let client = SshAgentClient::new()?;
    let add_result = client
        .add_identity_from_pem(&private_key)
        .map_err(|e| anyhow::anyhow!("Failed to add stored SSH key to agent: {}", e));
    private_key.clear();
    add_result?;

    println!("Added stored SSH key {} to agent.", id);
    Ok(())
}

pub fn handle_ssh_agent_clear() -> Result<()> {
    let client = SshAgentClient::new()?;
    client
        .remove_all_identities()
        .map_err(|e| anyhow::anyhow!("Failed to clear SSH agent identities: {}", e))?;
    println!("Cleared all SSH agent identities.");
    Ok(())
}

pub fn handle_ssh_key_add(
    vault_path: PathBuf,
    name: &str,
    private_key_file: &PathBuf,
    public_key_file: Option<&PathBuf>,
    comment: Option<String>,
) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let public_key_path = default_public_key_path(private_key_file, public_key_file);
    if !private_key_file.exists() {
        anyhow::bail!("Private key file not found: {}", private_key_file.display());
    }
    if !public_key_path.exists() {
        anyhow::bail!("Public key file not found: {}", public_key_path.display());
    }

    let private_key = std::fs::read_to_string(private_key_file).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read private key file {}: {}",
            private_key_file.display(),
            e
        )
    })?;
    let (public_key, key_type) =
        SshKeyImporter::import_public_key(&public_key_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read public key file {}: {}",
                public_key_path.display(),
                e
            )
        })?;

    let key_comment = comment.or_else(|| extract_public_key_comment(&public_key));
    let fingerprint = compute_ssh_fingerprint(&public_key)?;

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    let key_id = match backend.call(VaultOp::SshKeyAdd {
        name: name.to_string(),
        comment: key_comment,
        key_type: serde_json::to_value(key_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| anyhow::anyhow!("failed to encode SSH key type"))?,
        public_key,
        private_key: private_key.into(),
        fingerprint,
    })? {
        VaultOpResult::EntryId(key_id) => key_id,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    println!("SSH key added with ID: {}", key_id);
    Ok(())
}

pub fn handle_ssh_key_list(vault_path: PathBuf) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let keys = match backend.call(VaultOp::SshKeyList)? {
        VaultOpResult::SshKeyList(keys) => keys,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    if keys.is_empty() {
        println!("No SSH keys found in vault.");
    } else {
        println!();
        println!("{:<5} {:<24} {:<18} Fingerprint", "ID", "Name", "Type");
        println!("{}", "-".repeat(96));
        for key in keys {
            println!(
                "{:<5} {:<24} {:<18} {}",
                key.key_id, key.name, key.key_type, key.fingerprint
            );
        }
        println!();
    }
    Ok(())
}

pub fn handle_ssh_key_get(vault_path: PathBuf, id: i64, show_private: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    let key = match backend.call(VaultOp::SshKeyGet {
        key_id: id,
        include_private: show_private,
    })? {
        VaultOpResult::SshKey(key) => key,
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    println!();
    println!("ID: {}", id);
    println!("Name: {}", key.name);
    if let Some(comment) = key.comment {
        println!("Comment: {}", comment);
    }
    println!("Type: {}", key.key_type);
    println!("Fingerprint: {}", key.fingerprint);
    println!("Public key: {}", key.public_key);

    if show_private {
        match key.private_key {
            Some(private_key) => {
                println!();
                println!("Private key:");
                println!("{}", private_key.as_str());
            }
            None => anyhow::bail!("daemon did not return the private key"),
        }
    }
    println!();
    Ok(())
}

pub fn handle_ssh_key_delete(vault_path: PathBuf, id: i64, force: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    if !force {
        print!("Delete SSH key {}? [y/N]: ", id);
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        if !confirmation.trim().to_lowercase().starts_with('y') {
            println!("Delete cancelled");
            return Ok(());
        }
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::SshKeyDelete { key_id: id })?;
    println!("Deleted SSH key {}", id);
    Ok(())
}
