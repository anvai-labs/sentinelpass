use anyhow::Result;
use sentinelpass_core::{
    daemon::ipc::{default_ipc_socket_path, IpcClient, IpcMessage},
    ExternalSecretAllowlist, ExternalSecretGrant,
};

use crate::{SecretField, SecretOutputFormat};

#[derive(Debug, PartialEq, Eq)]
pub struct SecretLookupResult {
    pub domain: String,
    pub field: SecretField,
    pub client_id: Option<String>,
    pub purpose: Option<String>,
    pub value: String,
}

pub fn render_secret_lookup(
    result: &SecretLookupResult,
    output: SecretOutputFormat,
) -> Result<String> {
    match output {
        SecretOutputFormat::Plain => Ok(result.value.clone()),
        SecretOutputFormat::Json => serde_json::to_string(&serde_json::json!({
            "domain": &result.domain,
            "field": result.field.as_str(),
            "client_id": &result.client_id,
            "purpose": &result.purpose,
            "value": &result.value,
        }))
        .map_err(|e| anyhow::anyhow!("Failed to render secret lookup JSON: {}", e)),
    }
}

pub async fn unlock_daemon_with_biometric_if_requested(
    client: &IpcClient,
    biometric_unlock: bool,
    prompt_reason: &str,
) -> Result<()> {
    let status = client.send(IpcMessage::CheckVault).await?;
    let unlocked = matches!(status, IpcMessage::VaultStatusResponse { unlocked: true });

    if unlocked {
        return Ok(());
    }

    if !biometric_unlock {
        anyhow::bail!(
            "SentinelPass daemon is locked. Unlock the vault first or pass --biometric-unlock."
        );
    }

    match client
        .send(IpcMessage::UnlockVaultBiometric {
            prompt_reason: Some(prompt_reason.to_string()),
        })
        .await?
    {
        IpcMessage::UnlockVaultResponse { success: true, .. } => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => {
            let detail = error.unwrap_or_else(|| "unknown error".to_string());
            anyhow::bail!("Biometric unlock failed: {}", detail)
        }
        _ => anyhow::bail!("Unexpected daemon response during biometric unlock"),
    }
}

pub async fn get_secret_from_daemon(
    domain: String,
    field: SecretField,
    biometric_unlock: bool,
    prompt_reason: String,
    client_id: Option<String>,
    purpose: Option<String>,
    client_token: Option<String>,
) -> Result<SecretLookupResult> {
    let client = IpcClient::new_for_cli(default_ipc_socket_path(), client_token)?;
    unlock_daemon_with_biometric_if_requested(&client, biometric_unlock, &prompt_reason).await?;
    let lookup_domain = domain.clone();
    let lookup_client_id = client_id.clone();
    let lookup_purpose = purpose.clone();

    if let Some(client_id) = client_id {
        return match client
            .send(IpcMessage::GetExternalSecret {
                client_id,
                domain,
                field: field.into(),
                purpose,
            })
            .await?
        {
            IpcMessage::GetExternalSecretResponse {
                value,
                authorized: true,
                error: None,
                ..
            } => value
                .map(|value| SecretLookupResult {
                    domain: lookup_domain,
                    field,
                    client_id: lookup_client_id,
                    purpose: lookup_purpose,
                    value,
                })
                .ok_or_else(|| anyhow::anyhow!("Requested secret field is not available")),
            IpcMessage::GetExternalSecretResponse {
                authorized: false,
                error,
                ..
            } => {
                let detail = error.unwrap_or_else(|| "external secret access denied".to_string());
                anyhow::bail!("{}", detail)
            }
            IpcMessage::GetExternalSecretResponse {
                error: Some(error), ..
            } => anyhow::bail!("{}", error),
            _ => anyhow::bail!("Unexpected daemon response during external secret lookup"),
        };
    }

    match client.send(IpcMessage::GetCredential { domain }).await? {
        IpcMessage::GetCredentialResponse {
            username,
            password,
            title,
            ..
        } => {
            let value = match field {
                SecretField::Username => username,
                SecretField::Password => password,
                SecretField::Title => title,
            };

            value
                .map(|value| SecretLookupResult {
                    domain: lookup_domain,
                    field,
                    client_id: lookup_client_id,
                    purpose: lookup_purpose,
                    value,
                })
                .ok_or_else(|| anyhow::anyhow!("Requested secret field is not available"))
        }
        _ => anyhow::bail!("Unexpected daemon response during secret lookup"),
    }
}

pub fn allow_external_secret(
    client_id: String,
    domain: String,
    field: SecretField,
    expires_in: Option<String>,
    allow_write: bool,
    no_token: bool,
) -> Result<(sentinelpass_core::ExternalSecretGrant, Option<String>)> {
    let expires_at = expires_in
        .as_deref()
        .map(parse_external_secret_grant_duration)
        .transpose()?
        .map(|duration| chrono::Utc::now() + duration);

    let path = ExternalSecretAllowlist::default_path();
    let mut allowlist = ExternalSecretAllowlist::load_from_path(&path)
        .map_err(|e| anyhow::anyhow!("Failed to load external secret allowlist: {}", e))?;

    let grant = allowlist
        .upsert_grant(&client_id, &domain, field.into(), expires_at, allow_write)
        .map_err(|e| anyhow::anyhow!("Failed to update external secret allowlist: {}", e))?;

    let minted = if !no_token
        && allowlist.token_status(&grant.client_id) == sentinelpass_core::ClientTokenStatus::Legacy
    {
        Some(
            allowlist
                .mint_client_token(&grant.client_id)
                .map_err(|e| anyhow::anyhow!("Failed to mint client token: {}", e))?,
        )
    } else {
        None
    };

    allowlist
        .save_to_path(&path)
        .map_err(|e| anyhow::anyhow!("Failed to save external secret allowlist: {}", e))?;

    Ok((grant, minted))
}

pub fn revoke_external_secret(
    client_id: String,
    domain: String,
    field: SecretField,
) -> Result<Option<sentinelpass_core::ExternalSecretGrant>> {
    ExternalSecretAllowlist::revoke_default(&client_id, &domain, field.into())
        .map_err(|e| anyhow::anyhow!("Failed to update external secret allowlist: {}", e))
}

pub fn revoke_all_external_secrets(client_id: &str) -> Result<usize> {
    let path = ExternalSecretAllowlist::default_path();
    let mut allowlist = ExternalSecretAllowlist::load_from_path(&path)
        .map_err(|e| anyhow::anyhow!("Failed to load external secret allowlist: {}", e))?;
    let removed = allowlist
        .revoke_all_for_client(client_id)
        .map_err(|e| anyhow::anyhow!("Failed to update external secret allowlist: {}", e))?;
    allowlist
        .save_to_path(&path)
        .map_err(|e| anyhow::anyhow!("Failed to save external secret allowlist: {}", e))?;
    Ok(removed)
}

pub fn list_external_secret_grants(client_id: Option<&str>) -> Result<Vec<ExternalSecretGrant>> {
    ExternalSecretAllowlist::load_default()
        .and_then(|allowlist| allowlist.grants_for_client(client_id))
        .map_err(|e| anyhow::anyhow!("Failed to load external secret allowlist: {}", e))
}

pub fn render_external_secret_grants(grants: &[ExternalSecretGrant]) -> String {
    if grants.is_empty() {
        return "No external secret grants configured".to_string();
    }

    let allowlist = ExternalSecretAllowlist::load_default().unwrap_or_default();

    let mut output = format!(
        "{:<20} {:<30} {:<10} {:<10} Write Expires\n",
        "Client", "Domain", "Field", "Token"
    );
    output.push_str(&"-".repeat(100));
    output.push('\n');

    for grant in grants {
        let expires = grant
            .expires_at
            .map(|expires_at| expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".to_string());
        let token = match allowlist.token_status(&grant.client_id) {
            sentinelpass_core::ClientTokenStatus::Enforced => "required",
            sentinelpass_core::ClientTokenStatus::Legacy => "legacy",
            sentinelpass_core::ClientTokenStatus::Revoked => "revoked",
        };
        let write = if grant.allow_write { "yes" } else { "no" };
        output.push_str(&format!(
            "{:<20} {:<30} {:<10} {:<10} {:<5} {}\n",
            grant.client_id,
            grant.domain,
            grant.field.as_str(),
            token,
            write,
            expires
        ));
    }

    output.push_str(&format!("Total: {} grants", grants.len()));
    output
}

pub fn render_client_tokens(client_id: Option<&str>) -> String {
    let allowlist = match ExternalSecretAllowlist::load_default() {
        Ok(allowlist) => allowlist,
        Err(e) => return format!("Failed to load external secret allowlist: {}", e),
    };

    let mut clients: Vec<&String> = allowlist
        .client_tokens
        .keys()
        .filter(|id| client_id.is_none_or(|filter| id == &filter))
        .collect();
    clients.sort();

    if clients.is_empty() {
        return "No client tokens configured (all clients are legacy / tokenless)".to_string();
    }

    let mut output = format!("{:<20} {:<10} {:<12} Created\n", "Client", "Token", "State");
    output.push_str(&"-".repeat(64));
    output.push('\n');

    for id in &clients {
        let record = &allowlist.client_tokens[id.as_str()];
        let state = if record.revoked { "revoked" } else { "active" };
        output.push_str(&format!(
            "{:<20} {:<10} {:<12} {}\n",
            id,
            allowlist
                .token_fingerprint(id)
                .unwrap_or_else(|| "-".to_string()),
            state,
            record.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    output.push_str(&format!("Total: {} client tokens", clients.len()));
    output
}

pub fn parse_external_secret_grant_duration(value: &str) -> Result<chrono::Duration> {
    let value = value.trim();
    if value.len() < 2 {
        anyhow::bail!("Grant duration must use a positive number plus s, m, h, or d");
    }

    let (amount, unit) = value.split_at(value.len() - 1);
    let amount: i64 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("Grant duration amount must be a positive integer"))?;
    if amount <= 0 {
        anyhow::bail!("Grant duration amount must be greater than zero");
    }

    match unit {
        "s" => Ok(chrono::Duration::seconds(amount)),
        "m" => Ok(chrono::Duration::minutes(amount)),
        "h" => Ok(chrono::Duration::hours(amount)),
        "d" => Ok(chrono::Duration::days(amount)),
        _ => anyhow::bail!("Grant duration unit must be one of s, m, h, or d"),
    }
}

pub fn load_external_secret_audit_events(
    limit: usize,
) -> Result<Vec<sentinelpass_core::AuditEntry>> {
    let logger = sentinelpass_core::AuditLogger::new(sentinelpass_core::get_audit_log_dir())
        .map_err(|e| anyhow::anyhow!("Failed to open audit log: {}", e))?;
    logger
        .get_entries(limit)
        .map_err(|e| anyhow::anyhow!("Failed to read audit log: {}", e))
}

pub fn render_external_secret_audit_report(
    entries: &[sentinelpass_core::AuditEntry],
    client_id: Option<&str>,
    failures_only: bool,
) -> String {
    let client_id = client_id.map(|value| value.trim().to_ascii_lowercase());
    let events: Vec<_> = entries
        .iter()
        .filter_map(|entry| match &entry.event_type {
            sentinelpass_core::AuditEventType::ExternalSecretAccess {
                client_id: event_client_id,
                domain,
                field,
                purpose,
                success,
            } => {
                if failures_only && *success {
                    return None;
                }

                let event_client_normalized = event_client_id
                    .as_deref()
                    .map(|value| value.trim().to_ascii_lowercase());
                if client_id
                    .as_ref()
                    .is_some_and(|client_id| event_client_normalized.as_ref() != Some(client_id))
                {
                    return None;
                }

                Some((
                    entry,
                    event_client_id.as_deref().unwrap_or("legacy"),
                    domain.as_str(),
                    field.as_deref().unwrap_or("unknown"),
                    purpose.as_deref().unwrap_or("-"),
                    *success,
                ))
            }
            _ => None,
        })
        .collect();

    if events.is_empty() {
        return "No external secret audit events found".to_string();
    }

    let mut output = format!(
        "{:<20} {:<8} {:<16} {:<24} {:<10} Purpose\n",
        "Timestamp", "Status", "Client", "Domain", "Field"
    );
    output.push_str(&"-".repeat(96));
    output.push('\n');

    for (entry, client_id, domain, field, purpose, success) in &events {
        let status = if *success { "allowed" } else { "denied" };
        output.push_str(&format!(
            "{:<20} {:<8} {:<16} {:<24} {:<10} {}\n",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            status,
            client_id,
            domain,
            field,
            purpose
        ));
    }

    output.push_str(&format!("Total: {} events", events.len()));
    output
}

pub fn handle_secret_get(
    domain: String,
    field: SecretField,
    biometric_unlock: bool,
    client_id: Option<String>,
    purpose: Option<String>,
    output: SecretOutputFormat,
    prompt_reason: String,
) -> Result<()> {
    let result = crate::run_async(get_secret_from_daemon(
        domain,
        field,
        biometric_unlock,
        prompt_reason,
        client_id,
        purpose,
        None,
    ))??;
    println!("{}", render_secret_lookup(&result, output)?);
    Ok(())
}

pub fn handle_secret_command(command: &crate::SecretCommands) -> Result<()> {
    match command {
        crate::SecretCommands::Allow {
            client_id,
            domain,
            field,
            expires_in,
            write,
            no_token,
        } => {
            let (grant, minted) = allow_external_secret(
                client_id.clone(),
                domain.clone(),
                *field,
                expires_in.clone(),
                *write,
                *no_token,
            )?;
            let expiry = grant
                .expires_at
                .map(|expires_at| format!(" until {}", expires_at.format("%Y-%m-%d %H:%M:%S UTC")))
                .unwrap_or_default();
            let write_note = if grant.allow_write {
                " (read + write)"
            } else {
                ""
            };
            println!(
                "Allowed client '{}' to retrieve {} for {}{}{}",
                grant.client_id,
                grant.field.as_str(),
                grant.domain,
                write_note,
                expiry
            );
            if let Some(token) = minted {
                println!();
                println!(
                    "Client token (shown once — store it now; it authorizes ALL grants for '{}'):",
                    grant.client_id
                );
                println!("  export SENTINELPASS_CLIENT_TOKEN={}", token);
            } else if *no_token {
                println!("Created a legacy grant without a client token (not recommended).");
            }
        }
        crate::SecretCommands::Revoke {
            client_id,
            domain,
            field,
            all,
        } => {
            if *all {
                let removed = revoke_all_external_secrets(client_id)?;
                if removed == 0 {
                    println!("No external secret grants found for client '{}'", client_id);
                } else {
                    println!(
                        "Revoked {} grant(s) for client '{}' (its token, if any, still applies)",
                        removed, client_id
                    );
                    println!(
                        "To also block the tool entirely: sentinelpass secret token revoke --client-id {}",
                        client_id
                    );
                }
            } else {
                let Some(domain) = domain else {
                    anyhow::bail!("--domain is required unless --all is set");
                };
                let Some(field) = field else {
                    anyhow::bail!("--field is required unless --all is set");
                };
                match revoke_external_secret(client_id.clone(), domain.clone(), *field)? {
                    Some(grant) => println!(
                        "Revoked client '{}' access to {} for {}",
                        grant.client_id,
                        grant.field.as_str(),
                        grant.domain
                    ),
                    None => println!("No matching external secret grant found"),
                }
            }
        }
        crate::SecretCommands::Token { command } => handle_secret_token_command(command)?,
        crate::SecretCommands::List { ref client_id } => {
            let grants = list_external_secret_grants(client_id.as_deref())?;
            println!("{}", render_external_secret_grants(&grants));
        }
        crate::SecretCommands::Audit {
            ref client_id,
            limit,
            failures_only,
        } => {
            let entries = load_external_secret_audit_events(*limit)?;
            println!(
                "{}",
                render_external_secret_audit_report(&entries, client_id.as_deref(), *failures_only)
            );
        }
        crate::SecretCommands::Get {
            client_id,
            domain,
            field,
            purpose,
            token,
            output,
            biometric_unlock,
            prompt_reason,
        } => {
            let result = crate::run_async(get_secret_from_daemon(
                domain.clone(),
                *field,
                *biometric_unlock,
                prompt_reason.clone(),
                Some(client_id.clone()),
                purpose.clone(),
                token.clone(),
            ))??;
            println!("{}", render_secret_lookup(&result, *output)?);
        }
    }
    Ok(())
}

pub fn handle_secret_token_command(command: &crate::SecretTokenCommands) -> Result<()> {
    let load = || -> Result<sentinelpass_core::ExternalSecretAllowlist> {
        ExternalSecretAllowlist::load_default()
            .map_err(|e| anyhow::anyhow!("Failed to load external secret allowlist: {}", e))
    };
    let save = |allowlist: &sentinelpass_core::ExternalSecretAllowlist| -> Result<()> {
        allowlist
            .save_to_path(&sentinelpass_core::ExternalSecretAllowlist::default_path())
            .map_err(|e| anyhow::anyhow!("Failed to save external secret allowlist: {}", e))
    };

    match command {
        crate::SecretTokenCommands::Mint { client_id } => {
            let mut allowlist = load()?;
            let token = allowlist
                .mint_client_token(client_id)
                .map_err(|e| anyhow::anyhow!("Failed to mint client token: {}", e))?;
            save(&allowlist)?;
            println!(
                "Client token for '{}' (shown once — store it now; it authorizes ALL grants for this client):",
                client_id
            );
            println!("  export SENTINELPASS_CLIENT_TOKEN={}", token);
        }
        crate::SecretTokenCommands::Rotate { client_id } => {
            let mut allowlist = load()?;
            let token = allowlist
                .rotate_client_token(client_id)
                .map_err(|e| anyhow::anyhow!("Failed to rotate client token: {}", e))?;
            save(&allowlist)?;
            println!(
                "Rotated client token for '{}' (old token no longer works). New token, shown once:",
                client_id
            );
            println!("  export SENTINELPASS_CLIENT_TOKEN={}", token);
        }
        crate::SecretTokenCommands::Revoke { client_id } => {
            let mut allowlist = load()?;
            let existed = allowlist
                .revoke_client_token(client_id)
                .map_err(|e| anyhow::anyhow!("Failed to revoke client token: {}", e))?;
            if !existed {
                println!("No client token exists for '{}'", client_id);
                return Ok(());
            }
            save(&allowlist)?;
            println!(
                "Revoked client token for '{}'. Fail-closed: every grant for this client is now denied, even with the old token.",
                client_id
            );
            println!(
                "To also purge the grants: sentinelpass secret revoke --client-id {} --all",
                client_id
            );
        }
        crate::SecretTokenCommands::List { client_id } => {
            println!("{}", render_client_tokens(client_id.as_deref()));
        }
    }

    Ok(())
}
