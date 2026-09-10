use crate::commands::service_client as sc;
use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::{parse_otpauth_uri, TotpAlgorithm};
use sentinelpass_protocol::service::{VaultOp, VaultOpResult};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
pub fn handle_totp_add(
    vault_path: PathBuf,
    entry_id: i64,
    secret: Option<&str>,
    otpauth_uri: Option<&str>,
    algorithm: Option<&str>,
    digits: Option<u8>,
    period: Option<u32>,
    issuer: Option<String>,
    account: Option<String>,
) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let (uri_secret, uri_algorithm, uri_digits, uri_period, uri_issuer, uri_account) =
        if let Some(uri) = otpauth_uri {
            let parsed = parse_otpauth_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))?;
            (
                Some(parsed.secret_base32),
                Some(parsed.algorithm),
                Some(parsed.digits),
                Some(parsed.period),
                parsed.issuer,
                parsed.account_name,
            )
        } else {
            (None, None, None, None, None, None)
        };

    let secret_value = match (secret, uri_secret.as_deref()) {
        (Some(value), _) => value.to_string(),
        (None, Some(value)) => value.to_string(),
        (None, None) => prompt_password("Enter TOTP secret (base32): ")?,
    };

    let algorithm = match algorithm {
        Some(value) => value
            .parse::<TotpAlgorithm>()
            .map_err(|e| anyhow::anyhow!("{}", e))?,
        None => uri_algorithm.unwrap_or(TotpAlgorithm::Sha1),
    };

    let digits = digits.or(uri_digits).unwrap_or(6);
    let period = period.or(uri_period).unwrap_or(30);
    let issuer_value = issuer.or(uri_issuer);
    let account_value = account.or(uri_account);

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    backend.call(VaultOp::TotpAdd {
        entry_id,
        secret: Zeroizing::new(secret_value),
        algorithm: Some(algorithm.to_string()),
        digits: Some(digits),
        period: Some(period),
        issuer: issuer_value,
        account_name: account_value,
    })?;

    println!("TOTP secret saved for entry {}", entry_id);
    Ok(())
}

pub fn handle_totp_code(vault_path: PathBuf, entry_id: i64) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;

    match backend.call(VaultOp::TotpCode { entry_id })? {
        VaultOpResult::TotpCode {
            code,
            seconds_remaining,
        } => {
            println!("TOTP code: {}", code);
            println!("Valid for: {} seconds", seconds_remaining);
        }
        other => anyhow::bail!("Unexpected response: {other:?}"),
    }
    Ok(())
}

pub fn handle_totp_remove(vault_path: PathBuf, entry_id: i64, force: bool) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    if !force {
        print!("Remove TOTP secret for entry {}? [y/N]: ", entry_id);
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        if !confirmation.trim().to_lowercase().starts_with('y') {
            println!("Removal cancelled");
            return Ok(());
        }
    }

    let backend = sc::connect(&vault_path, || crate::prompt_master_password(false))?;
    backend.call(VaultOp::TotpRemove { entry_id })?;
    println!("TOTP secret removed for entry {}", entry_id);
    Ok(())
}
