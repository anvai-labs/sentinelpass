//! SP-1 / ADR-014: exact-entry service grants — CLI surface.
//!
//! Administration (create, revoke, enrollment begin) rides the daemon's
//! master-password step-up: `Backend::call` retries once with an
//! interactive step-up when the daemon answers the typed
//! `step_up_required` error. Retrieval (`get`) and enrollment completion
//! are unattended-safe and never prompt for the master password.

use anyhow::Result;
use sentinelpass_protocol::{VaultOp, VaultOpResult};

use crate::commands::service_client::{self, Backend};

/// The service token may arrive by flag or by environment (never argv in
/// steady-state scripts): `SENTINELPASS_SERVICE_TOKEN`.
const SERVICE_TOKEN_ENV: &str = "SENTINELPASS_SERVICE_TOKEN";

fn connect_backend(vault_path: &std::path::PathBuf) -> Result<Backend> {
    if !vault_path.exists() {
        anyhow::bail!(
            "Vault not found at {}. Run `sentinelpass init` first.",
            vault_path.display()
        );
    }
    service_client::connect(vault_path, || crate::prompt_master_password(false))
}

fn report(result: VaultOpResult) -> Result<serde_json::Value> {
    service_client::expect_report(result)
}

fn print_report(report: &serde_json::Value) {
    // The report is secret-bearing by design (client_token / value are
    // shown exactly once). Print the JSON body verbatim; callers decide
    // redirection.
    println!(
        "{}",
        serde_json::to_string_pretty(report).unwrap_or_default()
    );
}

fn report_error(report: &serde_json::Value) -> Result<()> {
    let status = report.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status == "authorized"
        || status == "created"
        || status == "challenge"
        || status == "enrolled"
        || status == "revoked"
    {
        return Ok(());
    }
    let detail = report
        .get("error")
        .and_then(|e| e.as_str())
        .map(|e| format!(": {e}"))
        .unwrap_or_default();
    anyhow::bail!("daemon denied the operation (status: {status}){detail}")
}

/// Parse a positive duration (`30m`, `8h`, `7d`) into unix-seconds-from-now.
fn expires_at_from(duration: &str) -> Result<i64> {
    let duration = duration.trim();
    if duration.len() < 2 {
        anyhow::bail!("Expiry must be a positive number plus s, m, h, or d");
    }
    let (amount, unit) = duration.split_at(duration.len() - 1);
    let amount: i64 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("Expiry amount must be a positive integer"))?;
    if amount <= 0 {
        anyhow::bail!("Expiry amount must be greater than zero");
    }
    let secs = match unit {
        "s" => Some(amount),
        "m" => amount.checked_mul(60),
        "h" => amount.checked_mul(3600),
        "d" => amount.checked_mul(86400),
        _ => anyhow::bail!("Expiry unit must be one of s, m, h, or d"),
    }
    .ok_or_else(|| anyhow::anyhow!("Expiry out of range"))?;
    Ok(chrono::Utc::now().timestamp() + secs)
}

/// Validate the fields list against the daemon's accepted set before we
/// spend a step-up on a malformed op.
fn parse_fields(fields: &str) -> Result<Vec<String>> {
    let parsed: Vec<String> = fields
        .split(',')
        .map(|f| f.trim().to_ascii_lowercase())
        .filter(|f| !f.is_empty())
        .collect();
    if parsed.is_empty() {
        anyhow::bail!("--fields must name at least one of: username, password, title");
    }
    for field in &parsed {
        if !matches!(field.as_str(), "username" | "password" | "title") {
            anyhow::bail!("unknown field {field:?} (username, password, title)");
        }
    }
    Ok(parsed)
}

/// Validate a 40-hex OpenPGP fingerprint.
fn parse_fingerprint(value: &str) -> Result<String> {
    let fp = value.trim().to_ascii_uppercase();
    if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "--key-fingerprint must be a full 40-hex-digit OpenPGP fingerprint (got {} chars)",
            fp.len()
        );
    }
    Ok(fp)
}

/// Validate hex SHA-256 executable pins.
fn parse_exe_pins(value: &str) -> Result<Vec<String>> {
    let pins: Vec<String> = value
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    if pins.is_empty() {
        anyhow::bail!("--exe-sha256 must name at least one 64-hex SHA-256 digest");
    }
    for pin in &pins {
        if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("--exe-sha256 entries must be 64-hex SHA-256 digests (got {pin})");
        }
    }
    Ok(pins)
}

pub fn handle_create(
    vault_path: std::path::PathBuf,
    client_id: String,
    entry_id: i64,
    fields: String,
    expires_in: Option<String>,
    exe_sha256: Option<String>,
    key_fingerprint: Option<String>,
) -> Result<()> {
    let fields = parse_fields(&fields)?;
    let expires_at = expires_in.as_deref().map(expires_at_from).transpose()?;
    let required_exe_sha256 = exe_sha256.as_deref().map(parse_exe_pins).transpose()?;
    let registration_key_fingerprint = key_fingerprint
        .as_deref()
        .map(parse_fingerprint)
        .transpose()?;

    let backend = connect_backend(&vault_path)?;
    let result = backend.call(VaultOp::ServiceGrantCreate {
        client_id,
        entry_id,
        fields,
        expires_at,
        required_exe_sha256,
        registration_key_fingerprint,
    })?;
    let report = report(result)?;
    report_error(&report)?;
    print_report(&report);
    if report.get("status").and_then(|s| s.as_str()) == Some("pending_enrollment") {
        println!();
        println!("Next: `sentinelpass service-grant enrollment begin --client-id <id>`");
    } else if let Some(token) = report.get("client_token").and_then(|t| t.as_str()) {
        println!();
        println!("Service token (shown once — store it now; it authorizes this grant only):");
        println!("  export {SERVICE_TOKEN_ENV}={token}");
    }
    Ok(())
}

pub fn handle_get(
    vault_path: std::path::PathBuf,
    client_id: String,
    entry_id: i64,
    field: String,
    token: Option<String>,
    output_json: bool,
) -> Result<()> {
    let token = match token.or_else(|| std::env::var(SERVICE_TOKEN_ENV).ok()) {
        Some(token) => token,
        None => anyhow::bail!(
            "pass --token or set {SERVICE_TOKEN_ENV} (the service token shown when the grant was created)"
        ),
    };
    let field = field.to_ascii_lowercase();
    if !matches!(field.as_str(), "username" | "password" | "title") {
        anyhow::bail!("unknown field {field:?} (username, password, title)");
    }

    let backend = connect_backend(&vault_path)?;
    let result = backend.call(VaultOp::ServiceGetSecret {
        client_id,
        entry_id,
        field,
        token,
    })?;
    let report = report(result)?;
    report_error(&report)?;
    let value = report
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("daemon authorized the grant but returned no value"))?;
    if output_json {
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        // Raw value only: this is a machine-facing retrieval surface.
        println!("{value}");
    }
    Ok(())
}

pub fn handle_revoke(vault_path: std::path::PathBuf, grant_id: String) -> Result<()> {
    let grant_id = grant_id
        .parse::<uuid::Uuid>()
        .map_err(|_| anyhow::anyhow!("--grant-id must be a UUID (as shown by create)"))?
        .to_string();
    let backend = connect_backend(&vault_path)?;
    let result = backend.call(VaultOp::ServiceGrantRevoke { grant_id })?;
    let report = report(result)?;
    report_error(&report)?;
    print_report(&report);
    Ok(())
}

pub fn handle_enrollment_begin(vault_path: std::path::PathBuf, client_id: String) -> Result<()> {
    let backend = connect_backend(&vault_path)?;
    let result = backend.call(VaultOp::ServiceEnrollmentBegin { client_id })?;
    let report = report(result)?;
    report_error(&report)?;
    print_report(&report);
    println!();
    println!("Have the CLIENT sign the transcript above (clearsigned, their OpenPGP key),");
    println!(
        "then run `service-grant enrollment complete` with the signature and their public key."
    );
    Ok(())
}

fn read_blob(path: &str) -> Result<String> {
    if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to read stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("failed to read {path}: {e}"))
    }
}

pub fn handle_enrollment_complete(
    vault_path: std::path::PathBuf,
    client_id: String,
    nonce: String,
    signature: String,
    public_key: String,
) -> Result<()> {
    let signature_armored = read_blob(&signature)?;
    let client_public_key = read_blob(&public_key)?;
    let backend = connect_backend(&vault_path)?;
    let result = backend.call(VaultOp::ServiceEnrollmentComplete {
        client_id,
        nonce,
        signature_armored,
        client_public_key,
    })?;
    let report = report(result)?;
    report_error(&report)?;
    print_report(&report);
    if let Some(token) = report.get("client_token").and_then(|t| t.as_str()) {
        println!();
        println!("Service token (shown once — enrollment complete):");
        println!("  export {SERVICE_TOKEN_ENV}={token}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_validation_rejects_unknown_and_empty() {
        assert_eq!(
            parse_fields("password, username").unwrap(),
            vec!["password".to_string(), "username".to_string()]
        );
        assert!(parse_fields("").is_err());
        assert!(parse_fields("api_key").is_err());
        // Whitespace-only entries are dropped, not parsed as a field.
        assert!(parse_fields(" , ").is_err());
    }

    #[test]
    fn fingerprint_requires_40_hex() {
        let ok = parse_fingerprint("0123456789abcdef0123456789ABCDEF01234567").unwrap();
        assert_eq!(ok.len(), 40);
        assert!(parse_fingerprint("short").is_err());
        assert!(parse_fingerprint(&"g".repeat(40)).is_err());
        assert!(parse_fingerprint(&"a".repeat(39)).is_err());
    }

    #[test]
    fn exe_pins_require_64_hex_each() {
        let good = "a".repeat(64);
        assert_eq!(parse_exe_pins(&good).unwrap().len(), 1);
        let pair = format!("{},{}", "b".repeat(64), "c".repeat(64));
        assert_eq!(parse_exe_pins(&pair).unwrap().len(), 2);
        assert!(parse_exe_pins("nothex").is_err());
        assert!(parse_exe_pins(&"a".repeat(63)).is_err());
        assert!(parse_exe_pins("").is_err());
    }

    #[test]
    fn expiry_parses_units_and_rejects_garbage() {
        let now = chrono::Utc::now().timestamp();
        let at = expires_at_from("90s").unwrap();
        assert!((90..=95).contains(&(at - now)));
        let at = expires_at_from("2d").unwrap();
        assert!((2 * 86400..=2 * 86400 + 5).contains(&(at - now)));
        assert!(expires_at_from("0s").is_err());
        assert!(expires_at_from("-5m").is_err());
        assert!(expires_at_from("5w").is_err());
        assert!(expires_at_from("99999999999999999999d").is_err());
    }

    #[test]
    fn report_error_classifies_statuses() {
        let ok = serde_json::json!({"status": "authorized", "value": "v"});
        assert!(report_error(&ok).is_ok());
        let denied = serde_json::json!({"status": "denied", "error": "no grant"});
        let err = report_error(&denied).unwrap_err().to_string();
        assert!(err.contains("denied") && err.contains("no grant"), "{err}");
    }
}
