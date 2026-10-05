//! SP-1 / ADR-014: exact-entry service grants — CLI surface.
//!
//! Administration (create, revoke, enrollment begin) rides the daemon's
//! master-password step-up: `Backend::call` retries once with an
//! interactive step-up when the daemon answers the typed
//! `step_up_required` error. Retrieval (`get`) and enrollment completion
//! are unattended-safe: they never prompt for the master password and
//! never unlock a locked daemon — a locked vault is a typed failure
//! telling the operator to unlock (an owner act), not a hidden prompt.

use anyhow::Result;
use sentinelpass_protocol::{VaultOp, VaultOpResult};

use crate::commands::service_client::{self, Backend};

/// The service token may arrive by flag or environment (never argv in
/// steady-state scripts): `SENTINELPASS_SERVICE_TOKEN`. clap's `env` on
/// the flag resolves it; the literal lives here for error messages.
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

/// Unattended-safe connection for retrieval-side ops (review S3): probe
/// the daemon, REFUSE a locked vault with actionable guidance, and never
/// prompt or unlock. Custom `--vault` paths are refused — service grants
/// are daemon-served for the default vault only (no direct path exists
/// by design).
fn connect_backend_no_unlock(vault_path: &std::path::PathBuf) -> Result<Backend> {
    if !vault_path.exists() {
        anyhow::bail!(
            "Vault not found at {}. Run `sentinelpass init` first.",
            vault_path.display()
        );
    }
    if *vault_path != sentinelpass_core::get_default_vault_path() {
        anyhow::bail!(
            "Service grants are served by the daemon for the default vault only; \
             a custom --vault path cannot be used here."
        );
    }
    let probed = crate::run_async(Backend::probe())??;
    let Some(client) = probed else {
        anyhow::bail!(
            "No reachable SentinelPass daemon. Start it with `sentinelpass-daemon` \
             (or launch the desktop app), then retry."
        );
    };
    let backend = Backend::Daemon(client);
    if !backend.is_unlocked()? {
        anyhow::bail!(
            "SentinelPass daemon is locked. Retrieval never prompts or unlocks: \
             run `sentinelpass unlock` (owner act) and retry."
        );
    }
    Ok(backend)
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
    // Success statuses across the five service-grant ops (daemon
    // inventory, server.rs service_secret_report call sites). Review B2:
    // `pending_enrollment` IS a success — the grant is persisted and the
    // enrollment ceremony is the documented next step; reporting it as a
    // denial caused retry loops that minted duplicate pending grants.
    if matches!(
        status,
        "authorized" | "created" | "pending_enrollment" | "challenge" | "enrolled" | "revoked"
    ) {
        return Ok(());
    }
    let detail = report
        .get("error")
        .and_then(|e| e.as_str())
        .map(|e| format!(": {e}"))
        .unwrap_or_default();
    // Review S4: distinguish the actionable non-denial outcomes — a
    // locked vault (operator must unlock; the grant itself is fine) and
    // a missing entry (grant may reference a deleted entry).
    match status {
        "locked" => anyhow::bail!(
            "vault is locked — the daemon locked between connect and execution; \
             unlock and retry{detail}"
        ),
        // Review M4: the daemon deliberately distinguishes store_error
        // ("NOT published — the change did not persist") from authz
        // denials. Reporting it as "denied" made operators believe a
        // revoke succeeded while the grant is still live (and invited
        // create retries that minted duplicate pending grants).
        "store_error" => anyhow::bail!(
            "grant-store write failed — the change was NOT persisted; treat the \
             grant's state as UNCHANGED (a revoked grant is still live; a created \
             grant may not exist — check state before retrying){detail}"
        ),
        "not_found" => anyhow::bail!(
            "no matching grant or entry (the grant may reference a deleted entry){detail}"
        ),
        _ => anyhow::bail!("daemon denied the operation (status: {status}){detail}"),
    }
}

/// Parse a positive duration (`30m`, `8h`, `7d`) into unix-seconds-from-now.
/// Char-boundary-safe (review M3: the byte-index split_at panicked when the
/// last character was multi-byte, e.g. `--expires-in "5日"`).
fn expires_at_from(duration: &str) -> Result<i64> {
    let duration = duration.trim();
    let Some(unit) = ["s", "m", "h", "d"]
        .iter()
        .find_map(|u| duration.strip_suffix(u).map(|amount| (amount, *u)))
    else {
        anyhow::bail!("Expiry must be a positive number plus s, m, h, or d");
    };
    let (amount, unit) = unit;
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
    chrono::Utc::now()
        .timestamp()
        .checked_add(secs)
        .ok_or_else(|| anyhow::anyhow!("Expiry out of range"))
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

/// Validate a 40-hex OpenPGP fingerprint. Normalized to LOWERCASE — the
/// daemon's mint path requires exactly lowercase hex (review B1: an
/// uppercase normalization made every fingerprinted create fail daemon-side
/// after the step-up was already spent).
fn parse_fingerprint(value: &str) -> Result<String> {
    let fp = value.trim().to_ascii_lowercase();
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
    no_newline: bool,
) -> Result<()> {
    // clap's `env` on the flag already resolves SENTINELPASS_SERVICE_TOKEN
    // (review N6: no second manual env read).
    let Some(token) = token else {
        anyhow::bail!(
            "pass --token or set {SERVICE_TOKEN_ENV} (the service token shown when the grant was created)"
        );
    };
    let (value, report) =
        retrieve_service_secret(&vault_path, &client_id, entry_id, &field, &token)?;
    if output_json {
        // Verification-round nit: --json and --no-newline are
        // contradictory output modes — reject rather than half-honor.
        if no_newline {
            anyhow::bail!("--json and --no-newline are mutually exclusive output modes");
        }
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else if no_newline {
        // Review S5: byte-exact output for pipelines (e.g. systemd-creds
        // encrypt over SSH) — the default newline would corrupt the
        // provisioned credential.
        use std::io::Write;
        print!("{value}");
        std::io::stdout()
            .flush()
            .map_err(|e| anyhow::anyhow!("failed to write output: {e}"))?;
    } else {
        println!("{value}");
    }
    Ok(())
}

/// Shared exact-entry retrieval core (F3): fetch one field under a service
/// grant without prompting or unlocking (review S3 discipline). Returns the
/// raw value plus the full daemon report (for callers that surface JSON);
/// callers decide disposition (print / pipe to systemd-creds / zeroize).
/// Used by `service-grant get` AND `service-credential install/verify
/// --entry-id`.
pub fn retrieve_service_secret(
    vault_path: &std::path::PathBuf,
    client_id: &str,
    entry_id: i64,
    field: &str,
    token: &str,
) -> Result<(String, serde_json::Value)> {
    let field = field.to_ascii_lowercase();
    if !matches!(field.as_str(), "username" | "password" | "title") {
        anyhow::bail!("unknown field {field:?} (username, password, title)");
    }
    // Review S3: retrieval never prompts or unlocks — a locked vault is a
    // typed failure with unlock guidance, not a hidden master-password
    // prompt that would hang unattended/cron retrieval.
    let backend = connect_backend_no_unlock(vault_path)?;
    let result = backend.call(VaultOp::ServiceGetSecret {
        client_id: client_id.to_string(),
        entry_id,
        field,
        token: token.to_string(),
    })?;
    let report = report(result)?;
    report_error(&report)?;
    let value = report
        .get("value")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("daemon authorized the grant but returned no value"))?;
    Ok((value, report))
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
    // Review N8: both blobs cannot come from stdin — the second read
    // would silently get "".
    if signature == "-" && public_key == "-" {
        anyhow::bail!(
            "--signature and --public-key cannot BOTH read stdin; pass at least one as a file"
        );
    }
    let signature_armored = read_blob(&signature)?;
    let client_public_key = read_blob(&public_key)?;
    // Unattended-safe side of the ceremony (nonce + signature are the
    // credentials): never prompts, never unlocks.
    let backend = connect_backend_no_unlock(&vault_path)?;
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
    fn fingerprint_normalizes_to_lowercase_40_hex() {
        // Review B1/N9: assert the EXACT normalized value — the daemon's
        // mint path rejects uppercase hex, so any uppercase here would
        // dead-end the enrollment ceremony after the step-up was spent.
        let ok = parse_fingerprint("0123456789ABCDEF0123456789abcdef01234567").unwrap();
        assert_eq!(ok, "0123456789abcdef0123456789abcdef01234567");
        assert!(parse_fingerprint("short").is_err());
        assert!(parse_fingerprint(&"g".repeat(40)).is_err());
        assert!(parse_fingerprint(&"a".repeat(39)).is_err());
    }

    #[test]
    fn exe_pins_normalize_to_lowercase_64_hex_each() {
        let good = "A".repeat(64);
        assert_eq!(parse_exe_pins(&good).unwrap(), vec!["a".repeat(64)]);
        let pair = format!("{},{}", "B".repeat(64), "c".repeat(64));
        assert_eq!(
            parse_exe_pins(&pair).unwrap(),
            vec!["b".repeat(64), "c".repeat(64)]
        );
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
        // Review M3: multi-byte final characters must fail cleanly, not
        // panic on a char boundary (the byte-index split_at did).
        assert!(expires_at_from("5日").is_err());
        assert!(expires_at_from("日").is_err());
        assert!(expires_at_from("m").is_err());
        assert!(expires_at_from("99999999999999999999d").is_err());
        // Review N7: no panic/wrap at the i64 ceiling.
        assert!(expires_at_from("9223372036854775807s").is_err());
    }

    #[test]
    fn report_error_classifies_statuses() {
        let ok = serde_json::json!({"status": "authorized", "value": "v"});
        assert!(report_error(&ok).is_ok());
        // Review B2: pending_enrollment is a SUCCESS (grant persisted);
        // misreporting it as a denial caused duplicate-grant retry loops.
        let pending = serde_json::json!({"status": "pending_enrollment"});
        assert!(report_error(&pending).is_ok());
        for status in ["created", "challenge", "enrolled", "revoked"] {
            assert!(
                report_error(&serde_json::json!({"status": status})).is_ok(),
                "{status} must be a success"
            );
        }
        let denied = serde_json::json!({"status": "denied", "error": "no grant"});
        let err = report_error(&denied).unwrap_err().to_string();
        assert!(err.contains("denied") && err.contains("no grant"), "{err}");
        // Review S4: locked/not_found get actionable wording, not
        // "denied" (an operator with a valid grant must not re-mint).
        let locked = serde_json::json!({"status": "locked"});
        let err = report_error(&locked).unwrap_err().to_string();
        assert!(err.contains("locked") && !err.contains("denied"), "{err}");
        let missing = serde_json::json!({"status": "not_found"});
        let err = report_error(&missing).unwrap_err().to_string();
        assert!(
            err.contains("no matching grant") && !err.contains("denied"),
            "{err}"
        );
        // Review M4: store_error means NOT PERSISTED — must not read as a
        // denial (an operator would believe a failed revoke succeeded
        // while the grant is still live).
        let store_err = serde_json::json!({"status": "store_error"});
        let err = report_error(&store_err).unwrap_err().to_string();
        assert!(!err.contains("denied"), "{err}");
        assert!(
            err.contains("NOT persisted") && err.contains("UNCHANGED"),
            "{err}"
        );
    }
}
