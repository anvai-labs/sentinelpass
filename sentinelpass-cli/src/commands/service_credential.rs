//! `sentinelpass service-credential` — provision vault secrets into Linux
//! systemd encrypted credentials (ADR-011; runbook: docs/SERVICE_CREDENTIALS.md).
//!
//! Security invariants: the resolved plaintext travels from the broker to
//! `systemd-creds` via a stdin pipe only; it is never printed, never passed
//! as an argument, and never written to disk by this CLI.

use anyhow::Result;
use sentinelpass_core::{
    default_credstore_dir, install_credential, remove_credential, verify_installed, InstallOptions,
    PasswordManagerError, ProtectionMode as CoreProtectionMode, ServiceCredentialManifest,
    ServiceCredentialRecord, SystemdCredsTool,
};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::{SecretField, ServiceProtection};

pub(crate) struct InstallArgs {
    pub client_id: String,
    pub token: Option<String>,
    pub domain: String,
    pub field: SecretField,
    pub cred_name: String,
    pub protection: ServiceProtection,
    pub not_after: Option<String>,
    pub credstore_dir: Option<PathBuf>,
    pub systemd_creds: Option<PathBuf>,
    pub verify: bool,
    pub biometric_unlock: bool,
    pub prompt_reason: String,
}

pub(crate) struct VerifyArgs {
    pub client_id: String,
    pub token: Option<String>,
    pub domain: String,
    pub field: SecretField,
    pub cred_name: String,
    pub credstore_dir: Option<PathBuf>,
    pub systemd_creds: Option<PathBuf>,
    pub biometric_unlock: bool,
    pub prompt_reason: String,
}

/// Resolve the credential store directory: explicit override, else the
/// platform default (Linux only — elsewhere the caller must be explicit,
/// which keeps non-Linux hosts limited to tests/exotics by construction).
fn resolve_credstore_dir(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    explicit.cloned().map_or_else(
        || {
            default_credstore_dir().ok_or_else(|| {
                anyhow::anyhow!(
                    "no default encrypted credential store on this platform; \
                     pass --credstore-dir explicitly"
                )
            })
        },
        Ok,
    )
}

fn tool_path(explicit: Option<&PathBuf>) -> PathBuf {
    if let Some(explicit) = explicit {
        return explicit.clone();
    }
    // Prefer an absolute, root-owned location over PATH lookup: this process
    // typically runs as root, and a preserved user PATH would let a planted
    // ~/bin/systemd-creds receive the plaintext (adversarial review F3).
    // --systemd-creds always wins for exotic layouts and tests.
    if cfg!(target_os = "linux") {
        for candidate in ["/usr/bin/systemd-creds", "/usr/local/bin/systemd-creds"] {
            let candidate = PathBuf::from(candidate);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("systemd-creds")
}

/// Fetch the secret through the audited broker (grant + client token) and
/// return it as zeroized bytes. Nothing is printed.
fn resolve_secret_bytes(
    client_id: String,
    token: Option<String>,
    domain: String,
    field: SecretField,
    biometric_unlock: bool,
    prompt_reason: String,
    purpose: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let lookup = crate::run_async(crate::commands::secret::get_secret_from_daemon(
        domain,
        field,
        biometric_unlock,
        prompt_reason,
        client_id,
        Some(purpose.to_string()),
        token,
    ))??;
    Ok(Zeroizing::new(lookup.value.into_bytes()))
}

pub(crate) fn handle_install(args: InstallArgs) -> Result<()> {
    let credstore_dir = resolve_credstore_dir(args.credstore_dir.as_ref())?;
    let tool = SystemdCredsTool::new(tool_path(args.systemd_creds.as_ref()));

    // Fail fast on bad names and an unusable credential store BEFORE
    // touching the daemon or the vault (a doomed run should not consume an
    // audited broker fetch — adversarial review nit).
    sentinelpass_core::validate_credential_name(&args.cred_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    sentinelpass_core::preflight_credstore_dir(&credstore_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let plaintext = resolve_secret_bytes(
        args.client_id.clone(),
        args.token,
        args.domain.clone(),
        args.field,
        args.biometric_unlock,
        args.prompt_reason,
        "service-credential-install",
    )?;

    let receipt = install_credential(
        &plaintext,
        &InstallOptions {
            cred_name: &args.cred_name,
            protection: CoreProtectionMode::from(args.protection),
            credstore_dir: &credstore_dir,
            not_after: args.not_after.as_deref(),
            verify: args.verify,
            tool: &tool,
        },
    )
    .map_err(|e: PasswordManagerError| anyhow::anyhow!("{e}"))?;

    // Manifest (metadata only, no secret material).
    let manifest_path = ServiceCredentialManifest::default_path();
    let mut manifest = ServiceCredentialManifest::load_from_path(&manifest_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    manifest.upsert(ServiceCredentialRecord {
        cred_name: args.cred_name.clone(),
        client_id: args.client_id.clone(),
        domain: args.domain.clone(),
        field: args.field.into(),
        protection: CoreProtectionMode::from(args.protection),
        credstore_dir: credstore_dir.to_string_lossy().to_string(),
        installed_at: chrono::Utc::now(),
        cipher_len: receipt.cipher_len,
        not_after: args.not_after.clone(),
    });
    manifest.save_to_path(&manifest_path).map_err(|e| {
        // The credential IS published; the manifest is not. Make that state
        // explicit instead of letting `list` silently miss it (review nit).
        anyhow::anyhow!(
            "credential PUBLISHED at {} but recording it failed: {e} — re-run \
             'service-credential install' (idempotent) or 'remove' to reconcile",
            receipt.path.display()
        )
    })?;

    println!("Installed service credential:");
    println!("  credential : {}", args.cred_name);
    println!("  file       : {}", receipt.path.display());
    println!("  cipher     : {} bytes", receipt.cipher_len);
    println!(
        "  protection : {}{}",
        args.protection,
        if receipt.verified {
            " (verified before publish)"
        } else {
            " (NOT verified)"
        }
    );
    if let Some(not_after) = &args.not_after {
        println!("  not-after  : {not_after}");
    }
    println!();
    println!("Unit wiring (systemd >= 254):");
    println!("  [Service]");
    println!("  LoadCredentialEncrypted={}", args.cred_name);
    println!();
    println!(
        "Read it in the unit from $CREDENTIALS_DIRECTORY/{} — then \
         'systemctl daemon-reload && systemctl restart <unit>'.",
        args.cred_name
    );
    if matches!(args.protection, ServiceProtection::HostKey) {
        println!();
        println!(
            "Note: host-key mode is defeated by a FULL disk snapshot (the key \
             lives on the same disk) — see docs/SERVICE_CREDENTIALS.md."
        );
    }
    Ok(())
}

/// Returns a process exit code: 0 = match, 3 = mismatch/absent.
pub(crate) fn handle_verify(args: VerifyArgs) -> Result<i32> {
    // Directory precedence: explicit flag, else the manifest's recorded dir
    // for this credential, else the platform default (matches the `Verify`
    // help text and `remove`'s behavior — proxy review finding 5).
    let manifest =
        ServiceCredentialManifest::load_from_path(&ServiceCredentialManifest::default_path())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    let credstore_dir = match &args.credstore_dir {
        Some(explicit) => explicit.clone(),
        None => manifest
            .find(&args.cred_name)
            .map(|record| PathBuf::from(&record.credstore_dir))
            .map_or_else(|| resolve_credstore_dir(None), Ok)?,
    };
    let tool = SystemdCredsTool::new(tool_path(args.systemd_creds.as_ref()));

    let plaintext = resolve_secret_bytes(
        args.client_id,
        args.token,
        args.domain,
        args.field,
        args.biometric_unlock,
        args.prompt_reason,
        "service-credential-verify",
    )?;

    let matches = verify_installed(&plaintext, &args.cred_name, &credstore_dir, &tool)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if matches {
        println!(
            "MATCH: installed credential '{}' decrypts to the current vault value",
            args.cred_name
        );
        Ok(0)
    } else {
        println!(
            "MISMATCH: installed credential '{}' does not match the vault value \
             (rotate with 'service-credential install')",
            args.cred_name
        );
        Ok(3)
    }
}

pub(crate) fn handle_list() -> Result<()> {
    let manifest =
        ServiceCredentialManifest::load_from_path(&ServiceCredentialManifest::default_path())
            .map_err(|e| anyhow::anyhow!("{e}"))?;

    if manifest.records.is_empty() {
        println!("No service credentials provisioned");
        return Ok(());
    }

    let mut output = format!(
        "{:<32} {:<16} {:<28} {:<10} {:<8} {}\n",
        "Credential", "Client", "Domain", "Field", "Protect", "Installed (UTC)"
    );
    output.push_str(&"-".repeat(120));
    output.push('\n');
    for record in &manifest.records {
        output.push_str(&format!(
            "{:<32} {:<16} {:<28} {:<10} {:<8} {}\n",
            record.cred_name,
            record.client_id,
            record.domain,
            record.field.as_str(),
            record.protection,
            record.installed_at.format("%Y-%m-%d %H:%M"),
        ));
    }
    output.push_str(&format!("Total: {} credential(s)", manifest.records.len()));
    println!("{output}");
    Ok(())
}

pub(crate) fn handle_remove(cred_name: String, credstore_dir: Option<PathBuf>) -> Result<()> {
    let manifest_path = ServiceCredentialManifest::default_path();
    let mut manifest = ServiceCredentialManifest::load_from_path(&manifest_path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let dir = match (credstore_dir, manifest.find(&cred_name)) {
        (Some(explicit), _) => explicit,
        (None, Some(record)) => PathBuf::from(&record.credstore_dir),
        (None, None) => resolve_credstore_dir(None)?,
    };

    // An explicit --credstore-dir that disagrees with the manifest's
    // recorded directory removes THAT file but keeps the row: silently
    // dropping it would orphan the recorded-dir ciphertext (proxy review
    // finding 7).
    let recorded_dir: Option<String> = manifest.find(&cred_name).map(|r| r.credstore_dir.clone());
    let keep_row = match &recorded_dir {
        Some(recorded) if dir.to_string_lossy() != *recorded => {
            println!(
                "Note: --credstore-dir {} differs from the manifest's recorded {}; \
                 the row for the recorded directory is kept",
                dir.display(),
                recorded
            );
            true
        }
        _ => false,
    };

    let removed_file = remove_credential(&cred_name, &dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    let removed_record = if keep_row {
        None
    } else {
        manifest.remove(&cred_name)
    };
    if !keep_row {
        manifest
            .save_to_path(&manifest_path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    if !removed_file && removed_record.is_none() {
        println!("No service credential named '{cred_name}' found");
        return Ok(());
    }

    println!("Removed service credential '{cred_name}'");
    if !removed_file {
        println!("  (ciphertext file was already absent; manifest row cleared)");
    }
    println!();
    println!(
        "Removal is not revocation: rotate the secret at its provider if it may \
         have been exposed (docs/SERVICE_CREDENTIALS.md)."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_explicit_dir_over_platform_default() {
        let dir = resolve_credstore_dir(Some(&PathBuf::from("/tmp/custom-credstore"))).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/custom-credstore"));
    }

    #[test]
    fn platform_default_is_optional() {
        // On Linux this is Some(/etc/credstore.encrypted); elsewhere None.
        let resolved = resolve_credstore_dir(None);
        if cfg!(target_os = "linux") {
            assert!(resolved.is_ok());
        } else {
            assert!(resolved.is_err());
        }
    }

    #[test]
    fn tool_defaults_to_path_lookup() {
        assert_eq!(tool_path(None), PathBuf::from("systemd-creds"));
        assert_eq!(
            tool_path(Some(&PathBuf::from("/opt/fake/systemd-creds"))),
            PathBuf::from("/opt/fake/systemd-creds")
        );
    }
}
