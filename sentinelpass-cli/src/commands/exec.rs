//! `sentinelpass exec` and `sentinelpass env` — serve secrets as environment
//! variables to local tools through the allowlisted daemon IPC path.
//!
//! Security note: the child process inherits the full parent environment plus
//! the injected variables; only run trusted commands. Resolved values are
//! never printed by exec.

use anyhow::Result;
use sentinelpass_core::{
    daemon::ipc::{default_ipc_socket_path, IpcClient, IpcMessage},
    ExternalSecretField,
};

use crate::commands::secret::SecretLookupResult;
use crate::SecretOutputFormat;

/// One NAME=domain[:field] mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSpec {
    pub name: String,
    pub domain: String,
    pub field: ExternalSecretField,
}

/// Parse `NAME=domain[:field]`. The domain may itself contain colons (for
/// example sandhi's `sandhi:provider:label`), so the split happens at the
/// LAST colon. Missing field defaults to password.
pub fn parse_env_spec(spec: &str) -> Result<EnvSpec> {
    let (name, rest) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid --env spec '{}': expected NAME=domain[:field]",
            spec
        )
    })?;

    let name = name.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!(
            "Invalid --env spec '{}': NAME must be non-empty ASCII letters, digits, or '_'",
            spec
        );
    }

    let (domain, field) = match rest.rfind(':') {
        None => (rest, ExternalSecretField::Password),
        Some(pos) => {
            let field = match &rest[pos + 1..] {
                "username" => ExternalSecretField::Username,
                "password" => ExternalSecretField::Password,
                "title" => ExternalSecretField::Title,
                other => anyhow::bail!(
                    "Invalid --env spec '{}': unknown field '{}' (use username, password, or title)",
                    spec,
                    other
                ),
            };
            (&rest[..pos], field)
        }
    };

    if domain.is_empty() {
        anyhow::bail!("Invalid --env spec '{}': domain must not be empty", spec);
    }

    Ok(EnvSpec {
        name: name.to_string(),
        domain: domain.to_string(),
        field,
    })
}

pub struct ExecOptions {
    pub client_id: String,
    pub token: Option<String>,
    pub biometric_unlock: bool,
    pub purpose: Option<String>,
}

struct ResolvedSpec {
    name: String,
    lookup: SecretLookupResult,
}

async fn resolve_all(specs: &[EnvSpec], opts: &ExecOptions) -> Result<Vec<ResolvedSpec>> {
    let client = IpcClient::new_for_cli(default_ipc_socket_path(), opts.token.clone())?;

    // Preflight once: report lock state before touching any spec.
    crate::commands::secret::unlock_daemon_with_biometric_if_requested(
        &client,
        opts.biometric_unlock,
        "Unlock SentinelPass to serve environment secrets",
    )
    .await?;

    let purpose = opts.purpose.clone().unwrap_or_else(|| "exec".to_string());
    let mut resolved = Vec::with_capacity(specs.len());

    for spec in specs {
        let response = client
            .send(IpcMessage::GetExternalSecret {
                client_id: opts.client_id.clone(),
                domain: spec.domain.clone(),
                field: spec.field,
                purpose: Some(purpose.clone()),
            })
            .await?;

        match response {
            IpcMessage::GetExternalSecretResponse {
                value: Some(value),
                authorized: true,
                error: None,
                locked,
            } => {
                if locked == Some(true) {
                    anyhow::bail!(LockedExit);
                }
                resolved.push(ResolvedSpec {
                    name: spec.name.clone(),
                    lookup: SecretLookupResult {
                        domain: spec.domain.clone(),
                        field: spec.field.into(),
                        client_id: Some(opts.client_id.clone()),
                        purpose: Some(purpose.clone()),
                        value,
                    },
                });
            }
            IpcMessage::GetExternalSecretResponse {
                locked: Some(true), ..
            } => anyhow::bail!(LockedExit),
            IpcMessage::GetExternalSecretResponse {
                value: None,
                authorized: true,
                ..
            } => {
                anyhow::bail!(
                    "no entry for '{}' (grant may exist but the vault has no matching entry)",
                    spec.domain
                );
            }
            IpcMessage::GetExternalSecretResponse {
                authorized: false,
                error,
                ..
            } => {
                let detail = error.unwrap_or_else(|| "not authorized".to_string());
                anyhow::bail!(
                    "{}\nhint: sentinelpass secret allow --client-id {} --domain {} --field {}",
                    detail,
                    opts.client_id,
                    spec.domain,
                    spec.field.as_str()
                );
            }
            IpcMessage::GetExternalSecretResponse {
                error: Some(error), ..
            } => anyhow::bail!("{}", error),
            _ => anyhow::bail!("Unexpected daemon response while resolving '{}'", spec.name),
        }
    }

    Ok(resolved)
}

/// Sentinel error carrying the locked exit code through anyhow.
#[derive(Debug)]
pub struct LockedExit;

impl std::fmt::Display for LockedExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault is locked")
    }
}

impl std::error::Error for LockedExit {}

fn render_exports(resolved: &[ResolvedSpec]) -> String {
    let mut out = String::new();
    for spec in resolved {
        let escaped = spec.lookup.value.replace('\'', "'\\''");
        out.push_str(&format!("export {}='{}'\n", spec.name, escaped));
    }
    out
}

fn render_json(resolved: &[ResolvedSpec]) -> Result<String> {
    let map: serde_json::Map<String, serde_json::Value> = resolved
        .iter()
        .map(|spec| {
            (
                spec.name.clone(),
                serde_json::Value::String(spec.lookup.value.clone()),
            )
        })
        .collect();
    Ok(serde_json::Value::Object(map).to_string())
}

fn daemon_unreachable(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<sentinelpass_core::daemon::ipc::ProtocolError>())
        .any(|protocol_error| {
            matches!(protocol_error, sentinelpass_core::daemon::ipc::ProtocolError::Ipc(msg) if msg.contains("Failed to connect"))
                || matches!(protocol_error, sentinelpass_core::daemon::ipc::ProtocolError::Io(_))
        })
}

fn classify_and_report(err: anyhow::Error) -> i32 {
    if err.is::<LockedExit>() {
        eprintln!(
            "sentinelpass vault is locked — unlock via the UI, \
             'sentinelpass unlock-biometric', or pass --biometric-unlock"
        );
        3
    } else if daemon_unreachable(&err) {
        eprintln!(
            "sentinelpass daemon not running — start it with 'sentinelpass-daemon' \
             (use --start-locked to boot without prompting)"
        );
        4
    } else {
        eprintln!("error: {err}");
        2
    }
}

/// Run `cmd` with the resolved specs injected into its environment.
/// Returns the process exit code to terminate with.
pub fn handle_exec_command(
    specs: &[String],
    opts: ExecOptions,
    command: Vec<std::ffi::OsString>,
) -> Result<i32> {
    let parsed: Vec<EnvSpec> = specs
        .iter()
        .map(|s| parse_env_spec(s))
        .collect::<Result<_>>()?;

    if command.is_empty() {
        anyhow::bail!("No command given after '--'; usage: sentinelpass exec --env NAME=domain[:field] -- cmd [args...]");
    }

    let resolved = match crate::run_async(resolve_all(&parsed, &opts)) {
        Ok(Ok(inner)) => inner,
        Ok(Err(err)) => return Ok(classify_and_report(err)),
        Err(err) => return Ok(classify_and_report(err)),
    };

    let (program, args) = command.split_first().expect("checked non-empty");
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for spec in &resolved {
        cmd.env(&spec.name, &spec.lookup.value);
    }

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{}': {}", program.to_string_lossy(), e))?;

    Ok(status.code().unwrap_or(1))
}

/// Print resolved specs as shell exports or JSON.
pub fn handle_env_command(
    specs: &[String],
    opts: ExecOptions,
    format: SecretOutputFormat,
) -> Result<i32> {
    let parsed: Vec<EnvSpec> = specs
        .iter()
        .map(|s| parse_env_spec(s))
        .collect::<Result<_>>()?;

    let resolved = match crate::run_async(resolve_all(&parsed, &opts)) {
        Ok(Ok(inner)) => inner,
        Ok(Err(err)) => return Ok(classify_and_report(err)),
        Err(err) => return Ok(classify_and_report(err)),
    };

    match format {
        SecretOutputFormat::Plain | SecretOutputFormat::Exports => {
            print!("{}", render_exports(&resolved));
        }
        SecretOutputFormat::Json => {
            println!("{}", render_json(&resolved)?);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_domain_and_field() {
        let spec = parse_env_spec("ANTHROPIC_KEY=anthropic:password").unwrap();
        assert_eq!(spec.name, "ANTHROPIC_KEY");
        assert_eq!(spec.domain, "anthropic");
        assert_eq!(spec.field, ExternalSecretField::Password);
    }

    #[test]
    fn splits_on_last_colon_for_namespaced_domains() {
        let spec = parse_env_spec("ANTHROPIC_KEY=sandhi:anthropic:key:username").unwrap();
        assert_eq!(spec.domain, "sandhi:anthropic:key");
        assert_eq!(spec.field, ExternalSecretField::Username);
    }

    #[test]
    fn missing_field_defaults_to_password() {
        let spec = parse_env_spec("DB_URL=postgres.internal").unwrap();
        assert_eq!(spec.domain, "postgres.internal");
        assert_eq!(spec.field, ExternalSecretField::Password);
    }

    #[test]
    fn rejects_malformed_specs() {
        assert!(parse_env_spec("NO_EQUALS").is_err());
        assert!(parse_env_spec("=domain").is_err());
        assert!(parse_env_spec("BAD-NAME=domain").is_err());
        assert!(parse_env_spec("NAME=domain:typo").is_err());
    }

    #[test]
    fn exports_escape_single_quotes() {
        let resolved = vec![ResolvedSpec {
            name: "SECRET".to_string(),
            lookup: SecretLookupResult {
                domain: "d".into(),
                field: crate::SecretField::Password,
                client_id: None,
                purpose: None,
                value: "it's".into(),
            },
        }];
        let rendered = render_exports(&resolved);
        assert_eq!(rendered, "export SECRET='it'\\''s'\n");
    }
}
