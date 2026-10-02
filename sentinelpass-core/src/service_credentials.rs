//! Restart-safe service credentials: provision vault secrets into Linux
//! systemd **encrypted credentials** so units restart with no SentinelPass
//! daemon, vault, or master password available (ADR-011).
//!
//! Flow: a secret resolved through the scoped external-secret broker is
//! piped (stdin only — never argv, environment, or a temp file) into
//! `systemd-creds encrypt --with-key=<mode> --name=<id>`, the ciphertext is
//! verified by decrypting it back BEFORE publication, and it is then
//! published with an atomic rename into the encrypted credential store
//! (`/etc/credstore.encrypted/<name>` by default). At unit start, PID 1
//! decrypts `LoadCredentialEncrypted=<name>` into the unit's
//! `$CREDENTIALS_DIRECTORY` — the plaintext never rests on disk.
//!
//! Runbook (rotation, revocation, failure recovery, snapshot limitation):
//! `docs/SERVICE_CREDENTIALS.md`.

use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use sentinelpass_protocol::ExternalSecretField;

const MANIFEST_FILE: &str = "service-credentials.json";

/// systemd loads service credentials into memory; keep provisioning bounded.
pub const MAX_CREDENTIAL_BYTES: usize = 512 * 1024;

/// Hard caps on buffered tool output (base64 of the max credential is
/// ~700 KiB; diagnostics are tiny). Past the cap the output is drained and
/// discarded and the run fails (adversarial review F7).
pub const MAX_TOOL_STDOUT: usize = 1024 * 1024;
pub const MAX_TOOL_STDERR: usize = 64 * 1024;

/// Default encrypted-credential store for system units (systemd ≥ 254
/// searches it for bare `LoadCredentialEncrypted=<name>`). Only meaningful
/// on Linux — elsewhere the caller must pass an explicit directory (tests,
/// non-Linux development).
pub const DEFAULT_SYSTEM_CREDSTORE_DIR: &str = "/etc/credstore.encrypted";

/// At-rest protection for the provisioned credential. Mandatory at the CLI
/// surface: `null`/`auto` systemd key modes are refused by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionMode {
    /// `--with-key=host`: encrypted to `/var/lib/systemd/credential.secret`.
    /// A complete disk snapshot includes that key — see the runbook's
    /// documented limitation.
    HostKey,
    /// `--with-key=tpm2`: bound to the host's TPM2 chip (no key on disk).
    Tpm2,
}

impl ProtectionMode {
    /// The `systemd-creds --with-key=` value for this mode.
    pub fn with_key(&self) -> &'static str {
        match self {
            ProtectionMode::HostKey => "host",
            ProtectionMode::Tpm2 => "tpm2",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectionMode::HostKey => "host-key",
            ProtectionMode::Tpm2 => "tpm2",
        }
    }
}

impl std::fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Credential names double as filenames in the credstore, so they must be
/// filename-safe ASCII (systemd requires "a short string suitable as a
/// filename"; we additionally refuse `.`/`..`, leading dots, and `/`).
pub fn validate_credential_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() || name.len() > 96 {
        return Err(format!(
            "credential name must be 1-96 characters: got {name:?}"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        || name.starts_with('.')
    {
        return Err(format!(
            "credential name {name:?} must be filename-safe ASCII \
             (letters, digits, '.', '_', '-'; no leading dot)"
        ));
    }
    Ok(())
}

/// Default encrypted credstore directory, Linux only.
pub fn default_credstore_dir() -> Option<PathBuf> {
    if cfg!(target_os = "linux") {
        Some(PathBuf::from(DEFAULT_SYSTEM_CREDSTORE_DIR))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Manifest — metadata only, never secret material or secret hashes (a
// fingerprint of a low-entropy secret is itself a leak).
// ---------------------------------------------------------------------------

/// One provisioned credential's provenance (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCredentialRecord {
    /// Credential name == filename in the credstore == systemd credential id.
    pub cred_name: String,
    /// Broker client whose grant resolved the secret.
    pub client_id: String,
    /// Vault domain/service key the secret was resolved from.
    pub domain: String,
    pub field: ExternalSecretField,
    pub protection: ProtectionMode,
    /// Absolute path of the directory holding the ciphertext.
    pub credstore_dir: String,
    pub installed_at: DateTime<Utc>,
    /// Ciphertext size in bytes (safe: the file is on disk anyway).
    pub cipher_len: u64,
    /// `systemd-creds --not-after=` value, when one was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCredentialManifest {
    pub records: Vec<ServiceCredentialRecord>,
}

impl ServiceCredentialManifest {
    pub fn default_path() -> PathBuf {
        get_config_dir().join(MANIFEST_FILE)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        // Same fail-closed hygiene as the grants allowlist: a symlinked or
        // foreign-owned manifest is refused; a loose mode is warned about
        // and tightened (WBS-413 discipline).
        crate::platform::validate_sensitive_path(
            path,
            crate::platform::OwnerOnlyPolicy::WarnAndRepair,
        )
        .map_err(PasswordManagerError::from)?;
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to parse service credential manifest: {e}"
            )))
        })
    }

    /// Atomically persisted (temp file + rename), born 0600.
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "service credential manifest {} is a symlink; refusing to write \
                     through it (possible symlink swap). Remove the symlink and retry",
                    path.display()
                )));
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                crate::platform::create_private_dir(parent)
                    .map_err(|e| PasswordManagerError::InvalidInput(e.to_string()))?;
            }
        }
        let contents = serde_json::to_string_pretty(self).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize service credential manifest: {e}"
            )))
        })?;

        // Same unique-temp discipline as the credential itself (verification
        // round N2): a deterministic temp let two overlapping installs
        // interleave truncate-writes and publish an invalid-JSON manifest.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "service-credentials.json".to_string());
        let (temp, mut file) = create_exclusive_temp(parent, &file_name)?;
        if let Err(e) = file
            .write_all(contents.as_bytes())
            .and_then(|_| file.sync_all())
        {
            let _ = std::fs::remove_file(&temp);
            return Err(PasswordManagerError::InvalidInput(format!(
                "Failed to write service credential manifest: {e}"
            )));
        }
        drop(file);
        std::fs::rename(&temp, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            PasswordManagerError::InvalidInput(format!(
                "Failed to publish service credential manifest: {e}"
            ))
        })?;
        // Durably record the rename itself (a crash after the file-level
        // sync must not silently drop the row).
        sync_directory(path.parent().unwrap_or_else(|| Path::new(".")));
        Ok(())
    }

    pub fn find(&self, cred_name: &str) -> Option<&ServiceCredentialRecord> {
        self.records.iter().find(|r| r.cred_name == cred_name)
    }

    pub fn upsert(&mut self, record: ServiceCredentialRecord) {
        match self
            .records
            .iter_mut()
            .find(|r| r.cred_name == record.cred_name)
        {
            Some(existing) => *existing = record,
            None => self.records.push(record),
        }
    }

    pub fn remove(&mut self, cred_name: &str) -> Option<ServiceCredentialRecord> {
        let index = self.records.iter().position(|r| r.cred_name == cred_name)?;
        Some(self.records.remove(index))
    }
}

// ---------------------------------------------------------------------------
// systemd-creds tool wrapper
// ---------------------------------------------------------------------------

/// Thin wrapper around the `systemd-creds(1)` binary.
///
/// Plaintext is exchanged with the tool through pipes only: it never appears
/// in argv, environment, or a file we create. The tool's own stderr (bounded
/// excerpt) is the only diagnostic surfaced on failure — systemd-creds never
/// echoes the payload.
#[derive(Debug, Clone)]
pub struct SystemdCredsTool {
    program: PathBuf,
}

impl SystemdCredsTool {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// `systemd-creds encrypt --with-key=<mode> --name=<name> [- -]`.
    /// Returns the base64 ciphertext (encrypted credentials are always
    /// base64-encoded by the tool).
    pub fn encrypt(
        &self,
        name: &str,
        protection: ProtectionMode,
        not_after: Option<&str>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut command = std::process::Command::new(&self.program);
        command
            .arg("encrypt")
            .arg(format!("--with-key={}", protection.with_key()))
            .arg(format!("--name={name}"));
        if let Some(not_after) = not_after {
            command.arg(format!("--not-after={not_after}"));
        }
        command.arg("-").arg("-");
        let output = Self::run(command, plaintext)?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            // Redact the plaintext from the excerpt: real systemd-creds never
            // echoes the payload, but a replaced/hostile tool might, and the
            // error must not become a leak channel (adversarial review F3).
            let mut stderr = output.stderr;
            redact_bytes(&mut stderr, plaintext);
            Err(tool_error(
                "encrypt",
                &self.program,
                &output.status,
                &stderr,
            ))
        }
    }

    /// `systemd-creds decrypt --name=<name> <path> -` — used only to verify
    /// our own ciphertext before publication (and by the `verify` command).
    pub fn decrypt_path(&self, name: &str, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let mut command = std::process::Command::new(&self.program);
        command
            .arg("decrypt")
            .arg(format!("--name={name}"))
            .arg(path)
            .arg("-");
        let output = Self::run(command, b"")?;
        if output.status.success() {
            Ok(Zeroizing::new(output.stdout))
        } else {
            Err(tool_error(
                "decrypt",
                &self.program,
                &output.status,
                &output.stderr,
            ))
        }
    }

    /// Run the tool with `plaintext` on stdin. Hardening (adversarial review
    /// F3/F7): all `SENTINELPASS_*` environment variables (notably the grant
    /// token) are scrubbed from the child environment, and stdout/stderr are
    /// read under hard caps — a broken or replaced tool cannot memory-exhaust
    /// the (root) CLI by streaming unbounded output.
    fn run(mut command: std::process::Command, plaintext: &[u8]) -> Result<ToolOutput> {
        use std::process::Stdio;
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SENTINELPASS_") {
                command.env_remove(&key);
            }
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "Failed to launch {}: {e} (set --systemd-creds or check PATH)",
                command.get_program().to_string_lossy()
            ))
        })?;

        // Owned copy of the plaintext for the writer thread; zeroized on drop.
        let payload = Zeroizing::new(plaintext.to_vec());
        let mut stdin = child.stdin.take().expect("stdin piped");
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
            // Drop closes the pipe → EOF for the tool.
        });

        // Capped readers on their own threads. Past the cap they keep
        // DRAINING (discarding) until EOF: the child can never block on a
        // full pipe, so a tool streaming unbounded output still terminates
        // cleanly and we merely refuse to buffer it (adversarial review F7).
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();
        let stdout_reader = std::thread::spawn(move || read_capped(stdout_handle, MAX_TOOL_STDOUT));
        let stderr_reader = std::thread::spawn(move || read_capped(stderr_handle, MAX_TOOL_STDERR));

        let join_capped =
            |handle: std::thread::JoinHandle<std::io::Result<CappedRead>>| -> Result<CappedRead> {
                handle.join().map_err(|_| thread_panic())?.map_err(|e| {
                    PasswordManagerError::InvalidInput(format!(
                        "failed reading systemd-creds output: {e}"
                    ))
                })
            };
        let stdout = join_capped(stdout_reader);
        let stderr = join_capped(stderr_reader);
        let over_cap = matches!(&stdout, Ok(read) if read.over_cap)
            || matches!(&stderr, Ok(read) if read.over_cap);
        if over_cap || stdout.is_err() || stderr.is_err() {
            // Reap the child FIRST (verification round N1): killing it closes
            // the pipes, which unblocks the writer thread (EPIPE) — otherwise
            // a hostile tool that overflows a cap and then ignores its stdin
            // wedges the writer's join() forever, and the child stays a
            // zombie on the reader-error paths.
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            return if over_cap {
                Err(PasswordManagerError::InvalidInput(format!(
                    "systemd-creds output exceeded its byte cap (stdout {}, stderr {}) — \
                     refusing to buffer it (is the tool at {} really systemd-creds?)",
                    MAX_TOOL_STDOUT,
                    MAX_TOOL_STDERR,
                    command.get_program().to_string_lossy()
                )))
            } else {
                Err(stdout.err().or(stderr.err()).unwrap_or_else(thread_panic))
            };
        }
        let stdout = stdout.unwrap();
        let stderr = stderr.unwrap();
        let status = child.wait().map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "systemd-creds did not run to completion: {e}"
            ))
        })?;
        let _ = writer.join();
        Ok(ToolOutput {
            status,
            stdout: stdout.data,
            stderr: stderr.data,
        })
    }
}

struct ToolOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn thread_panic() -> PasswordManagerError {
    PasswordManagerError::InvalidInput("tool output reader thread failed".to_string())
}

fn read_capped<R: std::io::Read>(mut reader: Option<R>, cap: usize) -> std::io::Result<CappedRead> {
    let mut data = Vec::new();
    let mut over_cap = false;
    let mut chunk = [0u8; 8192];
    if let Some(reader) = &mut reader {
        loop {
            let n = reader.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if over_cap {
                continue; // drain and discard
            }
            if data.len() + n > cap {
                over_cap = true;
                continue;
            }
            data.extend_from_slice(&chunk[..n]);
        }
    }
    Ok(CappedRead { data, over_cap })
}

struct CappedRead {
    data: Vec<u8>,
    over_cap: bool,
}

/// Replace every occurrence of `secret` in `data` with `[redacted]`.
fn redact_bytes(data: &mut Vec<u8>, secret: &[u8]) {
    if secret.is_empty() || data.len() < secret.len() {
        return;
    }
    let replacement = b"[redacted]";
    let mut i = 0;
    while i + secret.len() <= data.len() {
        if &data[i..i + secret.len()] == secret {
            data.splice(i..i + secret.len(), replacement.iter().copied());
            i += replacement.len();
        } else {
            i += 1;
        }
    }
    // Verification round N3: the scan skips past each inserted marker, so a
    // secret that is itself a substring of "[redacted]" could survive. If
    // anything secret-looking remains, suppress the whole buffer.
    if data.windows(secret.len()).any(|w| w == secret) {
        data.clear();
        data.extend_from_slice(b"[stderr suppressed]");
    }
}

fn tool_error(
    phase: &str,
    program: &Path,
    status: &std::process::ExitStatus,
    stderr: &[u8],
) -> PasswordManagerError {
    // Bounded, plaintext-redacted stderr excerpt (adversarial review F3).
    let stderr = String::from_utf8_lossy(stderr);
    let excerpt: String = stderr.chars().take(300).collect();
    PasswordManagerError::InvalidInput(format!(
        "systemd-creds {phase} failed ({status}) ({}): {excerpt}",
        program.display(),
    ))
}

// ---------------------------------------------------------------------------
// Install / verify / remove
// ---------------------------------------------------------------------------

pub struct InstallOptions<'a> {
    pub cred_name: &'a str,
    pub protection: ProtectionMode,
    pub credstore_dir: &'a Path,
    /// Optional `--not-after=` timestamp for the credential.
    pub not_after: Option<&'a str>,
    /// Verify by decrypting the ciphertext BEFORE publishing (default on at
    /// the CLI; only skip with a documented reason).
    pub verify: bool,
    pub tool: &'a SystemdCredsTool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReceipt {
    /// Published ciphertext path.
    pub path: PathBuf,
    pub cipher_len: u64,
    /// Whether decrypt-and-compare ran before publication.
    pub verified: bool,
}

/// Encrypt, verify, and atomically publish one credential.
///
/// Ordering guarantee: the existing credential (if any) is only replaced by
/// the atomic rename in the LAST step, after the new ciphertext was written
/// to a same-directory temp file and (by default) round-trip verified. Any
/// earlier failure leaves the previous credential untouched and removes the
/// temp file.
pub fn install_credential(plaintext: &[u8], opts: &InstallOptions<'_>) -> Result<InstallReceipt> {
    validate_credential_name(opts.cred_name).map_err(PasswordManagerError::InvalidInput)?;
    if plaintext.is_empty() {
        return Err(PasswordManagerError::InvalidInput(
            "refusing to provision an empty secret".to_string(),
        ));
    }
    if plaintext.len() > MAX_CREDENTIAL_BYTES {
        return Err(PasswordManagerError::InvalidInput(format!(
            "secret is {} bytes; service credentials are capped at {} bytes",
            plaintext.len(),
            MAX_CREDENTIAL_BYTES
        )));
    }

    let dir = prepare_credstore_dir(opts.credstore_dir)?;
    let final_path = dir.join(opts.cred_name);
    if let Ok(meta) = std::fs::symlink_metadata(&final_path) {
        if meta.file_type().is_symlink() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "{} is a symlink; refusing to publish through it (possible symlink swap)",
                final_path.display()
            )));
        }
    }

    // Ciphertext first (nothing is published yet).
    let ciphertext =
        opts.tool
            .encrypt(opts.cred_name, opts.protection, opts.not_after, plaintext)?;

    // Unique-per-attempt temp name, created EXCLUSIVE + NOFOLLOW. A
    // deterministic name let two concurrent installs of the same credential
    // interleave: run B truncated the temp between run A's successful
    // decrypt-verification and A's rename, publishing B's never-verified
    // ciphertext (adversarial review F1, demonstrated). Uniqueness plus
    // O_EXCL makes each run verify exactly the bytes it renames.
    let (temp_path, mut temp_file) = create_exclusive_temp(&dir, opts.cred_name)?;
    let install_result = (|| -> Result<()> {
        temp_file
            .write_all(&ciphertext)
            .and_then(|_| temp_file.sync_all())
            .map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to write credential temp file: {e}"
                ))
            })?;
        drop(temp_file);

        if opts.verify {
            let decrypted = opts.tool.decrypt_path(opts.cred_name, &temp_path)?;
            if !constant_time_equal(&decrypted, plaintext) {
                return Err(PasswordManagerError::InvalidInput(
                    "verification failed: decrypted ciphertext does not match the secret \
                     (nothing was published; the installed credential is unchanged)"
                        .to_string(),
                ));
            }
        }

        std::fs::rename(&temp_path, &final_path).map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Failed to publish credential: {e}"))
        })?;
        sync_directory(&dir);
        Ok(())
    })();

    if let Err(e) = install_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    Ok(InstallReceipt {
        cipher_len: ciphertext.len() as u64,
        path: final_path,
        verified: opts.verify,
    })
}

/// Decrypt the installed credential and compare against `plaintext` in
/// constant time. `Ok(true)` = match. A symlink at the credential path is
/// REFUSED (consistent with install/remove — review symmetry finding).
pub fn verify_installed(
    plaintext: &[u8],
    cred_name: &str,
    credstore_dir: &Path,
    tool: &SystemdCredsTool,
) -> Result<bool> {
    validate_credential_name(cred_name).map_err(PasswordManagerError::InvalidInput)?;
    let path = credstore_dir.join(cred_name);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(PasswordManagerError::InvalidInput(format!(
                "{} is a symlink; refusing to verify through it — inspect it manually",
                path.display()
            )))
        }
        Ok(meta) if meta.is_file() => {
            let decrypted = tool.decrypt_path(cred_name, &path)?;
            Ok(constant_time_equal(&decrypted, plaintext))
        }
        _ => Ok(false),
    }
}

/// Remove the installed ciphertext and return whether a file was removed.
///
/// This removes the credential going forward; it is NOT a secure erase
/// (SSD/snapshot remanence) and NOT a revocation of the secret itself —
/// rotate at the provider (see the runbook).
pub fn remove_credential(cred_name: &str, credstore_dir: &Path) -> Result<bool> {
    validate_credential_name(cred_name).map_err(PasswordManagerError::InvalidInput)?;
    let path = credstore_dir.join(cred_name);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(PasswordManagerError::InvalidInput(format!(
                "{} is a symlink; refusing to remove through it — inspect it manually",
                path.display()
            )))
        }
        Ok(_) => {
            // Best-effort truncate before unlink keeps the old inode's pages
            // from holding the full ciphertext on CoW-averse filesystems.
            if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) {
                let _ = file.set_len(0);
                let _ = file.sync_all();
            }
            std::fs::remove_file(&path).map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to remove {}: {e}",
                    path.display()
                ))
            })?;
            sync_directory(credstore_dir);
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Create the credstore directory when missing (0700) and refuse a symlink
/// planted at its path.
fn prepare_credstore_dir(dir: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(PasswordManagerError::InvalidInput(format!(
                "credential store {} is a symlink; refusing to provision through it",
                dir.display()
            )))
        }
        Ok(meta) if meta.is_dir() => {
            validate_existing_credstore_dir(dir, &meta)?;
            Ok(dir.to_path_buf())
        }
        Ok(_) => Err(PasswordManagerError::InvalidInput(format!(
            "credential store path {} exists and is not a directory",
            dir.display()
        ))),
        Err(_) => {
            crate::platform::create_private_dir(dir).map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to create credential store directory {}: {e}",
                    dir.display()
                ))
            })?;
            Ok(dir.to_path_buf())
        }
    }
}

/// Validate an existing credential store (adversarial review F4):
/// group/world-writable or foreign-owned stores are REFUSED — writability
/// is the attack surface for temp planting and final-path symlink DoS. A
/// merely group/world-readable store only earns a warning: the ciphertext
/// is not secret without the decryption key.
#[cfg(unix)]
fn validate_existing_credstore_dir(dir: &Path, meta: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let euid = unsafe { libc::geteuid() };
    let mode = meta.permissions().mode() & 0o777;
    if meta.uid() != euid {
        return Err(PasswordManagerError::InvalidInput(format!(
            "credential store {} is owned by uid {} (we are uid {euid}); refusing to \
             provision into a foreign-owned directory",
            dir.display(),
            meta.uid()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(PasswordManagerError::InvalidInput(format!(
            "credential store {} is group/world-writable (mode {mode:o}); refusing to \
             provision into it — fix with: chmod go-w {}",
            dir.display(),
            dir.display()
        )));
    }
    if mode & 0o044 != 0 {
        tracing::warn!(
            "credential store {} is group/world-readable (mode {mode:o}); the \
             ciphertext is not secret without the decryption key, but tightening \
             it is recommended: chmod go-rwx {}",
            dir.display(),
            dir.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_existing_credstore_dir(_dir: &Path, _meta: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

/// Same-directory temp file with a random suffix, created O_EXCL (never
/// clobbering, never following a symlink at the chosen name) and born 0600.
/// Uniqueness is what closes the concurrent-install race (adversarial review
/// F1): each run verifies exactly the bytes it renames.
fn create_exclusive_temp(dir: &Path, cred_name: &str) -> Result<(PathBuf, std::fs::File)> {
    use rand::RngCore;
    use std::io::ErrorKind;
    let mut suffix = [0u8; 4];
    for _ in 0..16 {
        rand::thread_rng().fill_bytes(&mut suffix);
        let candidate = dir.join(format!(".{cred_name}.{}.tmp", hex::encode(suffix)));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW: the random name is unguessable, but never write
            // through a symlink should one exist (defense in depth).
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "Failed to create credential temp file in {}: {e}",
                    dir.display()
                )))
            }
        }
    }
    Err(PasswordManagerError::InvalidInput(
        "could not find a free temp name in the credential store after 16 attempts".to_string(),
    ))
}

/// Validate (and create when missing) the credential store directory without
/// provisioning anything. The CLI calls this BEFORE resolving the secret so a
/// doomed run fails fast without consuming an audited broker fetch.
pub fn preflight_credstore_dir(dir: &Path) -> Result<()> {
    prepare_credstore_dir(dir).map(|_| ())
}

/// Length is compared first only because ciphertext size is already public
/// on disk; the byte comparison itself is constant-time (`subtle`).
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(unix)]
fn sync_directory(dir: &Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_dir: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Synthetic secret used by every test — never a real credential.
    const SYNTHETIC_SECRET: &[u8] = b"synthetic-test-secret-3f9a-not-real";

    /// Write an executable fake `systemd-creds` into a temp dir and return
    /// (tool, dir). Modes:
    /// - "ok": encrypt = base64(stdin), decrypt = base64 -d <file>
    /// - "fail-encrypt": encrypt exits 1 with a stderr message
    /// - "tamper": encrypt ok, decrypt returns garbage (verify must catch)
    /// - "spy": like "ok", but also appends its argv to argv.log next to
    ///   itself (proves the plaintext never rides in argv)
    fn fake_tool(mode: &str) -> (SystemdCredsTool, TempDir) {
        let dir = TempDir::new().unwrap();
        let script = dir.path().join("systemd-creds");
        let body = match mode {
            "fail-encrypt" => {
                "#!/bin/sh\n[ \"$1\" = encrypt ] && { echo 'mock: unavailable key' >&2; exit 1; }\nexit 0\n"
            }
            "tamper" => {
                "#!/bin/sh\ncase \"$1\" in encrypt) base64 ;; decrypt) echo bm90LXRoZS1zZWNyZXQ= ;; *) exit 2 ;; esac\n"
            }
            "spy" => {
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/argv.log\"\nenv | grep '^SENTINELPASS_' >> \"$(dirname \"$0\")/env.log\" || true\ncase \"$1\" in\n  encrypt) base64 ;;\n  decrypt) base64 -d < \"$3\" ;;\nesac\n"
            }
            "leak" => {
                "#!/bin/sh\ncase \"$1\" in\n  encrypt) cat >&2; exit 1 ;;\n  decrypt) exit 2 ;;\nesac\n"
            }
            _ => "#!/bin/sh\ncase \"$1\" in\n  encrypt) base64 ;;\n  decrypt) base64 -d < \"$3\" ;;\nesac\n",
        };
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tool = SystemdCredsTool::new(&script);
        (tool, dir)
    }

    fn credstore() -> TempDir {
        let dir = TempDir::new().unwrap();
        // tempdirs can be 0755; the store must be owner-only as in production
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn install<'a>(
        tool: &'a SystemdCredsTool,
        dir: &'a Path,
        verify: bool,
    ) -> Result<InstallReceipt> {
        install_credential(
            SYNTHETIC_SECRET,
            &InstallOptions {
                cred_name: "sandhi.provider.apikey",
                protection: ProtectionMode::HostKey,
                credstore_dir: dir,
                not_after: None,
                verify,
                tool,
            },
        )
    }

    #[test]
    fn installs_verified_credential_owner_only() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        let receipt = install(&tool, store.path(), true).unwrap();

        assert!(receipt.verified);
        assert_eq!(receipt.path, store.path().join("sandhi.provider.apikey"));
        assert!(receipt.path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = receipt.path.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // No temp file remains.
        assert!(!store.path().join(".sandhi.provider.apikey.tmp").exists());
    }

    // Scope note: with the fake tool this is a PLAINTEXT-AT-REST guard (the
    // fake "ciphertext" is base64) — it proves the pipeline never writes the
    // resolved secret to disk, not anything about real encryption.
    #[test]
    fn ciphertext_at_rest_is_not_the_plaintext() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        let receipt = install(&tool, store.path(), true).unwrap();
        let at_rest = std::fs::read(&receipt.path).unwrap();
        assert!(!at_rest
            .windows(SYNTHETIC_SECRET.len())
            .any(|w| w == SYNTHETIC_SECRET));
    }

    #[test]
    fn plaintext_never_appears_in_tool_argv() {
        let (tool, tool_dir) = fake_tool("spy");
        let store = credstore();
        install(&tool, store.path(), true).unwrap();
        let argv_log = std::fs::read_to_string(tool_dir.path().join("argv.log")).unwrap();
        let secret = String::from_utf8_lossy(SYNTHETIC_SECRET);
        assert!(
            !argv_log.contains(secret.as_ref()),
            "plaintext leaked into systemd-creds argv"
        );
        assert!(argv_log.contains("--with-key=host"));
        assert!(argv_log.contains("--name=sandhi.provider.apikey"));
    }

    #[test]
    fn failed_encrypt_leaves_existing_credential_untouched() {
        let (good, _good_dir) = fake_tool("ok");
        let store = credstore();
        install(&good, store.path(), true).unwrap();
        let before = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();

        let (bad, _bad_dir) = fake_tool("fail-encrypt");
        let err = install(&bad, store.path(), true).unwrap_err();
        assert!(
            err.to_string().contains("mock: unavailable key"),
            "unexpected error from the failing tool: {err}"
        );

        let after = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();
        assert_eq!(
            before, after,
            "failed run must not damage installed credential"
        );
        assert!(!store.path().join(".sandhi.provider.apikey.tmp").exists());
    }

    #[test]
    fn verification_mismatch_blocks_publication() {
        let (tampered, _tamper_dir) = fake_tool("tamper");
        let store = credstore();
        // Pre-existing good credential from a healthy tool.
        let (good, _good_dir) = fake_tool("ok");
        install(&good, store.path(), true).unwrap();
        let before = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();

        let err = install(&tampered, store.path(), true).unwrap_err();
        assert!(err.to_string().contains("verification failed"));

        let after = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();
        assert_eq!(before, after);
        assert!(!store.path().join(".sandhi.provider.apikey.tmp").exists());
    }

    #[test]
    fn rotation_replaces_content_atomically() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        let first = install(&tool, store.path(), true).unwrap();
        let first_bytes = std::fs::read(&first.path).unwrap();

        // Same secret: bytes stable, nothing left behind.
        let _second = install(&tool, store.path(), true).unwrap();
        let second_bytes = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();
        assert_eq!(first_bytes, second_bytes);
        assert!(store.path().read_dir().unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));

        // DIFFERENT secret (proxy review finding 3): the on-disk bytes must
        // actually change and the new value must verify while the old fails.
        let rotated = "rotated-synthetic-secret-4b7c";
        install_credential(
            rotated.as_bytes(),
            &InstallOptions {
                cred_name: "sandhi.provider.apikey",
                protection: ProtectionMode::HostKey,
                credstore_dir: store.path(),
                not_after: None,
                verify: true,
                tool: &tool,
            },
        )
        .unwrap();
        let third_bytes = std::fs::read(store.path().join("sandhi.provider.apikey")).unwrap();
        assert_ne!(second_bytes, third_bytes, "rotation must replace content");
        assert!(verify_installed(
            rotated.as_bytes(),
            "sandhi.provider.apikey",
            store.path(),
            &tool
        )
        .unwrap());
        assert!(!verify_installed(
            SYNTHETIC_SECRET,
            "sandhi.provider.apikey",
            store.path(),
            &tool
        )
        .unwrap());
    }

    /// Adversarial review F1 regression: two overlapping installs of the same
    /// credential must never publish unverified or torn content. With
    /// unique-per-attempt temp files both runs succeed independently and the
    /// final file is exactly one run's verified ciphertext.
    #[test]
    fn concurrent_installs_never_publish_unverified_content() {
        use std::sync::Arc;
        let (tool, _tool_dir) = fake_tool("ok");
        let tool = Arc::new(tool);
        let store = Arc::new(credstore());
        let secret_a = b"concurrent-secret-A-1111".to_vec();
        let secret_b = b"concurrent-secret-B-2222".to_vec();

        let mut joins = Vec::new();
        for secret in [secret_a.clone(), secret_b.clone()] {
            let tool = Arc::clone(&tool);
            let store = Arc::clone(&store);
            joins.push(std::thread::spawn(move || {
                install_credential(
                    &secret,
                    &InstallOptions {
                        cred_name: "sandhi.provider.apikey",
                        protection: ProtectionMode::HostKey,
                        credstore_dir: store.path(),
                        not_after: None,
                        verify: true,
                        tool: &tool,
                    },
                )
            }));
        }
        for join in joins {
            join.join().expect("install thread panicked").unwrap();
        }

        // The published ciphertext decrypts to exactly one of the two inputs.
        let match_a =
            verify_installed(&secret_a, "sandhi.provider.apikey", store.path(), &tool).unwrap();
        let match_b =
            verify_installed(&secret_b, "sandhi.provider.apikey", store.path(), &tool).unwrap();
        assert!(
            match_a ^ match_b,
            "final credential must decrypt to exactly one installed value"
        );
        // No temp litter from either run.
        assert!(store.path().read_dir().unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
    }

    /// Adversarial review F3: a replaced/hostile tool must not see the grant
    /// token (or any SENTINELPASS_* state) in its environment.
    #[test]
    fn child_environment_is_scrubbed_of_sentinelpass_state() {
        let (tool, tool_dir) = fake_tool("spy");
        let store = credstore();
        std::env::set_var("SENTINELPASS_CLIENT_TOKEN", "synthetic-token-do-not-leak");
        let result = install(&tool, store.path(), true);
        std::env::remove_var("SENTINELPASS_CLIENT_TOKEN");
        result.unwrap();

        let env_log = tool_dir.path().join("env.log");
        let leaked = if env_log.exists() {
            std::fs::read_to_string(&env_log).unwrap()
        } else {
            String::new()
        };
        assert!(
            !leaked.contains("synthetic-token-do-not-leak"),
            "grant token leaked into tool environment"
        );
    }

    /// Adversarial review F3: a tool echoing the payload to stderr must not
    /// turn our error output into a leak channel.
    #[test]
    fn encrypt_error_redacts_the_plaintext_from_stderr() {
        let (tool, _tool_dir) = fake_tool("leak");
        let store = credstore();
        let err = install(&tool, store.path(), true).unwrap_err();
        let rendered = err.to_string();
        let secret = String::from_utf8_lossy(SYNTHETIC_SECRET).to_string();
        assert!(
            !rendered.contains(&secret),
            "stderr excerpt leaked the secret"
        );
        assert!(rendered.contains("[redacted]"));
    }

    /// Verification round N3: a secret that is itself a substring of the
    /// "[redacted]" marker must not survive in the rendered error.
    #[test]
    fn redaction_suppresses_stderr_when_secret_is_a_marker_substring() {
        let (tool, _tool_dir) = fake_tool("leak");
        let store = credstore();
        let err = install_credential(
            b"act",
            &InstallOptions {
                cred_name: "tiny.secret",
                protection: ProtectionMode::HostKey,
                credstore_dir: store.path(),
                not_after: None,
                verify: true,
                tool: &tool,
            },
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            !rendered.contains("act"),
            "marker-substring secret survived: {rendered}"
        );
        assert!(rendered.contains("[stderr suppressed]"));
    }

    /// Adversarial review F4: group/world-writable stores are refused;
    /// world-readable ones are accepted (ciphertext is not secret).
    #[test]
    fn refuses_group_writable_credstore() {
        use std::os::unix::fs::PermissionsExt;
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = install(&tool, store.path(), true).unwrap_err();
        assert!(err.to_string().contains("group/world-writable"));
    }

    #[test]
    fn accepts_world_readable_credstore() {
        use std::os::unix::fs::PermissionsExt;
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        install(&tool, store.path(), true).unwrap();
    }

    #[test]
    fn verify_installed_matches_and_mismatches() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        install(&tool, store.path(), true).unwrap();
        assert!(verify_installed(
            SYNTHETIC_SECRET,
            "sandhi.provider.apikey",
            store.path(),
            &tool
        )
        .unwrap());
        assert!(!verify_installed(
            b"other-value",
            "sandhi.provider.apikey",
            store.path(),
            &tool
        )
        .unwrap());
        assert!(
            !verify_installed(SYNTHETIC_SECRET, "absent.credential", store.path(), &tool).unwrap()
        );
    }

    #[test]
    fn removes_installed_credential() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        install(&tool, store.path(), true).unwrap();
        assert!(remove_credential("sandhi.provider.apikey", store.path()).unwrap());
        assert!(!store.path().join("sandhi.provider.apikey").exists());
        assert!(!remove_credential("sandhi.provider.apikey", store.path()).unwrap());
    }

    #[test]
    fn refuses_credential_directory_symlink() {
        let (tool, _tool_dir) = fake_tool("ok");
        let real = credstore();
        let link_parent = TempDir::new().unwrap();
        let link = link_parent.path().join("credstore-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(real.path(), &link).unwrap();

        let err = install(&tool, &link, true);
        assert!(err.is_err(), "symlinked credstore must be refused");
    }

    #[test]
    fn refuses_final_path_symlink() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        let target_parent = TempDir::new().unwrap();
        let outside = target_parent.path().join("outside-file");
        std::fs::write(&outside, b"planted").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, store.path().join("sandhi.provider.apikey")).unwrap();

        let err = install(&tool, store.path(), true).unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert_eq!(std::fs::read(&outside).unwrap(), b"planted");
    }

    #[test]
    fn validates_credential_names() {
        assert!(validate_credential_name("sandhi.provider.apikey").is_ok());
        assert!(validate_credential_name("A9._-").is_ok());
        for bad in [
            "",
            ".",
            "..",
            "/etc/passwd",
            "a/b",
            ".hidden",
            "has space",
            "täin",
            &"x".repeat(97),
        ] {
            assert!(
                validate_credential_name(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn refuses_empty_and_oversized_secrets() {
        let (tool, _tool_dir) = fake_tool("ok");
        let store = credstore();
        let err = install_credential(
            b"",
            &InstallOptions {
                cred_name: "empty.secret",
                protection: ProtectionMode::HostKey,
                credstore_dir: store.path(),
                not_after: None,
                verify: true,
                tool: &tool,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));

        let big = Zeroizing::new(vec![b'x'; MAX_CREDENTIAL_BYTES + 1]);
        let err = install_credential(
            &big,
            &InstallOptions {
                cred_name: "big.secret",
                protection: ProtectionMode::HostKey,
                credstore_dir: store.path(),
                not_after: None,
                verify: true,
                tool: &tool,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("capped"));
    }

    #[test]
    fn manifest_round_trips_and_persists_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        let mut manifest = ServiceCredentialManifest::default();
        manifest.upsert(ServiceCredentialRecord {
            cred_name: "sandhi.provider.apikey".into(),
            client_id: "myautomation".into(),
            domain: "sandhi:provider:apikey".into(),
            field: ExternalSecretField::Password,
            protection: ProtectionMode::HostKey,
            credstore_dir: "/etc/credstore.encrypted".into(),
            installed_at: Utc::now(),
            cipher_len: 172,
            not_after: None,
        });
        manifest.save_to_path(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = path.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(dir.path().read_dir().unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));

        let loaded = ServiceCredentialManifest::load_from_path(&path).unwrap();
        assert_eq!(loaded, manifest);
        assert!(loaded.find("sandhi.provider.apikey").is_some());

        let mut editable = loaded;
        let removed = editable.remove("sandhi.provider.apikey").unwrap();
        assert_eq!(removed.cred_name, "sandhi.provider.apikey");
        assert!(editable.records.is_empty());
        assert!(editable.remove("nope").is_none());
    }

    #[test]
    fn manifest_refuses_symlink_write_through() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, "{}").unwrap();
        let link = dir.path().join(MANIFEST_FILE);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = ServiceCredentialManifest::default()
            .save_to_path(&link)
            .unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
    }

    #[test]
    fn default_credstore_dir_is_linux_only() {
        if cfg!(target_os = "linux") {
            assert_eq!(
                default_credstore_dir().as_deref(),
                Some(Path::new(DEFAULT_SYSTEM_CREDSTORE_DIR))
            );
        } else {
            assert_eq!(default_credstore_dir(), None);
        }
    }
}
