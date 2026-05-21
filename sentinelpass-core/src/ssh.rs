//! SSH key storage for SentinelPass

use crate::{PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// SSH key type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SshKeyType {
    #[serde(rename = "rsa")]
    Rsa,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "ecdsa")]
    Ecdsa,
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaSha256,
    #[serde(rename = "ecdsa-sha2-nistp384")]
    EcdsaSha384,
    #[serde(rename = "ecdsa-sha2-nistp521")]
    EcdsaSha521,
}

impl std::fmt::Display for SshKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshKeyType::Rsa => write!(f, "RSA"),
            SshKeyType::Ed25519 => write!(f, "ED25519"),
            SshKeyType::Ecdsa => write!(f, "ECDSA"),
            SshKeyType::EcdsaSha256 => write!(f, "ECDSA-SHA2-NISTP256"),
            SshKeyType::EcdsaSha384 => write!(f, "ECDSA-SHA2-NISTP384"),
            SshKeyType::EcdsaSha521 => write!(f, "ECDSA-SHA2-NISTP521"),
        }
    }
}

/// SSH key entry stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub key_id: Option<i64>,
    pub name: String,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub key_size: Option<u32>,
    pub public_key: String,
    pub private_key_encrypted: Vec<u8>,
    pub nonce: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

/// Summary of an SSH key (without private key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeySummary {
    pub key_id: i64,
    pub name: String,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint: String,
}

impl SshKey {
    /// Create a new SSH key entry
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        comment: Option<String>,
        key_type: SshKeyType,
        key_size: Option<u32>,
        public_key: String,
        private_key_encrypted: Vec<u8>,
        nonce: Vec<u8>,
        auth_tag: Vec<u8>,
        fingerprint: String,
    ) -> Self {
        Self {
            key_id: None,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        }
    }
}

/// Helper functions for SSH key encryption/decryption
impl SshKey {
    /// Encrypt a private key using the vault's DEK
    pub fn encrypt_private_key(
        dek: &crate::crypto::DataEncryptionKey,
        private_key: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use crate::crypto::cipher::encrypt_entry;

        let encrypted =
            encrypt_entry(dek, private_key.as_bytes()).map_err(PasswordManagerError::Crypto)?;

        Ok((
            encrypted.ciphertext,
            encrypted.nonce.to_vec(),
            encrypted.auth_tag.to_vec(),
        ))
    }

    /// Decrypt a private key using the vault's DEK
    pub fn decrypt_private_key(
        dek: &crate::crypto::DataEncryptionKey,
        private_key_encrypted: &[u8],
        nonce: &[u8],
        auth_tag: &[u8],
    ) -> Result<String> {
        use crate::crypto::cipher::{decrypt_entry, EncryptedEntry};

        let nonce_arr: [u8; 12] = nonce
            .try_into()
            .map_err(|_| PasswordManagerError::InvalidInput("Invalid nonce length".to_string()))?;
        let auth_tag_arr: [u8; 16] = auth_tag.try_into().map_err(|_| {
            PasswordManagerError::InvalidInput("Invalid auth tag length".to_string())
        })?;

        let encrypted = EncryptedEntry {
            nonce: nonce_arr,
            ciphertext: private_key_encrypted.to_vec(),
            auth_tag: auth_tag_arr,
        };

        let decrypted = decrypt_entry(dek, &encrypted).map_err(PasswordManagerError::Crypto)?;

        String::from_utf8(decrypted).map_err(|_| {
            PasswordManagerError::InvalidInput("Invalid UTF-8 in private key".to_string())
        })
    }

    /// Create an SshKey with encrypted private key
    #[allow(clippy::too_many_arguments)]
    pub fn create_encrypted(
        dek: &crate::crypto::DataEncryptionKey,
        name: String,
        comment: Option<String>,
        key_type: SshKeyType,
        key_size: Option<u32>,
        public_key: String,
        private_key: String,
        fingerprint: String,
    ) -> Result<Self> {
        let (private_key_encrypted, nonce, auth_tag) =
            Self::encrypt_private_key(dek, &private_key)?;

        Ok(Self {
            key_id: None,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        })
    }
}

/// SSH key importer (simplified version - imports already-generated keys)
pub struct SshKeyImporter;

impl SshKeyImporter {
    /// Import a public key from a file
    pub fn import_public_key<P: AsRef<Path>>(path: P) -> Result<(String, SshKeyType)> {
        let path = path.as_ref();

        let key_data = std::fs::read_to_string(path).map_err(PasswordManagerError::Io)?;

        let line = key_data.trim();
        if !line.starts_with("ssh-") {
            return Err(PasswordManagerError::InvalidInput(
                "Not a valid SSH public key".to_string(),
            ));
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(PasswordManagerError::InvalidInput(
                "Invalid public key format".to_string(),
            ));
        }

        let key_type = Self::map_key_type_string(parts[0])?;
        let public_key = line.to_string();

        Ok((public_key, key_type))
    }

    fn map_key_type_string(key_type_str: &str) -> Result<SshKeyType> {
        match key_type_str {
            "ssh-rsa" => Ok(SshKeyType::Rsa),
            "ssh-ed25519" => Ok(SshKeyType::Ed25519),
            "ecdsa-sha2-nistp256" => Ok(SshKeyType::EcdsaSha256),
            "ecdsa-sha2-nistp384" => Ok(SshKeyType::EcdsaSha384),
            "ecdsa-sha2-nistp521" => Ok(SshKeyType::EcdsaSha521),
            _ => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported key type: {}",
                key_type_str
            ))),
        }
    }
}

/// SSH key generator (simplified - delegates to ssh-keygen)
pub struct SshKeyGenerator;

impl SshKeyGenerator {
    /// Generate a new Ed25519 key pair using ssh-keygen
    /// Returns the path to the generated private key
    pub fn generate_ed25519(name: &str, output_dir: Option<&Path>) -> Result<(String, String)> {
        use std::process::Command;

        let output_path = output_dir
            .map(|p| p.join(name))
            .unwrap_or_else(|| Path::new(name).to_path_buf());

        let private_key_path = format!("{}.ssh", output_path.display());
        let public_key_path = format!("{}.pub", output_path.display());

        // Remove existing keys if they exist
        let _ = std::fs::remove_file(&private_key_path);
        let _ = std::fs::remove_file(&public_key_path);

        // Run ssh-keygen
        let output = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&private_key_path)
            .arg("-C")
            .arg(name)
            .output()
            .map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to run ssh-keygen: {}. Is ssh-keygen installed and in PATH?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PasswordManagerError::InvalidInput(format!(
                "ssh-keygen failed: {}",
                stderr
            )));
        }

        Ok((private_key_path, public_key_path))
    }

    /// Generate a new RSA key pair using ssh-keygen
    pub fn generate_rsa(
        name: &str,
        bits: u32,
        output_dir: Option<&Path>,
    ) -> Result<(String, String)> {
        use std::process::Command;

        if bits != 2048 && bits != 3072 && bits != 4096 {
            return Err(PasswordManagerError::InvalidInput(
                "RSA key size must be 2048, 3072, or 4096 bits".to_string(),
            ));
        }

        let output_path = output_dir
            .map(|p| p.join(name))
            .unwrap_or_else(|| Path::new(name).to_path_buf());

        let private_key_path = format!("{}.ssh", output_path.display());
        let public_key_path = format!("{}.pub", output_path.display());

        // Run ssh-keygen
        let output = Command::new("ssh-keygen")
            .arg("-t")
            .arg("rsa")
            .arg("-b")
            .arg(bits.to_string())
            .arg("-f")
            .arg(&private_key_path)
            .arg("-C")
            .arg(name)
            .output()
            .map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to run ssh-keygen: {}. Is ssh-keygen installed and in PATH?",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PasswordManagerError::InvalidInput(format!(
                "ssh-keygen failed: {}",
                stderr
            )));
        }

        Ok((private_key_path, public_key_path))
    }
}

/// SSH agent client implemented via `ssh-add` command integration.
pub struct SshAgentClient;

impl SshAgentClient {
    /// Create a new SSH agent client
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    fn has_usable_ssh_add() -> bool {
        use std::process::Command;

        let output = match Command::new("ssh-add").arg("-l").output() {
            Ok(output) => output,
            Err(_) => return false,
        };

        Self::is_probe_success_exit_code(output.status.code())
    }

    fn is_probe_success_exit_code(code: Option<i32>) -> bool {
        matches!(code, Some(0) | Some(1))
    }

    fn format_failure_output(stderr: &[u8], stdout: &[u8]) -> String {
        let stderr = String::from_utf8_lossy(stderr).trim().to_string();
        if !stderr.is_empty() {
            return stderr;
        }

        let stdout = String::from_utf8_lossy(stdout).trim().to_string();
        if !stdout.is_empty() {
            return stdout;
        }

        "unknown error".to_string()
    }

    fn format_ssh_add_failure(output: &std::process::Output) -> String {
        Self::format_failure_output(&output.stderr, &output.stdout)
    }

    /// Check if SSH agent is available
    pub fn is_available(&self) -> bool {
        Self::has_usable_ssh_add()
    }

    /// Add an identity to the agent (delegates to ssh-add)
    pub fn add_identity(&self, key_path: &Path) -> Result<()> {
        use std::process::Command;

        if !self.is_available() {
            return Err(PasswordManagerError::NotFound(
                "SSH agent not available".to_string(),
            ));
        }

        if !key_path.exists() {
            return Err(PasswordManagerError::NotFound(format!(
                "SSH key file not found: {}",
                key_path.display()
            )));
        }

        let output = Command::new("ssh-add")
            .arg(key_path)
            .output()
            .map_err(|e| {
                PasswordManagerError::InvalidInput(format!("Failed to run ssh-add: {}", e))
            })?;

        if !output.status.success() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "ssh-add failed: {}",
                Self::format_ssh_add_failure(&output)
            )));
        }

        Ok(())
    }

    /// Add a private key to the agent from in-memory PEM/openssh text.
    ///
    /// This avoids writing decrypted key material to disk by piping it
    /// directly to `ssh-add -` via stdin.
    pub fn add_identity_from_pem(&self, private_key_pem: &str) -> Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        if !self.is_available() {
            return Err(PasswordManagerError::NotFound(
                "SSH agent not available".to_string(),
            ));
        }

        if private_key_pem.trim().is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Private key content cannot be empty".to_string(),
            ));
        }

        let mut child = Command::new("ssh-add")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed to run ssh-add for stdin key input: {}",
                    e
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(private_key_pem.as_bytes()).map_err(|e| {
                PasswordManagerError::InvalidInput(format!(
                    "Failed writing private key to ssh-add stdin: {}",
                    e
                ))
            })?;

            if !private_key_pem.ends_with('\n') {
                stdin.write_all(b"\n").map_err(|e| {
                    PasswordManagerError::InvalidInput(format!(
                        "Failed finalizing private key input for ssh-add: {}",
                        e
                    ))
                })?;
            }
        } else {
            return Err(PasswordManagerError::InvalidInput(
                "ssh-add stdin unavailable".to_string(),
            ));
        }

        let output = child.wait_with_output().map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "Failed waiting for ssh-add stdin process: {}",
                e
            ))
        })?;

        if !output.status.success() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "ssh-add failed: {}",
                Self::format_ssh_add_failure(&output)
            )));
        }

        Ok(())
    }

    /// Remove all identities from the agent (delegates to ssh-add -D)
    pub fn remove_all_identities(&self) -> Result<()> {
        use std::process::Command;

        if !self.is_available() {
            return Err(PasswordManagerError::NotFound(
                "SSH agent not available".to_string(),
            ));
        }

        let output = Command::new("ssh-add").arg("-D").output().map_err(|e| {
            PasswordManagerError::InvalidInput(format!("Failed to run ssh-add -D: {}", e))
        })?;

        if !output.status.success() {
            return Err(PasswordManagerError::InvalidInput(format!(
                "ssh-add -D failed: {}",
                Self::format_ssh_add_failure(&output)
            )));
        }

        Ok(())
    }
}

impl Default for SshAgentClient {
    fn default() -> Self {
        Self::new().unwrap_or(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ssh_key_type_display() {
        assert_eq!(SshKeyType::Ed25519.to_string(), "ED25519");
        assert_eq!(SshKeyType::Rsa.to_string(), "RSA");
        assert_eq!(SshKeyType::EcdsaSha256.to_string(), "ECDSA-SHA2-NISTP256");
    }

    #[test]
    fn test_ssh_agent_client_creation() {
        let client = SshAgentClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_probe_success_exit_code() {
        assert!(SshAgentClient::is_probe_success_exit_code(Some(0)));
        assert!(SshAgentClient::is_probe_success_exit_code(Some(1)));
        assert!(!SshAgentClient::is_probe_success_exit_code(Some(2)));
        assert!(!SshAgentClient::is_probe_success_exit_code(None));
    }

    #[test]
    fn test_format_ssh_add_failure_prefers_stderr() {
        assert_eq!(
            SshAgentClient::format_failure_output(b"stderr message", b"stdout message"),
            "stderr message"
        );
    }

    #[test]
    fn test_format_ssh_add_failure_falls_back_to_stdout() {
        assert_eq!(
            SshAgentClient::format_failure_output(b"", b"stdout message"),
            "stdout message"
        );
    }

    #[test]
    fn test_import_public_key_invalid_format() {
        // Test with non-existent file
        let result = SshKeyImporter::import_public_key("/nonexistent/key.pub");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_public_key_valid_format() {
        let valid_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKeyButValidFormat test@example.com";
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("test_key.pub");

        std::fs::write(&key_path, valid_key).expect("Failed to write test key");

        let result = SshKeyImporter::import_public_key(&key_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_identity_from_pem_rejects_empty() {
        let client = SshAgentClient::new().unwrap();
        let result = client.add_identity_from_pem("   ");
        assert!(result.is_err());
    }
}
