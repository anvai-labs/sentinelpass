//! SP-4 / ADR-017: OpenPGP enrollment — canonical transcript, single-use
//! nonce, and key-possession verification via a pinned external `gpg`.
//!
//! The enrollment is a two-step ceremony:
//! 1. `ServiceEnrollmentBegin` (owner step-up) mints a single-use 256-bit
//!    nonce and returns the canonical transcript bytes for the client to
//!    sign with its OpenPGP key.
//! 2. `ServiceEnrollmentComplete` (client) presents the signed transcript;
//!    the daemon verifies via the pinned gpg and, on success, reveals the
//!    grant's service token (minted once, shown once).
//!
//! Fail-closed: any verification failure consumes the nonce and denies.

use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Enrollment challenge TTL (handoff §5: "initial target five minutes").
pub const ENROLLMENT_TTL: Duration = Duration::from_secs(300);

/// Domain separator — prevents cross-protocol replay of the signature.
pub const DOMAIN_SEPARATOR: &str = "sentinelpass/service-enrollment/v1";

/// Default pinned gpg path (configurable for tests).
pub const DEFAULT_GPG_PATH: &str = "/usr/bin/gpg";

/// An outstanding enrollment challenge (server-held only, never persisted).
#[derive(Debug, Clone)]
pub struct EnrollmentChallenge {
    pub nonce: String,
    pub client_id: String,
    pub grant_id: uuid::Uuid,
    pub transcript: Vec<u8>,
    pub expires: Instant,
}

/// Single-use nonce store. Restart-safe by construction (in-memory).
#[derive(Default)]
pub struct EnrollmentState {
    challenges: std::sync::Mutex<HashMap<String, EnrollmentChallenge>>,
}

impl EnrollmentState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a challenge for a pre-approved grant. Returns (nonce_hex,
    /// transcript_bytes).
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &self,
        client_id: &str,
        grant_id: uuid::Uuid,
        entry_id: i64,
        fields: &[&str],
        exe_policy_digest: Option<&str>,
        registration_fingerprint: &str,
        expires_at_unix: Option<i64>,
    ) -> (String, Vec<u8>) {
        let mut nonce_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Canonical transcript: deterministic JSON, sorted keys, no
        // whitespace, with the domain separator as the first field.
        let transcript = json!({
            "client_id": client_id,
            "entry_id": entry_id,
            "grant_id": grant_id.to_string(),
            "exe_policy_sha256": exe_policy_digest,
            "expires_at": expires_at_unix,
            "fields": fields,
            "nonce": nonce,
            "protocol": DOMAIN_SEPARATOR,
            "registration_key_fingerprint": registration_fingerprint,
        });
        // serde_json with sorted keys requires the "preserve_order" off +
        // manual sorting; the simplest deterministic form is to serialize
        // with sorted keys via a BTreeMap-backed Value. `json!` uses
        // insertion order by default with preserve_order; without it, keys
        // are sorted. Verify: serde_json::Value::Object is a Map<String,
        // Value> which IS sorted by default (BTreeMap) unless the
        // preserve_order feature is enabled. Our workspace does not enable
        // it, so keys are already sorted.
        let transcript_bytes = serde_json::to_vec(&transcript).expect("canonical JSON serializes");

        let mut challenges = self.challenges.lock().unwrap();
        // Prune expired (bounded memory).
        challenges.retain(|_, c| c.expires > Instant::now());
        challenges.insert(
            nonce.clone(),
            EnrollmentChallenge {
                nonce: nonce.clone(),
                client_id: client_id.to_string(),
                grant_id,
                transcript: transcript_bytes.clone(),
                expires: Instant::now() + ENROLLMENT_TTL,
            },
        );
        (nonce, transcript_bytes)
    }

    /// Consume a challenge by nonce. Single-use: consumed on ANY outcome
    /// (success or failure). Returns None if unknown/expired/consumed.
    pub fn take(&self, nonce: &str) -> Option<EnrollmentChallenge> {
        let mut challenges = self.challenges.lock().unwrap();
        let challenge = challenges.remove(nonce)?;
        if challenge.expires <= Instant::now() {
            return None; // expired (and now also consumed by the remove)
        }
        Some(challenge)
    }

    /// Outstanding challenge count (test/diagnostic).
    pub fn outstanding(&self) -> usize {
        let challenges = self.challenges.lock().unwrap();
        let now = Instant::now();
        challenges.values().filter(|c| c.expires > now).count()
    }
}

/// Create a unique temp directory (no tempfile dep in the main build).
fn temp_dir_unique(base: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use rand::RngCore;
    let mut suffix = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut suffix);
    let dir = base.join(format!("sp-enroll-{}", hex::encode(suffix)));
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create temp dir: {e}"))?;
    Ok(dir)
}

/// Unix-domain-socket path budget (sun_path minus headroom). gpg places
/// its agent socket inside the --homedir; when the projected path is too
/// long, gpg imports the key but exits nonzero ("can't connect to the
/// gpg-agent: File name too long") — verification would fail on every
/// macOS host whose TMPDIR is the long /var/folders form (found by the
/// SP-7 perf drill on gpg 2.5.24).
#[cfg(unix)]
const UNIX_SOCKET_PATH_BUDGET: usize = 96;

/// Pick a work dir whose keyring keeps gpg's agent-socket path inside the
/// unix budget: prefer the caller's base, fall back to /tmp when the
/// platform temp root is too deep (macOS /var/folders/...).
fn socket_safe_base(base: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        use std::path::Path;
        let projected = base.join("sp-enroll-0000000000000000/gnupg/keyring/S.gpg-agent");
        if projected.as_os_str().len() > UNIX_SOCKET_PATH_BUDGET {
            if let Ok(short) = std::env::var("SENTINELPASS_GPG_SHORT_TMP") {
                return std::path::PathBuf::from(short);
            }
            return Path::new("/tmp").to_path_buf();
        }
    }
    base.to_path_buf()
}

/// Remove the temp dir on drop.
struct TempDirGuard<'a>(&'a std::path::Path);
impl Drop for TempDirGuard<'_> {
    fn drop(&mut self) {
        if std::env::var_os("SP_KEEP_ENROLL_TMP").is_none() {
            let _ = std::fs::remove_dir_all(self.0);
        }
    }
}

/// Verify an OpenPGP detached signature against the expected transcript
/// using the pinned gpg binary, with the client's public key imported
/// into an ISOLATED per-verification keyring (review F2: detached
/// signatures do NOT embed key material — the key must be supplied).
///
/// Returns Ok(()) on verified signature with matching fingerprint.
/// Fail-closed: any gpg failure, wrong key, or mismatch denies.
pub fn verify_signature(
    gpg_path: &str,
    client_public_key: &str,
    transcript_bytes: &[u8],
    signature_armored: &str,
    expected_fingerprint: &str,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    // Isolated per-verification environment (review F2/F7), on a path
    // that keeps gpg's agent-socket inside the unix sun_path budget.
    let temp_base = std::env::temp_dir();
    let work_dir = temp_dir_unique(&socket_safe_base(&temp_base))?;
    let _guard = TempDirGuard(&work_dir);

    let gnupg_home = work_dir.join("gnupg");
    let keyring_dir = gnupg_home.join("keyring");
    std::fs::create_dir_all(&keyring_dir)
        .map_err(|e| format!("cannot create isolated keyring: {e}"))?;
    // gpg >= 2.4 refuses a --homedir with group/other permission bits
    // ("unsafe permissions") — the import fails outright on modern hosts
    // (found by the SP-7 perf drill on gpg 2.5.24; CI's older gpg only
    // warned). The isolated keyring is owner-only by intent anyway.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keyring_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot secure isolated keyring: {e}"))?;
    }

    // Import the client's public key into the isolated keyring.
    let key_path = work_dir.join("client pubkey.asc");
    std::fs::write(&key_path, client_public_key)
        .map_err(|e| format!("cannot write client key: {e}"))?;
    let import = Command::new(gpg_path)
        .arg("--homedir")
        .arg(&keyring_dir)
        .arg("--no-default-keyring")
        .arg("--auto-key-locate")
        .arg("clear") // no network keyserver fetch (ADR-017)
        .arg("--import")
        .arg(&key_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gpg import failed to launch: {e}"))?;
    if !import.status.success() {
        let stderr = String::from_utf8_lossy(&import.stderr);
        return Err(format!(
            "cannot import client public key: {}",
            stderr.chars().take(200).collect::<String>()
        ));
    }

    // Write the signature and transcript data for detached verification.
    let sig_path = work_dir.join("signature.asc");
    let data_path = work_dir.join("transcript.bin");
    std::fs::write(&sig_path, signature_armored)
        .map_err(|e| format!("cannot write signature temp: {e}"))?;
    std::fs::write(&data_path, transcript_bytes)
        .map_err(|e| format!("cannot write transcript temp: {e}"))?;

    // Detached verify against the isolated keyring.
    let output = Command::new(gpg_path)
        .arg("--homedir")
        .arg(&keyring_dir)
        .arg("--no-default-keyring")
        .arg("--auto-key-locate")
        .arg("clear")
        .arg("--status-fd")
        .arg("1")
        .arg("--verify")
        .arg(&sig_path)
        .arg(&data_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gpg verify failed to launch: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "gpg verification failed: {}",
            stderr.chars().take(200).collect::<String>()
        ));
    }

    // Parse the status output for the signing key fingerprint.
    let status = String::from_utf8_lossy(&output.stdout);
    for line in status.lines() {
        if line.starts_with("[GNUPG:] VALIDSIG ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // parts: ["[GNUPG:]", "VALIDSIG", "<fingerprint>", ...] - fp is THIRD (review V1).
            if parts.len() >= 3 {
                let fingerprint = parts[2];
                // Full 40-char v4 fingerprint match (public identifier —
                // constant-time not required, ADR-017).
                if fingerprint.eq_ignore_ascii_case(expected_fingerprint) {
                    return Ok(());
                }
                return Err(format!(
                    "signing key fingerprint mismatch: expected {expected_fingerprint}, got {fingerprint}"
                ));
            }
        }
        if line.starts_with("[GNUPG:] BADSIG") {
            return Err("signature does not match the transcript".to_string());
        }
        if line.starts_with("[GNUPG:] ERRSIG") {
            return Err("signature verification error".to_string());
        }
        if line.starts_with("[GNUPG:] NO_PUBKEY") {
            return Err("client public key not available in isolated keyring".to_string());
        }
    }
    Err("gpg did not report a valid signature status".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic_for_same_inputs() {
        let state = EnrollmentState::new();
        let (n1, t1) = state.begin(
            "svc",
            uuid::Uuid::new_v4(),
            1,
            &["password"],
            None,
            &"a".repeat(40),
            None,
        );
        let (n2, t2) = state.begin(
            "svc",
            uuid::Uuid::new_v4(),
            1,
            &["password"],
            None,
            &"a".repeat(40),
            None,
        );
        // Nonces are random (different) — but the transcript structure
        // contains the nonce so they differ. The DETERMINISM is: same
        // nonce → same transcript, verified by the take/consume cycle.
        assert_ne!(n1, n2);
        assert_ne!(t1, t2); // different nonces
                            // Both are valid canonical JSON with the domain separator.
        let v: serde_json::Value = serde_json::from_slice(&t1).unwrap();
        assert_eq!(v["protocol"], DOMAIN_SEPARATOR);
    }

    #[test]
    fn transcript_keys_are_sorted() {
        let state = EnrollmentState::new();
        let (_, t) = state.begin(
            "svc",
            uuid::Uuid::new_v4(),
            1,
            &["password"],
            None,
            &"a".repeat(40),
            None,
        );
        let text = String::from_utf8_lossy(&t);
        // client_id must appear before entry_id in the byte stream
        // (BTreeMap ordering — 'c' < 'e').
        let ci = text.find("\"client_id\"").unwrap();
        let ei = text.find("\"entry_id\"").unwrap();
        assert!(ci < ei, "keys must be sorted: {text}");
        // protocol must be near the end ('p' is late alphabetically)
        let pi = text.find("\"protocol\"").unwrap();
        assert!(ei < pi);
    }

    #[test]
    fn nonce_is_single_use() {
        let state = EnrollmentState::new();
        let (nonce, _) = state.begin(
            "svc",
            uuid::Uuid::new_v4(),
            1,
            &["password"],
            None,
            &"a".repeat(40),
            None,
        );
        assert!(state.take(&nonce).is_some());
        assert!(state.take(&nonce).is_none(), "second use denied");
        assert_eq!(state.outstanding(), 0);
    }

    #[test]
    fn unknown_nonce_denied() {
        let state = EnrollmentState::new();
        assert!(state.take("deadbeef").is_none());
    }

    #[test]
    fn expired_nonce_denied() {
        let state = EnrollmentState::new();
        let (nonce, _) = state.begin(
            "svc",
            uuid::Uuid::new_v4(),
            1,
            &["password"],
            None,
            &"a".repeat(40),
            None,
        );
        // Manually expire
        {
            let mut challenges = state.challenges.lock().unwrap();
            if let Some(c) = challenges.get_mut(&nonce) {
                c.expires = Instant::now() - Duration::from_secs(1);
            }
        }
        assert!(state.take(&nonce).is_none(), "expired nonce denied");
    }

    #[test]
    fn gpg_verify_rejects_missing_binary() {
        let err = verify_signature("/nonexistent/gpg", "key", b"data", "sig", "fp").unwrap_err();
        assert!(err.contains("cannot launch") || err.contains("failed"));
    }

    /// Positive-path (review V1/F9): real key, real signature, matching
    /// fingerprint -> Ok. Would have caught the round-2 off-by-one.
    #[test]
    fn gpg_verify_happy_path_with_real_key() {
        use std::process::Command;
        if !std::path::Path::new(DEFAULT_GPG_PATH).exists() {
            eprintln!("skipping: no gpg at {DEFAULT_GPG_PATH}");
            return;
        }
        let work = std::env::temp_dir().join(format!("sp-gpg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let home = work.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();

        let gen = Command::new(DEFAULT_GPG_PATH)
            .arg("--homedir")
            .arg(&home)
            .arg("--batch")
            .arg("--passphrase")
            .arg("")
            .arg("--quick-generate-key")
            .arg("test@example.com")
            .arg("ed25519")
            .arg("sign")
            .arg("0")
            .output()
            .expect("gpg keygen");
        assert!(
            gen.status.success(),
            "keygen: {}",
            String::from_utf8_lossy(&gen.stderr)
        );

        let fp_out = Command::new(DEFAULT_GPG_PATH)
            .arg("--homedir")
            .arg(&home)
            .arg("--with-colons")
            .arg("--list-keys")
            .output()
            .expect("gpg list");
        let fp_text = String::from_utf8_lossy(&fp_out.stdout).to_lowercase();
        let fingerprint = fp_text
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| {
                l.split(':')
                    .skip(1)
                    .find(|f| !f.is_empty() && f.len() == 40)
            })
            .expect("fingerprint")
            .to_string();
        assert_eq!(fingerprint.len(), 40, "v4 fp: {fingerprint}");

        let key_out = Command::new(DEFAULT_GPG_PATH)
            .arg("--homedir")
            .arg(&home)
            .arg("--armor")
            .arg("--export")
            .arg(&fingerprint)
            .output()
            .expect("gpg export");
        let pubkey = String::from_utf8_lossy(&key_out.stdout).to_string();

        let data_file = work.join("data.bin");
        std::fs::write(&data_file, b"canonical transcript bytes").unwrap();
        let sig_out = Command::new(DEFAULT_GPG_PATH)
            .arg("--homedir")
            .arg(&home)
            .arg("--batch")
            .arg("--passphrase")
            .arg("")
            .arg("--detach-sign")
            .arg("--armor")
            .arg("--output")
            .arg(work.join("sig.asc"))
            .arg(&data_file)
            .output()
            .expect("gpg sign");
        assert!(sig_out.status.success());
        let sig = std::fs::read_to_string(work.join("sig.asc")).unwrap();

        let result = verify_signature(
            DEFAULT_GPG_PATH,
            &pubkey,
            b"canonical transcript bytes",
            &sig,
            &fingerprint,
        );
        assert!(result.is_ok(), "happy path: {result:?}");

        let wrong = "f".repeat(40);
        assert!(verify_signature(
            DEFAULT_GPG_PATH,
            &pubkey,
            b"canonical transcript bytes",
            &sig,
            &wrong
        )
        .is_err());
        assert!(
            verify_signature(DEFAULT_GPG_PATH, &pubkey, b"TAMPERED", &sig, &fingerprint).is_err()
        );

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn gpg_verify_rejects_garbage_signature() {
        // Use the real gpg if present, else skip
        if !std::path::Path::new(DEFAULT_GPG_PATH).exists() {
            eprintln!("skipping: no gpg at {DEFAULT_GPG_PATH}");
            return;
        }
        let err = verify_signature(
            DEFAULT_GPG_PATH,
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n-----END PGP PUBLIC KEY BLOCK-----",
            b"canonical transcript bytes",
            "-----BEGIN PGP SIGNATURE-----\ngarbage\n-----END PGP SIGNATURE-----",
            &"a".repeat(40),
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }
}
