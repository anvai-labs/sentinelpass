//! SP-3 / ADR-016: Linux executable policy — resolve and hash the
//! kernel-referenced peer executable (`/proc/<pid>/exe`) for grant pins.
//!
//! Fail-closed: unavailable evidence DENIES, never degrades to token-only.
//! The digest is computed over the OPEN file (never a caller path or a
//! later `readlink`), streamed (bounded), on the blocking pool. No caching
//! (ADR-016 §5).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Outcome of an executable-policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExePolicyResult {
    /// Grant carries no pin — no requirement (SP-1 behavior).
    NotRequired,
    /// The peer's executable hash matches one of the pinned digests.
    Matched,
    /// Resolved but matches none of the pins.
    Mismatch,
    /// Evidence unavailable (non-Linux, /proc unreachable, pid absent,
    /// unreadable exe). Deny — never degrade.
    EvidenceUnavailable(String),
}

/// Hash the kernel-referenced executable for `pid`. Linux-only path;
/// returns Err on any failure (the caller maps it to
/// EvidenceUnavailable).
pub fn resolve_exe_digest(pid: u32) -> Result<String, String> {
    let path = format!("/proc/{pid}/exe");
    // Plain pathname open of the procfs magic symlink: security rests on
    // the kernel-owned numeric pid + kernel-controlled procfs, not on
    // open flags (O_NOFOLLOW would ELOOP on magic symlinks — see
    // ADR-016 §2).
    let mut file = std::fs::File::open(&path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    const MAX_EXE_BYTES: u64 = 512 * 1024 * 1024; // absurd bound; real binaries are far smaller
    use std::io::Read;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_EXE_BYTES {
            return Err(format!("executable exceeds {MAX_EXE_BYTES} bytes"));
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Enforce a grant's pin against the peer's kernel executable evidence.
pub fn check_policy(pins: &[String], pid: Option<u32>) -> ExePolicyResult {
    if pins.is_empty() {
        return ExePolicyResult::NotRequired;
    }
    let Some(pid) = pid else {
        return ExePolicyResult::EvidenceUnavailable(
            "peer pid unavailable on this platform".to_string(),
        );
    };
    match resolve_exe_digest(pid) {
        Ok(digest) => {
            let matched = pins.iter().any(|pin| {
                pin.len() == digest.len() && bool::from(pin.as_bytes().ct_eq(digest.as_bytes()))
            });
            if matched {
                ExePolicyResult::Matched
            } else {
                ExePolicyResult::Mismatch
            }
        }
        Err(reason) => ExePolicyResult::EvidenceUnavailable(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn self_exe_digest_resolves_and_matches_own_pin() {
        let pid = std::process::id();
        let digest = resolve_exe_digest(pid).expect("self /proc/<pid>/exe resolves");
        assert_eq!(digest.len(), 64, "sha256 hex");
        // The policy check with our own digest pinned must match.
        assert_eq!(
            check_policy(&[digest.clone()], Some(pid)),
            ExePolicyResult::Matched
        );
        // A wrong pin mismatches.
        assert_eq!(
            check_policy(&["0".repeat(64)], Some(pid)),
            ExePolicyResult::Mismatch
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_denies_with_evidence_unavailable() {
        assert!(matches!(
            check_policy(&["a".repeat(64)], Some(1)),
            ExePolicyResult::EvidenceUnavailable(_)
        ));
    }

    #[test]
    fn empty_pins_not_required() {
        assert_eq!(check_policy(&[], Some(1)), ExePolicyResult::NotRequired);
        assert_eq!(check_policy(&[], None), ExePolicyResult::NotRequired);
    }

    #[test]
    fn missing_pid_is_evidence_unavailable() {
        match check_policy(&["a".repeat(64)], None) {
            ExePolicyResult::EvidenceUnavailable(_) => {}
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonexistent_pid_is_evidence_unavailable() {
        // pid 0xFFFFFFFC is in the kernel-reserved range; /proc/<pid>/exe
        // will not exist.
        match check_policy(&["a".repeat(64)], Some(0xFFFF_FFFC)) {
            ExePolicyResult::EvidenceUnavailable(_) => {}
            other => panic!("expected unavailable, got {other:?}"),
        }
    }
}
