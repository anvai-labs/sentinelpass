//! Epoch high-water sidecar, format v3 (ADR-004 rev 4-5, WBS-301 + WBS-302;
//! hardened across four adversarial review rounds).
//!
//! The vault database's `key_epoch` and key material are attacker-writable
//! storage: an attacker (or an unlucky restore) can roll the whole file back
//! to a self-consistent earlier state, or surgically rewind just the wrapped
//! key material while holding the epoch constant — either way a revoked
//! master password unlocks again. This sidecar is a monotonic epoch high-water
//! mark **plus a digest of the durable key material**, stored OUTSIDE the
//! vault database in an owner-only file beside it and checked at every open.
//!
//! Format v3 (line-based):
//! ```text
//! sentinelpass-epoch-hwm/3
//! <vault_uuid>
//! <epoch>
//! <hex sha256 of length-prefixed (kdf_params, wrapped_dek, dek_nonce,
//!              slot_registry_mac) + epoch>
//! ```
//!
//! Semantics (normative):
//! - Vault epoch == sidecar epoch AND material digest matches → current.
//! - Vault epoch == sidecar epoch + 1 → a rotation that committed but whose
//!   sidecar follow crashed (the only legitimate lag — every open heals the
//!   sidecar and an open must precede any further rotation): adopt, write
//!   the new epoch + digest.
//! - Vault epoch < sidecar epoch → suspected rollback: REFUSED.
//! - Vault epoch > sidecar epoch + 1 → unexplained jump (tampering,
//!   corruption, or an unhandled import): REFUSED, not followed — following
//!   arbitrary jumps would let a DB-writable attacker ratchet the mark
//!   irreversibly and brick future rotations.
//! - Digest mismatch at equal epoch → material rewind with the epoch pinned:
//!   REFUSED (the surgical-rewind attack on revoked passwords).
//! - Sidecar for a different vault UUID → mismatch: REFUSED.
//! - Absent or unparseable sidecar → trust-on-first-use: mint from the
//!   current vault state and warn visibly (also the new-machine /
//!   ADR-008 bundle-restore path; deleting is strictly easier than corrupting
//!   for an attacker, so refusing on corruption would only add bit-rot DoS).
//!
//! Note on pre-auth disclosure: callers run this check before password
//! verification (a cheap refusal ahead of expensive KDF work), so its errors
//! reveal the vault's rotation generation to an unauthenticated same-UID
//! caller. Same-UID adversaries are a declared non-goal (ADR-003 rev 3); the
//! epochs in the error are kept because legitimate users need them to act.
//!
//! Honest boundary: the sidecar is not DEK-bound. An attacker with write
//! access to BOTH the database and the vault directory can forge or delete it
//! and re-enter the TOFU path. It is defense-in-depth that makes an attack
//! require coordinated tampering across two artifacts plus surviving a
//! visible warning — not a tamper-proof control. A supervised
//! (reauthenticate + acknowledge) restore override arrives with WBS-417;
//! until then, an intentional older restore re-bases by deleting the sidecar
//! file named in the refusal messages.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{DatabaseError, PasswordManagerError, Result};

/// Magic + format version of the sidecar file.
/// Format v3: the material digest now includes the slot-registry MAC
/// (WBS-302 composition rule). Sidecars written under /2 semantics
/// (pre-registry, never released) fail the magic check and re-mint via
/// trust-on-first-use with a visible warning.
const MAGIC: &str = "sentinelpass-epoch-hwm/3";

/// Derive the sidecar path for a vault database (`<vault>.epoch`).
pub fn sidecar_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_os_string();
    s.push(".epoch");
    PathBuf::from(s)
}

/// SHA-256 over the durable key-material columns plus the epoch — computed
/// from the STORED bytes (not re-serialized structs, which would diverge for
/// legacy blob shapes). Binds the sidecar to the exact wrap it protects.
pub fn material_digest(conn: &rusqlite::Connection) -> Result<[u8; 32]> {
    /// Raw authority row: kdf/wrap/nonce blobs, registry MAC, epoch.
    type AuthorityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, i64);
    let row: AuthorityRow = conn
        .query_row(
            "SELECT kdf_params, wrapped_dek, dek_nonce, slot_registry_mac, COALESCE(key_epoch, 1)
             FROM db_metadata WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(DatabaseError::Sqlite)?;
    Ok(digest_of(
        &row.0,
        &row.1,
        &row.2,
        row.3.as_deref().unwrap_or(&[]),
        row.4,
    ))
}

/// The digest core over raw stored bytes. `biometric_ref` is deliberately
/// EXCLUDED: the keychain entry is the authority for that path (a restored
/// ref gates an empty slot once disable clears the entry loudly), and
/// anchoring a column that legitimately toggles at constant epoch would
/// false-refuse every biometric toggle at the next open (round-4 finding).
/// Every consumer — the DB reader above and the single-snapshot loader in
/// `vault/mod.rs` — MUST go through this one function so the anchored bytes
/// can never diverge between call sites.
pub fn digest_of(
    kdf_params: &[u8],
    wrapped_dek: &[u8],
    dek_nonce: &[u8],
    registry_mac: &[u8],
    key_epoch: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for blob in [kdf_params, wrapped_dek, dek_nonce, registry_mac] {
        hasher.update((blob.len() as u64).to_le_bytes());
        hasher.update(blob);
    }
    hasher.update(key_epoch.to_le_bytes());
    hasher.finalize().into()
}

/// Verdict of a pre-authentication epoch check. `check` NEVER adopts new
/// material: adopting on unauthenticated evidence lets a DB-only writer
/// launder a material rewind through the one-step-lag window (verified
/// adversarially). Healing is a separate, post-authentication call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochCheck {
    /// Sidecar matches the on-disk epoch and material.
    Current,
    /// The vault is exactly one epoch ahead with different material — the
    /// crash-lag signature. NOT adopted here: the caller must authenticate
    /// the new state (epoch-AAD-verified password unlock) and then call
    /// [`adopt_heal`]. Legacy (non-epoch-bound) wraps cannot authenticate a
    /// transition and must refuse the heal instead.
    HealPending { from: i64, to: i64 },
    /// No usable sidecar existed; minted from the CURRENT vault state
    /// (records the status quo — safe pre-auth). Callers MUST surface a
    /// visible warning: revocations before this point are unenforced.
    MintedFromAbsent { epoch: i64 },
}

struct Sidecar {
    vault_uuid: String,
    epoch: i64,
    digest_hex: String,
}

fn parse(contents: &str) -> Option<Sidecar> {
    let mut lines = contents.lines();
    if lines.next()? != MAGIC {
        return None;
    }
    let vault_uuid = lines.next()?.trim().to_string();
    let epoch: i64 = lines.next()?.trim().parse().ok()?;
    let digest_hex = lines.next()?.trim().to_lowercase();
    if vault_uuid.is_empty()
        || digest_hex.len() != 64
        || !digest_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    Some(Sidecar {
        vault_uuid,
        epoch,
        digest_hex,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write via a randomly-named temp file + fsync + rename: a concurrent
/// reader never observes a torn sidecar, and a directory-write attacker
/// cannot pre-plant a symlink at a guessable temp path for us to truncate.
fn write(path: &Path, vault_uuid: &str, epoch: i64, digest: &[u8; 32]) -> Result<()> {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let tmp = {
        let mut s = path.as_os_str().to_os_string();
        s.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
        PathBuf::from(s)
    };
    let write_result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        writeln!(file, "{MAGIC}")?;
        writeln!(file, "{vault_uuid}")?;
        writeln!(file, "{epoch}")?;
        writeln!(file, "{}", hex(digest))?;
        file.sync_all()
    })();
    if let Err(e) = write_result {
        // Never leak the randomly-named temp file (round-4 finding).
        let _ = fs::remove_file(&tmp);
        return Err(PasswordManagerError::Io(std::io::Error::other(format!(
            "epoch sidecar write failed: {e}"
        ))));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        PasswordManagerError::Io(std::io::Error::other(format!(
            "epoch sidecar rename failed: {e}"
        )))
    })
}

fn refusal(path: &Path, what: &str) -> PasswordManagerError {
    PasswordManagerError::InvalidInput(format!(
        "{what} To re-base rollback protection on purpose (intentional restore or \
         vault replacement), delete the sidecar file: {}",
        path.display()
    ))
}

/// Read-only peek at a parseable sidecar's (vault_uuid, epoch). Returns
/// None when absent/unparseable (callers decide what that means for them).
pub fn peek(path: &Path) -> Option<(String, i64)> {
    let sidecar = fs::read_to_string(path).ok().and_then(|c| parse(&c))?;
    Some((sidecar.vault_uuid, sidecar.epoch))
}

/// Check the vault's on-disk epoch and key material against the sidecar.
/// Fails closed on rollback, unexplained jumps, material rewind, and vault
/// mismatch. The ONLY write this performs pre-authentication is the TOFU
/// mint, which records the CURRENT (status-quo) state and is therefore
/// protection-neutral. One-step-lag healing is deferred to the caller
/// (authenticate first, then [`adopt_heal`]).
pub fn check(
    path: &Path,
    vault_uuid: &str,
    db_epoch: i64,
    digest: &[u8; 32],
) -> Result<EpochCheck> {
    let existing = fs::read_to_string(path).ok().and_then(|c| parse(&c));

    let Some(sidecar) = existing else {
        // Absent or unparseable: trust-on-first-use, with a visible warning —
        // revocations from before this point are not enforced.
        warn!(
            vault_uuid = vault_uuid,
            epoch = db_epoch,
            "Epoch high-water sidecar missing or unreadable — minting from current vault \
             state (trust-on-first-use). Revocations recorded before this point are NOT \
             enforced; if you did not expect this, stop and investigate."
        );
        write(path, vault_uuid, db_epoch, digest)?;
        return Ok(EpochCheck::MintedFromAbsent { epoch: db_epoch });
    };

    if sidecar.vault_uuid != vault_uuid {
        return Err(refusal(
            path,
            &format!(
                "epoch sidecar belongs to a different vault (sidecar vault {}); refusing \
                 to reset rollback protection by sidecar swap.",
                sidecar.vault_uuid
            ),
        ));
    }

    match db_epoch.cmp(&sidecar.epoch) {
        std::cmp::Ordering::Less => Err(PasswordManagerError::EpochRollback {
            on_disk: db_epoch,
            high_water: sidecar.epoch,
        }),
        std::cmp::Ordering::Greater => {
            // The only legitimate lag is exactly one (a rotation whose sidecar
            // follow crashed; every open heals the sidecar and an open must
            // precede any further rotation). Anything larger is tampering,
            // corruption, or an import that forgot to rebase — refuse.
            if db_epoch > sidecar.epoch.saturating_add(1) {
                return Err(refusal(
                    path,
                    &format!(
                        "vault epoch jumped from {} to {} — expected at most +1; \
                         suspected tampering, corruption, or an unhandled import.",
                        sidecar.epoch, db_epoch
                    ),
                ));
            }
            // Deferred: adoption happens only after the caller authenticates
            // the new state (post-authentication epoch-AAD unlock).
            Ok(EpochCheck::HealPending {
                from: sidecar.epoch,
                to: db_epoch,
            })
        }
        std::cmp::Ordering::Equal => {
            if sidecar.digest_hex == hex(digest) {
                Ok(EpochCheck::Current)
            } else {
                // Same epoch, different key material: someone rewound the
                // wrapped key (and its KDF parameters) while pinning the
                // epoch — the surgical-rewind attack on revoked passwords.
                Err(refusal(
                    path,
                    "vault key material does not match the high-water record at the \
                     same epoch — suspected material rollback (a revoked password \
                     would unlock this state).",
                ))
            }
        }
    }
}

/// Adopt a pending one-step heal AFTER the new state has been authenticated
/// (an epoch-AAD-verified password unlock of the on-disk wrap). Refuses to
/// move anything but the exact pending transition, so a caller compromise
/// cannot repurpose it as a general write.
pub fn adopt_heal(
    path: &Path,
    vault_uuid: &str,
    from: i64,
    to: i64,
    digest: &[u8; 32],
) -> Result<()> {
    let sidecar = fs::read_to_string(path)
        .ok()
        .and_then(|c| parse(&c))
        .ok_or_else(|| {
            PasswordManagerError::InvalidInput(
                "epoch sidecar vanished before the pending heal could be adopted".to_string(),
            )
        })?;
    // Idempotent for concurrent adopters (round-4 finding): a second open
    // that authenticated the same transition finds the sidecar already at
    // `to` — that is success, not a mismatch.
    if sidecar.vault_uuid == vault_uuid && sidecar.epoch == to && sidecar.digest_hex == hex(digest)
    {
        return Ok(());
    }
    if sidecar.vault_uuid != vault_uuid || sidecar.epoch != from || to != from + 1 {
        return Err(PasswordManagerError::InvalidInput(format!(
            "refusing to adopt a heal that does not match the pending transition \
             (sidecar epoch {}, pending {from} -> {to})",
            sidecar.epoch
        )));
    }
    write(path, vault_uuid, to, digest)
}

/// Advance the high-water mark after a durable epoch change (rotation,
/// recovery), binding the new material digest. Only ever moves forward.
pub fn bump(path: &Path, vault_uuid: &str, new_epoch: i64, digest: &[u8; 32]) -> Result<()> {
    if let Some(sidecar) = fs::read_to_string(path).ok().and_then(|c| parse(&c)) {
        if sidecar.vault_uuid != vault_uuid {
            return Err(refusal(
                path,
                &format!(
                    "epoch sidecar belongs to a different vault (sidecar vault {}); \
                     refusing to bump.",
                    sidecar.vault_uuid
                ),
            ));
        }
        if new_epoch < sidecar.epoch {
            return Err(PasswordManagerError::EpochRollback {
                on_disk: new_epoch,
                high_water: sidecar.epoch,
            });
        }
    }
    write(path, vault_uuid, new_epoch, digest)
}

/// Unconditionally (re)base the sidecar for a deliberate identity adoption:
/// `create()` on a verified-fresh path, or pair-join importing a bootstrap
/// (the joining vault deliberately adopts the origin's epoch and material).
pub fn rebase(path: &Path, vault_uuid: &str, epoch: i64, digest: &[u8; 32]) -> Result<()> {
    write(path, vault_uuid, epoch, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sp-epoch-{}-{}",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn digest_a() -> [u8; 32] {
        [0x11u8; 32]
    }

    fn digest_b() -> [u8; 32] {
        [0x22u8; 32]
    }

    #[test]
    fn absent_sidecar_mints_with_tofu_then_reads_current() {
        let dir = tmp_dir("absent");
        let path = dir.join("vault.db.epoch");

        match check(&path, "uuid-a", 3, &digest_a()).unwrap() {
            EpochCheck::MintedFromAbsent { epoch } => assert_eq!(epoch, 3),
            other => panic!("expected TOFU mint, got {other:?}"),
        }
        assert!(path.exists());
        assert_eq!(
            check(&path, "uuid-a", 3, &digest_a()).unwrap(),
            EpochCheck::Current
        );
    }

    #[test]
    fn one_step_lag_is_pending_until_authenticated_adoption() {
        // A rotation that committed but crashed before its sidecar follow:
        // exactly +1 with new material is PENDING pre-auth (no write), and
        // adopted only via the explicit post-authentication call.
        let dir = tmp_dir("lag");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 2, &digest_a()).unwrap();

        // Pre-auth: the lag is visible but NOT adopted (the file still
        // records epoch 2) — unauthenticated evidence must not move the
        // anchor (adversarial-review bypass fix).
        match check(&path, "uuid-a", 3, &digest_b()).unwrap() {
            EpochCheck::HealPending { from, to } => assert_eq!((from, to), (2, 3)),
            other => panic!("expected pending heal, got {other:?}"),
        }
        assert_eq!(
            check(&path, "uuid-a", 2, &digest_a()).unwrap(),
            EpochCheck::Current
        );

        // Post-auth adoption writes the transition...
        adopt_heal(&path, "uuid-a", 2, 3, &digest_b()).unwrap();
        // ...the new material is now the recorded one...
        assert_eq!(
            check(&path, "uuid-a", 3, &digest_b()).unwrap(),
            EpochCheck::Current
        );
        // ...and the OLD material at the same epoch is refused.
        let err = check(&path, "uuid-a", 3, &digest_a()).unwrap_err();
        match err {
            PasswordManagerError::InvalidInput(msg) => {
                assert!(msg.contains("key material"), "got: {msg}");
            }
            other => panic!("expected material-rewind refusal, got {other:?}"),
        }

        // Adoption refuses anything that is not the exact pending transition.
        let err = adopt_heal(&path, "uuid-a", 3, 9, &digest_a()).unwrap_err();
        assert!(err.to_string().contains("pending transition"));
    }

    #[test]
    fn rolled_back_epoch_is_refused() {
        let dir = tmp_dir("rollback");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 7, &digest_a()).unwrap();

        let err = check(&path, "uuid-a", 4, &digest_a()).unwrap_err();
        match err {
            PasswordManagerError::EpochRollback {
                on_disk,
                high_water,
            } => {
                assert_eq!((on_disk, high_water), (4, 7));
            }
            other => panic!("expected EpochRollback, got {other:?}"),
        }
        // The sidecar is unchanged by the refusal.
        assert_eq!(
            check(&path, "uuid-a", 7, &digest_a()).unwrap(),
            EpochCheck::Current
        );
    }

    #[test]
    fn unexplained_epoch_jump_is_refused_not_followed() {
        let dir = tmp_dir("ratchet");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 5, &digest_a()).unwrap();

        let err = check(&path, "uuid-a", 9_999_999, &digest_a()).unwrap_err();
        match err {
            PasswordManagerError::InvalidInput(msg) => {
                assert!(msg.contains("at most +1"), "got: {msg}");
            }
            other => panic!("expected jump-refusal, got {other:?}"),
        }
        // +1 remains the legitimate lag: pending (adopted post-auth).
        match check(&path, "uuid-a", 6, &digest_a()).unwrap() {
            EpochCheck::HealPending { from, to } => assert_eq!((from, to), (5, 6)),
            other => panic!("expected pending heal, got {other:?}"),
        }
    }

    #[test]
    fn sidecar_from_a_different_vault_is_refused() {
        let dir = tmp_dir("swap");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 5, &digest_a()).unwrap();

        let err = check(&path, "uuid-b", 5, &digest_a()).unwrap_err();
        match err {
            PasswordManagerError::InvalidInput(msg) => {
                assert!(msg.contains("different vault"), "got: {msg}");
            }
            other => panic!("expected vault-mismatch error, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_sidecar_is_treated_as_absent_not_fatal() {
        let dir = tmp_dir("corrupt");
        let path = dir.join("vault.db.epoch");
        fs::write(&path, "garbage that does not parse").unwrap();

        match check(&path, "uuid-a", 2, &digest_a()).unwrap() {
            EpochCheck::MintedFromAbsent { epoch } => assert_eq!(epoch, 2),
            other => panic!("expected TOFU re-mint on corruption, got {other:?}"),
        }
    }

    #[test]
    fn refusal_messages_name_the_sidecar_path() {
        let dir = tmp_dir("discoverable");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 5, &digest_a()).unwrap();

        let err = check(&path, "uuid-a", 5, &digest_b()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(path.display().to_string().as_str()),
            "refusal must tell the user where the sidecar is: {msg}"
        );
    }

    #[test]
    fn bump_moves_forward_and_refuses_regression() {
        let dir = tmp_dir("bump");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 1, &digest_a()).unwrap();

        bump(&path, "uuid-a", 2, &digest_b()).unwrap();
        assert_eq!(
            check(&path, "uuid-a", 2, &digest_b()).unwrap(),
            EpochCheck::Current
        );

        let err = bump(&path, "uuid-a", 1, &digest_b()).unwrap_err();
        assert!(matches!(err, PasswordManagerError::EpochRollback { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_file_is_owner_only_and_no_temp_left_behind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perms");
        let path = dir.join("vault.db.epoch");
        check(&path, "uuid-a", 1, &digest_a()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "sidecar must be owner-only (0600)");

        // Random temp names must never linger after a successful write.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp sidecar files must not linger");
    }
}
