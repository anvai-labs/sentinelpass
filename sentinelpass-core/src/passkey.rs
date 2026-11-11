//! Passkey reference metadata (design-gated Phase 1)
//!
//! Implements the metadata-only passkey scope defined in
//! `docs/PASSKEY_PRODUCT_DESIGN.md`: SentinelPass stores *references* to
//! platform passkeys (RP ID, account label, platform, hints) so users can
//! find, audit, and launch the correct platform passkey. Passkey private
//! keys are NEVER stored here — `metadata_only` is a structural marker the
//! parser enforces, and `is_retrievable_secret()` returns `false` for
//! [`CredentialType::PasskeyReference`], keeping these entries out of every
//! retrievable-secret path (get-secret, export, sync of secret payloads).
//!
//! The JSON reference format is stable: the Tauri UI reference panel and
//! already-created vault entries parse this exact shape. Only additive
//! fields may be introduced (with `#[serde(default)]`).

use crate::{CredentialType, Entry, PasswordManagerError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Reference-JSON schema version marker stored alongside the metadata.
const REFERENCE_KIND: &str = "passkey_reference";

/// Typed view of a `passkey_reference` entry's locator payload.
///
/// This is metadata only — it identifies an external/platform credential and
/// MUST NOT contain private key material. See `docs/PASSKEY_PRODUCT_DESIGN.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyReferenceMetadata {
    /// WebAuthn relying party ID, for example `example.com`
    pub relying_party_id: String,
    /// User-facing account label, often username or email
    pub account_label: String,
    /// Source platform, for example `icloud_keychain`, `windows_hello`,
    /// `android`, or `security_key`
    #[serde(default = "default_platform", deserialize_with = "platform_or_default")]
    pub platform: String,
    /// Optional display-safe credential identifier hint or fingerprint
    #[serde(default)]
    pub credential_id_hint: Option<String>,
    /// Optional expected sync source, for example `icloud_keychain`
    #[serde(default)]
    pub sync_source: Option<String>,
}

fn default_platform() -> String {
    "unknown".to_string()
}

/// Accept explicit JSON `null` for `platform` (written by the legacy CLI
/// builder when the field was absent) and fall back to `"unknown"`.
fn platform_or_default<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(default_platform))
}

impl PasskeyReferenceMetadata {
    /// Render the canonical reference JSON stored in the entry secret field.
    ///
    /// The payload carries structural markers (`kind`, `metadata_only`) that
    /// [`Self::from_reference_json`] enforces on parse, so a private key or
    /// any non-reference payload can never be mistaken for metadata.
    pub fn to_reference_json(&self) -> Result<Zeroizing<String>> {
        let json = serde_json::to_string(&serde_json::json!({
            "kind": REFERENCE_KIND,
            "relying_party_id": self.relying_party_id,
            "account_label": self.account_label,
            "platform": self.platform,
            "credential_id_hint": self.credential_id_hint,
            "sync_source": self.sync_source,
            "metadata_only": true,
        }))
        .map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "Failed to render passkey reference metadata: {}",
                e
            ))
        })?;
        Ok(Zeroizing::new(json))
    }

    /// Parse and validate a reference payload from an entry secret field.
    ///
    /// Rejects anything that is not a metadata-only passkey reference —
    /// including well-formed JSON that lacks the `metadata_only: true` and
    /// `kind: "passkey_reference"` markers.
    pub fn from_reference_json(secret: &str) -> Result<Self> {
        let parsed: serde_json::Value = serde_json::from_str(secret).map_err(|_| {
            PasswordManagerError::InvalidInput(
                "Entry secret is not a valid passkey reference payload".to_string(),
            )
        })?;

        let ok = parsed.get("kind").and_then(|v| v.as_str()) == Some(REFERENCE_KIND)
            && parsed.get("metadata_only").and_then(|v| v.as_bool()) == Some(true);
        if !ok {
            return Err(PasswordManagerError::InvalidInput(
                "Entry secret is not a metadata-only passkey reference".to_string(),
            ));
        }

        let metadata: Self = serde_json::from_value(parsed).map_err(|e| {
            PasswordManagerError::InvalidInput(format!(
                "Passkey reference metadata is malformed: {}",
                e
            ))
        })?;
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<()> {
        if self.relying_party_id.trim().is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Passkey reference requires a relying party ID".to_string(),
            ));
        }
        if self.account_label.trim().is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Passkey reference requires an account label".to_string(),
            ));
        }
        if self.platform.trim().is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Passkey reference requires a platform".to_string(),
            ));
        }
        Ok(())
    }

    /// Build a typed metadata record, validating required fields.
    pub fn new(
        relying_party_id: &str,
        account_label: &str,
        platform: &str,
        credential_id_hint: Option<&str>,
        sync_source: Option<&str>,
    ) -> Result<Self> {
        let metadata = Self {
            relying_party_id: relying_party_id.trim().to_string(),
            account_label: account_label.trim().to_string(),
            platform: platform.trim().to_string(),
            credential_id_hint: credential_id_hint.map(|s| s.trim().to_string()),
            sync_source: sync_source.map(|s| s.trim().to_string()),
        };
        metadata.validate()?;
        Ok(metadata)
    }
}

/// Build a `passkey_reference` vault entry from typed metadata.
///
/// The reference JSON is stored in the secret field as a locator — never a
/// private key — and the RP ID doubles as the URL so `launch`-style flows
/// (Phase 2) have a target.
pub fn build_passkey_reference_entry(
    metadata: &PasskeyReferenceMetadata,
    notes: Option<&str>,
    favorite: bool,
) -> Result<Entry> {
    let reference = metadata.to_reference_json()?;
    let now = chrono::Utc::now();
    Ok(Entry {
        entry_id: None,
        title: format!("Passkey reference: {}", metadata.relying_party_id),
        username: metadata.account_label.clone(),
        password: reference,
        url: Some(metadata.relying_party_id.clone()),
        notes: notes
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty()),
        credential_type: CredentialType::PasskeyReference,
        created_at: now,
        modified_at: now,
        favorite,
    })
}

/// Parse the typed metadata out of a passkey-reference entry.
///
/// Returns an error for entries whose secret field is not a valid
/// metadata-only reference (corrupted or foreign payload).
pub fn parse_passkey_reference_entry(entry: &Entry) -> Result<PasskeyReferenceMetadata> {
    if entry.credential_type != CredentialType::PasskeyReference {
        return Err(PasswordManagerError::InvalidInput(
            "Entry is not a passkey reference".to_string(),
        ));
    }
    PasskeyReferenceMetadata::from_reference_json(&entry.password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PasskeyReferenceMetadata {
        PasskeyReferenceMetadata::new(
            "example.com",
            "alice@example.com",
            "icloud_keychain",
            Some("cred-hint-123"),
            Some("icloud_keychain"),
        )
        .expect("valid metadata")
    }

    #[test]
    fn builds_and_round_trips_reference_entry() {
        let entry =
            build_passkey_reference_entry(&sample(), Some("  work account  "), true).unwrap();
        assert_eq!(entry.credential_type, CredentialType::PasskeyReference);
        assert_eq!(entry.title, "Passkey reference: example.com");
        assert_eq!(entry.username, "alice@example.com");
        assert_eq!(entry.url.as_deref(), Some("example.com"));
        assert_eq!(entry.notes.as_deref(), Some("work account"));
        assert!(entry.favorite);

        let parsed = parse_passkey_reference_entry(&entry).unwrap();
        assert_eq!(parsed, sample());
    }

    #[test]
    fn reference_json_carries_structural_markers() {
        let json = sample().to_reference_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "passkey_reference");
        assert_eq!(v["metadata_only"], true);
    }

    #[test]
    fn rejects_non_reference_payloads() {
        // A private-key-looking payload must never parse as metadata.
        for payload in [
            "{}",
            r#"{"kind":"passkey_reference","metadata_only":false,"relying_party_id":"x.com","account_label":"a","platform":"p"}"#,
            r#"{"kind":"private_key","metadata_only":true,"relying_party_id":"x.com","account_label":"a","platform":"p"}"#,
            "not json at all",
            r#"{"kind":"passkey_reference","metadata_only":true}"#,
        ] {
            assert!(
                PasskeyReferenceMetadata::from_reference_json(payload).is_err(),
                "payload must be rejected: {payload}"
            );
        }
    }

    #[test]
    fn rejects_blank_required_fields() {
        assert!(PasskeyReferenceMetadata::new("", "a", "p", None, None).is_err());
        assert!(PasskeyReferenceMetadata::new("x.com", "  ", "p", None, None).is_err());
        assert!(PasskeyReferenceMetadata::new("x.com", "a", "", None, None).is_err());
    }

    #[test]
    fn parses_entries_created_by_the_legacy_cli_shape() {
        // Byte-compatible with the JSON the pre-existing `passkey add` wrote.
        let legacy = r#"{"kind":"passkey_reference","relying_party_id":"example.com","account_label":"alice@example.com","platform":null,"credential_id_hint":null,"sync_source":null,"metadata_only":true}"#;
        let parsed = PasskeyReferenceMetadata::from_reference_json(legacy).unwrap();
        assert_eq!(parsed.relying_party_id, "example.com");
        assert_eq!(parsed.platform, "unknown");
    }

    #[test]
    fn non_passkey_entries_are_refused() {
        let mut entry = build_passkey_reference_entry(&sample(), None, false).unwrap();
        entry.credential_type = CredentialType::Password;
        assert!(parse_passkey_reference_entry(&entry).is_err());
    }
}
