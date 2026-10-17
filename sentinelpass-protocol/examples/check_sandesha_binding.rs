//! Nonshipping KC-03A public-metadata conformance, not a production adapter.
use sentinelpass_protocol::custody::{decimal, CustodyScope, Purpose};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, &'static str>;
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or("string")
}
fn keys(v: &Value, expected: &[&str]) -> Result<()> {
    let map = v.as_object().ok_or("object")?;
    if map.len() != expected.len() || expected.iter().any(|k| !map.contains_key(*k)) {
        return Err("fields");
    }
    Ok(())
}
fn hex(s: &str, length: usize, upper: bool) -> bool {
    s.len() == length
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || if upper {
                    (b'A'..=b'F').contains(&b)
                } else {
                    (b'a'..=b'f').contains(&b)
                }
        })
}
#[derive(Serialize)]
struct Owner<'a> {
    issuer: &'a str,
    subject: &'a str,
    mailbox: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Header<'a> {
    version: u64,
    purpose: &'a str,
    owner: Owner<'a>,
    epoch: u64,
    key_id: &'a str,
    certificate_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailReference<'a> {
    header: Header<'a>,
    envelope_sha256: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageReference<'a> {
    key_id: &'a str,
    epoch: u64,
    sha256: &'a str,
}
fn json(v: &impl Serialize) -> Result<String> {
    serde_json::to_string(v).map_err(|_| "json")
}

fn binding(v: &Value) -> Result<(String, String)> {
    keys(
        v,
        &[
            "scope",
            "journalId",
            "profile",
            "keyEpoch",
            "reference",
            "primaryFingerprint",
            "encryptionFingerprint",
        ],
    )?;
    let scope: CustodyScope = serde_json::from_value(v["scope"].clone()).map_err(|_| "scope")?;
    if scope.namespace != "sandesha" {
        return Err("namespace");
    }
    let journal = string(v, "journalId")?;
    let profile = string(v, "profile")?;
    let epoch_text = string(v, "keyEpoch")?;
    let epoch = decimal(epoch_text).map_err(|_| "epoch")?;
    if epoch > 9_007_199_254_740_991 || !hex(journal, 32, false) {
        return Err("bounds");
    }
    let raw = string(v, "reference")?;
    if raw.len() > 12288 {
        return Err("reference bounds");
    }
    let r: Value = serde_json::from_str(raw).map_err(|_| "reference json")?;
    let primary = string(v, "primaryFingerprint")?;
    let encryption = string(v, "encryptionFingerprint")?;
    let canonical = match scope.purpose {
        Purpose::MailRecovery => {
            keys(&r, &["header", "envelopeSha256"])?;
            let h = &r["header"];
            let version = h["version"].as_u64().ok_or("version")?;
            let (expected_profile, fingerprint_size) = match version {
                1 => {
                    keys(
                        h,
                        &[
                            "version",
                            "purpose",
                            "owner",
                            "epoch",
                            "keyId",
                            "certificateSha256",
                        ],
                    )?;
                    ("openpgp-v4-ecc", 40)
                }
                2 => {
                    keys(
                        h,
                        &[
                            "version",
                            "purpose",
                            "owner",
                            "epoch",
                            "keyId",
                            "certificateSha256",
                            "profile",
                        ],
                    )?;
                    if string(h, "profile")? != "openpgp-v6-25519" {
                        return Err("profile");
                    }
                    ("openpgp-v6-25519", 64)
                }
                _ => return Err("version"),
            };
            let o = &h["owner"];
            keys(o, &["issuer", "subject", "mailbox"])?;
            if string(o, "issuer")? != scope.issuer
                || string(o, "subject")? != scope.subject
                || string(o, "mailbox")? != scope.mailbox_id
                || h["epoch"].as_u64() != Some(epoch)
                || string(h, "purpose")? != "sandesha-mail-key"
                || profile != expected_profile
                || !hex(primary, fingerprint_size, true)
                || !hex(encryption, fingerprint_size, true)
            {
                return Err("mail binding");
            }
            let id = string(h, "keyId")?;
            if id.len() != 22
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || !matches!(id.as_bytes()[21], b'A' | b'Q' | b'g' | b'w')
            {
                return Err("key id");
            }
            let certificate = string(h, "certificateSha256")?;
            let envelope = string(&r, "envelopeSha256")?;
            if !hex(certificate, 64, false) || !hex(envelope, 64, false) {
                return Err("digest");
            }
            json(&MailReference {
                header: Header {
                    version,
                    purpose: "sandesha-mail-key",
                    owner: Owner {
                        issuer: &scope.issuer,
                        subject: &scope.subject,
                        mailbox: &scope.mailbox_id,
                    },
                    epoch,
                    key_id: id,
                    certificate_sha256: certificate,
                    profile: if version == 2 { Some(profile) } else { None },
                },
                envelope_sha256: envelope,
            })?
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
        }
        Purpose::StorageRecovery => {
            keys(&r, &["keyId", "epoch", "sha256"])?;
            let id = string(&r, "keyId")?;
            let digest = string(&r, "sha256")?;
            if scope.subject.len() > 256
                || scope.mailbox_id.len() > 256
                || profile != "sandesha-recipient-trust-storage-v1"
                || !primary.is_empty()
                || !encryption.is_empty()
                || !hex(id, 32, false)
                || !hex(digest, 64, false)
                || r["epoch"].as_u64() != Some(epoch)
            {
                return Err("storage binding");
            }
            json(&StorageReference {
                key_id: id,
                epoch,
                sha256: digest,
            })?
        }
    };
    if canonical != raw {
        return Err("canonical reference");
    }
    let preimage = json(&[
        "sandesha.personal-custody.binding.v1",
        "sandesha",
        &scope.issuer,
        &scope.subject,
        &scope.mailbox_id,
        scope.purpose.as_str(),
        journal,
        profile,
        epoch_text,
        raw,
        primary,
        encryption,
    ])?;
    if preimage.len() > 16384 {
        return Err("preimage bounds");
    }
    let hash = format!("{:x}", Sha256::digest(preimage.as_bytes()));
    Ok((preimage, hash))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let vectors: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/sandesha-custody-binding-v1.json"
    ))?;
    let valid = vectors["valid"].as_array().ok_or("valid vectors")?;
    let invalid = vectors["invalid"].as_array().ok_or("invalid vectors")?;
    for vector in valid {
        let (preimage, hash) = binding(&vector["input"])?;
        if Some(preimage.as_str()) != vector["preimage"].as_str()
            || Some(hash.as_str()) != vector["sha256"].as_str()
        {
            return Err("valid vector mismatch".into());
        }
    }
    for vector in invalid {
        if binding(&vector["input"]).is_ok() {
            return Err("invalid vector accepted".into());
        }
    }
    println!(
        "Rust binding conformance: {} valid, {} refused; no runtime authority",
        valid.len(),
        invalid.len()
    );
    Ok(())
}
