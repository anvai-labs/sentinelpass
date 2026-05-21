//! TOTP (RFC 6238) support for one-time codes.

use crate::crypto::cipher::{decrypt_to_string, encrypt_string, EncryptedEntry};
use crate::{PasswordManagerError, Result};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::str::FromStr;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Supported TOTP HMAC algorithms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpAlgorithm {
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
}

impl TotpAlgorithm {
    pub fn as_db_value(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
        }
    }
}

impl std::fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpAlgorithm::Sha1 => write!(f, "sha1"),
            TotpAlgorithm::Sha256 => write!(f, "sha256"),
        }
    }
}

impl FromStr for TotpAlgorithm {
    type Err = PasswordManagerError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sha1" => Ok(TotpAlgorithm::Sha1),
            "sha256" => Ok(TotpAlgorithm::Sha256),
            other => Err(PasswordManagerError::InvalidInput(format!(
                "Unsupported TOTP algorithm '{}'. Use 'sha1' or 'sha256'.",
                other
            ))),
        }
    }
}

/// Runtime TOTP code response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u32,
}

/// Stored secret metadata (excluding secret material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecretMetadata {
    pub totp_id: i64,
    pub entry_id: i64,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

/// Parsed provisioning data from an `otpauth://totp/...` URI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTotpUri {
    pub secret_base32: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

/// Parse an `otpauth://totp/...` URI (commonly embedded in QR codes).
pub fn parse_otpauth_uri(uri: &str) -> Result<ParsedTotpUri> {
    let trimmed = uri.trim();
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(|| {
        PasswordManagerError::InvalidInput("TOTP URI must start with otpauth://".to_string())
    })?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP URI must start with otpauth://".to_string(),
        ));
    }

    let (kind, remainder) = rest.split_once('/').ok_or_else(|| {
        PasswordManagerError::InvalidInput("Invalid otpauth URI format".to_string())
    })?;
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(PasswordManagerError::InvalidInput(
            "Only otpauth://totp URIs are supported".to_string(),
        ));
    }

    let (label_raw, query_raw) = match remainder.split_once('?') {
        Some((label, query)) => (label, query),
        None => (remainder, ""),
    };

    let label = percent_decode(label_raw)?;
    let mut issuer_from_label = None;
    let mut account_name = None;
    if let Some((issuer, account)) = label.split_once(':') {
        let issuer = issuer.trim();
        let account = account.trim();
        if !issuer.is_empty() {
            issuer_from_label = Some(issuer.to_string());
        }
        if !account.is_empty() {
            account_name = Some(account.to_string());
        }
    } else {
        let account = label.trim();
        if !account.is_empty() {
            account_name = Some(account.to_string());
        }
    }

    let mut secret_base32 = None;
    let mut issuer_from_query = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;

    if !query_raw.is_empty() {
        for pair in query_raw.split('&').filter(|part| !part.is_empty()) {
            let (key_raw, value_raw) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key_raw)?.to_ascii_lowercase();
            let value = percent_decode(value_raw)?;

            match key.as_str() {
                "secret" if !value.trim().is_empty() => {
                    secret_base32 = Some(value);
                }
                "issuer" if !value.trim().is_empty() => {
                    issuer_from_query = Some(value);
                }
                "algorithm" if !value.trim().is_empty() => {
                    algorithm = value.parse::<TotpAlgorithm>()?;
                }
                "digits" if !value.trim().is_empty() => {
                    digits = value.parse::<u8>().map_err(|_| {
                        PasswordManagerError::InvalidInput(
                            "TOTP digits must be numeric".to_string(),
                        )
                    })?;
                }
                "period" if !value.trim().is_empty() => {
                    period = value.parse::<u32>().map_err(|_| {
                        PasswordManagerError::InvalidInput(
                            "TOTP period must be numeric".to_string(),
                        )
                    })?;
                }
                _ => {}
            }
        }
    }

    if digits != 6 && digits != 8 {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP digits must be 6 or 8".to_string(),
        ));
    }
    if period == 0 {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP period must be greater than 0".to_string(),
        ));
    }

    let secret = secret_base32.ok_or_else(|| {
        PasswordManagerError::InvalidInput("TOTP URI is missing secret parameter".to_string())
    })?;
    let secret = normalize_secret(&secret)?;

    if let (Some(label_issuer), Some(query_issuer)) = (&issuer_from_label, &issuer_from_query) {
        if !label_issuer.eq_ignore_ascii_case(query_issuer) {
            return Err(PasswordManagerError::InvalidInput(
                "Issuer in label does not match issuer query parameter".to_string(),
            ));
        }
    }

    Ok(ParsedTotpUri {
        secret_base32: secret,
        algorithm,
        digits,
        period,
        issuer: issuer_from_query.or(issuer_from_label),
        account_name,
    })
}

/// Encrypt a base32 TOTP secret with the vault DEK.
pub fn encrypt_totp_secret(
    dek: &crate::crypto::DataEncryptionKey,
    secret_base32: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let normalized = normalize_secret(secret_base32)?;
    let encrypted = encrypt_string(dek, &normalized).map_err(PasswordManagerError::Crypto)?;
    Ok((
        encrypted.ciphertext,
        encrypted.nonce.to_vec(),
        encrypted.auth_tag.to_vec(),
    ))
}

/// Decrypt a stored TOTP secret using the vault DEK.
pub fn decrypt_totp_secret(
    dek: &crate::crypto::DataEncryptionKey,
    secret_encrypted: &[u8],
    nonce: &[u8],
    auth_tag: &[u8],
) -> Result<String> {
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| PasswordManagerError::InvalidInput("Invalid TOTP nonce length".to_string()))?;
    let auth_tag_arr: [u8; 16] = auth_tag.try_into().map_err(|_| {
        PasswordManagerError::InvalidInput("Invalid TOTP auth tag length".to_string())
    })?;

    let encrypted = EncryptedEntry {
        nonce: nonce_arr,
        ciphertext: secret_encrypted.to_vec(),
        auth_tag: auth_tag_arr,
    };

    let secret = decrypt_to_string(dek, &encrypted).map_err(PasswordManagerError::Crypto)?;
    normalize_secret(&secret)
}

/// Generate a TOTP code for the given timestamp.
pub fn generate_totp_code(
    secret_base32: &str,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
    timestamp: i64,
) -> Result<String> {
    if digits != 6 && digits != 8 {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP digits must be 6 or 8".to_string(),
        ));
    }
    if period == 0 {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP period must be greater than 0".to_string(),
        ));
    }

    let secret = decode_secret(secret_base32)?;
    let counter = (timestamp.max(0) as u64) / period as u64;
    let counter_bytes = counter.to_be_bytes();

    let digest = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(&secret).map_err(|_| {
                PasswordManagerError::InvalidInput("Invalid TOTP secret".to_string())
            })?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(&secret).map_err(|_| {
                PasswordManagerError::InvalidInput("Invalid TOTP secret".to_string())
            })?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    if digest.len() < 20 {
        return Err(PasswordManagerError::InvalidInput(
            "Invalid TOTP digest length".to_string(),
        ));
    }

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    if offset + 3 >= digest.len() {
        return Err(PasswordManagerError::InvalidInput(
            "Invalid TOTP digest offset".to_string(),
        ));
    }

    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    let modulo = 10u32.pow(digits as u32);
    let code = binary % modulo;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Get remaining seconds until the next TOTP rotation.
pub fn seconds_remaining(period: u32, timestamp: i64) -> u32 {
    if period == 0 {
        return 0;
    }

    let elapsed = timestamp.rem_euclid(period as i64) as u32;
    if elapsed == 0 {
        period
    } else {
        period - elapsed
    }
}

fn normalize_secret(secret_base32: &str) -> Result<String> {
    let normalized = secret_base32
        .trim()
        .replace([' ', '-'], "")
        .to_ascii_uppercase();

    if normalized.is_empty() {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP secret cannot be empty".to_string(),
        ));
    }

    decode_secret(&normalized)?;
    Ok(normalized)
}

fn decode_secret(secret_base32: &str) -> Result<Vec<u8>> {
    let normalized = secret_base32
        .trim()
        .replace([' ', '-'], "")
        .to_ascii_uppercase();

    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|_| {
            PasswordManagerError::InvalidInput("TOTP secret must be valid base32".to_string())
        })?;

    if decoded.is_empty() {
        return Err(PasswordManagerError::InvalidInput(
            "TOTP secret cannot decode to empty bytes".to_string(),
        ));
    }

    Ok(decoded)
}

fn percent_decode(input: &str) -> Result<String> {
    fn from_hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(PasswordManagerError::InvalidInput(
                        "Invalid percent encoding in TOTP URI".to_string(),
                    ));
                }
                let hi = from_hex(bytes[i + 1]).ok_or_else(|| {
                    PasswordManagerError::InvalidInput(
                        "Invalid percent encoding in TOTP URI".to_string(),
                    )
                })?;
                let lo = from_hex(bytes[i + 2]).ok_or_else(|| {
                    PasswordManagerError::InvalidInput(
                        "Invalid percent encoding in TOTP URI".to_string(),
                    )
                })?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|_| {
        PasswordManagerError::InvalidInput("TOTP URI contains invalid UTF-8".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DataEncryptionKey;

    #[test]
    fn test_rfc_sha1_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(
            generate_totp_code(secret, TotpAlgorithm::Sha1, 8, 30, 59).unwrap(),
            "94287082"
        );
        assert_eq!(
            generate_totp_code(secret, TotpAlgorithm::Sha1, 8, 30, 1_111_111_109).unwrap(),
            "07081804"
        );
    }

    #[test]
    fn test_rfc_sha256_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        assert_eq!(
            generate_totp_code(secret, TotpAlgorithm::Sha256, 8, 30, 59).unwrap(),
            "46119246"
        );
        assert_eq!(
            generate_totp_code(secret, TotpAlgorithm::Sha256, 8, 30, 1_111_111_109).unwrap(),
            "68084774"
        );
    }

    #[test]
    fn test_encrypt_decrypt_secret_roundtrip() {
        let dek = DataEncryptionKey::new().unwrap();
        let secret = "JBSWY3DPEHPK3PXP";

        let (ciphertext, nonce, auth_tag) = encrypt_totp_secret(&dek, secret).unwrap();
        let decrypted = decrypt_totp_secret(&dek, &ciphertext, &nonce, &auth_tag).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_seconds_remaining() {
        assert_eq!(seconds_remaining(30, 59), 1);
        assert_eq!(seconds_remaining(30, 60), 30);
        assert_eq!(seconds_remaining(30, 0), 30);
    }

    #[test]
    fn test_parse_otpauth_uri_with_all_fields() {
        let parsed = parse_otpauth_uri(
            "otpauth://totp/Acme:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA256&digits=8&period=45",
        )
        .unwrap();

        assert_eq!(parsed.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 45);
        assert_eq!(parsed.issuer.as_deref(), Some("Acme"));
        assert_eq!(parsed.account_name.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn test_parse_otpauth_uri_defaults() {
        let parsed =
            parse_otpauth_uri("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP").unwrap();

        assert_eq!(parsed.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
        assert_eq!(parsed.account_name.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn test_parse_otpauth_uri_rejects_issuer_mismatch() {
        let err = parse_otpauth_uri(
            "otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Other",
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("Issuer in label does not match issuer query parameter"));
    }

    #[test]
    fn test_algorithm_as_db_value() {
        assert_eq!(TotpAlgorithm::Sha1.as_db_value(), "SHA1");
        assert_eq!(TotpAlgorithm::Sha256.as_db_value(), "SHA256");
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", TotpAlgorithm::Sha1), "sha1");
        assert_eq!(format!("{}", TotpAlgorithm::Sha256), "sha256");
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            "sha1".parse::<TotpAlgorithm>().unwrap(),
            TotpAlgorithm::Sha1
        );
        assert_eq!(
            "SHA1".parse::<TotpAlgorithm>().unwrap(),
            TotpAlgorithm::Sha1
        );
        assert_eq!(
            "sha256".parse::<TotpAlgorithm>().unwrap(),
            TotpAlgorithm::Sha256
        );
        assert_eq!(
            "SHA256".parse::<TotpAlgorithm>().unwrap(),
            TotpAlgorithm::Sha256
        );
    }

    #[test]
    fn test_algorithm_from_str_invalid() {
        let err = "sha512".parse::<TotpAlgorithm>().unwrap_err();
        assert!(err.to_string().contains("Unsupported TOTP algorithm"));
    }

    #[test]
    fn test_normalize_secret_strips_spaces_and_dashes() {
        let result = normalize_secret("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!(result, "JBSWY3DPEHPK3PXP");

        let result = normalize_secret("JBSW-Y3DP-EHPK-3PXP").unwrap();
        assert_eq!(result, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_normalize_secret_lowercases_to_upper() {
        let result = normalize_secret("jbswy3dpehpk3pxp").unwrap();
        assert_eq!(result, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_normalize_secret_empty_fails() {
        assert!(normalize_secret("").is_err());
        assert!(normalize_secret("   ").is_err());
    }

    #[test]
    fn test_decode_secret_invalid_base32() {
        assert!(decode_secret("!!!invalid!!!").is_err());
    }

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(
            percent_decode("alice%40example.com").unwrap(),
            "alice@example.com"
        );
        assert_eq!(percent_decode("a+b").unwrap(), "a b");
        assert_eq!(percent_decode("plain").unwrap(), "plain");
    }

    #[test]
    fn test_percent_decode_invalid_truncated() {
        assert!(percent_decode("hello%2").is_err());
        assert!(percent_decode("hello%").is_err());
    }

    #[test]
    fn test_percent_decode_invalid_hex() {
        assert!(percent_decode("hello%GZ").is_err());
    }

    #[test]
    fn test_generate_totp_invalid_digits() {
        let err = generate_totp_code("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 7, 30, 0);
        assert!(err.is_err());
    }

    #[test]
    fn test_generate_totp_invalid_period() {
        let err = generate_totp_code("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 0, 0);
        assert!(err.is_err());
    }

    #[test]
    fn test_generate_totp_6_digit() {
        let code = generate_totp_code("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30, 0).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_totp_8_digit() {
        let code = generate_totp_code("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha256, 8, 30, 0).unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_seconds_remaining_zero_period() {
        assert_eq!(seconds_remaining(0, 100), 0);
    }

    #[test]
    fn test_parse_otpauth_missing_secret() {
        let err = parse_otpauth_uri("otpauth://totp/Test?issuer=Acme").unwrap_err();
        assert!(err.to_string().contains("missing secret"));
    }

    #[test]
    fn test_parse_otpauth_invalid_scheme() {
        assert!(parse_otpauth_uri("https://totp/Test?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn test_parse_otpauth_hotp_rejected() {
        assert!(parse_otpauth_uri("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn test_parse_otpauth_invalid_digits() {
        let err =
            parse_otpauth_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7").unwrap_err();
        assert!(err.to_string().contains("digits must be 6 or 8"));
    }

    #[test]
    fn test_parse_otpauth_zero_period() {
        let err =
            parse_otpauth_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0").unwrap_err();
        assert!(err.to_string().contains("period must be greater than 0"));
    }

    #[test]
    fn test_parse_otpauth_no_label_split() {
        // URI with no colon in label -- account_name only, no issuer
        let parsed = parse_otpauth_uri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert!(parsed.issuer.is_none());
        assert_eq!(parsed.account_name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_parse_otpauth_issuer_from_label_only() {
        let parsed =
            parse_otpauth_uri("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(parsed.issuer.as_deref(), Some("Acme"));
        assert_eq!(parsed.account_name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_decrypt_totp_secret_wrong_nonce_length() {
        let dek = DataEncryptionKey::new().unwrap();
        let err = decrypt_totp_secret(&dek, &[0; 32], &[0; 5], &[0; 16]);
        assert!(err.is_err());
    }

    #[test]
    fn test_decrypt_totp_secret_wrong_auth_tag_length() {
        let dek = DataEncryptionKey::new().unwrap();
        let err = decrypt_totp_secret(&dek, &[0; 32], &[0; 12], &[0; 8]);
        assert!(err.is_err());
    }
}
