//! Recovery key generation and encoding (WBS-310 / ADR-004 rev 4-5).
//!
//! The recovery key is 256 bits of machine-generated entropy — the raw AES
//! key-wrap input for the recovery slot (no KDF: the wrap policy is by key
//! ORIGIN, and machine-generated keys of at least 128 recorded bits wrap
//! raw; human-typed material would require Argon2id and is not supported).
//!
//! Printable form: Crockford-style base32 (digits + letters minus I L O U —
//! no ambiguous glyphs), 52 symbols carrying the 256-bit body (last 4 bits
//! are zero padding) plus a 2-symbol CRC-10 checksum computed over the raw
//! bytes, grouped in sixes with dashes:
//!
//! ```text
//! XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
//! ```
//!
//! The checksum is load-bearing for WBS-311's verification step: CRC-10
//! detects every error burst of at most 10 bits, and a single base32 symbol
//! substitution alters at most 5 contiguous bits — so every single-character
//! transcription error is caught at parse time (exhaustively tested below).
//! It is NOT a security control (an attacker forging a key can compute the
//! checksum); the wrap's GCM tag is the security boundary.
//!
//! The display string IS the key material. Handlers must show it once,
//! never log it, and drop it promptly.

use zeroize::Zeroizing;

use crate::{PasswordManagerError, Result};

/// Body length: 256 bits of entropy.
pub const RECOVERY_KEY_BYTES: usize = 32;
/// Symbols carrying the body: ceil(256 / 5) = 52 (last 4 bits are padding).
pub const BODY_SYMBOLS: usize = 52;
/// Checksum symbols: CRC-10 → 10 bits → exactly 2 base32 symbols.
pub const CHECKSUM_SYMBOLS: usize = 2;
/// Total symbols before grouping (54 = 9 × 6, so sixes group exactly).
pub const TOTAL_SYMBOLS: usize = BODY_SYMBOLS + CHECKSUM_SYMBOLS;

/// Crockford base32 alphabet — digits plus letters, minus I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// CRC-10/ATM polynomial (x^10 + x^4 + x + 1), MSB-first, init 0, no
/// reflection, no final XOR — the standard frame-check sequence.
const CRC10_POLY: u16 = 0x233;

fn crc10(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 2;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x400 != 0 {
                crc ^= CRC10_POLY;
            }
        }
    }
    crc & 0x3FF
}

/// A generated recovery key. Holds the raw 256-bit entropy (zeroized on
/// drop); the display form is derived on demand.
pub struct RecoveryKey {
    bytes: Zeroizing<[u8; RECOVERY_KEY_BYTES]>,
}

fn symbol_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => upper_value(c),
        b'a'..=b'z' => upper_value(c.to_ascii_uppercase()),
        // Crockford decode leniency: O reads as 0, I/L read as 1 (the
        // encoder never emits them, but humans transcribe them).
        _ => None,
    }
}

fn upper_value(c: u8) -> Option<u8> {
    match c {
        b'O' => Some(0),
        b'I' | b'L' => Some(1),
        _ => ALPHABET.iter().position(|&a| a == c).map(|i| i as u8),
    }
}

impl RecoveryKey {
    /// Generate a fresh 256-bit recovery key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut bytes = Zeroizing::new([0u8; RECOVERY_KEY_BYTES]);
        rand::thread_rng().fill_bytes(bytes.as_mut_slice());
        Ok(Self { bytes })
    }

    /// Build from exactly 32 raw bytes (test seam; production keys come
    /// from [`generate`] or [`parse_recovery_key`]).
    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The raw wrap key (AES-256). Zeroized with the struct.
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_BYTES] {
        &self.bytes
    }

    /// The canonical display form: 9 groups of 6 Crockford symbols.
    /// This string IS the secret — show once, never log.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let mut symbols = Vec::with_capacity(TOTAL_SYMBOLS);

        // Body: 5 bits MSB-first per symbol over 32 bytes (256 bits); the
        // final symbol's low 4 bits are zero padding. Two adjacent bytes
        // form the window; the wanted 5 bits sit at window offset `off`,
        // i.e. shift = 16 - 5 - off (always ≥ 4).
        for i in 0..BODY_SYMBOLS {
            let bit = i * 5;
            let byte = bit / 8;
            let off = bit % 8;
            let window: u16 = ((self.bytes[byte] as u16) << 8)
                | self.bytes.get(byte + 1).copied().unwrap_or(0) as u16;
            let value = ((window >> (11 - off)) & 0x1F) as u8;
            symbols.push(ALPHABET[value as usize]);
        }

        // Checksum: CRC-10 over the raw bytes, 2 symbols (10 bits).
        let crc = crc10(self.bytes.as_slice());
        symbols.push(ALPHABET[((crc >> 5) & 0x1F) as usize]);
        symbols.push(ALPHABET[(crc & 0x1F) as usize]);

        let mut out = String::with_capacity(TOTAL_SYMBOLS + 8);
        for (i, sym) in symbols.iter().enumerate() {
            if i > 0 && i % 6 == 0 {
                out.push('-');
            }
            out.push(*sym as char);
        }
        Zeroizing::new(out)
    }
}

/// Parse and validate a recovery key from its display (or ungrouped) form.
/// Case-insensitive; dashes and inner whitespace are stripped; O/I/L are
/// decoded per Crockford leniency. Rejects wrong length, non-alphabet
/// characters (including U), padding-bit corruption, and ANY checksum
/// mismatch — which includes every single-character substitution.
pub fn parse_recovery_key(input: &str) -> Result<RecoveryKey> {
    let normalized: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'-')
        .collect();

    if normalized.len() != TOTAL_SYMBOLS {
        return Err(PasswordManagerError::InvalidInput(format!(
            "recovery key must be {TOTAL_SYMBOLS} characters (plus optional grouping), \
             got {}",
            normalized.len()
        )));
    }

    let mut values = [0u8; TOTAL_SYMBOLS];
    for (i, &c) in normalized.iter().enumerate() {
        values[i] = symbol_value(c).ok_or_else(|| {
            PasswordManagerError::InvalidInput(format!(
                "recovery key contains invalid character {:?} at position {}",
                c as char,
                i + 1
            ))
        })?;
    }

    // Reconstruct the 32 body bytes from 52 × 5 bits. 52 × 5 = 260 bits:
    // the first 256 are the key; the FINAL symbol's low 4 bits are padding
    // and live past the last byte — checked on the symbol, not the byte.
    if values[BODY_SYMBOLS - 1] & 0x0F != 0 {
        return Err(PasswordManagerError::InvalidInput(
            "recovery key is malformed (padding bits set) — re-check the characters".to_string(),
        ));
    }
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    let mut bitpos: usize = 0;
    for &v in &values[..BODY_SYMBOLS] {
        for shift in (1..=5).rev() {
            if bitpos >= RECOVERY_KEY_BYTES * 8 {
                break; // padding bits — already validated on the symbol
            }
            let bit = (v >> (shift - 1)) & 1;
            if bit == 1 {
                bytes[bitpos / 8] |= 1 << (7 - (bitpos % 8));
            }
            bitpos += 1;
        }
    }

    // Checksum: CRC-10 over the reconstructed bytes vs the last 2 symbols.
    let expected = crc10(&bytes);
    let provided = ((values[BODY_SYMBOLS] as u16) << 5) | values[BODY_SYMBOLS + 1] as u16;
    if expected != provided {
        return Err(PasswordManagerError::InvalidInput(
            "recovery key checksum mismatch — at least one character is wrong; \
             re-check the key against what was displayed"
                .to_string(),
        ));
    }

    Ok(RecoveryKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_their_display_form() {
        for _ in 0..50 {
            let key = RecoveryKey::generate().unwrap();
            let display = key.to_display_string();
            let parsed = parse_recovery_key(&display).expect("own display form must parse");
            assert_eq!(parsed.as_bytes(), key.as_bytes());
        }
    }

    #[test]
    fn parse_is_case_insensitive_and_tolerates_grouping_variants() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display_string();
        // lowercase, no dashes, spaces instead
        let lower = display.to_lowercase();
        assert_eq!(
            parse_recovery_key(&lower).unwrap().as_bytes(),
            key.as_bytes()
        );
        let ungrouped: String = display.chars().filter(|c| *c != '-').collect();
        assert_eq!(
            parse_recovery_key(&ungrouped).unwrap().as_bytes(),
            key.as_bytes()
        );
        let spaced = display.replace('-', "  ");
        assert_eq!(
            parse_recovery_key(&spaced).unwrap().as_bytes(),
            key.as_bytes()
        );
    }

    #[test]
    fn display_form_is_nine_groups_of_six_canonical_symbols() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display_string();
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 9, "9 groups of 6: {}", *display);
        for g in &groups {
            assert_eq!(g.len(), 6);
            assert!(g.bytes().all(|b| ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn generation_produces_distinct_full_entropy_keys() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let key = RecoveryKey::generate().unwrap();
            assert!(seen.insert(key.as_bytes().to_vec()), "duplicate key");
        }
    }

    /// The load-bearing property for onboarding verification: EVERY
    /// single-character substitution at EVERY position must be rejected.
    #[test]
    fn every_single_character_substitution_is_rejected() {
        for seed in 0..3 {
            let mut raw = [0u8; RECOVERY_KEY_BYTES];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut raw);
            raw[31] &= 0xF0; // keep padding bits zero
            let _ = seed;
            let key = RecoveryKey::from_bytes(raw);
            let display = key.to_display_string();
            let chars: Vec<char> = display.chars().filter(|c| *c != '-').collect();

            for pos in 0..TOTAL_SYMBOLS {
                let original = chars[pos];
                for &alt in ALPHABET.iter() {
                    let alt = alt as char;
                    if alt == original {
                        continue;
                    }
                    let mut mutated = chars.clone();
                    mutated[pos] = alt;
                    let joined: String = mutated.into_iter().collect();
                    assert!(
                        parse_recovery_key(&joined).is_err(),
                        "substitution {original}->{alt} at position {pos} must be rejected"
                    );
                }
            }
        }
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let key = RecoveryKey::generate().unwrap();
        let ungrouped: String = key
            .to_display_string()
            .chars()
            .filter(|c| *c != '-')
            .collect();

        // Too short / too long (even with a self-consistent checksum on the
        // short one — a 40-char body simply cannot carry 256 bits).
        assert!(parse_recovery_key(&ungrouped[..40]).is_err());
        assert!(parse_recovery_key(&format!("{ungrouped}0")).is_err());
        assert!(parse_recovery_key("").is_err());

        // Non-alphabet characters (U is deliberately excluded from Crockford;
        // punctuation and symbols are invalid).
        for bad in [
            'U', 'u', '#', '@', '!', 'l', /* accepted as 1 — see below */
        ] {
            if bad == 'l' {
                continue; // Crockford leniency: I/L decode as 1 — valid input
            }
            let mut corrupted: Vec<char> = ungrouped.chars().collect();
            corrupted[3] = bad;
            let joined: String = corrupted.into_iter().collect();
            assert!(
                parse_recovery_key(&joined).is_err(),
                "{bad:?} must be rejected"
            );
        }

        // Transposition (two adjacent chars swapped) — caught by the CRC
        // whenever the swapped symbols differ (always here, since we pick
        // a position where neighbors differ).
        let chars: Vec<char> = ungrouped.chars().collect();
        let mut swap = chars.clone();
        let mut i = 0;
        while i + 1 < swap.len() && swap[i] == swap[i + 1] {
            i += 1;
        }
        assert!(
            i + 1 < swap.len(),
            "test assumption: adjacent distinct pair"
        );
        swap.swap(i, i + 1);
        let joined: String = swap.into_iter().collect();
        assert!(
            parse_recovery_key(&joined).is_err(),
            "adjacent transposition must be caught by the checksum"
        );
    }

    /// A fixed-vector check: the same bytes must always produce the same
    /// display form (forward-stability for cross-device entry).
    #[test]
    fn display_form_is_deterministic_for_fixed_bytes() {
        let a = RecoveryKey::from_bytes([0xAB; RECOVERY_KEY_BYTES]);
        let b = RecoveryKey::from_bytes([0xAB; RECOVERY_KEY_BYTES]);
        assert_eq!(*a.to_display_string(), *b.to_display_string());

        // And the all-zero key's first symbols are identifiable padding.
        let zero = RecoveryKey::from_bytes([0u8; RECOVERY_KEY_BYTES]);
        let display = zero.to_display_string();
        assert!(display.starts_with("000000-"), "zero key: {}", *display);
        let parsed = parse_recovery_key(&display).unwrap();
        assert_eq!(parsed.as_bytes(), &[0u8; RECOVERY_KEY_BYTES]);
    }

    #[test]
    fn crockford_leniency_decodes_o_and_i_and_l() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display_string();
        // Rewrite every 0 as O and every 1 as I in a copy — must still parse.
        let homoglyph: String = display
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                other => other,
            })
            .collect();
        assert_eq!(
            parse_recovery_key(&homoglyph).unwrap().as_bytes(),
            key.as_bytes()
        );
    }
}
