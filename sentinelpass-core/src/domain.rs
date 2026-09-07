//! Domain identity: host normalization, suffix-chain matching, and keyed
//! equality tags for encrypted domain lookups (WBS-306 / ADR-005 rev 4).
//!
//! Why this module exists: `domain_mappings.domain` (and its index) used to
//! be plaintext. WBS-306 seals the domain under the vault DEK, so the SQL
//! index can no longer answer "which mappings point at this host?" — the
//! ciphertext is not searchable. The searchable artifact is a set of KEYED
//! EQUALITY TAGS: one HMAC-SHA256 per label-chain suffix of the normalized
//! host, under a purpose-bound key derived from the DEK
//! ([`crate::crypto::keyring::derive_domain_tag_key`] — the same HKDF
//! discipline as the registry equality key, with its own info label so the
//! two tag domains never share input space).
//!
//! Semantics contract (ADR-005 rev 4): tag matching is EXACTLY today's
//! `domains_match` semantics — a query for `a.b.example.com` matches a
//! stored `example.com` and vice versa — realized as "the two hosts'
//! suffix-chain tag sets intersect". No Public Suffix List (explicitly
//! rejected in ADR-005 rev 4): the chain is every dot-suffix, including
//! `com`, so a bare parent matches its dotted children in BOTH directions.
//!
//! Leakage model (deliberate, this is the feature): tags are deterministic,
//! so the database leaks EQUALITY of label-chain suffixes across mappings —
//! that is the minimum needed for a searchable encrypted index. A storage
//! attacker without the key learns nothing else: they cannot forge a tag
//! for a chosen domain, cannot verify offline guesses (keyed HMAC), and
//! cannot relocate tags between rows (the lookup re-opens the row's sealed
//! domain envelope, whose AAD binds vault + mapping identity, and refuses
//! on disagreement — see `vault/domain_ops.rs`).

use crate::{CryptoError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of label-chain suffix tags generated for one host
/// (ADR-005 rev 4 chain cap). A host with more labels than this stores only
/// its longest `MAX_CHAIN_TAGS` chains; matches on deeper suffixes of such
/// extreme hosts are not findable via tags (documented cap, not a PSL).
pub const MAX_CHAIN_TAGS: usize = 10;

/// Bookkeeping identity of the domain-tag HKDF label currently in effect
/// ([`crate::crypto::keyring::DOMAIN_TAG_KEY_INFO`]), mirroring the
/// registry's `EQUALITY_KEY_ID`. Stored on the sweep bookkeeping row; a
/// mismatch triggers a full re-tag (key migration, never silently misread).
pub const DOMAIN_TAG_KEY_ID: i64 = 1;

/// Extract the bare hostname from a URL or hostname string.
///
/// Tries the `url` crate first (handles schemes, auth, ports, IPv6, encoding).
/// Falls back to treating the input as a bare hostname so that plain domain
/// strings like `"example.com"` still work without a scheme prefix.
pub fn normalize_host(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    // Extract the host string from a parsed URL, stripping IPv6 brackets that
    // url::Url includes in host_str() (e.g. "[::1]" → "::1").
    let extract = |url: Url| -> Option<String> {
        let h = url.host_str()?.trim_matches('.');
        let h = h
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(h);
        if h.is_empty() {
            None
        } else {
            Some(h.to_string())
        }
    };

    // Try parsing as a full URL first; only use the result if a host was found.
    // "example.com:8443" parses as scheme="example.com" with no host — skip it.
    if let Ok(url) = Url::parse(&trimmed) {
        if let Some(host) = extract(url) {
            return Some(host);
        }
    }

    // No scheme, or scheme-only parse produced no host — prepend a dummy scheme.
    if let Ok(url) = Url::parse(&format!("dummy://{}", trimmed)) {
        if let Some(host) = extract(url) {
            return Some(host);
        }
    }

    // Last resort: bare hostname. Strip stray brackets (e.g. "[]" → "") and dots.
    let host = trimmed
        .trim_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Today's autofill domain semantics: two hosts match when equal or when
/// either is a dot-suffix of the other (gitlab.com ↔ sub.gitlab.com).
pub fn domains_match(request_domain: &str, entry_url_or_domain: &str) -> bool {
    let Some(request_host) = normalize_host(request_domain) else {
        return false;
    };
    let Some(entry_host) = normalize_host(entry_url_or_domain) else {
        return false;
    };

    if request_host == entry_host {
        return true;
    }

    let request_suffix = format!(".{}", request_host);
    let entry_suffix = format!(".{}", entry_host);
    request_host.ends_with(&entry_suffix) || entry_host.ends_with(&request_suffix)
}

/// The label-chain suffixes of an ALREADY-NORMALIZED host, longest first:
/// `a.b.example.com` → `[a.b.example.com, b.example.com, example.com, com]`,
/// capped at [`MAX_CHAIN_TAGS`] entries. An empty host yields no chains.
pub fn domain_chain_suffixes(normalized_host: &str) -> Vec<String> {
    let mut chains = Vec::new();
    if normalized_host.is_empty() {
        return chains;
    }
    let labels: Vec<&str> = normalized_host.split('.').collect();
    for i in 0..labels.len() {
        if chains.len() == MAX_CHAIN_TAGS {
            break;
        }
        chains.push(labels[i..].join("."));
    }
    chains
}

/// The keyed tag set for one host: the ROOT tag (the full normalized host)
/// plus one tag per PROPER suffix chain. The root/suffix split is load
/// bearing: `domains_match(a, b)` means one host is a suffix of the other —
/// NOT that the two chain sets intersect (every `.com` host shares the
/// `com` chain; plain set intersection would match `notgitlab.com` against
/// `gitlab.com`). The correct tag-level predicate is
/// [`chain_tag_sets_match`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTags {
    /// Tag of the FULL normalized host (`chains[0]`).
    pub root: [u8; 32],
    /// Tags of the proper suffix chains (`chains[1..]`).
    pub suffixes: Vec<[u8; 32]>,
}

impl ChainTags {
    /// All tags (root first), for pre-filter binds and set comparisons.
    pub fn all(&self) -> Vec<[u8; 32]> {
        let mut all = Vec::with_capacity(self.suffixes.len() + 1);
        all.push(self.root);
        all.extend(self.suffixes.iter().copied());
        all
    }
}

/// Compute the keyed tag set for a host (normalized here): HMAC-SHA256 per
/// label-chain suffix under the DEK-derived domain-tag key.
///
/// An unnormalizable host (empty after normalization) yields `None`: the
/// row stays sealed (its envelope still opens) but carries no tags and is
/// not findable via tags — the same visibility an empty domain has today.
pub fn compute_domain_chain_tags(tag_key: &[u8], host: &str) -> Result<Option<ChainTags>> {
    let Some(normalized) = normalize_host(host) else {
        return Ok(None);
    };
    compute_chain_tags_for_normalized(tag_key, &normalized)
}

/// As [`compute_domain_chain_tags`], for a host that is already normalized
/// (write paths normalize once and reuse the result).
pub fn compute_chain_tags_for_normalized(
    tag_key: &[u8],
    normalized_host: &str,
) -> Result<Option<ChainTags>> {
    fn hmac_one(tag_key: &[u8], chain: &str) -> Result<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(tag_key)
            .map_err(|e| CryptoError::KdfFailed(format!("domain tag HMAC init failed: {}", e)))?;
        mac.update(chain.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    let mut chains = domain_chain_suffixes(normalized_host).into_iter();
    let Some(root_chain) = chains.next() else {
        return Ok(None);
    };
    let root = hmac_one(tag_key, &root_chain)?;
    let suffixes = chains
        .map(|chain| hmac_one(tag_key, &chain))
        .collect::<Result<Vec<[u8; 32]>>>()?;
    Ok(Some(ChainTags { root, suffixes }))
}

/// Constant-time "needle equals ANY member of `set`": every pair is
/// compared (no early exit on match) so comparison timing does not reveal
/// WHICH member matched (WBS-306 adversarial pre-check A2).
fn ct_set_contains(set: &[[u8; 32]], needle: &[u8; 32]) -> bool {
    let mut hit = 0u8;
    for member in set {
        hit |= member.ct_eq(needle).unwrap_u8();
    }
    hit == 1
}

/// The tag-level equivalent of `domains_match`: hosts a and b match (one is
/// a suffix of the other, or equal) EXACTLY when a's ROOT tag appears in
/// b's chain set or b's ROOT tag appears in a's chain set. Comparisons are
/// constant-time per pair.
pub fn chain_tag_sets_match(a: &ChainTags, b: &ChainTags) -> bool {
    ct_set_contains(&b.all(), &a.root) || ct_set_contains(&a.all(), &b.root)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Moved from daemon/vault_state.rs (functions relocated here) ------

    #[test]
    fn test_normalize_host_handles_urls_and_ports() {
        assert_eq!(
            normalize_host("https://Login.Example.com:443/path"),
            Some("login.example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com:8443"),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn test_domains_match_exact_and_subdomains_only() {
        assert!(domains_match("example.com", "https://example.com/login"));
        assert!(domains_match(
            "accounts.example.com",
            "https://example.com/login"
        ));
        assert!(domains_match(
            "example.com",
            "https://accounts.example.com/login"
        ));
        assert!(!domains_match(
            "evil-example.com",
            "https://example.com/login"
        ));
        assert!(!domains_match(
            "notexample.com",
            "https://example.com/login"
        ));
    }

    #[test]
    fn test_normalize_host_strips_userinfo() {
        assert_eq!(
            normalize_host("https://user:pass@example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("user@host.com"),
            Some("host.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_strips_query_and_fragment() {
        assert_eq!(
            normalize_host("example.com/path?query=1#frag"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_trailing_dots() {
        assert_eq!(
            normalize_host("example.com."),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("..example.com.."),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host_whitespace_only() {
        assert_eq!(normalize_host("   "), None);
        assert_eq!(normalize_host(" . "), None);
    }

    #[test]
    fn test_normalize_host_bracketed_ipv6() {
        assert_eq!(normalize_host("[::1]:8080"), Some("::1".to_string()));
        assert_eq!(
            normalize_host("https://[::1]:443/path"),
            Some("::1".to_string())
        );
    }

    #[test]
    fn test_normalize_host_empty_bracketed_ipv6() {
        assert_eq!(normalize_host("[]"), None);
    }

    #[test]
    fn test_normalize_host_bare_ipv6() {
        // Non-bracketed IPv6 -- colons not stripped since it looks like IPv6
        let result = normalize_host("::1");
        assert_eq!(result, Some("::1".to_string()));
    }

    #[test]
    fn test_domains_match_both_empty() {
        assert!(!domains_match("", ""));
        assert!(!domains_match("", "example.com"));
        assert!(!domains_match("example.com", ""));
    }

    #[test]
    fn test_domains_match_different_schemes() {
        assert!(domains_match(
            "http://example.com",
            "https://example.com/login"
        ));
    }

    #[test]
    fn test_domains_match_with_ports() {
        assert!(domains_match(
            "example.com:8443",
            "https://example.com:443/"
        ));
    }

    // --- WBS-306: chain generation (property-style) ------------------------

    #[test]
    fn every_suffix_of_a_four_label_host_yields_a_chain() {
        let chains = domain_chain_suffixes("a.b.example.com");
        assert_eq!(
            chains,
            vec![
                "a.b.example.com".to_string(),
                "b.example.com".to_string(),
                "example.com".to_string(),
                "com".to_string(),
            ]
        );
    }

    #[test]
    fn chain_count_is_capped_at_max_chain_tags() {
        // 14-label host: only the 10 longest chains survive the cap.
        let host = "l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.l12.l13.l14.example.com";
        let chains = domain_chain_suffixes(host);
        assert_eq!(chains.len(), MAX_CHAIN_TAGS);
        assert_eq!(chains[0], host);
        // The cap keeps the LONGEST chains: the 10th entry is the suffix
        // starting at label l10.
        assert_eq!(chains[9], "l10.l11.l12.l13.l14.example.com");
    }

    #[test]
    fn chain_tags_evaluate_domains_match_semantics_exactly() {
        // Property: for a sweep of host pairs, the root/suffix tag
        // predicate is equivalent to `domains_match` on the same inputs
        // (including the bare-parent/dotted-child pairs gitlab ↔
        // sub.gitlab), and — critically — shared suffixes alone (the `com`
        // chain) do NOT produce matches.
        let key = [0x42u8; 32];
        let hosts = [
            "gitlab.com",
            "sub.gitlab.com",
            "a.b.example.com",
            "example.com",
            "example.org",
            "notexample.com",
            "notgitlab.com",
            "evil-example.com",
            "com",
            "localhost",
            "deep.a.b.c.d.e.f.g.h.i.j.k.example.com",
        ];
        for request in hosts {
            for stored in hosts {
                let request_tags = compute_domain_chain_tags(&key, request)
                    .unwrap()
                    .expect("test hosts normalize");
                let stored_tags = compute_domain_chain_tags(&key, stored)
                    .unwrap()
                    .expect("test hosts normalize");
                let tags_match = chain_tag_sets_match(&request_tags, &stored_tags);
                let legacy = domains_match(request, stored);
                // DOCUMENTED CAP (ADR-005 rev 4): a chain deeper than
                // MAX_CHAIN_TAGS labels is not stored, so a match whose
                // suffix distance exceeds the cap is not findable via tags
                // — the only sanctioned divergence from domains_match.
                let label_count = |h: &str| h.split('.').count();
                let within_cap = !legacy || {
                    let (short, long) = if label_count(request) <= label_count(stored) {
                        (request, stored)
                    } else {
                        (stored, request)
                    };
                    label_count(long) - label_count(short) < MAX_CHAIN_TAGS
                };
                assert_eq!(
                    tags_match,
                    legacy && within_cap,
                    "tag semantics diverged from the capped domains_match contract \
                     for ({request}, {stored})"
                );
            }
        }

        // The cap is visible by design: `example.com` IS a suffix of the
        // 15-label deep host (legacy matches), but its chain sits at index
        // 13 — beyond MAX_CHAIN_TAGS — so the tag path does not find it.
        // Matching deep chains is explicitly out of contract (no PSL).
        let deep = "deep.a.b.c.d.e.f.g.h.i.j.k.example.com";
        let deep_tags = compute_domain_chain_tags(&key, deep).unwrap().unwrap();
        let apex_tags = compute_domain_chain_tags(&key, "example.com")
            .unwrap()
            .unwrap();
        assert!(domains_match("example.com", deep));
        assert!(!chain_tag_sets_match(&apex_tags, &deep_tags));
    }

    #[test]
    fn sibling_hosts_share_no_tags_but_parent_child_do() {
        let key = [0x42u8; 32];
        let left = compute_domain_chain_tags(&key, "gitlab.com")
            .unwrap()
            .unwrap();
        let right = compute_domain_chain_tags(&key, "gitlab.org")
            .unwrap()
            .unwrap();
        assert!(
            !chain_tag_sets_match(&left, &right),
            "siblings must not match (even though both carry a `com` suffix tag)"
        );

        let parent = compute_domain_chain_tags(&key, "example.com")
            .unwrap()
            .unwrap();
        let child = compute_domain_chain_tags(&key, "sub.example.com")
            .unwrap()
            .unwrap();
        assert!(
            chain_tag_sets_match(&parent, &child),
            "bare parent must match dotted child"
        );
    }

    #[test]
    fn unnormalizable_host_yields_no_tags() {
        let key = [0x42u8; 32];
        assert!(compute_domain_chain_tags(&key, "").unwrap().is_none());
        assert!(compute_domain_chain_tags(&key, "   ").unwrap().is_none());
    }

    #[test]
    fn tags_are_key_bound_and_deterministic() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let a = compute_domain_chain_tags(&k1, "example.com")
            .unwrap()
            .unwrap();
        let b = compute_domain_chain_tags(&k1, "example.com")
            .unwrap()
            .unwrap();
        assert_eq!(a, b, "same key + host must give identical tags");
        let c = compute_domain_chain_tags(&k2, "example.com")
            .unwrap()
            .unwrap();
        assert_ne!(a, c, "different keys must give different tags");
    }

    #[test]
    fn root_and_suffix_split_covers_the_full_chain() {
        let key = [0x09u8; 32];
        let tags = compute_domain_chain_tags(&key, "a.b.example.com")
            .unwrap()
            .unwrap();
        assert_eq!(tags.suffixes.len(), 3, "root + three proper suffixes");
        let mut all = tags.all();
        assert_eq!(all.len(), 4);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 4, "chains of a 4-label host are all distinct");
    }
}
