export function normalizeUsername(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
export function isUsernameMatchOrUnknown(submittedUsername, existingUsername) {
    if (!submittedUsername || !existingUsername) {
        return true;
    }
    return submittedUsername === existingUsername;
}
/**
 * True when the string already carries a scheme prefix (`scheme:`), which
 * means it should first be parsed as a URL rather than as a bare host.
 */
function hasSchemePrefix(value) {
    return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}
/**
 * `host:port`-only shape (e.g. `example.com:8443`). Such input is
 * syntactically ambiguous — the WHATWG parser reads `example.com` as a
 * scheme with no host — but semantically always means host+port here, so it
 * is re-parsed behind a synthetic `https://` (never applied to values with
 * `@` or `/`, which would smuggle userinfo or path text into the host).
 */
const HOST_PORT_ONLY = /^[a-zA-Z0-9.-]+:[0-9]{1,5}$/;
/**
 * Extract the bare host from an already-parsed URL (WBS-706).
 *
 * `URL.hostname` is already lowercase, ASCII/punycode-encoded (IDN labels
 * become `xn--…`), and carries no userinfo, port, path, query, or fragment.
 * IPv6 hosts keep their square brackets in `hostname`; they are stripped so
 * policy entries are stored in the same shape the daemon uses (`::1`).
 */
function hostFromParsedUrl(parsed) {
    const host = parsed.hostname
        .replace(/^\[|\]$/g, '')
        .replace(/^\.+|\.+$/g, '')
        .toLowerCase();
    return host || null;
}
function stripPolicyWwwSuffix(host) {
    const withoutWww = host.startsWith('www.') ? host.slice(4) : host;
    return withoutWww || null;
}
/**
 * Normalize a domain-or-URL value to a bare hostname for policy storage and
 * matching (WBS-706, TD-CLIENT-06 URL half).
 *
 * All parsing goes through the WHATWG `URL` API — no string surgery on URLs:
 *
 * - Scheme-bearing input is parsed as-is; the host is extracted structurally
 *   (ports, userinfo, paths, query strings, and fragments are dropped; IDN
 *   hosts are punycoded exactly like `window.location.hostname`).
 * - Scheme-less input is parsed via a synthetic `https://` prefix (mirrors
 *   the daemon-side `domain::normalize_host` dummy-scheme approach), so
 *   `user@host.com` and `example.com/path` reduce to their host.
 * - `example.com:8443` (which the URL parser reads as a scheme with no
 *   host) is re-parsed as `https://example.com:8443` and yields
 *   `example.com`.
 * - Input that yields no host (parse failure, `mailto:` URLs, empty hosts)
 *   is REFUSED (`null`) instead of being stored raw as a pseudo-domain.
 *
 * A leading `www.` is still stripped afterwards so legacy policy entries
 * recorded before this function existed keep matching.
 */
export function normalizeDomainForPolicy(value) {
    if (!value || typeof value !== 'string') {
        return null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return null;
    }
    if (hasSchemePrefix(trimmed)) {
        try {
            const host = hostFromParsedUrl(new URL(trimmed));
            if (host) {
                return stripPolicyWwwSuffix(host);
            }
        }
        catch {
            // Fall through: some scheme-shaped input is really a host:port.
        }
        if (HOST_PORT_ONLY.test(trimmed)) {
            try {
                const host = hostFromParsedUrl(new URL(`https://${trimmed}`));
                return host ? stripPolicyWwwSuffix(host) : null;
            }
            catch {
                return null;
            }
        }
        // Scheme-shaped but no host (`mailto:…`, `https://`, …) — refuse the
        // value rather than storing arbitrary text as a policy domain.
        return null;
    }
    try {
        const host = hostFromParsedUrl(new URL(`https://${trimmed}`));
        if (!host) {
            return null;
        }
        return stripPolicyWwwSuffix(host);
    }
    catch {
        // Not a parseable host — refuse rather than store raw text.
        return null;
    }
}
export function classifyCredentialUrlSecurity(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') {
        return 'unknown';
    }
    const trimmed = rawUrl.trim();
    if (!trimmed) {
        return 'unknown';
    }
    try {
        const parsed = new URL(trimmed);
        if (parsed.protocol === 'https:') {
            return 'secure';
        }
        if (parsed.protocol === 'http:') {
            return 'insecure';
        }
        return 'unknown';
    }
    catch {
        return 'unknown';
    }
}
export function domainMatchesPolicy(domain, policyDomain) {
    // Bracket-insensitive so legacy never-save keys recorded before WBS-706
    // (which stored `window.location.hostname` verbatim, i.e. `[::1]`) keep
    // matching the bracket-stripped hosts the structured normalizer produces.
    const normalizedDomain = domain.replace(/^\[|\]$/g, '');
    const normalizedPolicy = policyDomain.replace(/^\[|\]$/g, '');
    return (normalizedDomain === normalizedPolicy ||
        normalizedDomain.endsWith(`.${normalizedPolicy}`));
}
export function normalizeCredentialUrl(rawUrl, fallbackDomain) {
    const domain = normalizeDomainForPolicy(fallbackDomain || '');
    const raw = typeof rawUrl === 'string' ? rawUrl.trim() : '';
    if (raw) {
        try {
            const withScheme = hasSchemePrefix(raw) ? raw : `https://${raw}`;
            const parsed = new URL(withScheme);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.origin;
            }
        }
        catch {
            // Fall through to the host:port rescue, then to the domain fallback.
        }
        // `host:port` input parses as a non-URL scheme (no host); re-read it as
        // a URL behind the same synthetic scheme used for scheme-less input.
        if (HOST_PORT_ONLY.test(raw)) {
            try {
                const parsed = new URL(`https://${raw}`);
                if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                    return parsed.origin;
                }
            }
            catch {
                // Fall through to domain fallback below.
            }
        }
    }
    if (domain) {
        return `https://${domain}`;
    }
    return null;
}
export function buildSaveNotificationRequestKey(data) {
    const domain = normalizeDomainForPolicy(data?.domain || data?.url || '') || 'unknown';
    const username = typeof data?.username === 'string' ? data.username.trim().toLowerCase() : '';
    const url = typeof data?.url === 'string' ? data.url.split('#')[0] : '';
    const passwordLength = typeof data?.password === 'string' ? data.password.length : 0;
    return `${domain}|${username}|${url}|len:${passwordLength}`;
}
