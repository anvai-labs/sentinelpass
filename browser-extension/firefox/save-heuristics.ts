export function normalizeUsername(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function isUsernameMatchOrUnknown(
  submittedUsername: string,
  existingUsername: string
): boolean {
  if (!submittedUsername || !existingUsername) {
    return true;
  }
  return submittedUsername === existingUsername;
}

export function normalizeDomainForPolicy(value: unknown): string | null {
  if (!value || typeof value !== 'string') {
    return null;
  }

  let normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
    try {
      normalized = new URL(normalized).hostname.toLowerCase();
    } catch {
      // Keep original value if URL parsing fails.
    }
  }

  normalized = normalized.replace(/^\.+|\.+$/g, '');
  if (normalized.startsWith('www.')) {
    normalized = normalized.slice(4);
  }

  return normalized || null;
}

export function domainMatchesPolicy(domain: string, policyDomain: string): boolean {
  return domain === policyDomain || domain.endsWith(`.${policyDomain}`);
}

export function normalizeCredentialUrl(rawUrl: unknown, fallbackDomain: unknown): string | null {
  const domain = normalizeDomainForPolicy(fallbackDomain || '');
  const raw = typeof rawUrl === 'string' ? rawUrl.trim() : '';

  if (raw) {
    try {
      const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw) ? raw : `https://${raw}`;
      const parsed = new URL(withScheme);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.origin;
      }
    } catch {
      // Fall through to domain fallback below.
    }
  }

  if (domain) {
    return `https://${domain}`;
  }

  return null;
}

export function buildSaveNotificationRequestKey(data: {
  domain?: string;
  url?: string;
  username?: string;
  password?: string;
}): string {
  const domain = normalizeDomainForPolicy(data?.domain || data?.url || '') || 'unknown';
  const username = typeof data?.username === 'string' ? data.username.trim().toLowerCase() : '';
  const url = typeof data?.url === 'string' ? data.url.split('#')[0] : '';
  const passwordLength = typeof data?.password === 'string' ? data.password.length : 0;
  return `${domain}|${username}|${url}|len:${passwordLength}`;
}
