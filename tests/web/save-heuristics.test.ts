import { describe, expect, it } from 'vitest';
import {
  buildSaveNotificationRequestKey,
  classifyCredentialUrlSecurity,
  domainMatchesPolicy,
  isUsernameMatchOrUnknown,
  normalizeCredentialUrl,
  normalizeDomainForPolicy,
  normalizeUsername
} from '../../browser-extension/chrome/save-heuristics.ts';

describe('save heuristics', () => {
  it('normalizes usernames', () => {
    expect(normalizeUsername('  USER@Example.COM ')).toBe('user@example.com');
    expect(normalizeUsername(null)).toBe('');
  });

  it('normalizes policy domains', () => {
    expect(normalizeDomainForPolicy('https://www.GitHub.com/login')).toBe('github.com');
    expect(normalizeDomainForPolicy('..example.com..')).toBe('example.com');
    expect(normalizeDomainForPolicy('   ')).toBeNull();
  });

  // WBS-706 positive: structured parsing of tricky URLs. Everything below
  // must go through the URL API — hosts come back lowercase/punycoded with
  // no port, userinfo, path, query, or fragment.
  describe('structured URL parsing (WBS-706)', () => {
    it('drops ports from scheme-bearing and bare host:port input', () => {
      expect(normalizeDomainForPolicy('https://example.com:8443/login')).toBe('example.com');
      expect(normalizeDomainForPolicy('http://example.com:80')).toBe('example.com');
      expect(normalizeDomainForPolicy('example.com:8080')).toBe('example.com');
      expect(normalizeDomainForPolicy('example.com.:8443')).toBe('example.com');
    });

    it('strips userinfo instead of storing it as part of the host', () => {
      expect(normalizeDomainForPolicy('https://user:secret@example.com/login')).toBe('example.com');
      expect(normalizeDomainForPolicy('user@host.com')).toBe('host.com');
    });

    it('punycodes IDN hosts the same way location.hostname does', () => {
      expect(normalizeDomainForPolicy('https://münchen.de/login')).toBe('xn--mnchen-3ya.de');
      expect(normalizeDomainForPolicy('münchen.de')).toBe('xn--mnchen-3ya.de');
      expect(normalizeDomainForPolicy('xn--mnchen-3ya.de')).toBe('xn--mnchen-3ya.de');
    });

    it('drops paths, query strings, and fragments', () => {
      expect(normalizeDomainForPolicy('https://example.com/a/b?x=1#frag')).toBe('example.com');
      expect(normalizeDomainForPolicy('example.com/path')).toBe('example.com');
    });

    it('normalizes IPv4 and bracketed IPv6 hosts', () => {
      expect(normalizeDomainForPolicy('192.168.1.1:8080')).toBe('192.168.1.1');
      expect(normalizeDomainForPolicy('https://192.168.1.1/admin')).toBe('192.168.1.1');
      expect(normalizeDomainForPolicy('https://[::1]:8080/')).toBe('::1');
      expect(normalizeDomainForPolicy('[::1]:8443')).toBe('::1');
    });

    it('extracts hosts from non-web schemes rather than storing them raw', () => {
      expect(normalizeDomainForPolicy('ftp://example.com/pub')).toBe('example.com');
    });

    it('uppercases nothing: mixed-case hosts and schemes normalize fully', () => {
      expect(normalizeDomainForPolicy('HTTPS://Login.Example.COM:443/path')).toBe('login.example.com');
    });

    it('keeps legacy www-stripping and subdomain policy matching', () => {
      expect(normalizeDomainForPolicy('https://www.App.Example.com')).toBe('app.example.com');
      expect(domainMatchesPolicy(
        normalizeDomainForPolicy('https://app.example.com')!,
        normalizeDomainForPolicy('https://www.Example.com')!
      )).toBe(true);
    });

    it('keeps legacy bracketed-IPv6 never-save keys matching (upgrade compat)', () => {
      // Pre-WBS-706 entries stored window.location.hostname verbatim, i.e.
      // with brackets; the structured normalizer now stores '::1'.
      expect(normalizeDomainForPolicy('https://[::1]:8080/')).toBe('::1');
      expect(domainMatchesPolicy('::1', '[::1]')).toBe(true);
      expect(domainMatchesPolicy('[::1]', '::1')).toBe(true);
    });

    it('rescues host:port strings the URL parser misreads as scheme:path', () => {
      // `example.com:8443` parses as scheme "example.com" with no host; the
      // normalizer must re-read it as a host, not refuse or store it raw.
      expect(normalizeDomainForPolicy('example.com:8443')).toBe('example.com');
    });
  });

  // WBS-706 negative: values with no extractable host are REFUSED (null),
  // never stored raw as pseudo-domains.
  describe('structured parse refusals (WBS-706)', () => {
    it('refuses scheme-shaped values with no host', () => {
      expect(normalizeDomainForPolicy('https://')).toBeNull();
      expect(normalizeDomainForPolicy('http://')).toBeNull();
      expect(normalizeDomainForPolicy('mailto:user@example.com')).toBeNull();
      expect(normalizeDomainForPolicy('about:blank')).toBeNull();
    });

    it('refuses unparseable garbage instead of storing it', () => {
      expect(normalizeDomainForPolicy('not a url!!')).toBeNull();
      expect(normalizeDomainForPolicy('://invalid')).toBeNull();
      expect(normalizeDomainForPolicy('ht tp://example.com')).toBeNull();
    });

    it('refuses empty and non-string values', () => {
      expect(normalizeDomainForPolicy('')).toBeNull();
      expect(normalizeDomainForPolicy('   ')).toBeNull();
      expect(normalizeDomainForPolicy(null)).toBeNull();
      expect(normalizeDomainForPolicy(undefined)).toBeNull();
      expect(normalizeDomainForPolicy(42)).toBeNull();
      expect(normalizeDomainForPolicy({})).toBeNull();
    });
  });

  // WBS-706 HTTP warn half: only an explicit http: URL is insecure.
  describe('credential URL security classification (WBS-706)', () => {
    it('classifies plain HTTP as insecure', () => {
      expect(classifyCredentialUrlSecurity('http://example.com/login')).toBe('insecure');
      expect(classifyCredentialUrlSecurity('HTTP://EXAMPLE.COM')).toBe('insecure');
      expect(classifyCredentialUrlSecurity('http://192.168.1.1/login')).toBe('insecure');
      expect(classifyCredentialUrlSecurity('http://[::1]/login')).toBe('insecure');
    });

    it('classifies HTTPS as secure', () => {
      expect(classifyCredentialUrlSecurity('https://example.com/login?x=1')).toBe('secure');
    });

    it('does not fabricate a scheme: scheme-less and non-web input stays unknown', () => {
      expect(classifyCredentialUrlSecurity('example.com')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('example.com/login')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('ftp://example.com')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('about:blank')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('chrome-extension://abc/popup.html')).toBe('unknown');
    });

    it('treats missing or unparseable input as unknown, never secure', () => {
      expect(classifyCredentialUrlSecurity('')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('   ')).toBe('unknown');
      expect(classifyCredentialUrlSecurity(null)).toBe('unknown');
      expect(classifyCredentialUrlSecurity(undefined)).toBe('unknown');
      expect(classifyCredentialUrlSecurity(12345)).toBe('unknown');
      expect(classifyCredentialUrlSecurity('http://')).toBe('unknown');
      expect(classifyCredentialUrlSecurity('not a url!!')).toBe('unknown');
    });
  });

  it('matches policy domains for subdomains', () => {
    expect(domainMatchesPolicy('app.github.com', 'github.com')).toBe(true);
    expect(domainMatchesPolicy('github.com', 'github.com')).toBe(true);
    expect(domainMatchesPolicy('github.com', 'example.com')).toBe(false);
  });

  it('normalizes credential URL to origin', () => {
    expect(normalizeCredentialUrl('https://github.com/login?x=1', '')).toBe('https://github.com');
    expect(normalizeCredentialUrl('github.com/login', '')).toBe('https://github.com');
    expect(normalizeCredentialUrl('', 'github.com')).toBe('https://github.com');
    expect(normalizeCredentialUrl('ftp://github.com/repo', 'github.com')).toBe('https://github.com');
    expect(normalizeCredentialUrl('://invalid', '')).toBeNull();
    expect(normalizeCredentialUrl('example.com:8080', 'example.com')).toBe('https://example.com:8080');
    // host:port/path cannot be rescued (path text present) — domain fallback.
    expect(normalizeCredentialUrl('example.com:8080/login', 'example.com')).toBe('https://example.com');
    // Userinfo never leaks into the stored origin (URL.origin drops it).
    expect(normalizeCredentialUrl('https://user:secret@example.com/', 'example.com')).toBe('https://example.com');
  });

  it('builds stable save notification dedupe key', () => {
    expect(
      buildSaveNotificationRequestKey({
        domain: 'github.com',
        username: ' User@Example.com ',
        url: 'https://github.com/login#section',
        password: 'secret123'
      })
    ).toBe('github.com|user@example.com|https://github.com/login|len:9');
  });

  it('handles username match or unknown semantics', () => {
    expect(isUsernameMatchOrUnknown('', 'user@example.com')).toBe(true);
    expect(isUsernameMatchOrUnknown('user@example.com', '')).toBe(true);
    expect(isUsernameMatchOrUnknown('a@example.com', 'a@example.com')).toBe(true);
    expect(isUsernameMatchOrUnknown('a@example.com', 'b@example.com')).toBe(false);
  });
});
