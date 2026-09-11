import { describe, expect, it } from 'vitest';
import {
  PENDING_CREDENTIAL_KEY,
  PENDING_CREDENTIAL_TTL_MS,
  PENDING_INLINE_PREFIX,
  PENDING_SAVE_PREFIX,
  PENDING_SAVE_TTL_MS,
  PENDING_UNLOCK_RETRY_KEY,
  PENDING_UNLOCK_RETRY_TTL_MS,
  expiredSessionSecretKeys,
  isSessionSecretExpired,
  isSessionSecretKey,
  sessionSecretExpiry,
  sessionSecretTtlMs
} from '../../browser-extension/chrome/session-secrets.ts';

describe('session secret registry (WBS-716)', () => {
  it('classifies secret-bearing session keys', () => {
    expect(isSessionSecretKey(PENDING_CREDENTIAL_KEY)).toBe(true);
    expect(isSessionSecretKey(`${PENDING_SAVE_PREFIX}save-password-1`)).toBe(true);
    expect(isSessionSecretKey(`${PENDING_INLINE_PREFIX}prompt-1`)).toBe(true);
    expect(isSessionSecretKey(PENDING_UNLOCK_RETRY_KEY)).toBe(true);
    expect(isSessionSecretKey('neverSaveDomains')).toBe(false);
    expect(isSessionSecretKey('pendingSaveCredentialX')).toBe(false);
    expect(isSessionSecretKey('pendingInlinePromptX')).toBe(false);
    expect(isSessionSecretKey('debugModeEnabled')).toBe(false);
  });

  it('bounds every secret key with a TTL and stamps expiries', () => {
    expect(sessionSecretTtlMs(PENDING_CREDENTIAL_KEY)).toBe(PENDING_CREDENTIAL_TTL_MS);
    expect(sessionSecretTtlMs(`${PENDING_SAVE_PREFIX}x`)).toBe(PENDING_SAVE_TTL_MS);
    expect(sessionSecretTtlMs(`${PENDING_INLINE_PREFIX}x`)).toBe(PENDING_SAVE_TTL_MS);
    expect(sessionSecretTtlMs(PENDING_UNLOCK_RETRY_KEY)).toBe(PENDING_UNLOCK_RETRY_TTL_MS);
    expect(sessionSecretTtlMs('neverSaveDomains')).toBeNull();

    // 2FA-page pending logins stay bounded by the same 30s window the
    // resume check uses.
    expect(PENDING_CREDENTIAL_TTL_MS).toBe(30_000);
    expect(sessionSecretExpiry(PENDING_CREDENTIAL_KEY, 1_000)).toBe(31_000);
    expect(sessionSecretExpiry('neverSaveDomains', 1_000)).toBeNull();
  });

  it('treats entries past their expiry as expired', () => {
    const entry = { password: 'secret', expiresAt: 5_000 };
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, entry, 4_999)).toBe(false);
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, entry, 5_000)).toBe(true);
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, entry, 6_000)).toBe(true);
  });

  it('fails closed: an unstamped or malformed secret entry counts as expired', () => {
    // No stamp at all.
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, { password: 'x' }, 0)).toBe(true);
    // Malformed stamps.
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, { expiresAt: 'soon' }, 0)).toBe(true);
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, { expiresAt: NaN }, 0)).toBe(true);
    // Non-object junk.
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, 'raw-string', 0)).toBe(true);
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, null, 0)).toBe(true);
    // A missing key (undefined value) is expired/swept trivially.
    expect(isSessionSecretExpired(PENDING_CREDENTIAL_KEY, undefined, 0)).toBe(true);
  });

  it('never sweeps non-secret keys regardless of shape', () => {
    expect(isSessionSecretExpired('neverSaveDomains', { anything: true }, 10_000)).toBe(false);
    expect(isSessionSecretExpired('recentSaveNotARealKey', { expiresAt: 1 }, 10_000)).toBe(false);
  });

  it('produces the sweep list for expired entries only', () => {
    const now = 100_000;
    const store: Record<string, unknown> = {
      [PENDING_CREDENTIAL_KEY]: { expiresAt: now - 1 },
      [`${PENDING_SAVE_PREFIX}a`]: { expiresAt: now + 60_000 },
      [`${PENDING_SAVE_PREFIX}b`]: { password: 'no-stamp' },
      [PENDING_UNLOCK_RETRY_KEY]: { expiresAt: now - 60_000 },
      neverSaveDomains: { someDomain: { createdAt: 1 } }
    };
    const keys = Object.keys(store);
    const swept = expiredSessionSecretKeys(keys, (k) => store[k], now);
    expect(swept.sort()).toEqual(
      [PENDING_CREDENTIAL_KEY, `${PENDING_SAVE_PREFIX}b`, PENDING_UNLOCK_RETRY_KEY].sort()
    );
  });
});
