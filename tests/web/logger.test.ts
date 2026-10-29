import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// We test both production (debugMode=false) and debug (debugMode=true) paths
// by re-importing the module with different chrome mocks.

function createChromeMock(installType: string, storedDebug: boolean) {
  return {
    management: {
      getSelf: (cb: (info: { installType: string }) => void) => cb({ installType }),
    },
    storage: {
      local: {
        get: (_keys: string[], cb: (result: Record<string, unknown>) => void) =>
          cb({ debugModeEnabled: storedDebug }),
        set: vi.fn(),
      },
    },
  };
}

describe('logger (production mode)', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', createChromeMock('normal', false));
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('defaults to disabled in production', async () => {
    const { isDebugEnabled } = await import('../../browser-extension/chrome/logger.ts');
    expect(isDebugEnabled()).toBe(false);
  });

  it('debugLog does not output when disabled', async () => {
    const { debugLog } = await import('../../browser-extension/chrome/logger.ts');
    debugLog('should not appear');
    expect(console.log).not.toHaveBeenCalled();
  });

  it('infoLog always outputs with prefix', async () => {
    const { infoLog } = await import('../../browser-extension/chrome/logger.ts');
    infoLog('test message', 'extra');
    expect(console.log).toHaveBeenCalledWith('[SentinelPass] test message', 'extra');
  });

  it('warnLog always outputs', async () => {
    const { warnLog } = await import('../../browser-extension/chrome/logger.ts');
    warnLog('warning msg');
    expect(console.warn).toHaveBeenCalledWith('[SentinelPass] warning msg');
  });

  it('errorLog always outputs', async () => {
    const { errorLog } = await import('../../browser-extension/chrome/logger.ts');
    errorLog('error msg');
    expect(console.error).toHaveBeenCalledWith('[SentinelPass] error msg');
  });

  it('sanitizeUrl returns origin only in production', async () => {
    const { sanitizeUrl } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizeUrl('https://example.com/path?secret=123#hash')).toBe('https://example.com');
    expect(sanitizeUrl('not-a-url')).toBe('(invalid URL)');
  });

  it('sanitizeHostname returns generic indicator in production', async () => {
    const { sanitizeHostname } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizeHostname('secret.example.com')).toBe('(hostname)');
  });

  it('sanitizePasswordLength returns strength categories', async () => {
    const { sanitizePasswordLength } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizePasswordLength('')).toBe('empty');
    expect(sanitizePasswordLength('short')).toBe('short (<8 chars)');
    expect(sanitizePasswordLength('mediumpass')).toBe('medium (8-11 chars)');
    expect(sanitizePasswordLength('longpassword12')).toBe('long (12+ chars)');
  });
});

describe('logger (debug mode via development install)', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', createChromeMock('development', false));
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('enables debug mode for unpacked extensions', async () => {
    const { isDebugEnabled } = await import('../../browser-extension/chrome/logger.ts');
    expect(isDebugEnabled()).toBe(true);
  });

  it('debugLog outputs when debug mode is on', async () => {
    const { debugLog } = await import('../../browser-extension/chrome/logger.ts');
    debugLog('visible debug msg');
    expect(console.log).toHaveBeenCalledWith('[SentinelPass Debug]', 'visible debug msg');
  });

  it('sanitizeUrl returns full URL in debug mode', async () => {
    const { sanitizeUrl } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizeUrl('https://example.com/path?secret=123')).toBe('https://example.com/path?secret=123');
  });

  it('sanitizeHostname returns actual hostname in debug mode', async () => {
    const { sanitizeHostname } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizeHostname('secret.example.com')).toBe('secret.example.com');
  });

  it('sanitizePasswordLength returns exact length in debug mode', async () => {
    const { sanitizePasswordLength } = await import('../../browser-extension/chrome/logger.ts');
    expect(sanitizePasswordLength('hello')).toBe('5');
  });
});

describe('logger (debug mode via storage)', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', createChromeMock('normal', true));
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('enables debug mode from chrome.storage', async () => {
    const { isDebugEnabled } = await import('../../browser-extension/chrome/logger.ts');
    expect(isDebugEnabled()).toBe(true);
  });
});

describe('logger (no chrome API)', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', undefined);
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('does not crash when chrome is undefined', async () => {
    const { isDebugEnabled, debugLog, infoLog } = await import('../../browser-extension/chrome/logger.ts');
    expect(isDebugEnabled()).toBe(false);
    debugLog('no output');
    infoLog('still works');
    expect(console.log).toHaveBeenCalledWith('[SentinelPass] still works');
  });
});

// redactForLog moved here from background.ts/content.ts (extension
// deduplication). It is the console-redaction boundary, so its behavior is
// pinned directly: sensitive keys must never survive a log call.
describe('redactForLog', () => {
  beforeEach(() => {
    vi.stubGlobal('chrome', createChromeMock('normal', false));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('passes primitives and null through untouched', async () => {
    const { redactForLog } = await import('../../browser-extension/chrome/logger.ts');
    expect(redactForLog('plain')).toBe('plain');
    expect(redactForLog(42)).toBe(42);
    expect(redactForLog(true)).toBe(true);
    expect(redactForLog(null)).toBeNull();
    expect(redactForLog(undefined)).toBeUndefined();
  });

  it('redacts every sensitive key, case-insensitively', async () => {
    const { redactForLog } = await import('../../browser-extension/chrome/logger.ts');
    const redacted = redactForLog({
      username: 'alice',
      password: 'hunter2',
      token: 'abc',
      SECRET: 's',
      PassPhrase: 'p',
      totp_code: '000000'
    }) as Record<string, unknown>;
    expect(redacted['username']).toBe('alice');
    expect(redacted['password']).toBe('[REDACTED]');
    expect(redacted['token']).toBe('[REDACTED]');
    expect(redacted['SECRET']).toBe('[REDACTED]');
    expect(redacted['PassPhrase']).toBe('[REDACTED]');
    expect(redacted['totp_code']).toBe('[REDACTED]');
  });

  it('recurses into nested objects and arrays', async () => {
    const { redactForLog } = await import('../../browser-extension/chrome/logger.ts');
    const redacted = redactForLog({
      request: { url: 'https://example.com', password: 'nested-secret' },
      attempts: [{ token: 'one' }, { ok: true }]
    }) as Record<string, unknown>;
    const request = redacted['request'] as Record<string, unknown>;
    const attempts = redacted['attempts'] as Record<string, unknown>[];
    expect(request['url']).toBe('https://example.com');
    expect(request['password']).toBe('[REDACTED]');
    expect(attempts[0]['token']).toBe('[REDACTED]');
    expect(attempts[1]['ok']).toBe(true);
  });

  it('does not mutate the input value', async () => {
    const { redactForLog } = await import('../../browser-extension/chrome/logger.ts');
    const input = { password: 'hunter2' };
    redactForLog(input);
    expect(input.password).toBe('hunter2');
  });
});
