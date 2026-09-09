import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * WBS-707 / TD-CLIENT-03 negative gate.
 *
 * The Tauri capability grant set must equal the audited least-privilege
 * allowlist exactly — no capability may be added (or silently kept) without
 * a matching usage anchor in the frontend sources, and the CSP must block
 * remote script. This runs in CI (web_tdd job), so capability drift fails
 * the build instead of shipping.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const CAPABILITIES_PATH = path.join(repoRoot, 'sentinelpass-ui', 'capabilities', 'default.json');
const TAURI_CONF_PATH = path.join(repoRoot, 'sentinelpass-ui', 'tauri.conf.json');
const MAIN_RS_PATH = path.join(repoRoot, 'sentinelpass-ui', 'src-tauri', 'src', 'main.rs');
const UI_SOURCES = ['app.ts', 'entries.ts', 'registry.ts', 'state.ts', 'totp.ts', 'utils.ts', 'clipboard.ts', 'credential-types.ts', 'url-utils.ts']
  .map((f) => path.join(repoRoot, 'sentinelpass-ui', f));

function readUiSources(): string {
  return UI_SOURCES.map((f) => readFileSync(f, 'utf8')).join('\n');
}

/**
 * The audited allowlist: permission -> regex that must match some UI source
 * for the grant to stay justified. Any permission added to
 * capabilities/default.json without an entry here fails the suite, and any
 * entry whose usage disappears from the sources fails too.
 *
 * WBS-709: clipboard secrets no longer go through the clipboard-manager
 * plugin at all (no IPC surface — the backend writes via arboard), so the
 * plugin grants are gone and the plugin must not be registered either.
 */
const AUDITED_ALLOWLIST: Record<string, RegExp> = {
  'dialog:allow-confirm': /dialog\s*\.\s*confirm/
};

const capabilityFile = JSON.parse(readFileSync(CAPABILITIES_PATH, 'utf8'));
const tauriConf = JSON.parse(readFileSync(TAURI_CONF_PATH, 'utf8'));
const granted: string[] = capabilityFile.permissions;

describe('tauri capability allowlist (WBS-707)', () => {

  it('grants exactly the audited allowlist — nothing more', () => {
    const unexpected = granted.filter((p: string) => !(p in AUDITED_ALLOWLIST));
    expect(unexpected, `unaudited capability grants: ${unexpected.join(', ')}`).toEqual([]);
  });

  it('grants exactly the audited allowlist — nothing less', () => {
    const missing = Object.keys(AUDITED_ALLOWLIST).filter((p) => !granted.includes(p));
    expect(missing, `audited grants removed without updating this gate: ${missing.join(', ')}`).toEqual([]);
  });

  it('has no duplicate permission grants', () => {
    expect(new Set(granted).size).toBe(granted.length);
  });

  it('documents that the capability file is the single source of truth', () => {
    expect(capabilityFile.identifier).toBe('default');
    expect(capabilityFile.windows).toEqual(['main']);
  });

  it('every granted permission has live usage evidence in the frontend sources', () => {
    const sources = readUiSources();
    for (const [permission, pattern] of Object.entries(AUDITED_ALLOWLIST)) {
      if (!granted.includes(permission)) continue;
      expect(pattern.test(sources), `no usage anchor found for granted permission ${permission}`).toBe(true);
    }
  });

  it('tauri.conf.json does not duplicate capability grants inline', () => {
    // capabilities/default.json is the single source of truth; an inline
    // `app.security.capabilities` copy drifts silently (that is how the
    // over-granted set survived the 0.9 audit).
    const inline = tauriConf?.app?.security?.capabilities;
    expect(inline === undefined || (Array.isArray(inline) && inline.length === 0)).toBe(true);
  });

  it('no remote-domain IPC access is configured', () => {
    expect(tauriConf?.app?.security?.dangerousRemoteDomainIpcAccess).toBeUndefined();
  });
});

describe('tauri CSP (WBS-707 / TD-CLIENT-03)', () => {
  const csp: string = tauriConf?.app?.security?.csp ?? '';

  function directive(name: string): string[] {
    const match = csp.match(new RegExp(`${name}\\s+([^;]+);`));
    return match ? match[1].trim().split(/\s+/) : [];
  }

  it('is present', () => {
    expect(csp.length).toBeGreaterThan(0);
  });

  it('script-src is exactly self — no remote script, no unsafe-inline/eval', () => {
    const scriptSrc = directive('script-src');
    expect(scriptSrc).toEqual(["'self'"]);
  });

  it('default-src is exactly self', () => {
    expect(directive('default-src')).toEqual(["'self'"]);
  });

  it('object-src is none (no plugin content)', () => {
    expect(directive('object-src')).toEqual(["'none'"]);
  });

  it('base-uri is self (no injection-driven base hijack)', () => {
    expect(directive('base-uri')).toEqual(["'self'"]);
  });

  it('no remote host may be connected to over http(s)', () => {
    const connectSrc = directive('connect-src');
    const remote = connectSrc.filter((src) => /^https?:\/\//.test(src) && !src.startsWith('http://ipc.localhost'));
    expect(remote, `remote connect-src entries: ${remote.join(', ')}`).toEqual([]);
  });

  it('every allow-listed directive source is local or the Tauri IPC origins', () => {
    const allowed = new Set(["'self'", "'none'", 'ipc:', 'http://ipc.localhost', 'data:']);
    for (const directiveName of ['script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'default-src', 'frame-src', 'form-action', 'object-src', 'base-uri']) {
      for (const src of directive(directiveName)) {
        expect(allowed.has(src), `unexpected ${directiveSrcLabel(directiveName)} source: ${src}`).toBe(true);
      }
    }
  });

  it('allows no blanket WebSocket escape hatch (no WS usage exists in the UI)', () => {
    expect(csp.includes('ws://')).toBe(false);
  });

  function directiveSrcLabel(name: string): string {
    return name;
  }
});

describe('tauri plugin registration matches the capability surface (WBS-707/709)', () => {
  const mainRs = readFileSync(MAIN_RS_PATH, 'utf8');

  it('the unused shell plugin is not registered (URLs open via custom commands)', () => {
    expect(mainRs.includes('tauri_plugin_shell')).toBe(false);
  });

  it('the clipboard-manager plugin is not registered (WBS-709 native clipboard path)', () => {
    expect(mainRs.includes('tauri_plugin_clipboard_manager')).toBe(false);
  });

  it('every registered plugin family still has at least one granted permission', () => {
    const registeredFamilies = [...mainRs.matchAll(/tauri_plugin_([a-z_]+)::init\(\)/g)].map((m) => m[1]);
    expect(registeredFamilies.length).toBeGreaterThan(0);
    for (const family of registeredFamilies) {
      const prefixed = granted.some((p: string) => p.startsWith(`${family}:`) || p.startsWith(`${family.replace(/_/g, '-')}:`));
      expect(prefixed, `plugin "${family}" is registered but has no capability grants`).toBe(true);
    }
  });

  it('secret clipboard copies use the native backend path, not a plugin grant', () => {
    const sources = readUiSources();
    expect(/invoke\(\s*['"]copy_secret_to_clipboard/.test(sources.replace(/\/\/[^\n]*/g, ''))).toBe(true);
    expect(/clipboardManager/.test(sources)).toBe(false);
  });
});
