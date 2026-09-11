import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const chromeManifest = JSON.parse(
  readFileSync(path.join(repoRoot, 'browser-extension', 'chrome', 'manifest.json'), 'utf8')
) as Record<string, any>;
const firefoxManifest = JSON.parse(
  readFileSync(path.join(repoRoot, 'browser-extension', 'firefox', 'manifest.json'), 'utf8')
) as Record<string, any>;

const PINNED_CHROME_EXTENSION_ID = 'nophfgfiiohedlodfeepjoioljbhggdd';
const HOST_NAME = 'com.passwordmanager.host';

/** Chrome stable extension ID: a-p base-16 of SHA256(manifest key)[0..16]. */
function deriveChromeExtensionId(manifestKey: string): string {
  const keyDer = Buffer.from(manifestKey, 'base64');
  const digest = createHash('sha256').update(keyDer).digest();
  const toAlpha = (byte: number): string => String.fromCharCode(97 + (byte & 0x0f));
  return Array.from(digest.subarray(0, 16))
    .map((b) => toAlpha(b >> 4) + toAlpha(b))
    .join('');
}

/** Extract a literal string constant from a Rust source file. */
function constantFromSource(source: string, name: string): string | null {
  const match = source.match(new RegExp(`${name}\\s*:\\s*&?str\\s*=\\s*"([^"]+)"`));
  return match ? match[1] : null;
}

describe('manifest/native-host parity (WBS-718, SR-CLIENT-004, TD-CLIENT-08)', () => {
  it('keeps both manifests on one version and one identity surface', () => {
    expect(chromeManifest.version).toBe(firefoxManifest.version);
    expect(chromeManifest.name).toBe(firefoxManifest.name);
    expect(chromeManifest.manifest_version).toBe(firefoxManifest.manifest_version);
    expect(chromeManifest.permissions).toEqual(firefoxManifest.permissions);
    expect(chromeManifest.optional_host_permissions).toEqual(
      firefoxManifest.optional_host_permissions
    );
    expect(chromeManifest.content_scripts).toEqual(firefoxManifest.content_scripts);
  });

  it('derives the pinned stable Chrome extension ID from the manifest key', () => {
    expect(typeof chromeManifest.key).toBe('string');
    expect(deriveChromeExtensionId(chromeManifest.key)).toBe(PINNED_CHROME_EXTENSION_ID);
  });

  it('allows the derived Chrome ID in every native-host registration source', () => {
    const sources: Array<[string, string]> = [
      ['installation/install.sh', readFileSync(path.join(repoRoot, 'installation', 'install.sh'), 'utf8')],
      [
        'installation/install.ps1',
        readFileSync(path.join(repoRoot, 'installation', 'install.ps1'), 'utf8')
      ],
      [
        'sentinelpass-ui/src-tauri/src/main.rs',
        readFileSync(path.join(repoRoot, 'sentinelpass-ui', 'src-tauri', 'src', 'main.rs'), 'utf8')
      ]
    ];
    for (const [label, source] of sources) {
      expect(
        source.includes(PINNED_CHROME_EXTENSION_ID),
        `${label} does not allow the Chrome extension ID ${PINNED_CHROME_EXTENSION_ID}`
      ).toBe(true);
    }
  });

  it('uses ONE firefox extension ID across the manifest and every native-host source', () => {
    const geckoId = firefoxManifest.browser_specific_settings?.gecko?.id;
    expect(typeof geckoId).toBe('string');
    const sources: Array<[string, string]> = [
      ['installation/install.sh', readFileSync(path.join(repoRoot, 'installation', 'install.sh'), 'utf8')],
      [
        'installation/install.ps1',
        readFileSync(path.join(repoRoot, 'installation', 'install.ps1'), 'utf8')
      ],
      [
        'sentinelpass-ui/src-tauri/src/main.rs',
        readFileSync(path.join(repoRoot, 'sentinelpass-ui', 'src-tauri', 'src', 'main.rs'), 'utf8')
      ]
    ];
    for (const [label, source] of sources) {
      expect(
        source.includes(geckoId),
        `${label} pins a different firefox ID than the manifest (${geckoId})`
      ).toBe(true);
    }
  });

  it('pins one native-host name across the extension and every installed-host source', () => {
    const backgroundSource = readFileSync(
      path.join(repoRoot, 'browser-extension', 'chrome', 'background.ts'),
      'utf8'
    );
    expect(backgroundSource).toContain(`'${HOST_NAME}'`);

    const hostJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'installation', 'com.passwordmanager.host.json'), 'utf8')
    );
    expect(hostJson.name).toBe(HOST_NAME);

    const installSh = readFileSync(path.join(repoRoot, 'installation', 'install.sh'), 'utf8');
    expect(installSh).toContain(HOST_NAME);
    const installPs1 = readFileSync(path.join(repoRoot, 'installation', 'install.ps1'), 'utf8');
    expect(installPs1).toContain(HOST_NAME);
    const tauriMain = readFileSync(
      path.join(repoRoot, 'sentinelpass-ui', 'src-tauri', 'src', 'main.rs'),
      'utf8'
    );
    expect(constantFromSource(tauriMain, 'NATIVE_HOST_NAME')).toBe(HOST_NAME);
  });
});
