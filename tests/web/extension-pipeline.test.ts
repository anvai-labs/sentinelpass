import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const chromeDir = path.join(repoRoot, 'browser-extension', 'chrome');
const firefoxDir = path.join(repoRoot, 'browser-extension', 'firefox');

function sha256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

describe('extension single-source pipeline (WBS-717)', () => {
  it('keeps ONE set of TypeScript sources (no per-target .ts copies)', () => {
    // The canonical sources live in chrome/; firefox/ carries only build
    // outputs. A firefox/*.ts copy is exactly the TD-CLIENT-08 drift trap.
    const firefoxSources = readdirSync(firefoxDir).filter((f) => f.endsWith('.ts'));
    expect(firefoxSources, `stale firefox sources: ${firefoxSources.join(', ')}`).toEqual([]);
    expect(existsSync(path.join(chromeDir, 'content.ts'))).toBe(true);
    expect(existsSync(path.join(chromeDir, 'background.ts'))).toBe(true);
  });

  it('ships byte-identical artifacts to chrome/ and firefox/', () => {
    const chromeArtifacts = readdirSync(chromeDir).filter((f) => f.endsWith('.js'));
    expect(chromeArtifacts.length).toBeGreaterThan(0);
    for (const artifact of chromeArtifacts) {
      const chrome = readFileSync(path.join(chromeDir, artifact));
      const firefox = readFileSync(path.join(firefoxDir, artifact));
      expect(sha256(firefox), `${artifact} drifted between targets`).toBe(sha256(chrome));
    }
  });

  it('rebuilds every checked-in artifact byte-exactly (canonical pipeline)', () => {
    const distDir = mkdtempSync(path.join(tmpdir(), 'ext-pipeline-'));
    try {
      const emit = spawnSync(
        path.join(repoRoot, 'node_modules', '.bin', 'tsc'),
        ['-p', path.join(repoRoot, 'tsconfig.extension.json'), '--outDir', distDir],
        { encoding: 'utf8' }
      );
      const emitted = existsSync(distDir)
        ? readdirSync(distDir).filter((f) => f.endsWith('.js'))
        : [];
      expect(emitted.length, 'the pipeline emitted no artifacts').toBeGreaterThan(0);
      void emit;

      for (const artifact of emitted) {
        const fresh = readFileSync(path.join(distDir, artifact));
        const checkedInChrome = readFileSync(path.join(chromeDir, artifact));
        const checkedInFirefox = readFileSync(path.join(firefoxDir, artifact));
        const digest = sha256(fresh).slice(0, 12);
        expect(
          sha256(checkedInChrome),
          `chrome/${artifact} does not match a fresh pipeline build (${digest}); run \`npm run ext:build\``
        ).toBe(sha256(fresh));
        expect(
          sha256(checkedInFirefox),
          `firefox/${artifact} does not match a fresh pipeline build (${digest}); run \`npm run ext:build\``
        ).toBe(sha256(fresh));
      }
    } finally {
      rmSync(distDir, { recursive: true, force: true });
    }
  });
});
