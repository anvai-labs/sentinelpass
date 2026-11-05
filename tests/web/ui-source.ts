import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Shared plumbing for the source-anchor test convention (see
 * tauri-capabilities.test.ts): `app.ts` and friends are not importable
 * under this suite's node environment, so gates read the frontend
 * sources as text instead.
 */

/** Repo root resolved from this suite's location (tests/web → repo). */
export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Read one repo file as text (segments are joined under the repo root). */
export function readRepoFile(...segments: string[]): string {
  return readFileSync(path.join(repoRoot, ...segments), 'utf8');
}
