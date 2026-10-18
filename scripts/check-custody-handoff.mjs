// Offline source-drift check, not runtime qualification or release authority.
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path, { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifestPath = 'docs/evidence/custody-kc03-preflight/inputs.json';

export function isWithinRoot(root, target, paths = path) {
  const inside = paths.relative(root, target);
  return !paths.isAbsolute(inside) && inside.split(/[\\/]/)[0] !== '..';
}

export function checkSources(roots, manifest) {
  if (manifest.version !== 1) throw Error('unsupported manifest');
  const checks = [];
  for (const name of ['sentinelpass', 'sandesha']) {
    const root = realpathSync(roots[name]);
    const pins = manifest.sources[name];
    if (!pins || Object.keys(pins).length === 0) throw Error('missing source pins');
    for (const [file, expected] of Object.entries(pins)) {
      if (isAbsolute(file) || file.split(/[\\/]/).includes('..')
          || !/^[a-f0-9]{64}$/.test(expected)) throw Error('invalid source pin');
      let status = 'missing';
      try {
        const actualPath = realpathSync(resolve(root, file));
        if (!isWithinRoot(root, actualPath)) {
          throw Error('source outside checkout');
        }
        const actual = createHash('sha256').update(readFileSync(actualPath)).digest('hex');
        status = actual === expected ? 'match' : 'drift';
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      checks.push({ repository: name, file, status });
    }
  }
  return {
    version: 1,
    sourceCheck: checks.every(check => check.status === 'match') ? 'pass' : 'fail',
    scope: 'pinned source bytes only; no CI, approval, crypto or platform execution',
    integrationReady: false,
    productionReady: false,
    checks,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [consumer, flag, output, ...extra] = process.argv.slice(2);
    if (!consumer || (flag && (flag !== '--output' || !output)) || extra.length) {
      throw Error('usage: node scripts/check-custody-handoff.mjs SANDESHA_ROOT [--output REPORT.json]');
    }
    const manifest = JSON.parse(readFileSync(resolve(repository, manifestPath), 'utf8'));
    const report = checkSources({ sentinelpass: repository, sandesha: consumer }, manifest);
    const json = JSON.stringify(report, null, 2) + '\n';
    if (output) writeFileSync(output, json, { flag: 'wx' });
    else process.stdout.write(json);
    process.exitCode = report.sourceCheck === 'pass' ? 0 : 1;
  } catch (error) {
    // No source contents or underlying filesystem diagnostics in this output.
    console.error(error.message.startsWith('usage:') ? error.message : 'custody handoff check failed');
    process.exitCode = 1;
  }
}
