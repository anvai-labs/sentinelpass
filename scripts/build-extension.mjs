// Canonical browser-extension build pipeline (WBS-717).
//
// The Chrome and Firefox extensions share ONE set of TypeScript sources and
// ONE transpile step; the checked-in `chrome/*.js` and `firefox/*.js`
// artifacts are byte-identical build outputs of this script. Never
// hand-edit a `.js` artifact: edit the `.ts` source and run
// `npm run ext:build`.
//
// The pipeline is deliberately boring: the repo-local TypeScript compiler
// emits with `tsconfig.extension.json`, and the emitted `.js` files are
// copied into both target directories. Byte-parity between the two targets
// is asserted here so Chrome/Firefox cannot drift (TD-CLIENT-08).
//
// ONE exception to plain tsc emit: `content.js` is a CONTENT script, and
// content scripts are CLASSIC scripts — ES module syntax (`import`) throws
// a SyntaxError and the script silently never runs (WBS-719 discovered the
// injection had been broken exactly this way). The content entry is
// therefore BUNDLED with esbuild into a single classic IIFE. The other
// modules (background service worker, popup) are ES modules by manifest
// declaration and keep tsc emit.

import { spawnSync } from 'node:child_process';
import * as esbuild from 'esbuild';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(repoRoot, 'browser-extension', 'dist', 'extension');
const targets = [
  join(repoRoot, 'browser-extension', 'chrome'),
  join(repoRoot, 'browser-extension', 'firefox'),
];

function fail(message) {
  console.error(`[ext:build] ${message}`);
  process.exit(1);
}

// 1. Emit the shared sources through the repo-local TypeScript compiler.
const tscBin = join(repoRoot, 'node_modules', '.bin', 'tsc');
if (!existsSync(tscBin)) {
  fail('TypeScript not found — run `npm install` first.');
}

rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });

const emit = spawnSync(tscBin, ['-p', join(repoRoot, 'tsconfig.extension.json')], {
  stdio: 'inherit',
});
// tsc exits non-zero on type-level diagnostics but still emits the `.js`
// artifacts (the historical pipeline behavior). Type ERRORS are gated by
// `npm run web:typecheck` in CI; this script only requires artifacts.
const emitted = readdirSync(distDir).filter((f) => f.endsWith('.js'));
if (emitted.length === 0) {
  fail(emit.status !== 0
    ? 'TypeScript emit failed and produced no artifacts — fix the sources.'
    : 'TypeScript emitted no .js files — check tsconfig.extension.json include.');
}
if (emit.status !== 0) {
  console.warn('[ext:build] warning: tsc reported type diagnostics; run `npm run web:typecheck`.');
}

// 1b. Bundle the content script into a single classic IIFE: content
// scripts are classic scripts, and ES `import` syntax throws a
// SyntaxError there (the injection was silently broken this way — found
// by the WBS-719 suite).
await esbuild.build({
  entryPoints: [join(repoRoot, 'browser-extension', 'chrome', 'content.ts')],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  outfile: join(distDir, 'content.js'),
  logLevel: 'silent',
});

const digests = new Map();
for (const target of targets) {
  // Review F7: remove stale artifacts a previous build left behind (a
  // renamed/removed module would otherwise keep shipping its old .js).
  for (const existing of readdirSync(target)) {
    if (existing.endsWith('.js') && !emitted.includes(existing)) {
      rmSync(join(target, existing), { force: true });
    }
  }
  cpSync(distDir, target, {
    recursive: true,
    filter: (src) => src === distDir || src.endsWith('.js'),
    force: true,
  });
}

// 3. Assert byte-parity across targets (Chrome/Firefox drift gate).
for (const file of emitted) {
  const digest = createHash('sha256');
  for (const target of targets) {
    digest.update(readFileSync(join(target, file)));
  }
  digests.set(file, digest.digest('hex'));
}
for (const [file, digest] of digests) {
  // Two targets, one hash input each: recompute pairwise equality instead
  // of comparing hex strings concatenated (which is order-dependent).
  const contents = targets.map((t) => readFileSync(join(t, file)));
  const identical = contents.every((c) => c.equals(contents[0]));
  const label = `${file} sha256:${digest.slice(0, 16)}`;
  if (!identical) {
    fail(`artifact drift detected: ${label} differs between targets`);
  }
  console.log(`[ext:build] ${label} -> chrome/ + firefox/ (byte-identical)`);
}

console.log(`[ext:build] ${emitted.length} shared modules built for ${targets.length} targets.`);
