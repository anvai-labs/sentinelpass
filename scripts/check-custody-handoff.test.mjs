import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, win32, posix } from 'node:path';
import { checkSources, isWithinRoot } from './check-custody-handoff.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'custody-handoff-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, 'source'), 'synthetic source');
  const hash = createHash('sha256').update('synthetic source').digest('hex');
  return {
    root, roots: { sentinelpass: root, sandesha: root },
    manifest: { version: 1, sources: { sentinelpass: { source: hash }, sandesha: { source: hash } } },
  };
}

test('matching source never grants integration or production readiness', t => {
  const f = fixture(t), result = checkSources(f.roots, f.manifest);
  assert.equal(result.sourceCheck, 'pass');
  assert.equal(result.integrationReady, false);
  assert.equal(result.productionReady, false);
});
test('changed source and missing source fail the check', t => {
  const f = fixture(t);
  writeFileSync(join(f.root, 'source'), 'changed');
  assert.equal(checkSources(f.roots, f.manifest).sourceCheck, 'fail');
  rmSync(join(f.root, 'source'));
  assert.equal(checkSources(f.roots, f.manifest).sourceCheck, 'fail');
});
test('empty pins and unknown manifest versions are refused', t => {
  const f = fixture(t);
  f.manifest.version = 2;
  assert.throws(() => checkSources(f.roots, f.manifest));
  f.manifest.version = 1;
  f.manifest.sources.sandesha = {};
  assert.throws(() => checkSources(f.roots, f.manifest));
});
test('path traversal and out-of-checkout symlinks are refused', t => {
  const f = fixture(t), outside = fixture(t);
  const hash = f.manifest.sources.sandesha.source;
  f.manifest.sources.sandesha = { '../source': hash };
  assert.throws(() => checkSources(f.roots, f.manifest));
  symlinkSync(join(outside.root, 'source'), join(f.root, 'linked'));
  f.manifest.sources.sandesha = { linked: hash };
  assert.throws(() => checkSources(f.roots, f.manifest));
});
test('containment refuses Windows parent paths and different drives', () => {
  assert.equal(isWithinRoot('C:\\checkout', 'C:\\outside\\source', win32), false);
  assert.equal(isWithinRoot('C:\\checkout', 'D:\\source', win32), false);
  assert.equal(isWithinRoot('C:\\checkout', 'C:\\checkout\\source', win32), true);
  assert.equal(isWithinRoot('/checkout', '/outside/source', posix), false);
  assert.equal(isWithinRoot('/checkout', '/checkout/source', posix), true);
});
