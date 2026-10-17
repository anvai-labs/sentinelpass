// Synthetic receipts. --storage uses temporary vaults with random loaded keys.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { platform, release, arch } from 'node:os';
import { resolve } from 'node:path';
const destination = process.argv[2];
if (!destination) throw Error('usage: node scripts/qualify-custody.mjs OUTPUT.json [--storage]');
const storage = process.argv[3] === '--storage';
if (process.argv[3] && !storage) throw Error('unknown qualification mode');
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) throw Error(`${command} failed: ${result.stderr}\n${result.stdout.slice(-16000)}`);
  return result.stdout;
}
const build = run('cargo', ['test', '-p', 'sentinelpass-core', '--lib', '--no-run', '--message-format=json']);
const artifact = build.split('\n').filter(Boolean).map(line => JSON.parse(line))
  .find(message => message.reason === 'compiler-artifact' && message.target.name === 'sentinelpass_core' && message.executable);
if (!artifact) throw Error('no core test artifact');
const start = performance.now();
const test = storage ? 'custody::personal::tests::qualification_storage' : 'custody::tests::qualification';
const output = run(artifact.executable, [test, '--exact', '--ignored', '--nocapture', '--test-threads=1']);
const processWallMs = performance.now() - start;
const cohorts = [...output.matchAll(/CUSTODY_RECEIPT (\{[^\n]+\})/g)].map(match => JSON.parse(match[1]));
if (cohorts.length !== 2) throw Error('missing timing cohorts');
for (const cohort of cohorts) {
  if (cohort.p95TrialMaximumMs > 100 || cohort.rssIncrementBytes > 16 * 1024 * 1024 || cohort.liveHandlesAfterClose !== 0) throw Error('frozen budget failed');
}
const files = [
  'Cargo.lock', 'sentinelpass-protocol/src/custody.rs', 'sentinelpass-core/src/custody/mod.rs',
  'Cargo.toml', 'sentinelpass-core/Cargo.toml', 'sentinelpass-mobile-bridge/src/abi.rs',
  'sentinelpass-core/src/custody/personal.rs', 'sentinelpass-core/src/custody/personal/tests.rs',
  'sentinelpass-core/src/custody/workers.rs',
  'sentinelpass-core/src/vault/custody_ops.rs', 'sentinelpass-core/src/vault/custody_tests.rs',
  'sentinelpass-core/src/vault/content_guard.rs', 'sentinelpass-core/src/vault/activation_ops.rs',
  'sentinelpass-core/src/vault/rekey_ops.rs', 'sentinelpass-core/src/database/schema.rs',
  'sentinelpass-core/src/database/migrations.rs', 'sentinelpass-core/src/database/fixtures.rs',
  'sentinelpass-core/src/crypto/aad.rs', 'sentinelpass-core/src/daemon/vault_state.rs',
  'sentinelpass-core/src/daemon/ipc/stepup.rs', 'sentinelpass-core/src/audit.rs',
  'sentinelpass-protocol/examples/generate_custody_bindings.rs',
  'sentinelpass-protocol/examples/custody_validator.ts.in',
  'sentinelpass-protocol/examples/custody_ports.ts.in',
  'sentinelpass-protocol/tests/custody_contract.rs',
  'sentinelpass-mobile-bridge/tests/custody_contract.rs',
  'sentinelpass-mobile-bridge/tests/jni_contract.rs',
  'tests/custody-contract.test.ts',
  'bindings/custody/scope.array.invalid.json',
  'bindings/custody/reference.array.invalid.json',
  'bindings/custody/capabilities.array.invalid.json',
  'tests/native/custody/main.swift',
  'tests/native/custody/com/sentinelpass/custody/CustodyContract.java',
  'sentinelpass-core/src/custody/synthetic.rs', 'sentinelpass-core/src/custody/tests.rs',
  'sentinelpass-mobile-bridge/src/custody.rs', 'sentinelpass-mobile-bridge/src/ffi.rs',
  'sentinelpass-mobile-bridge/src/jni.rs', 'bindings/custody/v1.ts',
  'bindings/custody/CustodyContract.swift',
  'android/SentinelPass/app/src/main/java/com/sentinelpass/custody/CustodyContract.kt',
  'sentinelpass-mobile-bridge/include/sentinelpass_bridge.h',
  'scripts/qualify-custody.mjs'
];
const sha256 = file => createHash('sha256').update(readFileSync(file)).digest('hex');
const receipt = {
  contract: 1, status: storage ? 'synthetic-native-storage-only' : 'synthetic-native-only', sourceBase: run('git', ['rev-parse', 'HEAD']).trim(),
  collectedAt: new Date().toISOString(), platform: platform(), release: release(), arch: arch(),
  rustc: run('rustc', ['--version']).trim(), processWallMs,
  processWallScope: 'fresh test process, includes all trials; excludes cargo build; not device/app startup',
  artifactSha256: sha256(artifact.executable),
  sourceSha256: Object.fromEntries(files.map(file => [file, sha256(file)])), cohorts,
};
mkdirSync(resolve(destination, '..'), { recursive: true });
writeFileSync(destination, JSON.stringify(receipt, null, 2) + '\n');
console.log(`Custody synthetic receipt saved: ${destination}`);
