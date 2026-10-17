// Nonshipping binding conformance. Reuses pinned consumer validation, not crypto.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateCustodyScope } from '../../bindings/custody/v1.ts';
import { checkSources } from '../../scripts/check-custody-handoff.mjs';

const root = resolve(import.meta.dirname, '../..');
const consumer = process.argv[2];
if (!consumer) throw Error('usage: node prototypes/custody-binding/check.mjs SANDESHA_ROOT');
const pins = JSON.parse(readFileSync(resolve(root, 'docs/evidence/custody-kc03-preflight/inputs.json')));
if (checkSources({ sentinelpass: root, sandesha: consumer }, pins).sourceCheck !== 'pass') {
  throw Error('source drift; consumer code was not loaded');
}
const { mailReference, canonicalReference } = await import(pathToFileURL(resolve(consumer, 'lib/encryption/key-reference.ts')));
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).sort().join(',') === keys.split(',').sort().join(',');
function binding(v) {
  if (!exact(v, 'scope,journalId,profile,keyEpoch,reference,primaryFingerprint,encryptionFingerprint')
    || !validateCustodyScope(v.scope) || v.scope.namespace !== 'sandesha'
    || typeof v.journalId !== 'string' || !/^[a-f0-9]{32}$/.test(v.journalId)
    || typeof v.keyEpoch !== 'string' || !/^[1-9][0-9]{0,15}$/.test(v.keyEpoch)
    || BigInt(v.keyEpoch) > 9007199254740991n
    || typeof v.reference !== 'string' || Buffer.byteLength(v.reference) > 12288) throw Error('binding');
  const r = JSON.parse(v.reference), epoch = Number(v.keyEpoch);
  if (v.scope.purpose === 'mail-recovery') {
    const owner = { issuer: v.scope.issuer, subject: v.scope.subject, mailbox: v.scope.mailboxId };
    const ref = mailReference(r, owner);
    const profile = ref.header.version === 1 ? 'openpgp-v4-ecc' : 'openpgp-v6-25519';
    const size = ref.header.version === 1 ? 40 : 64;
    if (v.profile !== profile || ref.header.epoch !== epoch || canonicalReference(ref) !== v.reference
      || ![v.primaryFingerprint, v.encryptionFingerprint].every(fp => typeof fp === 'string'
        && new RegExp(`^[A-F0-9]{${size}}$`).test(fp))) throw Error('binding');
  } else {
    if (v.scope.subject.length > 256 || v.scope.mailboxId.length > 256
      || v.profile !== 'sandesha-recipient-trust-storage-v1'
      || v.primaryFingerprint !== '' || v.encryptionFingerprint !== ''
      || !exact(r, 'keyId,epoch,sha256') || typeof r.keyId !== 'string'
      || !/^[a-f0-9]{32}$/.test(r.keyId) || r.epoch !== epoch
      || typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)
      || JSON.stringify({ keyId: r.keyId, epoch: r.epoch, sha256: r.sha256 }) !== v.reference) throw Error('binding');
  }
  const preimage = JSON.stringify(['sandesha.personal-custody.binding.v1', 'sandesha',
    v.scope.issuer, v.scope.subject, v.scope.mailboxId, v.scope.purpose, v.journalId,
    v.profile, v.keyEpoch, v.reference, v.primaryFingerprint, v.encryptionFingerprint]);
  if (Buffer.byteLength(preimage) > 16384) throw Error('binding');
  return { preimage, sha256: createHash('sha256').update(preimage).digest('hex') };
}
const vectors = JSON.parse(readFileSync(resolve(root, 'sentinelpass-protocol/tests/fixtures/sandesha-custody-binding-v1.json')));
for (const vector of vectors.valid) {
  const result = binding(vector.input);
  if (result.preimage !== vector.preimage || result.sha256 !== vector.sha256) throw Error(`vector mismatch: ${vector.name}`);
}
for (const vector of vectors.invalid) {
  let refused = false;
  try { binding(vector.input); } catch { refused = true; }
  if (!refused) throw Error(`accepted invalid vector: ${vector.name}`);
}
console.log(`Node + pinned Sandesha validator: ${vectors.valid.length} valid, ${vectors.invalid.length} refused; no runtime authority`);
