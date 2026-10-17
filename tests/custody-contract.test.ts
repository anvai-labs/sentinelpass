import { describe, expect, it } from 'vitest';
import scope from '../bindings/custody/scope.golden.json';
import reference from '../bindings/custody/reference.golden.json';
import { validateCustodyScope, validateObjectRef, validateProviderCapabilities } from '../bindings/custody/v1';

describe('generated custody metadata', () => {
  it('accepts the same golden metadata as Rust and the native ABI', () => {
    expect(validateCustodyScope(scope)).toBe(true);
    expect(validateObjectRef(reference)).toBe(true);
    expect(validateProviderCapabilities({ protocol: 1, providerId: 'sentinelpass', assurance: 'unknown', userVerification: 'none', scopeEnforcement: 'app', canSync: false, canTransferToRuntime: false, canPortableExport: false, maxSecretBytes: 32 })).toBe(true);
  });
  it('rejects invalid versions, owners, purposes, fields and accessors', () => {
    for (const changed of [{ version: 2 }, { subject: '*' }, { issuer: '' }, { namespace: 'a'.repeat(129) }, { mailboxId: 'a b' }, { purpose: 'password' }, { secret: 'synthetic-canary' }]) {
      expect(validateCustodyScope({ ...scope, ...changed })).toBe(false);
    }
    expect(validateCustodyScope(null)).toBe(false);
    expect(validateCustodyScope([])).toBe(false);
    expect(validateCustodyScope(Object.create(scope))).toBe(false);
    const accessor = { ...scope };
    Object.defineProperty(accessor, 'subject', { get: () => { throw Error('must not invoke'); } });
    expect(validateCustodyScope(accessor)).toBe(false);
    expect(validateCustodyScope({ ...scope, [Symbol()]: true })).toBe(false);
  });
  it('keeps decimal versions exact across JS number boundaries', () => {
    for (const value of ['1', '9007199254740993', '18446744073709551615']) {
      expect(validateObjectRef({ ...reference, revision: value })).toBe(true);
    }
    for (const value of [1, '0', '01', '-1', '+1', '1.0', '1e1', '18446744073709551616', '', 'a'.repeat(10000)]) {
      expect(validateObjectRef({ ...reference, revision: value })).toBe(false);
      expect(validateObjectRef({ ...reference, keyEpoch: value })).toBe(false);
    }
    expect(validateObjectRef({ ...reference, bindingSha256: 'A'.repeat(64) })).toBe(false);
  });
});
