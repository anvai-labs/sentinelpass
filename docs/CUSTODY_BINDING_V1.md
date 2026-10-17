# Sandesha custody binding v1 — qualification contract

Frozen 2026-10-17 for KC-03A. Public metadata only. This commitment detects
substitution; it does not grant authority, establish current references, verify
fingerprints or implement a provider. The existing custody protocol stays v1.
Production adoption requires the native adapter review in CUSTODY_KC03_WORKCARD.md.

`ObjectRef.bindingSha256` is lowercase SHA-256 of the UTF-8 encoding of this
12-element JSON array, with every element a string:

```text
[
  "sandesha.personal-custody.binding.v1",  // domain and encoding version
  "sandesha",                            // fixed application namespace
  issuer, subject, mailboxId,
  purpose,                               // mail-recovery OR storage-recovery
  journalId,                             // 32 lowercase hex characters
  profile,                               // explicit mapping below
  keyEpoch,                              // positive canonical decimal string
  canonicalRecoveryReference,             // JSON text encoded as one string
  primaryFingerprint, encryptionFingerprint
]
```

Serialize compactly with no whitespace, BOM or newline. Outer JSON uses standard
string escapes for quote/backslash; do not HTML-escape `<`, `>` or `&` in outer
strings. Reference text is already canonical and its existing escapes are data:
outer JSON escapes its backslashes without decoding or normalizing them. Hash
the UTF-8 bytes, not UTF-16 code units or a JSON object with sortable properties.
The maximum preimage is16KiB. Reject rather than truncate.

Scope must satisfy the existing `CustodyScope` validator, version1 and namespace
`sandesha`. Mapping is exact: mail owner `issuer/subject/mailbox` maps to
`issuer/subject/mailboxId`; storage owner `authority` maps to issuer. No case,
URL, Unicode or whitespace normalization. Intersection with custody's ASCII/no-*
identity rules is deliberate; a consumer identity outside it is unsupported,
never silently renamed.
Storage subject and mailbox are further limited to256 ASCII bytes, matching the
existing storage session's owner validator; mail retains its512-byte limits.

`keyEpoch` must be in1..9007199254740991, with no leading zeros/sign/exponent,
and equal the numeric epoch in the reference. This is a codec boundary, not
permission to bypass Sandesha's current anchor policy (which requires epoch1).
Object revision remains an independent u64 decimal revision. Object ID/revision
are bound by SentinelPass's authenticated row and are not part of this portable
recovery commitment; moving an unchanged secret to a separately authorized
provider must not change its original recovery reference.

| Purpose | Profile | Reference | Fingerprints |
| --- | --- | --- | --- |
| mail-recovery | openpgp-v4-ecc | Existing v1 mail reference; profile field absent | Two uppercase40-hex strings |
| mail-recovery | openpgp-v6-25519 | Existing v2 mail reference; explicit same profile | Two uppercase64-hex strings |
| storage-recovery | sandesha-recipient-trust-storage-v1 | Compact JSON in order keyId, epoch, sha256 | Both empty strings |

Mail reference text is exactly Sandesha `canonicalReference(mailReference(...))`:
header order version,purpose,owner,epoch,keyId,certificateSha256, then profile
for v2; owner order issuer,subject,mailbox; outer order header,envelopeSha256.
Its existing `<>&` escapes remain lowercase `\u003c`, `\u003e`, `\u0026`.
Header purpose is sandesha-mail-key. Key ID is canonical unpadded base64url16
bytes. Digests are lowercase64-hex. Unknown/null profile, extra fields, duplicate
fields, noncanonical text, wrong owner/purpose and mismatched epoch refuse.
Storage key ID is lowercase32-hex; sha256 is lowercase64-hex. The existing
storage envelope/AAD/version and recovery secret are unchanged.

Fingerprints must come from independently approved current public-certificate
inspection and match the exact certificate hash in the recovery reference.
The codec only checks representation; synthetic vectors are not certificates or
proof of possession. The native recovery adapter must perform the actual match.
Storage commitment binds the owner and journal even though its reference has no
owner field. Independent current authority must bind that same journal and both
references before acquisition and again after recovery.

Separate purpose and object IDs are required for mail and storage enrollment.
The codec does not allocate IDs or enforce multi-object admission. The recovery
kit, secrets, ciphertext envelopes, passwords and private keys never enter the
preimage. Reference metadata and fingerprints may still identify an account;
do not treat a digest as anonymization or log these inputs in product flows.

Qualification vectors live in `sentinelpass-protocol/tests/fixtures/` so the Rust
example remains self-contained when the protocol crate is packaged. The independent
Node check is in `prototypes/custody-binding/`. These are nonshipping tools and grant
no runtime capability. Changing this encoding requires a new domain/version and
migration review, not silently rewriting existing bindings.
