# Independent KC-03A binding preparation review

Reviewed nonshipping working-tree tools and specification over local HEAD
`732b0d883eeddfa414a0957b87906e0d088a69fa`; runtime candidate remains
`1df027932f08baabf2afebb6a0444bab867fcd12`. No repository edits, application
activation, real key use or dependency changes were performed during review.

## Finding: low, storage owner bounds exceed the consumer's accepted domain

`prototypes/custody-binding/check.mjs:35` and the Rust checker's
`Purpose::StorageRecovery` branch apply CustodyScope's 512-character subject and
mailbox bounds without the storage consumer's tighter constraints. The pinned
consumer's `lib/encryption/recovery/key-custody.ts:31` permits at most 256
characters for each of those two storage-owner fields.

Reproduction executed: clone the valid `storage-v1` metadata input, replace its
scope subject with 257 ASCII `x` characters, and invoke the current Node binding
function. It returns a commitment. Importing the actual pinned consumer's
`recoverStorageSession` and passing the same mapped owner rejects with
`recovery_owner` before parsing any envelope or recovery code. The Rust branch
has the same missing purpose-specific check by inspection.

Impact: a purported storage binding can pass both codec checks while being
unusable with the inspected recovery API. This is a preparation compatibility
gap, not a plaintext exposure or authority bypass. Unlike generic epochs above
one, this broader codec domain is not documented as a deliberate non-admitted
case. Prefer storage-specific subject/mailbox maxima of 256 plus exact-boundary
positive and 257-character negative vectors. Mail's 512-character bound remains
valid and need not change.

## Other inspected properties

- The fixed 12-string array is framed and domain-separated. Owner, namespace,
  purpose, journal, explicit profile, epoch, complete original reference text
  and both applicable fingerprints are committed. Object ID/revision exclusion
  is intentional and documented; their authenticated row/CAS binding remains
  separate from portable recovery identity.
- Compact outer JSON preserves quotes/backslashes; the mail reference uses the
  pinned consumer's canonical order and existing lowercase HTML escapes. Rust
  constructs that order explicitly. ASCII scope restrictions exclude Unicode
  normalization and JavaScript/Rust Unicode serialization ambiguity here.
- Strict canonical reference comparison rejects unknown/duplicate reference
  fields and alternate whitespace/escaping even though intermediate JSON
  parsers can collapse duplicate fields. The tools consume parsed outer fixture
  values; they are not a qualified raw JSON transport/parser.
- Mail v1 requires an absent profile field and 40-hex uppercase fingerprints;
  v2 requires the exact modern profile and 64-hex uppercase fingerprints. Storage
  requires its own profile and empty fingerprints. Actual certificate/hash and
  fingerprint relationship validation remains an explicit native proof gate.
- Decimal epochs are positive, canonical and capped at JavaScript's safe integer
  maximum, and must equal the reference epoch. Acceptance of codec epochs above
  one is explicitly distinct from current anchor admission; no finding is made
  against that intentional distinction.
- Pinned consumer `mailReference`/`canonicalReference` and storage recovery
  owner handling were inspected directly. Node source checks precede loading the
  pinned mail validator. No capability minting, ciphertext/key handling or
  runtime adapter is introduced.
- Independent current owner/journal/reference authority, separate purpose object
  IDs, recovery proof, lifecycle invalidation and migration remain required.

## Verification

- `node prototypes/custody-binding/check.mjs /private/tmp/sandesha-rust-assets-pilot-20261016`:
  **15 valid vectors, 36 negative vectors refused**. Only Node module-type
  detection warnings appeared.
- `cargo run -p sentinelpass-protocol --example check_sandesha_binding`:
  **15 valid vectors, 36 negative vectors refused**.
- Executed the 257-character storage-owner mismatch reproducer above using the
  actual consumer API; no envelope or secret was required or generated.

## Initially reviewed SHA-256

| File | SHA-256 |
| --- | --- |
| `docs/CUSTODY_BINDING_V1.md` | `16e8f3455ccfe635f16357deb508738d1b2978ea37857d2ee028b75aea1f1dbe` |
| `prototypes/custody-binding/check.mjs` | `3e2065292a4eb916424974598b648762dd41d0a7b4b5a92da8251d9c2467e7b4` |
| `prototypes/custody-binding/vectors.json` | `8066a5665f1fb268b082034f542490d25759fef3ec639799e3d5b97f36958433` |
| `sentinelpass-protocol/examples/check_sandesha_binding.rs` | `0c63ebefeb4e66ced72ad235b8ee26456d7b05fbf2c9f6c2c0e13ef09038b8ba` |

The single compatibility finding should be resolved or explicitly scoped before
freezing this preparation contract. No other blocker identified within this
metadata-only review. This is not independent validation of consumer crypto,
complete dependency provenance, platform qualification, merge or activation.

## Corrective follow-up

The storage-owner compatibility finding is resolved in the reviewed working tree.
Both checkers now reject storage subjects and mailboxes longer than 256 ASCII
bytes; existing scope validation makes Rust byte length and JavaScript string
length equivalent for these inputs. Mail's 512-byte limit is preserved. The
specification states the storage-specific limit explicitly.

The corpus now contains separate 256-character positive and 257-character
negative cases for each storage-owner field. I checked those boundary values,
the package-local vector relocation and both updated loader paths. The Rust
example's include path now stays within sentinelpass-protocol when packaged.
The CI addition invokes that example in the existing Clippy job, without a
sibling checkout or a weakened error condition. The evidence README keeps
codec conformance separate from current anchor admission, native recovery proof
and runtime authority. No further blocker found within this reviewed scope.

Reran both conformance commands: Node with the pinned Sandesha validator and
Rust each reported **17 valid vectors and 38 rejected negative vectors**.
`git diff --check` also passed. Node's existing module-type detection warnings
remain nonfatal. Reviewed the retained Node/Rust red logs for the original
storage-boundary rejection regression; their failures agree with the finding.

Corrective file SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `docs/CUSTODY_BINDING_V1.md` | `dae93950cee1a3adcfdf625d12f12280f4c4f2d7af9f3e47d254f14fd11132ca` |
| `prototypes/custody-binding/check.mjs` | `f49dc898477a98a84d092e3a5a55e2db2815484a2d295c4115f2e295c0dcd04c` |
| `sentinelpass-protocol/tests/fixtures/sandesha-custody-binding-v1.json` | `0fac21fad38ba14f4ebaa53d746128a1dc41a1dea1ad8d970ac128e5d6941d09` |
| `sentinelpass-protocol/examples/check_sandesha_binding.rs` | `cc36d1fa6898599ece2967119acc345f3db015e440c2f394b75093bf1b041bf6` |
| `docs/evidence/custody-binding-v1/README.md` | `9327ca7ea1683bbe0a9367b7771d9aedb690538e2d46841ef601d57107a3e9a0` |
| `.github/workflows/rust.yml` | `2157d1eae19c5c0a83eb1960927c67383d924cf31c31aec0b903441dd21361e1` |

This corrective acceptance is scoped to these nonshipping metadata tools and
documented encoding. It does not extend to other concurrent work or replace
exact-head CI for the eventual follow-up commit, nor authorize activation.

## Release-preparation metadata addendum

Read-only review of the release-preparation additions over local HEAD `732b0d8`:
no new blocker identified in the version/claim/provenance changes inspected.

- Cargo workspace and Tauri versions both change from 0.17.0 to 0.18.0. The
  actual Cargo.lock diff consists of exactly eight first-party package version
  replacements, with no registry dependency record change. This matches the
  separate persistence reviewer's dependency-delta assessment.
- `RELEASE_0.18.0.md` describes preparation rather than asserting publication.
  It preserves unavailable application enrollment, missing native storage and
  trusted transport, no browser/cross-device/mobile/hardware enablement, and
  separate tag-time security/platform gates. Combined-graph evidence does not
  become a shipping dependency, advisory waiver or runtime capability.
- The handback's dated acceptance update distinguishes the actual PR269 merge
  from its retained historical snapshot. The local object
  `026d772e61a17950e942f6940472f223a2172e9e` exists and identifies the PR269
  squash. The text explicitly does not claim code-owner approval. The parent's
  supplied user authorization for conditional admin merge is recorded as such,
  not represented as a technical approval generated by the checker.
- Historical `inputs-1df0279.json` is byte-identical to the prior committed
  preflight manifest. Compared source mappings: only Cargo.toml and Cargo.lock
  pins changed. Current `versionOnlyRefresh` records the old/new hashes and
  release context. The README clearly separates the refresh from historical
  runtime/performance evidence; the old candidate label is not a claim that
  the version-bumped source passed that candidate's CI.
- Recomputed source checks: all **61 pins match**, with `integrationReady` and
  `productionReady` both **false**. Binding document/checker/vector/example and
  workflow hashes remain the same as in the clean corrective review above.
- The workcard links newly frozen binding bytes and graph evidence while keeping
  full dependency adoption, native runtime, enrollment and transport gates open.

Reviewed addendum file SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `Cargo.toml` | `35cd8d8a5cdb3fc4a14670a6ec3ec996bcbcb2862af8e30b737a56b739bbd385` |
| `Cargo.lock` | `27cd090b1ab7d12ad54e2f6661950ec9e9ac500895be12ad460370e3955c38d2` |
| `sentinelpass-ui/tauri.conf.json` | `20823272345675e83cea9fc674aa444a00db4a84c9151f9d3b0afaf011c5b9fb` |
| `docs/RELEASE_0.18.0.md` | `ba8875bbcf82374311563c94668361c795e09237345ba70b4e4da59d1cd8ff2c` |
| `docs/SANDESHA_USER_KEY_CUSTODY_HANDBACK_2026-10-17.md` | `d0abbbb35ed7db0f445df975f044d55754567751c2bb44e2b2debddac6f108b0` |
| `docs/CUSTODY_KC03_WORKCARD.md` | `2db0dfd4de02cf0fb760af2e388f7d08cbe297a3933a542e004d8f238ffc778f` |
| `docs/evidence/custody-kc03-preflight/README.md` | `4d0e759aa5bed1e820b5f8b6b1378abe552b4adc913305d213d0b3be78db66ae` |
| `docs/evidence/custody-kc03-preflight/inputs.json` | `2035fd5d6e1f71e8162d2a1de6ffb9fedb321f487628fe6f2e316e02f89cded5` |
| `docs/evidence/custody-kc03-preflight/inputs-1df0279.json` | `3099936dedff3ce48cbd025b01368b89abbd1867ab562029aa731944dc216c04` |

This addendum does not report new exact-head CI completion or completed release
publication. The eventual committed follow-up and promotion must independently
meet the user's stated clean-review/green-CI conditions. No runtime activation
authority is manufactured by the reviewed metadata.
