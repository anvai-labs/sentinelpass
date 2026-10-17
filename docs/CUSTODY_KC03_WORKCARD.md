# KC-03: native recovery integration preparation

Frozen preparation scope, 2026-10-17. Producer candidate `1df0279` (PR269),
consumer snapshot `3b5ca0258d8644c797b160678f32e24b1885280c`. This workcard
prepares the next synthetic integration; it does not accept KC-01/02 or enable
an application adapter. See the [original contract](SANDESHA_USER_KEY_CUSTODY_CONTRACT_2026-10-16.md)
and [pinned inputs](evidence/custody-kc03-preflight/inputs.json).

## Current and target boundaries

```text
CURRENT
SentinelPass temporary vault                Sandesha native Rust
  exact-object lease                         recover(envelope, secret,
        |                                      public, authority, now)
  test-only native receiver     X missing X          |
        |                                          v
  zeroizing recovery value                  RecoveredMailKey
                                            public / seal / open / dispose

Sandesha Settings -> Worker mail recovery + WebCrypto storage recovery
                 X no native custody bridge X

NEXT SAME-PROCESS PROOF (synthetic, not an IPC adapter)
  independently supplied current owner/reference/profile
                         |
  temporary vault -> exact lease -> private Rust recovery adapter
                         |                   |
                 secret consumed       recover existing envelope
                 inside Rust only      prove same public certificate
                                             |
                              bounded, lifecycle-owned key context
                              no private-key/recovery-byte getter

LATER MACOS PILOT
  trusted personal-vault UI + fresh password + authenticated application peer
                         |
  bounded native registration and reviewed connection-bound transfer
                         |
  same recovery proof + lifecycle fencing + destination verification
```

## Reuse and incompatibilities established by source inspection

| Boundary | Existing implementation | Required next work |
| --- | --- | --- |
| Mail recovery | Sandesha `prototypes/rust-mail-custody/src/recovery.rs::recover` authenticates original envelope/reference, imports the existing key and exercises sign/encrypt/decrypt proof. | Reuse this function in an isolated native adapter; compare returned public bytes and both fingerprints against independent current authority. Do not generate a replacement identity. |
| Native custody | SentinelPass `custody/personal.rs` owns encrypted objects and exact approvals; constructors are private/test-only. | A same-process test seam may remain test-only. Production needs separate trusted enrollment and receiver registration, not public constructors or a callback returning bytes. |
| Storage recovery | Sandesha `lib/encryption/recovery/key-custody.ts` unwraps a WebCrypto storage key from the independent `SK1` recovery value. | No equivalent native storage session was identified in the inspected Rust crate. A mail-only proof cannot claim both-purpose integration. Freeze a native storage port preserving existing AAD/envelope bytes before implementing it. |
| Application facade | `MailKeySession.recover` currently takes a `Uint8Array`; storage recovery accepts a code string. | Keep the recovery-kit API intact. Add a separately qualified custody operation whose receiver owns the secret; never implement it by returning the vault secret to these application methods. |
| macOS identity | Current Unix transport uses `getpeereid`: UID/GID, no PID or application signing identity. | Specify and qualify application-peer admission before the inter-application pilot. Same UID, claimed application name, OIDC and service tokens are insufficient substitutes. |
| Dependencies | SentinelPass workspace baseline Rust1.89; inspected Sandesha native crate requires Rust1.98.1 and a vendored experimental OpenPGP import feature. | Start with a standalone, nonshipping qualification workspace. Review the combined resolved graph, sources, licenses, toolchain and advisory exposure before linking; do not insert Sandesha's graph into the shipping workspace as a shortcut. |

The native mail recovery function exists even though the integrated Settings flow
uses a Worker. The earlier high-level diagram must not be read as absence of native
crypto. Conversely, generated metadata ABI validation supplies no secret transport.

## Ordered slices and exit evidence

### KC-03A: reproducible handback and binding design

Deliver source pins and an offline drift check; preserve the KC-01/02 evidence
and review reports. Check status in GitHub separately: matching bytes are not
passing CI, code-owner approval or merge. Reconcile Sandesha's proposed KC-01/02
row only through a reviewed consumer handback; this work does not edit an active
sibling checkout.

Before any combined native runtime work, freeze golden vectors for:

- Owner: `issuer/subject/mailbox` maps exactly to custody
  `issuer/subject/mailboxId`; storage's `authority` means the same issuer.
  Namespace is a fixed application namespace, never caller-selected authority.
- Two distinct purposes and object IDs. A custody object revision is independent
  of the mailbox key epoch and is not an OpenPGP fingerprint.
- `bindingSha256`: a versioned, domain-separated, canonical commitment covering
  the exact owner, purpose, existing recovery reference, profile and public-key
  expectations where applicable. The concrete encoding is still a required
  design/vector gate; neither repository currently defines this integration mapping.
- Numeric intersection: custody decimal u64 values must not be silently coerced
  into Sandesha's JavaScript-safe epochs. Reject unrepresentable values.
- Mail v1/compat and v2/modern profiles preserve their original bytes. Storage
  has its own version/reference and must not inherit the mail profile implicitly.

### KC-03B: isolated same-process native proof

Entry: reviewed KC-01/02 handback, frozen mapping vectors and approved combined
dependency/source inventory. Use ephemeral synthetic keys and temporary vaults.
Do not move production constructors or advertise feature bit8 to make a test work.

Positive path: store independent secrets, authorize exact read, deliver only into
the private native crypto context, recover the original envelope, prove possession,
and verify original public certificate plus primary/encryption fingerprints. The
storage path must separately recover the existing storage key and authenticate a
known checkpoint/journal without changing its format. A mail-only intermediate
receipt must say so explicitly.

Fresh negative cases must reach the intended boundary: wrong owner/mailbox/purpose,
changed profile, swapped envelope/public certificate, stale reference or epoch,
OIDC-only admission, empty-vault reset, forged receiver, cross-session delivery,
expired/replayed approval, lock/revoke/logout/account change, cancellation and late
completion. Retain failed-before-fix evidence for defects discovered during review.

Recovered-key lifetime belongs to the native adapter: closing a recovery lease
alone cannot erase an already imported key. Check independent current authority
before and after work; dispose the key context on lifetime loss, and prohibit
copying it into an untracked application handle. No arbitrary closure/callback may
receive recovery bytes. Reopening requires fresh authority and a new proof.

Migration uses separate steps: copy with approval, independently reopen and verify
the destination, recheck current authority, then separately approve source removal.
Failed or uncertain destination verification leaves the source and recovery kit
intact. No cross-provider transaction or rollback is claimed; crash recovery must
inspect authenticated state and require fresh approval, never replay a mutation.

Keep the existing warm-delivery budgets (p95<=100ms, incremental RSS<=16MiB,
8 leases, zero handles after close). Measure native recovery proof separately,
including full runtime startup and key import; freeze its budgets before timing.
Report KDF/user interaction separately. Do not reuse Worker timings as native proof.

### KC-03C: macOS inter-application pilot

Entry: accepted same-process proof and a separately reviewed transport/UI design.
Choose the actual application identity mechanism, personal-vault selection,
trusted password prompt, source/receiver enrollment bounds, binary frame limits,
connection lifetime and revocation ordering before implementing a new IPC route.
The current macOS transport does not establish signing identity. Kernel-derived
evidence must be obtained by the accept path, never deserialized from the client.

Pending source values and approvals need explicit count/byte/lifetime bounds.
KC-02's worker/lease bounds do not qualify admission queues. Authorization must
bind vault, peer connection, operation, scope, expected/target reference and
source/receiver registration. Disconnect/restart invalidates authority; document
the cross-process revocation race and already-released-key limitation.

Test two real processes and an impostor; wrong peer/connection, reconnect/replay,
approval substitution, cancellation during native work, late completion and
cleanup must fail closed. Browser transfer, OS hardware protection, cross-device
bootstrap, mobile relay and production activation remain independent later gates.

## Completion accounting

KC-03A preparation is useful even while PR269 waits for CI/code-owner approval.
It does not satisfy KC-03B/C entry gates. No merge, release, real-key enrollment,
production configuration or sibling activation follows from this workcard.
