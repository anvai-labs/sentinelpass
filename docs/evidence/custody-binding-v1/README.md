# Sandesha binding v1 conformance

2026-10-17. [Frozen encoding](../../CUSTODY_BINDING_V1.md). This qualifies public
metadata bytes only, not native enrollment, current-key authority or crypto proof.
The producer and consumer inputs remain those in the KC-03 preflight manifest;
all61 pins match despite unrelated consumer commits after the recorded snapshot.

Seventeen positive and38 negative synthetic metadata vectors are shared by an
independent Rust example and a Node checker using the actual pinned Sandesha
`mailReference`/`canonicalReference` functions and generated custody scope validator.
Expected bytes/hashes were initially calculated with Python standard-library
JSON/SHA-256, separately from both checkers. No keys or recovery secrets appear.

Cases cover both mail profiles, separate storage purpose, escaping, exact owner
and reference fields, fingerprint representation, safe numeric bounds, canonical
key IDs, duplicate/extra fields, changed epoch/profile, and maximum identity sizes.
Distinct valid owner/mailbox/journal/reference/fingerprint inputs have distinct
expected hashes. Epoch>1 vectors qualify encoding only; current consumer anchor
admission still requires epoch1. Representation is not proof that fingerprints
match a certificate; the eventual recovery adapter must establish that match.

Independent review found that initial storage validation accepted257..512-byte
subject/mailbox fields while the actual consumer storage validator permits256.
Both checkers now apply that purpose-specific bound, retaining mail's512 limit.
Failing Node/Rust regressions and corrected output are recorded here. The Node
loader's typeless-package warnings are retained; no package module mode was changed.

```sh
node prototypes/custody-binding/check.mjs /path/to/sandesha-checkout
cargo run -p sentinelpass-protocol --example check_sandesha_binding
cargo clippy -p sentinelpass-protocol --example check_sandesha_binding -- -D warnings
```

Rust conformance runs in CI without a sibling checkout. The Node comparison is
local cross-repository evidence and refuses source drift before loading the
consumer validator. Vectors are packaged within the protocol crate so its example
does not depend on files outside the crate. No protocol version, production
constructor, application lockfile, custody feature or browser bridge changed.
