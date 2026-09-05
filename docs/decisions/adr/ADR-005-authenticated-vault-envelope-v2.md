# ADR-005: Authenticated Vault Envelope v2

| Field | Value |
|-------|-------|
| Status | Accepted (rev 4, 2026-09-04 — owner decision after three adversarial review rounds) |
| Date | 2026-09-04 |
| Owners | Security lead, core maintainer |
| Related | ADR-004; ADR-006; ADR-008 |

## Summary

Replace context-free field ciphertexts and opaque Rust-specific persistence with a
versioned, bounded envelope whose semantic identity is authenticated using AAD.

## Context

Current AES-GCM tags authenticate ciphertext but do not bind a blob to its vault,
entry, type, or field. A storage writer can exchange otherwise valid ciphertexts.
Sync metadata has the same gap. Long-lived `bincode` values also lack a durable,
language-neutral format contract.

## Decision

Each entry uses separately versioned summary and secret envelopes. AAD binds the
vault UUID, stable entry UUID, envelope purpose, entry type, crypto epoch, schema
version, crypto version, and authenticated tombstone state where applicable.

Durable envelopes use a documented language-neutral serialization with explicit
magic/version/algorithm/length fields and hard decode limits. Domain originals are
encrypted; local lookup uses keyed equality tags. Absence is a typed nullable value,
not an empty ciphertext. Corrupt timestamps and enum values are rejected.

Newer unsupported schema, envelope, or crypto versions fail closed. Encryption and
serialization algorithms are agile only through explicit new versions and migrations.

### Canonical serialization profile (rev 2, from adversarial review)

"Language-neutral and bounded" is normative, not aspirational. The durable format is
a canonical JSON profile with: **duplicate object keys rejected** on decode (no
last-wins), **integers only** for numeric fields (no float coercion — mobile JSON
decoders must not round-trip epochs/lengths through double), strict UTF-8, a fixed
depth cap, and **binary fields (SSH DER keys, arbitrary-byte secrets) encoded as
base64 with an explicit byte-length maximum**, not raw JSON strings. The exact AAD
input byte-encoding is part of the frozen contract: WBS-303's golden vectors fix the
AAD bytes themselves, so any later re-derivation from parsed values must reproduce
identical bytes or fail.

### Domain lookup tags (rev 4)

Equality tags cannot express today's dot-suffix subdomain matching. The tag index
therefore stores a **full label-chain tag set per mapping**: a tag for the stored
host and for every dot-suffix of it (e.g. `a.b.example.com` → tags for
`a.b.example.com`, `b.example.com`, `example.com`, `com`), bounded by a maximum
label-count cap. One canonicalization rule applies on every write and query path:
lowercase + IDNA/punycode normalization (including bare hostnames that skip URL
parsing today), versioned with the envelope schema.

**Match predicate (normative, exactly today's semantics — rev 4):** a query matches
a mapping iff the *stored host's* full-host tag is in the query's chain-tag set OR
the *query host's* full-host tag is in the stored chain-tag set — mutual
ancestor-chain containment, which is precisely what `domains_match`
(`vault_state.rs`) implements, including the bare-parent/dotted-child cases
(`gitlab` ↔ `sub.gitlab` matches today and must match under v2). Chain tags
themselves (e.g. `com`) are never matchable on their own — only full hosts are
tested — so siblings under a shared suffix do not match. Plain set intersection is
explicitly rejected.

**No Public Suffix List (rev 4, simplification):** the earlier rev-3 design cut
chains at eTLD+1 and therefore required bundling a PSL snapshot with pinned
versions and a re-derivation migration on every PSL update. Full chains make the
PSL unnecessary: matching is defined by the two hosts alone, no third-party dataset
can drift between devices, and no recurring migration exists. Canonicalization
(lowercase, IDNA) remains the only versioned input.

**Write-path reality (rev 3, correcting rev 2):** local CRUD does **not** populate
`domain_mappings` today — the only production writers are sync pull-apply paths; the
`repository.rs` INSERT is test-only (verified: it sits inside `#[cfg(test)]`). The v2
tag backfill therefore derives mappings from entry URLs/domains for effectively all
locally-created entries, and the mapping write-path becomes part of the WBS-306
application-service contract rather than a sync side effect.

### Summary index ownership and lifecycle (rev 2)

The decrypted summary index (titles/usernames for listing) is **owned by the daemon**
and built **lazily on first list after unlock** with invalidation on mutation — not
eagerly at every unlock (biometric quick-unlock and the Phase-6 FFI path must not pay
a full-vault decrypt per unlock). The index is zeroized on lock together with key
material, so a post-lock crash dump leaks no titles/usernames; the desktop UI
re-requests summaries from the daemon rather than caching its own copy (WBS-701/702
consume this contract).

### Legacy disposition and old-client enforcement (rev 3)

"Atomically activate v2" must make shipped binaries (≤ 0.8.x) **fail loudly at
open**. Dropping legacy data tables alone does not suffice — and the rev-2 rationale
for it was wrong: `VaultManager::open()` calls `validate_schema_version()` directly
and never `initialize_schema()` (that call is `create()`-only), so the empty-vault
resurrection sequence rev 2 described exists on no shipped *open* path. The genuine
risks are (a) the proceed-anyway branch for newer schema versions and (b)
`VaultManager::create()` resurrecting a legacy schema beside v2 data.

The mechanism that actually reaches shipped binaries: activation, in the same
transaction, **renames/removes `db_metadata`** (v2 keeps its own metadata table
under a new name) and drops the legacy data tables. An old binary's open path then
fails at the version probe itself — the `SELECT ... FROM db_metadata` dies with "no
such table" — loud, immediate, before any user-visible vault state. From v2 on,
`validate_schema_version` also fails closed on newer versions (WBS-315/406).

The *real* resurrection machinery is `VaultManager::create()`, which runs
`initialize_schema()` and inserts a fresh metadata row, and is guarded today only by
call-site file-exists checks (CLI; Tauri UI and sync pair-join have their own
create() callers). **WBS-402 must add a core-API guard: `create()` refuses to
initialize over an existing non-empty database file** (any schema version), with the
old-binary-opens-v2 and create()-over-v2 negatives both required. Migration version
bumps and post-migration data backfills must occur inside one transaction with the
DDL — the existing runner's post-commit data phase is in scope for WBS-402 to fix,
and WBS-407's fixtures are regenerated from *actual released* schema dumps, not the
drifted `migrations/v1_initial.sql` labels.

## Options Considered

- Add only field-name AAD: rejected because it omits vault/record/version identity.
- Encrypt the entire database with a transparent database codec: deferred; it does not
  replace semantic AAD and complicates portability.
- Whole-record ciphertext only: rejected for current summary/listing needs.
- Authenticated summary plus secret envelopes: proposed.

## Threat Model

Protects integrity against an attacker able to copy, exchange, or replay stored blobs
without the DEK. It limits plaintext metadata. It does not hide database size, record
count, access timing, or data exposed by an unlocked compromised process.

## MVP vs. Later

- MVP: credential, TOTP, SSH, registry, and key-slot envelopes plus migration.
- Later: optional size padding profiles and stronger access-pattern protection.

## Migration and Rollout

Migration runs only after successful legacy unlock, creates a verified backup, builds
v2 tables alongside legacy data, decrypts and re-encrypts all records, verifies every
result, and atomically activates v2. Older clients must refuse the migrated vault.

## Consequences

The format change is deliberately incompatible and must precede sync v2 and stable
mobile ABI work. Integrity and recovery improve at the cost of a substantial migration
and permanent schema/version discipline.

**Supersedes one plan line on acceptance (rev 3):** the strategic plan's Phase 5
deliverable "store summaries in UI state" is superseded by this ADR's daemon-owned,
zeroize-on-lock summary index — the UI re-requests summaries rather than caching
them. The plan line is amended when this ADR is accepted; WBS-701/702 implement the
ADR contract. Canonical JSON decode must never round-trip through an untyped
`serde_json::Value` (typed structs only, so duplicate keys fail structurally);
WBS-303/305 carry a profile-conformance test.
