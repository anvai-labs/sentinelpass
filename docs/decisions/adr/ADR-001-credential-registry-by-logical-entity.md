# ADR-001: Credential Registry by Logical Entity

| | |
|---|---|
| **Status** | Proposed (rev 2, after adversarial review — see git history) |
| **Date** | 2026-09-02 |
| **Area** | `sentinelpass-core` (schema v5, crypto, vault, sync apply), `sentinelpass-cli`, `sentinelpass-ui` |
| **Related** | [TECHNICAL_DEBT.md](../../../../TECHNICAL_DEBT.md) deferred item 1 (schema v5 typed payloads + entry ownership; the "real `DeleteSecret`" rider is **not** absorbed — see D1); `crypto/health.rs` password-health analysis; v0.8.0 `sentinelpass exec`/`env` secret serving + per-client allowlist grants |

## Summary

Give SentinelPass a **credential registry**: credentials grouped by the logical entity they
belong to (a broker, a market-data API, a database, a notification webhook…), with
password-reuse detection across entities, age- and risk-based rotation recommendations, and
a read-only posture dashboard. The registry is not a second store of secrets — full secrets
stay in the vault as ordinary encrypted entries (decision D1), and the registry layer holds
only entity metadata and derived material, with the derived equality tags **encrypted at
rest** (decision D4).

## Context

Today the vault is a flat list. An entry has a `credential_type` discriminator
(`Password | ApiKey | PasskeyReference`, `vault/mod.rs:32-37`) but no grouping concept:
no folders, tags, entities, or ownership (verified across `database/*.rs` and
`vault/mod.rs`). There is no rotation timestamp and no password history — `update_entry`
stamps `modified_at` (`vault/mod.rs:609`, written at `:624`) but cannot distinguish a
password change from a title edit.

Some posture machinery already exists: `crypto/health.rs` computes strength distribution,
a 0–100 vault health score, and password-reuse detection (`is_reused`, `reuse_count`). But
reuse is detected by grouping on **raw decrypted password bytes in memory**
(`health.rs:216-231`, `:349-363`), recomputed on every scan; it cannot be persisted or
diffed over time, and it has no notion of *which* entities share a password.
`sentinelpass health` (CLI, dispatched `main.rs:1087-1092` →
`commands/generate.rs:109`) exposes this report today; the Tauri UI does not surface it
at all (no health command in `generate_handler!`, `src-tauri/src/main.rs:1273-1298`).

The driving use case is operator infrastructure credentials: a multi-component trading
system whose secrets live in an unmanaged env file (`~/.ibkr_tradeapp.env`, 18 keys —
two Postgres connection URLs with embedded credentials, a FRED API key, a Telegram bot
token/chat id, an observability API token; see Appendix A), plus webhook/Telegram
credentials in a notifications component and an Argon2-hashed dashboard login. The same
population is already partially served by v0.8.0 external secrets: `secret get` /
`exec` / `env` with per-client allowlist grants store tool-provided credentials as
**ordinary vault entries** (`credential_type: ApiKey`, `title = domain`,
`vault_state.rs:487-499`). Those entries are in scope for the registry like any other —
with tool-managed lifecycle semantics (see Detailed design).

## Decision drivers

1. **Blast radius.** A stolen `vault.db` without the master key must reveal **no secret
   material, admit no offline password guessing, and expose no new secret-derived
   structure** (with D4's encrypted tags, this holds; the accepted residuals — plaintext
   policy declarations and lifecycle timestamps — are owned explicitly in the threat
   model).
2. **Custody enables action.** Recommendations that cannot be acted on inside the product
   (rotate *now*, with a generated replacement) decay into shelfware. Monitoring-only
   designs were considered and rejected (see Alternatives) for the MVP.
3. **Existing seams.** Reuse `crypto/strength.rs` scoring, `crypto/health.rs` analysis,
   the hand-rolled migration runner, and the `domain_mappings` child-table pattern rather
   than inventing parallel structures.
4. **Surface discipline.** The browser extension must not gain any new read path
   (CLAUDE.md rule: never return more than the requested credential). The registry is a
   desktop-UI + CLI feature.
5. **Sync-agnostic core.** Local-first; sync *metadata* integration is additive and
   deferred — but sync's entry **write path** is fully in scope (D4), because pulled
   entries change secrets.

## Scoping decisions

### D1 — Storage boundary: vault custody + derived-only registry

**Options:**

- **(a) Hash-only registry (verifier pattern).** Registry stores keyed hashes + metadata;
  secrets stay wherever they are today (env files, service config). Smallest blast
  radius, but the registry is advisory-only: it cannot rotate anything, cannot store the
  replacement, and becomes a second source of truth that drifts from reality.
- **(b) Full custody in the vault + registry as metadata/index layer.** Credentials become
  ordinary vault entries (Argon2id/AES-256-GCM path unchanged); the registry adds
  entities, membership, rotation lifecycle metadata, and a keyed equality index.

**Decision: (b).** The vault already solves encrypted custody with the exact primitives
the registry needs; the registry's job is organization and posture, not storage. Option
(a) survives in reduced form as the *import bridge* (Phase 3 reads the env file once)
and as a future "observer entry" type for secrets that cannot move yet (MVP vs. later).

This decision absorbs the **typed-metadata and entry-ownership halves** of TECHNICAL_DEBT
deferred item 1 (schema v5 api-key provider/scopes/expiry metadata + entry ownership).
It deliberately does **not** absorb that item's "→ real `DeleteSecret`" rider: the
protocol message remains defined-but-rejected (`sentinelpass-protocol/src/message.rs:97-102`,
rejection at `daemon/ipc/server.rs:700-709`). The registry's per-entry lifecycle rows make
a future delete path safer (a deletion becomes an auditable lifecycle event), but
implementing `DeleteSecret` stays a separate decision.

### D2 — Reuse semantics: exact-match keyed index first

- **MVP: exact-match reuse detection** via a persisted equality tag — HMAC-SHA256 of the
  secret under a key derived from the DEK (D4), **stored encrypted at rest**. Equal
  secret ⇔ equal tag; grouping happens in application memory after decryption (which the
  read path already does — VaultManager-only, no SQL-level aggregation).
- **Normalization policy: exact UTF-8 bytes, no trimming or case-folding.** Normalization
  silently changes what "same password" means and can merge distinct secrets; if it is
  ever added it must ship as a new `algorithm_version` with a full re-sweep, never as a
  reinterpretation of existing tags. (The Phase-3 *importer* may trim surrounding
  whitespace from env-file values as part of parsing — that is ingestion hygiene at the
  boundary, applied before custody, and is documented in the importer spec.)
- **Weak/derived-pattern scoring** reuses `crypto/strength.rs::analyze_password` (entropy,
  charset, warnings) via the existing `crypto/health.rs` analyzer. The registry adds the
  *policy* layer: strength below threshold + entity criticality → recommendation.
- **Later:** near-duplicate/similarity detection (n-gram or MinHash over password
  material), derived-pattern rules (password contains entity name/username/season),
  breach-corpus checks (the `is_compromised` stub in `health.rs:287` already reserves the
  HIBP seam; k-anonymity range queries fit the keyed-tag design without exposing
  secrets).

Similarity and pattern work is genuinely policy-heavy (false-positive UX, thresholds);
exact-match is cheap, deterministic, and catches the dominant real-world failure
(password repeated across broker, database, and webhook).

### D3 — Dashboard: read-only posture view first

- **MVP:** a read-only posture panel in the Tauri desktop UI (entity cards with credential
  counts, reuse clusters, rotation-due list, weak-secret flags, overall score) plus CLI
  parity (`sentinelpass registry status` / `registry report`, rhyming with the existing
  `sentinelpass health` command). There is no web ops console in this workspace (verified:
  the only HTTP server is the sync relay), so the Tauri UI is the dashboard surface.
- **Later:** lifecycle workflows in the UI (rotate-now wired to the password generator,
  policy editor, entity editor), and an external-consumer read API over
  `sentinelpass-protocol` IPC. **Normative requirement for that phase:** existing grants
  are scoped per `(client_id, domain, field)` (`external_secret_access.rs:26-45`); an
  aggregate/posture endpoint must define a new grant class such that aggregate visibility
  never exceeds the intersection of the caller's grants — a single-domain grant must not
  become an oracle for "this domain's credential is reused with two others". This needs
  its own (small) ADR before any aggregate IPC surface ships.

Read-only first because the data model and policy engine are the risky parts; workflows
are thin once recommendations exist and are trusted.

### D4 — Where the equality index lives, how it is stored, and who reads it

**Derivation.** `KeyHierarchy` gains an `equality_key()` accessor
(`crypto/keyring.rs`): `HKDF-SHA256` with the DEK as IKM, **empty salt**,
`info = "sentinelpass-registry-equality-v1"`, output length 32 bytes. There is no
existing purpose-derived subkey facility to reuse — `KeyHierarchy` is
MasterKey→wraps→DEK only, sole accessor `dek()` (`keyring.rs:131-135`) — so this is new
API in the security-sensitive `crypto/` area. The derivation runs on demand per
operation, the result is held in a zeroizing buffer, never persisted, never cached across
lock. Biometric unlock reaches the same DEK (`keyring.rs:114-117`), so tags are
computable on every unlock path. `hkdf` must become an **unconditional** dependency of
`sentinelpass-core` (today it is `sync`-feature-gated, `sentinelpass-core/Cargo.toml:15`,
`:46`); `hmac` is already unconditional.

**Storage.** A `secret_equality_index` table inside `vault.db`:

```
CREATE TABLE secret_equality_index (
    entry_id         INTEGER PRIMARY KEY REFERENCES entries(entry_id) ON DELETE CASCADE,
    tag_cipher       BLOB NOT NULL,        -- DEK-encrypted tag, per existing field-encryption pattern
    algorithm_version INTEGER NOT NULL DEFAULT 1,
    equality_key_id  INTEGER NOT NULL DEFAULT 1,
    updated_at       INTEGER NOT NULL
);
```

`tag_cipher` encrypts `hex(HMAC-SHA256(equality_key, secret_bytes))` using the existing
per-field encryption pattern (`encrypt_string(dek, …)` at `vault/mod.rs:281-295`).
`PRIMARY KEY (entry_id)` makes sweep upserts idempotent. `equality_key_id` identifies
which derivation label/version produced the tag (see DEK lifecycle below).

**Why encrypted tags.** HMAC tags are deterministic: two entries with the same secret
produce byte-identical values, and *comparing stored tags requires no key*. Plaintext
tags would hand a database-only thief the vault's reuse-cluster structure and cluster
sizes. Encrypting each tag under the DEK hides that structure at rest while preserving
exact-match grouping in memory — the aggregation is application-side anyway (D4 read
path), and the sweep/scan already decrypts per-entry data. The cost is one symmetric
decrypt per entry per scan, negligible next to the entry decrypt itself.

**Read path.** `VaultManager` exclusively. The index is:

- never returned over native messaging / to browser extensions (CLAUDE.md rule 8);
- never exported (`import_export` walks entries, not the index; the index is derived and
  rebuilt lazily);
- never synced (derived data);
- surfaced only as *in-memory aggregates* (reuse clusters, counts) to CLI and Tauri UI.

**Write path — complete census.** Tag recomputation must hook **every** site that writes
entry secrets:

1. `add_entry` / `update_entry` (`vault/mod.rs:273`, `:564`) — covers CLI, Tauri
   commands (`src-tauri/src/main.rs:832-870`), daemon `save_credential` /
   `save_secret_value` (`daemon/vault_state.rs:373-441`, `:446-502`), JSON/CSV/KeePass
   imports (`import_export.rs:239`, `:326`, `keepass/mod.rs:138`), and the mobile bridge.
2. **Sync pull-apply is a first-class write site**: `apply_credential`
   (`sync/engine.rs:283-406`) writes pulled entries with direct SQL (UPDATE `:325-347`,
   INSERT `:371-393`) and never passes through `VaultManager`. It already holds the
   decrypted payload (from `decrypt_sync_payload`, `engine.rs:320`, `:366`) and the DEK,
   so it recomputes the tag inline — one HMAC + one encrypt per pulled credential
   entry. Without this hook, remote-origin rotations would be invisible to the rotation
   signal *forever* on multi-device vaults (a sweep over "missing rows" never revisits a
   stale row that exists).

**Rotation detection semantics.** On any write-site tag computation:

- prior index row exists, computed tag differs, and `equality_key_id` matches → the
  secret changed: rewrite `tag_cipher`, bump `updated_at`, set
  `entry_lifecycle.password_rotated_at = now`, emit `SecretRotated { entry_id }`.
- no prior index row (pre-backfill, first sight of an entry) → insert the tag, **do not
  stamp rotation** — absence of a prior row is not evidence of change.
- `equality_key_id` differs (key version changed) → rewrite the tag under the new key,
  **suppress** the rotation stamp and `SecretRotated` (mass key-version migration must
  not read as mass rotation).

**Sweep policy.** Three triggers, each scoped:

- **Backfill sweep (on unlock, only when incomplete):** if live `Password`/`ApiKey`
  entries lack index rows, or any row's `equality_key_id` is stale, compute the missing
  tags. Completion is recorded as **database state** (a flag in a small `registry_state`
  key-value table) so a fresh process does not redo the work; in-memory "done" flags do
  not survive the UI↔daemon split.
- **Health scan:** `analyze_vault` already decrypts every entry (`health.rs:207-214`);
  it additionally recomputes all tags — incremental cost is n HMACs + n symmetric
  decrypts.
- **Orphan pruning:** any sweep also deletes index/lifecycle/membership rows whose entry
  row is missing or soft-deleted (belt-and-braces alongside the delete-path purge below).

The sweep uses a **dedicated decrypt-and-HMAC path — not `get_entry`**. Routing it
through `get_entry` would (a) emit one `CredentialViewed` audit event per entry per sweep,
and (b) write the bincode-encrypted `title_hint` blob into the plaintext audit log via
`format!("Created credential: …")`-style context handling (`vault/mod.rs:368`) — an
existing hygiene bug the sweep must not multiply. The path decrypts the password field
per entry, computes the tag, and drops the plaintext immediately; it never accumulates a
vault-wide plaintext map (the pattern `health.rs:216-231` uses today is explicitly *not*
copied).

A full-vault decrypt at unlock is **new cost** — `VaultManager::open` today performs KDF
+ DEK unwrap only and decrypts nothing (`vault/mod.rs:115-160`). It happens only when
the index is incomplete (post-migration, post-restore), not on every unlock.

**Delete semantics.** `delete_entry` is a **soft delete** (`is_deleted = 1`,
`vault/mod.rs:493-561`); no code path undeletes, and FK CASCADE never fires on soft
delete — the existing code already handles this for `domain_mappings` with an explicit
DELETE in the same transaction (`vault/mod.rs:543-548`). The registry follows that
precedent: `delete_entry` explicitly purges the entry's `secret_equality_index`,
`entry_lifecycle`, and `entity_memberships` rows; additionally every registry aggregate
query joins `entries.is_deleted = 0`, and sweeps prune orphans. A v4→v5 migration test
must cover a soft-deleted entry.

**DEK lifecycle.** The equality key is bound to the DEK's lifetime. Today no operation
changes the DEK of a non-empty vault: biometric stores a DEK *copy* in the OS keystore
(`biometric_ops.rs:111-115`), and `import_pairing_bootstrap` replaces DEK + KDF params
wholesale (`sync_ops.rs:100-125`) but is gated to an empty vault (`:84-98`) — safe by
that guard, not by design. If that guard ever loosens or a DEK-rotation feature lands,
the operation must bump the HKDF `info` label (and `equality_key_id` on all rows) and
trigger a full sweep with rotation stamping suppressed, per the semantics above. The
current `algorithm_version` is `1`; the exact HKDF parameters are fixed in this ADR so
independent implementations cannot diverge.

**Cross-device.** Paired devices share the DEK, so tags are deterministic across
devices; the index is nevertheless local-only and rebuilt/refreshed via the sweep policy
above. Rebuilding is O(n) HMACs + O(n) symmetric decrypts.

## Detailed design

### Entity taxonomy

- `entities` table: `entity_id` (UUID, plaintext), `name` (**DEK-encrypted**),
  `kind`, `criticality` (`Low | Medium | High`), `notes` (**DEK-encrypted**),
  `rotation_interval_days_override` (nullable, plaintext policy), `created_at`,
  `modified_at`.
- **Encryption posture:** today every user-composed value in `vault.db` is DEK-encrypted
  (`title/username/password/url/notes`, `vault/mod.rs:281-295`, `schema.rs:116-120`).
  Entity names and notes are exactly that kind of data — "trading-postgres", "FRED" —
  and map 1:1 to real infrastructure, so they are encrypted like entry fields. `kind`,
  `criticality`, and policy integers stay plaintext: they are declared policy enums, not
  user prose. Because `name` is encrypted, its uniqueness moves to application level
  (checked in the same critical section as insert); the benign TOCTOU window across the
  UI↔daemon processes is accepted for MVP (a duplicate name is a cosmetic, correctable
  state, not a security one).
- `EntityKind` is a fixed enum for MVP: `Broker | MarketData | RegulatoryData |
  Notification | Database | Infrastructure | Application | Other`. Entities are
  user-defined records *of* a kind; kinds are closed to keep policy defaults total, and
  `Other` is the escape hatch. Seed entities for the first onboarding target come from
  Appendix A.
- `entity_memberships` table: `entry_id` (**UNIQUE**, FK CASCADE) + `entity_id`
  (FK CASCADE) + optional `label` (**DEK-encrypted**; e.g. "paper", "prod"). Single
  membership per entry for MVP — it matches the recommendation model ("entity X's DB
  credential") and the structural precedent is `domain_mappings` (`models.rs:25-30`,
  child table + explicit cleanup on delete, `vault/mod.rs:543-548`). Many-to-many is a
  later extension if a real credential-straddles-two-entities need appears; nothing in
  the policy engine assumes uniqueness beyond MVP convenience.

### Schema v5

Hand-rolled migration, per the established runner (refinery is *not* used —
`CURRENT_SCHEMA_VERSION: i32 = 4` at `schema.rs:9`, sequential arms in
`migrations.rs:233-253`):

- `migrate_v4_to_v5()` following the `migrate_v1_to_v2` template (`execute_batch`,
  `BEGIN…COMMIT`, in-batch version bump; fixture lineage from `create_v1_db` at
  `migrations.rs:260`, tests from `:336` — a `create_v4_db` fixture is added).
- New tables: `entities`, `entity_memberships`, `secret_equality_index` (row shape in
  D4), `entry_lifecycle`, `registry_state`.
- `entry_lifecycle`: `entry_id` (**UNIQUE**, FK CASCADE), `password_rotated_at`
  (plaintext timestamp — see threat model for the accepted timing residual),
  `expires_at` (nullable — the api-key expiry metadata from deferred TD item 1),
  `rotation_interval_days_override` (nullable), `source`
  (`Manual | Imported | Generated | ToolManaged`).
- `registry_state`: `key TEXT PRIMARY KEY`, `value TEXT` — DB-state flags for sweep
  bookkeeping (e.g. `backfill_complete`, current `equality_key_id`).
- Both DDL paths get the tables: `migrate_v4_to_v5` for existing vaults and
  `initialize_schema` for fresh installs (v4 precedent: `schema.rs:113-134`); new indexes
  land in `create_indexes` (`schema.rs:274-298`) and the schema test assertions
  (`schema.rs:388-442`) are extended.
- **Deliberate choice: lifecycle is a sibling table, not columns on `entries`.** The
  `update_entry_modified_timestamp` trigger (`schema.rs:300-323`) force-bumps
  `sync_version` and re-marks sync state `'pending'` on any UPDATE of entry fields;
  stamping rotation through the entries table would fabricate sync churn on every
  rotation. Do not "simplify" this later.
- `CredentialType` grows no new variants in MVP. Api-key typed payloads
  (provider/scopes/expiry) land with this schema as lifecycle/metadata columns rather
  than a payload format change; a typed payload refactor can follow without a second
  migration.

### External secrets (v0.8.0) are in scope, with tool-managed semantics

`SaveSecret` / `secret get` / `exec` / `env` store tool-provided credentials as ordinary
ApiKey entries (`vault_state.rs:487-499`) written through `update_entry` (`:479`, `:499`)
— so they ride the D4 write path with no extra hooks, and the registry covers them like
any other entry. Their lifecycle differs:

- `source = ToolManaged` is stamped by the daemon's external-secret write path.
- Re-injection of an **unchanged** value produces an unchanged tag → no spurious rotation
  stamp (tag-change detection is naturally idempotent for stable values).
- If a tool itself rotates a value, the tag changes and the rotation stamp fires —
  correct semantics: the secret did change.
- **Age policy:** `ToolManaged` entries are excluded from age-based `DueSoon`/`Overdue`
  by default (their lifecycle is owned by the deploying tool); a per-entity override
  re-includes them. Reuse and strength checks always apply.
- Mapping: multi-colon domain scopes (e.g. `sandhi:anthropic:key`,
  `commands/exec.rs:25-27`) map onto entities via normal membership assignment — no new
  namespace is introduced.

### Rotation policy engine

Pure function, no I/O, fully unit-testable:

```
recommend(entry, lifecycle, membership, entity, tag_stats, analysis)
  -> RotationRecommendation { status: Ok | DueSoon | Overdue | Reused | Weak, reasons }
```

**Interval resolution order** (first hit wins; echoes the config three-tier override
pattern): entry override (`entry_lifecycle.rotation_interval_days_override`) → entity
override (`entities.rotation_interval_days_override`) → kind default (Appendix B) →
global fallback. The criticality and reuse multipliers then apply to the resolved
interval.

- Criticality multiplier: `High` ×0.5, `Low` ×2.
- Reuse: `reuse_count ≥ 2` → interval ×0.5 and status at least `Reused`.
- Strength: analysis below the configured threshold (default `PasswordStrength::Weak`)
  → status `Weak` regardless of age.
- `expires_at` → `DueSoon` at T-14d, `Overdue` past expiry.
- Age source: `entry_lifecycle.password_rotated_at` (D4 rotation semantics), falling
  back to `created_at` for entries not yet swept.
- `ToolManaged` entries: age-based statuses suppressed by default (above).

No auto-rotation in MVP: recommendations only. Rotation of **passwords** is a
generator-driven workflow later (`crypto/password.rs`, exposed as `generate_password`);
rotation of **provider-issued keys** (api keys, FRED) is necessarily a manual flow — the
recommendation says "rotate at provider, then update the entry", and updating the entry
is what re-stamps `password_rotated_at`. The later UI workflow includes an explicit
"mark rotated" action for exactly this case.

### Surfaces

- **Core:** a `registry` module in `sentinelpass-core` (entity CRUD, membership assign,
  lifecycle getters, equality index maintenance, policy engine, sweep) wired into
  `VaultManager` like the existing `*_ops.rs` split (`health_ops.rs`, `ssh_ops.rs`, …).
  New SQL uses the same parameterized-query and repository patterns as existing tables
  (no raw-SQL sprawl — this debt exists, do not grow it).
- **CLI:** nested `registry` subcommand group (pattern: `SecretCommands`,
  `main.rs:449`): `registry entity add/list`, `registry assign`, `registry status`,
  `registry report`. Env-file importer in Phase 3 (`registry import-env`).
- **Tauri UI:** new read-only posture panel in the vault screen (new header button +
  panel, per the `index.html` structure) backed by new Tauri commands
  (`get_registry_overview`, `list_entities`, `get_rotation_recommendations`) registered
  in `generate_handler!` (`src-tauri/src/main.rs:1273-1298`). The panel also becomes the
  first UI consumer of the existing `crypto/health.rs` summary. Implementation edits the
  **TypeScript sources** (`app.ts`, `entries.ts`, a new `registry.ts`) and ships through
  the `npm run web:build` transpile step — editing the transpiled `app.js` directly does
  not survive a rebuild.
- **Browser extension:** no changes, by design (D3/decision drivers).

### Audit

New `AuditEventType` variants (each needs an arm in `severity_for_event`,
`audit.rs:187-227`): `RegistryEntityCreated`, `RegistryEntityDeleted`,
`EntryAssignedToEntity`, `SecretRotated { entry_id }` (emitted on tag change per D4
semantics), `RegistryIndexRebuilt`. Recommendation *reads* are not audited (derived
data, high volume); mutations are. **Context strings carry entry/entity IDs, not
names** where avoidable: the audit log is a plaintext JSONL file outside `vault.db`
(`audit.rs:287-294`) that already receives entry titles today (`vault/mod.rs:345`,
`:635`) — the registry must not enlarge that surface beyond what existing events
already do, and the residual is owned in the threat model.

## Threat model

| Adversary / event | With registry | Notes |
|---|---|---|
| Stolen `vault.db` (no master key) | Learns **no secret material**; cannot test password guesses offline (computing a tag requires the DEK via Argon2id); tags are DEK-encrypted at rest, so **no equality/reuse structure** is visible. **Accepted residuals (plaintext by decision):** policy declarations (`kind`, `criticality`, intervals), lifecycle timestamps (`password_rotated_at`, `expires_at` — i.e. *that* a secret changed and when, not what it is), entity/member row existence and shapes. | Restores driver 1 with named, deliberate exceptions. Backups inherit the same properties. |
| Unlocked process / memory adversary | Gains nothing new: it can already decrypt every secret and could compute all tags itself. | Same trust boundary as the existing vault. |
| Sync relay / server | Never sees the index or any registry data; sync payloads are unchanged per-entry encrypted blobs. | Registry tables are not sync entry types. |
| Browser extension / native messaging | No new message types, no registry read path. | Preserves CLAUDE.md rule 8. |
| Local IPC client holding a v0.8.0 grant token | Sees only its granted `(client, domain, field)` values, as today. Registry aggregates are **not** exposed over IPC in MVP. The later aggregate API requires a new grant class whose visibility never exceeds the caller's grant intersection (D3). | Prevents the aggregate surface from becoming a cluster-structure oracle for grant holders. |
| Backups / DB snapshots | Old backups remain openable (existing forward-compat path, `schema.rs:365-374`); restoring an older `vault.db` is detected via incomplete/stale index and repaired by the backfill sweep. | Restore cannot resurrect ghost rows: delete-path purge + orphan pruning bound it. |
| Plaintext audit log (`<config>/audit/audit.log`) | Existing events already leak entry titles into this file; registry mutation events add entity names. Context strings carry IDs where avoidable; this is a documented residual, not a new category. | `audit.rs:287-294`, `vault/mod.rs:345`, `:635`. |
| Post-import source file (dual-homing) | Until the consumer cutover, imported secrets exist in both the vault and the original env file. Imported entries carry `source = Imported`; the dashboard marks dual-homed status. Secure archival of the source file is guidance/documentation, not automated deletion. | Prevents a false "all custody achieved" posture signal. |
| Malicious / buggy importer (Phase 3) | Import runs in a **single SQLite transaction per file** (all-or-nothing; the existing fail-fast importers that commit per entry are explicitly not copied), emits a summary audit event with succeeded/failed counts, accepts **file-path arguments only** (no secret material via argv — argv is world-readable via `ps`), never echoes resolved values, and parses URL-embedded credentials into per-field owned zeroizing buffers (the source line is dropped promptly; the residual parse buffer is documented as best-effort, consistent with existing `String`-based import plumbing). | `import_export.rs:214-243` is the anti-pattern. |

## MVP vs. later

| Capability | MVP (this ADR's slices) | Later |
|---|---|---|
| Entity CRUD + membership | ✅ core + CLI + API | UI editors |
| Exact-match reuse detection (keyed, encrypted-at-rest index) | ✅ | — |
| Strength scoring integration | ✅ (existing analyzer) | Derived-pattern rules, similarity/MinHash |
| Rotation recommendations (age + risk policy, ToolManaged-aware) | ✅ read-only | Rotate-now / mark-rotated workflows (generator wiring), policy editor |
| Posture dashboard | ✅ Tauri read-only panel + CLI report | External ops-console API over `sentinelpass-protocol` — gated on the aggregate-grant-class ADR (D3) |
| Env-file import (first onboarding) | ✅ Phase 3 | Generic CSV/other importers |
| Breach checks (HIBP k-anonymity) | — | ✅ fits keyed-tag design |
| Entity/lifecycle sync across devices | — | ✅ new `SyncEntryType` variants |
| "Observer" entries (hash+metadata only, secret stays external) | — | ✅ for secrets that cannot move yet (e.g. IBKR gateway login, Appendix A) |

## Migration path (slices; no code before this ADR is accepted)

1. **P1 — Core + schema.** `migrate_v4_to_v5` + registry module (entities, membership,
   lifecycle, equality index, policy engine, audit variants, sweep/backfill) + CLI
   `registry` group. Ships dark (no UI).
2. **P2 — Dashboard.** Tauri posture panel + Tauri commands; UI surfaces health summary +
   registry overlays. Read-only. (TypeScript sources + `npm run web:build`.)
3. **P3 — First onboarding.** `registry import-env` for `~/.ibkr_tradeapp.env` per
   Appendix A (single-transaction import, URL-splitting for Postgres URLs, typed api-key
   entries, entity seeds, `source = Imported`, dual-homing markers); consumer cutover on
   the trading-system side via the already-shipped `sentinelpass exec`/`env` +
   allowlist grants. **The consumer-side changes live in that repository's own governance
   and are a dependency, not scope, of this ADR.**
4. **P4 — Lifecycle + breadth.** Rotate-now / mark-rotated workflows, policy editor,
   similarity/breach checks, entity sync, observer entries, external console API (with
   the grant-class ADR).

Each slice is an independent PR; P1 gates everything else.

## Alternatives considered

1. **Hash-only sidecar registry (monitor-only).** Rejected for MVP (D1a): advisory-only,
   no custody, drifts from reality. Retained in reduced form as the import bridge and the
   later "observer entry" type.
2. **Registry tables outside `vault.db`.** Rejected (D4): crown-jewel-adjacent data
   outside the encrypted envelope; complicates backup/restore for zero benefit.
3. **Plaintext deterministic tags with an honestly-stated leak.** Rejected in favor of
   DEK-encrypted tags: the encrypted variant costs one symmetric decrypt per entry per
   scan and restores the "no new structure at rest" property, while aggregation is
   application-side anyway. (SQL-level `GROUP BY` on the tag is thereby lost —
   immaterial, since the read path is VaultManager-only.)
4. **Status quo (`crypto/health.rs` only).** Rejected: in-memory grouping cannot drive
   age-based policy (no rotation timestamps exist), has no entity dimension, and
   recomputes on every scan with no persistence.
5. **External secret manager (Vault, SOPS/AGE, 1Password Connect).** Rejected: violates
   the local-first product principle; the user owns this codebase and its roadmap.

## Consequences

**Positive**

- Rotation posture becomes real: first-class `password_rotated_at` (driven by a complete
  write-site census including sync pull-apply), age/risk recommendations, and a dashboard
  that makes reuse across logical entities visible.
- Reuse detection becomes persisted, indexable, and privacy-preserving — including
  against database-only theft, which the previous in-memory design never had to answer.
- Absorbs the typed-metadata and ownership halves of deferred TD item 1 into one coherent
  migration.
- Tool-managed (v0.8.0 external-secret) credentials get truthful lifecycle semantics
  instead of silently defeating age policy.
- Extension surface unchanged; sync payload format untouched.

**Negative / risks**

- A schema migration (v4→v5) with the usual risk — mitigated by the established
  sequential-migration test pattern extended with a `create_v4_db` fixture that includes
  a soft-deleted entry.
- Sweep policy adds a bounded full-vault decrypt on first unlock after migration/restore
  (not every unlock); sweep correctness depends on the write-site census staying complete
  — a future write path that bypasses both `VaultManager` and `apply_credential` would
  silently stale the index until the next full health scan.
- Encrypted tags move aggregation into application memory; vaults with very large entry
  counts pay a linear scan (bounded by the same scan the health analyzer already does).
- Single-membership-per-entry may force awkward entity choices; escape hatch documented
  (many-to-many later).
- New wire structs must use `Zeroizing<String>` for any secret-adjacent field — the
  secrets-as-`String` debt (TECHNICAL_DEBT.md deferred item 2) must not grow here; the
  importer's URL-splitting is designed around this (threat model row).
- Plaintext residuals (policy declarations, lifecycle timestamps, audit-log entity names)
  are accepted and documented rather than silently tolerated.

## Appendix A — First onboarding target: secret inventory

Source: `~/.ibkr_tradeapp.env` (18 keys inventoried 2026-09-02; **values intentionally
not reproduced**), plus the notifications component and the metrics-server dashboard
auth. This inventory defines the seed entities of the registry and the Phase-3 importer's
test fixture.

| Secret (key / source) | Seed entity | Kind | Consumer today | Rotation posture |
|---|---|---|---|---|
| `TRADING__DATABASE__POSTGRES_URL` (credentials embedded in URL) | trading-postgres | Database | trading app DB pool | 90d; importer must split URL → host/user/secret |
| `TRADING__SEC_DATABASE__POSTGRES_URL` (credentials embedded in URL) | sec-postgres | Database | SEC data pipeline | 90d; same URL-splitting |
| `FRED_API_KEY` | fred | RegulatoryData | macro data fetcher | 365d (provider-issued) / on compromise |
| `TRADING__NOTIFICATIONS__TELEGRAM__BOT_TOKEN` | telegram-alerts | Notification | notifications component | 180d / on leak |
| `TRADING__NOTIFICATIONS__TELEGRAM__CHAT_ID` | telegram-alerts | Notification | notifications component | identifier, low sensitivity; registered for completeness |
| Webhook URL + credentials (notifications component) | alert-webhooks | Notification | webhook posting | 180d / on leak |
| `TRADING__OBSERVABILITY__API_TOKEN` | metrics-server | Infrastructure | metrics server request auth | 180d |
| Dashboard login password (Argon2-verified via `PasswordVerifier`) | metrics-server | Application | metrics server dashboard login | password itself is a custody candidate; today only its hash exists on disk |
| `TRADING__BROKER__HOST` / `PAPER_PORT` / `LIVE_PORT` | ibkr-gateway | Broker | TWS/Gateway endpoints | not secrets; registered as entity context only |
| `TRADING__DATABASE__MAX_CONNECTIONS`, `CONNECTION_TIMEOUT_SECONDS`, `ORDER__ORDER_TIMEOUT_SECONDS`, `RL__LOG_DIR`, `FACTORS__DATA_DIR`, `SYMBOL_CACHE_PATH`, `MONITORING_PERSIST_DIR` | — | — | non-secret config | out of scope (registry tracks credentials only) |

**Gaps the registry should eventually close** (not reachable by the Phase-3 importer):

- IBKR gateway/TWS login credentials live outside the env file entirely — no inventory,
  no rotation discipline. Candidate for a manual vault entry now, "observer entry" later.
- The dashboard login exists only as an Argon2 hash on the consumer side; custody of the
  password itself is the fix, not tracking the hash.

## Appendix B — Policy defaults (seeds, adjustable)

| Kind | Base interval | Rationale |
|---|---|---|
| Database | 90d | Highest blast radius; frequent rotation is cheap (app-side DSN) |
| Broker | 90d | Financial control plane |
| Notification / MarketData / Infrastructure / Application | 180d | Medium impact, often provider-integrated |
| RegulatoryData | 365d | Provider-issued API keys with their own lifecycle |

Multipliers: criticality `High` ×0.5 / `Low` ×2; reuse `≥2` ×0.5 (and floors status at
`Reused`); strength below `Weak` floors status at `Weak`; `expires_at` drives
`DueSoon`/`Overdue` independent of age; `ToolManaged` suppresses age-based statuses by
default (per-entity override re-includes).
