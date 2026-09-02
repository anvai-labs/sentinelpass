# ADR-001: Credential Registry by Logical Entity

| | |
|---|---|
| **Status** | Proposed |
| **Date** | 2026-09-02 |
| **Area** | `sentinelpass-core` (schema v5, crypto, vault), `sentinelpass-cli`, `sentinelpass-ui` |
| **Related** | [TECHNICAL_DEBT.md](../../../../TECHNICAL_DEBT.md) deferred item 1 (schema v5 typed payloads + entry ownership); `crypto/health.rs` password-health analysis; v0.8.0 `sentinelpass exec`/`env` secret serving with per-client allowlist grants |

## Summary

Give SentinelPass a **credential registry**: credentials grouped by the logical entity they
belong to (a broker, a market-data API, a database, a notification webhook…), with
password-reuse detection across entities, age- and risk-based rotation recommendations, and
a read-only posture dashboard. The registry is not a second store of secrets — full secrets
stay in the vault as ordinary encrypted entries (decision D1), and the registry layer holds
only entity metadata and derived, vault-keyed material.

## Context

Today the vault is a flat list. An entry has a `credential_type` discriminator
(`Password | ApiKey | PasskeyReference`, `vault/mod.rs:32-37`) but no grouping concept:
no folders, tags, entities, or ownership (verified across `database/*.rs` and
`vault/mod.rs`). There is no rotation timestamp and no password history — `update_entry`
stamps `modified_at` (`vault/mod.rs:610`) but cannot distinguish a password change from a
title edit.

Some posture machinery already exists: `crypto/health.rs` computes strength distribution,
a 0–100 vault health score, and password-reuse detection (`is_reused`, `reuse_count`). But
reuse is detected by grouping on **raw decrypted password bytes in memory**
(`health.rs:217-231`, `:349-363`), recomputed on every scan; it cannot be indexed,
persisted, or diffed over time, and it has no notion of *which* entities share a password.
`sentinelpass health` (CLI, `commands/generate.rs::handle_health`) exposes this report
today; the Tauri UI does not surface it at all (no health command is registered in
`src-tauri/src/main.rs:1273-1298`).

The driving use case is operator infrastructure credentials: a multi-component trading
system whose secrets live in an unmanaged env file (`~/.ibkr_tradeapp.env`, 18 keys —
two Postgres connection URLs with embedded credentials, a FRED API key, a Telegram bot
token/chat id, an observability API token; see Appendix A), plus webhook/Telegram
credentials in a notifications component and an Argon2-hashed dashboard login. No
inventory, no rotation discipline, no reuse visibility across components. This is the
first onboarding target for the registry, and the shape of its taxonomy (broker /
market-data / regulatory-data / notification / database / infrastructure) comes from that
inventory.

## Decision drivers

1. **Blast radius.** Derived material about secrets (e.g. equality tags) must not weaken
   the vault's at-rest posture: a stolen `vault.db` without the master key must reveal
   nothing new.
2. **Custody enables action.** Recommendations that cannot be acted on inside the product
   (rotate *now*, with a generated replacement) decay into shelfware. Monitoring-only
   designs were considered and rejected (see Alternatives) for the MVP.
3. **Existing seams.** Reuse `crypto/strength.rs` scoring, `crypto/health.rs` analysis,
   the hand-rolled migration runner, and the `domain_mappings` child-table pattern rather
   than inventing parallel structures.
4. **Surface discipline.** The browser extension must not gain any new read path
   (CLAUDE.md rule: never return more than the requested credential). The registry is a
   desktop-UI + CLI feature.
5. **Sync-agnostic core.** Local-first; sync integration is additive and deferred, not a
   design dependency.

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
the registry needs; the registry's job is organization and posture, not storage. The
"smaller blast radius" argument for (a) dissolves once the derived material is properly
keyed (D4): the only new at-rest artifact is HMAC tags under a DEK-derived key, which
reveal nothing to a database-only adversary. Option (a) survives in reduced form as the
*import bridge* (Phase 3 reads the env file once) and as a future "observer entry" type
for secrets that cannot move yet (see MVP vs. later).

This decision also absorbs TECHNICAL_DEBT.md deferred item 1 ("Schema v5 typed payloads:
api-key provider/scopes/expiry metadata + entry ownership"): the registry's schema v5 is
that schema work, with entry ownership realized as entity membership.

### D2 — Reuse semantics: exact-match keyed index first

- **MVP: exact-match reuse detection** via a persisted equality tag — HMAC-SHA256 of the
  secret under a key derived from the DEK (D4). Equal secret ⇔ equal tag, so reuse across
  entities is a `GROUP BY tag`. Normalization policy: **exact UTF-8 bytes, no trimming or
  case-folding** — normalization silently changes what "same password" means and can merge
  distinct secrets; if it is ever added it must be a new `algorithm_version`, never a
  reinterpretation of existing tags.
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
  `sentinelpass-protocol` IPC with allowlist grants — the same pattern sandhi (sibling PR
  #176) and victor (#985) already use — so an ops console in *another* repository can
  consume posture data without SentinelPass growing a web server.

Read-only first because the data model and policy engine are the risky parts; workflows
are thin once recommendations exist and are trusted.

### D4 — Where the equality index lives and who reads it

**Storage.** A `secret_equality_index` table inside `vault.db`, rows of
`(entry_id, tag BLOB(32), algorithm_version, updated_at)` where
`tag = HMAC-SHA256(HKDF(DEK, "sentinelpass-registry-equality-v1"), secret_bytes)`.
The HKDF-from-DEK derivation follows the existing precedent in `sync/pairing.rs:14-19`
(HKDF-SHA256 with a purpose label); `hmac` is already a workspace dependency.

**Placement rationale.** Inside the vault database the index is covered by the same
file-permission story as everything else, and the keying makes it inert to a
database-only thief (see Threat model). A sidecar store outside `vault.db` would put
crown-jewel-adjacent data outside the encrypted envelope and complicate backup/restore —
rejected.

**Read path.** `VaultManager` exclusively. The index is:

- never returned over native messaging / to browser extensions (CLAUDE.md rule 8);
- never exported (`import_export` must exclude it — it is derived data, rebuilt lazily);
- never synced (derived data; see below);
- surfaced only as *aggregates* (reuse clusters, counts) to CLI and Tauri UI.

**Write path / rotation detection.** `add_entry` and `update_entry` recompute the tag.
In `update_entry`, a changed tag is the first reliable "password changed" signal the
codebase has had — on change, stamp `password_rotated_at` in the entry's lifecycle row.
This solves the "cannot distinguish password change from title edit" gap without a
plaintext comparison.

**Cross-device.** Paired devices share the DEK, so tags are deterministic across devices;
nevertheless the index is local-only and rebuilt lazily (opportunistic sweep on unlock or
health scan, plus on every add/update). Rebuilding is O(n) HMACs — cheap relative to the
decryption the scan already performs.

## Detailed design

### Entity taxonomy

- `entities` table: `entity_id` (UUID), `name` (unique, user-facing), `kind`, `criticality`
  (`Low | Medium | High`), `notes`, `created_at`, `modified_at`.
- `EntityKind` is a fixed enum for MVP: `Broker | MarketData | RegulatoryData |
  Notification | Database | Infrastructure | Application | Other`. Entities are
  user-defined records *of* a kind; kinds are closed to keep policy defaults total, and
  `Other` is the escape hatch. Seed entities for the first onboarding target come from
  Appendix A.
- `entity_memberships` table: `entry_id` (**UNIQUE**, FK CASCADE) + `entity_id`
  (FK CASCADE) + optional `label` (e.g. "paper", "prod"). Single membership per entry for
  MVP — it matches the recommendation model ("entity X's DB credential") and the
  structural precedent is `domain_mappings` (`models.rs:25-30`, child table + FK CASCADE).
  Many-to-many is a later extension if a real credential-straddles-two-entities need
  appears; nothing in the policy engine assumes uniqueness beyond MVP convenience.

### Schema v5

Hand-rolled migration, per the established runner (refinery is *not* used —
`CURRENT_SCHEMA_VERSION: i32 = 4` at `schema.rs:9`, sequential arms in
`migrations.rs:233-253`):

- `migrate_v4_to_v5()` following the `migrate_v1_to_v2` template (`execute_batch`,
  `BEGIN…COMMIT`, version bump; test fixture pattern from
  `migrations.rs:336`/`create_v1_db` at `:260`).
- New tables: `entities`, `entity_memberships`, `secret_equality_index`,
  `entry_lifecycle`.
- `entry_lifecycle`: `entry_id` (UNIQUE, FK CASCADE), `password_rotated_at`,
  `expires_at` (nullable — the api-key expiry metadata from deferred TD item 1),
  `rotation_interval_days_override` (nullable), `source`
  (`Manual | Imported | Generated`).
- Fresh-install path mirrors the same DDL in `schema.rs` (as v4 additions did at
  `schema.rs:113-134`).
- `CredentialType` grows no new variants in MVP. Api-key typed payloads
  (provider/scopes/expiry) land with this schema as lifecycle/metadata columns rather
  than a payload format change; a typed payload refactor can follow without a second
  migration.

### Rotation policy engine

Pure function, no I/O, fully unit-testable:

```
recommend(entry, lifecycle, membership, entity, tag_stats, analysis)
  -> RotationRecommendation { status: Ok | DueSoon | Overdue | Reused | Weak, reasons }
```

Defaults (all overridable per entity or per entry):

- Base interval by kind: `Database` 90d, `Broker` 90d, `Notification` 180d,
  `MarketData` 180d, `Infrastructure` 180d, `Application` 180d, `RegulatoryData` 365d
  (provider-governed keys), `Other` 180d.
- Criticality multiplier: `High` ×0.5, `Low` ×2.
- Reuse multiplier: `reuse_count ≥ 2` → ×0.5 and status at least `Reused`.
- Strength: analysis below the configured threshold (default `PasswordStrength::Weak`)
  → status `Weak` regardless of age.
- `expires_at` → `DueSoon` at T-14d, `Overdue` past expiry.
- Age source: `entry_lifecycle.password_rotated_at` (D4 write path), falling back to
  `created_at` for entries not yet swept.

No auto-rotation in MVP: recommendations only. The generator
(`crypto/password.rs`, exposed as `generate_password` in CLI/UI) is the Phase-4 rotation
workflow's engine.

### Surfaces

- **Core:** a `registry` module in `sentinelpass-core` (entity CRUD, membership assign,
  lifecycle getters, policy engine, equality index maintenance) wired into
  `VaultManager` like the existing `*_ops.rs` split (`health_ops.rs`,
  `ssh_ops.rs`, …).
- **CLI:** nested `registry` subcommand group (pattern: `SecretCommands`,
  `main.rs:449`): `registry entity add/list`, `registry assign`, `registry status`,
  `registry report`. Env-file importer in Phase 3 (`registry import-env`).
- **Tauri UI:** new read-only posture panel in the vault screen (new header button +
  panel, per the `index.html` structure) backed by new Tauri commands
  (`get_registry_overview`, `list_entities`, `get_rotation_recommendations`) registered
  in `generate_handler!` (`src-tauri/src/main.rs:1273-1298`). The panel also becomes the
  first UI consumer of the existing `crypto/health.rs` summary.
- **Browser extension:** no changes, by design (D3/decision drivers).

### Audit

New `AuditEventType` variants (each needs an arm in `severity_for_event`,
`audit.rs:187-227`): `RegistryEntityCreated`, `RegistryEntityDeleted`,
`EntryAssignedToEntity`, `SecretRotated { entry_id }` (emitted on tag change),
`RegistryIndexRebuilt`. Recommendation *reads* are not audited (derived data, high
volume); mutations are.

### Backfill

The v4→v5 migration does **not** decrypt entries to build tags (migration runs at open
on the schema path; decrypting every secret there would slow vault open and widen the
failure surface). Instead: lazy backfill — a sweep on first unlock after upgrade (and on
every health scan) computes tags for `Password`/`ApiKey` entries missing index rows,
emits `RegistryIndexRebuilt` once, then marks complete. `PasskeyReference` and TOTP
secrets are excluded (passkeys carry no reusable secret; TOTP seeds are unique per entry
by construction).

## Threat model

| Adversary / event | With registry | Notes |
|---|---|---|
| Stolen `vault.db` (no master key) | Learns nothing new. Tags are HMAC outputs under a DEK-derived key; without the DEK they are opaque, including *equality* between two tags. | The at-rest posture is unchanged from today. |
| Unlocked process / memory adversary | Gains nothing new: it can already decrypt every secret and could compute all tags itself. | Same trust boundary as the existing vault. |
| Relay / sync server | Never sees the index; sync payloads are unchanged per-entry encrypted blobs. | Registry tables are not sync entry types. |
| Browser extension compromise | Sees no registry data; no new native-messaging message types. | Preserves CLAUDE.md rule 8. |
| Malicious importer (Phase 3) | Import parses plaintext env material in-memory, zeroizes buffers, emits `DataImported` audit; values never logged. | Import is the one new plaintext-reading path and is CLI-only. |
| Tag collision /cryptographic | 256-bit HMAC tags; collision risk negligible. `algorithm_version` column allows future normalization/key rotation without reinterpretation. | |

Residual risk accepted for MVP: within an *unlocked* session, the dashboard reveals
which entities share a password — that is the feature, and it is only available to
whoever can already unlock the vault.

## MVP vs. later

| Capability | MVP (this ADR's slices) | Later |
|---|---|---|
| Entity CRUD + membership | ✅ core + CLI + API | UI editors |
| Exact-match reuse detection (keyed index) | ✅ | — |
| Strength scoring integration | ✅ (existing analyzer) | Derived-pattern rules, similarity/MinHash |
| Rotation recommendations (age + risk policy) | ✅ read-only | Rotate-now workflows (generator wiring), policy editor |
| Posture dashboard | ✅ Tauri read-only panel + CLI report | External ops-console API over `sentinelpass-protocol` with allowlist grants |
| Env-file import (first onboarding) | ✅ Phase 3 | Generic CSV/other importers |
| Breach checks (HIBP k-anonymity) | — | ✅ fits keyed-tag design |
| Entity/lifecycle sync across devices | — | ✅ new `SyncEntryType` variants |
| "Observer" entries (hash+metadata only, secret stays external) | — | ✅ for secrets that cannot move yet (e.g. IBKR gateway login, Appendix A) |

## Migration path (slices; no code before this ADR is accepted)

1. **P1 — Core + schema.** `migrate_v4_to_v5` + registry module (entities, membership,
   lifecycle, equality index, policy engine, audit variants, lazy backfill) + CLI
   `registry` group. Ships dark (no UI).
2. **P2 — Dashboard.** Tauri posture panel + Tauri commands; UI surfaces health summary +
   registry overlays. Read-only.
3. **P3 — First onboarding.** `registry import-env` for `~/.ibkr_tradeapp.env` per
   Appendix A (URL-splitting for Postgres URLs, typed api-key entries, entity seeds);
   consumer cutover on the trading-system side via the already-shipped
   `sentinelpass exec`/`env` + allowlist grants. **The consumer-side changes live in that
   repository's own governance and are a dependency, not scope, of this ADR.**
4. **P4 — Lifecycle + breadth.** Rotate-now workflows, policy editor, similarity/breach
   checks, entity sync, observer entries, external console API.

Each slice is an independent PR; P1 gates everything else.

## Alternatives considered

1. **Hash-only sidecar registry (monitor-only).** Rejected for MVP (D1a): advisory-only,
   no custody, drifts from reality. Retained in reduced form as the import bridge and the
   later "observer entry" type.
2. **Registry tables outside `vault.db`.** Rejected (D4): crown-jewel-adjacent data
   outside the encrypted envelope; complicates backup/restore for zero benefit.
3. **Status quo (`crypto/health.rs` only).** Rejected: in-memory grouping cannot drive
   age-based policy (no rotation timestamps exist), has no entity dimension, and
   recomputes on every scan with no persistence.
4. **External secret manager (Vault, SOPS/AGE, 1Password Connect).** Rejected: violates
   the local-first product principle; the user owns this codebase and its roadmap.

## Consequences

**Positive**

- Rotation posture becomes real: first-class `password_rotated_at`, age/risk
  recommendations, and a dashboard that makes reuse across logical entities visible.
- Reuse detection becomes persisted, indexable, and privacy-preserving, replacing
  plaintext-bytes in-memory grouping.
- Absorbs deferred TD item 1 (schema v5 typed metadata + entry ownership) into one
  coherent migration.
- Extension surface unchanged; sync untouched in MVP.

**Negative / risks**

- A schema migration (v4→v5) with the usual risk — mitigated by the established
  sequential-migration test pattern (`create_v1_db` fixture lineage) extended with a
  `create_v4_db` fixture.
- Index staleness between sweeps is possible (e.g. rows written by an older binary);
  the lazy rebuild on unlock/scan bounds this, and missing rows degrade gracefully to
  `created_at`-based age.
- Single-membership-per-entry may force awkward entity choices; escape hatch documented
  (many-to-many later).
- New wire structs must use `Zeroizing<String>` for any secret-adjacent field — the
  secrets-as-`String` debt (TECHNICAL_DEBT.md deferred item 2) must not grow here.

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
`DueSoon`/`Overdue` independent of age.
