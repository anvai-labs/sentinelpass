# Multi-Device Sync

> Status Note (2026-02-26): This document describes the sync protocol and intended relay behavior. Some relay hardening controls listed here (for example certain config-driven limits and operational safeguards) are partially implemented or pending wiring in the current code. See `docs/GAP_REVIEW_2026-02-26.md`, `docs/REQUIREMENTS.md`, and `ROADMAP.md` for current implementation status and remediation priorities.

End-to-end encrypted sync between SentinelPass devices via a relay server. The relay never sees plaintext — all payloads are encrypted with the vault's DEK before leaving the device.

## At a Glance

| Property | Value |
|----------|-------|
| Transport encryption | AES-256-GCM (vault DEK, per-blob random nonce) |
| Request authentication | Ed25519 signatures over canonical request string |
| Pairing key derivation | HKDF-SHA256 (6-digit code + random salt) |
| Conflict resolution | Last-Write-Wins (higher version → higher timestamp → keep local) |
| Feature gate | `sync` (disabled by default; enables `reqwest`, `hkdf`) |
| Relay default listen | `127.0.0.1:8743` |
| Relay storage | SQLite (`relay.db`) |
| Bootstrap TTL | 300 seconds, single-use |

## System Map

```text
┌──────────────┐          ┌───────────────────┐          ┌──────────────┐
│   Device A   │          │   Relay Server    │          │   Device B   │
│              │          │                   │          │              │
│  Vault + DEK │──push──▶│  sync_entries     │◀──push───│  Vault + DEK │
│              │◀──pull───│  (encrypted blobs)│──pull──▶│              │
│              │          │                   │          │              │
│  Ed25519 SK  │──sign──▶│  Verify Ed25519   │◀──sign───│  Ed25519 SK  │
└──────────────┘          └───────────────────┘          └──────────────┘
                                   │
                          No plaintext ever
                          reaches the relay
```

## Sync Lifecycle

### 1. Initialize Sync (first device)

```text
Device A                           Relay
   │                                  │
   │  POST /api/v1/devices/register   │
   │  { device_id, name, type,        │
   │    public_key, vault_id }        │
   │─────────────────────────────────▶│
   │                                  │  Create vault + device record
   │  { status: "registered" }        │
   │◀─────────────────────────────────│
   │                                  │
   │  POST /api/v1/sync/full-push     │
   │  (all entries, encrypted)        │
   │─────────────────────────────────▶│
   │                                  │  Store encrypted blobs
   │  { accepted, server_sequence }   │
   │◀─────────────────────────────────│
```

### 2. Pair a New Device

```text
Device A (existing)                Relay                   Device B (new)
   │                                 │                          │
   │  generate pairing code (6 digits)                          │
   │  derive pairing_key = HKDF(code, salt)                     │
   │  encrypt VaultBootstrap with pairing_key                   │
   │                                 │                          │
   │  POST /pairing/bootstrap        │                          │
   │  { token, encrypted, salt }     │                          │
   │────────────────────────────────▶│                          │
   │                                 │                          │
   │  Display code to user ──────────────────(out of band)────▶│
   │                                 │                          │
   │                                 │  GET /pairing/bootstrap  │
   │                                 │◀─────────────────────────│
   │                                 │  { encrypted, salt }     │
   │                                 │─────────────────────────▶│
   │                                 │                          │
   │                                 │  derive pairing_key      │
   │                                 │  decrypt VaultBootstrap   │
   │                                 │  extract: kdf_params,     │
   │                                 │    wrapped_dek, relay_url │
   │                                 │                          │
   │                                 │  POST /devices/register  │
   │                                 │◀─────────────────────────│
   │                                 │                          │
   │                                 │  POST /sync/full-pull    │
   │                                 │◀─────────────────────────│
   │                                 │  (all encrypted blobs)   │
   │                                 │─────────────────────────▶│
```

### 3. Incremental Push / Pull

```text
Device                             Relay
   │                                 │
   │  Collect pending entries        │
   │  (sync_state = 'pending')       │
   │                                 │
   │  POST /api/v1/sync/push         │
   │  { device_sequence,             │
   │    entries: [SyncEntryBlob…] }  │
   │────────────────────────────────▶│
   │                                 │  Validate device_sequence > last
   │                                 │  LWW check per entry
   │                                 │  Increment server_sequence
   │  { accepted, rejected,          │
   │    server_sequence }            │
   │◀────────────────────────────────│
   │                                 │
   │  POST /api/v1/sync/pull         │
   │  { since_sequence }             │
   │────────────────────────────────▶│
   │                                 │
   │  { entries, server_sequence,    │
   │    has_more }                   │
   │◀────────────────────────────────│
   │                                 │
   │  Resolve conflicts (LWW)       │
   │  Apply remote changes           │
   │  Mark entries synced            │
```

### 4. Revoke a Device

```text
Device A                           Relay
   │                                 │
   │  POST /devices/{id}/revoke      │
   │────────────────────────────────▶│
   │                                 │  Set revoked=1, revoked_at=now()
   │  { status: "revoked" }          │
   │◀────────────────────────────────│
   │                                 │
   │  Revoked device's future        │
   │  requests → 401 Unauthorized    │
```

## CLI Commands

All sync commands live under `sentinelpass sync`:

| Command | Description | Feature gate |
|---------|-------------|--------------|
| `sync init --relay-url <URL> [--device-name <NAME>]` | Initialize sync, register with relay, full-push | `sync` |
| `sync now` | Run incremental push + pull cycle | `sync` |
| `sync status` | Show sync config + pending change count | — |
| `sync device-list` | List all devices registered in vault | `sync` |
| `sync device-revoke <DEVICE_ID>` | Revoke a device's sync access | `sync` |
| `sync pair-start` | Generate pairing code + upload bootstrap | `sync` |
| `sync pair-join --relay-url <URL> --code <CODE>` | Join vault using pairing code | `sync` |
| `sync disable` | Turn off sync (keeps local data) | — |

## Relay Server

### Configuration (`relay.toml`)

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `127.0.0.1:8743` | Bind address |
| `storage_path` | `relay.db` | SQLite database path |
| `max_entries_per_vault` | `10000` | Max sync entries per vault |
| `max_payload_size` | `65536` | Max encrypted payload bytes |
| `rate_limit_per_minute` | `60` | Requests per minute per device |
| `pairing_ttl_secs` | `300` | Bootstrap blob expiration |
| `max_active_pairings` | `5` | Concurrent unexpired pairing slots |
| `tombstone_retention_days` | `90` | Days to keep tombstones |
| `nonce_window_secs` | `300` | Auth nonce dedup window |

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/devices/register` | — | Register a new device |
| `GET` | `/api/v1/devices` | Ed25519 | List devices in vault |
| `POST` | `/api/v1/devices/{id}/revoke` | Ed25519 | Revoke a device |
| `POST` | `/api/v1/sync/push` | Ed25519 | Push incremental changes |
| `POST` | `/api/v1/sync/pull` | Ed25519 | Pull changes since sequence |
| `POST` | `/api/v1/sync/full-push` | Ed25519 | Upload entire vault |
| `POST` | `/api/v1/sync/full-pull` | Ed25519 | Download entire vault |
| `GET` | `/api/v1/sync/status` | Ed25519 | Vault entry count + sequence |
| `POST` | `/api/v1/pairing/bootstrap` | — | Upload encrypted bootstrap |
| `GET` | `/api/v1/pairing/bootstrap/{token}` | — | Fetch + consume bootstrap |
| `GET` | `/health` | — | JSON health check with `status`, `service`, and `version` |

Health response example:

```json
{
  "status": "ok",
  "service": "sentinelpass-relay",
  "version": "0.6.3"
}
```

### Run

```bash
# Default config
cargo run --bin sentinelpass-relay

# Custom config
cargo run --bin sentinelpass-relay -- --config /path/to/relay.toml

# Override listen address
cargo run --bin sentinelpass-relay -- --listen 0.0.0.0:9000
```

## Cryptographic Details

### Extended Key Hierarchy (with sync paths)

```text
                    MASTER PASSWORD
                           │
                           ▼
                    ┌──────────────┐
                    │   Argon2id   │
                    └──────┬───────┘
                           │
                  32-byte Master Key
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Vault Key  │ │  HMAC Key   │ │  Biometric  │
    │  (wrapped)  │ │  (derived)  │ │   Wrapper   │
    └──────┬──────┘ └─────────────┘ └─────────────┘
           │
           ▼
    Data Encryption Key (DEK)
           │
     ┌─────┴──────────────────┐
     │                        │
     ▼                        ▼
  Local vault            Sync payloads
  AES-256-GCM            AES-256-GCM
  (per-entry nonce)      (per-blob nonce)
                              │
                         ┌────┴────┐
                         │ Padding │  ← bucket sizes: 256..8192
                         └────┬────┘
                              ▼
                     Relay (opaque blobs)

    ─── Device Identity (independent) ───

    Ed25519 keypair (generated per device)
           │
     ┌─────┴──────┐
     │ Signing Key │ ← stored encrypted with DEK in sync_metadata
     └─────┬──────┘
           │
           ▼
    Request signatures (canonical string)

    ─── Pairing (ephemeral) ───

    6-digit code + 16-byte salt
           │
           ▼
    HKDF-SHA256 ("sentinelpass-v1")
           │
           ▼
    32-byte pairing key
           │
           ▼
    AES-256-GCM encrypt VaultBootstrap
    (kdf_params, wrapped_dek, relay_url, vault_id)
```

### Wire Format (sync entry payload)

```text
┌──────────┬────────────────────────┬──────────┐
│  Nonce   │      Ciphertext        │   Tag    │
│ 12 bytes │    variable length     │ 16 bytes │
└──────────┴────────────────────────┴──────────┘
           ▲                        ▲
           │    encrypted with      │
           │    vault DEK           │
           │    (AES-256-GCM)       │
```

Minimum blob size: 29 bytes (12 nonce + 1 ciphertext + 16 tag).

Payloads are padded to fixed buckets (256, 512, 1024, 2048, 4096, 8192 bytes) before encryption to prevent metadata leakage.

### Authentication Header

```text
Authorization: SentinelPass-Ed25519 {device_id}:{timestamp}:{nonce}:{base64(signature)}
```

Canonical string (signed):

```text
{METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256(BODY)}
```

- Timestamp: Unix epoch seconds; must be within 300s of server time
- Nonce: UUID v4; checked for uniqueness (replay protection)
- Body hash: SHA-256 of raw request body (empty string if no body)

## Conflict Resolution

Last-Write-Wins with version precedence:

| Local version | Remote version | Local timestamp | Remote timestamp | Resolution |
|:---:|:---:|:---:|:---:|:---|
| 3 | 5 | any | any | **Accept remote** (higher version) |
| 5 | 3 | any | any | **Keep local** (higher version) |
| 3 | 3 | 1000 | 2000 | **Accept remote** (same version, later timestamp) |
| 3 | 3 | 2000 | 1000 | **Keep local** (same version, earlier remote) |
| 3 | 3 | 1000 | 1000 | **Keep local** (tie-break) |
| — | 1 | — | any | **Accept new** (no local copy) |
| 3 | 3 | any | tombstone | **Accept remote** if version ≥ local |
| 3 | 2 | any | tombstone | **Keep local** (rollback rejected) |

Tombstones (soft-deletes) are treated as regular entries for version comparison. Rollback attacks are prevented by always rejecting lower versions.

## Source File Map

| File | Responsibility |
|------|----------------|
| `sentinelpass-core/src/sync/mod.rs` | Module root, re-exports |
| `sentinelpass-core/src/sync/models.rs` | `SyncEntryBlob`, `PushRequest/Response`, `PullRequest/Response`, payload structs |
| `sentinelpass-core/src/sync/crypto.rs` | `encrypt_for_sync`, `decrypt_from_sync`, `pad_payload`, `unpad_payload` |
| `sentinelpass-core/src/sync/auth.rs` | `canonical_string`, `sign_request`, `format_auth_header`, `verify_auth_header` |
| `sentinelpass-core/src/sync/device.rs` | `DeviceIdentity` (Ed25519 keypair, persist to DB) |
| `sentinelpass-core/src/sync/pairing.rs` | `generate_pairing_code`, `derive_pairing_key` (HKDF), bootstrap encrypt/decrypt |
| `sentinelpass-core/src/sync/conflict.rs` | `ConflictResolver::resolve` (LWW), `Resolution` enum |
| `sentinelpass-core/src/sync/change_tracker.rs` | Collect pending blobs, mark synced, tombstone tracking |
| `sentinelpass-core/src/sync/config.rs` | `SyncConfig` (load/save from `sync_metadata` table) |
| `sentinelpass-core/src/sync/client.rs` | `SyncClient` (HTTP + Ed25519 auth) — feature-gated `sync` |
| `sentinelpass-core/src/sync/engine.rs` | `SyncEngine::sync` (push → pull → apply) — feature-gated `sync` |
| `sentinelpass-relay/src/main.rs` | Relay binary entry point, CLI args |
| `sentinelpass-relay/src/server.rs` | Axum router, route registration |
| `sentinelpass-relay/src/config.rs` | `RelayConfig` (TOML parsing, defaults) |
| `sentinelpass-relay/src/auth.rs` | Auth middleware (Ed25519 verify, nonce dedup) |
| `sentinelpass-relay/src/storage/mod.rs` | Relay SQLite schema + queries |
| `sentinelpass-relay/src/handlers/devices.rs` | Register, list, revoke handlers |
| `sentinelpass-relay/src/handlers/sync.rs` | Push, pull, full-push, full-pull, status handlers |
| `sentinelpass-relay/src/handlers/pairing.rs` | Bootstrap upload + fetch handlers |
