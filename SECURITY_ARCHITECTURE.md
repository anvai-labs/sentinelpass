# PASSWORD MANAGER - SECURITY ARCHITECTURE SPECIFICATION

> **Status Note (2026-09-04):** This document contains a mixture of implemented
> controls and target-state architecture. The 2026-09-04 review identified new
> release-blocking work in recovery, authenticated ciphertext context, sync, IPC,
> mobile, backup, and release assurance. Use
> `docs/SECURITY_STATUS_MATRIX.md` for current implementation evidence and
> `docs/STRATEGIC_REMEDIATION_PLAN_2026-09-04.md` plus ADR-003 through ADR-010 for
> the active remediation design. A section in this document must not be treated as a
> shipped claim unless the status matrix marks the control Implemented or Verified.

**Status Key:**
- ✅ **Implemented** - Fully implemented and verified
- ⚠️ **Partial** - Partially implemented (see notes)
- 🧪 **Experimental** - Reachable but not approved for production credentials
- 📋 **Planned** - Target-state design, not yet implemented

## 1. HIGH-LEVEL ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER INTERFACES                                     │
├──────────────┬──────────────┬──────────────┬──────────────────────────────────┤
│   Desktop    │   Chrome    │   Firefox   │    SSH Agent Integration          │
│   (Tauri)    │ Extension   │ Extension   │                                   │
└──────┬───────┴──────┬───────┴──────┬──────┴───────────────────┬──────────────┘
       │              │              │                           │
       │    Native    │    Native    │                           │
       │   Messaging  │   Messaging  │                           │
       │              │              │                           │
       └──────────────┴──────────────┘                           │
                              │                                    │
                              ▼                                    │
                    ┌─────────────────────┐                       │
                    │   Core Daemon       │                       │
                    │   (Rust Binary)     │                       │
                    └──────────┬──────────┘                       │
                               │                                    │
                         ┌─────┴──────┐                            │
                         ▼            ▼                            │
              ┌──────────────┐ ┌──────────────┐                   │
              │ Crypto Engine│ │ Sync Engine  │                   │
              │ - Argon2id   │ │ (optional)   │                   │
              │ - AES-256-GCM│ │ - Ed25519    │                   │
              │ - Key Mgmt   │ │ - HKDF       │                   │
              └──────┬───────┘ └──────┬───────┘                   │
                     │                │                              │
                     ▼                ▼                              │
              ┌──────────────┐ ┌──────────────┐                   │
              │ SQLite DB    │ │ Relay Server │                   │
              │ (encrypted   │ │ (opaque blobs│                   │
              │  entries)    │ │  only)       │                   │
              └──────────────┘ └──────────────┘                   │
                                                                     │
                               ┌─────────────────────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │  OS Keystore       │
                    │  - Keychain (macOS)│
                    │  - DPAPI (Windows) │
                    └─────────────────────┘
```

---

## 2. THREAT MODEL AND MITIGATIONS

| Threat | Attack Vector | Mitigation Strategy | Status |
|--------|---------------|---------------------|--------|
| **Stolen Laptop** | Physical access to encrypted database | • Argon2id with high memory cost (256MB)<br>• Master password required<br>• No plaintext keys stored<br>• Biometric unlock stores OS-protected DEK material, not the master password | ✅ |
| **Malware** | Process memory reading | • Zeroization on unlock timeout<br>• ~~mlock() to prevent swap~~ (memory locking was removed with the unused `memsec` dependency; secrets are zeroized but not locked)<br>• ASLR and PIE enabled | ⚠️ (zeroization only; no memory locking) |
| **Memory Scraping** | Heap inspection for keys | • Zeroizing wrappers for owned secrets<br>• ~~Secrets in locked memory pages~~ (memory locking removed; no swap protection today)<br>• Minimize time in memory<br>• Wire/IPC/export structs still carry `String` secrets in places (SR-CRYPTO-004 sweep pending) | ⚠️ |
| **Clipboard Snooping** | Other apps reading clipboard | • Auto-clear clipboard after 30s<br>• Protected API on macOS<br>• User notification on copy | ⚠️ (auto-clear partial) |
| **Keylogging** | Input capture of master password | • Virtual keyboard option (desktop)<br>• Biometric bypass<br>• Password quality meter | 📋 (virtual keyboard) |
| **Browser Extension Compromise** | Malicious extension accessing vault | • Native messaging whitelist<br>• Domain matching enforced daemon-side<br>• User approval per domain<br>• No API access to full vault | ✅ |
| **SQLite File Theft** | Copy of database file | • Per-field AES-256-GCM encryption of secret values (not whole-database encryption)<br>• Per-entry random nonce<br>• Key wrapping with KDF<br>• Identity metadata (domain mappings, SSH/TOTP metadata) is still stored in plaintext and is not yet AAD-bound (ADR-005) | ⚠️ (per-field only; metadata plaintext) |
| **Offline Brute Force** | Dictionary attacks on DB | • Argon2id: t=3, m=256MB, p=4<br>• Exponential backoff on failures<br>• Account lockout after 10 attempts<br>• No timing leak on password check | ✅ |
| **Timing Attacks** | Response time analysis | • Constant-time comparisons<br>• Fixed delay on auth<br>• Dummy operations for padding | ⚠️ (constant-time only) |
| **Phishing** | Fake websites requesting credentials | • Domain matching with TLD validation<br>• Visual domain confirmation<br>• URL bar integration | ⚠️ (domain matching only) |
| **CSRF on Autofill** | Malicious site triggering fill | • User gesture required<br>• Origin validation<br>• Frame depth checking | ✅ |
| **Relay Compromise** | Attacker gains relay server access | • All payloads encrypted with vault DEK (relay is zero-knowledge)<br>• Ed25519 device keys never stored on relay<br>• Relay holds only public keys + opaque blobs | ✅ |
| **Device Impersonation** | Forged sync requests | • Ed25519 signature over canonical request string<br>• Signing key stored encrypted with DEK locally<br>• Public key registered at pairing time | ✅ |
| **Replay Attack (Sync)** | Re-sending captured sync requests | • UUID nonce in every auth header, checked for uniqueness<br>• Timestamp freshness window (300s)<br>• Monotonic device_sequence validation | ✅ |
| **Pairing Interception** | Eavesdropping on pairing exchange | • Bootstrap encrypted with HKDF-derived key (6-digit code + salt)<br>• 5-minute TTL, single-use consumption<br>• Code transmitted out-of-band<br>• **Known gap:** a 6-digit code gives limited entropy and permits offline guessing; v2 replaces it with a high-entropy QR secret or PAKE (ADR-006) | 🧪 |
| **Metadata Leakage (Sync)** | Payload size reveals entry type/length | • A padding helper exists but is **not used** by the production sync path — payload sizes leak today; either authenticated padding lands with sync v2 or this mitigation claim is removed (TD-NET-07) | 🧪 |
| **Rollback Attack** | Pushing older entry versions | • sync_version must be monotonically increasing<br>• Lower versions rejected by both relay and client<br>• **Known gap:** version numbers and tombstone state are not cryptographically authenticated end to end, so version lineage cannot be fully trusted; authenticated lineage lands with sync v2 (ADR-006) | ⚠️ |
| **Cross-Vault Access** | Device accessing wrong vault | • vault_id scoped per device at registration<br>• Relay enforces vault isolation on all queries | ✅ |

---

## 3. CRYPTOGRAPHIC DESIGN

### 3.1 Algorithm Specifications

```
┌─────────────────────────────────────────────────────────────────┐
│                    KEY DERIVATION                               │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm: Argon2id                                           │
│  Salt: 16 random bytes (stored in DB header)                   │
│  Memory: 256 MB (m=262144 blocks)                              │
│  Iterations: 3 (t=3)                                           │
│  Parallelism: 4 lanes (p=4)                                    │
│  Output: 32-byte master key                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION                                   │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm: AES-256-GCM                                        │
│  Key: 32 bytes                                                 │
│  Nonce: 96-bit (12 bytes) random per entry                     │
│  Tag: 128-bit authentication                                    │
│  Mode: Per-entry encryption (not whole-file)                   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Hierarchy

```
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
    └──────┬──────┘ └─────────────┘ └──────┬──────┘
           │                                 │
           ▼                                 ▼
    ┌─────────────┐                 ┌─────────────┐
    │     DEK     │                 │   OS        │
    │ (32 bytes)  │                 │ Keystore    │
    └──────┬──────┘                 └─────────────┘
           │
     ┌─────┴──────────────────┐
     │                        │
     ▼                        ▼
  Local vault            Sync payloads
  AES-256-GCM            AES-256-GCM
  (per-entry nonce)      (per-blob nonce, padded)

    ─── Device Identity (independent per device) ───

    Ed25519 keypair
    │  Signing key encrypted with DEK, stored in sync_metadata
    └──▶ Request signatures (canonical string → Ed25519 sig)

    ─── Pairing (ephemeral) ───

    6-digit code + 16-byte random salt
    └──▶ HKDF-SHA256 → 32-byte pairing key
         └──▶ AES-256-GCM encrypt VaultBootstrap
```

### 3.3 Cryptographic Flow

**Setup (First Run):**
```
1. User generates master password
2. Generate 16-byte salt: salt = randombytes(16)
3. Derive master key: MK = Argon2id(password, salt, t=3, m=256MB, p=4)
4. Generate data encryption key: DEK = randombytes(32)
5. Wrap DEK: WDEK = AES-256-GCM-Encrypt(MK, nonce1, DEK)
6. Store: salt, nonce1, WDEK in database header
7. Zero all intermediate keys from memory
```

**Unlock:**
```
1. User enters master password
2. Retrieve salt, nonce1, WDEK from DB
3. Derive MK = Argon2id(password, salt, ...)
4. Decrypt DEK = AES-256-GCM-Decrypt(MK, nonce1, WDEK)
5. Verify authentication tag (constant-time compare)
6. DEK zeroized on drop (memory locking was removed with the unused `memsec` dependency; swap protection is **not** currently provided)
7. Zero MK immediately after DEK extraction
```

**Biometric Enrollment:**
```
1. After successful password unlock
2. Store DEK material behind the OS biometric/keyring reference:
   - macOS: Keychain-backed biometric access
   - Windows: Windows Hello / current-user protected storage
3. Store reference ID in database
4. Future biometric unlock retrieves the DEK and unlocks the in-memory key hierarchy
```

**Entry Encryption:**
```
For each credential entry:
1. Generate entry_nonce = randombytes(12)
2. Serialize entry to JSON/MessagePack
3. ciphertext = AES-256-GCM-Encrypt(DEK, entry_nonce, plaintext)
4. Store: entry_nonce || ciphertext || auth_tag
```

### 3.4 Sync Encryption

**Wire Format (sync entry payload):**
```
┌──────────┬────────────────────────┬──────────┐
│  Nonce   │      Ciphertext        │   Tag    │
│ 12 bytes │    variable length     │ 16 bytes │
└──────────┴────────────────────────┴──────────┘
```
Minimum blob size: 29 bytes. Encrypted with vault DEK (AES-256-GCM). Each blob gets a unique random nonce.

**Payload Padding:**
Plaintext is padded to fixed bucket sizes (256, 512, 1024, 2048, 4096, 8192 bytes) before encryption. Format: `len(8-bytes LE) || data || zero-padding`. This prevents metadata leakage through payload size analysis.

**Pairing Flow:**
```
1. Device A generates 6-digit code + 16-byte random salt
2. Derive pairing_key = HKDF-SHA256(code, salt, info="sentinelpass-v1") → 32 bytes
3. Encrypt VaultBootstrap { kdf_params, wrapped_dek, relay_url, vault_id }
4. Upload encrypted blob + salt to relay (5-minute TTL, single-use)
5. Device B enters code, fetches blob + salt from relay
6. Derive same pairing_key, decrypt VaultBootstrap
7. Device B now has KDF params + wrapped DEK → can unlock vault with master password
```

**Auth Signature:**
```
Canonical string: {METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256(BODY)}
Header: SentinelPass-Ed25519 {device_id}:{timestamp}:{nonce}:{base64(signature)}
```
Timestamp must be within 300s of server time. Nonce (UUID v4) checked for uniqueness to prevent replay.

---

## 4. SQLITE DATABASE SCHEMA

```sql
-- ============================================================================
-- DATABASE SCHEMA VERSION 1.0
-- ============================================================================

-- Database metadata and versioning
CREATE TABLE db_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_params BLOB NOT NULL,           -- JSON: algorithm, salt, mem, iter, parallelism
    wrapped_dek BLOB NOT NULL,          -- Wrapped Data Encryption Key
    dek_nonce BLOB NOT NULL,            -- Nonce for DEK encryption (12 bytes)
    created_at INTEGER NOT NULL,        -- Unix timestamp
    last_modified INTEGER NOT NULL,     -- Unix timestamp
    biometric_ref TEXT,                  -- Reference to OS keystore entry
    CHECK(version = 1)
);

-- Insert initial metadata row
CREATE TRIGGER metadata_init AFTER INSERT ON db_metadata WHEN NEW.id != 1
BEGIN
    SELECT RAISE(ABORT, 'Only one metadata row allowed');
END;

-- Users (single-user for now, schema for future)
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    kdf_salt BLOB NOT NULL,             -- Per-user salt (16 bytes)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1))
);

-- Vaults/folders for organization
CREATE TABLE vaults (
    vault_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name BLOB NOT NULL,                 -- Encrypted
    parent_vault_id INTEGER,             -- NULL for top-level vaults
    icon BLOB,                          -- Optional encrypted metadata
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (parent_vault_id) REFERENCES vaults(vault_id)
);

-- Credential entries (the core table)
CREATE TABLE entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    title BLOB NOT NULL,                -- Encrypted
    username BLOB NOT NULL,             -- Encrypted
    password BLOB NOT NULL,             -- Encrypted
    url BLOB,                           -- Encrypted (nullable)
    notes BLOB,                         -- Encrypted (nullable)
    custom_fields BLOB,                 -- Encrypted JSON: [{name, value, type}]
    entry_nonce BLOB NOT NULL,          -- Per-entry nonce (12 bytes)
    auth_tag BLOB NOT NULL,             -- GCM auth tag (16 bytes)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    modified_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_used_at INTEGER,               -- For sorting/favorites
    favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0, 1)),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

-- SSH keys storage
CREATE TABLE ssh_keys (
    ssh_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    name BLOB NOT NULL,                 -- Encrypted
    private_key BLOB NOT NULL,           -- Encrypted (PEM or OpenSSH format)
    public_key BLOB,                     -- Encrypted (for convenience)
    passphrase BLOB,                      -- Encrypted (nullable)
    key_type TEXT NOT NULL,              -- 'rsa', 'ed25519', 'ecdsa'
    key_bits INTEGER,                    -- For RSA: 2048, 4096, etc.
    fingerprint BLOB,                    -- Unencrypted (for identification)
    entry_nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

-- TOTP secrets
CREATE TABLE totp_secrets (
    totp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,           -- Link to credential entry
    secret BLOB NOT NULL,                -- Encrypted base32 secret
    algorithm TEXT NOT NULL DEFAULT 'SHA1',  -- SHA1, SHA256, SHA512
    digits INTEGER NOT NULL DEFAULT 6 CHECK(digits IN (6, 8)),
    period INTEGER NOT NULL DEFAULT 30,     -- Seconds
    entry_nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

-- Domain mappings for autofill security
CREATE TABLE domain_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    domain TEXT NOT NULL,                -- Canonical domain (e.g., 'example.com')
    is_primary INTEGER NOT NULL DEFAULT 1 CHECK(is_primary IN (0, 1)),
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE,
    UNIQUE(entry_id, domain)
);

-- Audit log for security events
CREATE TABLE audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,            -- 'unlock', 'entry_view', 'entry_modify', etc.
    resource_type TEXT,                  -- 'entry', 'vault', 'ssh_key'
    resource_id INTEGER,
    details BLOB,                        -- Encrypted details
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    success INTEGER NOT NULL DEFAULT 1 CHECK(success IN (0, 1))
);

-- Failed unlock attempts (for rate limiting)
CREATE TABLE unlock_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    success INTEGER NOT NULL CHECK(success IN (0, 1)),
    ip_address TEXT                      -- For future remote access
);

-- Performance indexes
CREATE INDEX idx_entries_vault ON entries(vault_id);
CREATE INDEX idx_entries_favorite ON entries(favorite, last_used_at DESC);
CREATE INDEX idx_ssh_keys_vault ON ssh_keys(vault_id);
CREATE INDEX idx_domain_mapping ON domain_mappings(domain);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
```

---

## 5. RUST IMPLEMENTATION

### 5.1 Why Rust is Preferred

| Aspect | Rust | Python |
|--------|------|--------|
| Memory Safety | Compile-time guarantees, no GC pauses | GC pauses, reference cycles |
| Secret Zeroization | Explicit control with zeroize | Relies on GC, unpredictable |
| Binary Size | Static linking, single binary | Requires Python runtime |
| WebAssembly | Easy wasm-pack for future | Pyodide is slow |
| Concurrency | Fearless concurrency, no data races | GIL limitations |
| FFI | Excellent C interop for OS APIs | ctypes, but slower |
| Distribution | Single binary, no dependencies | venv, pip, dependency hell |
| **Verdict: RUST** | More secure, predictable, better for security-critical software | |

### 5.2 Project Structure

```
sentinelpass/                         # Workspace root
├── Cargo.toml                        # Workspace manifest
├── sentinelpass-core/                # Core library
│   └── src/
│       ├── crypto/                   # KDF, cipher, keyring, zeroization
│       ├── daemon/                   # IPC, native messaging, auto-lock
│       ├── database/                 # Schema, models, migrations
│       ├── sync/                     # Sync models, crypto, auth, engine
│       │   ├── models.rs             #   SyncEntryBlob, payloads
│       │   ├── crypto.rs             #   encrypt/decrypt/pad for sync
│       │   ├── auth.rs               #   Ed25519 canonical signing
│       │   ├── device.rs             #   DeviceIdentity (keypair)
│       │   ├── pairing.rs            #   HKDF pairing key derivation
│       │   ├── conflict.rs           #   LWW conflict resolver
│       │   ├── change_tracker.rs     #   Pending blob collection
│       │   ├── config.rs             #   SyncConfig (DB persistence)
│       │   ├── client.rs             #   HTTP client (feature: sync)
│       │   └── engine.rs             #   Push/pull orchestrator (feature: sync)
│       ├── vault.rs                  # VaultManager (CRUD, lock/unlock)
│       └── ...                       # audit, biometric, ssh, totp, platform
├── sentinelpass-cli/                 # CLI binary
├── sentinelpass-daemon/              # Background daemon
├── sentinelpass-host/                # Native messaging bridge
├── sentinelpass-ui/                  # Tauri desktop app
│   ├── src-tauri/
│   └── ...
├── sentinelpass-relay/               # Sync relay server
│   └── src/
│       ├── main.rs                   #   CLI + startup
│       ├── server.rs                 #   Axum router
│       ├── config.rs                 #   relay.toml parsing
│       ├── auth.rs                   #   Ed25519 middleware
│       ├── storage/                  #   Relay SQLite schema
│       └── handlers/                 #   devices, sync, pairing
├── browser-extension/
│   ├── chrome/                       # MV3 extension
│   └── firefox/                      # MV2 extension
└── tests/
```

### 5.3 Core Dependencies

The workspace uses centralized dependency management in the root `Cargo.toml`. Key security-relevant dependencies:

| Crate | Purpose |
|-------|---------|
| `argon2` | Argon2id key derivation |
| `aes-gcm` | AES-256-GCM encryption |
| `ed25519-dalek` | Ed25519 device signing (sync) |
| `hkdf` + `sha2` | HKDF-SHA256 pairing key derivation (sync, feature-gated) |
| `zeroize` | Secret memory zeroization |
| `rusqlite` | SQLite (parameterized queries only) |
| `subtle` | Constant-time comparisons |
| `reqwest` | HTTP sync client (feature-gated `sync`) |
| `axum` | Relay server HTTP framework |

See `Cargo.toml` (workspace root) and `CLAUDE.md` § Dependencies Note for the full list.

---

## 6. BROWSER EXTENSION DESIGN (PRIORITY)

### 6.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Browser Extension                             │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  content.js  |  Injected into each page                        │  │
│  │              |  - Detect password fields                        │  │
│  │              |  - Inject autofill button                         │  │
│  │              |  - Communicate with background                   │  │
│  └──────────────────────┬────────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────┴────────────────────────────────────────┐  │
│  │  background.js (Service Worker for MV3)                       │  │
│  │              |  - Native messaging client                      │  │
│  │              |  - Domain validation                           │  │
│  │              |  - Credential caching (memory only)              │  │
│  └──────────────────────┬────────────────────────────────────────┘  │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          │ Native Messaging Protocol
                          │ (JSON over stdin/stdout)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Native Messaging Host                            │
│  (Separate binary installed with desktop app)                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Reads JSON from stdin                                        │  │
│  │  Validates message format and origin                          │  │
│  │  Forwards to daemon via local socket/pipe                      │  │
│  │  Writes response to stdout                                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          │ Local IPC (named pipe/Unix socket)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Core Daemon                                    │
│  - Domain matching                                                 │
│  - Credential lookup                                              │
│  - Returns ONLY requested credential, not full vault               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. SECURITY HARDENING CHECKLIST

| Category | Item | Status | Notes |
|----------|------|--------|-------|
| **Memory** | Zeroization | ✅ | `zeroize` crate on all secrets (`crypto/zero.rs`) |
| **Memory** | Zeroized buffers | ⚠️ | `zeroize` on drop; memory locking was removed with the unused `memsec` dependency — no swap protection today |
| **Memory** | No string copies | ✅ | `SecureBuffer` in `crypto/keyring.rs` |
| **Timing** | Constant-time compare | ✅ | `subtle` crate for password checks |
| **Timing** | Fixed delay on auth | 📋 | Not yet implemented |
| **Brute Force** | Exponential backoff | ⚠️ | Simple backoff, not exponential |
| **Brute Force** | Account lockout | ✅ | 10 failed attempts = 5 min lockout (`lockout.rs`) |
| **Auto-lock** | Timeout | ✅ | Default 5 min inactivity (`autolock.rs`) |
| **Auto-lock** | Lock on sleep | ⚠️ | macOS only |
| **Auto-lock** | Lock on screen lock | 📋 | Platform-specific APIs planned |
| **Clipboard** | Auto-clear | ✅ | Tauri clipboard plugin |
| **Clipboard** | Clear on exit | ⚠️ | Daemon only, not host |
| **Audit Log** | Track access | ✅ | Encrypted audit log (`audit.rs`) |
| **SQL Injection** | Parameterized queries | ✅ | rusqlite bindings only |
| **Updates** | Signature verification | 📋 | Planned for distribution |
| **Updates** | Secure channel | ✅ | HTTPS for sync client |
| **Process Isolation** | Sandboxing | 📋 | Platform-specific planned |
| **Anti-debug** | Detect debugger | 📋 | Not yet implemented |
| **Anti-dump** | Encrypt secrets | ✅ | Memory encryption in `crypto/keyring.rs` |

---

## 8. DEVELOPMENT ROADMAP

> **Progress as of 2026-02-27:** Phases 1-7 substantially complete. Phase 8 (hardening) in progress.

| Phase | Status | Notes |
|-------|--------|-------|
| **Phase 1: Core Foundation** | ✅ Complete | Crypto, database, CLI all implemented |
| **Phase 2: Desktop Client** | ⚠️ Partial | Tauri UI functional, needs feature parity |
| **Phase 3: Browser Extension** | ✅ Complete | Chrome MV3 + Firefox MV2 with sender validation |
| **Phase 4: SSH Support** | ✅ Complete | Storage, CLI, agent integration implemented |
| **Phase 5: Biometrics** | ⚠️ Partial | macOS Touch ID + Windows Hello implemented; master password is not stored for biometric unlock |
| **Phase 6: Advanced Features** | ⚠️ Partial | TOTP ✅, KeePass import 📋, audit log ✅ |
| **Phase 7: Multi-Device Sync** | ✅ Complete | E2E sync, relay, pairing, Ed25519 all implemented |
| **Phase 8: Hardening & Testing** | ⚠️ In Progress | Security hardening (Phase 1) complete, audit pending |

### Detailed Breakdown

#### Phase 1: Core Foundation ✅
1. ✅ Project setup, dependencies
2. ✅ Crypto module implementation (Argon2id, AES-256-GCM)
3. ✅ Database schema and migrations (refinery)
4. ✅ Basic CLI for vault operations
5. ✅ Unit tests for crypto (276 tests passing)

#### Phase 2: Desktop Client ⚠️
1. ✅ Tauri UI development
2. ✅ Vault CRUD operations
3. ⚠️ Entry management UI (partial)
4. ⚠️ Search functionality (basic only)
5. ✅ Clipboard integration

#### Phase 3: Browser Extension ✅
1. ✅ Native messaging protocol
2. ✅ Chrome extension (MV3)
3. ✅ Domain matching logic (daemon-side validation)
4. ✅ Autofill injection
5. ✅ Phishing protection (sender URL validation)

#### Phase 4: SSH Support ✅
1. ✅ SSH key storage (RSA, Ed25519, ECDSA)
2. ✅ ssh-agent integration
3. ✅ Key loading functionality

#### Phase 5: Biometrics ⚠️
1. ✅ macOS Touch ID (LocalAuthentication framework)
2. ✅ Windows Hello (Windows Credentials API)
3. ✅ Biometric unlock stores DEK material instead of master password
4. 📋 Platform-native non-exportable DEK wrapping / enrollment invalidation
5. 📋 Linux support (planned)

#### Phase 6: Advanced Features ⚠️
1. ✅ TOTP authenticator (SHA1, SHA256, SHA512)
2. 📋 KeePass import/export (planned)
3. ✅ Audit log (encrypted events)
4. ✅ Firefox extension (MV2)

#### Phase 7: Multi-Device Sync ✅
1. ✅ E2E encrypted sync engine (push/pull with LWW)
2. ✅ Relay server (Axum + SQLite, zero-knowledge)
3. ✅ Device pairing (HKDF-SHA256 + Ed25519)
4. ✅ Device revocation
5. ✅ Metadata padding (fixed buckets)

#### Phase 8: Hardening & Testing ⚠️
1. ✅ Phase 1 security hardening complete (see GAP_REVIEW)
2. ✅ Relay tests (38 tests)
3. ✅ Extension debug log gating
4. ✅ Windows named pipe IPC
5. 📋 Security audit (planned)
6. 📋 Penetration testing (planned)

---

## 9. COMMON MISTAKES TO AVOID

1. **Never log secrets** - Use safe logging that redacts sensitive data
2. **Never use `String` for passwords** - Always use `SecureBuffer`
3. **Never compare passwords with `==`** - Use constant-time compare
4. **Never store keys in environment variables** - Use locked memory or OS keystore
5. **Never reuse nonces** - Always generate random per-entry nonce
6. **Never skip authentication tag validation** - GCM tag is mandatory
7. **Never write plaintext to disk** - Even for debugging
8. **Never trust domain from browser** - Validate daemon-side
9. **Never return full vault to extension** - Only return requested credential
10. **Never forget to zeroize** - Drop all secret buffers promptly

## 10. SECRETS BROKER FOR LOCAL TOOLS (v0.8.0)

SentinelPass's daemon exposes a least-privilege secrets broker so local
developer tools (AI agents, proxies, scripts) can fetch exactly the secrets
they were granted — no more.

### Trust boundaries

| Boundary | Mechanism | Notes |
| --- | --- | --- |
| Process → daemon | 32-byte IPC token file (`<config>/ipc.token`, 0600), constant-time compared | Same-OS-user trust root. Any process running as the user can read the token. |
| Tool → secret scope | `ExternalSecretGrant` (client_id × domain × field [+ expires_at]) in `<config>/external-secret-access.json` (0600) | Exact scope match, no wildcards. |
| Tool identity | Per-client token (`spt_…`, 32 random bytes, SHA-256 at rest, shown once at mint) | A client with a `client_tokens` entry is token-enforced on **all** its grants; revocation is fail-closed. Legacy (tokenless) clients keep working during the migration window but are warned about. |
| Browser autofill | Native-messaging origin label on every envelope | **Provenance labeling, not authentication.** Originless requests are **denied by default** (with a warning naming the upgrade path); `SENTINELPASS_ALLOW_LEGACY_ORIGINLESS=1` temporarily **re-allows** the legacy pre-0.8-host path (removed in 1.0). |

### Rules enforced by the daemon

1. `GetExternalSecret` requires an unexpired grant whose scope matches exactly,
   and a valid client token whenever the client is token-enforced.
2. `SaveSecret` additionally requires the grant to carry `allow_write`.
   Writes upsert one value for one domain and are audited as
   `ExternalSecretWrite`.
3. `DeleteSecret` is always rejected for external tools: deletion needs entry
   ownership metadata (schema v5). A write grant must never delete a
   human-created login.
4. The CLI cannot use the legacy unscoped `GetCredential` path at all
   (`secret get` / `secret-get` require `--client-id`).
5. Every external lookup and write is appended to the audit log
   (`<config>/audit/audit.log`); `sentinelpass secret audit` renders it.

### Non-goals

- Multi-user isolation: everything below the OS-user boundary is one trust
  domain. Per-tool tokens provide *scope* containment, not process identity
  (no SO_PEERCRED/getpeyeid reliance; macOS cannot expose peer PIDs).
- Environment-injected secrets cannot be zeroized once a child process owns
  them. `sentinelpass exec` is for trusted children only.
