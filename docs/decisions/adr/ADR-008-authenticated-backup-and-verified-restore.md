# ADR-008: Authenticated Backup and Verified Restore

| Field | Value |
|-------|-------|
| Status | Accepted (rev 2, 2026-09-08 — owner decision after adversarial review round 1; amendments folded) |
| Date | 2026-09-07 |
| Owners | Core maintainer, security lead, product lead |
| Related | ADR-004; ADR-005; ADR-006 |

## Summary

Define backup and restore as security-critical recovery operations using atomic
snapshots, authenticated manifests, portable versioning, and routine verification.

## Context

Forgotten-password recovery is insufficient if the only vault copy is lost or corrupt.
Copying a live SQLite database without coordinated WAL/SHM state is unreliable. Old
backups also retain old wrapped keys and cannot be remotely revoked.

## Decision

SentinelPass uses SQLite-supported snapshot/backup behavior to create a consistent
encrypted portable bundle: the snapshot is a consistent read including WAL content
under concurrent daemon writes (online backup API or `VACUUM INTO` in a read
transaction), with the exact mechanism and size bounds delegated to WBS-416. The
bundle contains a versioned manifest, vault UUID and epoch, encrypted snapshot,
required key-slot material, creation metadata, and authenticated integrity
information. The manifest is authenticated under a MAC key derived from vault key
material (HKDF over the DEK with a dedicated info label, per the key-slot registry MAC
precedent); it binds the snapshot digest, vault UUID, epoch, and key-slot material, so
backup requires the unlocked DEK. MAC verification (fail closed) precedes any state
mutation. The manifest format is registered in docs/DURABLE_WIRE_FORMATS.md under the
canonical JSON profile. It contains no plaintext entry content (titles, usernames,
URLs, notes, secrets); operational metadata (timestamps, type flags, tombstone flags,
record count) remains visible, per ADR-005's stated limits. The manifest's
creation-metadata fields are enumerated in the format contract.

Restore validates format, bounds, integrity, vault identity, key-slot availability,
schema migration, and a full functional/decryption check before replacing active data;
unsupported newer envelope/crypto content versions fail closed (ADR-005). The database
swap is a single rename of a fully validated staged copy, with the live database's
`-wal`/`-shm` sidecars removed as part of the swap; the epoch sidecar is re-baselined
(TOFU mint or supervised override per ADR-004 rev 4) as the subsequent step, whose
interruption leaves the refused-open rollback state with its documented recovery.
Exactly one pre-restore snapshot is retained (replaced on the next restore) and is
deleted only after the restored state verifies. Recovery and restore operations
require reauthentication and are audited with opaque identifiers.

A bundle restore on a vault with sync enabled follows the ADR-004 rev 4 rotation rule
until sync v2: restore either refuses while sync is configured or disables sync and
requires re-pairing. A restored device's sync lineage (pull cursor, device sequence)
is re-baselined and never reused against the old relay history.

The UI states that an old exported backup may remain openable with the credentials it
contained when created. Compromise response includes backup guidance and optional DEK
rotation; it cannot revoke an attacker-held offline copy.

## Options Considered

- Copy the database file directly: rejected because live SQLite state may be incomplete.
- Export plaintext JSON/CSV as the primary backup: rejected because it discards the
  security model.
- Authenticated encrypted bundle plus explicit unsafe plaintext export: proposed.

## Threat Model

Addresses device loss, filesystem corruption, interrupted backup/restore, manifest
tampering, wrong-vault restore, and malformed/oversized bundles. It does not protect a
plaintext export or a recovery credential stored beside the backup.

## MVP vs. Later

- MVP: manual encrypted backup, verify, restore, migration, and recovery drill.
- Later: scheduled/versioned backups, retention policies, remote storage adapters, and
  threshold recovery metadata.

## Migration and Rollout

Envelope-v2 migration creates a pre-migration bundle through the same subsystem. Add
fixtures for every supported schema and platform. Mobile backup policies must either
exclude live files or back up only this coordinated encrypted format.

## Consequences

Backup becomes a first-class format and compatibility promise. Release validation must
retain old restore fixtures and cannot remove a format without an announced support
window.
