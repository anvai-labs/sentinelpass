# ADR-008: Authenticated Backup and Verified Restore

| Field | Value |
|-------|-------|
| Status | Proposed |
| Date | 2026-09-04 |
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
encrypted portable bundle. The bundle contains a versioned manifest, vault UUID and
epoch, encrypted snapshot, required key-slot material, creation metadata, and
authenticated integrity information. It contains no plaintext entry metadata.

Restore validates format, bounds, integrity, vault identity, key-slot availability,
schema migration, and a full functional/decryption check before replacing active data.
Replacement is atomic and retains a recoverable pre-restore snapshot. Recovery and
restore operations require reauthentication and are audited with opaque identifiers.

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
