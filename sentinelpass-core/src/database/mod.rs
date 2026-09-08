//! Database layer for the password manager.
//!
//! This module handles all database operations including schema management,
//! migrations, and encrypted data persistence.

pub mod migrations;
pub mod models;
pub mod repository;
pub mod schema;

/// Schema fixtures for every released version (WBS-407). Test-only: the
/// builder constructs vault files programmatically from the actual
/// migration ladder.
#[cfg(test)]
pub(crate) mod fixtures;

pub use models::{DomainMapping, Entry, TotpSecret};
pub use repository::{
    insert_entry_row, update_entry_row, EntryFilter, EntryRepository, NewEntryParams, RawEntryRow,
    SqliteEntryRepository, UpdateEntryParams,
};
pub use schema::Database;

/// Fault-injection harness for the SR-DATA-001 (WBS-411) transactional
/// mutation tests: denies the Nth write action via the SQLite authorizer
/// (the denial lands at statement-prepare time, mid-transaction), so a test
/// can sweep every injection point of a multi-statement mutation and assert
/// the outcome is complete-old or complete-new — never partial.
#[cfg(test)]
pub(crate) mod fault_injection;
