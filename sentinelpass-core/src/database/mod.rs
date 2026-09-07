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
    EntryFilter, EntryRepository, NewEntryParams, RawEntryRow, SqliteEntryRepository,
    UpdateEntryParams,
};
pub use schema::Database;
