//! E2E Encrypted Sync for SentinelPass
//!
//! Implements zero-knowledge device synchronization:
//! - Per-entry incremental sync with AES-256-GCM encryption
//! - Ed25519 device identity and request signing
//! - Transactional mutation protocol v2 (ADR-006): idempotent mutations,
//!   durable per-object results, CAS version guards
//! - Tombstone-based soft deletes
//! - Device pairing (v2: high-entropy challenge bootstrap)
//!
//! The v1 wire (`models.rs`) remains for cross-version interop until v1
//! retirement (ADR-006 migration); the client engine speaks v2
//! (`v2.rs` / `engine.rs`).

pub mod auth;
pub mod change_tracker;
#[cfg(feature = "sync")]
pub mod client;
pub mod config;
pub mod conflict;
pub mod crypto;
pub mod device;
#[cfg(feature = "sync")]
pub mod engine;
pub mod models;
pub mod pairing;
pub mod v2;

pub use config::SyncConfig;
pub use conflict::ConflictResolver;
pub use models::{SyncEntryBlob, SyncEntryType, SyncStatus};
