//! SentinelPass Relay Server (library surface).
//!
//! The relay previously existed only as a binary with private modules,
//! which made its hostile-input parsers (sync v2 shape validation, auth
//! frame handling) un-fuzzable and un-linkable from integration tooling.
//! WBS-903 moved the module tree into this library crate; `main.rs` is a
//! thin binary shell over it. Nothing about module behavior changed — the
//! same modules, the same tests, now under the `sentinelpass_relay` lib
//! target.

pub mod app_state;
pub mod auth;
pub mod cleanup;
pub mod config;
pub mod error;
#[cfg(test)]
pub mod fault_injection;
pub mod handlers;
pub mod pairing_security;
pub mod rate_limit;
pub mod server;
pub mod storage;
