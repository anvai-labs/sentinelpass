// sentinelpass-mobile-bridge: FFI/JNI bridge for mobile platforms
//
// This crate provides a safe interface to sentinelpass-core for mobile platforms:
// - iOS: C ABI via extern "C" functions (called from Swift/Objective-C)
// - Android: JNI bindings (called from Kotlin/Java)
//
// # Architecture
//
// ┌─────────────────────────────────────────────────────────────┐
// │              Mobile Platform (iOS/Android)                  │
// │                   (Swift/Kotlin)                            │
// └────────────────────────────┬────────────────────────────────┘
//                              │
//                              │ FFI/JNI
//                              ▼
// ┌─────────────────────────────────────────────────────────────┐
// │           sentinelpass-mobile-bridge (this crate)           │
// │  ┌──────────────────┐        ┌──────────────────┐          │
// │  │   iOS FFI (C)    │        │  Android JNI     │          │
// │  │  ffi.rs          │        │  jni.rs          │          │
// │  └──────────────────┘        └──────────────────┘          │
// │           │                          │                      │
// │           └──────────────┬───────────┘                      │
// │                          ▼                                  │
// │              ┌──────────────────────┐                      │
// │              │   Bridge Core        │                      │
// │              │   bridge.rs          │                      │
// │              └──────────────────────┘                      │
// └────────────────────────────┬────────────────────────────────┘
//                              │
//                              │
//                              ▼
// ┌─────────────────────────────────────────────────────────────┐
// │                 sentinelpass-core                           │
// │  (VaultManager, Crypto, Database, Sync, etc.)               │
// └─────────────────────────────────────────────────────────────┘

#![allow(clippy::missing_safety_doc)]
// We use unsafe for FFI boundaries, safety is documented per function

mod abi;
mod backup;
mod bridge;
mod error;
mod ffi;
mod slot;

#[cfg(feature = "jni")]
mod jni;

// The CloudKit/Drive file-sync placeholder modules (drive.rs, icloud.rs) and
// their sp_sync_prepare_* / collect / apply exports were removed under
// WBS-807 (ADR-009 rev 2: mobile sync is relay-based sync v2 only — ADR-006;
// the file-sync paths conflicted with it and serialized plaintext entry
// titles into "sync blobs").

// Re-export error types
pub use error::{BridgeError, ErrorCode};

// FFI exports for iOS (always compiled, guarded by cfg in ffi.rs)
pub use ffi::*;

// JNI exports for Android (feature-gated)
#[cfg(feature = "jni")]
pub use jni::*;
