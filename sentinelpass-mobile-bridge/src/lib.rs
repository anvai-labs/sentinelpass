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
mod bridge;
mod error;
mod ffi;

#[cfg(feature = "jni")]
mod jni;

mod drive;
mod icloud;

// Re-export error types
pub use error::{BridgeError, ErrorCode};

// FFI exports for iOS (always compiled, guarded by cfg in ffi.rs)
pub use ffi::*;

// JNI exports for Android (feature-gated)
#[cfg(feature = "jni")]
pub use jni::*;
