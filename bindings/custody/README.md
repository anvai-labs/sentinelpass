# Personal custody metadata v1

Generated from `sentinelpass-protocol/src/custody.rs`:

```sh
cargo run -p sentinelpass-protocol --example generate_custody_bindings
cargo run -p sentinelpass-protocol --example generate_custody_bindings -- --check
```

Rust owns the schema. TS types and parsed-object validators, Swift Codable models
and Kotlin serialization models share the same field/enum declarations. The C ABI
is generated separately by the existing bridge cbindgen build. Golden scope and
reference JSON is synthetic public metadata, shared by Rust, TS, Swift/C and JVM
checks. Rust rejects duplicate keys before any authority decision; TS validators
accept parsed objects and cannot detect duplicates already lost by JSON.parse.
Swift/Kotlin decoding alone is not validation: call the Rust metadata validator.
All three metadata types require JSON objects; positional arrays are rejected.
The shared `*.array.invalid.json` vectors exercise Rust, TS, C, JVM/JNI and
Swift/C rejection without replacing the valid object-shaped golden vectors.

`sp_custody_validate_metadata` and generated `CustodyContract.validateMetadata`
validate bounded metadata only. Kind 1 is CustodyScope, 2 ObjectRef, 3
ProviderCapabilities. Success never creates a provider, session, grant, lease,
source, receiver or approval. Native ABI remains 2. The reserved custody feature
bit (8) is **unset**, as is mobile relay sync. Negotiate the ABI and require the
actual feature before attempting future custody operations; there are none yet.

TypeScript opaque brands declare the future port shape, not runtime authority.
There is no browser adapter and no JavaScript handle constructor. The native
engine has no production enrollment constructor; only its synthetic tests can
create sessions/receivers. Do not invent a callback, JSON secret or generic keyring
fallback to fill that gap. No provider here can be selected for real mail.

Native host probes (after `cargo build -p sentinelpass-mobile-bridge --features jni`):

```sh
javac -d /tmp/custody-jvm tests/native/custody/com/sentinelpass/custody/CustodyContract.java
java -cp /tmp/custody-jvm com.sentinelpass.custody.CustodyContract \
  target/debug/libsentinelpass_mobile_bridge.dylib bindings/custody
swiftc -import-objc-header sentinelpass-mobile-bridge/include/sentinelpass_bridge.h \
  -L target/debug -lsentinelpass_mobile_bridge \
  -Xlinker -rpath -Xlinker "$PWD/target/debug" \
  bindings/custody/CustodyContract.swift tests/native/custody/main.swift \
  -o /tmp/custody-swift
/tmp/custody-swift bindings/custody
```

The shown library suffix is macOS-specific. Host JVM/Swift checks are metadata
ABI evidence, not Android/iOS keystore or physical-device evidence. The generated
Kotlin class expects the existing native library loader to have run first.
