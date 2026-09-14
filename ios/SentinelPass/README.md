# SentinelPass iOS App

A secure, local-first password manager for iOS devices (iPhone and iPad) built with SwiftUI and the SentinelPass Rust mobile bridge.

## Features

- **Secure Vault Storage**: Encrypted with Argon2id KDF + AES-256-GCM (Rust core; the Swift layer never persists secrets)
- **Platform Keychain Slot** (WBS-821): vault DEK in a biometry-gated Keychain item, opened via `sp_slot_open_with_dek`
- **File Protection** (WBS-822): `NSFileProtectionComplete` + excluded from iCloud/device backups
- **Scene Lock** (WBS-823): privacy cover when inactive, 5-minute auto-lock while backgrounded
- **Expiring Pasteboard** (WBS-824): copied passwords/TOTP codes expire after 30 s
- **Credential Provider** (WBS-825): iOS 17 AutoFill extension sharing the vault via the App Group
- **Password Management**: add, edit, delete, and search password entries
- **TOTP Support**: generate time-based one-time passwords (2FA codes)
- **Password Generator**: create strong, random passwords with strength analysis

## Architecture

```
SentinelPass iOS App (SwiftUI)        SentinelPassCredential extension
        │                                     │
        └──────────► VaultBridge (Swift) ◄────┘
                          │ C FFI
              sentinelpass-mobile-bridge (Rust static library)
                          │
                  sentinelpass-core (Rust)
```

Both targets open the SAME vault database under the
`group.com.sentinelpass` App Group container.

## Building

### Prerequisites

1. macOS with Xcode 15.0+
2. Rust toolchain with the `aarch64-apple-ios-sim` / `aarch64-apple-ios` targets

### Build Steps

1. **Build the Rust mobile bridge and populate `Native/libs/`**:

```bash
cd ios/SentinelPass
./build-ios.sh
```

2. **Open in Xcode**:

```bash
open SentinelPassApp.xcodeproj
```

3. Select the **SentinelPassApp** scheme and an iOS Simulator, then **Cmd+R**.

Or from the command line:

```bash
xcodebuild -project SentinelPassApp.xcodeproj -scheme SentinelPassApp \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  build CODE_SIGNING_ALLOWED=NO
```

See `README-iOS.md` for the full development guide.

## Project Structure

```
ios/SentinelPass/
├── SentinelPass/                      # App target sources
│   ├── SentinelPassApp.swift          # App entry point (scene lock)
│   ├── ContentView.swift              # Main view router
│   ├── Info.plist
│   ├── SentinelPass.entitlements      # App Group
│   ├── Models/                        # VaultState, EntryModel (non-sensitive mirror)
│   ├── Views/                         # SwiftUI screens
│   ├── Services/                      # VaultBridge, KeychainSlot, VaultFile, Pasteboard, BiometricAuth
│   └── Native/                        # module.modulemap + header copy + libs/ (script-populated)
└── SentinelPassCredential/            # WBS-825 credential-provider extension target
    ├── CredentialProviderViewController.swift
    ├── Info.plist
    └── SentinelPassCredential.entitlements
```

## Integration with Rust Bridge

The app uses the `VaultBridge` class to communicate with the Rust mobile
bridge via C ABI v2 (`ios/SentinelPass/SentinelPass/Native/include/sentinelpass_bridge.h`,
a copy of the generated contract in `sentinelpass-mobile-bridge/include/`).

### Key Integration Points

1. **Vault Creation/Unlock**: `sp_vault_init()`
2. **Platform slot unlock**: Keychain DEK release → `sp_slot_open_with_dek()`
3. **Entry CRUD**: `sp_entry_add()`, `sp_entry_get_by_id()`, `sp_entry_list_all()`, `sp_entry_update()` (atomic), `sp_entry_delete()`
4. **TOTP**: `sp_totp_generate_code()`
5. **Password Generation**: `sp_password_generate()` and `sp_password_check_strength()`

## Security Considerations

1. **Keychain slot**: the DEK lives in the Keychain under
   `kSecAccessControlBiometryCurrentSet`; the OS-gated read IS the
   authorization (no secrets in UserDefaults or plaintext files)
2. **Vault at rest**: `NSFileProtectionComplete`, excluded from backups,
   inside the App Group container
3. **No Swift-side persistence of secrets**: the SwiftData plaintext
   mirror was removed (WBS-826); full entries exist only in memory
4. **Memory management**: all C strings returned from Rust are freed
   (`sp_string_free` / `sp_entry_list_free` / `sp_bytes_free`)
5. **No Network Calls**: all operations are local-first (relay sync is a
   later deliverable; CloudKit/Drive paths were removed under WBS-807)

## Permissions Required

- `NSFaceIDUsageDescription`: Face ID authentication (the only usage
  description iOS requires for this app; bogus legacy keys were removed)

## License

Same as parent SentinelPass project.
