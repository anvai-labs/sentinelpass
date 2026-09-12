# SentinelPass iOS App

A secure, local-first password manager for iOS devices (iPhone and iPad) built with SwiftUI and the SentinelPass Rust mobile bridge.

## Features

- **Secure Vault Storage**: Encrypted with Argon2id KDF + AES-256-GCM
- **Biometric Authentication**: Face ID and Touch ID support
- **Password Management**: Add, edit, delete, and search password entries
- **TOTP Support**: Generate time-based one-time passwords (2FA codes)
- **Password Generator**: Create strong, random passwords with strength analysis
- **Local-First**: All data stored locally on device
- **Auto-Lock**: Vault locks automatically after period of inactivity

## Architecture

```
SentinelPass iOS App (SwiftUI)
    ↓
VaultBridge (Swift)
    ↓ C FFI
sentinelpass-mobile-bridge (Rust static library)
    ↓
sentinelpass-core (Rust)
```

## Building

### Prerequisites

1. macOS 14.0+ (Xcode 15.0+)
2. Rust toolchain (for building the mobile bridge)
3. CocoaPods (optional, for additional dependencies)

### Build Steps

1. **Build the Rust mobile bridge**:

```bash
cd /path/to/sentinelpass
cargo build --package sentinelpass-mobile-bridge --release
```

The static library will be at:
`target/release/libsentinelpass_mobile_bridge.a`

The C header will be at:
`sentinelpass-mobile-bridge/include/sentinelpass_bridge.h`

2. **Open in Xcode**:

```bash
cd ios/SentinelPass
open SentinelPass.xcodeproj
```

3. **Configure Xcode project**:

   - Add the static library to "Link Binary With Libraries"
   - Add the header path to "Header Search Paths"
   - Ensure `SwiftData` and `LocalAuthentication` frameworks are linked

4. **Build and Run**:

   - Select a simulator or physical device
   - Press `Cmd+R` to build and run

## Project Structure

```
ios/SentinelPass/
├── SentinelPass/
│   ├── SentinelPassApp.swift          # App entry point
│   ├── ContentView.swift              # Main view router
│   ├── Info.plist                     # App configuration
│   ├── Models/
│   │   ├── VaultState.swift           # Central vault state manager
│   │   └── EntryModel.swift           # Data models
│   ├── Views/
│   │   ├── LockView.swift             # Lock/unlock screen
│   │   ├── SetupView.swift            # Initial vault setup
│   │   ├── EntriesList.swift          # Password list
│   │   ├── AddEntryView.swift         # Add new entry
│   │   ├── EntryDetailView.swift      # Entry details
│   │   ├── EditEntryView.swift        # Edit existing entry
│   │   ├── TotpList.swift             # TOTP codes
│   │   ├── GeneratorView.swift        # Password generator
│   │   ├── PasswordGeneratorView.swift
│   │   └── SettingsView.swift         # Settings
│   └── Services/
│       └── BiometricAuth.swift        # Biometric authentication
├── SentinelPassBridge/
│   └── VaultBridge.swift              # FFI bridge to Rust
└── README.md
```

## Integration with Rust Bridge

The app uses `VaultBridge` class to communicate with the Rust mobile bridge via C ABI. See `docs/MOBILE_BRIDGE_USAGE.md` for detailed usage instructions.

### Key Integration Points

1. **Vault Creation/Unlock**: Uses `sp_vault_init()`
2. **Entry CRUD**: Uses `sp_entry_add()`, `sp_entry_get_by_id()`, `sp_entry_list_all()`, `sp_entry_delete()`
3. **TOTP**: Uses `sp_totp_generate_code()`
4. **Password Generation**: Uses `sp_password_generate()` and `sp_password_check_strength()`
5. **Biometric**: Uses `sp_biometric_set_key()`, `sp_biometric_has_key()`, `sp_biometric_unlock()`

## Security Considerations

1. **Biometric Key Storage**: Biometric keys are stored in the iOS Keychain
2. **Vault Storage**: Vault database stored in app's Documents directory
3. **Memory Management**: All C strings returned from Rust are properly freed
4. **No Network Calls**: All operations are local-first (future sync support planned)

## Permissions Required

- `NSFaceIDUsageDescription`: Face ID authentication
- `NSBiometricIdentityUsageDescription`: Biometric authentication
- `NSKeychainUsageDescription`: Keychain access for biometric keys

## Future Enhancements

- AutoFill integration with iOS Password AutoFill
- Web browser integration with Safari extension
- Import from other password managers (1Password, LastPass, Bitwarden)
- Secure sharing with other iOS devices
- WatchOS companion app
- Spotlight search integration

## Troubleshooting

### Build Issues

If you see "Undefined symbols" errors:
1. Ensure the Rust mobile bridge is built: `cargo build --package sentinelpass-mobile-bridge --release`
2. Check that the static library path is correct in Xcode
3. Verify the header search path includes `sentinelpass-mobile-bridge/include/`

### Runtime Issues

If the app crashes on startup:
1. Check that the vault database path is accessible
2. Ensure all C function declarations are properly linked
3. Verify biometric permissions are in `Info.plist`

### Biometric Issues

If Face ID/Touch ID doesn't work:
1. Check device supports biometric authentication
2. Verify `NSFaceIDUsageDescription` is in `Info.plist`
3. Ensure user has granted biometric permission

## Contributing

When making changes:

1. Update Swift code following Swift API design guidelines
2. Ensure all memory from C calls is properly freed
3. Test on both iPhone and iPad
4. Test biometric authentication on physical devices

## License

Same as parent SentinelPass project.
