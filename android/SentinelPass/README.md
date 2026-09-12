# SentinelPass Android App

A secure, local-first password manager for Android devices (phones and tablets) built with Jetpack Compose and the SentinelPass Rust mobile bridge.

## Features

- **Secure Vault Storage**: Encrypted with Argon2id KDF + AES-256-GCM
- **Biometric Authentication**: Fingerprint and Face Unlock support
- **Password Management**: Add, edit, delete, and search password entries
- **TOTP Support**: Generate time-based one-time passwords (2FA codes)
- **Password Generator**: Create strong, random passwords with strength analysis
- **Local-First**: All data stored locally on device
- **Auto-Lock**: Vault locks automatically after period of inactivity
- **Jetpack Compose**: Modern Material 3 UI

## Architecture

```
SentinelPass Android App (Kotlin/Compose)
    ↓
VaultBridge (Kotlin JNI)
    ↓ JNI
sentinelpass-mobile-bridge (Rust shared library)
    ↓
sentinelpass-core (Rust)
```

## Building

### Prerequisites

1. Android Studio Hedgehog (2023.1.1) or later
2. JDK 17
3. Android SDK 34
4. NDK 25.x or later
5. Rust toolchain (for building the mobile bridge)

### Build Steps

1. **Build the Rust mobile bridge**:

```bash
cd /path/to/sentinelpass
cargo build --package sentinelpass-mobile-bridge --features jni --release
```

2. **Copy JNI libraries to project**:

```bash
# Create JNI libs directory
mkdir -p android/SentinelPass/app/src/main/jniLibs

# Copy built libraries
cp target/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/arm64-v8a/

# For other architectures, build with --target flag:
# cargo build --package sentinelpass-mobile-bridge --features jni --release --target aarch64-linux-android
# cargo build --package sentinelpass-mobile-bridge --features jni --release --target armv7-linux-androideabi
# cargo build --package sentinelpass-mobile-bridge --features jni --release --target x86_64-linux-android
```

3. **Open in Android Studio**:

```bash
cd android/SentinelPass
# Open project in Android Studio
```

4. **Build and Run**:

   - Connect Android device or start emulator
   - Click "Run" or press `Shift+F10`

## Project Structure

```
android/SentinelPass/
├── app/
│   ├── src/main/
│   │   ├── java/com/sentinelpass/
│   │   │   ├── SentinelPassApplication.kt
│   │   │   ├── MainActivity.kt
│   │   │   ├── VaultBridge.kt              # JNI bridge to Rust
│   │   │   ├── data/
│   │   │   │   └── VaultState.kt          # Central vault state manager
│   │   │   ├── ui/
│   │   │   │   ├── screens/
│   │   │   │   │   ├── LockScreen.kt      # Lock/unlock screen
│   │   │   │   │   ├── SetupScreen.kt     # Initial vault setup
│   │   │   │   │   ├── MainScreen.kt      # Main tab navigation
│   │   │   │   │   ├── entries/
│   │   │   │   │   │   ├── EntriesListScreen.kt
│   │   │   │   │   │   ├── AddEntryScreen.kt
│   │   │   │   │   │   └── EntryDetailScreen.kt
│   │   │   │   │   ├── totp/
│   │   │   │   │   │   └── TotpListScreen.kt
│   │   │   │   │   ├── generator/
│   │   │   │   │   │   └── GeneratorScreen.kt
│   │   │   │   │   └── settings/
│   │   │   │   │       └── SettingsScreen.kt
│   │   │   │   └── theme/
│   │   │   │       ├── Theme.kt
│   │   │   │       └── Type.kt
│   │   │   └── autofill/
│   │   │       └── SentinelPassAutofillService.kt
│   │   ├── res/
│   │   │   ├── values/
│   │   │   ├── layout/
│   │   │   └── xml/
│   │   └── jniLibs/                       # Native libraries
│   │       ├── arm64-v8a/
│   │       ├── armeabi-v7a/
│   │       └── x86_64/
│   ├── build.gradle.kts
│   └── proguard-rules.pro
├── settings.gradle.kts
├── build.gradle.kts
└── README.md
```

## Integration with Rust Bridge

The app uses `VaultBridge` class to communicate with the Rust mobile bridge via JNI. See `docs/MOBILE_BRIDGE_USAGE.md` for detailed usage instructions.

### Key Integration Points

1. **Vault Creation/Unlock**: Uses `nativeInit()`
2. **Entry CRUD**: Uses `nativeAddEntry()`, `nativeGetEntry()`, `nativeListEntries()`, `nativeDeleteEntry()`
3. **TOTP**: Uses `nativeGenerateTotp()`
4. **Password Generation**: Uses `nativeGeneratePassword()` and `nativeCheckStrength()`
5. **Biometric**: Keystore-bound platform slot (WBS-812) — unlock via `slotUnlock()`

## Building for Different Architectures

```bash
# arm64-v8a (most modern devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target aarch64-linux-android

# armeabi-v7a (older 32-bit devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target armv7-linux-androideabi

# x86_64 (emulators)
cargo build --package sentinelpass-mobile-bridge --features jni --release --target x86_64-linux-android
```

Note: You'll need the appropriate Android NDK toolchains installed.

## Security Considerations

1. **Biometric Key Storage**: Biometric keys stored in Android Keystore
2. **Vault Storage**: Vault database stored in app's private directory
3. **Memory Management**: JVM manages memory for JNI string returns
4. **No Network Calls**: All operations are local-first (future sync support planned)
5. **Screen Capture**: Disabled for sensitive screens via `FLAG_SECURE`

## Permissions Required

- `USE_BIOMETRIC`: Fingerprint/Face unlock
- `INTERNET`: For future sync functionality
- `CAMERA`: For QR code scanning (future feature)

## Future Enhancements

- Google Drive sync integration
- Autofill service integration
- QR code scanning for TOTP setup
- Import from other password managers (1Password, LastPass, Bitwarden)
- Secure sharing with other Android devices
- Wear OS companion app

## Troubleshooting

### Build Issues

If you see "UnsatisfiedLinkError":
1. Ensure the Rust mobile bridge is built with JNI feature: `--features jni`
2. Verify the .so files are in `app/src/main/jniLibs/<abi>/`
3. Check that the architecture matches your device/emulator

### Runtime Issues

If the app crashes on startup:
1. Check that the vault database path is accessible
2. Verify the native library is properly loaded in VaultBridge
3. Ensure all required permissions are in `AndroidManifest.xml`

### Biometric Issues

If biometric authentication doesn't work:
1. Check device supports biometric authentication
2. Verify `USE_BIOMETRIC` permission is in `AndroidManifest.xml`
3. Ensure user has enrolled biometric credentials in system settings

### Testing on Emulator

For biometric testing on emulator:
1. Open Extended Controls (⌘E or ... button in emulator toolbar)
2. Go to Biometric settings
3. Enroll fingerprint or set Face ID support

## Contributing

When making changes:

1. Update Kotlin code following Kotlin coding conventions
2. Ensure all JNI calls are properly handled
3. Test on both phone and tablet
4. Test biometric authentication on physical devices
5. Run unit tests: `./gradlew test`

## License

Same as parent SentinelPass project.
