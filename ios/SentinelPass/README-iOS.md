# SentinelPass iOS App - Development Guide

## Quick Start

### One-time setup: build the Rust bridge

No bridge binaries are committed (ADR-009 rev 2). Generate them first:

```bash
cd ios/SentinelPass
./build-ios.sh                 # simulator + device libraries
ONLY_SIM=1 ./build-ios.sh      # simulator only
```

This populates `SentinelPass/Native/libs/` with
`libsentinelpass_mobile_bridge_ios_sim.a` (simulator) and
`libsentinelpass_mobile_bridge_ios.a` (device), and refreshes the copied
C header `SentinelPass/Native/include/sentinelpass_bridge.h` from the
generated contract in `sentinelpass-mobile-bridge/include/`.

### Building the App

The project has TWO targets in `SentinelPassApp.xcodeproj`:

- **SentinelPassApp** — the main SwiftUI app (`com.sentinelpass.app`)
- **SentinelPassCredential** — iOS 17 credential-provider extension
  (`com.sentinelpass.app.credential-provider`), embedded in the app

#### Method 1: Xcode (Recommended)

```bash
cd ios/SentinelPass
open SentinelPassApp.xcodeproj
```

1. Select scheme: **SentinelPassApp** (or **SentinelPassCredential**)
2. Select an iOS Simulator destination
3. Press **Cmd+B** to build

#### Method 2: Command Line (xcodebuild)

```bash
cd ios/SentinelPass

xcodebuild -project SentinelPassApp.xcodeproj \
  -scheme SentinelPassApp \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  build CODE_SIGNING_ALLOWED=NO

# The extension target directly:
xcodebuild -project SentinelPassApp.xcodeproj \
  -scheme SentinelPassCredential \
  -sdk iphonesimulator \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  build CODE_SIGNING_ALLOWED=NO
```

(Adjust the simulator name to one listed by `xcrun simctl list devices available`.)

## Project Structure

```
ios/SentinelPass/
├── Package.swift                 # SPM manifest (systemLibrary + app target)
├── build-ios.sh                  # Populates Native/libs from cargo builds
├── README-iOS.md                 # This file
├── SentinelPass/                 # App sources
│   ├── SentinelPassApp.swift     # App entry (scene lock + privacy cover + auto-lock)
│   ├── ContentView.swift         # Root router
│   ├── Info.plist
│   ├── SentinelPass.entitlements # App Group group.com.sentinelpass
│   ├── Models/
│   │   ├── EntryModel.swift      # Non-sensitive list mirror (NO plaintext)
│   │   └── VaultState.swift      # Central vault state manager
│   ├── Services/
│   │   ├── BiometricAuth.swift   # LocalAuthentication availability helper
│   │   ├── VaultBridge.swift     # Rust FFI bridge (ABI v2)
│   │   ├── KeychainSlot.swift    # WBS-821 Keychain platform slot (DEK)
│   │   ├── VaultFile.swift       # WBS-822 shared vault path + at-rest policy
│   │   └── Pasteboard.swift      # WBS-824 local expiring paste (30 s)
│   ├── Views/                    # SwiftUI views
│   └── Native/                   # Swift/C module for the bridge
│       ├── include/
│       │   └── sentinelpass_bridge.h  # COPY of the generated contract
│       ├── libs/                 # script-populated .a files (NOT committed)
│       └── module.modulemap
└── SentinelPassCredential/       # WBS-825 credential-provider extension
    ├── CredentialProviderViewController.swift
    ├── SentinelPassCredential.entitlements
    └── Info.plist
```

## Dependencies

- **Swift**: 5.9+
- **iOS**: 17.0+
- **Xcode**: 15.0+
- **Rust**: with the `aarch64-apple-ios-sim` (+ `aarch64-apple-ios`) targets

## Building the Rust Mobile Bridge

Handled by `./build-ios.sh` (see Quick Start). Equivalent manual steps:

```bash
# From the repo root
cargo build --package sentinelpass-mobile-bridge --target aarch64-apple-ios-sim --release
cargo build --package sentinelpass-mobile-bridge --target aarch64-apple-ios --release

cp target/aarch64-apple-ios-sim/release/libsentinelpass_mobile_bridge.a \
   ios/SentinelPass/SentinelPass/Native/libs/libsentinelpass_mobile_bridge_ios_sim.a
cp target/aarch64-apple-ios/release/libsentinelpass_mobile_bridge.a \
   ios/SentinelPass/SentinelPass/Native/libs/libsentinelpass_mobile_bridge_ios.a
```

## Security notes

- The vault lives under the `group.com.sentinelpass` App Group container
  (shared with the credential-provider extension); Documents is the
  unsigned-build fallback.
- WBS-822: `NSFileProtectionComplete` + `isExcludedFromBackup` are applied
  to the vault database and its SQLite sidecars (best-effort, see
  `Services/VaultFile.swift`).
- WBS-821: the Keychain platform slot stores the vault DEK under
  `kSecAccessControlBiometryCurrentSet`; unlock goes through
  `sp_slot_open_with_dek`. Slot ENROLLMENT ships in M4 (needs a DEK export
  from the bridge ABI).
- WBS-823: privacy cover when the scene is not active; 5-minute auto-lock
  while backgrounded.
- WBS-824: sensitive copies (passwords, TOTP codes) expire from the
  pasteboard after 30 seconds. Universal Clipboard cannot be opted out of
  via the UIPasteboard API — see the comment in `Services/Pasteboard.swift`.

## Simulator Commands

```bash
# List available simulators
xcrun simctl list devices

# Boot / install / launch
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install "iPhone 17 Pro" <path>/Build/Products/Debug-iphonesimulator/SentinelPassApp.app
xcrun simctl launch "iPhone 17 Pro" com.sentinelpass.app
```

## Installing on Physical iPhone Device

Signing/provisioning with your own team is a user/CI concern: set
`DEVELOPMENT_TEAM` in the project (both targets share the App Group
entitlement, which must be provisioned), then let Xcode manage signing.
CI builds use `CODE_SIGNING_ALLOWED=NO` (entitlements are declarative
only in that mode).

## Troubleshooting

### "library not found for -lsentinelpass_mobile_bridge_ios_sim"

The bridge library is not built. Run:

```bash
cd ios/SentinelPass && ./build-ios.sh
```

### "building for 'macOS', but linking in object file built for 'iOS-simulator'"

`swift build` defaults to macOS. Use Xcode or `xcodebuild` with an iOS
Simulator destination.

### App crashes on launch

Check simulator logs:

```bash
xcrun simctl spawn "iPhone 17 Pro" log show --predicate 'process == "SentinelPassApp"' --last 5m
```

Look for missing symbols (FFI/ABI mismatch) — the header copy and the
`.a` must come from the SAME build of `sentinelpass-mobile-bridge`
(re-run `./build-ios.sh` after touching the bridge crate).

## Testing Features

### Test Vault Creation
1. Launch app in simulator
2. Enter a strong master password
3. Verify the vault is created and the entry list appears

### Test Credential Provider (device)
1. Build & run the app on a device
2. Settings → Passwords → Password Options → enable SentinelPass
3. Focus a password field in another app → choose SentinelPass → unlock → pick an entry

### Test Keychain Slot
Biometric testing requires the simulator's
Features → Face ID / Touch ID enrollment (or a physical device). Note the
slot must be enrolled for the lock screen to offer keychain unlock
(enrollment ships in M4).
