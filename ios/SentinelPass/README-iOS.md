# SentinelPass iOS App - Development Guide

## Quick Start

### Testing on iOS Simulator

```bash
cd ios/SentinelPass

# The app is already built and can be tested on simulator
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install "iPhone 17 Pro" SentinelPassApp.app
xcrun simctl launch "iPhone 17 Pro" com.sentinelpass.app
```

### Building the App

⚠️ **Important**: Swift Package Manager (`swift build`) defaults to macOS builds. For iOS development, use **Xcode**.

#### Method 1: Xcode (Recommended)

```bash
cd ios/SentinelPass
open Package.swift
```

In Xcode:
1. Select scheme: **SentinelPassApp**
2. Select destination: **Any iOS Simulator (arm64)**
3. Press **⌘+B** to build
4. Built app: `.build/debug/SentinelPassApp.app`

#### Method 2: Command Line (xcodebuild)

```bash
cd ios/SentinelPass

# Build for iOS Simulator
xcodebuild -scheme SentinelPassApp \
  -sdk iphonesimulator \
  -configuration Debug \
  build

# Find and install the built app
find .build -name "SentinelPassApp.app" -exec cp -r {} build/ \;
xcrun simctl install "iPhone 17 Pro" build/SentinelPassApp.app
```

## Project Structure

```
ios/SentinelPass/
├── Package.swift                 # Swift Package Manager manifest
├── Info.plist                   # App configuration
├── build-ios.sh                 # Build helper script
├── README-iOS.md                # This file
├── SentinelPass/                # Swift source code
│   ├── SentinelPassApp.swift    # App entry point
│   ├── ContentView.swift        # Root view
│   ├── Models/                  # Data models
│   │   ├── EntryModel.swift
│   │   └── VaultState.swift
│   ├── Services/                # Business logic
│   │   ├── BiometricAuth.swift
│   │   └── VaultBridge.swift    # Rust FFI bridge
│   ├── Views/                   # SwiftUI views
│   │   ├── AddEntryView.swift
│   │   ├── EditEntryView.swift
│   │   ├── EntryDetailView.swift
│   │   ├── EntriesList.swift
│   │   ├── GeneratorView.swift
│   │   ├── LockView.swift
│   │   ├── PasswordGeneratorView.swift
│   │   ├── SettingsView.swift
│   │   ├── SetupView.swift
│   │   └── TotpList.swift
│   └── Assets.xcassets/         # Images, icons
└── Native/                      # Rust bridge
    ├── include/
    │   └── sentinelpass_bridge.h  # C FFI header
    ├── libs/                     # Compiled libraries
    │   ├── libsentinelpass_mobile_bridge_ios.a
    │   └── libsentinelpass_mobile_bridge_ios_sim.a
    └── module.modulemap           # Swift module map
```

## Dependencies

- **Swift**: 5.9+
- **iOS**: 17.0+
- **Xcode**: 15.0+
- **Rust**: For building the native bridge (see below)

## Building the Rust Mobile Bridge

The iOS app uses a Rust library via C FFI. To rebuild:

```bash
# From project root
cd sentinelpass-mobile-bridge

# Build for iOS devices (arm64)
cargo build --target aarch64-apple-ios --release

# Build for iOS Simulator (arm64)
cargo build --target aarch64-apple-ios-sim --release

# Create XCFramework (universal)
mkdir -p ios/SentinelPass/SentinelPass/Native/libs
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsentinelpass_mobile_bridge_ios.a \
  -library target/aarch64-apple-ios-sim/release/libsentinelpass_mobile_bridge_ios_sim.a \
  -output ios/SentinelPass/SentinelPass/Native/libs/sentinelpass_mobile_bridge.xcframework
```

Copy header files:
```bash
cp sentinelpass-mobile-bridge/ffi/sentinelpass_bridge.h \
   ios/SentinelPass/SentinelPass/Native/include/
```

## Simulator Commands

```bash
# List available simulators
xcrun simctl list devices

# Boot a simulator
xcrun simctl boot "iPhone 17 Pro"

# Install app
xcrun simctl install "iPhone 17 Pro" /path/to/SentinelPassApp.app

# Launch app
xcrun simctl launch "iPhone 17 Pro" com.sentinelpass.app

# Terminate app
xcrun simctl terminate "iPhone 17 Pro" com.sentinelpass.app

# Uninstall app
xcrun simctl uninstall "iPhone 17 Pro" com.sentinelpass.app

# Take screenshot
xcrun simctl io "iPhone 17 Pro" screenshot screenshot.png

# View logs
xcrun simctl spawn "iPhone 17 Pro" log show --predicate 'process == "SentinelPassApp"' --last 5m

# Stream logs
xcrun simctl spawn "iPhone 17 Pro" log stream --predicate 'process == "SentinelPassApp"'

# Open Simulator app
open -a Simulator
```

## Installing on Physical iPhone Device

### Prerequisites

1. Apple Developer Account ($99/year) OR free Apple ID (7-day limit)
2. iPhone on same WiFi network as Mac
3. Xcode installed

### Method 1: Xcode (Easiest)

```bash
cd ios/SentinelPass
open Package.swift

# In Xcode:
# 1. Connect iPhone via USB (first time)
# 2. Select your iPhone as destination
# 3. Enable automatic signing in project settings
# 4. Press ⌘+R to run
```

### Method 2: TestFlight (Beta Testing)

1. Build for distribution in Xcode
2. Upload to App Store Connect
3. Add to TestFlight
4. Invite testers via email or public link

### Method 3: Ad-hoc WiFi Distribution

For ad-hoc distribution, you need to:
1. Create provisioning profile in Apple Developer Portal
2. Build and sign with xcodebuild
3. Distribute IPA (limited to 100 devices)

## Platform Availability

All SwiftUI views and models use `@available(iOS 17.0, macOS 14.0, *)` to ensure:

- **iOS 17.0+**: Required for modern SwiftUI features
- **iOS-specific APIs**: Guarded with `#if os(iOS)`

Key files requiring platform attributes:
- All `Views/*.swift` files
- `Models/EntryModel.swift`
- `Models/VaultState.swift`
- `Services/BiometricAuth.swift`

## Troubleshooting

### "building for 'macOS', but linking in object file built for 'iOS-simulator'"

**Cause**: `swift build` defaults to macOS. Use Xcode instead.

**Solution**:
```bash
open Package.swift
# Build in Xcode with iOS Simulator destination
```

### "library not found for -lsentinelpass_mobile_bridge_ios_sim"

**Cause**: Native library not built or in wrong location.

**Solution**:
```bash
cd sentinelpass-mobile-bridge
cargo build --target aarch64-apple-ios-sim --release
cp target/aarch64-apple-ios-sim/release/libsentinelpass_mobile_bridge_ios_sim.a \
   ../ios/SentinelPass/SentinelPass/Native/libs/
```

### App crashes on launch

Check simulator logs:
```bash
xcrun simctl spawn "iPhone 17 Pro" log show --predicate 'process == "SentinelPassApp"' --last 5m
```

Look for:
- Missing symbols (FFI mismatch)
- Platform errors (iOS vs macOS)
- Native library loading issues

## Testing Features

### Test Vault Creation
1. Launch app in simulator
2. Click "Create New Vault"
3. Enter master password
4. Verify vault is created

### Test Entry Management
1. Unlock vault (if locked)
2. Click "+" to add entry
3. Fill in: title, username, password
4. Save and verify in list

### Test TOTP
1. Add entry with TOTP secret
2. View entry details
3. Verify TOTP code generates

### Test Biometric (Simulator)
Note: Biometric testing requires:
- Physical device for Face ID / Touch ID
- Simulator: Enroll via Features → Face ID / Touch ID

## Resources

- [Swift Package Manager](https://www.swift.org/package-manager/)
- [Xcode Documentation](https://developer.apple.com/documentation/xcode)
- [simctl Manual](https://developer.apple.com/library/archive/technotes/tn2339/_index.html)
- [SwiftUI](https://developer.apple.com/documentation/swiftui)
