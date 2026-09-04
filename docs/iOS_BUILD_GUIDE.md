# iOS App Build & Wire-Up Guide

This guide explains how to build and wire up the SentinelPass iOS app with the Rust mobile bridge.

## Prerequisites

- macOS 14.0+ (Sonoma or later)
- Xcode 15.0+
- Rust stable toolchain
- iOS Device or Simulator (iOS 17.0+)

## Step 1: Build the Rust Mobile Bridge

```bash
cd /path/to/sentinelpass
cargo build --package sentinelpass-mobile-bridge --release
```

This produces:
- Static library: `target/release/libsentinelpass_mobile_bridge.a`
- C header: `sentinelpass-mobile-bridge/include/sentinelpass_bridge.h`

## Step 2: Create Xcode Project

Since we have SwiftUI source files but no Xcode project, you need to create one:

### Option A: Using Xcode (Recommended)

1. **Open Xcode** → File → New → Project
2. Select **iOS** → **App**
3. Configure:
   - Product Name: `SentinelPass`
   - Team: Your development team
   - Organization Identifier: `com.sentinelpass`
   - Interface: **SwiftUI**
   - Language: **Swift**
   - Storage: **SwiftData**
   - Save to: `ios/SentinelPass/SentinelPass` (replace existing folder or use different location)

4. **Replace/Delete auto-generated files** with our implementation:
   - Delete `SentinelPassApp.swift` (auto-generated)
   - Delete `ContentView.swift` (auto-generated)
   - Copy all `.swift` files from our `ios/SentinelPass/SentinelPass/` to project
   - Copy `SentinelPassBridge/` folder to project

### Option B: Manual Project Creation

Create `ios/SentinelPass/SentinelPass.xcodeproj/project.pbxproj` manually (not recommended).

## Step 3: Configure Xcode Project

### 3.1 Add Static Library

1. Select project in navigator
2. Select target → **Build Phases**
3. **Link Binary With Libraries** → **+** → **Add Other...**
4. Navigate to: `target/release/libsentinelpass_mobile_bridge.a`
5. Click **Open**

### 3.2 Add Header Search Path

1. Select target → **Build Settings**
2. Search for "Header Search Paths"
3. Add: `$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include`
4. Set to **recursive** ✅

### 3.3 Add Module Map (for Swift-C interop)

1. Add `sentinelpass.modulemap` to project (already created in `ios/SentinelPass/`)
2. In Build Settings:
   - Search for "Import Paths"
   - Add: `$(PROJECT_DIR)/` (path to modulemap)

### 3.4 Link Required Frameworks

**Build Phases** → **Link Binary With Libraries** → **+**:
- `LocalAuthentication.framework`
- `CloudKit.framework` (for iCloud sync)

Note: `SwiftData.framework` is optional and only needed if using SwiftData persistence.

### 3.5 Configure Signing & Capabilities

**Signing & Capabilities**:
1. Select your development team
2. **+ Capability** → **Face ID**
3. **+ Capability** → **iCloud** (for CloudKit sync):
   - Check "CloudKit"
   - Select or create a container (e.g., "iCloud.com.sentinelpass.sync")

## Step 4: Verify Build

```bash
# From command line
xcodebuild -project ios/SentinelPass/SentinelPass.xcodeproj \
           -scheme SentinelPass \
           -destination 'platform=iOS Simulator,name=iPhone 15' \
           clean build
```

Or press `Cmd+B` in Xcode.

## Step 5: Run on Simulator/Device

1. Select a simulator or connected device
2. Press `Cmd+R` or click Play button

## Troubleshooting

### "sentinelpass_bridge.h file not found"

**Solution**: Add header search path:
```
$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include
```
Set to recursive ✅

### "Undefined symbols: _sp_vault_init"

**Solution**:
1. Ensure static library is linked in "Link Binary With Libraries"
2. Verify library path points to `target/release/libsentinelpass_mobile_bridge.a`
3. Check library architecture matches simulator/device

### "Cannot find 'VaultBridge' in scope"

**Solution**:
1. Ensure `VaultBridge.swift` is added to target
2. Check "Target Membership" includes your app

### "Linker command failed" (arm64 vs x86_64)

**Solution**: Build for correct architecture:

```bash
# For Apple Silicon Mac simulators (arm64)
cargo build --package sentinelpass-mobile-bridge --release

# For Intel Mac simulators (x86_64) - Rosetta
cargo build --package sentinelpass-mobile-bridge --release --target x86_64-apple-ios

# For physical devices (arm64)
cargo build --package sentinelpass-mobile-bridge --release --target aarch64-apple-ios
```

Then combine with lipo for universal binary:

```bash
lipo -create \
  target/aarch64-apple-ios/release/libsentinelpass_mobile_bridge.a \
  target/x86_64-apple-ios/release/libsentinelpass_mobile_bridge.a \
  -output target/universal/libsentinelpass_mobile_bridge.a
```

### "Module 'sentinelpass' not found"

**Solution**: The module map may not be needed. Our `VaultBridge.swift` directly declares C functions via imports. Instead, just ensure:

1. Header is in search path
2. `VaultBridge.swift` uses proper function declarations

Actually, for simplicity, our `VaultBridge.swift` doesn't need to import the module - it declares the C functions directly. The linker resolves them at build time.

## Quick Start Script

Save this as `ios/build.sh`:

```bash
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Building mobile bridge..."
cd "$PROJECT_ROOT"
cargo build --package sentinelpass-mobile-bridge --release

echo "Static library: $(find target -name libsentinelpass_mobile_bridge.a)"
echo "C header: $PROJECT_ROOT/sentinelpass-mobile-bridge/include/sentinelpass_bridge.h"
echo ""
echo "Next steps:"
echo "1. Open ios/SentinelPass/SentinelPass.xcodeproj in Xcode"
echo "2. Add static library to 'Link Binary With Libraries'"
echo "3. Add header search path: \$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include"
echo "4. Press Cmd+R to build and run"
```

Run: `chmod +x ios/build.sh && ./ios/build.sh`

## Architecture Notes

### iOS App Architecture
```
SwiftUI Views
    ↓
VaultState (Observable)
    ↓
VaultBridge (Swift)
    ↓ C FFI
sentinelpass_mobile_bridge.a (Rust static lib)
    ↓
sentinelpass_core (Rust)
```

### Memory Management

- Rust returns owned C strings → Swift must call `sp_string_free()`
- Rust returns arrays → Swift must call `sp_bytes_free()`
- Swift `String` with `cString(using:)` for Rust consumption

### Threading

- All bridge calls are `async` and run on background thread
- `@MainActor` ensures UI updates on main thread
- `withCheckedContinuation` bridges async/await with C callbacks

## Testing the Integration

1. **Create Vault**:
   - App should show "Create Your Vault" screen
   - Enter master password
   - Should unlock to main screen

2. **Add Entry**:
   - Navigate to Passwords tab
   - Tap **+**
   - Fill in entry details
   - Save

3. **Search**:
   - Type in search bar
   - Results should filter

4. **TOTP**:
   - Add entry with TOTP secret (via CLI first)
   - Navigate to TOTP tab
   - Should show code with countdown

5. **Biometric**:
   - Enable biometric in Settings
   - Lock vault
   - Should prompt for Face ID/Touch ID

## Next Steps

After wiring up:

1. Test on physical device (simulator has limited biometric)
2. Verify all CRUD operations work
3. Test TOTP generation
4. Test password generator
5. Add unit tests for `VaultBridge`
6. **CloudKit Sync Integration**:
   - Create `CloudKitService` instance in your app
   - Initialize with device ID: `let cloudKit = CloudKitService(deviceID: UUID())`
   - Check availability: `await cloudKit.checkCloudKitAvailability()`
   - Push entries: `await cloudKit.pushEntries(records)`
   - Pull entries: `let (records, nextToken) = await cloudKit.pullEntries()`
   - Handle errors for auth, quota, network issues

### CloudKit Sync Data Model

Records are stored in CloudKit's private database:

**Record Type**: `SyncEntry`
- `encryptedPayload` (String): Base64-encoded encrypted sync blob
- `modifiedAt` (Int64): Unix timestamp for LWW ordering
- `isTombstone` (Bool): Soft delete marker
- `entryType` (String): SyncEntryType discriminator
- `syncVersion` (Int64): Monotonic version counter
- `originDeviceId` (String): Source device UUID

**Record Type**: `DeviceInfo` (for device registration)
- `deviceID` (String): Device UUID
- `deviceName` (String): Device display name
- `deviceType` (String): "iOS"
- `registeredAt` (Date): Registration timestamp

## Resources

- [SwiftUI Documentation](https://developer.apple.com/documentation/swiftui)
- [Swift-C Interop](https://www.swift.org/documentation/cxx-interop/)
- [Biometric Authentication](https://developer.apple.com/documentation/localauthentication)
- [CloudKit Documentation](https://developer.apple.com/documentation/cloudkit)
- [CloudKit Quick Start](https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/CloudKitQuickStart/)
