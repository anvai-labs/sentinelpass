# Mobile App Testing Guide

This guide explains how to test the SentinelPass iOS and Android apps on simulators/emulators.

## Prerequisites Checklist

- [ ] macOS 14.0+ (for iOS development)
- [ ] Xcode 15.0+ (for iOS simulators)
- [ ] Android Studio (for Android emulators)
- [ ] Android NDK 25.x+ (for Android native builds)

---

## iOS Testing (Simulators)

### Step 1: Install Xcode

Xcode includes iOS simulators. Check if installed:

```bash
xcodebuild -version
```

If not installed, download from Mac App Store.

### Step 2: Build the Mobile Bridge

```bash
cd /path/to/sentinelpass

# Run the setup script
./setup-xcode.sh
```

This builds the Rust static library for iOS.

### Step 3: Create Xcode Project

**Note:** This is a manual process using Xcode GUI:

1. **Open Xcode**

2. **Create New Project:**
   - File → New → Project
   - Select **iOS** → **App**
   - Click **Next**

3. **Configure Project:**
   - Product Name: `SentinelPass`
   - Team: Select your Apple ID (or "Add an Account" → Sign in with Apple ID)
   - Organization Identifier: `com.sentinelpass`
   - Interface: **SwiftUI**
   - Language: **Swift**
   - Storage: **SwiftData** ✓
   - Include Tests: (optional)
   - Save to: `/path/to/sentinelpass/ios/XcodeProject` (or replace existing `SentinelPass` folder)

4. **Replace Auto-Generated Files:**
   - Delete `SentinelPassApp.swift` (Xcode generated)
   - Delete `ContentView.swift` (Xcode generated)
   - Copy all `.swift` files from `ios/SentinelPass/SentinelPass/`:
     ```bash
     cp -r ios/SentinelPass/SentinelPass/*.swift XcodeProject/SentinelPass/
     ```
   - Copy `SentinelPassBridge/` folder:
     ```bash
     cp -r ios/SentinelPass/SentinelPassBridge XcodeProject/SentinelPass/
     ```

5. **Add Static Library:**
   - Select project in navigator → Target → **Build Phases**
   - **Link Binary With Libraries** → **+** → **Add Other...**
   - Navigate to: `target/release/libsentinelpass_mobile_bridge.a`
   - Click **Open**

6. **Add Header Search Path:**
   - Target → **Build Settings**
   - Search: "Header Search Paths"
   - Add: `$(PROJECT_DIR)/../../sentinelpass-mobile-bridge/include`
   - Set to **recursive** ✓

7. **Add Frameworks:**
   - **Build Phases** → **Link Binary With Libraries** → **+**
   - Add: `LocalAuthentication.framework`
   - Add: `SwiftData.framework`

8. **Add Face ID Capability:**
   - Target → **Signing & Capabilities**
   - **+ Capability** → **Face ID**

### Step 4: Select Simulator

In Xcode toolbar:
- Click device dropdown (near "Play" button)
- Select an iOS Simulator:
  - **iPhone 15** (recommended)
  - **iPhone 15 Pro**
  - **iPad Pro** (for tablet testing)

### Step 5: Build and Run

- Press `Cmd+R` or click **Play** button
- Simulator will launch automatically
- First launch may take longer (compiling Rust code)

### Step 6: Test the App

1. **Create Vault:**
   - Should show "Create Your Vault" screen
   - Enter a master password (with strength indicator)
   - Tap "Create Vault"

2. **Test Password Management:**
   - Add a test entry
   - Search for it
   - View details
   - Copy password to clipboard

3. **Test TOTP:**
   - (Requires TOTP secret - add via CLI first)

4. **Test Biometric:**
   - Enable Face ID in Settings (simulator only)
   - Lock vault
   - Should prompt for Face ID

---

## Android Testing (Emulators)

### Step 1: Install Android Studio

Download from: https://developer.android.com/studio

Install with default settings (includes SDK, emulator, etc.)

### Step 2: Install Android NDK

1. Open Android Studio
2. **Settings** → **Appearance & Behavior** → **System Settings** → **Android SDK**
3. **SDK Tools** tab
4. Check **NDK (Side by side)**
5. Click **Apply** (downloads ~1GB)

### Step 3: Install Rust Android Targets

```bash
cd /path/to/sentinelpass
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

### Step 4: Build JNI Libraries

```bash
# Use the automated build script
./android/build-libs.sh
```

This builds native `.so` files for all Android architectures and copies them to `jniLibs/`.

### Step 5: Create Android Virtual Device (AVD)

1. **Open Android Studio**

2. **Create Device:**
   - **Device Manager** (phone icon in toolbar)
   - **Create Device** button
   - Select device (e.g., **Pixel 6**)
   - Click **Next**

3. **Select System Image:**
   - Recommended: **API 34** (Android 14)
   - If not downloaded, click **Download** next to it
   - Click **Next**

4. **Finish Configuration:**
   - AVD Name: `Pixel_6_API_34`
   - Show Advanced Settings: (optional)
   - Click **Finish**

### Step 6: Open Project in Android Studio

```bash
cd android/SentinelPass
# Or: File → Open → Select android/SentinelPass directory
```

### Step 7: Build and Run

**In Android Studio:**

1. Select the emulator from device dropdown (top toolbar)
2. Click **Run** (green play button) or press `Shift+F10`
3. Gradle will sync, build, and install the app

**From Command Line:**

```bash
cd android/SentinelPass

# Build debug APK
./gradlew assembleDebug

# Install to running emulator
./gradlew installDebug

# Or build and run in one step
./gradlew installDebug
adb shell am start -n com.sentinelpass/.MainActivity
```

### Step 8: Test the App

1. **Create Vault:**
   - Should show "Create Your Vault" screen
   - Enter master password
   - Watch strength indicator change
   - Tap "Create Vault"

2. **Test Password Management:**
   - Tap **Passwords** tab
   - Tap **+** button
   - Add test entry
   - Use search
   - Tap entry to view details
   - Tap copy icons

3. **Test TOTP:**
   - Navigate to **TOTP** tab
   - Should show countdown timer
   - Codes refresh every 30 seconds

4. **Test Password Generator:**
   - Navigate to **Generate** tab
   - Adjust length slider
   - Toggle symbols
   - Tap "Generate"
   - Tap "Copy"

5. **Test Biometric:**
   - Go to **Settings**
   - Enable "Biometric Unlock"
   - Lock vault
   - Should show fingerprint prompt

---

## Quick Reference Commands

### iOS Simulator

```bash
# List available simulators
xcrun simctl list devices available

# Boot specific simulator
xcrun simctl boot "iPhone 15"

# Install app (requires .ipa)
xcrun simctl install "iPhone 15" /path/to/SentinelPass.app

# Launch app
xcrun simctl launch "iPhone 15" com.sentinelpass.ios

# Reset simulator (clear data)
xcrun simctl erase "iPhone 15"
```

### Android Emulator

```bash
# List running emulators
adb devices

# Install APK
adb install android/SentinelPass/app/build/outputs/apk/debug/app-debug.apk

# Launch app
adb shell am start -n com.sentinelpass/.MainActivity

# Clear app data
adb shell pm clear com.sentinelpass

# View logs
adb logcat | grep -E "SentinelPass|sentinelpass"

# Emulator controls
# - Ctrl+Cmd+←: Back
# - Ctrl+Cmd+→: Recent apps
# - Cmd+K: Keyboard
# - Cmd+M: Menu
```

---

## Troubleshooting

### iOS Simulator Issues

**"Library not loaded: @rpath/libsentinelpass_mobile_bridge.a"**
- Static library not linked
- Check "Link Binary With Libraries" in Build Phases

**"sentinelpass_bridge.h file not found"**
- Header search path missing
- Add path to Build Settings with recursive ✓

**App crashes on launch**
- Check console logs in Xcode (Cmd+Shift+C)
- Verify architecture matches (arm64 vs x86_64)

### Android Emulator Issues

**"UnsatisfiedLinkError: Couldn't load sentinelpass_mobile_bridge"**
- JNI libraries not built or in wrong folder
- Run `./android/build-libs.sh`
- Check `app/src/main/jniLibs/` for `.so` files

**"error: failed to find tool aarch64-linux-android-clang"**
- NDK not installed or not in PATH
- Install via Android Studio SDK Manager
- Set `ANDROID_NDK_HOME` environment variable

**Emulator is slow**
- Enable hardware acceleration (HAXM or Hypervisor Framework)
- Use x86_64 system image (faster than ARM emulation)
- Increase RAM in AVD settings

**App not installing**
- Uninstall old version: `adb uninstall com.sentinelpass`
- Try: `./gradlew clean installDebug`

---

## Testing Checklist

### iOS

- [ ] Create vault
- [ ] Unlock with master password
- [ ] Add password entry
- [ ] Search entries
- [ ] View entry details
- [ ] Copy password to clipboard
- [ ] Generate password
- [ ] Check password strength
- [ ] Enable Face ID
- [ ] Lock/unlock with biometric
- [ ] TOTP code generation

### Android

- [ ] Create vault
- [ ] Unlock with master password
- [ ] Add password entry
- [ ] Search entries
- [ ] View entry details
- [ ] Copy password to clipboard
- [ ] Generate password
- [ ] Check password strength
- [ ] Enable fingerprint
- [ ] Lock/unlock with biometric
- [ ] TOTP code generation
- [ ] All tabs work (Passwords, TOTP, Generate, Settings)

---

## Next Steps After Testing

1. **Report Issues**: Document any bugs or crashes
2. **Test on Physical Devices**:
   - iOS: Requires real device for true biometric testing
   - Android: Test on different Android versions
3. **Missing Features**:
   - iOS: AutoFill integration, iCloud sync *(OBSOLETE 2026-09-11: CloudKit/Drive sync removed per ADR-009 rev 2 / WBS-807 — mobile sync is relay-only sync v2; ignore this item.)*
   - Android: Autofill service, QR scanner for TOTP
   - Both: Import/export, advanced settings
