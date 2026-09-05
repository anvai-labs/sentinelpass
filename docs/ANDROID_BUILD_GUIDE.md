# Android App Build & Wire-Up Guide

> **Prototype status (2026-09-04):** the Android client is an unreleased prototype.
> Biometric unlock, sync, and autofill contain placeholder implementations and are not
> security controls; the JNI-enabled build does not yet compile in CI. Do not store
> production credentials in a prototype build. See `docs/SECURITY_STATUS_MATRIX.md`
> (Android rows) and ADR-009 for the production-readiness plan.

This guide explains how to build and wire up the SentinelPass Android app with the Rust mobile bridge via JNI.

## Prerequisites

1. **Android Studio** Hedgehog (2023.1.1) or later
2. **JDK 17**
3. **Android SDK 34**
4. **Android NDK 25.x or later**
5. **Rust stable toolchain**
6. **Android Rust targets**

## Step 1: Install Android NDK

### Via Android Studio (Recommended)

1. Open Android Studio
2. **Settings** → **Appearance & Behavior** → **System Settings** → **Android SDK**
3. Go to **SDK Tools** tab
4. Check **NDK (Side by side)**
5. Click **Apply** to install

### Verify Installation

```bash
# Check if NDK is in PATH
which ndk-build

# Or check ANDROID_NDK_HOME
echo $ANDROID_NDK_HOME

# Should output something like: /Users/username/Library/Android/sdk/ndk/25.2.9519653
```

### Set Environment Variable (Optional but Recommended)

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
# macOS
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/25.2.9519653"

# Linux
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/25.2.9519653"
```

Then reload: `source ~/.zshrc`

## Step 2: Install Rust Android Targets

```bash
rustup target add aarch64-linux-android    # arm64-v8a (modern devices)
rustup target add armv7-linux-androideabi  # armeabi-v7a (older 32-bit devices)
rustup target add x86_64-linux-android     # x86_64 (emulators)
```

## Step 3: Build JNI Libraries

### Using the Build Script (Recommended)

```bash
cd /path/to/sentinelpass
./android/build-libs.sh
```

This will:
1. Detect your NDK installation
2. Build the mobile bridge for all architectures
3. Copy `.so` files to the correct locations

### Manual Build (Alternative)

```bash
cd /path/to/sentinelpass

# Set NDK path (if not in environment)
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/25.2.9519653"
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"

# Build for arm64-v8a (most physical devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release \
  --target aarch64-linux-android

# Build for armeabi-v7a (older 32-bit devices)
cargo build --package sentinelpass-mobile-bridge --features jni --release \
  --target armv7-linux-androideabi

# Build for x86_64 (emulators)
cargo build --package sentinelpass-mobile-bridge --features jni --release \
  --target x86_64-linux-android
```

### Copy JNI Libraries

```bash
# Create directories
mkdir -p android/SentinelPass/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

# Copy libraries
cp target/aarch64-linux-android/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/armeabi-v7a/

cp target/x86_64-linux-android/release/libsentinelpass_mobile_bridge.so \
   android/SentinelPass/app/src/main/jniLibs/x86_64/
```

## Step 4: Open in Android Studio

```bash
cd android/SentinelPass
# Or open Android Studio → Open → Select android/SentinelPass directory
```

## Step 5: Configure Gradle

The `app/build.gradle.kts` should already have the JNI configuration:

```kotlin
android {
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}
```

## Step 6: Build and Run

### From Android Studio

1. Select a device or emulator
2. Click **Run** (green play button) or press `Shift+F10`

### From Command Line

```bash
cd android/SentinelPass

# Build debug APK
./gradlew assembleDebug

# Install to connected device
./gradlew installDebug

# Build release APK
./gradlew assembleRelease
```

## Troubleshooting

### "error: failed to find tool aarch64-linux-android-clang"

**Cause**: NDK not found or not in PATH

**Solution**:
1. Install NDK via Android Studio
2. Set `ANDROID_NDK_HOME` environment variable
3. Or use the build script which auto-detects NDK

### "UnsatisfiedLinkError: Couldn't load sentinelpass_mobile_bridge"

**Cause**: Native library not found or wrong architecture

**Solution**:
1. Verify `.so` files are in `app/src/main/jniLibs/<abi>/`
2. Check device architecture:
   ```bash
   adb shell getprop ro.product.cpu.abi
   ```
3. Build only for required architecture
4. Clean and rebuild:
   ```bash
   ./gradlew clean
   ./gradlew assembleDebug
   ```

### "java.lang.UnsatisfiedLinkError: dlopen failed: cannot locate symbol"

**Cause**: Missing system libraries or incompatible NDK version

**Solution**:
1. Ensure you're using NDK 25.x
2. Check that all Rust dependencies are compatible
3. Try building with `--release` flag for optimized binaries

### "No implementation found for Java_com_sentinelpass_VaultManager_nativeInit"

**Cause**: JNI function signature mismatch

**Solution**:
1. Verify package name matches: `com.sentinelpass`
2. Check JNI function naming in `jni.rs`
3. Ensure JNI feature is enabled: `--features jni`

### Build works on emulator but crashes on device

**Cause**: Architecture mismatch (emulator is x86_64, device is arm64)

**Solution**:
```bash
# Build for device architecture
cargo build --package sentinelpass-mobile-bridge --features jni --release \
  --target aarch64-linux-android
```

### Build works on device but crashes on emulator

**Cause**: Missing x86_64 library

**Solution**:
```bash
cargo build --package sentinelpass-mobile-bridge --features jni --release \
  --target x86_64-linux-android
```

## Testing the Integration

1. **Create Vault**:
   - App should show "Create Your Vault" screen
   - Enter master password (with strength indicator)
   - Should unlock to main screen

2. **Add Entry**:
   - Navigate to Passwords tab
   - Tap **+** floating action button
   - Fill in entry details
   - Save

3. **Search**:
   - Type in search bar
   - Results should filter

4. **TOTP**:
   - Add entry with TOTP secret (via CLI first)
   - Navigate to TOTP tab
   - Should show code with countdown progress

5. **Biometric**:
   - Enable biometric in Settings
   - Lock vault
   - Should show fingerprint/face prompt

6. **Password Generator**:
   - Navigate to Generate tab
   - Adjust length slider
   - Toggle symbols
   - Tap Generate

## Quick Start Script

Save this as `android/build-and-run.sh`:

```bash
#!/bin/bash
set -e

echo "Building JNI libraries..."
./build-libs.sh

echo ""
echo "Opening Android Studio..."
open -a "Android Studio" .

echo ""
echo "Or build from command line:"
echo "  cd android/SentinelPass"
echo "  ./gradlew assembleDebug"
echo "  ./gradlew installDebug"
```

## Architecture Notes

### Android App Architecture
```
Jetpack Compose UI
    ↓
VaultState (StateFlow)
    ↓
VaultBridge (Kotlin JNI)
    ↓ JNI
sentinelpass_mobile_bridge.so (Rust shared lib)
    ↓
sentinelpass_core (Rust)
```

### Threading

- All bridge calls are `suspend fun` (coroutines)
- Run on `Dispatchers.IO` (background thread)
- UI updates on main thread via `StateFlow.collectAsState()`

### Memory Management

- Rust returns JSON strings → Kotlin deserializes with kotlinx.serialization
- JVM manages memory automatically
- No manual free needed (unlike iOS)

## Building for Release

### 1. Configure Signing

In `app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            // Use keystore from local.properties (not in git)
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            if (keystorePropertiesFile.exists()) {
                val keystoreProperties = Properties()
                keystoreProperties.load(FileInputStream(keystorePropertiesFile))
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

### 2. Build Release APK/AAB

```bash
cd android/SentinelPass
./gradlew bundleRelease  # AAB for Play Store
./gradlew assembleRelease  # APK for direct distribution
```

## Next Steps

After wiring up:

1. Test on physical Android device
2. Test on emulator (different API levels)
3. Verify all CRUD operations work
4. Test biometric authentication
5. Test TOTP generation
6. Test password generator
7. Add unit tests for `VaultBridge`
8. Configure autofill service

## Resources

- [Jetpack Compose Documentation](https://developer.android.com/jetpack/compose)
- [Kotlin JNI](https://developer.android.com/training/articles/perf-jni)
- [BiometricPrompt](https://developer.android.com/training/sign-in/biometric-auth)
- [Coroutines Guide](https://developer.android.com/kotlin/coroutines)
