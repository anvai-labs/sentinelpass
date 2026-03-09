# SentinelPass Build System

Complete build system for all SentinelPass platforms: Desktop, Mobile, and Web.

## Quick Start

### Build Everything

```bash
# Build all platforms (release mode)
./scripts/build-all.sh

# Build everything in debug mode
./scripts/build-all.sh -t debug

# Build without running tests
./scripts/build-all.sh --skip-tests
```

### Build Specific Platforms

```bash
# Build only desktop platforms (current OS)
./scripts/build-all.sh -p desktop

# Build only mobile platforms
./scripts/build-all.sh -p mobile

# Build only web assets
./scripts/build-all.sh -p web
```

## Individual Build Scripts

### Desktop Build

Builds CLI, daemon, host, and Tauri UI for the current platform.

```bash
./scripts/build-desktop.sh                    # Release build
./scripts/build-desktop.sh --debug           # Debug build
./scripts/build-desktop.sh --installers       # Build native installers
./scripts/build-desktop.sh --skip-tests       # Skip tests
```

**Supported Platforms:**
- macOS (Intel & Apple Silicon)
- Linux (x86_64)
- Windows (x86_64)

**Outputs:**
- `target/release/sentinelpass` - CLI binary
- `target/release/sentinelpass-daemon` - Background daemon
- `target/release/sentinelpass-host` - Native messaging host
- `target/release/sentinelpass-ui` - Tauri desktop UI

### iOS Build

Builds iOS app for devices and simulators.

```bash
./scripts/build-ios.sh                        # Release build
./scripts/build-ios.sh --debug               # Debug build
./scripts/build-ios.sh --skip-tests          # Skip tests
```

**Requirements:**
- macOS
- Xcode 15.0+
- Rust with iOS targets

**Outputs:**
- `build/ios/` - Built app bundles
- `ios/SentinelPass/SentinelPass/Native/libs/` - Native libraries

**Targets:**
- `aarch64-apple-ios` - iOS devices (arm64)
- `aarch64-apple-ios-sim` - iOS Simulator (arm64)

### Android Build

Builds Android APK and AAB for all architectures.

```bash
./scripts/build-android.sh                    # Release build
./scripts/build-android.sh --debug           # Debug build
./scripts/build-android.sh --apk-only        # Build APK only
./scripts/build-android.sh --aab-only        # Build AAB only
./scripts/build-android.sh --skip-tests      # Skip tests
```

**Requirements:**
- Android SDK
- Android NDK
- JDK 17+
- Gradle

**Outputs:**
- `build/android/*.apk` - Android APK files
- `build/android/*.aab` - Android App Bundle (Play Store)

**ABIs:**
- `arm64-v8a` - ARM64 (64-bit)
- `armeabi-v7a` - ARMv7 (32-bit)
- `x86_64` - x86_64 (emulator)

### Web Build

Builds browser extensions and web assets.

```bash
./scripts/build-web.sh                        # Build with tests
./scripts/build-web.sh --skip-tests          # Skip tests
```

**Requirements:**
- Node.js 20+
- npm

**Outputs:**
- `sentinelpass-ui/dist/` - Tauri web UI
- `browser-extension/chrome/dist/` - Chrome extension
- `browser-extension/firefox/dist/` - Firefox extension

## CI/CD Integration

### GitHub Actions

The build system integrates with GitHub Actions workflows:

- `.github/workflows/build-all.yml` - Universal build workflow
- `.github/workflows/rust.yml` - Rust CI (desktop)
- `.github/workflows/ios.yml` - iOS CI
- `.github/workflows/android.yml` - Android CI
- `.github/workflows/release.yml` - Release builds

### Triggering Manual Builds

```bash
# Via GitHub CLI
gh workflow run build-all.yml \
  -f platform=mobile \
  -f build_type=debug

# Via GitHub web interface
# Actions → Build All Platforms → Run workflow
```

## Build Artifacts

### Desktop Artifacts

| Platform | Archive | Contents |
|----------|---------|----------|
| Linux | `sentinelpass-{version}-linux.tar.gz` | Portable binaries |
| Linux | `sentinelpass-installer-{version}-linux.tar.gz` | Installer script |
| macOS | `sentinelpass-{version}-macos.tar.gz` | Portable binaries |
| macOS | `sentinelpass-installer-{version}-macos.tar.gz` | Installer script |
| Windows | `sentinelpass-{version}-windows.zip` | Portable binaries |
| Windows | `sentinelpass-installer-{version}-windows.zip` | Installer script |

### Mobile Artifacts

| Platform | Artifact | Use Case |
|----------|----------|----------|
| iOS | `SentinelPass.xcframework` | Xcode integration |
| iOS | `.app` bundle | Simulator testing |
| Android | `.apk` | Direct installation |
| Android | `.aab` | Play Store |

### Web Artifacts

| Platform | Artifact | Use Case |
|----------|----------|----------|
| Chrome | `.zip` | Chrome Web Store / Sideloading |
| Firefox | `.zip` | Firefox Add-ons / Sideloading |
| UI | `dist/` | Tauri integration |

## Development Workflows

### Local Development

```bash
# Quick feedback loop
./scripts/build-desktop.sh --debug --skip-tests

# Test specific platform
./scripts/build-ios.sh --debug --skip-tests
./scripts/build-android.sh --debug --skip-tests

# Run tests only
cargo test --workspace
npm run test:ts
```

### Pre-Release Checklist

```bash
# 1. Format and lint
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
npm run web:typecheck

# 2. Run all tests
cargo test --workspace
npm run test:ts
cd browser-extension/e2e && npm run test:e2e

# 3. Build release artifacts
./scripts/build-all.sh --release

# 4. Test installers
./scripts/build-desktop.sh --installers

# 5. Security audit
./scripts/security-audit.sh
```

### Release Build

```bash
# Tag the release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# GitHub Actions will:
# 1. Build all platforms
# 2. Run tests
# 3. Package artifacts
# 4. Create GitHub release
# 5. Upload assets
```

## Troubleshooting

### Common Issues

#### iOS Build Fails

```
error: building for 'macOS', but linking in object file built for 'iOS-simulator'
```

**Solution:** Use Xcode to build iOS apps. Swift Package Manager defaults to macOS.

```bash
cd ios/SentinelPass
open Package.swift
# Build in Xcode with iOS Simulator destination
```

#### Android Build Fails

```
error: linker arm-linux-androideabi-lgcc not found
```

**Solution:** Install Android NDK.

```bash
# Via Android Studio
# Preferences → Appearance & Behavior → System Settings → Android SDK → SDK Tools
# Check "NDK (Side by side)" and "CMake"
```

#### Missing Web Dependencies

```
Error: Cannot find module 'xxx'
```

**Solution:** Install dependencies.

```bash
npm install
# or
npm ci
```

### Getting Help

- Check logs: `build/*/` directories
- Run with verbose: `cargo build --verbose`
- Enable debug logging: `RUST_LOG=debug cargo build`

## Advanced Usage

### Cross-Compilation

Cross-compilation requires additional toolchains:

```bash
# Add target
rustup target add x86_64-unknown-linux-musl

# Build for target
cargo build --release --target x86_64-unknown-linux-musl
```

### Custom Build Configurations

Modify `Cargo.toml` for custom features:

```toml
[features]
default = ["cli", "daemon", "ui", "sync"]
cli = ["sentinelpass-cli"]
daemon = ["sentinelpass-daemon"]
ui = ["sentinelpass-ui", "sync"]
sync = ["sentinelpass-core/sync"]
```

Build with custom features:

```bash
cargo build --release --features "cli,daemon"
```

### Build Cache

CI/CD uses Rust cache for faster builds:

```yaml
- uses: Swatinem/rust-cache@v2
  with:
    prefix-key: custom-prefix
```

Local cache:

```bash
# Clear cache
cargo clean

# Use sccache for distributed caching
cargo install sccache
RUSTC_WRAPPER=sccache cargo build
```

## Build Script Reference

### build-all.sh

Universal build orchestrator.

| Flag | Description |
|------|-------------|
| `-p, --platform` | Build specific platform: all|desktop|mobile|web |
| `-t, --type` | Build type: debug|release |
| `--skip-tests` | Skip running tests |
| `--skip-web` | Skip web build |
| `--skip-desktop` | Skip desktop build |
| `--skip-mobile` | Skip mobile build |

### build-desktop.sh

Desktop platform builder.

| Flag | Description |
|------|-------------|
| `--debug` | Debug build |
| `--release` | Release build |
| `-p, --platform` | Target platform: all|current|macos|linux|windows |
| `--skip-tests` | Skip tests |
| `--installers` | Build native installers |

### build-ios.sh

iOS platform builder.

| Flag | Description |
|------|-------------|
| `--debug` | Debug build |
| `--release` | Release build |
| `--skip-tests` | Skip tests |

### build-android.sh

Android platform builder.

| Flag | Description |
|------|-------------|
| `--debug` | Debug build |
| `--release` | Release build |
| `--apk-only` | Build APK only |
| `--aab-only` | Build AAB only |
| `--skip-tests` | Skip tests |

### build-web.sh

Web assets builder.

| Flag | Description |
|------|-------------|
| `--skip-tests` | Skip TypeScript tests |
