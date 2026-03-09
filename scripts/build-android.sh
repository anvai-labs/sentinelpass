#!/bin/bash
# SentinelPass Android Build Script
# Builds Android APK and AAB for all architectures

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Parse arguments
BUILD_TYPE="release"
BUILD_DIR="$PROJECT_ROOT/build/android"
BUILD_APK="true"
BUILD_AAB="true"
SKIP_TESTS="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            BUILD_TYPE="debug"
            shift
            ;;
        --release)
            BUILD_TYPE="release"
            shift
            ;;
        --apk-only)
            BUILD_AAB="false"
            shift
            ;;
        --aab-only)
            BUILD_APK="false"
            shift
            ;;
        --skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--debug|--release] [--apk-only|--aab-only] [--skip-tests]"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

# ============================================================================
# Check Android Environment
# ============================================================================

if [ ! -d "android/SentinelPass" ]; then
    log_error "Android project not found at android/SentinelPass"
    exit 1
fi

# Check for ANDROID_SDK_ROOT
if [ -z "$ANDROID_SDK_ROOT" ] && [ -z "$ANDROID_HOME" ]; then
    log_warning "ANDROID_SDK_ROOT not set. Using default Android SDK location."
fi

# ============================================================================
# Build Mobile Bridge (Rust)
# ============================================================================

log_info "Building Rust mobile bridge for Android..."

ANDROID_TARGETS=(
    "aarch64-linux-android"     # ARM64
    "armv7-linux-androideabi"   # ARM32
    "x86_64-linux-android"      # x86_64
)

# Set cargo flags
CARGO_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

for target in "${ANDROID_TARGETS[@]}"; do
    if rustc --print target-list | grep -q "^$target\$"; then
        log_info "Building for $target..."
        cargo build --package sentinelpass-mobile-bridge \
            --target "$target" \
            $CARGO_FLAGS
    else
        log_warning "Target $target not available, skipping"
    fi
done

log_success "Mobile bridge built"

# ============================================================================
# Prepare JNI Libraries
# ============================================================================

log_info "Preparing JNI libraries..."

ANDROID_DIR="$PROJECT_ROOT/android/SentinelPass"
JNI_LIBS_DIR="$ANDROID_DIR/app/src/main/jniLibs"

# Create ABI directories
mkdir -p "$JNI_LIBS_DIR/arm64-v8a"
mkdir -p "$JNI_LIBS_DIR/armeabi-v7a"
mkdir -p "$JNI_LIBS_DIR/x86_64"

# Copy libraries to correct ABI directories
cp "target/aarch64-linux-android/$BUILD_TYPE/libsentinelpass_mobile_bridge_android.so" \
   "$JNI_LIBS_DIR/arm64-v8a/" 2>/dev/null || log_warning "ARM64 library not found"

cp "target/armv7-linux-androideabi/$BUILD_TYPE/libsentinelpass_mobile_bridge_android.so" \
   "$JNI_LIBS_DIR/armeabi-v7a/" 2>/dev/null || log_warning "ARMv7 library not found"

cp "target/x86_64-linux-android/$BUILD_TYPE/libsentinelpass_mobile_bridge_android.so" \
   "$JNI_LIBS_DIR/x86_64/" 2>/dev/null || log_warning "x86_64 library not found"

log_success "JNI libraries prepared"

# ============================================================================
# Run Tests
# ============================================================================

if [ "$SKIP_TESTS" = "false" ]; then
    log_info "Running mobile bridge tests..."
    cargo test --package sentinelpass-mobile-bridge
    log_success "Tests passed"
fi

# ============================================================================
# Build Android App with Gradle
# ============================================================================

log_info "Building Android app with Gradle..."

cd "$ANDROID_DIR"

# Build output directory
mkdir -p "$BUILD_DIR"

# Determine Gradle task
BUILD_CONFIG=$(echo "$BUILD_TYPE" | sed 's/debug/debug/' | sed 's/release/release/')

# Build APK
if [ "$BUILD_APK" = "true" ]; then
    log_info "Building APK..."

    if [ "$BUILD_TYPE" = "release" ]; then
        # Release build requires signing
        if [ -f "keystore.properties" ]; then
            ./gradlew assembleRelease
            find app/build/outputs/apk -name "*.apk" -exec cp {} "$BUILD_DIR/" \;
            log_success "Release APK built"
        else
            log_warning "Release build requires keystore.properties"
            log_info "Building debug APK instead..."
            ./gradlew assembleDebug
            find app/build/outputs/apk -name "*.apk" -exec cp {} "$BUILD_DIR/" \;
            log_success "Debug APK built"
        fi
    else
        ./gradlew assembleDebug
        find app/build/outputs/apk -name "*.apk" -exec cp {} "$BUILD_DIR/" \;
        log_success "Debug APK built"
    fi
fi

# Build AAB (for Play Store)
if [ "$BUILD_AAB" = "true" ]; then
    log_info "Building AAB (Android App Bundle)..."

    if [ "$BUILD_TYPE" = "release" ]; then
        if [ -f "keystore.properties" ]; then
            ./gradlew bundleRelease
            find app/build/outputs/bundle -name "*.aab" -exec cp {} "$BUILD_DIR/" \;
            log_success "Release AAB built"
        else
            log_warning "Release build requires keystore.properties"
            log_info "Skipping AAB build"
        fi
    else
        log_info "AAB is only for release builds, skipping"
    fi
fi

cd "$PROJECT_ROOT"

log_success "Android build complete"
log_info "Build artifacts: $BUILD_DIR"
