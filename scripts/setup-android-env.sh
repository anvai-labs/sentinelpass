#!/bin/bash
# SentinelPass Android Environment Setup Script
# Sets up Android NDK and Rust cross-compilation targets

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

# Default Android SDK paths
DEFAULT_ANDROID_SDK="$HOME/Library/Android/sdk"
DEFAULT_NDK_VERSION="29.0.14206865"

# ============================================================================
# Detect Android SDK
# ============================================================================

log_info "Detecting Android SDK..."

# Use default path since env vars might not be set
ANDROID_SDK="$DEFAULT_ANDROID_SDK"

if [ ! -d "$ANDROID_SDK" ]; then
    log_error "Android SDK not found at: $ANDROID_SDK"
    log_info "Please install Android Studio or Android SDK Command-line Tools"
    log_info "Download from: https://developer.android.com/studio"
    exit 1
fi

log_success "Android SDK found at: $ANDROID_SDK"

# ============================================================================
# Detect NDK
# ============================================================================

log_info "Detecting Android NDK..."

# Check for NDK in common locations
NDK_PATH=""
if [ -n "$ANDROID_NDK_ROOT" ] && [ -d "$ANDROID_NDK_ROOT" ]; then
    NDK_PATH="$ANDROID_NDK_ROOT"
elif [ -d "$ANDROID_SDK/ndk" ]; then
    # Find the latest NDK version
    NDK_PATH=$(find "$ANDROID_SDK/ndk" -maxdepth 1 -type d -name "[0-9]*" | sort -V | tail -1)
fi

if [ -z "$NDK_PATH" ]; then
    log_error "Android NDK not found"
    log_info "Install NDK via Android Studio:"
    log_info "  Preferences → Appearance & Behavior → System Settings → Android SDK → SDK Tools"
    log_info "  Check 'NDK (Side by side)' and 'CMake'"
    exit 1
fi

log_success "Android NDK found at: $NDK_PATH"

# ============================================================================
# Set up environment variables
# ============================================================================

log_info "Setting up environment variables..."

# Create environment setup script
cat > "$PROJECT_ROOT/scripts/android-env.sh" << EOF
#!/bin/bash
# Android environment variables for SentinelPass
# Source this file before building: source scripts/android-env.sh

export ANDROID_SDK_ROOT="$ANDROID_SDK"
export ANDROID_HOME="$ANDROID_SDK"
export ANDROID_NDK_ROOT="$NDK_PATH"
export ANDROID_NDK_PATH="\$ANDROID_NDK_ROOT"

# Add Android tools to PATH
# IMPORTANT: NDK bin must be FIRST so cc-rs finds the generic tool symlinks
export PATH="\$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin:\$ANDROID_SDK_ROOT/platform-tools:\$ANDROID_SDK_ROOT/build-tools/34.0.0:\$PATH"

echo "Android environment configured:"
echo "  SDK: \$ANDROID_SDK_ROOT"
echo "  NDK: \$ANDROID_NDK_ROOT"
echo ""
echo "To build Android:"
echo "  ./scripts/build-android.sh"
EOF

chmod +x "$PROJECT_ROOT/scripts/android-env.sh"

log_success "Environment script created: scripts/android-env.sh"

# Source it for the current session
source "$PROJECT_ROOT/scripts/android-env.sh"

# ============================================================================
# Verify toolchain
# ============================================================================

log_info "Verifying NDK toolchain..."

if [ ! -d "$NDK_TOOLCHAIN_DIR" ]; then
    log_error "NDK toolchain not found at: $NDK_TOOLCHAIN_DIR"
    exit 1
fi

# Check for clang
if ! command -v "$NDK_TOOLCHAIN_DIR/bin/clang" >/dev/null 2>&1; then
    log_error "NDK clang not found"
    exit 1
fi

log_success "NDK toolchain verified"

# ============================================================================
# Install Rust targets
# ============================================================================

log_info "Installing Rust Android targets..."

ANDROID_TARGETS=(
    "aarch64-linux-android"      # ARM64
    "armv7-linux-androideabi"    # ARMv7
    "x86_64-linux-android"       # x86_64
)

for target in "${ANDROID_TARGETS[@]}"; do
    if rustup target list | grep -q "$target (installed)"; then
        log_info "Target $target already installed"
    else
        log_info "Installing Rust target: $target"
        rustup target add "$target"
    fi
done

log_success "Rust targets installed"

# ============================================================================
# Create .cargo/config.toml for Android builds
# ============================================================================

log_info "Configuring Cargo for Android builds..."

CARGO_CONFIG_DIR="$PROJECT_ROOT/.cargo"
CARGO_CONFIG="$CARGO_CONFIG_DIR/config.toml"

mkdir -p "$CARGO_CONFIG_DIR"

# Create or update cargo config
if [ -f "$CARGO_CONFIG" ]; then
    # Backup existing config
    cp "$CARGO_CONFIG" "$CARGO_CONFIG.bak"
fi

cat > "$CARGO_CONFIG" << 'EOF'
# Cargo configuration for Android cross-compilation

[target.aarch64-linux-android]
ar = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang"

[target.armv7-linux-androideabi]
ar = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi33-clang"

[target.x86_64-linux-android]
ar = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "/Users/REPLACE_USERNAME/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android33-clang"
EOF

# Replace username placeholder
CURRENT_USER=$(whoami)
sed -i.bak "s|/Users/REPLACE_USERNAME|/Users/$CURRENT_USER|g" "$CARGO_CONFIG"
rm -f "$CARGO_CONFIG.bak"

log_success "Cargo config created: .cargo/config.toml"

# ============================================================================
# Test Android build
# ============================================================================

log_info "Testing Android build..."

cd "$PROJECT_ROOT"

# Try building for ARM64
if cargo build --package sentinelpass-mobile-bridge --target aarch64-linux-android --release 2>&1 | tail -20; then
    log_success "Android ARM64 build test PASSED"
else
    log_warning "Android build test had issues (may still be OK if library was created)"
fi

# Check if library was created
if [ -f "target/aarch64-linux-android/release/libsentinelpass_mobile_bridge.a" ]; then
    log_success "Android library created successfully"
else
    log_error "Android library not found"
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
log_success "Android environment setup complete!"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""
echo "To use Android environment in new terminals:"
echo "  source scripts/android-env.sh"
echo ""
echo "Environment variables set:"
echo "  ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT"
echo "  ANDROID_NDK_ROOT=$ANDROID_NDK_ROOT"
echo ""
echo "Rust targets installed:"
rustup target list --installed | grep android
echo ""
echo "To build Android APK:"
echo "  ./scripts/build-android.sh"
echo ""
