#!/bin/bash
# SentinelPass Desktop Build Script
# Builds desktop applications for macOS, Linux, and Windows

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
PLATFORM="all"
SKIP_TESTS="false"
BUILD_INSTALLERS="false"

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
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        --skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        --installers)
            BUILD_INSTALLERS="true"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--debug|--release] [--platform all|current|macos|linux|windows] [--skip-tests] [--installers]"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

cd "$PROJECT_ROOT"

# Detect current platform
CURRENT_OS="$(uname -s)"
case "$CURRENT_OS" in
    Darwin)
        CURRENT_PLATFORM="macos"
        ;;
    Linux)
        CURRENT_PLATFORM="linux"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        CURRENT_PLATFORM="windows"
        ;;
    *)
        log_error "Unknown OS: $CURRENT_OS"
        exit 1
        ;;
esac

# ============================================================================
# Build Binaries
# ============================================================================

log_info "Building SentinelPass desktop..."

BUILD_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    BUILD_FLAGS="--release"
fi

# Determine targets based on platform
TARGETS=""
case $PLATFORM in
    all)
        case "$CURRENT_PLATFORM" in
            macos)
                TARGETS="x86_64-apple-darwin aarch64-apple-darwin"
                ;;
            linux)
                TARGETS="x86_64-unknown-linux-gnu"
                ;;
            windows)
                TARGETS="x86_64-pc-windows-msvc"
                ;;
        esac
        ;;
    current)
        # Use default target
        TARGETS=""
        ;;
    macos|linux|windows)
        log_error "Cross-compilation not supported in this script"
        log_info "Use CI/CD or build on the target platform"
        exit 1
        ;;
    *)
        log_error "Unknown platform: $PLATFORM"
        exit 1
        ;;
esac

# Build for each target
if [ -n "$TARGETS" ]; then
    for target in $TARGETS; do
        log_info "Building for $target..."
        rustup target add "$target" >/dev/null 2>&1 || true
        cargo build $BUILD_FLAGS --target "$target" \
            --bin sentinelpass \
            --bin sentinelpass-daemon \
            --bin sentinelpass-host \
            --bin sentinelpass-ui || {
            log_warning "Build for $target failed (may not be supported)"
        }
    done
else
    log_info "Building for $CURRENT_PLATFORM..."
    cargo build $BUILD_FLAGS \
        --bin sentinelpass \
        --bin sentinelpass-daemon \
        --bin sentinelpass-host \
        --bin sentinelpass-ui
fi

log_success "Binaries built"

# ============================================================================
# Run Tests
# ============================================================================

if [ "$SKIP_TESTS" = "false" ]; then
    log_info "Running tests..."
    cargo test --workspace
    log_success "Tests passed"
fi

# ============================================================================
# Build Web Assets (for Tauri UI)
# ============================================================================

if [ -f "package.json" ]; then
    log_info "Building web assets for Tauri UI..."

    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        log_info "Installing Node.js dependencies..."
        npm install
    fi

    # Build web assets
    npm run web:build

    log_success "Web assets built"
fi

# ============================================================================
# Build Native Installers
# ============================================================================

if [ "$BUILD_INSTALLERS" = "true" ]; then
    log_info "Building native installers..."

    if [ -f "$SCRIPT_DIR/build-native-installers.sh" ]; then
        "$SCRIPT_DIR/build-native-installers.sh"
    else
        log_warning "Installer script not found"
    fi

    log_success "Installers built"
fi

# ============================================================================
# Output Build Summary
# ============================================================================

log_success "Desktop build complete"

# Show build artifacts
if [ "$BUILD_TYPE" = "release" ]; then
    BUILD_DIR="target/release"
else
    BUILD_DIR="target/debug"
fi

log_info "Build artifacts:"
echo "  - $BUILD_DIR/sentinelpass"
echo "  - $BUILD_DIR/sentinelpass-daemon"
echo "  - $BUILD_DIR/sentinelpass-host"
echo "  - $BUILD_DIR/sentinelpass-ui"
