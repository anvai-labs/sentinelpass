#!/bin/bash
# SentinelPass - Universal Build Script
# Builds all platforms: Desktop, Mobile, and Web

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Parse arguments
PLATFORMS=""
BUILD_TYPE="release"
SKIP_TESTS="false"
SKIP_WEB="false"
SKIP_DESKTOP="false"
SKIP_MOBILE="false"
HELP="false"

print_usage() {
    cat << EOF
${BLUE}SentinelPass Universal Build Script${NC}

Usage: $0 [OPTIONS]

Builds all platforms for SentinelPass:
  - Desktop: macOS, Linux, Windows (CLI, Daemon, Host, Tauri UI)
  - Mobile: iOS (via Xcode), Android (via Gradle)
  - Web: Browser extension (Chrome/Firefox)

OPTIONS:
  -p, --platform PLATFORM    Build specific platform(s): all|desktop|mobile|web
                              (default: all)
  -t, --type TYPE             Build type: debug|release (default: release)
  --skip-tests                Skip running tests
  --skip-web                  Skip web build
  --skip-desktop              Skip desktop build
  --skip-mobile               Skip mobile build
  -h, --help                  Show this help message

EXAMPLES:
  $0                          # Build all platforms (release)
  $0 -p desktop               # Build only desktop platforms
  $0 -t debug --skip-tests    # Debug build without tests
  $0 -p mobile --skip-web     # Build only mobile platforms

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--platform)
            PLATFORMS="$2"
            shift 2
            ;;
        -t|--type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        --skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        --skip-web)
            SKIP_WEB="true"
            shift
            ;;
        --skip-desktop)
            SKIP_DESKTOP="true"
            shift
            ;;
        --skip-mobile)
            SKIP_MOBILE="true"
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Default to all platforms if none specified
if [ -z "$PLATFORMS" ]; then
    PLATFORMS="all"
fi

# Change to project root
cd "$PROJECT_ROOT"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# Build Desktop Platforms
# ============================================================================

build_desktop() {
    log_info "Building desktop platforms..."

    if [ "$BUILD_TYPE" = "release" ]; then
        CARGO_FLAGS="--release"
    else
        CARGO_FLAGS=""
    fi

    # Build Rust binaries
    log_info "Building Rust binaries (CLI, Daemon, Host, UI)..."
    cargo build $CARGO_FLAGS \
        --bin sentinelpass \
        --bin sentinelpass-daemon \
        --bin sentinelpass-host \
        --bin sentinelpass-ui

    log_success "Desktop build complete"

    # Run tests if not skipped
    if [ "$SKIP_TESTS" = "false" ]; then
        log_info "Running desktop tests..."
        cargo test --workspace
        log_success "Desktop tests passed"
    fi
}

# ============================================================================
# Build Mobile Platforms
# ============================================================================

build_mobile() {
    log_info "Building mobile platforms..."

    # Build iOS
    if command_exists xcodebuild; then
        log_info "Building iOS app..."
        "$SCRIPT_DIR/build-ios.sh" $([ "$BUILD_TYPE" = "release" ] && echo "--release" || echo "--debug")
        log_success "iOS build complete"
    else
        log_warning "Xcode not found, skipping iOS build"
    fi

    # Build Android
    if [ -d "android/SentinelPass" ] && command_exists gradle; then
        log_info "Building Android app..."
        "$SCRIPT_DIR/build-android.sh" $([ "$BUILD_TYPE" = "release" ] && echo "--release" || echo "--debug")
        log_success "Android build complete"
    else
        log_warning "Android SDK/Gradle not found, skipping Android build"
    fi
}

# ============================================================================
# Build Web Platforms
# ============================================================================

build_web() {
    log_info "Building web platforms..."

    # Check if Node.js is installed
    if ! command_exists node; then
        log_error "Node.js not found. Please install Node.js to build web assets."
        return 1
    fi

    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        log_info "Installing Node.js dependencies..."
        npm install
    fi

    # Build web assets
    log_info "Building web assets..."
    npm run web:build
    log_success "Web build complete"

    # Run TypeScript tests if not skipped
    if [ "$SKIP_TESTS" = "false" ]; then
        log_info "Running TypeScript tests..."
        npm run test:ts
        log_success "TypeScript tests passed"
    fi
}

# ============================================================================
# Main Build Flow
# ============================================================================

main() {
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  SentinelPass Universal Build${NC}"
    echo -e "${BLUE}  Platforms: $PLATFORMS${NC}"
    echo -e "${BLUE}  Build Type: $BUILD_TYPE${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo ""

    START_TIME=$(date +%s)

    # Build based on platform selection
    case $PLATFORMS in
        all)
            if [ "$SKIP_DESKTOP" = "false" ]; then
                build_desktop
            fi
            if [ "$SKIP_MOBILE" = "false" ]; then
                build_mobile
            fi
            if [ "$SKIP_WEB" = "false" ]; then
                build_web
            fi
            ;;
        desktop)
            build_desktop
            ;;
        mobile)
            build_mobile
            ;;
        web)
            build_web
            ;;
        *)
            log_error "Unknown platform: $PLATFORMS"
            log_info "Valid platforms: all, desktop, mobile, web"
            exit 1
            ;;
    esac

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    log_success "Build completed in ${DURATION}s"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
}

# Run main
main
