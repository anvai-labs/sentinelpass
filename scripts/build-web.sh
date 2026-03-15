#!/bin/bash
# SentinelPass Web Build Script
# Builds browser extensions and web assets

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
SKIP_TESTS="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--skip-tests]"
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
# Check Node.js
# ============================================================================

if ! command -v node >/dev/null 2>&1; then
    log_error "Node.js not found. Please install Node.js 20+"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    log_warning "Node.js version 20+ recommended (current: $(node -v))"
fi

# ============================================================================
# Install Dependencies
# ============================================================================

log_info "Installing dependencies..."

if [ ! -d "node_modules" ]; then
    npm ci
fi

log_success "Dependencies installed"

# ============================================================================
# Type Check
# ============================================================================

log_info "Type checking TypeScript sources..."
npm run web:typecheck

log_success "Type check passed"

# ============================================================================
# Build Web Assets
# ============================================================================

log_info "Building web assets..."

# Build UI and extensions
npm run web:build

log_success "Web assets built"

# ============================================================================
# Run Tests
# ============================================================================

if [ "$SKIP_TESTS" = "false" ]; then
    log_info "Running TypeScript tests..."

    npm run test:ts

    log_success "Tests passed"
fi

# ============================================================================
# Browser Extension Builds
# ============================================================================

log_info "Building browser extensions..."

# Chrome Extension
log_info "Building Chrome extension..."
cd browser-extension/chrome
if [ -f "package.json" ]; then
    npm install
    npm run build
fi
cd "$PROJECT_ROOT"

# Firefox Extension
log_info "Building Firefox extension..."
cd browser-extension/firefox
if [ -f "package.json" ]; then
    npm install
    npm run build
fi
cd "$PROJECT_ROOT"

log_success "Browser extensions built"

# ============================================================================
# Output Build Summary
# ============================================================================

log_success "Web build complete"

log_info "Build artifacts:"
echo "  - sentinelpass-ui/dist/"
echo "  - browser-extension/chrome/dist/"
echo "  - browser-extension/firefox/dist/"
