# Password Manager Development Commands

default:
    @just --list

# Build all workspace members
build:
    cargo build --release

# Run tests
test:
    cargo test --workspace

# Run tests with output
test-verbose:
    cargo test --workspace -- --nocapture

# Run Clippy
clippy:
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run integration tests
integration-test:
    cargo test --workspace --test '*'

# Run security tests
security-test:
    cargo test --workspace security

# Clean build artifacts
clean:
    cargo clean

# Initialize development database
init-db:
    cargo run --bin sentinelpass -- init --dev

# Run daemon in development
daemon:
    cargo run --bin sentinelpass-daemon

# Run CLI
cli:
    cargo run --bin sentinelpass --

# Install native messaging host (Windows)
install-host-windows:
    powershell -ExecutionPolicy Bypass -File installation/install.ps1

# Install native messaging host (Unix)
install-host-unix:
    bash installation/install.sh

# Build browser extension
build-extension:
    @echo "Extension is ready to load unpacked from browser-extension/chrome/"

# Run all linters
lint: clippy fmt-check

# Full CI pipeline
ci: lint test
