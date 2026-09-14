#!/bin/bash
# Password Manager Installation Script for macOS and Linux

set -e

BINARY_DIR_OVERRIDE="${SENTINELPASS_BINARY_DIR:-}"
FROM_APP_BUNDLE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --binary-dir" >&2
                exit 1
            fi
            BINARY_DIR_OVERRIDE="$2"
            shift 2
            ;;
        --from-app-bundle)
            FROM_APP_BUNDLE=true
            shift
            ;;
        *)
            echo "Unknown option for installation/install.sh: $1" >&2
            exit 1
            ;;
    esac
done

# Detect platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    INSTALL_DIR="$HOME/Library/Application Support/SentinelPass"
    CHROME_PREFS_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    CHROME_FLAGS_DIR="$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
    FIREFOX_NATIVE_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
else
    PLATFORM="linux"
    INSTALL_DIR="$HOME/.local/share/sentinelpass"
    CHROME_PREFS_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    CHROME_FLAGS_DIR="$HOME/.config/chromium/NativeMessagingHosts"
    FIREFOX_NATIVE_DIR="$HOME/.mozilla/native-messaging-hosts"
fi

NATIVE_HOST_NAME="com.passwordmanager.host"
CHROME_MANIFEST_FILE="$NATIVE_HOST_NAME.json"
FIREFOX_MANIFEST_FILE="$NATIVE_HOST_NAME.firefox.json"
CHROME_EXTENSION_ID="${SENTINELPASS_CHROME_EXTENSION_ID:-nophfgfiiohedlodfeepjoioljbhggdd}"

echo "Installing SentinelPass for $PLATFORM..."

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Resolve binary directory
if [[ "$FROM_APP_BUNDLE" == true ]]; then
    if [[ "$PLATFORM" == "macos" ]]; then
        BINARY_DIR="/Applications/SentinelPass.app/Contents/Resources/src-tauri/resources/bin"
    else
        # Linux: typical install locations for Tauri bundles
        for candidate in \
            "/usr/lib/sentinelpass/resources/bin" \
            "/opt/sentinelpass/resources/bin" \
            "/usr/share/sentinelpass/resources/bin"; do
            if [[ -d "$candidate" ]]; then
                BINARY_DIR="$candidate"
                break
            fi
        done
        if [[ -z "${BINARY_DIR:-}" ]]; then
            echo "Could not locate app bundle binaries. Use --binary-dir instead." >&2
            exit 1
        fi
    fi
    echo "Resolving binaries from app bundle: $BINARY_DIR"
else
    BINARY_DIR="${BINARY_DIR_OVERRIDE:-$PROJECT_ROOT/target/release}"
fi

# Check if binaries are built
if [[ ! -d "$BINARY_DIR" ]]; then
    echo "Binary directory not found. Please run 'cargo build --release' first."
    exit 1
fi

# Check if binaries exist
if [[ ! -f "$BINARY_DIR/sentinelpass-host" ]] && [[ ! -f "$BINARY_DIR/sentinelpass-host.exe" ]]; then
    echo "sentinelpass-host binary not found in $BINARY_DIR"
    echo "Please run 'cargo build --release' first."
    exit 1
fi

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy binaries (handle both Windows .exe and Unix binaries)
echo "Copying binaries..."
if [[ -f "$BINARY_DIR/sentinelpass-host" ]]; then
    cp "$BINARY_DIR/sentinelpass-host" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-host"
else
    cp "$BINARY_DIR/sentinelpass-host.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass-daemon" ]]; then
    cp "$BINARY_DIR/sentinelpass-daemon" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-daemon"
else
    cp "$BINARY_DIR/sentinelpass-daemon.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass-ui" ]]; then
    cp "$BINARY_DIR/sentinelpass-ui" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass-ui"
else
    cp "$BINARY_DIR/sentinelpass-ui.exe" "$INSTALL_DIR/"
fi

if [[ -f "$BINARY_DIR/sentinelpass" ]]; then
    cp "$BINARY_DIR/sentinelpass" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/sentinelpass"
elif [[ -f "$BINARY_DIR/sentinelpass.exe" ]]; then
    cp "$BINARY_DIR/sentinelpass.exe" "$INSTALL_DIR/"
fi

# Deploy the Chrome extension to a stable path inside the installation dir.
# Chrome never auto-updates unpacked extensions, but it re-reads the folder
# on reload/restart — so an in-place replacement here turns every future
# upgrade into a single reload click (same folder = same entry = same ID,
# which the native-host manifest's allowed_origins already pins).
EXT_SRC="$PROJECT_ROOT/browser-extension/chrome"
if [[ -f "$EXT_SRC/manifest.json" ]]; then
    EXT_VERSION="$(sed -n 's/.*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$EXT_SRC/manifest.json" | head -1)"
    echo "Deploying Chrome extension v${EXT_VERSION:-?} to: $INSTALL_DIR/chrome-extension"
    rm -rf "$INSTALL_DIR/chrome-extension"
    cp -R "$EXT_SRC" "$INSTALL_DIR/chrome-extension"
else
    echo "Chrome extension sources not found at $EXT_SRC — skipping extension deployment."
fi

# Generate native messaging host manifest
echo "Installing native messaging host manifest..."

# Determine the binary path
if [[ -f "$INSTALL_DIR/sentinelpass-host" ]]; then
    BINARY_PATH="$INSTALL_DIR/sentinelpass-host"
else
    BINARY_PATH="$INSTALL_DIR/sentinelpass-host.exe"
fi

# Create Chrome/Chromium manifest JSON
cat > "$INSTALL_DIR/$CHROME_MANIFEST_FILE" << EOF
{
  "name": "com.passwordmanager.host",
  "description": "SentinelPass Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$CHROME_EXTENSION_ID/"
  ]
}
EOF

# Create Firefox manifest JSON
cat > "$INSTALL_DIR/$FIREFOX_MANIFEST_FILE" << EOF
{
  "name": "com.passwordmanager.host",
  "description": "SentinelPass Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "sentinelpass@localhost"
  ]
}
EOF

# Create native messaging host directories
mkdir -p "$CHROME_PREFS_DIR"
mkdir -p "$CHROME_FLAGS_DIR"
mkdir -p "$FIREFOX_NATIVE_DIR"

# Create symlinks to manifest
ln -sf "$INSTALL_DIR/$CHROME_MANIFEST_FILE" "$CHROME_PREFS_DIR/$NATIVE_HOST_NAME.json"
ln -sf "$INSTALL_DIR/$CHROME_MANIFEST_FILE" "$CHROME_FLAGS_DIR/$NATIVE_HOST_NAME.json"
ln -sf "$INSTALL_DIR/$FIREFOX_MANIFEST_FILE" "$FIREFOX_NATIVE_DIR/$NATIVE_HOST_NAME.json"

echo "Native messaging host registered for Chrome, Chromium, and Firefox"

echo "Chrome extension ID used: $CHROME_EXTENSION_ID"

# Add to PATH (if not already there)
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    SHELL_CONFIG=""
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        SHELL_CONFIG="$HOME/.bashrc"
    fi

    if [[ -n "$SHELL_CONFIG" ]]; then
        echo "" >> "$SHELL_CONFIG"
        echo "# SentinelPass" >> "$SHELL_CONFIG"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_CONFIG"
        echo "Added $INSTALL_DIR to PATH in $SHELL_CONFIG"
        echo "Run 'source $SHELL_CONFIG' or restart your shell to use the new PATH"
    fi
fi

echo ""
echo "Installation completed successfully!"
echo ""
echo "Next steps:"
if [[ -d "$INSTALL_DIR/chrome-extension" ]]; then
    echo "1. Chrome extension deployed to: $INSTALL_DIR/chrome-extension"
    echo "   - First install: chrome://extensions -> Load unpacked -> that folder"
    echo "   - Upgrade: click the reload icon on the existing SentinelPass card"
else
    echo "1. Load the browser extension from browser-extension/chrome"
fi
echo "2. (Optional) Load Firefox extension from browser-extension/firefox/manifest.json"
echo "3. Run 'sentinelpass init' to create a new vault"
echo "4. Start the UI: sentinelpass-ui"
echo "5. Use the browser extension to autofill passwords"
