#!/bin/bash
# SentinelPass iOS setup: build the Rust bridge for the iOS targets, assemble
# the script-generated static libraries, and open the pre-made Xcode project.
#
# There is nothing to "create" anymore: ios/SentinelPass/SentinelPassApp.xcodeproj
# is the single Xcode project (app target SentinelPassApp + credential-provider
# extension target SentinelPassCredential). CloudKit and the old manual
# SentinelPassBridge/ folder are removed (ADR-009 / WBS-807) — do not recreate them.

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$PROJECT_ROOT/ios/SentinelPass"

echo "=== SentinelPass iOS Setup ==="
echo ""

# 1. Build the bridge and populate ios/SentinelPass/SentinelPass/Native/libs/
echo "1. Building mobile bridge for iOS (simulator + device)..."
ONLY_SIM=1 "$IOS_DIR/build-ios.sh"
echo "   (Simulator build done. Re-run '$IOS_DIR/build-ios.sh' without"
echo "    ONLY_SIM to also build the device library.)"
echo ""

# 2. Check Xcode
echo "2. Checking Xcode..."
if command -v xcodebuild &> /dev/null; then
    XCODE_VERSION=$(xcodebuild -version | head -1)
    echo "   ✓ Xcode found: $XCODE_VERSION"
else
    echo "   ✗ Xcode not found. Install from App Store."
    exit 1
fi
echo ""

# 3. Verify with a command-line build before opening Xcode
echo "3. Verifying the project builds for the simulator..."
SIM="$(xcrun simctl list devices available | awk -F'[()]' '/iPhone/ {print $2; exit}')"
if [ -n "$SIM" ]; then
    xcodebuild -project "$IOS_DIR/SentinelPassApp.xcodeproj" \
        -scheme SentinelPassApp \
        -sdk iphonesimulator \
        -destination "platform=iOS Simulator,name=$SIM" \
        build CODE_SIGNING_ALLOWED=NO -quiet \
        && echo "   ✓ SentinelPassApp builds for iOS Simulator ($SIM)"
else
    echo "   ⚠ No iPhone simulator found; skipping verification build."
    echo "     Run xcodebuild manually with an available destination."
fi
echo ""

# 4. Open the project
echo "4. Opening the project..."
open "$IOS_DIR/SentinelPassApp.xcodeproj"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Schemes:"
echo "  - SentinelPassApp          main SwiftUI app (com.sentinelpass.app)"
echo "  - SentinelPassCredential   iOS 17 credential-provider extension"
echo "                             (com.sentinelpass.app.credential-provider)"
echo ""
echo "Signing: entitlements (App Group group.com.sentinelpass) are declarative"
echo "in the repo; device provisioning with your own team is a user/CI concern"
echo "(set DEVELOPMENT_TEAM, then let Xcode manage signing)."
