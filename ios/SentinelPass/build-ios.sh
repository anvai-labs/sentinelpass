#!/bin/bash
# Build SentinelPass iOS app for simulator
# This script works around SPM's macOS default by using Xcode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building SentinelPass for iOS Simulator..."
echo ""
echo "NOTE: Swift Package Manager defaults to macOS."
echo "For iOS development, use Xcode directly:"
echo ""
echo "  cd ios/SentinelPass"
echo "  open Package.swift"
echo ""
echo "Then in Xcode:"
echo "  1. Select 'SentinelPassApp' scheme"
echo "  2. Select destination: 'Any iOS Simulator (arm64)'"
echo "  3. Press ⌘+B to build"
echo ""
echo "The built app will be in .build/debug/"
echo ""

# Alternative: Try to build with SDK override
echo "📱 Attempting build with iOS Simulator SDK..."

# Get the iOS Simulator SDK path
IOS_SIM_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)

if [ -z "$IOS_SIM_SDK" ]; then
    echo "❌ iOS Simulator SDK not found"
    echo "   Please use Xcode to build (see instructions above)"
    exit 1
fi

echo "Using SDK: $IOS_SIM_SDK"

# Note: This still won't work perfectly due to SPM limitations
# The recommended way is to use Xcode directly
echo ""
echo "⚠️  Command-line SPM has limited iOS support."
echo "   Please use Xcode for iOS builds."
