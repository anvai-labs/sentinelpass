#!/bin/bash
# Android environment variables for SentinelPass
# Source this file before building: source scripts/android-env.sh

export ANDROID_SDK_ROOT="/Users/vijaysingh/Library/Android/sdk"
export ANDROID_HOME="/Users/vijaysingh/Library/Android/sdk"
export ANDROID_NDK_ROOT="/Users/vijaysingh/Library/Android/sdk/ndk/29.0.14206865"
export ANDROID_NDK_PATH="$ANDROID_NDK_ROOT"

# Add Android tools to PATH
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/build-tools/34.0.0:$PATH"

# NDK toolchain paths (for C/C++ compilers)
export NDK_TOOLCHAIN_DIR="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64"

# Rust/Cargo Android build environment
export CC_aarch64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android34-clang"
export AR_aarch64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"

export CC_armv7_linux_androideabi="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi34-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDBROIDEABI_LINKER="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7-linux-androideabi34-clang"
export AR_armv7_linux_androideabi="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
export CARGO_TARGET_ARMV7_LINUX_ANDBROIDEABI_AR="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"

export CC_x86_64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android34-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android34-clang"
export AR_x86_64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_AR="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"

echo "Android environment configured:"
echo "  SDK: $ANDROID_SDK_ROOT"
echo "  NDK: $ANDROID_NDK_ROOT"
echo ""
echo "To build Android:"
echo "  ./scripts/build-android.sh"
