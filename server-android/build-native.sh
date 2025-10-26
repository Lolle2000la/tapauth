#!/bin/bash

# Script to build TapAuth shared library for Android targets
# Requires: cargo, cargo-ndk, Android NDK

set -e

echo "Building TapAuth shared library for Android..."

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SHARED_DIR="$PROJECT_ROOT/shared"
JNILIBS_DIR="$PROJECT_ROOT/server-android/app/src/main/jniLibs"

# Change to shared library directory
cd "$SHARED_DIR"

# Check if cargo-ndk is installed
if ! command -v cargo-ndk &> /dev/null; then
    echo "cargo-ndk not found. Installing..."
    cargo install cargo-ndk
fi

# Build for Android targets
TARGETS=("aarch64-linux-android" "armv7-linux-androideabi" "x86_64-linux-android" "i686-linux-android")

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo ndk --target $target --platform 24 build --release --features jni
done

echo "Creating jniLibs directory structure..."
mkdir -p "$JNILIBS_DIR"/{arm64-v8a,armeabi-v7a,x86_64,x86}

echo "Copying libraries..."
# With workspace, build output is at root target directory
cp "$PROJECT_ROOT/target/aarch64-linux-android/release/libshared.so" "$JNILIBS_DIR/arm64-v8a/"
cp "$PROJECT_ROOT/target/armv7-linux-androideabi/release/libshared.so" "$JNILIBS_DIR/armeabi-v7a/"
cp "$PROJECT_ROOT/target/x86_64-linux-android/release/libshared.so" "$JNILIBS_DIR/x86_64/"
cp "$PROJECT_ROOT/target/i686-linux-android/release/libshared.so" "$JNILIBS_DIR/x86/"

echo "✓ Build complete! Libraries copied to jniLibs/"
echo ""
echo "Library locations:"
echo "  - arm64-v8a: $JNILIBS_DIR/arm64-v8a/libshared.so"
echo "  - armeabi-v7a: $JNILIBS_DIR/armeabi-v7a/libshared.so"
echo "  - x86_64: $JNILIBS_DIR/x86_64/libshared.so"
echo "  - x86: $JNILIBS_DIR/x86/libshared.so"
