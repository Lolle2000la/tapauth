#!/bin/bash

# Script to build TapAuth shared library for Android targets
# Requires: cargo, cargo-ndk, Android NDK

set -e

echo "Building TapAuth shared library for Android..."

# Change to shared library directory
cd "$(dirname "$0")/../shared"

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
mkdir -p server-android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

echo "Copying libraries..."
cp target/aarch64-linux-android/release/libshared.so server-android/app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libshared.so server-android/app/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libshared.so server-android/app/src/main/jniLibs/x86_64/
cp target/i686-linux-android/release/libshared.so server-android/app/src/main/jniLibs/x86/

echo "✓ Build complete! Libraries copied to jniLibs/"
echo ""
echo "Library locations:"
echo "  - arm64-v8a: server-android/app/src/main/jniLibs/arm64-v8a/libshared.so"
echo "  - armeabi-v7a: server-android/app/src/main/jniLibs/armeabi-v7a/libshared.so"
echo "  - x86_64: server-android/app/src/main/jniLibs/x86_64/libshared.so"
echo "  - x86: server-android/app/src/main/jniLibs/x86/libshared.so"
