# Building the Native Library for Android

The TapAuth Android app uses a shared Rust library via JNI for cryptographic operations.

## Prerequisites

1. **Rust** with Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
   ```

2. **cargo-ndk** for cross-compilation:
   ```bash
   cargo install cargo-ndk
   ```

3. **Android NDK** (usually installed with Android Studio)
   - Make sure `ANDROID_NDK_HOME` environment variable is set
   - Or NDK is in your PATH

## Building

From the `server-android` directory, run:

```bash
./build-native.sh
```

This will:
1. Build the shared library for all Android architectures (arm64-v8a, armeabi-v7a, x86_64, x86)
2. Copy the `.so` files to `app/src/main/jniLibs/`
3. Make them available to the Android app

## Manual Build

If you prefer to build manually:

```bash
cd ../shared

# Build for ARM64 (most modern Android devices)
cargo ndk --target aarch64-linux-android --platform 24 build --release --features jni

# Build for ARMv7 (older 32-bit devices)
cargo ndk --target armv7-linux-androideabi --platform 24 build --release --features jni

# Build for x86_64 (emulators)
cargo ndk --target x86_64-linux-android --platform 24 build --release --features jni

# Build for x86 (older emulators)
cargo ndk --target i686-linux-android --platform 24 build --release --features jni
```

Then copy the libraries:

```bash
# Note: With Cargo workspace, build output is at the root target directory
mkdir -p ../server-android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}
cp ../target/aarch64-linux-android/release/libshared.so ../server-android/app/src/main/jniLibs/arm64-v8a/
cp ../target/armv7-linux-androideabi/release/libshared.so ../server-android/app/src/main/jniLibs/armeabi-v7a/
cp ../target/x86_64-linux-android/release/libshared.so ../server-android/app/src/main/jniLibs/x86_64/
cp ../target/i686-linux-android/release/libshared.so ../server-android/app/src/main/jniLibs/x86/
```

## JNI Functions Available

The `TapAuthCrypto` Kotlin class provides access to these native functions:

- `generateKeypair()`: Generate Ed25519 keypair
- `keyExchange(ourPrivate, theirPublic)`: X25519 Diffie-Hellman
- `getSas(sharedSecret)`: Generate 6-digit Short Authentication String

## Development Without Native Library

During development, you can comment out the calls to native functions and use placeholder implementations. The app will print an error when trying to load the library, but won't crash.

To use placeholder implementations:

1. Comment out the `System.loadLibrary("shared")` call in `TapAuthCrypto.kt`
2. Implement the `external` functions with dummy Kotlin implementations
3. Remember to build the native library before production builds!

## Troubleshooting

### "library "shared" not found"

Make sure you've run `./build-native.sh` and the `.so` files exist in `app/src/main/jniLibs/`.

### "UnsatisfiedLinkError"

Check that:
1. The library was built with the `jni` feature enabled
2. The function names match exactly (JNI name mangling)
3. The library is in the correct architecture folder

### NDK not found

Set your NDK path:
```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.1.8937393  # Adjust version
```

Or in your `~/.bashrc` or `~/.zshrc`.
