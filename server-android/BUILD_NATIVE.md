# Building the Native Library for Android

The TapAuth Android app uses the shared Rust library (`libshared.so`) through JNI for
cryptographic operations.

**There is no `build-native.sh` and nothing to invoke by hand.** The library is built by
Gradle: the `cargo { }` block in `app/build.gradle.kts` (the `net.mullvad.rust-android`
plugin) cross-compiles `shared` for the target ABIs, and `preBuild` depends on the
plugin's `cargoBuild` task, so every assemble / deploy / test task builds it first.

## Prerequisites

1. **Rust** with Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
   ```

2. **Android NDK** (usually installed with Android Studio)
   - `app/build.gradle.kts` reads `ANDROID_NDK_HOME` (then `ANDROID_NDK_ROOT`) when set,
     and otherwise falls back to its pinned `ndkVersion = "30.0.14904198"`
   - `cargo-ndk` is **not** needed: the plugin drives `cargo` directly

## Building

From the `server-android` directory, build only the native libraries:

```bash
./gradlew cargoBuild
```

or just run the task you wanted in the first place (assemble, install, test) — `preBuild`
depends on `cargoBuild`, so the library is already built:

```bash
./gradlew assembleDebug
```

This will:

1. Build the shared library for the ABIs in `nativeTargets` (`arm`, `arm64`, `x86`,
   `x86_64` — or only the ABI Android Studio injects via
   `android.injected.build.abi` when deploying to a device)
2. Copy each `libshared.so` to `app/build/rustJniLibs/android/<abi>/`
3. Leave that directory registered as the app's `jniLibs` source dir, so the libraries
   are packaged into the APK — the module configures no `jniLibs.srcDirs` of its own,
   so the plugin's registration is what the build uses, and `app/src/main/jniLibs/` is
   not read (it does not exist)

The build passes `--features jni` (the UniFFI surface) and uses `../../target` as the
cargo target directory, i.e. the workspace root's `target/`.

## Troubleshooting

### "library "shared" not found"

Run `./gradlew cargoBuild` and check that
`app/build/rustJniLibs/android/<abi>/libshared.so` exists for the ABI of the device or
emulator you are running (an x86_64 emulator needs the `x86_64` one).
`./gradlew cargoBuild --info` shows the cargo invocation.

### "UnsatisfiedLinkError"

Check that:
1. The library was built with the `jni` feature enabled (the Gradle block always passes it)
2. The function names match exactly (JNI name mangling)
3. The library is in the correct architecture folder

### NDK not found

Set your NDK path:
```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/30.0.14904198  # Adjust version
```

Or in your `~/.bashrc` or `~/.zshrc`.
