# TapAuth Android Server

A modern Android application for secure authentication using biometric verification. Part of the TapAuth ecosystem for passwordless authentication.

## 🎉 Status: **COMPLETE**

All core features are fully implemented and ready for use!

## Features

- ✅ **QR Code Pairing**: Scan desktop client QR codes for secure pairing
- ✅ **Biometric Authentication**: Fingerprint/face unlock for auth approval
- ✅ **Dual Transport**: UDP and BLE support
- ✅ **Ed25519 Signatures**: Cryptographic verification of all requests
- ✅ **Temporal Identifiers**: Privacy-preserving device identification
- ✅ **Secure Key Storage**: Android Keystore integration
- ✅ **Material 3 UI**: Modern, beautiful interface with Jetpack Compose

## Quick Start

1. **Build native library**:
   ```bash
   ./build-native.sh
   ```

2. **Build and install**:
   ```bash
   ./gradlew installDebug
   ```

3. **Run and pair**:
   - Launch app
   - Grant camera and biometric permissions
   - Tap "Scan QR Code"
   - Scan QR from desktop client
   - Verify 6-digit SAS code
   - Done!

See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.

## Documentation

- **[COMPLETION_SUMMARY.md](COMPLETION_SUMMARY.md)**: Comprehensive feature overview
- **[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)**: Detailed implementation status
- **[QUICKSTART.md](QUICKSTART.md)**: Getting started guide
- **[PROTOCOL_IMPLEMENTATION.md](PROTOCOL_IMPLEMENTATION.md)**: Protocol details
- **[BUILD_NATIVE.md](BUILD_NATIVE.md)**: Native library build guide

## Architecture

```
┌──────────────────────────────────────────┐
│           Android Application             │
│  ┌────────────────────────────────────┐  │
│  │         MainActivity               │  │
│  │  - QR Scanning (CameraX + ZXing)  │  │
│  │  - Biometric (BiometricPrompt)    │  │
│  │  - Device Management              │  │
│  └────────────────────────────────────┘  │
│           │                │              │
│  ┌────────▼────┐  ┌───────▼────────┐    │
│  │AuthService  │  │BleGattService  │    │
│  │(UDP:8442)   │  │(BLE GATT)      │    │
│  └────────┬────┘  └───────┬────────┘    │
│           │                │              │
│  ┌────────▼────────────────▼──────────┐  │
│  │    Shared Rust Library (JNI)      │  │
│  │  - Ed25519/X25519                 │  │
│  │  - AES-256-GCM                    │  │
│  │  - HKDF-SHA256                    │  │
│  │  - Protobuf                       │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

## Technologies

### Android Stack
- **Language**: Kotlin 2.0.21
- **Build**: Gradle 8.13.0, AGP 8.13.0
- **UI**: Jetpack Compose + Material 3
- **Camera**: CameraX 1.3.0
- **QR**: ZXing 3.5.2
- **Biometric**: BiometricPrompt 1.2.0-alpha05
- **Async**: Coroutines 1.7.3

### Native Library
- **Language**: Rust (edition 2021)
- **Crypto**: ed25519-dalek, x25519-dalek, aes-gcm, hkdf
- **Protocol**: prost (protobuf)
- **JNI**: jni 0.21

## Security

- **No Plain Text Keys**: All keys encrypted at rest
- **Android Keystore**: Hardware-backed encryption
- **Biometric Required**: Every auth needs approval
- **Signature Verification**: All requests must be signed
- **Temporal IDs**: Prevent device tracking
- **Challenge-Response**: Unique nonces prevent replay

## Requirements

- **Android**: 7.0 (API 24) or higher
- **Biometric**: Fingerprint sensor or face unlock
- **Bluetooth**: For BLE transport (optional)
- **Network**: WiFi/cellular for UDP transport

## Development

### Project Structure
```
server-android/
├── app/
│   ├── src/main/
│   │   ├── java/dev/rourunisen/tapauth/
│   │   │   ├── MainActivity.kt
│   │   │   ├── ble/
│   │   │   │   └── BleGattService.kt
│   │   │   ├── crypto/
│   │   │   │   └── TapAuthCrypto.kt
│   │   │   ├── data/
│   │   │   │   ├── Models.kt
│   │   │   │   ├── DeviceRepository.kt
│   │   │   │   ├── KeypairRepository.kt
│   │   │   │   └── AuthRequest.kt
│   │   │   ├── network/
│   │   │   │   └── PairingClient.kt
│   │   │   ├── protocol/
│   │   │   │   └── Messages.kt
│   │   │   ├── service/
│   │   │   │   ├── AuthenticationService.kt
│   │   │   │   └── AuthRequestManager.kt
│   │   │   └── ui/
│   │   │       ├── home/
│   │   │       ├── scanner/
│   │   │       ├── pairing/
│   │   │       ├── devices/
│   │   │       └── settings/
│   │   └── jniLibs/
│   │       ├── arm64-v8a/libshared.so
│   │       ├── armeabi-v7a/libshared.so
│   │       ├── x86_64/libshared.so
│   │       └── x86/libshared.so
│   └── build.gradle.kts
├── build-native.sh
└── README.md
```

### Building Native Library

Requirements:
- Rust toolchain
- Android NDK
- cargo-ndk: `cargo install cargo-ndk`

Build:
```bash
./build-native.sh
```

This compiles the shared Rust library for all Android architectures.

### Running Tests

```bash
# Android instrumented tests
./gradlew connectedAndroidTest

# Rust library tests
cd ../shared
cargo test --features jni

# View logs
adb logcat | grep TapAuth
```

## License

See [LICENSE](../LICENSE) file in repository root.

## Contributing

1. Follow Kotlin coding conventions
2. Use Jetpack Compose for UI
3. All crypto must use native library (no Java crypto)
4. Test on physical device with biometric hardware
5. Document new features in IMPLEMENTATION_STATUS.md

## Troubleshooting

### Build Issues
- Ensure Android SDK and NDK are installed
- Run `./build-native.sh` before building app
- Check Rust targets: `rustup target list | grep android`

### Runtime Issues
- Grant all permissions (camera, biometric, bluetooth)
- Check logs: `adb logcat | grep TapAuth`
- Verify biometric is set up in Android settings
- Ensure desktop client is running for pairing

### Performance
- App should use <1% CPU when idle
- Memory usage: ~50-100MB
- Network usage: Minimal (only during auth)
- Battery drain: Negligible

## Support

- Check documentation in this directory
- Review protocol specs in `../docs/design-documents/`
- View Rust library code in `../shared/`
- Check GitHub issues for known problems

## Acknowledgments

Built with:
- [Jetpack Compose](https://developer.android.com/jetpack/compose)
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)
- [CameraX](https://developer.android.com/training/camerax)
- [ZXing](https://github.com/zxing/zxing)
- [prost](https://github.com/tokio-rs/prost)

---

**Made with ❤️ for secure, passwordless authentication**
