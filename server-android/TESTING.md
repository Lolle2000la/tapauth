# Testing TapAuth Android App

## Running Tests

### Unit Tests (JVM)

Standard unit tests run on the JVM without requiring an Android device or emulator:

```bash
./gradlew test
```

### Instrumentation Tests (JNI/Native)

JNI crypto tests require native libraries and must run on an Android device or emulator:

#### Prerequisites

1. Build native libraries:
   ```bash
   ./build-native.sh
   ```

2. Start an Android emulator or connect a physical device

#### Run Tests

```bash
./gradlew connectedAndroidTest
```

Or run specific test class:

```bash
./gradlew connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.rourunisen.tapauth.crypto.TapAuthCryptoTest
```

#### Test Runner

The project uses a custom `TapAuthTestRunner` that replaces the production `TapAuthApplication` with `TestTapAuthApplication` during test execution. This prevents foreground services from starting in the test environment, avoiding `ForegroundServiceStartNotAllowedException` on Android 14+.

## Test Coverage

### JNI Crypto Tests (`TapAuthCryptoTest.kt`)

Located in `androidTest/`, these instrumentation tests validate the JNI boundary:

- **Key Generation**: Ed25519, X25519 keypair generation
- **Key Exchange**: X25519 Diffie-Hellman and PSK derivation
- **Temporal IDs**: Generation and verification for UDP (16 bytes) and BLE (10 bytes)
- **Encryption**: PSK and CSK encryption/decryption with AES-256-GCM
- **Signatures**: Ed25519 signing and verification consistency
- **Protobuf**: Message parsing and type determination
- **Pairing Protocol**: Message creation and parsing
- **Error Handling**: Invalid input validation and exception propagation

**50+ test cases** ensuring correct type conversions, error handling, and cryptographic consistency across the Kotlin/Rust FFI boundary.

### Protocol Tests (Rust)

Located in `shared/src/protocol/packet.rs`:

- Protobuf encoding/decoding (`EncryptedPacket`, `WrapperMessage`)
- Packet encryption/decryption
- Message type detection

Run with:
```bash
cd .. && cargo test --manifest-path shared/Cargo.toml --features jni protobuf_tests
```

## CI/CD

### GitHub Actions

The CI workflow (`.github/workflows/ci.yml`):

1. **Rust Tests**: All workspace tests including protobuf tests
2. **Android Build**: Builds native libraries for all ABIs
3. **APK Build**: Assembles debug APK
4. **Android Instrumentation Tests**: Runs JNI tests in Android emulator (API 34, x86_64)
5. **Code Formatting**: Checks Rust (rustfmt) and Kotlin (Spotless)

The emulator step uses KVM acceleration and caches AVD snapshots for faster execution. Test results are uploaded as artifacts.

## Manual Testing

For manual QA testing of JNI functionality:

1. Install the app on a physical device or emulator
2. Run through pairing workflow
3. Test authentication via UDP and BLE
4. Verify cryptographic operations work correctly

This provides end-to-end validation of the JNI boundary in production-like conditions.
