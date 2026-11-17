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

1. Native libraries are built by Gradle itself — the `cargo { }` block in
   `app/build.gradle.kts` cross-compiles `shared` for the requested ABIs and
   `preBuild` depends on it, so there is nothing to run by hand:

   ```bash
   # Optional: build just the native libraries and stop
   ./gradlew cargoBuild
   ```

2. Start an Android emulator or connect a physical device

#### Run Tests

`testBuildType` is `e2e` (`app/build.gradle.kts`), so the instrumented task is the
`e2e` variant's:

```bash
./gradlew connectedE2eAndroidTest
```

Or run specific test class:

```bash
./gradlew connectedE2eAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.rourunisen.tapauth.crypto.TapAuthCryptoTest
```

#### Test Runner

The project uses a custom `TapAuthTestRunner` that replaces the production `TapAuthApplication` with `TestTapAuthApplication` during test execution. This prevents foreground services from starting in the test environment, avoiding `ForegroundServiceStartNotAllowedException` on Android 14+.

## Test Coverage

### JNI Crypto Tests (`TapAuthCryptoTest.kt`)

Located in `androidTest/`, these instrumentation tests validate the JNI boundary:

- **Key Generation**: Ed25519, X25519 keypair generation
- **Key Exchange**: X25519 Diffie-Hellman, and the HKDF-SHA256 `K_c2s`/`K_s2c`/SAS derivation salted with the handshake transcript `H` (there is no PSK in v2: the only symmetric key is the CSK)
- **Temporal IDs**: Generation and verification for UDP (16 bytes) and BLE (10 bytes)
- **Encryption**: CSK encryption/decryption with AES-256-GCM
- **Signatures**: Ed25519 signing and verification consistency
- **Protobuf**: Message parsing and type determination
- **Pairing Protocol**: Message creation and parsing
- **Error Handling**: Invalid input validation and exception propagation

**28 test cases** (`@Test`) ensuring correct type conversions, error handling, and cryptographic consistency across the Kotlin/Rust FFI boundary.

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

The CI workflows (`.github/workflows/ci.yml` for the Rust checks and formatting, `.github/workflows/ci-android.yml` for the Android build and emulator runs):

1. **Rust Tests**: All workspace tests including protobuf tests
2. **Android Build**: Builds native libraries for all ABIs
3. **APK Build**: Assembles debug APK
4. **Android Instrumentation Tests**: Runs JNI tests in an emulator (API 36, x86_64) as part of the real-Android E2E run (`scripts/ci/run-all-e2e.sh`)
5. **Code Formatting**: Checks Rust (rustfmt) and Kotlin (Spotless)

The emulator step uses KVM acceleration and caches AVD snapshots for faster execution. Test results are uploaded as artifacts.

## Manual Testing

For manual QA testing of JNI functionality:

1. Install the app on a physical device or emulator
2. Run through pairing workflow
3. Test authentication via UDP and BLE
4. Verify cryptographic operations work correctly

This provides end-to-end validation of the JNI boundary in production-like conditions.
