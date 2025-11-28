# AGENTS.md - TapAuth Context & Architecture

## 1. Project Overview
**TapAuth** is a privacy-first, low-latency authentication system that allows a Linux desktop (**Client**) to be unlocked using a paired mobile device (**Server**) via biometrics.

**Core Philosophy:**
- **Local First:** No cloud servers. All communication happens over local UDP Broadcast/Multicast or Bluetooth Low Energy (BLE).
- **Parallel Discovery:** To minimize latency, the Client "races" UDP and BLE simultaneously; the first successful transport wins.
- **Privacy:** Uses rotating temporal identifiers to prevent passive network tracking.

## 2. Terminology & Roles

| Term | Role | Component Path | Tech Stack |
| :--- | :--- | :--- | :--- |
| **Client** | The Linux Desktop requesting authentication. | `tapauthd`, `client-pam`, `client-config-gui` | Rust |
| **Server** | The Android/Mobile device performing biometric verification. | `server-android` | Kotlin / Jetpack Compose |
| **Daemon** | The background service on the Client managing transport & crypto. | `tapauthd` | Rust (Tokio) |
| **PAM** | The Pluggable Authentication Module integrating with Linux login. | `client-pam` | Rust (FFI) |
| **Shared** | Common library for Protocol, Crypto, and Networking. | `shared` | Rust |

## 3. Architecture & Component Interaction

### A. The Client Ecosystem (Linux)
The Linux side is split into three parts to separate privileges and responsibilities:
1.  **`client-pam`**:
    * **Responsibility**: Hooks into the Linux login process (GDM, sudo, etc.).
    * **Behavior**: Acts as a thin client. It pauses the login, sends an IPC request to `tapauthd`, and waits for a Yes/No response.
2.  **`tapauthd` (The Core)**:
    * **Responsibility**: Runs as a systemd service. Manages Bluetooth/UDP sockets, stores cryptographic keys, and handles the "Race" logic.
    * **Privileges**: Needs network capabilities and access to BLE hardware.
3.  **`client-config-gui`**:
    * **Responsibility**: User interface for pairing new devices, managing keys, and settings.
    * **Behavior**: Communicates with `tapauthd` via IPC to initiate pairing modes.

### B. The Server Ecosystem (Android)
* **Path**: `server-android/`
* **Architecture**: 
    * **Foreground Services**: Both UDP (`AuthenticationService`) and BLE (`BleGattService`) run as Android Foreground Services to prevent the OS from killing them during background operation.
    * **JNI Bridge**: The Android app is a "shell" for the UI and hardware access. All core logic resides in the Rust `shared` library.
    * **Strict Boundary**: Kotlin code **never** parses or manipulates Protobuf messages directly. It passes raw bytes to the JNI layer (`jni_api.rs`), which handles validation, decryption, and parsing, returning safe POJOs to Kotlin.

### C. The Protocol (Shared)
* **Definition**: `proto/auth_protocol.proto` & `proto/ipc.proto`.
* **Logic**: Implemented in `shared/`.
* **Packet Structure**:
    * All payloads are wrapped in an `EncryptedPacket`.
    * **Temporal ID**: The header contains a 16-byte (UDP) or 10-byte (BLE) ID derived from an HMAC-SHA256 of the current time window (60s). This allows the Server to identify the Client without exposing static IDs.

## 4. Critical Workflows

### 4.1. Authentication "Race" Flow
When `client-pam` triggers `tapauthd`:
1.  `tapauthd` broadcasts `EncryptedPacket` via **UDP** (Port 36692).
2.  `tapauthd` simultaneously starts **BLE Advertising**.
3.  The `server-android` listens on both.
4.  If the User approves on the Server:
    * Server replies via the *same* transport method that delivered the request.
    * Server retransmits the Grant every 500ms until confirmed or timed out (10s).
5.  `tapauthd` accepts the first valid Grant, verifies the signature, and signals `client-pam` to unlock.

### 4.2. Pairing Flow
1.  Client generates a QR code containing its public key and IP info.
2.  Server scans QR code.
3.  Key exchange occurs (Protocol details in `docs/design-documents/protocol/initial-key-exchange.md`).
4.  **Client Symmetric Key (CSK)** is generated/exchanged. This key is used for future `EncryptedPacket` encryption.

## 5. Directory Structure & Navigation

* `docs/`: **READ FIRST.** Source-of-truth design docs (`authentication-flow.md` is critical).
* `proto/`: Protobuf definitions. Modifying these requires recompiling `shared`, `tapauthd`, and `server-android`.
* `shared/`:
    * `src/crypto/`: Encryption (AES-GCM), Signing (Ed25519), and Key Derivation.
    * `src/jni_api.rs`: **Critical.** The JNI interface. All Protobuf serialization/deserialization for Android happens here.
* `tapauthd/`:
    * `src/transport/`: Implementation of `ble.rs` (using `bluer`) and `udp.rs`.
    * `src/auth_handler.rs`: The state machine deciding when to unlock.
* `server-android/`:
    * `app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt`: The Kotlin gatekeeper for JNI calls.

## 6. Development Constraints & Guidelines

### Security & Protocol Boundaries
* **Rust is the Source of Truth**: Protocol logic, packet structures, and cryptographic operations live exclusively in Rust.
* **No Manual Parsing in Kotlin**: The Android app must treat `ByteArray` messages as opaque until processed by `TapAuthCrypto` (JNI). Do not write manual parsers in Kotlin.
* **Replay Protection**: The Server explicitly checks `challenge` nonces and `timestamp_unix_seconds` (60s window). Do not remove these checks.
* **Metadata**: Never transmit static identifiers (like MAC addresses or Public Keys) in cleartext during the Authentication phase. Use Temporal IDs.

### Rust Considerations
* **Async**: The daemon uses `tokio`. Ensure no blocking operations occur in the main event loop, especially regarding BLE socket handling.
* **Error Handling**: Use `thiserror` in libraries and `anyhow` in binaries/tests.
* **Verify Buildability**: Always run `cargo check` with the appropriate features (or `--all-features`) after modifying shared code. Run it for the whole workspace for a final check.
* **Code Formatting**: Use `cargo fmt` and `cargo clippy` regularly to maintain code quality.

### Android Considerations
* **Foreground Requirement**: Authentication listeners (`BleGattService`, `AuthenticationService`) **must** run as Foreground Services. Ensure `startForeground` is called immediately in `onCreate` to avoid `ForegroundServiceDidNotStartInTimeException`.
* **Permissions**: Handling `POST_NOTIFICATIONS` (Android 13+) is a prerequisite for starting the foreground services.
* **Biometrics**: Relies on `androidx.biometric`.
* **Spotless Format**: Use Spotless for Kotlin code formatting. Run `./gradlew spotlessApply` before commits.

## 7. Common Tasks for Agents

* **Adding a Protocol Field**:
    1.  Edit `proto/auth_protocol.proto`.
    2.  Update `shared/src/protocol/messages.rs` (Rust) to handle the logic.
    3.  Update `shared/src/jni_api.rs` (Rust) to expose the new field to JNI.
    4.  Update `ProtocolDataClasses.kt` (Kotlin) to receive the field.
* **Debugging Connection Issues**:
    1.  Check `tapauthd` logs (uses `tracing`).
    2.  Verify `systemd` socket activation status.
    3.  Check if `firewalld` is blocking UDP port 36692.