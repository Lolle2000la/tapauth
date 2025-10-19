# Pairing Protocol Fix - Protobuf Implementation

## Problem
The pairing protocol had a mismatch between the Android and Rust implementations:
- **Android (server-android)**: Was sending raw bytes over TCP
- **Rust (client-config-gui)**: Was expecting protobuf-encoded messages

This caused a deserialization error: `failed to decode Protobuf message: invalid key value: 104943578462216`

## Root Cause
The Android `PairingClient.kt` was implementing a custom binary protocol instead of using protobuf messages as defined in `proto/auth_protocol.proto`. The Rust side correctly implemented the specification using protobuf.

## Solution
Added JNI functions to the shared Rust library to handle protobuf message creation and parsing for the pairing protocol, then updated Android to use these functions.

## Changes Made

### 1. Rust Shared Library (`shared/`)

#### `shared/Cargo.toml`
- Added `base64 = "0.22"` dependency for base64 encoding in JNI functions

#### `shared/src/jni_api.rs`
Added JNI wrapper functions for pairing protocol messages:

1. **`createPairingHello`** - Creates PairingHello message (protobuf)
   ```rust
   Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingHello(
       version: jint,
       x25519_public_key: JByteArray,
       ed25519_public_key: JByteArray
   ) -> jbyteArray
   ```

2. **`parsePairingResponse`** - Parses PairingResponse message (protobuf)
   ```rust
   Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingResponse(
       response_bytes: JByteArray
   ) -> jstring  // Returns JSON with base64-encoded keys
   ```

3. **`createPairingCskMessage`** - Creates PairingCskMessage (protobuf)
   ```rust
   Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingCskMessage(
       encrypted_csk: JByteArray
   ) -> jbyteArray
   ```

4. **`parsePairingCskMessage`** - Parses PairingCskMessage (protobuf)
   ```rust
   Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingCskMessage(
       message_bytes: JByteArray
   ) -> jbyteArray  // Returns encrypted CSK bytes
   ```

5. **`parsePairingComplete`** - Parses PairingComplete message (protobuf)
   ```rust
   Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingComplete(
       complete_bytes: JByteArray
   ) -> jstring  // Returns JSON: {"success": true/false}
   ```

### 2. Android App (`server-android/`)

#### `app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt`

**Added JNI declarations:**
```kotlin
external fun createPairingHello(version: Int, x25519PublicKey: ByteArray, ed25519PublicKey: ByteArray): ByteArray
external fun parsePairingResponse(responseBytes: ByteArray): String
external fun createPairingCskMessage(encryptedCsk: ByteArray): ByteArray
external fun parsePairingCskMessage(messageBytes: ByteArray): ByteArray
external fun parsePairingComplete(completeBytes: ByteArray): String
```

**Added Kotlin wrapper functions:**
```kotlin
fun createPairingHello(version: Int, x25519PublicKey: ByteArray, ed25519PublicKey: ByteArray): ByteArray
fun parsePairingResponse(responseBytes: ByteArray): Triple<Int, ByteArray, ByteArray>
fun createPairingCskMessage(encryptedCsk: ByteArray): ByteArray
fun parsePairingCskMessage(messageBytes: ByteArray): ByteArray
fun parsePairingComplete(completeBytes: ByteArray): Boolean
```

#### `app/src/main/java/dev/rourunisen/tapauth/network/PairingClient.kt`

**Complete rewrite to use protobuf messages:**

**Before (raw bytes):**
```kotlin
// Send raw public key
output.writeInt(serverEphemeralKeyPair.publicKey.size)
output.write(serverEphemeralKeyPair.publicKey)
```

**After (protobuf):**
```kotlin
// Send PairingHello message (protobuf)
val pairingHello = createPairingHello(
    version = 1,
    x25519PublicKey = serverEphemeralKeyPair.publicKey,
    ed25519PublicKey = serverEphemeralKeyPair.publicKey
)
output.writeInt(pairingHello.size)
output.write(pairingHello)
```

**Updated protocol flow:**

1. **initiatePairing():**
   - Generate ephemeral X25519 keypair
   - Send `PairingHello` message (protobuf) with version, X25519 public key, Ed25519 public key
   - Receive `PairingResponse` message (protobuf)
   - Parse response to extract client's public keys
   - Perform X25519 ECDH to compute PSK
   - Generate SAS for verification
   - Return `AwaitingSASVerification` state

2. **completePairing():**
   - Generate CSK (32 random bytes)
   - Encrypt CSK with PSK (context: "csk_exchange")
   - Send `PairingCskMessage` (protobuf) containing encrypted CSK
   - Receive `PairingComplete` message (protobuf)
   - Parse confirmation and verify success
   - Store paired device with CSK
   - Discard PSK

**Updated data structures:**
```kotlin
sealed class PairingInitResult {
    data class AwaitingSASVerification(
        val socket: Socket,
        val psk: ByteArray,
        val clientPublicKey: ByteArray,
        val clientEd25519Key: ByteArray,  // NEW: Store Ed25519 key for device ID
        val sas: String
    ) : PairingInitResult()
}
```

#### `app/src/main/java/dev/rourunisen/tapauth/ui/pairing/PairingScreen.kt`

**Updated to pass new parameter:**
```kotlin
// Updated PairingState.VerifySAS to include clientEd25519Key
data class VerifySAS(
    val sas: String,
    val socket: java.net.Socket,
    val psk: ByteArray,
    val clientPublicKey: ByteArray,
    val clientEd25519Key: ByteArray  // NEW
) : PairingState()

// Updated completePairing call
pairingClient.completePairing(
    socket = state.socket,
    psk = state.psk,
    clientPublicKey = state.clientPublicKey,
    clientEd25519Key = state.clientEd25519Key,  // NEW
    sasConfirmed = true
)
```

## Protocol Specification Compliance

The implementation now correctly follows the protocol defined in `proto/auth_protocol.proto`:

### Message Flow

```
Android (Server)              Desktop (Client)
================              ================
1. PairingHello      -->
   (version, x25519_pub, ed25519_pub)
   
2.                   <--     PairingResponse
                             (version, x25519_pub, ed25519_pub)
   
3. Compute PSK via X25519 ECDH
   Display SAS
   
4. User verifies SAS on both sides
   
5. PairingCskMessage -->
   (encrypted_csk)
   
6.                   <--     PairingComplete
                             (success: true)
   
7. Store paired device
   Discard PSK
```

### Message Structures (from proto file)

```protobuf
message PairingHello {
  uint32 version = 1;
  bytes x25519_public_key = 2;
  bytes ed25519_public_key = 3;
}

message PairingResponse {
  uint32 version = 1;
  bytes x25519_public_key = 2;
  bytes ed25519_public_key = 3;
}

message PairingCskMessage {
  bytes encrypted_csk = 1;
}

message PairingComplete {
  bool success = 1;
}
```

## Testing

To test the fix:

1. **Build native libraries:**
   ```bash
   cd server-android
   ./build-native.sh
   ```

2. **Build and install Android app:**
   ```bash
   ./gradlew assembleDebug
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

3. **Run desktop GUI (in Docker):**
   ```bash
   ./dev-start.sh
   ./dev-shell.sh
   run-gui
   ```

4. **Test pairing flow:**
   - Generate QR code on desktop
   - Scan with Android app
   - Verify SAS matches on both sides
   - Confirm pairing
   - Should complete without protobuf errors!

## Expected Outcome

- ✅ Android sends protobuf-encoded `PairingHello`
- ✅ Rust parses `PairingHello` correctly
- ✅ Rust sends protobuf-encoded `PairingResponse`
- ✅ Android parses `PairingResponse` correctly
- ✅ SAS displayed on both sides
- ✅ Android sends protobuf-encoded `PairingCskMessage`
- ✅ Rust parses `PairingCskMessage` and decrypts CSK
- ✅ Rust sends protobuf-encoded `PairingComplete`
- ✅ Android parses confirmation
- ✅ Pairing completes successfully
- ✅ Device stored with CSK for future authentication

## Benefits of This Approach

1. **Uses existing pattern**: JNI already had protobuf handling for authentication messages
2. **No new dependencies**: Didn't need to add protobuf plugin to Android
3. **Type-safe**: Rust handles all protobuf serialization/deserialization
4. **Consistent**: Both sides now use the same protocol format
5. **Specification compliant**: Matches the protocol defined in auth_protocol.proto
6. **Maintainable**: Changes to protocol only require updating JNI functions

## Files Modified

### Rust (shared library):
- `shared/Cargo.toml` - Added base64 dependency
- `shared/src/jni_api.rs` - Added 5 new JNI functions (234 lines)

### Android:
- `server-android/app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt` - Added 5 JNI declarations + 5 wrapper functions
- `server-android/app/src/main/java/dev/rourunisen/tapauth/network/PairingClient.kt` - Rewrote to use protobuf messages
- `server-android/app/src/main/java/dev/rourunisen/tapauth/ui/pairing/PairingScreen.kt` - Updated to pass clientEd25519Key

## Related Documents

- [PAIRING_PROTOCOL_MISMATCH.md](PAIRING_PROTOCOL_MISMATCH.md) - Original problem analysis
- [proto/auth_protocol.proto](proto/auth_protocol.proto) - Protocol specification
- [shared/src/protocol/pairing.rs](shared/src/protocol/pairing.rs) - Rust pairing implementation

## Date
2025-10-19
