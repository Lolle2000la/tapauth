# Pairing Protocol Mismatch Issue

**Date**: 2025-10-19  
**Status**: ❌ **BLOCKING** - Pairing fails at protocol layer  
**Error**: `Deserialization error: failed to decode Protobuf message: invalid key value: 104943578462216`

---

## Problem

The Android server and Rust desktop client are implementing **different protocols** for pairing:

### Android Client (`PairingClient.kt`)
- Sends **raw bytes** over TCP
- Protocol:
  1. Send: `writeInt(publicKey.size)` + `write(publicKey)`
  2. Compute PSK from X25519
  3. Generate SAS
  4. Wait for user confirmation
  5. Send encrypted CSK as raw bytes

### Rust Desktop Client (`shared/src/protocol/pairing.rs`)
- Expects **Protocol Buffers messages** over TCP
- Protocol:
  1. Receive: `PairingHello` protobuf message
  2. Send: `PairingResponse` protobuf message
  3. Compute PSK from X25519
  4. Derive SAS
  5. Receive: `PairingCskMessage` protobuf message
  6. Send: `PairingComplete` protobuf message

The Rust client tries to decode raw bytes as protobuf, which fails with "invalid key value" error.

---

## Root Cause

The Android app was implemented **without Protocol Buffers support**. The `PairingClient.kt` file implements a custom binary protocol instead of using the `.proto` definitions in `proto/auth_protocol.proto`.

---

## Solution Options

### Option 1: Add Protobuf to Android (RECOMMENDED)

**Pros**:
- Follows the specification correctly
- Type-safe, maintainable protocol
- Consistent with Rust implementation

**Steps**:
1. Add protobuf plugin to `server-android/app/build.gradle.kts`
2. Configure to generate Kotlin code from `proto/auth_protocol.proto`
3. Rewrite `PairingClient.kt` to use generated protobuf classes:
   - `PairingHello`
   - `PairingResponse`
   - `PairingCskMessage`
   - `PairingComplete`
4. Update message format to match Rust implementation

**Dependencies needed**:
```kotlin
// In build.gradle.kts plugins:
id("com.google.protobuf") version "0.9.4"

// In dependencies:
implementation("com.google.protobuf:protobuf-kotlin-lite:3.24.0")
```

**Configuration needed**:
```kotlin
protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.24.0"
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("java") {
                    option("lite")
                }
                create("kotlin") {
                    option("lite")
                }
            }
        }
    }
}
```

**Example rewrite** (partial):
```kotlin
// Instead of:
output.writeInt(publicKey.size)
output.write(publicKey)

// Use:
val hello = PairingHello.newBuilder()
    .setVersion(1)
    .setX25519PublicKey(ByteString.copyFrom(publicKey))
    .setEd25519PublicKey(ByteString.copyFrom(keypair.publicKey))
    .build()

val bytes = hello.toByteArray()
output.writeInt(bytes.size)
output.write(bytes)
```

---

### Option 2: Modify Rust to Accept Raw Bytes (HACKY)

**Pros**:
- Faster fix
- No Android changes needed

**Cons**:
- Violates specification
- Less maintainable
- Protocol versioning becomes harder

**Not recommended** - Would create technical debt.

---

## Protocol Buffers Messages

From `proto/auth_protocol.proto`:

```protobuf
message PairingHello {
    uint32 version = 1;
    bytes x25519_public_key = 2;  // 32 bytes
    bytes ed25519_public_key = 3; // 32 bytes
}

message PairingResponse {
    uint32 version = 1;
    bytes x25519_public_key = 2;  // 32 bytes
    bytes ed25519_public_key = 3; // 32 bytes
}

message PairingCskMessage {
    bytes encrypted_csk = 1;  // CSK encrypted with PSK
}

message PairingComplete {
    uint32 status = 1;  // 0 = success
}
```

---

## Current Status

✅ **Working**:
- QR code generation (Rust GUI)
- QR code scanning (Android)
- TCP connection establishment
- X25519 key exchange computation
- SAS generation and display

❌ **Broken**:
- Protocol message format (Android sends raw bytes, Rust expects protobuf)
- Message deserialization on Rust side
- Pairing completion

---

## Next Steps

1. Add protobuf support to Android build system
2. Copy `proto/auth_protocol.proto` to Android source set
3. Configure protobuf code generation
4. Rewrite `PairingClient.kt` to use protobuf messages
5. Test end-to-end pairing flow

---

## References

- Protocol definition: `proto/auth_protocol.proto`
- Rust implementation: `shared/src/protocol/pairing.rs`
- Android implementation: `server-android/app/src/main/java/dev/rourunisen/tapauth/network/PairingClient.kt`
- Error location: Rust desktop client trying to decode `PairingResponse` from Android
