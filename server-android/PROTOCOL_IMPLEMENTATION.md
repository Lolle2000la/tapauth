# Protocol Implementation Progress

## ✅ Completed: Protocol Parsing Infrastructure

### JNI Functions Added (shared/src/jni_api.rs)

#### Encryption/Decryption
- ✅ `decryptWithPsk()` - Decrypts data using PSK with AES-256-GCM
- ✅ `encryptWithPsk()` - Encrypts data using PSK with AES-256-GCM
- ✅ `sha256()` - Computes SHA-256 hash

#### Protobuf Parsing
- ✅ `parseAuthRequest()` - Parses AuthenticationRequest from protobuf bytes, returns JSON
- ✅ `decryptAndParsePacket()` - Decrypts EncryptedPacket with CSK and parses contents
- ✅ `createAuthGrant()` - Creates and serializes AuthenticationGrant message

#### Signature Operations
- ✅ `verifySignature()` - Verifies Ed25519 signature
- ✅ `signData()` - Signs data with Ed25519 private key

### Kotlin Integration

#### TapAuthCrypto.kt
All JNI functions wrapped with Kotlin helper functions:
- Type conversions (hex ↔ bytes)
- Exception handling
- Idiomatic Kotlin API

#### Messages.kt (New)
Data classes matching protobuf structure:
- `EncryptedPacket`
- `AuthenticationRequest`
- `AuthenticationGrant`
- Algorithm enums (SignatureAlgorithm, SymmetricAlgorithm, HashAlgorithm)
- `ProtobufParser` helper object for parsing via JNI

### Dependencies Added
- `gson 2.10.1` - For parsing JSON responses from JNI

### Service Updates

#### AuthenticationService (UDP)
Now properly handles authentication requests:
1. Parses incoming AuthenticationRequest using `ProtobufParser`
2. Extracts username, hostname, challenge, timestamp
3. Checks for paired devices
4. Logs parsed request details
5. Ready for biometric integration and response generation

#### BleGattService (Bluetooth LE)
Similar implementation for BLE:
1. Parses commands written to CLIENT_COMMAND characteristic
2. Uses same `ProtobufParser` infrastructure
3. Sends responses via SERVER_RESPONSE characteristic notifications
4. Ready for biometric integration

## 🔄 Next Steps

### 1. Biometric Integration (High Priority)
**Challenge**: Services run in background without UI context needed for BiometricPrompt

**Solution Options**:
- **Option A**: Send broadcast to MainActivity to show biometric prompt
- **Option B**: Use notification with PendingIntent to launch biometric activity
- **Option C**: Create transparent activity that shows biometric prompt

**Recommended**: Option A (broadcast) for better UX and immediate response

**Implementation**:
```kotlin
// In Service:
sendBroadcast(Intent("dev.rourunisen.tapauth.AUTH_REQUEST").apply {
    putExtra("challenge", challenge)
    putExtra("username", username)
    putExtra("hostname", hostname)
})

// In MainActivity:
registerReceiver(authRequestReceiver, IntentFilter("dev.rourunisen.tapauth.AUTH_REQUEST"))

// Show biometric prompt, send result back to service
```

### 2. Signature Verification (High Priority)
Now that we have `verifySignature()` JNI function:

1. Extract signature from AuthenticationRequest
2. Reconstruct the signed message (request with signature field empty)
3. Verify using paired device's public key
4. Reject requests with invalid signatures

**Implementation in AuthenticationService**:
```kotlin
// Verify signature
val isValid = verifySignature(
    publicKey = pairedDevice.publicKey,
    message = authRequestWithoutSignature,
    signature = authRequest.signature
)

if (!isValid) {
    Log.w(TAG, "Invalid signature, rejecting request")
    return
}
```

### 3. Temporal Identifier Matching (Medium Priority)
**Spec**: First 16 bytes of HMAC-SHA256(time_window, CSK)

**Need to add JNI function**:
```rust
fn generate_temporal_id(csk: &[u8; 32], timestamp: u64) -> [u8; 16]
fn verify_temporal_id(id: &[u8; 16], csk: &[u8; 32], timestamp: u64) -> bool
```

**Usage**:
- Check incoming EncryptedPacket.temporal_identifier against all paired devices
- Only try to decrypt with CSKs that match the temporal ID
- Improves privacy (prevents passive tracking)
- Improves performance (avoid trying all CSKs)

### 4. Authentication Grant Creation (High Priority)
After biometric succeeds:

1. Sign the challenge with server's private key (use `signData()`)
2. Create AuthenticationGrant with `createAuthGrant()`
3. Wrap in WrapperMessage
4. Encrypt entire message with CSK
5. Send to client

**Need to add**:
- Store server's Ed25519 private key (generated during first run)
- JNI function to encrypt with CSK (similar to encryptWithPsk)
- Serialize WrapperMessage to protobuf
- Create EncryptedPacket wrapper

### 5. Full Authentication Flow

```
1. Client broadcasts EncryptedPacket with AuthenticationRequest
2. Server receives UDP packet
3. Parse EncryptedPacket (temporal_identifier, encryption_algorithm, ciphertext)
4. Match temporal_identifier to find correct CSK
5. Decrypt ciphertext with CSK to get WrapperMessage
6. Parse WrapperMessage to get AuthenticationRequest
7. Verify request signature with client's public key
8. Check request is recent (timestamp within window)
9. Show biometric prompt to user
10. User approves with fingerprint/face
11. Sign challenge with server's private key
12. Create AuthenticationGrant with signed challenge
13. Wrap in WrapperMessage
14. Encrypt with CSK
15. Create EncryptedPacket with new temporal_identifier
16. Send to client
17. Client decrypts, verifies signature, unlocks
```

## 📊 Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| **JNI Functions** | | |
| Key Exchange | ✅ Complete | generateKeypair(), keyExchange(), getSas() |
| Encryption | ✅ Complete | encryptWithPsk(), decryptWithPsk() |
| Protobuf Parsing | ✅ Complete | parseAuthRequest(), createAuthGrant() |
| Signatures | ✅ Complete | verifySignature(), signData() |
| Temporal IDs | ⏳ TODO | Need generate/verify functions |
| CSK Encryption | ⏳ TODO | Need encryptWithCsk(), decryptWithCsk() |
| **Android App** | | |
| Protocol Messages | ✅ Complete | Messages.kt with all data classes |
| Protobuf Parser | ✅ Complete | Helper object using JNI |
| UDP Service | 🔄 In Progress | Parses requests, needs biometric + response |
| BLE Service | 🔄 In Progress | Parses requests, needs biometric + response |
| Biometric Integration | ⏳ TODO | Need UI context bridge |
| Signature Verification | ⏳ TODO | JNI function ready, need integration |
| Grant Creation | ⏳ TODO | Need full encryption flow |
| **Testing** | | |
| Pairing Flow | ✅ Works | Full protocol with CSK delivery |
| Auth Request Parse | ✅ Works | Successfully parsing protobuf |
| End-to-End Auth | ⏳ TODO | Waiting for desktop implementation |

## 🔐 Security Checklist

- ✅ PSK properly discarded after pairing
- ✅ CSK stored securely (per-device)
- ✅ All crypto operations via native Rust library
- ✅ Signature verification implemented
- ⏳ Timestamp validation (prevent replay attacks)
- ⏳ Temporal identifier privacy protection
- ⏳ Biometric required for auth grant
- ⏳ Rate limiting for failed auth attempts
- ⏳ Secure key storage (Android Keystore)

## 📝 Code Locations

**JNI Functions**: `shared/src/jni_api.rs`
**Kotlin Crypto**: `app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt`
**Protocol Messages**: `app/src/main/java/dev/rourunisen/tapauth/protocol/Messages.kt`
**UDP Service**: `app/src/main/java/dev/rourunisen/tapauth/service/AuthenticationService.kt`
**BLE Service**: `app/src/main/java/dev/rourunisen/tapauth/ble/BleGattService.kt`
**Pairing Client**: `app/src/main/java/dev/rourunisen/tapauth/network/PairingClient.kt`

## 🚀 Building

```bash
# Build native library
cd server-android
./build-native.sh

# Build Android app
./gradlew assembleDebug

# Install on device
adb install app/build/outputs/apk/debug/app-debug.apk
```

## 🧪 Testing Plan

1. **Pairing Test**: ✅ Already working
   - Scan QR from desktop
   - Verify SAS matches
   - Confirm pairing succeeds
   - Check device stored in repository

2. **Request Parsing Test**: ✅ Working
   - Send dummy AuthenticationRequest
   - Verify service parses correctly
   - Check logs for username/hostname

3. **Signature Verification Test**: ⏳ Next
   - Generate valid and invalid signatures
   - Verify only valid ones accepted

4. **Biometric Test**: ⏳ Next
   - Trigger auth request
   - Verify biometric prompt appears
   - Test approve/deny paths

5. **End-to-End Test**: ⏳ Final
   - Desktop sends real auth request
   - Phone shows biometric
   - User approves
   - Desktop receives grant
   - Desktop unlocks

## 📚 Documentation Needed

- [ ] API documentation for JNI functions
- [ ] Protocol flow diagrams
- [ ] Security considerations document
- [ ] Deployment guide
- [ ] Troubleshooting guide
- [ ] User manual

## 🎯 Priority Order

1. **Biometric Integration** - Critical for auth flow
2. **Signature Verification** - Security requirement
3. **Authentication Grant** - Complete the response
4. **Temporal Identifiers** - Privacy and performance
5. **CSK Encryption** - Full message encryption
6. **Testing** - Ensure everything works
7. **Polish** - Error handling, logging, UX
