# Android JNI Contract (v2)

This document is the authoritative description of the Rust ↔ Kotlin boundary used by the Android **Server**: `shared/src/jni_api.rs` exports it, `server-android/app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt` declares it, and `shared/src/jni_api/ops.rs` holds every decision it makes. Kotlin never parses protobuf: each packet argument and packet return below is a whole serialized protobuf blob (`EncryptedPacket`, `WrapperMessage` or `PairingPacket`), and every signature, AEAD operation, key derivation and pairing state transition happens inside Rust.

## 1. Entry Points

Every Rust export is `Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_<name>`, where `<name>` is exactly the Kotlin function name in the first column; the tables therefore write only `…TapAuthCrypto_<name>`. JVM types: `ByteArray` = `[B`, `String` = `Ljava/lang/String;`, `Long` = `J`, `Int` = `I`, `Boolean` = `Z`, Kotlin `Unit` = `void`.

### 1.1 Keys and identity

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `generateKeypair` | `(): Array<ByteArray>` | `…TapAuthCrypto_generateKeypair` | Fresh `Ed_S`: `Object[]{priv(32), pub(32)}` |

The pairing session is given its own `Ed_S` copy (`pairingServerSessionCreate`); `generateKeypair` is otherwise the only entry point that hands private key material to Kotlin, and it does so once, for the phone to store.

### 1.2 Encrypted packets

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `decryptEncryptedPacket` | `(encryptedPacketBytes: ByteArray, csk: ByteArray, expectedSymAlg: Int): ByteArray` | `…TapAuthCrypto_decryptEncryptedPacket` | Decrypted `WrapperMessage` bytes, under the pinned algorithm |
| `extractTemporalIdentifier` | `(packetBytes: ByteArray): ByteArray` | `…TapAuthCrypto_extractTemporalIdentifier` | The packet's 16-byte `temporal_identifier`, before any AEAD work |
| `determineMessageType` | `(wrapperMessageBytes: ByteArray): String` | `…TapAuthCrypto_determineMessageType` | Dispatch name (`AUTH_REQUEST`, `AUTH_GRANT`, `AUTH_DENIAL`, `GRANT_CONFIRMATION`, `AUTH_CANCEL`, `UNKNOWN`); **not authenticated** |

### 1.3 Verified parsing of Client messages

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `parseAndVerifyAuthRequest` | `(wrapperBytes: ByteArray, clientEd25519Pub: ByteArray, protocolVersion: Int, expectedSignatureAlgorithm: Int): ParsedAuthRequest` | `…TapAuthCrypto_parseAndVerifyAuthRequest` | Signature-verified `ParsedAuthRequest`; `protocolVersion` must be `2` |
| `parseAndVerifyGrantConfirmation` | `(wrapperBytes: ByteArray, clientEd25519Pub: ByteArray, protocolVersion: Int, expectedSignatureAlgorithm: Int): ByteArray` | `…TapAuthCrypto_parseAndVerifyGrantConfirmation` | The confirmed 32-byte challenge |
| `parseAndVerifyAuthCancel` | `(wrapperBytes: ByteArray, clientEd25519Pub: ByteArray, protocolVersion: Int, expectedSignatureAlgorithm: Int): ByteArray` | `…TapAuthCrypto_parseAndVerifyAuthCancel` | The cancelled 32-byte challenge |

Each verifies the `WrapperMessage` signature over the raw payload **before** the inner protobuf is decoded, and pins `payload_type` first, so no forged envelope reaches a decoder.

### 1.4 Server responses

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `createGrantWrapperMessage` | `(challenge: ByteArray, serverPrivKey: ByteArray, csk: ByteArray, symmetricAlgorithm: Int, hashAlgorithm: Int): ByteArray` | `…TapAuthCrypto_createGrantWrapperMessage` | Finished `EncryptedPacket` carrying a signed `AuthenticationGrant` |
| `createDenialWrapperMessage` | `(challenge: ByteArray, reason: String, serverPrivKey: ByteArray, csk: ByteArray, symmetricAlgorithm: Int, hashAlgorithm: Int): ByteArray` | `…TapAuthCrypto_createDenialWrapperMessage` | Finished `EncryptedPacket` carrying a signed `AuthenticationDenial` |

Both return the packet **already signed and AEAD-encrypted**; Kotlin must not wrap, encrypt or re-sign it.

### 1.5 Discovery and temporal identifiers

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `generateTemporalIdentifier` | `(csk: ByteArray, window: Long, hashAlgorithm: Int): ByteArray` | `…TapAuthCrypto_generateTemporalIdentifier` | 16-byte UDP/GATT identifier for `window` |
| `generateBleTemporalIdentifier` | `(csk: ByteArray, window: Long, hashAlgorithm: Int): ByteArray` | `…TapAuthCrypto_generateBleTemporalIdentifier` | 10-byte BLE advertisement identifier for `window` |
| `currentTimeWindow` | `(): Long` | `…TapAuthCrypto_currentTimeWindow` | The current 60-second window (`unix_seconds / 60`) |
| `verifyTemporalIdentifier` | `(temporalIdentifier: ByteArray, csk: ByteArray, hashAlgorithm: Int): Boolean` | `…TapAuthCrypto_verifyTemporalIdentifier` | `true` if the id matches the current or previous window |
| `deriveBlePairingAdvId` | `(sessionId: ByteArray, clientX25519Pub: ByteArray): ByteArray` | `…TapAuthCrypto_deriveBlePairingAdvId` | 10-byte BLE pairing advertisement id from the scanned QR `(sid, pk)` |

### 1.6 Pairing (stateful, keyed by an opaque handle)

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `pairingServerSessionCreate` | `(sessionId: ByteArray, serverEd25519PrivKey: ByteArray, serverDeviceName: String): Long` | `…TapAuthCrypto_pairingServerSessionCreate` | A positive session handle, or `0` after throwing |
| `pairingServerSessionFree` | `(handle: Long)` | `…TapAuthCrypto_pairingServerSessionFree` | Drops the session and zeroizes its keys |
| `pairingCreateInit` | `(handle: Long): ByteArray` | `…TapAuthCrypto_pairingCreateInit` | `PairingPacket(PairingInit)`, cached for retransmission |
| `pairingVerifyResponse` | `(handle: Long, responsePacket: ByteArray, expectedQrPk: ByteArray): ParsedPairingResponse` | `…TapAuthCrypto_pairingVerifyResponse` | `ParsedPairingResponse`: the SAS plus what the phone persists |
| `pairingProcessConfirmClient` | `(handle: Long, confirmClientPacket: ByteArray): ParsedPairingProvision` | `…TapAuthCrypto_pairingProcessConfirmClient` | `ParsedPairingProvision`: the provisioned CSK, user and hostname |
| `pairingCreateConfirmServer` | `(handle: Long, csk: ByteArray): ByteArray` | `…TapAuthCrypto_pairingCreateConfirmServer` | `PairingPacket(PairingConfirmServer)` completion proof |
| `pairingCreateAbort` | `(handle: Long, reason: Int): ByteArray` | `…TapAuthCrypto_pairingCreateAbort` | `PairingPacket(PairingAbort)`, MAC'd once the keys exist |
| `pairingVerifyAbort` | `(handle: Long, abortPacket: ByteArray): Boolean` | `…TapAuthCrypto_pairingVerifyAbort` | `true` only for an authenticated abort; `false` means unauthenticated — ignore it |
| `pairingCreateKeepalive` | `(handle: Long): ByteArray` | `…TapAuthCrypto_pairingCreateKeepalive` | `PairingPacket(PairingKeepalive)`, empty body |
| `pairingPacketSessionId` | `(packetBytes: ByteArray): ByteArray` | `…TapAuthCrypto_pairingPacketSessionId` | The packet's validated 16-byte `session_id` |

### 1.7 Logging

| Kotlin | Kotlin signature | Rust symbol | Returns / does |
| :--- | :--- | :--- | :--- |
| `initLogging` | `()` (declared `private`) | `…TapAuthCrypto_initLogging` | Installs logcat tracing once; export exists only on `target_os = "android"` |

### 1.8 Exceptions

| `JniError` (`ops.rs`) | Thrown Java class | Raised for |
| :--- | :--- | :--- |
| `Argument` | `java.lang.IllegalArgumentException` | Wrong lengths, unsupported version or algorithm id, unknown handle, foreign-session `PairingPacket` |
| `Security` | `java.security.GeneralSecurityException` | Bad Ed25519 signature, AEAD/AAD failure, algorithm downgrade, QR-`pk` mismatch |
| `Io` | `java.io.IOException` | Bytes that are not a decodable protobuf message |
| `State` | `java.lang.IllegalStateException` | VM/JNI failure, poisoned session table, DTO construction failure |

After throwing, a function returns `0`, `false` or `null` and makes no further JNI calls; Kotlin checks the return value and handles the exception.

## 2. Data Classes Built by `NewObject`

`shared/src/jni/objects.rs` constructs three DTOs by class name plus a hard-coded constructor descriptor. That mismatch has **no compile-time signal on either side**: `find_class`/`new_object` fails at runtime, on the device, and the entry point throws `IllegalStateException`. The reconciliation needed **three** classes, not two: `ParsedPairingProvision` (the decrypted CSK payload) is as much part of the surface as the request and the pairing response.

Each descriptor and field order must be read together — the descriptor is what `NewObject` looks up, the ordered list is what Kotlin's primary constructor receives, and a single reordered, renamed, retyped or defaulted field breaks one or both.

### 2.1 `ParsedAuthRequest`

Descriptor passed to `NewObject`:

```text
([BLjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
```

Field order (Rust argument → Kotlin property, JVM type):

| # | Rust argument (`create_parsed_auth_request`) | Kotlin property | JVM type |
| :--- | :--- | :--- | :--- |
| 1 | `challenge: &[u8]` | `challenge` | `[B` |
| 2 | `username: &str` | `username` | `Ljava/lang/String;` |
| 3 | `hostname: &str` | `hostname` | `Ljava/lang/String;` |
| 4 | `timestamp_unix_seconds: i64` | `timestampUnixSeconds` | `J` |
| 5 | `pam_service: &str` | `pamService` | `Ljava/lang/String;` |
| 6 | `process_name: &str` | `processName` | `Ljava/lang/String;` |
| 7 | `command_preview: &str` | `commandPreview` | `Ljava/lang/String;` |
| 8 | `tty_present: bool` | `ttyPresent` | `Z` |

### 2.2 `ParsedPairingProvision`

Descriptor passed to `NewObject`:

```text
([BLjava/lang/String;Ljava/lang/String;)V
```

Field order:

| # | Rust argument (`create_parsed_pairing_provision`) | Kotlin property | JVM type |
| :--- | :--- | :--- | :--- |
| 1 | `csk: &[u8]` | `csk` | `[B` |
| 2 | `username: &str` | `username` | `Ljava/lang/String;` |
| 3 | `client_hostname: &str` | `clientHostname` | `Ljava/lang/String;` |

### 2.3 `ParsedPairingResponse`

Descriptor passed to `NewObject`:

```text
(Ljava/lang/String;[BIII)V
```

Field order:

| # | Rust argument (`create_parsed_pairing_response`) | Kotlin property | JVM type |
| :--- | :--- | :--- | :--- |
| 1 | `sas: &str` | `sas` | `Ljava/lang/String;` |
| 2 | `client_ed25519_public_key: &[u8]` | `clientEd25519PublicKey` | `[B` |
| 3 | `symmetric_algorithm: i32` | `symmetricAlgorithm` | `I` |
| 4 | `hash_algorithm: i32` | `hashAlgorithm` | `I` |
| 5 | `signature_algorithm: i32` | `signatureAlgorithm` | `I` |

## 3. Handle and Key Lifetime Rules

* Kotlin holds **only an opaque `jlong`** from `pairingServerSessionCreate`. Handles are allocated monotonically from a counter that starts at `1`, so `0` is never a valid handle (`NEXT_HANDLE` / `pairing_session_create` in `shared/src/jni_api/ops.rs`).
* `K_c2s`, `K_s2c`, the transcript hash `H` and the ephemeral X25519 secret never cross into Kotlin: they live in the `ClientPairingSession` behind the handle (`SESSIONS`, a `Mutex<HashMap<i64, ClientPairingSession>>`).
* `Ed_S` is copied into the session by `pairing_server_session_create` and never returned by any entry point. `generateKeypair` is a separate entry point that mints a *new* identity keypair; it does not read back the session's copy.
* Every handle must be freed exactly once via `pairingServerSessionFree` (`pairing_session_free`). An unknown handle — already freed, or never created — throws `IllegalArgumentException`, so the second free of the same handle fails loudly instead of silently dropping another session.
* A failed `pairingVerifyResponse` caches nothing: `ClientPairingSession::verify_response` writes `negotiated`, `transcript_hash` and `keys` only after the QR commitment, the Ed25519 signature and the algorithm checks all passed. A later genuine response on the same handle therefore still succeeds.
* Every handle-taking entry point except `pairingServerSessionFree` runs through `with_session`; a packet whose `session_id` is not the session's own is rejected as an `IllegalArgumentException` before any crypto runs.

## 4. Invariants This Document Protects

* **No Kotlin code derives a key, builds an AAD, chooses an abort MAC direction, hashes a transcript or encodes a `PairingPacket`.** Each of those is one exported function: abort tags are computed by `ClientPairingSession::create_abort` (phone direction `K_s2c`) and verified by `ClientPairingSession::verify_abort` (desktop direction `K_c2s`).
* **Every packet argument and return is a whole serialized protobuf blob.** Kotlin never slices, splits or reassembles a packet field.
* **`pairingVerifyAbort` returning `false` means _unauthenticated_, not "aborted".** A tag-less abort received before any key existed is unauthenticated by construction and must be ignored; treating `false` as proof of an abort lets an on-path attacker cancel a pairing. Once keys exist, a tag-less or wrong-tag abort is `GeneralSecurityException`, never `false`.
* **The QR pin is mandatory.** `pairingVerifyResponse`'s `expectedQrPk` is the scanned QR `pk`, compared in constant time against `response.client_x25519_public_key` as the first check, with no "skip the pin" sentinel. A missing or wrong-length `expectedQrPk` throws instead of degrading to an unpinned comparison.
* **Temporal identifiers are 16 bytes for UDP/GATT and 10 bytes for the BLE advertisement.** `verifyTemporalIdentifier` accepts either length and rejects anything else; `extractTemporalIdentifier` and `decryptEncryptedPacket` accept only the 16-byte GATT form.
* **The two generator entry points take the 60-second _window_ (`unix_seconds / 60`), not a Unix timestamp.** Pass `currentTimeWindow()`; passing a timestamp silently produces an identifier no peer will match.

## 5. Structural Guard

`scripts/ci/check-jni-surface.sh` parses the `external fun` names out of `TapAuthCrypto.kt` and the `Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_*` exports out of `shared/src/jni_api.rs` (source text, not a built library, because the `initLogging` export is `cfg(target_os = "android")`) and requires set equality; it runs in the `Build and Test Workspace Modules` job. A Kotlin declaration with no Rust export therefore fails CI instead of throwing `UnsatisfiedLinkError` at device call time, and an export with no declaration fails instead of becoming dead code. It compares identifiers only, never signatures — that half of the contract is pinned by the JVM reflection test `server-android/app/src/test/java/dev/rourunisen/tapauth/crypto/JniDescriptorTest.kt`, which reflects the single constructor of each DTO and asserts the exact descriptor string above.

## 6. History

An earlier Kotlin-side redesign invented a stateless surface Rust never implemented — pairing functions taking explicit `H` / `K_c2s` / `K_s2c` slots, `createEncryptedPacket`, `pairingDecryptProvision`, and a 10-argument `AuthRequest` — which is why the set-equality guard exists. The reconciliation kept key material in Rust rather than moving it into Kotlin, because the stabilization plan requires Rust to stay the single source of truth for transcript hashing, HKDF, AAD construction and signatures; the handle-based pairing API and the three DTOs above are the surface that survived.
