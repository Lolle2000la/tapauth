use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use crate::crypto;

/// JNI wrapper for generating a new Ed25519 keypair.
/// Returns the keypair as a hex-encoded string "private_key:public_key"
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let keypair = crypto::Ed25519KeyPair::generate();

    let private_hex = hex::encode(keypair.signing_key.to_bytes());
    let public_hex = hex::encode(keypair.verifying_key.to_bytes());
    let combined = format!("{}:{}", private_hex, public_hex);

    match env.new_string(combined) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for performing X25519 key exchange.
/// Returns the shared secret as hex-encoded string
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_keyExchange(
    mut env: JNIEnv,
    _class: JClass,
    our_private_key_hex: JString,
    their_public_key_hex: JString,
) -> jstring {
    let our_private: String = match env.get_string(&our_private_key_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 input: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let their_public: String = match env.get_string(&their_public_key_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 input: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let our_key_bytes = match hex::decode(our_private) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let their_key_bytes = match hex::decode(their_public) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Convert to fixed-size arrays
    let our_key_array: [u8; 32] = match our_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "private key must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    let their_key_array: [u8; 32] = match their_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "public key must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    // Perform key exchange
    let our_keypair = crypto::X25519KeyPair::from_secret_bytes(our_key_array);
    let shared_secret = match our_keypair.diffie_hellman(&their_key_array) {
        Ok(secret) => secret,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("key exchange failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let hex_result = hex::encode(shared_secret);

    match env.new_string(hex_result) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for generating the Short Authentication String (SAS).
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_getSas(
    mut env: JNIEnv,
    _class: JClass,
    psk_hex: JString,
    client_public: JByteArray,
    server_public: JByteArray,
) -> jstring {
    let psk_hex: String = match env.get_string(&psk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 input: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_bytes = match hex::decode(psk_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_array: [u8; 32] = match psk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "PSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let client_pub_bytes = match env.convert_byte_array(client_public) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read client_public: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let client_pub_array: [u8; 32] = match client_pub_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "client_public must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    let server_pub_bytes = match env.convert_byte_array(server_public) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read server_public: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let server_pub_array: [u8; 32] = match server_pub_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "server_public must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    let psk = crypto::keys::PairingSymmetricKey::from_bytes(psk_array);

    let sas = match crypto::kdf::derive_sas(&psk, &client_pub_array, &server_pub_array) {
        Ok(value) => value,
        Err(err) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", err.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(sas) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for decrypting with PSK (used during pairing to decrypt CSK).
/// Returns decrypted bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptWithPsk(
    mut env: JNIEnv,
    _class: JClass,
    psk_hex: JString,
    context: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    // Extract PSK
    let psk_hex: String = match env.get_string(&psk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in psk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_bytes = match hex::decode(psk_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in psk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_array: [u8; 32] = match psk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "PSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let psk = crypto::PairingSymmetricKey::from_bytes(psk_array);

    // Extract context
    let context_str: String = match env.get_string(&context) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in context: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract ciphertext
    let ciphertext_bytes = match env.convert_byte_array(ciphertext) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read ciphertext: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Decrypt
    let plaintext = match crypto::decrypt_with_psk(&psk, context_str.as_bytes(), &ciphertext_bytes)
    {
        Ok(data) => data,
        Err(err) => {
            let _ = env.throw_new(
                "javax/crypto/BadPaddingException",
                format!("decryption failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as byte array
    match env.byte_array_from_slice(&plaintext) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for encrypting with PSK (used during pairing to encrypt confirmation hash).
/// Returns encrypted bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_encryptWithPsk(
    mut env: JNIEnv,
    _class: JClass,
    psk_hex: JString,
    context: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    // Extract PSK
    let psk_hex: String = match env.get_string(&psk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in psk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_bytes = match hex::decode(psk_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in psk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let psk_array: [u8; 32] = match psk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "PSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let psk = crypto::PairingSymmetricKey::from_bytes(psk_array);

    // Extract context
    let context_str: String = match env.get_string(&context) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in context: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract plaintext
    let plaintext_bytes = match env.convert_byte_array(plaintext) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read plaintext: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Encrypt
    let ciphertext = match crypto::encrypt_with_psk(&psk, context_str.as_bytes(), &plaintext_bytes)
    {
        Ok(data) => data,
        Err(err) => {
            let _ = env.throw_new(
                "javax/crypto/IllegalBlockSizeException",
                format!("encryption failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as byte array
    match env.byte_array_from_slice(&ciphertext) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for computing SHA-256 hash.
/// Returns hex-encoded hash
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_sha256(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
) -> jstring {
    use sha2::{Digest, Sha256};

    // Extract data
    let data_bytes = match env.convert_byte_array(data) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read data: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(&data_bytes);
    let hash = hasher.finalize();

    let hex_hash = hex::encode(hash);

    // Return as string
    match env.new_string(hex_hash) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for decrypting and parsing an EncryptedPacket.
/// Returns JSON string with packet contents
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptAndParsePacket(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    packet_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use prost::Message;

    // Extract CSK
    let csk_hex_str: String = match env.get_string(&csk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(csk_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Extract packet bytes
    let packet_data = match env.convert_byte_array(packet_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read packet: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse EncryptedPacket
    let encrypted_packet = match pb::EncryptedPacket::decode(&packet_data[..]) {
        Ok(pkt) => pkt,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse packet: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Decrypt the inner message
    // TODO: This needs the challenge for nonce derivation
    // For now, we'll return the encrypted packet structure as JSON
    let json_result = match serde_json::to_string(&encrypted_packet) {
        Ok(json) => json,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    match env.new_string(json_result) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for parsing AuthenticationRequest from protobuf bytes.
/// Returns JSON string with request contents
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAuthRequest(
    mut env: JNIEnv,
    _class: JClass,
    request_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use prost::Message;

    // Extract request bytes
    let data = match env.convert_byte_array(request_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read request: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse AuthenticationRequest
    let auth_request = match pb::AuthenticationRequest::decode(&data[..]) {
        Ok(req) => req,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse request: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Serialize to JSON for easy parsing in Kotlin
    let json_result = match serde_json::to_string(&auth_request) {
        Ok(json) => json,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    match env.new_string(json_result) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for creating and serializing an AuthenticationGrant.
/// Returns protobuf-encoded bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createAuthGrant(
    mut env: JNIEnv,
    _class: JClass,
    signed_challenge: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract signed challenge
    let signed_challenge_bytes = match env.convert_byte_array(signed_challenge) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read signed_challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create AuthenticationGrant
    let grant = pb::AuthenticationGrant {
        signed_challenge: signed_challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![], // Will be filled by caller after signing
    };

    // Serialize to protobuf
    let mut buf = Vec::new();
    if let Err(err) = grant.encode(&mut buf) {
        let _ = env.throw_new(
            "java/io/IOException",
            format!("failed to encode grant: {err}"),
        );
        return std::ptr::null_mut();
    }

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for generating temporal identifier
/// Returns 16-byte identifier as hex string
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    timestamp_seconds: jlong,
) -> jstring {
    // Extract CSK
    let csk_hex_str: String = match env.get_string(&csk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(csk_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Calculate time window
    let time_window = (timestamp_seconds as u64) / crypto::temporal::TIME_WINDOW_SECONDS;

    // Generate temporal identifier
    let identifier = match crypto::temporal::generate_temporal_identifier(&csk, time_window) {
        Ok(id) => id,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to generate temporal ID: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Convert to hex string
    let hex_string = hex::encode(identifier);

    match env.new_string(hex_string) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for verifying temporal identifier
/// Returns true if identifier matches current or previous time window
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifyTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    id_hex: JString,
    csk_hex: JString,
) -> jboolean {
    // Extract identifier
    let id_hex_str: String = match env.get_string(&id_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in id: {err}"),
            );
            return false as jboolean;
        }
    };

    let id_bytes = match hex::decode(id_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in id: {err}"),
            );
            return false as jboolean;
        }
    };

    let id_array: [u8; 16] = match id_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "temporal ID must be 16 bytes",
            );
            return false as jboolean;
        }
    };

    // Extract CSK
    let csk_hex_str: String = match env.get_string(&csk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in csk: {err}"),
            );
            return false as jboolean;
        }
    };

    let csk_bytes = match hex::decode(csk_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in csk: {err}"),
            );
            return false as jboolean;
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return false as jboolean;
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Verify temporal identifier
    match crypto::temporal::verify_temporal_identifier(&csk, &id_array) {
        Ok(valid) => valid as jboolean,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to verify temporal ID: {err}"),
            );
            false as jboolean
        }
    }
}

/// JNI wrapper for encrypting with CSK using challenge-derived nonce
/// Returns encrypted bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_encryptWithCsk(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    challenge: JByteArray,
    context: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    // Extract CSK
    let csk_hex_str: String = match env.get_string(&csk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(csk_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    // Extract challenge
    let challenge_bytes = match env.convert_byte_array(challenge) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let challenge_array: [u8; 32] = match challenge_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "challenge must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    // Extract context
    let context_str: String = match env.get_string(&context) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in context: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract plaintext
    let plaintext_bytes = match env.convert_byte_array(plaintext) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read plaintext: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Encrypt
    let ciphertext = match crypto::encryption::encrypt_with_csk(
        &csk,
        &challenge_array,
        context_str.as_bytes(),
        &plaintext_bytes,
    ) {
        Ok(ct) => ct,
        Err(err) => {
            let _ = env.throw_new(
                "javax/crypto/AEADBadTagException",
                format!("encryption failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as byte array
    match env.byte_array_from_slice(&ciphertext) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for decrypting with CSK using challenge-derived nonce
/// Returns decrypted bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptWithCsk(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    challenge: JByteArray,
    context: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    // Extract CSK
    let csk_hex_str: String = match env.get_string(&csk_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(csk_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    // Extract challenge
    let challenge_bytes = match env.convert_byte_array(challenge) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let challenge_array: [u8; 32] = match challenge_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "challenge must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    // Extract context
    let context_str: String = match env.get_string(&context) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in context: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract ciphertext
    let ciphertext_bytes = match env.convert_byte_array(ciphertext) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read ciphertext: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Decrypt
    let plaintext = match crypto::encryption::decrypt_with_csk(
        &csk,
        &challenge_array,
        context_str.as_bytes(),
        &ciphertext_bytes,
    ) {
        Ok(pt) => pt,
        Err(err) => {
            let _ = env.throw_new(
                "javax/crypto/AEADBadTagException",
                format!("decryption failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as byte array
    match env.byte_array_from_slice(&plaintext) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for verifying Ed25519 signature.
/// Returns true if signature is valid
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifySignature(
    mut env: JNIEnv,
    _class: JClass,
    public_key: JByteArray,
    message: JByteArray,
    signature: JByteArray,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Extract public key
    let public_key_bytes = match env.convert_byte_array(public_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read public_key: {err}"),
            );
            return false;
        }
    };

    let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "public key must be 32 bytes",
            );
            return false;
        }
    };

    // Extract message
    let message_bytes = match env.convert_byte_array(message) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read message: {err}"),
            );
            return false;
        }
    };

    // Extract signature
    let signature_bytes = match env.convert_byte_array(signature) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read signature: {err}"),
            );
            return false;
        }
    };

    let signature_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "signature must be 64 bytes",
            );
            return false;
        }
    };

    // Verify signature
    let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
        Ok(key) => key,
        Err(err) => {
            let _ = env.throw_new(
                "java/security/InvalidKeyException",
                format!("invalid public key: {err}"),
            );
            return false;
        }
    };

    let signature = Signature::from_bytes(&signature_array);

    verifying_key.verify(&message_bytes, &signature).is_ok()
}

/// JNI wrapper for signing data with Ed25519 private key.
/// Returns signature bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_signData(
    mut env: JNIEnv,
    _class: JClass,
    private_key_hex: JString,
    message: JByteArray,
) -> jbyteArray {
    use ed25519_dalek::{Signer, SigningKey};

    // Extract private key
    let private_key_hex_str: String = match env.get_string(&private_key_hex) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in private_key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let private_key_bytes = match hex::decode(private_key_hex_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid hex in private_key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let private_key_array: [u8; 32] = match private_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                "private key must be 32 bytes",
            );
            return std::ptr::null_mut();
        }
    };

    // Extract message
    let message_bytes = match env.convert_byte_array(message) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Sign message
    let signing_key = SigningKey::from_bytes(&private_key_array);
    let signature = signing_key.sign(&message_bytes);

    // Return signature as byte array
    match env.byte_array_from_slice(&signature.to_bytes()) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for serializing AuthenticationRequest for signature verification.
/// Returns the serialized request with signature field empty
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_serializeAuthRequestForVerification(
    mut env: JNIEnv,
    _class: JClass,
    request_json: JString,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Parse JSON back to AuthenticationRequest
    let json_str: String = match env.get_string(&request_json) {
        Ok(value) => value.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid UTF-8 in json: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let mut auth_request: pb::AuthenticationRequest = match serde_json::from_str(&json_str) {
        Ok(req) => req,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Clear the signature field (set to empty for verification)
    auth_request.signature = vec![];

    // Serialize to protobuf
    let mut buf = Vec::new();
    if let Err(err) = auth_request.encode(&mut buf) {
        let _ = env.throw_new(
            "java/io/IOException",
            format!("failed to encode request: {err}"),
        );
        return std::ptr::null_mut();
    }

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Parse a GrantConfirmation protobuf message and return as JSON
///
/// Takes raw protobuf bytes and returns a JSON representation:
/// {
///   "challenge": "base64...",
///   "signature_algorithm": 1,
///   "signature": "base64..."
/// }
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseGrantConfirmation(
    mut env: JNIEnv,
    _class: JClass,
    confirmation_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use prost::Message;

    // Convert from jbyteArray to Rust Vec<u8>
    let bytes = match env.convert_byte_array(confirmation_bytes) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Decode the protobuf GrantConfirmation
    let confirmation = match pb::GrantConfirmation::decode(&bytes[..]) {
        Ok(conf) => conf,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse GrantConfirmation protobuf: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Convert to JSON
    let json_str = match serde_json::to_string(&confirmation) {
        Ok(s) => s,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as Java String
    match env.new_string(&json_str) {
        Ok(jstr) => jstr.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create java string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Parse an AuthenticationCancel protobuf message and return as JSON
///
/// Takes raw protobuf bytes and returns a JSON representation:
/// {
///   "challenge": "base64...",
///   "signature_algorithm": 1,
///   "signature": "base64..."
/// }
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseAuthenticationCancel(
    mut env: JNIEnv,
    _class: JClass,
    cancel_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use prost::Message;

    // Convert from jbyteArray to Rust Vec<u8>
    let bytes = match env.convert_byte_array(cancel_bytes) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Decode the protobuf AuthenticationCancel
    let cancel = match pb::AuthenticationCancel::decode(&bytes[..]) {
        Ok(c) => c,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse AuthenticationCancel protobuf: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Convert to JSON
    let json_str = match serde_json::to_string(&cancel) {
        Ok(s) => s,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as Java String
    match env.new_string(&json_str) {
        Ok(jstr) => jstr.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create java string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Create a WrapperMessage containing an AuthenticationGrant
///
/// @param signedChallenge The signed challenge bytes
/// @return Serialized WrapperMessage protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createGrantWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    signed_challenge: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Get signed challenge bytes
    let signed_challenge_bytes = match env.convert_byte_array(signed_challenge) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read signed challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create AuthenticationGrant
    let grant = pb::AuthenticationGrant {
        signed_challenge: signed_challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![], // Will be filled by caller if needed
    };

    // Create WrapperMessage
    let wrapper = pb::WrapperMessage {
        version: 1,
        payload: Some(pb::wrapper_message::Payload::AuthGrant(grant)),
    };

    // Serialize to protobuf
    let mut buf = Vec::new();
    if let Err(err) = wrapper.encode(&mut buf) {
        let _ = env.throw_new(
            "java/io/IOException",
            format!("failed to encode WrapperMessage: {err}"),
        );
        return std::ptr::null_mut();
    }

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Create an EncryptedPacket from a WrapperMessage payload
///
/// @param cskHex Client Symmetric Key (hex) for encryption and temporal ID  
/// @param wrapperMessageBytes Serialized WrapperMessage protobuf
/// @return Serialized EncryptedPacket protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    wrapper_message_bytes: JByteArray,
) -> jbyteArray {
    use crate::crypto;
    use crate::protocol::pb;
    use hkdf::Hkdf;
    use prost::Message;
    use sha2::Sha256;

    // Parse CSK from hex
    let csk_str: String = match env.get_string(&csk_hex) {
        Ok(s) => s.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid CSK hex string: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(&csk_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid CSK hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Get WrapperMessage bytes
    let payload = match env.convert_byte_array(wrapper_message_bytes) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read wrapper message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Derive nonce from CSK for EncryptedPacket encryption
    // Per spec, each EncryptedPacket uses a unique nonce derived from CSK
    let hk = Hkdf::<Sha256>::new(None, csk.as_bytes());
    let mut nonce = [0u8; 12];
    if hk.expand(b"encrypted_packet_nonce", &mut nonce).is_err() {
        let _ = env.throw_new(
            "java/security/GeneralSecurityException",
            "nonce derivation failed",
        );
        return std::ptr::null_mut();
    }

    // Encrypt the WrapperMessage with CSK
    let ciphertext =
        match crypto::encryption::encrypt_aes_gcm(csk.as_bytes(), &nonce, &payload, &[]) {
            Ok(ct) => ct,
            Err(err) => {
                let _ = env.throw_new(
                    "java/security/GeneralSecurityException",
                    format!("encryption failed: {err}"),
                );
                return std::ptr::null_mut();
            }
        };

    // Generate temporal identifier for current time window
    let temporal_id = match crypto::temporal::generate_current_temporal_identifier(&csk) {
        Ok(id) => id,
        Err(err) => {
            let _ = env.throw_new(
                "java/security/GeneralSecurityException",
                format!("temporal ID generation failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create EncryptedPacket
    let encrypted_packet = pb::EncryptedPacket {
        temporal_identifier: temporal_id.to_vec(),
        encryption_algorithm: pb::SymmetricAlgorithm::Aes256Gcm as i32,
        ciphertext,
    };

    // Serialize to protobuf
    let mut buf = Vec::new();
    if let Err(err) = encrypted_packet.encode(&mut buf) {
        let _ = env.throw_new(
            "java/io/IOException",
            format!("failed to encode EncryptedPacket: {err}"),
        );
        return std::ptr::null_mut();
    }

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Decrypt and parse an EncryptedPacket to get the WrapperMessage
///
/// @param cskHex Client Symmetric Key (hex) for decryption
/// @param encryptedPacketBytes Serialized EncryptedPacket protobuf
/// @return Serialized WrapperMessage protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk_hex: JString,
    encrypted_packet_bytes: JByteArray,
) -> jbyteArray {
    use crate::crypto;
    use crate::protocol::pb;
    use hkdf::Hkdf;
    use prost::Message;
    use sha2::Sha256;

    // Parse CSK from hex
    let csk_str: String = match env.get_string(&csk_hex) {
        Ok(s) => s.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid CSK hex string: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_bytes = match hex::decode(&csk_str) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("invalid CSK hex: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let csk_array: [u8; 32] = match csk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "CSK must be 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let csk = crypto::ClientSymmetricKey::from_bytes(csk_array);

    // Get EncryptedPacket bytes
    let packet_bytes = match env.convert_byte_array(encrypted_packet_bytes) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read encrypted packet: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse EncryptedPacket
    let encrypted_packet = match pb::EncryptedPacket::decode(&packet_bytes[..]) {
        Ok(pkt) => pkt,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to decode EncryptedPacket: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Derive same nonce used for encryption
    let hk = Hkdf::<Sha256>::new(None, csk.as_bytes());
    let mut nonce = [0u8; 12];
    if hk.expand(b"encrypted_packet_nonce", &mut nonce).is_err() {
        let _ = env.throw_new(
            "java/security/GeneralSecurityException",
            "nonce derivation failed",
        );
        return std::ptr::null_mut();
    }

    // Decrypt the ciphertext
    let wrapper_bytes = match crypto::encryption::decrypt_aes_gcm(
        csk.as_bytes(),
        &nonce,
        &encrypted_packet.ciphertext,
        &[],
    ) {
        Ok(plaintext) => plaintext,
        Err(err) => {
            let _ = env.throw_new(
                "java/security/GeneralSecurityException",
                format!("decryption failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return decrypted WrapperMessage bytes
    match env.byte_array_from_slice(&wrapper_bytes) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

// ========== Pairing Protocol Message Functions ==========

/// JNI wrapper for creating and serializing a PairingHello message.
/// Returns protobuf-encoded bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingHello(
    mut env: JNIEnv,
    _class: JClass,
    version: jint,
    x25519_public_key: JByteArray,
    ed25519_public_key: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract X25519 public key
    let x25519_bytes = match env.convert_byte_array(x25519_public_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read x25519_public_key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract Ed25519 public key
    let ed25519_bytes = match env.convert_byte_array(ed25519_public_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read ed25519_public_key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create PairingHello
    let hello = pb::PairingHello {
        version: version as u32,
        x25519_public_key: x25519_bytes,
        ed25519_public_key: ed25519_bytes,
    };

    // Serialize to protobuf
    let buf = hello.encode_to_vec();

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for parsing a PairingResponse message from protobuf bytes.
/// Returns JSON string with response contents: {"version": 1, "x25519_public_key": "base64...", "ed25519_public_key": "base64..."}
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingResponse(
    mut env: JNIEnv,
    _class: JClass,
    response_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use prost::Message;

    // Extract response bytes
    let data = match env.convert_byte_array(response_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read response: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse PairingResponse
    let response = match pb::PairingResponse::decode(&data[..]) {
        Ok(resp) => resp,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse PairingResponse: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create JSON with base64-encoded keys
    let json_result = serde_json::json!({
        "version": response.version,
        "x25519_public_key": BASE64.encode(&response.x25519_public_key),
        "ed25519_public_key": BASE64.encode(&response.ed25519_public_key),
    });

    let json_str = match serde_json::to_string(&json_result) {
        Ok(s) => s,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    match env.new_string(json_str) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for creating and serializing a PairingCskMessage.
/// Returns protobuf-encoded bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_csk: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract encrypted CSK
    let encrypted_csk_bytes = match env.convert_byte_array(encrypted_csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read encrypted_csk: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create PairingCskMessage
    let csk_msg = pb::PairingCskMessage {
        encrypted_csk: encrypted_csk_bytes,
    };

    // Serialize to protobuf
    let buf = csk_msg.encode_to_vec();

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for parsing a PairingCskMessage from protobuf bytes.
/// Returns the encrypted CSK bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    message_bytes: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract message bytes
    let data = match env.convert_byte_array(message_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse PairingCskMessage
    let csk_msg = match pb::PairingCskMessage::decode(&data[..]) {
        Ok(msg) => msg,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse PairingCskMessage: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return encrypted CSK as byte array
    match env.byte_array_from_slice(&csk_msg.encrypted_csk) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for creating a PairingComplete message.
/// Returns protobuf-encoded bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingComplete(
    mut env: JNIEnv,
    _class: JClass,
    success: jboolean,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Create PairingComplete
    let complete = pb::PairingComplete {
        success: success != 0,
    };

    // Serialize to protobuf
    let buf = complete.encode_to_vec();

    // Return as byte array
    match env.byte_array_from_slice(&buf) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for parsing a PairingComplete message from protobuf bytes.
/// Returns JSON string: {"success": true/false}
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingComplete(
    mut env: JNIEnv,
    _class: JClass,
    complete_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use prost::Message;

    // Extract complete bytes
    let data = match env.convert_byte_array(complete_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read complete message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse PairingComplete
    let complete = match pb::PairingComplete::decode(&data[..]) {
        Ok(msg) => msg,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse PairingComplete: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create JSON
    let json_result = serde_json::json!({
        "success": complete.success,
    });

    let json_str = match serde_json::to_string(&json_result) {
        Ok(s) => s,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    match env.new_string(json_str) {
        Ok(output) => output.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate string: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}
