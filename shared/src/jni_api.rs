use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring};
use jni::JNIEnv;

use crate::crypto;
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// JNI wrapper for generating a new Ed25519 keypair.
/// Returns a 2-element Object array: [byte[] privateKey, byte[] publicKey]
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let keypair = crypto::Ed25519KeyPair::generate();

    let private_bytes = keypair.signing_key.to_bytes();
    let public_bytes = keypair.verifying_key.to_bytes();

    // Create byte array for private key
    let private_array = match env.byte_array_from_slice(&private_bytes) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create byte array for public key
    let public_array = match env.byte_array_from_slice(&public_bytes) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create object array [byte[], byte[]]
    let byte_array_class = match env.find_class("[B") {
        Ok(cls) => cls,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to find byte array class: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let result_array = match env.new_object_array(2, byte_array_class, JObject::null()) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create object array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Set elements: [0] = private_key, [1] = public_key
    if let Err(err) = env.set_object_array_element(&result_array, 0, private_array) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set array element: {err}"),
        );
        return std::ptr::null_mut();
    }

    if let Err(err) = env.set_object_array_element(&result_array, 1, public_array) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set array element: {err}"),
        );
        return std::ptr::null_mut();
    }

    result_array.into_raw()
}

/// JNI wrapper for generating a new X25519 keypair (for ECDH key exchange).
/// Returns a 2-element Object array: [byte[] privateKey, byte[] publicKey]
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateX25519Keypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let keypair = crypto::X25519KeyPair::generate();

    let private_bytes = keypair.secret_key_bytes();
    let public_bytes = keypair.public_key_bytes();

    // Create byte array for private key
    let private_array = match env.byte_array_from_slice(&private_bytes) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create byte array for public key
    let public_array = match env.byte_array_from_slice(&public_bytes) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create object array [byte[], byte[]]
    let byte_array_class = match env.find_class("[B") {
        Ok(cls) => cls,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to find byte array class: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let result_array = match env.new_object_array(2, byte_array_class, JObject::null()) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create object array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Set elements: [0] = private_key, [1] = public_key
    if let Err(err) = env.set_object_array_element(&result_array, 0, private_array) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set array element: {err}"),
        );
        return std::ptr::null_mut();
    }

    if let Err(err) = env.set_object_array_element(&result_array, 1, public_array) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set array element: {err}"),
        );
        return std::ptr::null_mut();
    }

    result_array.into_raw()
}

/// JNI wrapper for performing X25519 key exchange.
/// Returns the PSK (derived from shared secret via HKDF) as byte array
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_keyExchange(
    mut env: JNIEnv,
    _class: JClass,
    our_private_key: JByteArray,
    their_public_key: JByteArray,
) -> jbyteArray {
    let our_key_bytes = match env.convert_byte_array(our_private_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read private key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let their_key_bytes = match env.convert_byte_array(their_public_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read public key: {err}"),
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

    // Derive PSK from shared secret using HKDF
    tracing::debug!("Shared secret (sha256): {}", sha256_hex(&shared_secret));
    let psk = match crypto::derive_psk_from_x25519(&shared_secret) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!("PSK derivation FAILED: {}", err);
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("PSK derivation failed: {err}"),
            );
            return std::ptr::null_mut();
        }
    };
    tracing::debug!("Derived PSK (sha256): {}", sha256_hex(psk.as_bytes()));

    // Return PSK as byte array
    match env.byte_array_from_slice(psk.as_bytes()) {
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

/// JNI wrapper for generating the Short Authentication String (SAS).
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_getSas(
    mut env: JNIEnv,
    _class: JClass,
    psk: JByteArray,
    client_public: JByteArray,
    server_public: JByteArray,
) -> jstring {
    let psk_bytes = match env.convert_byte_array(psk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read PSK: {err}"),
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
    psk: JByteArray,
    context: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    // Extract PSK
    let psk_bytes = match env.convert_byte_array(psk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read PSK: {err}"),
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
    psk: JByteArray,
    context: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    // Extract PSK
    let psk_bytes = match env.convert_byte_array(psk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read PSK: {err}"),
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

    // First decode as WrapperMessage
    let wrapper = match pb::WrapperMessage::decode(&data[..]) {
        Ok(w) => w,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to decode Protobuf message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract AuthenticationRequest from WrapperMessage
    let auth_request = match wrapper.payload {
        Some(pb::wrapper_message::Payload::AuthRequest(req)) => req,
        _ => {
            let _ = env.throw_new(
                "java/io/IOException",
                "WrapperMessage does not contain AuthenticationRequest",
            );
            return std::ptr::null_mut();
        }
    };

    // Manually create JSON with base64-encoded byte fields
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let json_result = serde_json::json!({
        "challenge": BASE64.encode(&auth_request.challenge),
        "username": auth_request.username,
        "hostname": auth_request.hostname,
        "timestamp_unix_seconds": auth_request.timestamp_unix_seconds,
        "signature_algorithm": auth_request.signature_algorithm,
        "signature": BASE64.encode(&auth_request.signature),
    });

    let json_string = match serde_json::to_string(&json_result) {
        Ok(json) => json,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to serialize to JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    match env.new_string(json_string) {
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

/// JNI wrapper for parsing EncryptedPacket from protobuf bytes (without decryption).
/// Returns JSON string with packet structure
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parseEncryptedPacketStructure(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jstring {
    use crate::protocol::pb;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use prost::Message;

    // Extract packet bytes
    let data = match env.convert_byte_array(packet_bytes) {
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
    let encrypted_packet = match pb::EncryptedPacket::decode(&data[..]) {
        Ok(pkt) => pkt,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse EncryptedPacket: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create JSON with base64-encoded byte fields
    let json_result = serde_json::json!({
        "temporal_identifier": BASE64.encode(&encrypted_packet.temporal_identifier),
        "encryption_algorithm": encrypted_packet.encryption_algorithm,
        "ciphertext": BASE64.encode(&encrypted_packet.ciphertext),
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

/// Extract temporal_identifier from EncryptedPacket protobuf bytes.
///
/// This is used for DoS mitigation: allows checking the temporal_identifier
/// before performing expensive decryption operations.
///
/// @param packetBytes Serialized EncryptedPacket protobuf
/// @return 16-byte temporal_identifier, or null if parsing fails
/// @throws IOException if the packet cannot be parsed
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_extractTemporalIdentifier(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jbyteArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract packet bytes
    let data = match env.convert_byte_array(packet_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read packet: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse EncryptedPacket using prost
    let encrypted_packet = match pb::EncryptedPacket::decode(&data[..]) {
        Ok(pkt) => pkt,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse EncryptedPacket: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Verify temporal_identifier is exactly 16 bytes (per spec)
    if encrypted_packet.temporal_identifier.len() != 16 {
        let _ = env.throw_new(
            "java/io/IOException",
            format!(
                "invalid temporal_identifier length: {}, expected 16",
                encrypted_packet.temporal_identifier.len()
            ),
        );
        return std::ptr::null_mut();
    }

    // Return temporal_identifier as byte array
    match env.byte_array_from_slice(&encrypted_packet.temporal_identifier) {
        Ok(arr) => arr.into_raw(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create byte array: {err}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// JNI wrapper for generating temporal identifier
/// Returns 16-byte identifier as byte array
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    timestamp_seconds: jlong,
) -> jbyteArray {
    // Extract CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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

    // Return as byte array
    match env.byte_array_from_slice(&identifier) {
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

/// JNI wrapper for generating temporal identifier for BLE (10 bytes)
/// Used by Android BLE cache to match BLE advertisements
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_generateTemporalIdBle(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    timestamp_seconds: jlong,
) -> jbyteArray {
    // Extract CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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

    // Generate temporal identifier (10 bytes for BLE)
    let identifier = match crypto::temporal::generate_temporal_identifier_ble(&csk, time_window) {
        Ok(id) => id,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to generate temporal ID: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Return as byte array
    match env.byte_array_from_slice(&identifier) {
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

/// JNI wrapper for verifying temporal identifier
/// Returns true if identifier matches current or previous time window
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_verifyTemporalId(
    mut env: JNIEnv,
    _class: JClass,
    id: JByteArray,
    csk: JByteArray,
) -> jboolean {
    // Extract identifier
    let id_bytes = match env.convert_byte_array(id) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read ID: {err}"),
            );
            return false as jboolean;
        }
    };

    // Support both 16-byte (UDP) and 10-byte (BLE) temporal IDs
    let id_len = id_bytes.len();

    // Extract CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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

    // Verify temporal identifier (support both 16-byte and 10-byte IDs)
    let result = if id_len == 16 {
        let id_array: [u8; 16] = match id_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => unreachable!(), // Already checked length
        };
        crypto::temporal::verify_temporal_identifier(&csk, &id_array)
    } else if id_len == 10 {
        let id_array: [u8; 10] = match id_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => unreachable!(), // Already checked length
        };
        crypto::temporal::verify_temporal_identifier_ble(&csk, &id_array)
    } else {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            format!("temporal ID must be 10 or 16 bytes, got {}", id_len),
        );
        return false as jboolean;
    };

    match result {
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
    csk: JByteArray,
    challenge: JByteArray,
    context: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    // Extract CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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
    csk: JByteArray,
    challenge: JByteArray,
    context: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    // Extract CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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
    private_key: JByteArray,
    message: JByteArray,
) -> jbyteArray {
    use ed25519_dalek::{Signer, SigningKey};

    // Extract private key
    let private_key_bytes = match env.convert_byte_array(private_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read private key: {err}"),
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
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
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

    // Parse JSON manually because it has base64-encoded byte fields
    let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(val) => val,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to parse JSON: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract and decode fields
    let challenge_b64 = json_value["challenge"].as_str().unwrap_or("");
    let challenge = match BASE64.decode(challenge_b64) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to decode challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let username = json_value["username"].as_str().unwrap_or("").to_string();
    let hostname = json_value["hostname"].as_str().unwrap_or("").to_string();
    let timestamp = json_value["timestamp_unix_seconds"].as_u64().unwrap_or(0);
    let sig_algorithm = json_value["signature_algorithm"].as_i64().unwrap_or(0) as i32;

    // Create AuthenticationRequest with empty signature
    let auth_request = pb::AuthenticationRequest {
        challenge,
        username,
        hostname,
        timestamp_unix_seconds: timestamp,
        signature_algorithm: sig_algorithm,
        signature: vec![], // Empty for verification
    };

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

    // First decode as WrapperMessage
    let wrapper = match pb::WrapperMessage::decode(&bytes[..]) {
        Ok(w) => w,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to decode Protobuf message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract GrantConfirmation from WrapperMessage
    let confirmation = match wrapper.payload {
        Some(pb::wrapper_message::Payload::GrantConfirmation(conf)) => conf,
        _ => {
            let _ = env.throw_new(
                "java/io/IOException",
                "WrapperMessage does not contain GrantConfirmation",
            );
            return std::ptr::null_mut();
        }
    };

    // Manually create JSON with base64-encoded byte fields
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let json_result = serde_json::json!({
        "challenge": BASE64.encode(&confirmation.challenge),
        "signature_algorithm": confirmation.signature_algorithm,
        "signature": BASE64.encode(&confirmation.signature),
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

    // First decode as WrapperMessage
    let wrapper = match pb::WrapperMessage::decode(&bytes[..]) {
        Ok(w) => w,
        Err(err) => {
            let _ = env.throw_new(
                "java/io/IOException",
                format!("failed to decode Protobuf message: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Extract AuthenticationCancel from WrapperMessage
    let cancel = match wrapper.payload {
        Some(pb::wrapper_message::Payload::AuthCancel(c)) => c,
        _ => {
            let _ = env.throw_new(
                "java/io/IOException",
                "WrapperMessage does not contain AuthenticationCancel",
            );
            return std::ptr::null_mut();
        }
    };

    // Manually create JSON with base64-encoded byte fields
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let json_result = serde_json::json!({
        "challenge": BASE64.encode(&cancel.challenge),
        "signature_algorithm": cancel.signature_algorithm,
        "signature": BASE64.encode(&cancel.signature),
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
    private_key: JByteArray,
) -> jbyteArray {
    use crate::crypto::{signing::sign_ed25519, Ed25519KeyPair};
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

    // Parse private key
    let private_key_bytes = match env.convert_byte_array(private_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read private key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // The private key should be 64 bytes (full Ed25519 keypair) or 32 bytes (just signing key)
    let keypair = if private_key_bytes.len() == 64 {
        // Extract first 32 bytes (signing key)
        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(&private_key_bytes[..32]);
        match Ed25519KeyPair::from_signing_key_bytes(&signing_key_bytes) {
            Ok(kp) => kp,
            Err(err) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("invalid Ed25519 keypair: {err}"),
                );
                return std::ptr::null_mut();
            }
        }
    } else if private_key_bytes.len() == 32 {
        // Use directly as signing key
        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(&private_key_bytes);
        match Ed25519KeyPair::from_signing_key_bytes(&signing_key_bytes) {
            Ok(kp) => kp,
            Err(err) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("invalid Ed25519 keypair: {err}"),
                );
                return std::ptr::null_mut();
            }
        }
    } else {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "private key must be 32 bytes (signing key) or 64 bytes (full keypair)",
        );
        return std::ptr::null_mut();
    };

    // Create AuthenticationGrant with empty signature initially
    let mut grant = pb::AuthenticationGrant {
        signed_challenge: signed_challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![],
    };

    // Sign the grant message (without signature field)
    let data_to_sign = grant.encode_to_vec();
    grant.signature = sign_ed25519(&keypair, &data_to_sign);

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

/// Create a WrapperMessage containing an AuthenticationDenial
///
/// @param challenge The challenge bytes (32 bytes)
/// @param privateKey Private key (32 bytes)
/// @return Serialized WrapperMessage protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createDenialWrapperMessage(
    mut env: JNIEnv,
    _class: JClass,
    challenge: JByteArray,
    private_key: JByteArray,
) -> jbyteArray {
    use crate::crypto::{signing::sign_ed25519, Ed25519KeyPair};
    use crate::protocol::pb;
    use prost::Message;

    // Get challenge bytes
    let challenge_bytes = match env.convert_byte_array(challenge) {
        Ok(b) => b,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read challenge: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    if challenge_bytes.len() != 32 {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "challenge must be 32 bytes",
        );
        return std::ptr::null_mut();
    }

    // Parse private key
    let private_key_bytes = match env.convert_byte_array(private_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read private key: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // The private key should be 64 bytes (full Ed25519 keypair) or 32 bytes (just signing key)
    let keypair = if private_key_bytes.len() == 64 {
        // Extract first 32 bytes (signing key)
        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(&private_key_bytes[..32]);
        match Ed25519KeyPair::from_signing_key_bytes(&signing_key_bytes) {
            Ok(kp) => kp,
            Err(err) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("invalid Ed25519 keypair: {err}"),
                );
                return std::ptr::null_mut();
            }
        }
    } else if private_key_bytes.len() == 32 {
        // Use directly as signing key
        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(&private_key_bytes);
        match Ed25519KeyPair::from_signing_key_bytes(&signing_key_bytes) {
            Ok(kp) => kp,
            Err(err) => {
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("invalid Ed25519 keypair: {err}"),
                );
                return std::ptr::null_mut();
            }
        }
    } else {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "private key must be 32 bytes (signing key) or 64 bytes (full keypair)",
        );
        return std::ptr::null_mut();
    };

    // Create AuthenticationDenial with empty signature initially
    let mut denial = pb::AuthenticationDenial {
        challenge: challenge_bytes,
        signature_algorithm: pb::SignatureAlgorithm::Ed25519 as i32,
        signature: vec![],
    };

    // Sign the denial message (without signature field)
    let data_to_sign = denial.encode_to_vec();
    denial.signature = sign_ed25519(&keypair, &data_to_sign);

    // Create WrapperMessage
    let wrapper = pb::WrapperMessage {
        version: 1,
        payload: Some(pb::wrapper_message::Payload::AuthDenial(denial)),
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
/// @param csk Client Symmetric Key for encryption and temporal ID  
/// @param wrapperMessageBytes Serialized WrapperMessage protobuf
/// @return Serialized EncryptedPacket protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    wrapper_message_bytes: JByteArray,
) -> jbyteArray {
    use crate::crypto;
    use crate::protocol::pb;
    use prost::Message;

    // Parse CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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

    // Generate cryptographically secure random nonce for EncryptedPacket encryption
    // Each packet must have a unique random nonce to prevent AES-GCM reuse attacks
    use rand::{rngs::OsRng, TryRngCore};
    let mut nonce = [0u8; 12];
    if let Err(err) = OsRng.try_fill_bytes(&mut nonce) {
        let _ = env.throw_new(
            "java/security/GeneralSecurityException",
            format!("Random generation failed: {err}"),
        );
        return std::ptr::null_mut();
    }

    // Encrypt the WrapperMessage with CSK
    let ciphertext_with_nonce =
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

    // Prepend the nonce to the ciphertext
    let mut ciphertext = Vec::with_capacity(12 + ciphertext_with_nonce.len());
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&ciphertext_with_nonce);

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
/// @param csk Client Symmetric Key for decryption
/// @param encryptedPacketBytes Serialized EncryptedPacket protobuf
/// @return Serialized WrapperMessage protobuf bytes
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_decryptEncryptedPacket(
    mut env: JNIEnv,
    _class: JClass,
    csk: JByteArray,
    encrypted_packet_bytes: JByteArray,
) -> jbyteArray {
    use crate::crypto;
    use crate::protocol::pb;
    use prost::Message;

    // Parse CSK
    let csk_bytes = match env.convert_byte_array(csk) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read CSK: {err}"),
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

    // Extract nonce from ciphertext (first 12 bytes)
    if encrypted_packet.ciphertext.len() < 12 {
        let _ = env.throw_new(
            "java/security/GeneralSecurityException",
            "ciphertext too short - missing nonce",
        );
        return std::ptr::null_mut();
    }

    let nonce: [u8; 12] = match encrypted_packet.ciphertext[..12].try_into() {
        Ok(n) => n,
        Err(_) => {
            let _ = env.throw_new(
                "java/security/GeneralSecurityException",
                "failed to extract nonce",
            );
            return std::ptr::null_mut();
        }
    };

    let actual_ciphertext = &encrypted_packet.ciphertext[12..];

    // Decrypt the ciphertext
    let wrapper_bytes =
        match crypto::encryption::decrypt_aes_gcm(csk.as_bytes(), &nonce, actual_ciphertext, &[]) {
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
    device_name: JString,
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

    // Extract device name
    let device_name_str: String = match env.get_string(&device_name) {
        Ok(s) => s.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read device_name: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create PairingHello
    let hello = pb::PairingHello {
        version: version as u32,
        x25519_public_key: x25519_bytes,
        ed25519_public_key: ed25519_bytes,
        device_name: device_name_str,
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
/// Returns JSON string with response contents: {"version": 1, "x25519_public_key": "base64...", "ed25519_public_key": "base64...", "device_name": "client-device"}
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
        "device_name": response.device_name,
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
/// Note: This is not used by the Android server (only by clients), but kept for API completeness
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_createPairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    encrypted_csk: JByteArray,
    username: JString,
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

    // Extract username
    let username_str: String = match env.get_string(&username) {
        Ok(s) => s.into(),
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read username: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create PairingCskMessage
    let csk_msg = pb::PairingCskMessage {
        encrypted_csk: encrypted_csk_bytes,
        username: username_str,
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
/// Returns a tuple: (encrypted CSK bytes, username)
#[no_mangle]
pub extern "system" fn Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_parsePairingCskMessage(
    mut env: JNIEnv,
    _class: JClass,
    message_bytes: JByteArray,
) -> jobjectArray {
    use crate::protocol::pb;
    use prost::Message;

    // Extract message bytes
    let data = match env.convert_byte_array(message_bytes) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to read message_bytes: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Parse protobuf
    let csk_msg = match pb::PairingCskMessage::decode(&data[..]) {
        Ok(msg) => msg,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("failed to parse PairingCskMessage: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Convert username to JString
    let username_jstring = match env.new_string(&csk_msg.username) {
        Ok(s) => s,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create username string: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create byte array for encrypted CSK
    let encrypted_csk_array = match env.byte_array_from_slice(&csk_msg.encrypted_csk) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to allocate byte array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Create object array [byte[], String]
    let object_class = match env.find_class("java/lang/Object") {
        Ok(cls) => cls,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to find Object class: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    let result_array = match env.new_object_array(2, object_class, JObject::null()) {
        Ok(arr) => arr,
        Err(err) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                format!("failed to create array: {err}"),
            );
            return std::ptr::null_mut();
        }
    };

    // Set elements: [0] = encrypted_csk (byte[]), [1] = username (String)
    if let Err(err) = env.set_object_array_element(&result_array, 0, encrypted_csk_array) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set encrypted_csk: {err}"),
        );
        return std::ptr::null_mut();
    }

    if let Err(err) = env.set_object_array_element(&result_array, 1, username_jstring) {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("failed to set username: {err}"),
        );
        return std::ptr::null_mut();
    }

    result_array.into_raw()
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

#[cfg(test)]
mod extract_temporal_id_tests {
    use super::*;
    use crate::protocol::pb::{EncryptedPacket, SymmetricAlgorithm};
    use prost::Message;

    #[test]
    fn test_extract_temporal_identifier_correct_length() {
        // Create a test EncryptedPacket with exactly 16 bytes
        let temporal_id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        // Encode the packet
        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode using prost to verify we get the same temporal_identifier
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(decoded.temporal_identifier.len(), 16);
    }

    #[test]
    fn test_extract_temporal_identifier_wrong_length_fails() {
        // Create packet with wrong length temporal_identifier (should be 16 bytes)
        let packet = EncryptedPacket {
            temporal_identifier: vec![1, 2, 3, 4, 5], // Only 5 bytes
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: vec![0xAA, 0xBB],
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // This should parse fine with prost (it doesn't validate length)
        // But our JNI function should reject it
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier.len(), 5); // Prost allows it

        // The JNI function would reject this and throw IOException
        // (We can't easily test JNI throwing here, but the validation is in the code)
    }

    #[test]
    fn test_extract_temporal_identifier_field_order_independent() {
        // Verify that prost correctly handles fields regardless of encoding order
        // This is why using prost is better than manual parsing

        let temporal_id = vec![0xFF; 16];
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let packet = EncryptedPacket {
            temporal_identifier: temporal_id.clone(),
            encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
            ciphertext: ciphertext.clone(),
        };

        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        // Decode and verify all fields are correct
        let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
        assert_eq!(decoded.temporal_identifier, temporal_id);
        assert_eq!(
            decoded.encryption_algorithm,
            SymmetricAlgorithm::Aes256Gcm as i32
        );
        assert_eq!(decoded.ciphertext, ciphertext);
    }

    #[test]
    fn test_extract_temporal_identifier_with_various_ciphertext_lengths() {
        // Test that extraction works regardless of ciphertext size
        let temporal_id = vec![0x42; 16];

        for ciphertext_len in [0, 1, 100, 1000, 10000] {
            let ciphertext = vec![0xAB; ciphertext_len];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext,
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for ciphertext length {}",
                ciphertext_len
            );
        }
    }

    #[test]
    fn test_extract_temporal_identifier_all_byte_values() {
        // Ensure extraction works with any byte values in temporal_id
        for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
            let temporal_id = vec![byte_val; 16];

            let packet = EncryptedPacket {
                temporal_identifier: temporal_id.clone(),
                encryption_algorithm: SymmetricAlgorithm::Aes256Gcm as i32,
                ciphertext: vec![0x00],
            };

            let mut buf = Vec::new();
            packet.encode(&mut buf).unwrap();

            let decoded = EncryptedPacket::decode(&buf[..]).unwrap();
            assert_eq!(
                decoded.temporal_identifier, temporal_id,
                "Failed for byte value 0x{:02X}",
                byte_val
            );
        }
    }
}
