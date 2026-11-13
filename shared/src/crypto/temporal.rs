use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::{ClientSymmetricKey, CryptoError};
use crate::protocol::pb::HashAlgorithm;

type HmacSha256 = Hmac<Sha256>;

/// Time window duration in seconds (60 seconds per window)
pub const TIME_WINDOW_SECONDS: u64 = 60;

/// Context string prefixed to the BLE pairing advertisement identifier
/// (initial-key-exchange.md Step 1, ble-gatt-specification.md §1).
const BLE_PAIRING_ADV_ID_PREFIX: &[u8] = b"tapauth-ble-pair-v2";

/// Calculate current time window
pub fn current_time_window() -> Result<u64, CryptoError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CryptoError::SystemTimeError)?;
    Ok(now.as_secs() / TIME_WINDOW_SECONDS)
}

/// Derive the keyed MAC of the time window using the negotiated hash algorithm.
///
/// `SHA256` is HMAC-SHA256, `BLAKE3` is keyed BLAKE3
/// (cryptography-specification.md §1). The full 32-byte MAC is returned; callers
/// truncate it to the identifier length they need.
fn keyed_window_mac(
    csk: &ClientSymmetricKey,
    window: u64,
    alg: HashAlgorithm,
) -> Result<[u8; 32], CryptoError> {
    let window_bytes = window.to_be_bytes();

    match alg {
        HashAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(csk.as_bytes())
                .map_err(|_| CryptoError::KeyDerivationFailed)?;
            mac.update(&window_bytes);
            Ok(mac.finalize().into_bytes().into())
        }
        HashAlgorithm::Blake3 => Ok(*blake3::keyed_hash(csk.as_bytes(), &window_bytes).as_bytes()),
        HashAlgorithm::Unspecified => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Generate a temporal identifier for a given time window and hash algorithm.
///
/// Returns a 16-byte identifier (the keyed MAC truncated to 16 bytes).
pub fn generate_temporal_id_with_alg(
    csk: &ClientSymmetricKey,
    window: u64,
    alg: HashAlgorithm,
) -> Result<[u8; 16], CryptoError> {
    let mac = keyed_window_mac(csk, window, alg)?;
    let mut identifier = [0u8; 16];
    let slice = mac.get(..16).ok_or(CryptoError::KeyDerivationFailed)?;
    identifier.copy_from_slice(slice);
    Ok(identifier)
}

/// Generate a BLE temporal identifier (10 bytes to fit the BLE advertisement
/// budget) for a given time window and hash algorithm.
pub fn generate_ble_temporal_id_with_alg(
    csk: &ClientSymmetricKey,
    window: u64,
    alg: HashAlgorithm,
) -> Result<[u8; 10], CryptoError> {
    let mac = keyed_window_mac(csk, window, alg)?;
    let mut identifier = [0u8; 10];
    let slice = mac.get(..10).ok_or(CryptoError::KeyDerivationFailed)?;
    identifier.copy_from_slice(slice);
    Ok(identifier)
}

/// Generate temporal identifier for a given time window (HMAC-SHA256, the
/// SHA-256 default).
pub fn generate_temporal_identifier(
    csk: &ClientSymmetricKey,
    time_window: u64,
) -> Result<[u8; 16], CryptoError> {
    generate_temporal_id_with_alg(csk, time_window, HashAlgorithm::Sha256)
}

/// Generate temporal identifier for BLE advertisement (10 bytes to fit in 31-byte BLE limit)
pub fn generate_temporal_identifier_ble(
    csk: &ClientSymmetricKey,
    time_window: u64,
) -> Result<[u8; 10], CryptoError> {
    generate_ble_temporal_id_with_alg(csk, time_window, HashAlgorithm::Sha256)
}

/// Generate temporal identifier for the current time window with the negotiated
/// hash algorithm.
pub fn generate_current_temporal_identifier_with_alg(
    csk: &ClientSymmetricKey,
    alg: HashAlgorithm,
) -> Result<[u8; 16], CryptoError> {
    generate_temporal_id_with_alg(csk, current_time_window()?, alg)
}

/// Generate the BLE temporal identifier (10 bytes) for the current time window
/// with the negotiated hash algorithm.
pub fn generate_current_ble_temporal_identifier_with_alg(
    csk: &ClientSymmetricKey,
    alg: HashAlgorithm,
) -> Result<[u8; 10], CryptoError> {
    generate_ble_temporal_id_with_alg(csk, current_time_window()?, alg)
}

/// Generate temporal identifier for current time window
pub fn generate_current_temporal_identifier(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 16], CryptoError> {
    generate_current_temporal_identifier_with_alg(csk, HashAlgorithm::Sha256)
}

/// Generate temporal identifier for BLE advertisement (current window, 10 bytes)
pub fn generate_current_temporal_identifier_ble(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 10], CryptoError> {
    generate_current_ble_temporal_identifier_with_alg(csk, HashAlgorithm::Sha256)
}

/// Generate temporal identifier for previous time window
pub fn generate_previous_temporal_identifier(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 16], CryptoError> {
    let window = current_time_window()?;
    if window == 0 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    generate_temporal_identifier(csk, window - 1)
}

/// Generate temporal identifier for BLE advertisement (previous window, 10 bytes)
pub fn generate_previous_temporal_identifier_ble(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 10], CryptoError> {
    let window = current_time_window()?;
    if window == 0 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    generate_temporal_identifier_ble(csk, window - 1)
}

/// Verify a temporal identifier against the current and previous window using
/// the negotiated hash algorithm.
pub fn verify_temporal_identifier_with_alg(
    csk: &ClientSymmetricKey,
    identifier: &[u8; 16],
    alg: HashAlgorithm,
) -> Result<bool, CryptoError> {
    let window = current_time_window()?;

    if *identifier == generate_temporal_id_with_alg(csk, window, alg)? {
        return Ok(true);
    }

    if window == 0 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    Ok(*identifier == generate_temporal_id_with_alg(csk, window - 1, alg)?)
}

/// Verify a BLE temporal identifier (10 bytes) against the current and previous
/// window using the negotiated hash algorithm.
pub fn verify_ble_temporal_identifier_with_alg(
    csk: &ClientSymmetricKey,
    identifier: &[u8; 10],
    alg: HashAlgorithm,
) -> Result<bool, CryptoError> {
    let window = current_time_window()?;

    if *identifier == generate_ble_temporal_id_with_alg(csk, window, alg)? {
        return Ok(true);
    }

    if window == 0 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    Ok(*identifier == generate_ble_temporal_id_with_alg(csk, window - 1, alg)?)
}

/// Verify if a temporal identifier matches current or previous window
pub fn verify_temporal_identifier(
    csk: &ClientSymmetricKey,
    identifier: &[u8; 16],
) -> Result<bool, CryptoError> {
    verify_temporal_identifier_with_alg(csk, identifier, HashAlgorithm::Sha256)
}

/// Verify if a BLE temporal identifier (10 bytes) matches current or previous window
pub fn verify_temporal_identifier_ble(
    csk: &ClientSymmetricKey,
    identifier: &[u8; 10],
) -> Result<bool, CryptoError> {
    verify_ble_temporal_identifier_with_alg(csk, identifier, HashAlgorithm::Sha256)
}

/// Compute the 10-byte BLE pairing advertisement identifier:
///
/// ```text
/// SHA-256("tapauth-ble-pair-v2" || session_id || client_x25519_pub)[..10]
/// ```
///
/// `session_id` is the raw 16-byte QR `sid`, with no length prefix
/// (initial-key-exchange.md Step 1, ble-gatt-specification.md §1).
pub fn derive_ble_pairing_adv_id(session_id: &[u8], client_x25519_pub: &[u8; 32]) -> [u8; 10] {
    let mut hasher = Sha256::new();
    hasher.update(BLE_PAIRING_ADV_ID_PREFIX);
    hasher.update(session_id);
    hasher.update(client_x25519_pub);
    let digest = hasher.finalize();

    let mut identifier = [0u8; 10];
    if let Some(slice) = digest.get(..10) {
        identifier.copy_from_slice(slice);
    }
    identifier
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_time_window_calculation() {
        let window = current_time_window().unwrap();
        // Should be a reasonable number (assuming test runs after 2020)
        assert!(window > 26_000_000);
    }

    #[test]
    fn test_temporal_identifier_generation() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let window = current_time_window().unwrap();

        let id1 = generate_temporal_identifier(&csk, window).unwrap();
        let id2 = generate_temporal_identifier(&csk, window).unwrap();

        // Same window should produce same identifier
        assert_eq!(id1, id2);

        // Different window should produce different identifier
        let id3 = generate_temporal_identifier(&csk, window + 1).unwrap();
        assert_ne!(id1, id3);
    }

    /// The SHA-256 default wrappers must produce exactly what the explicit
    /// `_with_alg(.., Sha256)` path produces — v1 wire output is unchanged.
    /// The defect this catches: the wrapper drifting to a different truncation,
    /// input encoding (e.g. LE window) or MAC construction than the negotiated path.
    #[test]
    fn test_sha256_defaults_match_with_alg() {
        let csk = ClientSymmetricKey::from_bytes([7u8; 32]);
        let window = 41_000_000u64;

        assert_eq!(
            generate_temporal_identifier(&csk, window).unwrap(),
            generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap()
        );
        assert_eq!(
            generate_temporal_identifier_ble(&csk, window).unwrap(),
            generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap()
        );

        // And it really is HMAC-SHA256(csk, be64(window)) truncated to 16 bytes.
        let mut mac = HmacSha256::new_from_slice(csk.as_bytes()).unwrap();
        mac.update(&window.to_be_bytes());
        let expected = mac.finalize().into_bytes();
        assert_eq!(
            generate_temporal_identifier(&csk, window)
                .unwrap()
                .as_slice(),
            expected.get(..16).unwrap()
        );
    }

    /// BLAKE3 must be a different keyed MAC from HMAC-SHA256, deterministic, and
    /// truncated to 16 / 10 bytes.
    /// The defect this catches: BLAKE3 silently falling back to SHA-256 (all
    /// paired Servers using BLAKE3 would never match) or emitting the wrong length.
    #[test]
    fn test_blake3_temporal_identifiers() {
        let csk = ClientSymmetricKey::from_bytes([9u8; 32]);
        let window = 41_000_001u64;

        let sha16 = generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        let blake16 = generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Blake3).unwrap();
        assert_eq!(blake16.len(), 16);
        assert_ne!(blake16, sha16);
        // Deterministic.
        assert_eq!(
            blake16,
            generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Blake3).unwrap()
        );
        // Exactly keyed_blake3(csk, be64(window)) truncated to 16 bytes.
        let expected = blake3::keyed_hash(csk.as_bytes(), &window.to_be_bytes());
        assert_eq!(blake16.as_slice(), expected.as_bytes().get(..16).unwrap());

        let sha10 = generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        let blake10 =
            generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Blake3).unwrap();
        assert_eq!(blake10.len(), 10);
        assert_ne!(blake10, sha10);
        assert_eq!(blake10.as_slice(), expected.as_bytes().get(..10).unwrap());

        // A different window changes the BLAKE3 identifier.
        assert_ne!(
            blake16,
            generate_temporal_id_with_alg(&csk, window + 1, HashAlgorithm::Blake3).unwrap()
        );
    }

    /// `UNSPECIFIED` (and therefore any unknown algorithm) must be rejected
    /// rather than defaulting to a hash.
    #[test]
    fn test_unspecified_hash_algorithm_rejected() {
        let csk = ClientSymmetricKey::from_bytes([1u8; 32]);
        assert!(matches!(
            generate_temporal_id_with_alg(&csk, 1, HashAlgorithm::Unspecified),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            generate_ble_temporal_id_with_alg(&csk, 1, HashAlgorithm::Unspecified),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            verify_temporal_identifier_with_alg(&csk, &[0u8; 16], HashAlgorithm::Unspecified),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            verify_ble_temporal_identifier_with_alg(&csk, &[0u8; 10], HashAlgorithm::Unspecified),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }

    /// BLAKE3 verification accepts the current window's identifier and rejects an
    /// identifier from two windows ago — the same replay window as SHA-256.
    #[test]
    fn test_blake3_verification_window() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let window = current_time_window().unwrap();
        assert!(window > 1, "system clock may be broken");

        let current = generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Blake3).unwrap();
        assert!(
            verify_temporal_identifier_with_alg(&csk, &current, HashAlgorithm::Blake3).unwrap()
        );

        let previous =
            generate_temporal_id_with_alg(&csk, window - 1, HashAlgorithm::Blake3).unwrap();
        assert!(
            verify_temporal_identifier_with_alg(&csk, &previous, HashAlgorithm::Blake3).unwrap()
        );

        let stale = generate_temporal_id_with_alg(&csk, window - 2, HashAlgorithm::Blake3).unwrap();
        assert!(!verify_temporal_identifier_with_alg(&csk, &stale, HashAlgorithm::Blake3).unwrap());

        let ble_current =
            generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Blake3).unwrap();
        assert!(
            verify_ble_temporal_identifier_with_alg(&csk, &ble_current, HashAlgorithm::Blake3)
                .unwrap()
        );
    }

    #[test]
    fn test_temporal_identifier_verification() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let current_id = generate_current_temporal_identifier(&csk).unwrap();

        // Current identifier should verify
        assert!(verify_temporal_identifier(&csk, &current_id).unwrap());

        // Random identifier should not verify
        let random_id = [0u8; 16];
        assert!(!verify_temporal_identifier(&csk, &random_id).unwrap());
    }

    #[test]
    fn test_previous_identifier_verification() {
        let csk = ClientSymmetricKey::generate().unwrap();

        let window = current_time_window().unwrap();
        assert!(
            window > 0,
            "time window is zero - system clock may be broken"
        );

        let previous_id = generate_previous_temporal_identifier(&csk).unwrap();

        // Previous identifier should also verify
        assert!(verify_temporal_identifier(&csk, &previous_id).unwrap());
    }

    #[test]
    fn test_different_csk_produces_different_identifier() {
        let csk1 = ClientSymmetricKey::generate().unwrap();
        let csk2 = ClientSymmetricKey::generate().unwrap();
        let window = current_time_window().unwrap();

        let id1 = generate_temporal_identifier(&csk1, window).unwrap();
        let id2 = generate_temporal_identifier(&csk2, window).unwrap();

        // Different keys should produce different identifiers
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_temporal_identifier_length() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let id = generate_current_temporal_identifier(&csk).unwrap();

        // Should be exactly 16 bytes
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let csk1 = ClientSymmetricKey::generate().unwrap();
        let csk2 = ClientSymmetricKey::generate().unwrap();

        let id = generate_current_temporal_identifier(&csk1).unwrap();

        // Verification with wrong key should fail
        assert!(!verify_temporal_identifier(&csk2, &id).unwrap());
    }

    #[test]
    fn test_old_identifier_does_not_verify() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let current_window = current_time_window().unwrap();

        // Generate identifier from 2 windows ago
        if current_window > 1 {
            let old_id = generate_temporal_identifier(&csk, current_window - 2).unwrap();

            // Should not verify (only current and previous are accepted)
            assert!(!verify_temporal_identifier(&csk, &old_id).unwrap());
        }
    }

    /// The BLE pairing advertisement identifier is a plain SHA-256 (not keyed),
    /// deterministic, 10 bytes, and changes when either input changes.
    /// The defect this catches: a wrong context string, a length-prefixed
    /// session id, swapped inputs, or a non-truncated output.
    #[test]
    fn test_ble_pairing_adv_id() {
        let session_id = [0x11u8; 16];
        let public_key = [0x22u8; 32];

        let id = derive_ble_pairing_adv_id(&session_id, &public_key);
        assert_eq!(id.len(), 10);
        assert_eq!(
            id,
            derive_ble_pairing_adv_id(&session_id, &public_key),
            "must be deterministic"
        );

        // Exactly SHA-256("tapauth-ble-pair-v2" || sid || pk)[..10].
        let mut hasher = Sha256::new();
        hasher.update(b"tapauth-ble-pair-v2");
        hasher.update(session_id);
        hasher.update(public_key);
        let expected = hasher.finalize();
        assert_eq!(id.as_slice(), expected.get(..10).unwrap());

        // Changing the session id changes the identifier.
        let mut other_session = session_id;
        other_session[0] ^= 0x01;
        assert_ne!(id, derive_ble_pairing_adv_id(&other_session, &public_key));

        // Changing the public key changes the identifier.
        let mut other_key = public_key;
        other_key[31] ^= 0x01;
        assert_ne!(id, derive_ble_pairing_adv_id(&session_id, &other_key));

        // A full 16-byte session id and a differently sized one are distinct
        // inputs (raw bytes, no length prefix): padding vs. truncation differ.
        assert_ne!(
            id,
            derive_ble_pairing_adv_id(&session_id[..15], &public_key),
            "session id length participates in the hash"
        );
    }
}
