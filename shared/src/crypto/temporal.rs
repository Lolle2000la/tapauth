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

    /// The SHA-256 temporal identifier is exactly
    /// `HMAC-SHA256(csk, be64(window))` truncated to 16 bytes (and to 10 for the
    /// BLE form), deterministic and keyed — it is the only construction the
    /// negotiated path has.
    /// The defect this catches: a different truncation, a little-endian window
    /// encoding, a non-keyed digest, or the identifier not depending on the CSK.
    #[test]
    fn test_sha256_temporal_identifiers() {
        let csk = ClientSymmetricKey::from_bytes([7u8; 32]);
        let window = 41_000_000u64;

        let id16 = generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        assert_eq!(id16.len(), 16);
        assert_eq!(
            id16,
            generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap(),
            "must be deterministic"
        );

        let mut mac = HmacSha256::new_from_slice(csk.as_bytes()).unwrap();
        mac.update(&window.to_be_bytes());
        let expected = mac.finalize().into_bytes();
        assert_eq!(id16.as_slice(), expected.get(..16).unwrap());

        let id10 = generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        assert_eq!(id10.len(), 10);
        assert_eq!(id10.as_slice(), expected.get(..10).unwrap());

        // A different window and a different CSK both change the identifier.
        assert_ne!(
            id16,
            generate_temporal_id_with_alg(&csk, window + 1, HashAlgorithm::Sha256).unwrap()
        );
        let other_csk = ClientSymmetricKey::from_bytes([8u8; 32]);
        assert_ne!(
            id16,
            generate_temporal_id_with_alg(&other_csk, window, HashAlgorithm::Sha256).unwrap()
        );
    }

    /// SHA-256 verification accepts the current and previous window's identifier
    /// and rejects an older one.
    /// The defect this catches: a replay window wider than 60 s (an old identifier
    /// still verifying) or a window that drops the tolerated previous one (a client
    /// clock one window behind is locked out).
    #[test]
    fn test_sha256_verification_window() {
        let csk = ClientSymmetricKey::generate().unwrap();
        let window = current_time_window().unwrap();
        assert!(window > 1, "system clock may be broken");

        let current = generate_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        assert!(
            verify_temporal_identifier_with_alg(&csk, &current, HashAlgorithm::Sha256).unwrap()
        );

        let previous =
            generate_temporal_id_with_alg(&csk, window - 1, HashAlgorithm::Sha256).unwrap();
        assert!(
            verify_temporal_identifier_with_alg(&csk, &previous, HashAlgorithm::Sha256).unwrap()
        );

        let stale = generate_temporal_id_with_alg(&csk, window - 2, HashAlgorithm::Sha256).unwrap();
        assert!(!verify_temporal_identifier_with_alg(&csk, &stale, HashAlgorithm::Sha256).unwrap());

        // The BLE form follows the same window.
        let ble_current =
            generate_ble_temporal_id_with_alg(&csk, window, HashAlgorithm::Sha256).unwrap();
        assert!(
            verify_ble_temporal_identifier_with_alg(&csk, &ble_current, HashAlgorithm::Sha256)
                .unwrap()
        );

        // A wrong CSK never matches.
        let other_csk = ClientSymmetricKey::from_bytes([8u8; 32]);
        assert!(
            !verify_temporal_identifier_with_alg(&other_csk, &current, HashAlgorithm::Sha256)
                .unwrap()
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
