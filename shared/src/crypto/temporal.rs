use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{ClientSymmetricKey, CryptoError};

type HmacSha256 = Hmac<Sha256>;

/// Time window duration in seconds (60 seconds per window)
pub const TIME_WINDOW_SECONDS: u64 = 60;

/// Calculate current time window
pub fn current_time_window() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time before UNIX epoch");
    now.as_secs() / TIME_WINDOW_SECONDS
}

/// Generate temporal identifier for a given time window
/// Returns a 10-byte identifier (reduced from 16 to fit in BLE advertisement)
pub fn generate_temporal_identifier(
    csk: &ClientSymmetricKey,
    time_window: u64,
) -> Result<[u8; 10], CryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(csk.as_bytes()).map_err(|_| CryptoError::KeyDerivationFailed)?;

    mac.update(&time_window.to_be_bytes());

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut identifier = [0u8; 10];
    identifier.copy_from_slice(&bytes[..10]);

    Ok(identifier)
}

/// Generate temporal identifier for current time window
pub fn generate_current_temporal_identifier(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 10], CryptoError> {
    generate_temporal_identifier(csk, current_time_window())
}

/// Generate temporal identifier for previous time window
pub fn generate_previous_temporal_identifier(
    csk: &ClientSymmetricKey,
) -> Result<[u8; 10], CryptoError> {
    let window = current_time_window();
    if window == 0 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    generate_temporal_identifier(csk, window - 1)
}

/// Verify if a temporal identifier matches current or previous window
pub fn verify_temporal_identifier(
    csk: &ClientSymmetricKey,
    identifier: &[u8; 10],
) -> Result<bool, CryptoError> {
    let current = generate_current_temporal_identifier(csk)?;
    if identifier == &current {
        return Ok(true);
    }

    let previous = generate_previous_temporal_identifier(csk)?;
    Ok(identifier == &previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_window_calculation() {
        let window = current_time_window();
        // Should be a reasonable number (assuming test runs after 2020)
        assert!(window > 26_000_000);
    }

    #[test]
    fn test_temporal_identifier_generation() {
        let csk = ClientSymmetricKey::generate();
        let window = current_time_window();

        let id1 = generate_temporal_identifier(&csk, window).unwrap();
        let id2 = generate_temporal_identifier(&csk, window).unwrap();

        // Same window should produce same identifier
        assert_eq!(id1, id2);

        // Different window should produce different identifier
        let id3 = generate_temporal_identifier(&csk, window + 1).unwrap();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_temporal_identifier_verification() {
        let csk = ClientSymmetricKey::generate();
        let current_id = generate_current_temporal_identifier(&csk).unwrap();

        // Current identifier should verify
        assert!(verify_temporal_identifier(&csk, &current_id).unwrap());

        // Random identifier should not verify
        let random_id = [0u8; 10];
        assert!(!verify_temporal_identifier(&csk, &random_id).unwrap());
    }

    #[test]
    fn test_previous_identifier_verification() {
        let csk = ClientSymmetricKey::generate();

        // This test assumes we're not at time window 0
        if current_time_window() > 0 {
            let previous_id = generate_previous_temporal_identifier(&csk).unwrap();

            // Previous identifier should also verify
            assert!(verify_temporal_identifier(&csk, &previous_id).unwrap());
        }
    }
}
