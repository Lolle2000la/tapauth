use hkdf::Hkdf;
use sha2::Sha256;

use super::{CryptoError, PairingSymmetricKey};

/// Derive PSK from X25519 shared secret
pub fn derive_psk_from_x25519(
    shared_secret: &[u8; 32],
) -> Result<PairingSymmetricKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut psk = [0u8; 32];
    hk.expand(b"tapauth-pairing-key", &mut psk)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(PairingSymmetricKey::from_bytes(psk))
}

/// Derive Short Authentication String (SAS) as a 6-digit number
/// Input: client_public || server_public
pub fn derive_sas(
    psk: &PairingSymmetricKey,
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Result<String, CryptoError> {
    // Concatenate public keys
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(client_public);
    input[32..].copy_from_slice(server_public);

    let hk = Hkdf::<Sha256>::new(None, psk.as_bytes());
    let mut output = [0u8; 8];
    hk.expand_multi_info(&[b"tapauth-sas", &input], &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    // Convert to u64 and mod 1,000,000
    let value = u64::from_be_bytes(output);
    let sas_number = value % 1_000_000;

    // Format as 6-digit string with leading zeros
    Ok(format!("{:06}", sas_number))
}

/// Format SAS for display (e.g., "123-456")
pub fn format_sas(sas: &str) -> String {
    if sas.len() == 6 {
        format!("{}-{}", &sas[..3], &sas[3..])
    } else {
        sas.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_derivation() {
        let shared_secret = [1u8; 32];
        let psk = derive_psk_from_x25519(&shared_secret).unwrap();

        // Should be deterministic
        let psk2 = derive_psk_from_x25519(&shared_secret).unwrap();
        assert_eq!(psk.as_bytes(), psk2.as_bytes());
    }

    #[test]
    fn test_sas_derivation() {
        let psk = PairingSymmetricKey::from_bytes([2u8; 32]);
        let client_pub = [3u8; 32];
        let server_pub = [4u8; 32];

        let sas = derive_sas(&psk, &client_pub, &server_pub).unwrap();

        // Should be 6 digits
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));

        // Should be deterministic
        let sas2 = derive_sas(&psk, &client_pub, &server_pub).unwrap();
        assert_eq!(sas, sas2);
    }

    #[test]
    fn test_sas_formatting() {
        let sas = "123456";
        let formatted = format_sas(sas);
        assert_eq!(formatted, "123-456");
    }
}
