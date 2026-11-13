use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;

use super::{ClientSymmetricKey, CryptoError};
use crate::protocol::pb::SymmetricAlgorithm;

/// Length of the CSPRNG nonce prepended to every AEAD ciphertext (both
/// AES-256-GCM and ChaCha20-Poly1305 use a 96-bit nonce).
const AEAD_NONCE_LEN: usize = 12;

/// Context string prefixed to the `EncryptedPacket` AAD
/// (cryptography-specification.md §3).
const ENCRYPTED_PACKET_AAD_PREFIX: &[u8] = b"tapauth-pkt-v2";

/// Encrypt data using AES-256-GCM
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt data using ChaCha20-Poly1305
fn encrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt data using ChaCha20-Poly1305
fn decrypt_chacha20_poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// AEAD encrypt with an explicit nonce, dispatching on the negotiated algorithm.
fn encrypt_with_alg(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        SymmetricAlgorithm::Aes256Gcm => encrypt_aes_gcm(key, nonce, plaintext, associated_data),
        SymmetricAlgorithm::Chacha20Poly1305 => {
            encrypt_chacha20_poly1305(key, nonce, plaintext, associated_data)
        }
        SymmetricAlgorithm::Unspecified => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// AEAD decrypt with an explicit nonce, dispatching on the negotiated algorithm.
fn decrypt_with_alg(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        SymmetricAlgorithm::Aes256Gcm => decrypt_aes_gcm(key, nonce, ciphertext, associated_data),
        SymmetricAlgorithm::Chacha20Poly1305 => {
            decrypt_chacha20_poly1305(key, nonce, ciphertext, associated_data)
        }
        SymmetricAlgorithm::Unspecified => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Build the associated data bound into the AEAD tag of an `EncryptedPacket`:
///
/// ```text
/// "tapauth-pkt-v2" || be32(encryption_algorithm as u32) || be16(len) || temporal_identifier
/// ```
///
/// (cryptography-specification.md §3). The header fields are committed to the tag
/// so a downgrade of the algorithm or a tampered temporal identifier fails
/// authentication before the inner payload is parsed.
pub fn encrypted_packet_aad(encryption_algorithm: i32, temporal_identifier: &[u8]) -> Vec<u8> {
    let identifier_len = u16::try_from(temporal_identifier.len()).unwrap_or(u16::MAX);

    let mut aad =
        Vec::with_capacity(ENCRYPTED_PACKET_AAD_PREFIX.len() + 4 + 2 + temporal_identifier.len());
    aad.extend_from_slice(ENCRYPTED_PACKET_AAD_PREFIX);
    aad.extend_from_slice(&(encryption_algorithm as u32).to_be_bytes());
    aad.extend_from_slice(&identifier_len.to_be_bytes());
    aad.extend_from_slice(temporal_identifier);
    aad
}

/// Encrypt `plaintext` with a fresh 12-byte CSPRNG nonce, prepended to
/// `ciphertext || tag`. The algorithm is dispatched on `alg`.
pub fn encrypt_aead_with_random_nonce(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;

    let ciphertext = encrypt_with_alg(alg, key, &nonce, plaintext, aad)?;

    let mut combined = Vec::with_capacity(AEAD_NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

/// Decrypt `nonce || ciphertext || tag` produced by
/// [`encrypt_aead_with_random_nonce`] (or [`encrypt_with_key`]).
pub fn decrypt_aead_with_prepended_nonce(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    combined: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (nonce, ciphertext) = split_prepended_nonce(combined)?;
    decrypt_with_alg(alg, key, &nonce, ciphertext, aad)
}

/// Split `nonce (12 bytes) || ciphertext || tag` into its nonce and ciphertext.
fn split_prepended_nonce(combined: &[u8]) -> Result<([u8; AEAD_NONCE_LEN], &[u8]), CryptoError> {
    let nonce_slice = combined
        .get(..AEAD_NONCE_LEN)
        .ok_or(CryptoError::DecryptionFailed)?;
    let nonce: [u8; AEAD_NONCE_LEN] = nonce_slice
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let ciphertext = combined
        .get(AEAD_NONCE_LEN..)
        .ok_or(CryptoError::DecryptionFailed)?;
    Ok((nonce, ciphertext))
}

/// Encrypt with the CSK using a random nonce (prepended to ciphertext), under
/// the negotiated algorithm, binding `aad` into the tag.
pub fn encrypt_with_csk_and_random_nonce(
    csk: &ClientSymmetricKey,
    alg: SymmetricAlgorithm,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_aead_with_random_nonce(alg, csk.as_bytes(), plaintext, aad)
}

/// Decrypt with the CSK where the random nonce is prepended to the ciphertext.
pub fn decrypt_with_csk_and_prepended_nonce(
    csk: &ClientSymmetricKey,
    alg: SymmetricAlgorithm,
    combined: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_aead_with_prepended_nonce(alg, csk.as_bytes(), combined, aad)
}

/// Encrypt with a pairing key (`K_c2s` / `K_s2c`) using a random nonce
/// (prepended to the ciphertext).
///
/// Empty AAD is forbidden in v2 (cryptography-specification.md §3): it rejects
/// with [`CryptoError::InvalidAad`] so a caller cannot silently drop the
/// transcript binding.
pub fn encrypt_with_key(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if aad.is_empty() {
        return Err(CryptoError::InvalidAad);
    }
    encrypt_aead_with_random_nonce(alg, key, plaintext, aad)
}

/// Decrypt with a pairing key (`K_c2s` / `K_s2c`) where the random nonce is
/// prepended to the ciphertext. Rejects empty AAD like [`encrypt_with_key`].
pub fn decrypt_with_key(
    alg: SymmetricAlgorithm,
    key: &[u8; 32],
    combined: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if aad.is_empty() {
        return Err(CryptoError::InvalidAad);
    }
    decrypt_aead_with_prepended_nonce(alg, key, combined, aad)
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

    fn random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("getrandom failed");
        key
    }

    #[test]
    fn test_aes_gcm_encryption() {
        let key = random_key();
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("getrandom failed");
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    /// Both negotiated algorithms must round-trip under a random prepended nonce.
    /// The defect this catches: the ChaCha20-Poly1305 dispatch missing, or
    /// dispatching to the AES cipher (which would fail to decrypt).
    #[test]
    fn test_aead_roundtrip_both_algorithms() {
        let key = random_key();
        let plaintext = b"v2 packet payload";
        let aad = b"aad context";

        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let combined = encrypt_aead_with_random_nonce(alg, &key, plaintext, aad).unwrap();
            // 12-byte nonce + ciphertext + 16-byte tag
            assert_eq!(combined.len(), 12 + plaintext.len() + 16);
            let decrypted = decrypt_aead_with_prepended_nonce(alg, &key, &combined, aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    /// Two encryptions of the same plaintext must differ (fresh random nonce).
    /// The defect this catches: a nonce derived from the key/plaintext instead
    /// of the CSPRNG, which would reuse nonces.
    #[test]
    fn test_random_nonce_uniqueness() {
        let key = random_key();
        let plaintext = b"same plaintext";

        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let first = encrypt_aead_with_random_nonce(alg, &key, plaintext, b"aad").unwrap();
            let second = encrypt_aead_with_random_nonce(alg, &key, plaintext, b"aad").unwrap();
            assert_ne!(first, second, "nonces must be fresh per encryption");
            assert_ne!(first.get(..12), second.get(..12));
        }
    }

    /// The AAD must actually be authenticated: decrypting with a different AAD
    /// fails. The defect this catches: `aad` being ignored (always `&[]`).
    #[test]
    fn test_aad_mismatch_fails() {
        let key = random_key();
        let plaintext = b"aad bound payload";

        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let combined =
                encrypt_aead_with_random_nonce(alg, &key, plaintext, b"header-a").unwrap();
            assert_eq!(
                decrypt_aead_with_prepended_nonce(alg, &key, &combined, b"header-a").unwrap(),
                plaintext
            );
            let err = decrypt_aead_with_prepended_nonce(alg, &key, &combined, b"header-b");
            assert!(matches!(err, Err(CryptoError::DecryptionFailed)));
        }
    }

    /// A flipped ciphertext byte must fail authentication.
    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = random_key();
        let plaintext = b"tamper me";

        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let mut combined =
                encrypt_aead_with_random_nonce(alg, &key, plaintext, b"aad").unwrap();
            // Flip a byte in the ciphertext body (after the 12-byte nonce).
            let index = 12 + 1;
            if let Some(byte) = combined.get_mut(index) {
                *byte ^= 0xFF;
            }
            let err = decrypt_aead_with_prepended_nonce(alg, &key, &combined, b"aad");
            assert!(matches!(err, Err(CryptoError::DecryptionFailed)));
        }
    }

    /// An unspecified algorithm must be rejected, never silently mapped to AES.
    #[test]
    fn test_unspecified_algorithm_rejected() {
        let key = random_key();
        assert!(matches!(
            encrypt_aead_with_random_nonce(SymmetricAlgorithm::Unspecified, &key, b"x", b"aad"),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            decrypt_aead_with_prepended_nonce(
                SymmetricAlgorithm::Unspecified,
                &key,
                &[0u8; 28],
                b"aad"
            ),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
        // Same through the CSK helpers.
        let csk = ClientSymmetricKey::from_bytes(key);
        assert!(matches!(
            encrypt_with_csk_and_random_nonce(&csk, SymmetricAlgorithm::Unspecified, b"x", b"aad"),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }

    /// Short input (less than the 12-byte nonce) is a decryption failure.
    #[test]
    fn test_short_input_rejected() {
        let key = random_key();
        for len in [0usize, 1, 11] {
            let short = vec![1u8; len];
            let err = decrypt_aead_with_prepended_nonce(
                SymmetricAlgorithm::Aes256Gcm,
                &key,
                &short,
                b"aad",
            );
            assert!(matches!(err, Err(CryptoError::DecryptionFailed)));
        }
    }

    /// Exact byte layout of the `EncryptedPacket` AAD, including the big-endian
    /// length field and a zero-length temporal identifier.
    /// The defect this catches: a little-endian or native-endian length field,
    /// a missing prefix, or a wrong algorithm encoding.
    #[test]
    fn test_encrypted_packet_aad_exact_layout() {
        // Zero-length temporal identifier: be16 length is 0x0000.
        let empty = encrypted_packet_aad(SymmetricAlgorithm::Aes256Gcm as i32, &[]);
        assert_eq!(empty, b"tapauth-pkt-v2\x00\x00\x00\x01\x00\x00".to_vec());

        // 16-byte temporal identifier: be16 length is 0x0010.
        let identifier = [0xABu8; 16];
        let aad = encrypted_packet_aad(SymmetricAlgorithm::Chacha20Poly1305 as i32, &identifier);
        assert_eq!(
            aad,
            b"tapauth-pkt-v2\x00\x00\x00\x02\x00\x10\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab".to_vec()
        );
        assert_eq!(aad.len(), 14 + 4 + 2 + 16);

        // The tag really covers the AAD: same key/nonce-free round trip with the
        // AAD matching, and a mismatched AAD failing.
        let key = random_key();
        let combined = encrypt_aead_with_random_nonce(
            SymmetricAlgorithm::Chacha20Poly1305,
            &key,
            b"packet",
            &aad,
        )
        .unwrap();
        assert!(decrypt_aead_with_prepended_nonce(
            SymmetricAlgorithm::Chacha20Poly1305,
            &key,
            &combined,
            &aad
        )
        .is_ok());
        let other_aad = encrypted_packet_aad(SymmetricAlgorithm::Aes256Gcm as i32, &identifier);
        assert!(decrypt_aead_with_prepended_nonce(
            SymmetricAlgorithm::Chacha20Poly1305,
            &key,
            &combined,
            &other_aad
        )
        .is_err());
    }

    /// CSK helpers round-trip with a prepended random nonce.
    #[test]
    fn test_csk_random_nonce_roundtrip() {
        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let csk = ClientSymmetricKey::generate().unwrap();
            let plaintext = b"hello csk random nonce";
            let aad = b"aad";

            let combined = encrypt_with_csk_and_random_nonce(&csk, alg, plaintext, aad).unwrap();
            let decrypted =
                decrypt_with_csk_and_prepended_nonce(&csk, alg, &combined, aad).unwrap();

            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    /// Pairing-key helpers must reject empty AAD.
    /// The defect this catches: the transcript context (`"tapauth-pair-v2-provision" || H`)
    /// silently dropped for the pairing channel.
    #[test]
    fn test_pairing_key_helpers_reject_empty_aad() {
        let key = random_key();
        let combined =
            encrypt_with_key(SymmetricAlgorithm::Aes256Gcm, &key, b"provision", b"ctx").unwrap();

        assert!(matches!(
            encrypt_with_key(SymmetricAlgorithm::Aes256Gcm, &key, b"provision", b""),
            Err(CryptoError::InvalidAad)
        ));
        assert!(matches!(
            decrypt_with_key(SymmetricAlgorithm::Aes256Gcm, &key, &combined, b""),
            Err(CryptoError::InvalidAad)
        ));

        // Non-empty AAD still round-trips.
        assert_eq!(
            decrypt_with_key(SymmetricAlgorithm::Aes256Gcm, &key, &combined, b"ctx").unwrap(),
            b"provision"
        );
    }

    /// Pairing-key helpers round-trip for both algorithms and per-direction keys.
    #[test]
    fn test_pairing_key_helpers_roundtrip() {
        for alg in [
            SymmetricAlgorithm::Aes256Gcm,
            SymmetricAlgorithm::Chacha20Poly1305,
        ] {
            let key = random_key();
            let other = random_key();
            let aad = b"tapauth-pair-v2-provision-and-hash";
            let combined = encrypt_with_key(alg, &key, b"csk-and-username", aad).unwrap();

            assert_eq!(
                decrypt_with_key(alg, &key, &combined, aad).unwrap(),
                b"csk-and-username"
            );
            // Wrong directional key must not decrypt.
            assert!(matches!(
                decrypt_with_key(alg, &other, &combined, aad),
                Err(CryptoError::DecryptionFailed)
            ));
        }
    }
}
