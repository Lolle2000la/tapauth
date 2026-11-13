use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{CryptoError, PairingSymmetricKey};
use crate::protocol::pb::{HashAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};

type HmacSha256 = Hmac<Sha256>;

/// Context string prefixed to the pairing transcript hash
/// (cryptography-specification.md §2.2).
const PAIRING_TRANSCRIPT_PREFIX: &[u8] = b"tapauth-pair-transcript-v2";

/// HKDF `info` strings for the directional pairing keys and the SAS
/// (cryptography-specification.md §2.2 steps 2-4).
const HKDF_INFO_C2S: &[u8] = b"tapauth-pair-v2-c2s";
const HKDF_INFO_S2C: &[u8] = b"tapauth-pair-v2-s2c";
const HKDF_INFO_SAS: &[u8] = b"tapauth-pair-v2-sas";

/// Context string prefixed to the pairing abort MAC
/// (initial-key-exchange.md Step 4, proto `PairingAbort.auth_tag`).
const PAIRING_ABORT_PREFIX: &[u8] = b"tapauth-pair-v2-abort";

/// Every security-relevant pairing handshake parameter that is committed into
/// the transcript hash `H` (cryptography-specification.md §2.2).
#[derive(Debug, Clone, Copy)]
pub struct PairingTranscript<'a> {
    pub version: u32,
    pub session_id: &'a [u8],
    pub client_x25519_public_key: &'a [u8; 32],
    pub server_x25519_public_key: &'a [u8; 32],
    pub client_ed25519_public_key: &'a [u8; 32],
    pub server_ed25519_public_key: &'a [u8; 32],
    pub client_device_name: &'a str,
    pub server_device_name: &'a str,
    pub supported_symmetric: &'a [SymmetricAlgorithm],
    pub supported_hash: &'a [HashAlgorithm],
    pub supported_signature: &'a [SignatureAlgorithm],
    pub selected_symmetric: SymmetricAlgorithm,
    pub selected_hash: HashAlgorithm,
    pub selected_signature: SignatureAlgorithm,
}

/// Append `be32(len) || bytes` for a UTF-8 device name.
fn push_length_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Append `be32(n) || [be32(alg), ...]` for an algorithm list.
fn push_algorithm_list<T: Copy + Into<i32>>(out: &mut Vec<u8>, algorithms: &[T]) {
    out.extend_from_slice(&(algorithms.len() as u32).to_be_bytes());
    for algorithm in algorithms {
        let encoded: i32 = (*algorithm).into();
        out.extend_from_slice(&encoded.to_be_bytes());
    }
}

/// Compute the canonical pairing transcript hash `H`:
///
/// ```text
/// SHA-256("tapauth-pair-transcript-v2" || be32(version) || session_id
///         || X_C(32) || X_S(32) || Ed_C(32) || Ed_S(32)
///         || be32(len) || client_device_name || be32(len) || server_device_name
///         || be32(n) || [be32(alg)…]   (supported symmetric)
///         || be32(n) || [be32(alg)…]   (supported hash)
///         || be32(n) || [be32(alg)…]   (supported signature)
///         || be32(selected_symmetric) || be32(selected_hash) || be32(selected_signature))
/// ```
///
/// The device-name lengths are UTF-8 **byte** lengths, matching the contract in
/// cryptography-specification.md §2.2.
pub fn compute_pairing_transcript_hash(t: &PairingTranscript<'_>) -> [u8; 32] {
    let mut out = Vec::with_capacity(256);

    out.extend_from_slice(PAIRING_TRANSCRIPT_PREFIX);
    out.extend_from_slice(&t.version.to_be_bytes());
    out.extend_from_slice(t.session_id);
    out.extend_from_slice(t.client_x25519_public_key);
    out.extend_from_slice(t.server_x25519_public_key);
    out.extend_from_slice(t.client_ed25519_public_key);
    out.extend_from_slice(t.server_ed25519_public_key);
    push_length_prefixed_bytes(&mut out, t.client_device_name.as_bytes());
    push_length_prefixed_bytes(&mut out, t.server_device_name.as_bytes());
    push_algorithm_list(&mut out, t.supported_symmetric);
    push_algorithm_list(&mut out, t.supported_hash);
    push_algorithm_list(&mut out, t.supported_signature);
    out.extend_from_slice(&i32::from(t.selected_symmetric).to_be_bytes());
    out.extend_from_slice(&i32::from(t.selected_hash).to_be_bytes());
    out.extend_from_slice(&i32::from(t.selected_signature).to_be_bytes());

    let digest = Sha256::digest(&out);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

/// Ephemeral pairing session material derived from the X25519 shared secret `Z`
/// and the transcript hash `H` (cryptography-specification.md §2.2).
pub struct PairingSessionKeys {
    /// Encrypts Client -> Server pairing messages (and the Client `PairingAbort` MAC).
    pub k_c2s: Zeroizing<[u8; 32]>,
    /// Encrypts Server -> Client pairing messages (and the Server `PairingAbort` MAC).
    pub k_s2c: Zeroizing<[u8; 32]>,
    /// Short Authentication String in display form, exactly `"123-456"`.
    pub sas: String,
}

/// Derive `K_c2s`, `K_s2c` and the SAS from the X25519 shared secret and the
/// transcript hash:
///
/// 1. reject an all-zero shared secret (constant-time compare) with
///    [`CryptoError::InvalidKeyLength`];
/// 2. `HKDF-Extract(salt = H, IKM = Z)` and expand the three `info` strings.
pub fn derive_pairing_keys_and_sas(
    shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<PairingSessionKeys, CryptoError> {
    // Constant-time: never branch on the secret's bytes.
    let is_zero: bool = shared_secret.ct_eq(&[0u8; 32]).into();
    if is_zero {
        return Err(CryptoError::InvalidKeyLength);
    }

    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);

    let mut k_c2s = [0u8; 32];
    hk.expand(HKDF_INFO_C2S, &mut k_c2s)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut k_s2c = [0u8; 32];
    hk.expand(HKDF_INFO_S2C, &mut k_s2c)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut sas_bytes = [0u8; 8];
    hk.expand(HKDF_INFO_SAS, &mut sas_bytes)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let sas_number = u64::from_be_bytes(sas_bytes) % 1_000_000;
    let sas = format!("{:03}-{:03}", sas_number / 1000, sas_number % 1000);

    Ok(PairingSessionKeys {
        k_c2s: Zeroizing::new(k_c2s),
        k_s2c: Zeroizing::new(k_s2c),
        sas,
    })
}

/// Compute the pairing abort authentication tag:
///
/// ```text
/// HMAC-SHA256(key = k_dir, msg = "tapauth-pair-v2-abort" || H || be32(reason))
/// ```
///
/// Returns the full 32-byte MAC (proto comment on `PairingAbort.auth_tag`).
pub fn compute_pairing_abort_tag(
    k_dir: &[u8; 32],
    transcript_hash: &[u8; 32],
    reason: i32,
) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(k_dir) else {
        // HMAC accepts keys of any length, so this is unreachable; returning a
        // zero tag keeps the function infallible without panicking.
        return [0u8; 32];
    };
    mac.update(PAIRING_ABORT_PREFIX);
    mac.update(transcript_hash);
    mac.update(&reason.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Verify a pairing abort authentication tag in constant time.
///
/// Returns `false` for a tag that is not exactly 32 bytes.
pub fn verify_pairing_abort_tag(
    k_dir: &[u8; 32],
    transcript_hash: &[u8; 32],
    reason: i32,
    tag: &[u8],
) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let expected = compute_pairing_abort_tag(k_dir, transcript_hash, reason);
    expected.ct_eq(tag).into()
}

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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn session_id() -> [u8; 16] {
        [0x5Au8; 16]
    }

    fn base_transcript<'a>(
        session_id: &'a [u8],
        cx25519: &'a [u8; 32],
        sx25519: &'a [u8; 32],
        ced25519: &'a [u8; 32],
        sed25519: &'a [u8; 32],
        deprecated_names: &'a (&'a str, &'a str),
        supported: &'a (
            Vec<SymmetricAlgorithm>,
            Vec<HashAlgorithm>,
            Vec<SignatureAlgorithm>,
        ),
    ) -> PairingTranscript<'a> {
        PairingTranscript {
            version: 2,
            session_id,
            client_x25519_public_key: cx25519,
            server_x25519_public_key: sx25519,
            client_ed25519_public_key: ced25519,
            server_ed25519_public_key: sed25519,
            client_device_name: deprecated_names.0,
            server_device_name: deprecated_names.1,
            supported_symmetric: &supported.0,
            supported_hash: &supported.1,
            supported_signature: &supported.2,
            selected_symmetric: SymmetricAlgorithm::Aes256Gcm,
            selected_hash: HashAlgorithm::Sha256,
            selected_signature: SignatureAlgorithm::Ed25519,
        }
    }

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

    /// The transcript hash must be deterministic and cover every field.
    ///
    /// Each mutation below must change the hash; the defect this catches is any
    /// field silently left out of `H` (which would let an attacker vary it —
    /// e.g. a device name or a supported-algorithm list — without changing the
    /// SAS or the derived keys).
    #[test]
    fn test_transcript_hash_covers_every_field() {
        let sid = session_id();
        let cx = [1u8; 32];
        let sx = [2u8; 32];
        let ced = [3u8; 32];
        let sed = [4u8; 32];
        let names = ("desktop", "phone");
        let supported = (
            vec![
                SymmetricAlgorithm::Aes256Gcm,
                SymmetricAlgorithm::Chacha20Poly1305,
            ],
            vec![HashAlgorithm::Sha256, HashAlgorithm::Blake3],
            vec![SignatureAlgorithm::Ed25519],
        );

        let base = base_transcript(&sid, &cx, &sx, &ced, &sed, &names, &supported);
        let base_hash = compute_pairing_transcript_hash(&base);
        assert_eq!(
            base_hash,
            compute_pairing_transcript_hash(&base),
            "transcript hash must be deterministic"
        );

        // Version.
        let mut variant = base;
        variant.version = 3;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        // Session id.
        let mut other_sid = sid;
        other_sid[0] ^= 0xFF;
        let mut variant = base;
        variant.session_id = &other_sid;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        // Each key.
        for mutation in 0..4 {
            let mut other_cx = cx;
            let mut other_sx = sx;
            let mut other_ced = ced;
            let mut other_sed = sed;
            match mutation {
                0 => other_cx[0] ^= 0x01,
                1 => other_sx[0] ^= 0x01,
                2 => other_ced[0] ^= 0x01,
                _ => other_sed[0] ^= 0x01,
            }
            let mut variant = base;
            variant.client_x25519_public_key = &other_cx;
            variant.server_x25519_public_key = &other_sx;
            variant.client_ed25519_public_key = &other_ced;
            variant.server_ed25519_public_key = &other_sed;
            assert_ne!(
                base_hash,
                compute_pairing_transcript_hash(&variant),
                "key mutation {} must change the transcript hash",
                mutation
            );
        }

        // Each device name (including its length prefix).
        let other_names = ("desktop2", "phone");
        let mut variant = base;
        variant.client_device_name = other_names.0;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        let other_names = ("desktop", "phone2");
        let mut variant = base;
        variant.server_device_name = other_names.1;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        // Supported list length.
        let shrunk = (
            vec![SymmetricAlgorithm::Aes256Gcm],
            supported.1.clone(),
            supported.2.clone(),
        );
        let mut variant = base;
        variant.supported_symmetric = &shrunk.0;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        // Supported list member (same length, different order/content).
        let reordered = (
            vec![
                SymmetricAlgorithm::Chacha20Poly1305,
                SymmetricAlgorithm::Aes256Gcm,
            ],
            supported.1.clone(),
            supported.2.clone(),
        );
        let mut variant = base;
        variant.supported_symmetric = &reordered.0;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        let hash_lists = (
            supported.0.clone(),
            vec![HashAlgorithm::Blake3, HashAlgorithm::Sha256],
            supported.2.clone(),
        );
        let mut variant = base;
        variant.supported_hash = &hash_lists.1;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        let sig_lists = (
            supported.0.clone(),
            supported.1.clone(),
            vec![SignatureAlgorithm::Ed25519, SignatureAlgorithm::Ed25519],
        );
        let mut variant = base;
        variant.supported_signature = &sig_lists.2;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        // Each selected algorithm.
        let mut variant = base;
        variant.selected_symmetric = SymmetricAlgorithm::Chacha20Poly1305;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        let mut variant = base;
        variant.selected_hash = HashAlgorithm::Blake3;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));

        let mut variant = base;
        variant.selected_signature = SignatureAlgorithm::Unspecified;
        assert_ne!(base_hash, compute_pairing_transcript_hash(&variant));
    }

    /// The transcript must frame the device name with its byte length: two names
    /// that concatenate identically must not hash identically.
    /// The defect this catches: names joined without a length prefix, which
    /// lets a peer move bytes between the two fields.
    #[test]
    fn test_transcript_name_length_framing() {
        let sid = session_id();
        let cx = [1u8; 32];
        let sx = [2u8; 32];
        let ced = [3u8; 32];
        let sed = [4u8; 32];
        let supported = (
            vec![SymmetricAlgorithm::Aes256Gcm],
            vec![HashAlgorithm::Sha256],
            vec![SignatureAlgorithm::Ed25519],
        );

        let names_a = ("ab", "c");
        let names_b = ("a", "bc");
        let hash_a = compute_pairing_transcript_hash(&base_transcript(
            &sid, &cx, &sx, &ced, &sed, &names_a, &supported,
        ));
        let hash_b = compute_pairing_transcript_hash(&base_transcript(
            &sid, &cx, &sx, &ced, &sed, &names_b, &supported,
        ));
        assert_ne!(hash_a, hash_b);
    }

    /// An all-zero X25519 output is a low-order point and must be rejected.
    /// The defect this catches: deriving keys from an attacker-forced zero
    /// shared secret.
    #[test]
    fn test_zero_shared_secret_rejected() {
        let transcript_hash = [0x33u8; 32];
        assert!(matches!(
            derive_pairing_keys_and_sas(&[0u8; 32], &transcript_hash),
            Err(CryptoError::InvalidKeyLength)
        ));
    }

    /// The two directional keys must differ and be derived from both the secret
    /// and the transcript hash; the SAS must be hyphenated 3+3 digits.
    #[test]
    fn test_pairing_keys_and_sas() {
        let shared_secret = [0x42u8; 32];
        let transcript_hash = [0x77u8; 32];

        let keys = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash).unwrap();
        assert_ne!(*keys.k_c2s, *keys.k_s2c, "directional keys must differ");
        assert_ne!(*keys.k_c2s, [0u8; 32]);
        assert_ne!(*keys.k_s2c, [0u8; 32]);

        // SAS display form: NNN-NNN.
        let bytes = keys.sas.as_bytes();
        assert_eq!(
            bytes.len(),
            7,
            "SAS is exactly 7 characters: {:?}",
            keys.sas
        );
        assert_eq!(bytes[3], b'-');
        for (index, byte) in bytes.iter().enumerate() {
            if index == 3 {
                continue;
            }
            assert!(
                byte.is_ascii_digit(),
                "SAS digit expected in {:?}",
                keys.sas
            );
        }

        // Deterministic for identical inputs.
        let again = derive_pairing_keys_and_sas(&shared_secret, &transcript_hash).unwrap();
        assert_eq!(*keys.k_c2s, *again.k_c2s);
        assert_eq!(*keys.k_s2c, *again.k_s2c);
        assert_eq!(keys.sas, again.sas);
    }

    /// A different transcript hash (i.e. any transcript tampering) must change
    /// both the keys and the SAS.
    #[test]
    fn test_pairing_keys_depend_on_transcript_hash() {
        let shared_secret = [0x42u8; 32];
        let first = derive_pairing_keys_and_sas(&shared_secret, &[0x77u8; 32]).unwrap();
        let second = derive_pairing_keys_and_sas(&shared_secret, &[0x78u8; 32]).unwrap();

        assert_ne!(*first.k_c2s, *second.k_c2s);
        assert_ne!(*first.k_s2c, *second.k_s2c);

        // The SAS is 6 decimal digits, so a *specific* transcript pair may
        // collide by chance (1 in 10^6). Assert the property instead: some
        // transcript whose hash differs also yields a different SAS.
        let base_hash = transcript_hash_for_fill(0x11);
        let base_sas = derive_pairing_keys_and_sas(&shared_secret, &base_hash)
            .unwrap()
            .sas;
        let mut saw_different_sas = false;
        for fill in 0x12u8..=0xFF {
            let hash = transcript_hash_for_fill(fill);
            assert_ne!(base_hash, hash, "fixture transcripts must differ");
            if derive_pairing_keys_and_sas(&shared_secret, &hash)
                .unwrap()
                .sas
                != base_sas
            {
                saw_different_sas = true;
                break;
            }
        }
        assert!(saw_different_sas, "the SAS must track the transcript hash");
    }

    /// Build a transcript whose fields are all derived from `fill`.
    fn transcript_hash_for_fill(fill: u8) -> [u8; 32] {
        const SUPPORTED_SYMMETRIC: [SymmetricAlgorithm; 1] = [SymmetricAlgorithm::Aes256Gcm];
        const SUPPORTED_HASH: [HashAlgorithm; 1] = [HashAlgorithm::Sha256];
        const SUPPORTED_SIGNATURE: [SignatureAlgorithm; 1] = [SignatureAlgorithm::Ed25519];

        let session_id = [fill; 16];
        let key = [fill; 32];

        compute_pairing_transcript_hash(&PairingTranscript {
            version: 2,
            session_id: &session_id,
            client_x25519_public_key: &key,
            server_x25519_public_key: &key,
            client_ed25519_public_key: &key,
            server_ed25519_public_key: &key,
            client_device_name: "desktop",
            server_device_name: "phone",
            supported_symmetric: &SUPPORTED_SYMMETRIC,
            supported_hash: &SUPPORTED_HASH,
            supported_signature: &SUPPORTED_SIGNATURE,
            selected_symmetric: SymmetricAlgorithm::Aes256Gcm,
            selected_hash: HashAlgorithm::Sha256,
            selected_signature: SignatureAlgorithm::Ed25519,
        })
    }

    /// The abort tag authenticates the direction key, the transcript hash and
    /// the reason. Any mismatch must be rejected.
    /// The defect this catches: an unauthenticated (or reason-independent) abort
    /// that a LAN/BLE observer could forge to cancel a pairing.
    #[test]
    fn test_pairing_abort_tag() {
        let k_dir = [0x01u8; 32];
        let transcript_hash = [0x02u8; 32];
        let reason = 1; // USER_REJECTED_SAS

        let tag = compute_pairing_abort_tag(&k_dir, &transcript_hash, reason);
        assert_eq!(tag.len(), 32);
        assert!(verify_pairing_abort_tag(
            &k_dir,
            &transcript_hash,
            reason,
            &tag
        ));

        // Wrong tag bytes.
        let mut wrong = tag;
        wrong[31] ^= 0x01;
        assert!(!verify_pairing_abort_tag(
            &k_dir,
            &transcript_hash,
            reason,
            &wrong
        ));

        // Wrong reason.
        assert!(!verify_pairing_abort_tag(
            &k_dir,
            &transcript_hash,
            reason + 1,
            &tag
        ));

        // Wrong directional key.
        let mut other_key = k_dir;
        other_key[0] ^= 0xFF;
        assert!(!verify_pairing_abort_tag(
            &other_key,
            &transcript_hash,
            reason,
            &tag
        ));

        // Wrong transcript hash.
        let mut other_hash = transcript_hash;
        other_hash[0] ^= 0xFF;
        assert!(!verify_pairing_abort_tag(&k_dir, &other_hash, reason, &tag));

        // A tag that is not 32 bytes is rejected without panicking.
        assert!(!verify_pairing_abort_tag(
            &k_dir,
            &transcript_hash,
            reason,
            &tag[..31]
        ));
        assert!(!verify_pairing_abort_tag(
            &k_dir,
            &transcript_hash,
            reason,
            &[]
        ));
    }
}
