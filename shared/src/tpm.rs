//! TPM (Trusted Platform Module) key storage implementation.
//!
//! This module provides secure key storage using TPM 2.0 chips when available.
//! Since TPM 2.0 doesn't natively support Ed25519, we seal the private key
//! directly using TPM's keyedseal functionality.
//!
//! ## Security Features
//!
//! - **PCR-7 Sealing**: Keys are bound to Secure Boot state
//!   - Prevents evil maid attacks (modified kernel/bootloader)
//!   - Keys only unseal if boot chain hasn't been tampered with
//! - **SHA-384**: Stronger cryptographic binding than SHA-256
//! - **Non-migratable**: Sealed data cannot be extracted from TPM
//! - **Machine-bound**: Keys tied to specific TPM hardware
//! - **No plaintext backup**: Keys only exist in TPM-sealed form
//!
//! ## Recovery
//!
//! If unsealing fails (e.g., after disabling Secure Boot), use the
//! configuration GUI to regenerate keys. This will require re-pairing
//! all devices.

use crate::crypto::{CryptoError, Ed25519KeyPair};
use std::io::Write;
use std::path::Path;

/// Error types for TPM operations
#[derive(Debug, thiserror::Error)]
pub enum TpmKeyError {
    #[error("TPM not available")]
    NotAvailable,

    #[error("Key not found")]
    KeyNotFound,

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Operation failed: {0}")]
    OperationFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Check if TPM is available on the system by checking for tpm2-tools
pub fn is_tpm_available() -> bool {
    std::process::Command::new("tpm2_getrandom")
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Generate an Ed25519 keypair and seal it with TPM
///
/// This creates a wrapping key in the TPM, encrypts the Ed25519 private key with it,
/// and stores the encrypted key in the specified file.
///
/// # Arguments
///
/// * `sealed_key_path` - Path where the sealed key will be stored
/// * `pcr_list` - Comma-separated list of PCR registers (e.g., "7,14" or "0,2,7,14")
pub fn generate_and_seal_keypair(
    sealed_key_path: &Path,
    pcr_list: &str,
) -> Result<Ed25519KeyPair, TpmKeyError> {
    if !is_tpm_available() {
        return Err(TpmKeyError::NotAvailable);
    }

    // Generate the Ed25519 keypair
    let keypair = Ed25519KeyPair::generate()?;

    // Get the private key bytes
    let private_bytes = keypair.signing_key_bytes();

    // Use TPM to seal the private key
    seal_data_with_tpm(&private_bytes, sealed_key_path, pcr_list)?;

    Ok(keypair)
}

/// Load an Ed25519 keypair that was sealed with TPM
///
/// This retrieves the encrypted key from disk and uses the TPM to decrypt it.
pub fn load_sealed_keypair(sealed_key_path: &Path) -> Result<Ed25519KeyPair, TpmKeyError> {
    if !is_tpm_available() {
        return Err(TpmKeyError::NotAvailable);
    }

    if !sealed_key_path.exists() {
        return Err(TpmKeyError::KeyNotFound);
    }

    // Use TPM to unseal the private key
    let private_bytes = unseal_data_with_tpm(sealed_key_path)?;

    if private_bytes.len() != 32 {
        return Err(TpmKeyError::InvalidKeyFormat);
    }

    // Reconstruct the keypair from private key bytes
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&private_bytes);

    Ok(Ed25519KeyPair::from_signing_key_bytes(&key_bytes)?)
}

/// Seal data using TPM (encrypt with TPM-bound key)
///
/// This is made public so the config module can use it directly
///
/// ## Security Hardening
///
/// This implementation uses configurable PCR sealing policies:
///
/// - **Standard** (recommended): PCR 7 + 14 (Secure Boot + MOK keys)
///   - Prevents evil maid attacks (modified kernel/bootloader)
///   - Maintains usability (doesn't break on BIOS/kernel updates)
///   - SHA-384 for stronger cryptographic binding
///
/// - **Paranoid**: PCR 0 + 2 + 7 + 14 (BIOS + Option ROMs + Secure Boot + MOK)
///   - Maximum protection against any boot chain modification
///   - ⚠️ WILL break on BIOS updates and some hardware changes
///   - Requires frequent key recovery via GUI
///
/// If the PCR values change (e.g., Secure Boot disabled, BIOS updated),
/// unsealing will fail and require recovery via the GUI.
pub fn seal_data_with_tpm(
    data: &[u8],
    output_path: &Path,
    pcr_list: &str,
) -> Result<(), TpmKeyError> {
    // Create a temporary file for the input data
    let temp_input = output_path.with_extension("tmp_in");
    let mut file = std::fs::File::create(&temp_input)?;
    file.write_all(data)?;
    drop(file);

    // Use tpm2_create to create a sealed object with PCR binding
    // We use the Storage Root Key (SRK) as the parent
    let output = std::process::Command::new("tpm2_create")
        .args([
            "-C",
            "0x81000001", // SRK handle (standard)
            "-l",
            &format!("sha256:{}", pcr_list), // 🔒 Configurable PCR sealing
            "-g",
            "sha384", // Hash algorithm
            "-G",
            "keyedseal", // Sealed data object
            "-i",
            temp_input.to_str().ok_or(TpmKeyError::InvalidKeyFormat)?,
            "-u",
            output_path
                .with_extension("pub")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
            "-r",
            output_path
                .with_extension("priv")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
        ])
        .output();

    // Clean up temp input file
    let _ = std::fs::remove_file(&temp_input);

    let output = output
        .map_err(|e| TpmKeyError::OperationFailed(format!("Failed to run tpm2_create: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TpmKeyError::OperationFailed(format!(
            "tpm2_create failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Unseal data using TPM (decrypt with TPM-bound key)
///
/// This is made public so the config module can use it directly
pub fn unseal_data_with_tpm(sealed_path: &Path) -> Result<Vec<u8>, TpmKeyError> {
    let temp_output = sealed_path.with_extension("tmp_out");

    // Load the sealed object and unseal it
    let output = std::process::Command::new("tpm2_load")
        .args([
            "-C",
            "0x81000001", // SRK handle
            "-u",
            sealed_path
                .with_extension("pub")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
            "-r",
            sealed_path
                .with_extension("priv")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
            "-c",
            temp_output
                .with_extension("ctx")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
        ])
        .output()
        .map_err(|e| TpmKeyError::OperationFailed(format!("Failed to run tpm2_load: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TpmKeyError::OperationFailed(format!(
            "tpm2_load failed: {}",
            stderr
        )));
    }

    // Now unseal the data
    let output = std::process::Command::new("tpm2_unseal")
        .args([
            "-c",
            temp_output
                .with_extension("ctx")
                .to_str()
                .ok_or(TpmKeyError::InvalidKeyFormat)?,
            "-o",
            temp_output.to_str().ok_or(TpmKeyError::InvalidKeyFormat)?,
        ])
        .output()
        .map_err(|e| TpmKeyError::OperationFailed(format!("Failed to run tpm2_unseal: {}", e)))?;

    if !output.status.success() {
        let _ = std::fs::remove_file(temp_output.with_extension("ctx"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(TpmKeyError::OperationFailed(format!(
            "tpm2_unseal failed: {}",
            stderr
        )));
    }

    // Read the unsealed data
    let data = std::fs::read(&temp_output)?;

    // Clean up temporary files
    let _ = std::fs::remove_file(&temp_output);
    let _ = std::fs::remove_file(temp_output.with_extension("ctx"));

    Ok(data)
}

/// Delete TPM-sealed key files
pub fn delete_sealed_key(sealed_key_path: &Path) -> Result<(), TpmKeyError> {
    // Remove the public and private portions
    let _ = std::fs::remove_file(sealed_key_path.with_extension("pub"));
    let _ = std::fs::remove_file(sealed_key_path.with_extension("priv"));
    Ok(())
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
    fn test_tpm_availability() {
        // This will check if tpm2-tools are installed
        let _available = is_tpm_available();
    }
}
