//! D-Bus interface for TapAuth BLE Daemon
//!
//! This module defines the D-Bus interface exposed by the BLE daemon
//! for communication with PAM modules and other clients.

use shared::AuthResult;
use zbus::interface;

/// Authentication request internal to daemon
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Encrypted authentication request packet (serialized protobuf)
    pub encrypted_packet: Vec<u8>,
    /// Temporal identifier for BLE advertising
    pub temporal_id: [u8; 16],
    /// Timeout in seconds
    pub timeout_secs: u64,
}

/// BLE Daemon D-Bus interface implementation
pub struct BleService {
    /// Channel to send authentication requests to the BLE handler
    auth_tx: tokio::sync::mpsc::Sender<(AuthRequest, tokio::sync::oneshot::Sender<AuthResult>)>,
}

impl BleService {
    pub fn new(
        auth_tx: tokio::sync::mpsc::Sender<(AuthRequest, tokio::sync::oneshot::Sender<AuthResult>)>,
    ) -> Self {
        Self { auth_tx }
    }
}

#[interface(name = "dev.rourunisen.tapauth.BLE")]
impl BleService {
    /// Start BLE authentication session
    ///
    /// # Arguments
    /// * `encrypted_packet` - Serialized EncryptedPacket containing auth request
    /// * `temporal_id` - 16-byte temporal identifier for advertising
    /// * `timeout_secs` - Maximum time to wait for authentication
    ///
    /// # Returns
    /// * `0` - Authentication granted
    /// * `1` - Authentication denied
    /// * `2` - Timeout
    /// * Other - Error code
    async fn authenticate(
        &self,
        encrypted_packet: Vec<u8>,
        temporal_id: Vec<u8>,
        timeout_secs: u64,
    ) -> u32 {
        tracing::info!(
            "D-Bus: Received authentication request (packet={} bytes, temporal_id={} bytes, timeout={}s)",
            encrypted_packet.len(),
            temporal_id.len(),
            timeout_secs
        );

        // Validate temporal_id length
        if temporal_id.len() != 16 {
            tracing::error!("D-Bus: Invalid temporal_id length: {}", temporal_id.len());
            return AuthResult::Error.to_u32();
        }

        let mut temporal_id_array = [0u8; 16];
        temporal_id_array.copy_from_slice(&temporal_id);

        let request = AuthRequest {
            encrypted_packet,
            temporal_id: temporal_id_array,
            timeout_secs,
        };

        // Create one-shot channel for response
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        // Send request to BLE handler
        if let Err(e) = self.auth_tx.send((request, response_tx)).await {
            tracing::error!("D-Bus: Failed to send auth request to handler: {}", e);
            return AuthResult::Error.to_u32();
        }

        // Wait for response
        match response_rx.await {
            Ok(result) => {
                tracing::info!("D-Bus: Authentication result: {:?}", result);
                result.to_u32()
            }
            Err(e) => {
                tracing::error!("D-Bus: Failed to receive response: {}", e);
                AuthResult::Error.to_u32()
            }
        }
    }

    /// Get daemon status
    async fn get_status(&self) -> String {
        "running".to_string()
    }

    /// Get daemon version
    async fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}
