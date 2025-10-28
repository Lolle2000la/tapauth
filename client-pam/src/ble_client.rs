/// BLE authentication client that communicates with the BLE daemon via D-Bus
///
/// This module provides an async interface to the BLE daemon using zbus.
use shared::{AuthResult, BleServiceProxy};
use std::time::Duration;
use zbus::Connection;

/// BLE client that communicates with the BLE daemon via D-Bus (async)
pub struct BleClient {
    proxy: BleServiceProxy<'static>,
}

impl BleClient {
    /// Create a new BLE client by connecting to the system D-Bus
    pub async fn new() -> Result<Self, String> {
        tracing::debug!("Connecting to system D-Bus");
        let connection = Connection::system()
            .await
            .map_err(|e| format!("Failed to connect to system bus: {}", e))?;

        tracing::info!("Connected to D-Bus system bus");

        // Create the proxy using the shared interface definition
        let proxy = BleServiceProxy::new(&connection)
            .await
            .map_err(|e| format!("Failed to create proxy: {}", e))?;

        Ok(Self { proxy })
    }

    /// Check if the BLE daemon is available
    pub async fn is_daemon_available(&self) -> bool {
        tracing::debug!("Checking if BLE daemon is available");

        match self.get_status().await {
            Ok(_) => {
                tracing::info!("BLE daemon is available");
                true
            }
            Err(e) => {
                tracing::warn!("BLE daemon not available: {}", e);
                false
            }
        }
    }

    /// Get the daemon status
    async fn get_status(&self) -> Result<String, String> {
        self.proxy
            .get_status()
            .await
            .map_err(|e| format!("GetStatus call failed: {}", e))
    }

    /// Authenticate via BLE using the daemon
    ///
    /// # Timeout
    /// This call has a timeout of `timeout_secs + 5` seconds to account for
    /// D-Bus overhead and daemon processing time. If the daemon doesn't respond
    /// within this time, the call will be cancelled.
    pub async fn authenticate(
        &self,
        encrypted_packet: Vec<u8>,
        temporal_id: Vec<u8>,
        timeout_secs: u64,
    ) -> Result<AuthResult, String> {
        tracing::info!(
            "Calling BLE daemon via D-Bus (packet={} bytes, temporal_id={} bytes, timeout={}s)",
            encrypted_packet.len(),
            temporal_id.len(),
            timeout_secs
        );

        // Add extra time for D-Bus overhead and daemon processing
        let call_timeout = Duration::from_secs(timeout_secs + 5);

        // Use tokio timeout to ensure we don't hang forever
        let result = tokio::time::timeout(
            call_timeout,
            self.proxy
                .authenticate(encrypted_packet, temporal_id, timeout_secs),
        )
        .await
        .map_err(|_| format!("D-Bus call timed out after {}s", call_timeout.as_secs()))?
        .map_err(|e| format!("Authenticate call failed: {}", e))?;

        Ok(AuthResult::from_u32(result))
    }

    /// Cancel ongoing BLE authentication
    /// This stops BLE advertising and makes the daemon available for new requests
    pub async fn cancel(&self) -> Result<(), String> {
        tracing::debug!("Cancelling BLE authentication via D-Bus");

        // Cancel should be fast, use a short timeout
        tokio::time::timeout(Duration::from_secs(2), self.proxy.cancel())
            .await
            .map_err(|_| "Cancel call timed out after 2s".to_string())?
            .map_err(|e| format!("Cancel call failed: {}", e))?;

        tracing::info!("BLE authentication cancelled");
        Ok(())
    }
}
