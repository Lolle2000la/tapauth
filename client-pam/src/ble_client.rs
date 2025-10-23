/// BLE authentication client that communicates with the BLE daemon via D-Bus
///
/// This module provides an async interface to the BLE daemon using zbus.
use shared::{AuthResult, DBUS_OBJECT_PATH, DBUS_SERVICE_NAME};
use zbus::Connection;

/// BLE client that communicates with the BLE daemon via D-Bus (async)
pub struct BleClient {
    connection: Connection,
}

impl BleClient {
    /// Create a new BLE client by connecting to the system D-Bus
    pub async fn new() -> Result<Self, String> {
        tracing::debug!("Connecting to system D-Bus");
        let connection = Connection::system()
            .await
            .map_err(|e| format!("Failed to connect to system bus: {}", e))?;

        tracing::info!("Connected to D-Bus system bus");
        Ok(Self { connection })
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
        let proxy = zbus::Proxy::new(
            &self.connection,
            DBUS_SERVICE_NAME,
            DBUS_OBJECT_PATH,
            "dev.rourunisen.tapauth.BLE",
        )
        .await
        .map_err(|e| format!("Failed to create proxy: {}", e))?;

        let status: String = proxy
            .call_method("GetStatus", &())
            .await
            .map_err(|e| format!("GetStatus call failed: {}", e))?
            .body()
            .deserialize()
            .map_err(|e| format!("Failed to parse status: {}", e))?;

        Ok(status)
    }

    /// Authenticate via BLE using the daemon
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

        let proxy = zbus::Proxy::new(
            &self.connection,
            DBUS_SERVICE_NAME,
            DBUS_OBJECT_PATH,
            "dev.rourunisen.tapauth.BLE",
        )
        .await
        .map_err(|e| format!("Failed to create proxy: {}", e))?;

        let result_code: u32 = proxy
            .call_method(
                "Authenticate",
                &(encrypted_packet, temporal_id, timeout_secs),
            )
            .await
            .map_err(|e| format!("Authenticate call failed: {}", e))?
            .body()
            .deserialize()
            .map_err(|e| format!("Failed to parse result: {}", e))?;

        Ok(AuthResult::from_u32(result_code))
    }
}
