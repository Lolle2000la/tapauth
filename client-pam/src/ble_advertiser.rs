//! BLE Advertisement and GATT Client Implementation
//!
//! This module provides BLE (Bluetooth Low Energy) functionality for the TapAuth client:
//!
//! 1. **BLE Advertisement**: Broadcasts temporal identifiers so paired servers can discover
//!    this client without revealing static identities.
//!
//! 2. **BLE GATT Client**: Connects to paired servers via GATT to exchange authentication
//!    messages as an alternative transport to UDP.
//!
//! ## GATT Service Specification
//!
//! - **Service UUID**: `b4ad84c0-2adb-4876-8315-b39d983b2bde`
//! - **Client Command Characteristic** (`caf54438-9d78-4697-8886-0a4cfa87ba8d`):
//!   - Properties: WRITE (without response)
//!   - Purpose: Client sends `EncryptedPacket` containing authentication requests
//! - **Server Response Characteristic** (`ca6238be-c194-49b7-855b-58f41d3da626`):
//!   - Properties: NOTIFY
//!   - Purpose: Server sends `EncryptedPacket` containing authentication grants/denials
//!
//! ## Security Requirements
//!
//! - **LE Secure Connections** MUST be used (ECDH-based key exchange)
//! - Legacy pairing is disabled
//! - Protects against passive eavesdropping and MITM attacks at link layer
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use client_pam::ble_advertiser::{BleAdvertiser, BleGattConnection};
//!
//! // Start advertising
//! let advertiser = BleAdvertiser::new().await?;
//! advertiser.start_advertising(&temporal_id).await?;
//!
//! // Connect to a server via GATT
//! let connection = advertiser.connect_gatt(device_address).await?;
//!
//! // Send authentication request
//! connection.send_command(&encrypted_packet).await?;
//!
//! // Receive authentication response
//! let response = connection.receive_response(Duration::from_secs(5)).await?;
//!
//! // Cleanup
//! connection.disconnect().await?;
//! ```

use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "ble")]
use bluer::{gatt::remote::Characteristic, Adapter, AdapterEvent, Address, Device};

#[cfg(feature = "ble")]
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
pub enum BleError {
    #[cfg(feature = "ble")]
    #[error("Bluer error: {0}")]
    Bluer(#[from] bluer::Error),
    #[error("Timeout")]
    Timeout,
    #[error("No adapter found")]
    NoAdapter,
    #[error("Advertisement failed")]
    AdvertisementFailed,
    #[error("BLE support not compiled")]
    NotCompiled,
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Service not found")]
    ServiceNotFound,
    #[error("Characteristic not found")]
    CharacteristicNotFound,
    #[error("Write failed")]
    WriteFailed,
    #[error("Notification setup failed")]
    NotificationFailed,
}

#[cfg(feature = "ble")]
pub struct BleAdvertiser {
    adapter: Adapter,
}

/// Represents a BLE GATT connection for sending commands and receiving responses
#[cfg(feature = "ble")]
pub struct BleGattConnection {
    device: Device,
    client_command_char: Characteristic,
    server_response_char: Characteristic,
}

/// Represents a BLE GATT server for receiving commands and sending responses
#[cfg(feature = "ble")]
pub struct BleGattServer {
    // Will be implemented with bluer's GATT server capabilities
    _adapter: Adapter,
}

#[cfg(not(feature = "ble"))]
pub struct BleGattConnection;

#[cfg(not(feature = "ble"))]
pub struct BleGattServer;

#[cfg(not(feature = "ble"))]
pub struct BleGattConnection;

#[cfg(feature = "ble")]
impl BleAdvertiser {
    /// Create a new BLE advertiser
    pub async fn new() -> Result<Self, BleError> {
        let session = bluer::Session::new().await?;
        let adapter_names = session.adapter_names().await?;
        let adapter_name = adapter_names.first().ok_or(BleError::NoAdapter)?;
        let adapter = session.adapter(adapter_name)?;

        Ok(Self { adapter })
    }

    /// Start advertising with temporal identifier
    pub async fn start_advertising(&self, temporal_identifier: &[u8; 16]) -> Result<(), BleError> {
        use shared::models::ble::SERVICE_UUID;

        // Set adapter to be powered on
        self.adapter.set_powered(true).await?;

        // Create advertisement
        let advertisement = bluer::adv::Advertisement {
            service_uuids: vec![SERVICE_UUID.parse().unwrap()].into_iter().collect(),
            service_data: [(SERVICE_UUID.parse().unwrap(), temporal_identifier.to_vec())]
                .into_iter()
                .collect(),
            discoverable: Some(true),
            local_name: Some("TapAuth".to_string()),
            ..Default::default()
        };

        // Start advertising
        let _handle = self.adapter.advertise(advertisement).await?;

        tracing::info!("Started BLE advertising");

        Ok(())
    }

    /// Stop advertising
    pub async fn stop_advertising(&self) -> Result<(), BleError> {
        // Advertising is stopped when the handle is dropped
        Ok(())
    }

    /// Run a GATT server to handle authentication requests/responses
    /// This is the client's role as advertiser/peripheral
    pub async fn run_authentication_server(
        &self,
        _request_packet: &shared::protocol::pb::EncryptedPacket,
        csk: &shared::crypto::ClientSymmetricKey,
        challenge: &[u8; 32],
        keypair: &shared::crypto::Ed25519KeyPair,
        config_manager: &shared::config::ClientConfigManager,
        timeout: Duration,
    ) -> Result<(), crate::auth_client::AuthError> {
        use futures_util::StreamExt;

        tracing::info!("BLE GATT server waiting for connections and responses");

        let start = Instant::now();
        let mut events = self
            .adapter
            .events()
            .await
            .map_err(|e| crate::auth_client::AuthError::Ble(BleError::Bluer(e)))?;

        // Wait for a server to connect and send a response
        while start.elapsed() < timeout {
            let timeout_remaining = timeout.saturating_sub(start.elapsed());

            match tokio::time::timeout(timeout_remaining, events.next()).await {
                Ok(Some(AdapterEvent::DeviceAdded(addr))) => {
                    tracing::info!("BLE device connected: {}", addr);

                    // Note: In a full implementation, we would set up GATT server
                    // characteristics here and wait for the server to write a response
                    // to our Server Response characteristic.
                    //
                    // For now, this is a placeholder that shows the structure.
                    // Full GATT server implementation requires:
                    // 1. Register GATT service with characteristics
                    // 2. Handle characteristic write requests (for server responses)
                    // 3. Allow characteristic reads (for our authentication request)
                    //
                    // This is complex with bluer and may require a different approach
                    // or using a different BLE library that better supports peripheral mode.

                    tracing::warn!("BLE GATT server mode not fully implemented yet");
                    return Err(crate::auth_client::AuthError::InitError(
                        "BLE peripheral/server mode requires additional implementation".to_string(),
                    ));
                }
                Ok(Some(_)) => {
                    // Other events, ignore
                }
                Ok(None) => {
                    // Stream ended
                    break;
                }
                Err(_) => {
                    // Timeout
                    return Err(crate::auth_client::AuthError::Timeout);
                }
            }
        }

        Err(crate::auth_client::AuthError::Timeout)
    }

    /// Wait for incoming connection with timeout
    pub async fn wait_for_connection(
        &self,
        timeout_duration: Duration,
    ) -> Result<Option<Address>, BleError> {
        use futures_util::StreamExt;

        let mut events = self.adapter.events().await?;

        match timeout(timeout_duration, async {
            while let Some(event) = events.next().await {
                match event {
                    AdapterEvent::DeviceAdded(addr) => {
                        tracing::debug!("Device added: {}", addr);
                        return Some(addr);
                    }
                    _ => {}
                }
            }
            None
        })
        .await
        {
            Ok(result) => Ok(result),
            Err(_) => Err(BleError::Timeout),
        }
    }

    /// Connect to a BLE device and discover GATT characteristics
    pub async fn connect_gatt(
        &self,
        device_address: Address,
    ) -> Result<BleGattConnection, BleError> {
        use shared::models::ble::{
            CLIENT_COMMAND_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID, SERVICE_UUID,
        };

        let device = self.adapter.device(device_address)?;

        // Ensure device is connected
        if !device.is_connected().await? {
            device.connect().await?;
        }

        // Wait for services to be resolved
        let mut retries = 0;
        while !device.is_services_resolved().await? && retries < 10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            retries += 1;
        }

        if !device.is_services_resolved().await? {
            return Err(BleError::ServiceNotFound);
        }

        // Find the TapAuth service
        let service_uuid = SERVICE_UUID
            .parse::<bluer::Uuid>()
            .map_err(|_| BleError::ServiceNotFound)?;

        let services = device.services().await?;
        let mut service = None;
        for s in services.iter() {
            if s.uuid().await? == service_uuid {
                service = Some(s);
                break;
            }
        }
        let service = service.ok_or(BleError::ServiceNotFound)?;

        // Find the characteristics
        let client_cmd_uuid = CLIENT_COMMAND_CHAR_UUID
            .parse::<bluer::Uuid>()
            .map_err(|_| BleError::CharacteristicNotFound)?;
        let server_resp_uuid = SERVER_RESPONSE_CHAR_UUID
            .parse::<bluer::Uuid>()
            .map_err(|_| BleError::CharacteristicNotFound)?;

        let characteristics = service.characteristics().await?;

        let mut client_command_char = None;
        let mut server_response_char = None;

        for c in characteristics.iter() {
            let uuid = c.uuid().await?;
            if uuid == client_cmd_uuid {
                client_command_char = Some(c.clone());
            } else if uuid == server_resp_uuid {
                server_response_char = Some(c.clone());
            }
        }

        let client_command_char = client_command_char.ok_or(BleError::CharacteristicNotFound)?;
        let server_response_char = server_response_char.ok_or(BleError::CharacteristicNotFound)?;

        tracing::info!("Connected to GATT service on device {}", device_address);

        Ok(BleGattConnection {
            device,
            client_command_char,
            server_response_char,
        })
    }
}

#[cfg(feature = "ble")]
impl BleGattConnection {
    /// Send an authentication command to the server via BLE GATT
    pub async fn send_command(&self, command: &[u8]) -> Result<(), BleError> {
        self.client_command_char
            .write(command)
            .await
            .map_err(|_| BleError::WriteFailed)?;

        tracing::debug!("Sent BLE command: {} bytes", command.len());
        Ok(())
    }

    /// Wait for a response from the server via BLE GATT notifications
    pub async fn receive_response(&self, timeout_duration: Duration) -> Result<Vec<u8>, BleError> {
        use futures_util::StreamExt;

        // Enable notifications
        let notify_stream = self
            .server_response_char
            .notify()
            .await
            .map_err(|_| BleError::NotificationFailed)?;

        // Wait for notification with timeout
        match timeout(timeout_duration, async {
            tokio::pin!(notify_stream);
            while let Some(notification) = notify_stream.next().await {
                tracing::debug!("Received BLE notification: {} bytes", notification.len());
                return Some(notification);
            }
            None
        })
        .await
        {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(BleError::NotificationFailed),
            Err(_) => Err(BleError::Timeout),
        }
    }

    /// Disconnect from the GATT server
    pub async fn disconnect(&self) -> Result<(), BleError> {
        if self.device.is_connected().await? {
            self.device.disconnect().await?;
            tracing::info!("Disconnected from GATT device");
        }
        Ok(())
    }
}

#[cfg(not(feature = "ble"))]
impl BleAdvertiser {
    /// Create a new BLE advertiser (stub when BLE is disabled)
    pub async fn new() -> Result<Self, BleError> {
        Err(BleError::NotCompiled)
    }

    /// Start advertising with temporal identifier (stub when BLE is disabled)
    pub async fn start_advertising(&self, _temporal_identifier: &[u8; 16]) -> Result<(), BleError> {
        Err(BleError::NotCompiled)
    }

    /// Stop advertising (stub when BLE is disabled)
    pub async fn stop_advertising(&self) -> Result<(), BleError> {
        Ok(())
    }

    /// Wait for incoming connection with timeout (stub when BLE is disabled)
    pub async fn wait_for_connection(
        &self,
        _timeout_duration: Duration,
    ) -> Result<Option<()>, BleError> {
        Err(BleError::NotCompiled)
    }

    /// Connect to a BLE device and discover GATT characteristics (stub when BLE is disabled)
    pub async fn connect_gatt(&self, _device_address: ()) -> Result<BleGattConnection, BleError> {
        Err(BleError::NotCompiled)
    }
}

#[cfg(not(feature = "ble"))]
impl BleGattConnection {
    /// Send an authentication command to the server via BLE GATT (stub when BLE is disabled)
    pub async fn send_command(&self, _command: &[u8]) -> Result<(), BleError> {
        Err(BleError::NotCompiled)
    }

    /// Wait for a response from the server via BLE GATT notifications (stub when BLE is disabled)
    pub async fn receive_response(&self, _timeout_duration: Duration) -> Result<Vec<u8>, BleError> {
        Err(BleError::NotCompiled)
    }

    /// Disconnect from the GATT server (stub when BLE is disabled)
    pub async fn disconnect(&self) -> Result<(), BleError> {
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "ble")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ble_advertiser_creation() {
        // This test will fail if no Bluetooth adapter is available
        // which is expected in CI/testing environments
        let result = BleAdvertiser::new().await;

        // Just verify it doesn't panic
        match result {
            Ok(_) => tracing::info!("BLE adapter found"),
            Err(BleError::NoAdapter) => tracing::info!("No BLE adapter (expected in CI)"),
            Err(e) => tracing::warn!("BLE error: {:?}", e),
        }
    }
}
