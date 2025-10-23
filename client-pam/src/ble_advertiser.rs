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
    // Keep advertisement handle alive
    adv_handle: std::sync::Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
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
        use tokio::time::{timeout, Duration};

        tracing::debug!("BLE: Creating new BlueZ session...");
        let session = match timeout(Duration::from_secs(2), bluer::Session::new()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::error!("BLE: Failed to create BlueZ session: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                tracing::error!("BLE: Timeout creating BlueZ session (D-Bus not accessible?)");
                return Err(BleError::Timeout);
            }
        };

        tracing::debug!("BLE: Getting adapter names...");
        let adapter_names = session.adapter_names().await.map_err(|e| {
            tracing::error!("BLE: Failed to get adapter names: {}", e);
            e
        })?;

        tracing::debug!("BLE: Found {} adapters", adapter_names.len());
        let adapter_name = adapter_names.first().ok_or_else(|| {
            tracing::error!("BLE: No Bluetooth adapter found");
            BleError::NoAdapter
        })?;

        tracing::debug!("BLE: Using adapter: {}", adapter_name);
        let adapter = session.adapter(adapter_name).map_err(|e| {
            tracing::error!("BLE: Failed to get adapter {}: {}", adapter_name, e);
            e
        })?;

        tracing::info!(
            "BLE: Advertiser created successfully with adapter {}",
            adapter_name
        );
        Ok(Self {
            adapter,
            adv_handle: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        })
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

        // Start advertising and keep handle alive
        let handle = self.adapter.advertise(advertisement).await?;
        *self.adv_handle.lock().await = Some(handle);

        tracing::info!("Started BLE advertising");

        Ok(())
    }

    /// Stop advertising
    pub async fn stop_advertising(&self) -> Result<(), BleError> {
        // Drop the advertisement handle to stop advertising
        *self.adv_handle.lock().await = None;
        tracing::info!("Stopped BLE advertising");
        Ok(())
    }

    /// Run a GATT server to handle authentication requests/responses
    /// This is the client's role as advertiser/peripheral
    pub async fn run_authentication_server(
        &self,
        request_packet: &shared::protocol::pb::EncryptedPacket,
        csk: &shared::crypto::ClientSymmetricKey,
        challenge: &[u8; 32],
        _keypair: &shared::crypto::Ed25519KeyPair,
        config_manager: &shared::config::ClientConfigManager,
        timeout: Duration,
    ) -> Result<(), crate::auth_client::AuthError> {
        use bluer::gatt::local::{
            Application, Characteristic, CharacteristicRead, CharacteristicWrite, Service,
        };
        use prost::Message as ProstMessage;
        use shared::models::ble::{
            CLIENT_COMMAND_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID, SERVICE_UUID,
        };
        use std::sync::Arc;
        use tokio::sync::Mutex;

        tracing::info!("Starting BLE GATT server (peripheral mode)");

        // Serialize the request packet for the characteristic
        let request_data = request_packet.encode_to_vec();
        let request_data = Arc::new(request_data);

        // Shared state for receiving the server's response
        let response_data: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let response_data_clone = response_data.clone();

        // Create the GATT service
        let service_uuid = SERVICE_UUID.parse::<bluer::Uuid>().map_err(|_| {
            crate::auth_client::AuthError::InitError("Invalid service UUID".to_string())
        })?;

        let client_cmd_uuid = CLIENT_COMMAND_CHAR_UUID
            .parse::<bluer::Uuid>()
            .map_err(|_| {
                crate::auth_client::AuthError::InitError("Invalid characteristic UUID".to_string())
            })?;

        let server_resp_uuid = SERVER_RESPONSE_CHAR_UUID
            .parse::<bluer::Uuid>()
            .map_err(|_| {
                crate::auth_client::AuthError::InitError("Invalid characteristic UUID".to_string())
            })?;

        // Client Command Characteristic - allows server to READ our auth request
        let request_data_for_read = request_data.clone();
        let client_cmd_char = Characteristic {
            uuid: client_cmd_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_req| {
                    let data = request_data_for_read.clone();
                    Box::pin(async move {
                        tracing::debug!(
                            "BLE: Server reading authentication request ({} bytes)",
                            data.len()
                        );
                        Ok((*data).clone())
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Server Response Characteristic - allows server to WRITE response to us
        let server_resp_char = Characteristic {
            uuid: server_resp_uuid,
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: true,
                method: bluer::gatt::local::CharacteristicWriteMethod::Fun(Box::new(
                    move |new_value, _req| {
                        let response_data = response_data_clone.clone();
                        Box::pin(async move {
                            tracing::info!(
                                "BLE: Received server response ({} bytes)",
                                new_value.len()
                            );
                            *response_data.lock().await = Some(new_value);
                            Ok(())
                        })
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        };

        let service = Service {
            uuid: service_uuid,
            primary: true,
            characteristics: vec![client_cmd_char, server_resp_char],
            ..Default::default()
        };

        let app = Application {
            services: vec![service],
            ..Default::default()
        };

        // Register the GATT application
        let app_handle = self
            .adapter
            .serve_gatt_application(app)
            .await
            .map_err(|e| crate::auth_client::AuthError::Ble(BleError::Bluer(e)))?;

        tracing::info!("BLE GATT server registered, waiting for server connection and response");

        // Wait for response with timeout
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                tracing::warn!("BLE authentication timeout");
                drop(app_handle); // Unregister GATT service
                return Err(crate::auth_client::AuthError::Timeout);
            }

            // Check if we received a response
            {
                let response_lock = response_data.lock().await;
                if let Some(ref response_bytes) = *response_lock {
                    tracing::info!("BLE: Processing received response");

                    // Decrypt and verify the response
                    let result = self
                        .process_ble_response(response_bytes, csk, challenge, config_manager)
                        .await;

                    drop(app_handle); // Unregister GATT service
                    return result;
                }
            }

            // Sleep briefly before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Process a BLE response (decrypt and verify grant)
    async fn process_ble_response(
        &self,
        encrypted_bytes: &[u8],
        csk: &shared::crypto::ClientSymmetricKey,
        challenge: &[u8; 32],
        config_manager: &shared::config::ClientConfigManager,
    ) -> Result<(), crate::auth_client::AuthError> {
        use prost::Message as ProstMessage;
        use shared::protocol::messages::{verify_auth_denial, verify_auth_grant};
        use shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce;
        use shared::protocol::pb::{wrapper_message, EncryptedPacket, WrapperMessage};

        // Parse the encrypted packet
        let encrypted_packet = EncryptedPacket::decode(&encrypted_bytes[..]).map_err(|e| {
            crate::auth_client::AuthError::InitError(format!(
                "Failed to decode BLE response: {}",
                e
            ))
        })?;

        tracing::debug!("BLE: Decrypting response packet");

        // Decrypt the packet using CSK-based nonce (same as UDP flow)
        let wrapper = decrypt_encrypted_packet_with_csk_nonce(csk, &encrypted_packet)
            .map_err(|e| crate::auth_client::AuthError::Protocol(e))?;

        // Extract AuthenticationGrant or AuthenticationDenial
        match wrapper.payload {
            Some(wrapper_message::Payload::AuthGrant(ref grant)) => {
                tracing::info!("BLE: Received authentication grant");

                // Get all paired servers
                let paired_servers = config_manager.load_paired_servers()?;

                // Try to verify against each paired server
                for (_id, server) in paired_servers.iter() {
                    let pub_key_bytes = hex::decode(&server.public_key).map_err(|_| {
                        crate::auth_client::AuthError::Protocol(
                            shared::protocol::ProtocolError::InvalidMessageFormat,
                        )
                    })?;

                    if pub_key_bytes.len() != 32 {
                        tracing::warn!(
                            "Server {} has invalid public key length: {}",
                            server.name,
                            pub_key_bytes.len()
                        );
                        continue;
                    }

                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);

                    match verify_auth_grant(grant, challenge, &pub_key) {
                        Ok(_) => {
                            tracing::info!(
                                "BLE: Authentication grant verified for server: {}",
                                server.name
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!(
                                "BLE: Verification failed for server {}: {:?}",
                                server.name,
                                e
                            );
                        }
                    }
                }

                tracing::error!("BLE: No server matched the grant signature");
                Err(crate::auth_client::AuthError::Protocol(
                    shared::protocol::ProtocolError::InvalidSignature,
                ))
            }
            Some(wrapper_message::Payload::AuthDenial(ref denial)) => {
                tracing::warn!("BLE: Received authentication denial");

                // Verify the denial
                let paired_servers = config_manager.load_paired_servers()?;

                for (_id, server) in paired_servers.iter() {
                    let pub_key_bytes = hex::decode(&server.public_key).map_err(|_| {
                        crate::auth_client::AuthError::Protocol(
                            shared::protocol::ProtocolError::InvalidMessageFormat,
                        )
                    })?;

                    if pub_key_bytes.len() != 32 {
                        continue;
                    }

                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);

                    if verify_auth_denial(denial, &pub_key).is_ok() {
                        tracing::info!(
                            "BLE: Authentication denial verified for server: {}",
                            server.name
                        );
                        return Err(crate::auth_client::AuthError::Denied);
                    }
                }

                Err(crate::auth_client::AuthError::Protocol(
                    shared::protocol::ProtocolError::InvalidSignature,
                ))
            }
            _ => {
                tracing::error!("BLE: Unexpected message type in response");
                Err(crate::auth_client::AuthError::InitError(
                    "Unexpected BLE response type".to_string(),
                ))
            }
        }
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
