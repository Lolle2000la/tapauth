// Suppress async_fn_in_trait warning since this trait is only used internally
// and we don't need to specify Send bounds explicitly
#![allow(async_fn_in_trait)]

/// Transport abstraction for authentication protocol
///
/// This module provides a trait-based abstraction for different transport mechanisms
/// (UDP broadcast/multicast, BLE via direct BlueZ, etc.) to enable code reuse, testability,
/// and easy extension with new transport types.
use enum_dispatch::enum_dispatch;
use shared::protocol::pb::EncryptedPacket;
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "ble")]
use std::sync::Arc;

use crate::AuthError;

/// Result of attempting to receive an authentication response
#[derive(Debug)]
pub enum ReceiveResult {
    /// Successfully received a response packet from the given address
    Response(EncryptedPacket, SocketAddr),
    /// No response received within the timeout
    Timeout,
}

/// Trait for authentication transport mechanisms
///
/// Implementors provide methods to send authentication requests, receive responses,
/// send confirmations, and cancel ongoing operations.
#[enum_dispatch]
pub trait Transport {
    /// Send an authentication request packet
    ///
    /// # Arguments
    /// * `packet` - The encrypted authentication request packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Try to receive a response packet with timeout
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a response
    ///
    /// # Returns
    /// * `ReceiveResult::Response` with packet and address if response received
    /// * `ReceiveResult::Timeout` if no response within timeout
    /// * `Err` on error
    async fn receive_response(&mut self, timeout: Duration) -> Result<ReceiveResult, AuthError>;

    /// Send a confirmation packet (GrantConfirmation)
    ///
    /// # Arguments
    /// * `packet` - The encrypted confirmation packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_confirmation(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Send a cancel packet (AuthenticationCancel)
    ///
    /// # Arguments
    /// * `packet` - The encrypted cancel packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_cancel(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Get a human-readable name for this transport (for logging)
    fn name(&self) -> &'static str;
}

/// Transport enum using enum_dispatch for zero-cost abstraction
#[enum_dispatch(Transport)]
pub enum AuthTransport {
    Udp(UdpTransport),
    #[cfg(feature = "ble")]
    Ble(BleTransport),
}

/// UDP transport using broadcast (IPv4) and multicast (IPv6)
pub struct UdpTransport {
    socket: tokio::net::UdpSocket,
    port: u16,
}

impl UdpTransport {
    /// Create a new UDP transport
    ///
    /// # Arguments
    /// * `port` - The UDP port to bind and send to
    pub async fn new(port: u16) -> Result<Self, AuthError> {
        let socket = shared::network::create_broadcast_socket(port).await?;
        Ok(Self { socket, port })
    }
}

impl Transport for UdpTransport {
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send broadcast on IPv4
        if let Err(e) = send_udp_broadcast(&self.socket, self.port, packet).await {
            tracing::warn!("Failed to send IPv4 broadcast: {}", e);
        }

        // Send multicast on IPv6 (on all available interfaces)
        if is_ipv6_available() {
            match send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await {
                Ok(count) if count > 0 => {
                    tracing::trace!("Sent IPv6 multicast on {} interface(s)", count);
                }
                Ok(_) => {
                    tracing::debug!("No suitable IPv6 interfaces found for multicast");
                }
                Err(e) => {
                    tracing::warn!("Failed to send IPv6 multicast: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn receive_response(&mut self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use shared::network::try_receive_udp_packet;

        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }

    async fn send_cancel(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use shared::network::{
            is_ipv6_available, send_udp_broadcast, send_udp_multicast_all_interfaces,
            IPV6_MULTICAST_ADDR,
        };

        // Send on both IPv4 and IPv6
        send_udp_broadcast(&self.socket, self.port, packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, self.port, packet).await;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "UDP"
    }
}

/// BLE transport using direct BlueZ access via D-Bus
#[cfg(feature = "ble")]
#[allow(dead_code)] // timeout is passed to receive_response
pub struct BleTransport {
    adapter: bluer::Adapter,
    temporal_id: [u8; 10],
    timeout: Duration,
    request_packet: Option<EncryptedPacket>,
    config_manager: Arc<shared::config::ClientConfigManager>,
    keypair: Arc<shared::crypto::Ed25519KeyPair>,
    challenge: [u8; 32],
    // Keep advertisement and GATT server alive
    adv_handle: Option<bluer::adv::AdvertisementHandle>,
    gatt_handle: Option<bluer::gatt::local::ApplicationHandle>,
    // Shared state for GATT server callbacks
    response_data: Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
    confirmation_data: Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
}

#[cfg(feature = "ble")]
impl BleTransport {
    /// Create a new BLE transport
    ///
    /// # Arguments
    /// * `temporal_id` - The 10-byte temporal identifier for BLE advertising
    /// * `timeout` - Timeout for authentication
    /// * `config_manager` - Configuration manager for loading config/keys
    /// * `keypair` - Ed25519 keypair for signing
    /// * `challenge` - 32-byte challenge for confirmation
    pub async fn new(
        temporal_id: [u8; 10],
        timeout: Duration,
        config_manager: Arc<shared::config::ClientConfigManager>,
        keypair: Arc<shared::crypto::Ed25519KeyPair>,
        challenge: [u8; 32],
    ) -> Result<Self, AuthError> {
        // Initialize BlueZ session and get adapter
        let session = bluer::Session::new()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to create BlueZ session: {}", e)))?;

        let adapter_names = session
            .adapter_names()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to get adapter names: {}", e)))?;

        let adapter_name = adapter_names
            .first()
            .ok_or_else(|| AuthError::BleError("No Bluetooth adapter found".to_string()))?;

        let adapter = session
            .adapter(adapter_name)
            .map_err(|e| AuthError::BleError(format!("Failed to get adapter: {}", e)))?;

        // Ensure adapter is powered on
        adapter
            .set_powered(true)
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to power on adapter: {}", e)))?;

        Ok(Self {
            adapter,
            temporal_id,
            timeout,
            request_packet: None,
            config_manager,
            keypair,
            challenge,
            adv_handle: None,
            gatt_handle: None,
            response_data: Arc::new(tokio::sync::Mutex::new(None)),
            confirmation_data: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }
}

#[cfg(feature = "ble")]
impl Transport for BleTransport {
    async fn send_request(&mut self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use bluer::adv::Advertisement;
        use bluer::gatt::local::{
            Application, Characteristic, CharacteristicRead, CharacteristicWrite, Service,
        };
        use prost::Message;
        use shared::models::ble::{
            CLIENT_COMMAND_CHAR_UUID, CLIENT_CONFIRMATION_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID,
            SERVICE_UUID,
        };

        // Only set up once (on first call)
        if self.adv_handle.is_some() {
            // Already set up, nothing to do
            return Ok(());
        }

        // Store the packet for later use in receive_response
        self.request_packet = Some(packet.clone());

        // Encode request packet for GATT characteristic
        let mut request_bytes = Vec::new();
        packet
            .encode(&mut request_bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode request: {}", e)))?;

        let request_data = Arc::new(request_bytes);

        // Start BLE advertising with temporal ID
        let advertisement = Advertisement {
            service_data: [(
                SERVICE_UUID
                    .parse()
                    .map_err(|e| AuthError::BleError(format!("Invalid service UUID: {}", e)))?,
                self.temporal_id.to_vec(),
            )]
            .into_iter()
            .collect(),
            discoverable: Some(true),
            local_name: Some("".to_string()),
            ..Default::default()
        };

        // Start advertising (will be kept alive until BleTransport is dropped)
        // Try multiple times to handle "Busy" errors
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.adapter.advertise(advertisement.clone()).await {
                Ok(handle) => {
                    tracing::info!("BLE advertising started (attempt {})", attempt);
                    self.adv_handle = Some(handle);
                    break;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    let is_busy = error_msg.contains("Busy") || error_msg.contains("0x0a");

                    if attempt < MAX_ATTEMPTS {
                        if is_busy {
                            tracing::warn!(
                                "BLE advertising is busy, retrying in 1s (attempt {}/{})",
                                attempt,
                                MAX_ATTEMPTS
                            );
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            tracing::warn!(
                                "Failed to start BLE advertising (attempt {}): {}. Retrying...",
                                attempt,
                                e
                            );
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    } else {
                        return Err(AuthError::BleError(format!(
                            "Failed to start BLE advertising after {} attempts: {}",
                            MAX_ATTEMPTS, e
                        )));
                    }
                }
            }
        }

        // Set up GATT server (once)
        let service_uuid = SERVICE_UUID
            .parse()
            .map_err(|e| AuthError::BleError(format!("Invalid service UUID: {}", e)))?;
        let client_cmd_uuid = CLIENT_COMMAND_CHAR_UUID
            .parse()
            .map_err(|e| AuthError::BleError(format!("Invalid characteristic UUID: {}", e)))?;
        let server_resp_uuid = SERVER_RESPONSE_CHAR_UUID
            .parse()
            .map_err(|e| AuthError::BleError(format!("Invalid characteristic UUID: {}", e)))?;
        let client_conf_uuid = CLIENT_CONFIRMATION_CHAR_UUID
            .parse()
            .map_err(|e| AuthError::BleError(format!("Invalid characteristic UUID: {}", e)))?;

        // Client Command Characteristic - Server reads auth request
        let request_data_for_read = request_data.clone();
        let client_cmd_char = Characteristic {
            uuid: client_cmd_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_req| {
                    let data = request_data_for_read.clone();
                    Box::pin(async move {
                        tracing::debug!("GATT: Server reading auth request ({} bytes)", data.len());
                        Ok((*data).clone())
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Server Response Characteristic - Server writes response
        let response_data = self.response_data.clone();
        let server_resp_char = Characteristic {
            uuid: server_resp_uuid,
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: true,
                method: bluer::gatt::local::CharacteristicWriteMethod::Fun(Box::new(
                    move |new_value, _req| {
                        let response_data = response_data.clone();
                        Box::pin(async move {
                            tracing::info!(
                                "GATT: Received server response ({} bytes)",
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

        // Client Confirmation Characteristic - Server reads confirmation
        let confirmation_data = self.confirmation_data.clone();
        let client_conf_char = Characteristic {
            uuid: client_conf_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_req| {
                    let conf_data = confirmation_data.clone();
                    Box::pin(async move {
                        let data = conf_data.lock().await;
                        match &*data {
                            Some(bytes) => {
                                tracing::debug!(
                                    "GATT: Server reading confirmation ({} bytes)",
                                    bytes.len()
                                );
                                Ok(bytes.clone())
                            }
                            None => {
                                tracing::debug!("GATT: No confirmation available yet");
                                Ok(vec![])
                            }
                        }
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create GATT service
        let service = Service {
            uuid: service_uuid,
            primary: true,
            characteristics: vec![client_cmd_char, server_resp_char, client_conf_char],
            ..Default::default()
        };

        let app = Application {
            services: vec![service],
            ..Default::default()
        };

        // Register GATT application
        let app_handle = self
            .adapter
            .serve_gatt_application(app)
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to register GATT server: {}", e)))?;

        // Store handle to keep GATT server alive
        self.gatt_handle = Some(app_handle);

        tracing::info!("GATT server registered and ready");
        Ok(())
    }

    async fn receive_response(&mut self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use prost::Message;
        use shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce;
        use shared::protocol::pb::wrapper_message;

        let request_packet = self
            .request_packet
            .as_ref()
            .ok_or_else(|| {
                AuthError::BleError(
                    "send_request must be called before receive_response".to_string(),
                )
            })?
            .clone();

        // Wait for response with timeout
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(ReceiveResult::Timeout);
            }

            // Check if we received a response from GATT callback
            {
                let mut response_lock = self.response_data.lock().await;
                if let Some(ref response_bytes) = *response_lock {
                    tracing::info!("Processing received BLE response");

                    // Parse and decrypt response
                    let encrypted_response = match EncryptedPacket::decode(&response_bytes[..]) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decode response: {}, waiting for other devices",
                                e
                            );
                            *response_lock = None;
                            continue;
                        }
                    };

                    // Load CSK from config manager
                    let csk = self
                        .config_manager
                        .load_csk()
                        .map_err(|e| AuthError::Config(e))?;

                    // Decrypt response
                    let decrypted_message =
                        match decrypt_encrypted_packet_with_csk_nonce(&csk, &encrypted_response) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to decrypt response: {}, waiting for other devices",
                                    e
                                );
                                *response_lock = None;
                                continue;
                            }
                        };

                    // Check message type and store confirmation
                    match decrypted_message.payload {
                        Some(wrapper_message::Payload::AuthGrant(_)) => {
                            // Create GrantConfirmation
                            if let Ok(confirmation) = self.create_confirmation(&request_packet) {
                                *self.confirmation_data.lock().await = Some(confirmation);
                                tracing::debug!("Stored confirmation for server to read");
                            }
                        }
                        _ => {
                            tracing::warn!("Unexpected message type, waiting for other devices");
                            *response_lock = None;
                            continue;
                        }
                    };

                    // Wait briefly for server to read confirmation
                    tokio::time::sleep(Duration::from_millis(500)).await;

                    // Return success - the encrypted response will be verified by auth_client
                    // We use a dummy SocketAddr since BLE doesn't have IP addresses
                    return Ok(ReceiveResult::Response(
                        encrypted_response,
                        "0.0.0.0:0".parse().unwrap(),
                    ));
                }
            }

            // Sleep briefly before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn send_confirmation(&mut self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Confirmation is handled in receive_response
        Ok(())
    }

    async fn send_cancel(&mut self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Advertising will be stopped when BleTransport is dropped
        Ok(())
    }

    fn name(&self) -> &'static str {
        "BLE"
    }
}

#[cfg(feature = "ble")]
impl BleTransport {
    /// Create a GrantConfirmation message
    fn create_confirmation(&self, request_packet: &EncryptedPacket) -> Result<Vec<u8>, AuthError> {
        use prost::Message;
        use shared::crypto::encrypt_with_csk_static_nonce;
        use shared::protocol::messages::create_grant_confirmation;
        use shared::protocol::packet::wrap_grant_confirmation;

        // Load CSK
        let csk = self
            .config_manager
            .load_csk()
            .map_err(|e| AuthError::Config(e))?;

        // Create GrantConfirmation with challenge signature
        let confirmation = create_grant_confirmation(&self.keypair, &self.challenge)
            .map_err(|e| AuthError::BleError(format!("Failed to create confirmation: {}", e)))?;

        // Wrap in WrapperMessage
        let wrapper = wrap_grant_confirmation(confirmation);

        // Serialize wrapper
        let plaintext = wrapper.encode_to_vec();

        // Encrypt using CSK static nonce (same as request packet)
        let ciphertext = encrypt_with_csk_static_nonce(&csk, &plaintext)
            .map_err(|e| AuthError::BleError(format!("Failed to encrypt confirmation: {}", e)))?;

        // Create encrypted packet with same temporal identifier as request
        let encrypted = EncryptedPacket {
            temporal_identifier: request_packet.temporal_identifier.clone(),
            encryption_algorithm: request_packet.encryption_algorithm,
            ciphertext,
        };

        let mut bytes = Vec::new();
        encrypted
            .encode(&mut bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode confirmation: {}", e)))?;

        Ok(bytes)
    }
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        tracing::debug!("UDP transport explicitly closed");
    }
}

#[cfg(feature = "ble")]
impl Drop for BleTransport {
    fn drop(&mut self) {
        tracing::debug!("BLE transport explicitly closed");
    }
}
