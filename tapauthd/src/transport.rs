// Suppress async_fn_in_trait warning since this trait is only used internally
// and we don't need to specify Send bounds explicitly
#![allow(async_fn_in_trait)]

/// Transport abstraction for authentication protocol
///
/// This module provides a trait-based abstraction for different transport mechanisms
/// (UDP broadcast/multicast, BLE via direct BlueZ, etc.) to enable code reuse, testability,
/// and easy extension with new transport types.
use shared::protocol::pb::EncryptedPacket;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "ble")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "ble")]
use std::sync::Arc;

use crate::auth_handler::AuthHandlerError as AuthError;

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
pub trait Transport {
    /// Send an authentication request packet
    ///
    /// # Arguments
    /// * `packet` - The encrypted authentication request packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Try to receive a response packet with timeout
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a response
    ///
    /// # Returns
    /// * `ReceiveResult::Response` with packet and address if response received
    /// * `ReceiveResult::Timeout` if no response within timeout
    /// * `Err` on error
    async fn receive_response(&self, timeout: Duration) -> Result<ReceiveResult, AuthError>;

    /// Send a confirmation packet (GrantConfirmation)
    ///
    /// # Arguments
    /// * `packet` - The encrypted confirmation packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_confirmation(&self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Send a cancel packet (AuthenticationCancel)
    ///
    /// # Arguments
    /// * `packet` - The encrypted cancel packet
    ///
    /// # Returns
    /// Ok(()) if the send was successful, Err otherwise
    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError>;

    /// Finalize and tear down any transport-specific state
    ///
    /// Default is a no-op. Transports with long-lived connections (e.g., BLE)
    /// should override this to explicitly disconnect and release resources.
    async fn finalize(&self) -> Result<(), AuthError> {
        Ok(())
    }
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
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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

    async fn receive_response(&self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use shared::network::try_receive_udp_packet;

        match try_receive_udp_packet(&self.socket, timeout).await? {
            Some((packet, addr)) => {
                // Filter out local addresses (already done in receive_udp_packet)
                Ok(ReceiveResult::Response(packet, addr))
            }
            None => Ok(ReceiveResult::Timeout),
        }
    }

    async fn send_confirmation(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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

    async fn send_cancel(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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
}

/// BLE transport using direct BlueZ access via D-Bus
#[cfg(feature = "ble")]
#[allow(dead_code)] // timeout is passed to receive_response
pub struct BleTransport {
    adapter: bluer::Adapter,
    temporal_id: [u8; 10],
    timeout: Duration,
    request_packet: Arc<tokio::sync::Mutex<Option<EncryptedPacket>>>,
    config_manager: Arc<shared::config::ClientConfigManager>,
    keypair: Arc<shared::crypto::Ed25519KeyPair>,
    challenge: [u8; 32],
    // Keep advertisement and GATT server alive
    adv_handle: Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
    gatt_handle: Arc<tokio::sync::Mutex<Option<bluer::gatt::local::ApplicationHandle>>>,
    // Shared state for GATT server callbacks
    confirmation_data: Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
    // Store all connected devices to disconnect them on cancel
    connected_devices: Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    // Queue of responses from potentially multiple devices
    response_queue: Arc<tokio::sync::Mutex<VecDeque<Vec<u8>>>>,
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
        tracing::trace!("BleTransport::new - initializing BlueZ session");
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

        // Ensure adapter is powered on; attempt to power it if not.
        match adapter.is_powered().await {
            Ok(true) => tracing::trace!("Adapter already powered"),
            Ok(false) => {
                tracing::info!("Bluetooth adapter is off; attempting to power it on");
                if let Err(e) = adapter.set_powered(true).await {
                    tracing::warn!(
                        "Failed to power on Bluetooth adapter ({}); falling back to UDP",
                        e
                    );
                    return Err(AuthError::BleError(
                        "Bluetooth adapter not powered".to_string(),
                    ));
                } else {
                    tracing::info!("Bluetooth adapter powered on successfully");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to query adapter power state ({}); attempting to power on",
                    e
                );
                if let Err(e2) = adapter.set_powered(true).await {
                    tracing::warn!(
                        "Failed to power on Bluetooth adapter after query error ({}); falling back to UDP",
                        e2
                    );
                    return Err(AuthError::BleError(
                        "Bluetooth adapter not powered".to_string(),
                    ));
                }
            }
        }
        Ok(Self {
            adapter,
            temporal_id,
            timeout,
            request_packet: Arc::new(tokio::sync::Mutex::new(None)),
            config_manager,
            keypair,
            challenge,
            adv_handle: Arc::new(tokio::sync::Mutex::new(None)),
            gatt_handle: Arc::new(tokio::sync::Mutex::new(None)),
            confirmation_data: Arc::new(tokio::sync::Mutex::new(None)),
            connected_devices: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            response_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
        })
    }
}

#[cfg(feature = "ble")]
impl Transport for BleTransport {
    async fn send_request(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
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
        if self.adv_handle.lock().await.is_some() {
            // Already set up, nothing to do
            return Ok(());
        }

        let send_start = Instant::now();
        tracing::trace!("send_request started");

        // Store the packet for later use in receive_response
        *self.request_packet.lock().await = Some(packet.clone());

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
            // Balanced advertising: faster than default, but not battery-killing
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(200)),
            ..Default::default()
        };

        // Start advertising (will be kept alive until BleTransport is dropped)
        // Try multiple times to handle "Busy" errors
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match self.adapter.advertise(advertisement.clone()).await {
                Ok(handle) => {
                    tracing::trace!(
                        "BLE advertising started (attempt {}), elapsed={:?}",
                        attempt,
                        send_start.elapsed()
                    );
                    *self.adv_handle.lock().await = Some(handle);
                    break;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    let is_busy = error_msg.contains("Busy") || error_msg.contains("0x0a");

                    if attempt < MAX_ATTEMPTS {
                        if is_busy {
                            tracing::warn!(
                                "BLE advertising is busy, retrying in 150ms (attempt {}/{})",
                                attempt,
                                MAX_ATTEMPTS
                            );
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        } else {
                            tracing::warn!(
                                "Failed to start BLE advertising (attempt {}): {}. Retrying...",
                                attempt,
                                e
                            );
                            tokio::time::sleep(Duration::from_millis(100)).await;
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

        let adapter = self.adapter.clone();

        // Client Command Characteristic - Server reads auth request
        let request_data_for_read = request_data.clone();
        let connected_devices_read = self.connected_devices.clone();
        let adapter_read = adapter.clone();
        let client_cmd_char = Characteristic {
            uuid: client_cmd_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |req| {
                    let data = request_data_for_read.clone();
                    let connected_devices = connected_devices_read.clone();
                    let adapter = adapter_read.clone();
                    Box::pin(async move {
                        let addr = req.device_address;
                        tracing::debug!(
                            "GATT: Device {} reading auth request ({} bytes)",
                            addr,
                            data.len()
                        );

                        match adapter.device(addr) {
                            Ok(device) => {
                                connected_devices.lock().await.insert(addr, device);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to get device object for {}: {}", addr, e);
                            }
                        }
                        Ok((*data).clone())
                    })
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Server Response Characteristic - Server writes response
        let response_queue = self.response_queue.clone();
        let connected_devices_write = self.connected_devices.clone();
        let adapter_write = adapter.clone();
        let server_resp_char = Characteristic {
            uuid: server_resp_uuid,
            write: Some(CharacteristicWrite {
                write: true,
                write_without_response: true,
                method: bluer::gatt::local::CharacteristicWriteMethod::Fun(Box::new(
                    move |new_value, req| {
                        let response_queue = response_queue.clone();
                        let connected_devices = connected_devices_write.clone();
                        let adapter = adapter_write.clone();
                        Box::pin(async move {
                            let addr = req.device_address;
                            tracing::info!(
                                "GATT: Received server response ({} bytes) from device {}",
                                new_value.len(),
                                addr
                            );

                            match adapter.device(addr) {
                                Ok(device) => {
                                    connected_devices.lock().await.insert(addr, device);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to get device object for {}: {}",
                                        addr,
                                        e
                                    );
                                }
                            }

                            // Enqueue the response bytes
                            response_queue.lock().await.push_back(new_value);
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
        *self.gatt_handle.lock().await = Some(app_handle);

        tracing::trace!(
            "GATT server registered and ready, total send_request elapsed={:?}",
            send_start.elapsed()
        );
        tracing::trace!("send_request completed in {:?}", send_start.elapsed());
        Ok(())
    }

    async fn receive_response(&self, timeout: Duration) -> Result<ReceiveResult, AuthError> {
        use prost::Message;
        use shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce;
        use shared::protocol::pb::wrapper_message;

        let request_packet = self
            .request_packet
            .lock()
            .await
            .as_ref()
            .ok_or_else(|| {
                AuthError::BleError(
                    "send_request must be called before receive_response".to_string(),
                )
            })?
            .clone();

        let response_queue = self.response_queue.clone();

        // Wait for response with timeout
        let start = std::time::Instant::now();
        tracing::trace!("receive_response started, timeout={:?}", timeout);
        loop {
            if start.elapsed() >= timeout {
                return Ok(ReceiveResult::Timeout);
            }

            // Check if we received a response from GATT callback
            let response_bytes;
            {
                // Lock, pop, and unlock quickly
                response_bytes = response_queue.lock().await.pop_front();
            }

            if let Some(response_bytes) = response_bytes {
                tracing::trace!(
                    "Processing received BLE response ({} bytes), elapsed={:?}",
                    response_bytes.len(),
                    start.elapsed()
                );

                // Parse and decrypt response
                let encrypted_response = match EncryptedPacket::decode(&response_bytes[..]) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decode response: {}, waiting for other devices",
                            e
                        );
                        continue;
                    }
                };

                // Load CSK from config manager
                let csk = self.config_manager.load_csk().map_err(AuthError::Config)?;

                // Decrypt response
                let decrypted_message =
                    match decrypt_encrypted_packet_with_csk_nonce(&csk, &encrypted_response) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decrypt response: {}, waiting for other devices",
                                e
                            );
                            continue;
                        }
                    };

                // Check message type and store confirmation
                match decrypted_message.payload {
                    Some(wrapper_message::Payload::AuthGrant(_)) => {
                        // Create GrantConfirmation
                        if let Ok(confirmation) = self.create_confirmation(&request_packet) {
                            *self.confirmation_data.lock().await = Some(confirmation);
                            tracing::trace!(
                                "Stored confirmation for server to read, elapsed={:?}",
                                start.elapsed()
                            );
                        }
                    }
                    _ => {
                        tracing::warn!("Unexpected message type, waiting for other devices");
                        continue;
                    }
                };

                // Wait briefly for server to read confirmation
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Return success - the encrypted response will be verified by auth_client
                // We use a dummy SocketAddr since BLE doesn't have IP addresses
                tracing::trace!(
                    "receive_response returning Response, total elapsed={:?}",
                    start.elapsed()
                );
                return Ok(ReceiveResult::Response(
                    encrypted_response,
                    "0.0.0.0:0".parse().unwrap(),
                ));
            }

            // Sleep briefly before checking again
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn send_confirmation(&self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        // Confirmation is handled in receive_response
        Ok(())
    }

    async fn send_cancel(&self, _packet: &EncryptedPacket) -> Result<(), AuthError> {
        tracing::debug!(
            "BLE transport: send_cancel called, disconnecting clients and stopping services."
        );
        self.shutdown_impl().await
    }

    async fn finalize(&self) -> Result<(), AuthError> {
        tracing::debug!("BLE transport: finalize called");
        self.shutdown_impl().await
    }
}

#[cfg(feature = "ble")]
impl BleTransport {
    /// Create a GrantConfirmation message
    fn create_confirmation(&self, request_packet: &EncryptedPacket) -> Result<Vec<u8>, AuthError> {
        use prost::Message;
        use shared::crypto::encrypt_with_csk_and_random_nonce;
        use shared::protocol::messages::create_grant_confirmation;
        use shared::protocol::packet::wrap_grant_confirmation;

        // Load CSK
        let csk = self.config_manager.load_csk().map_err(AuthError::Config)?;

        // Create GrantConfirmation with challenge signature
        let confirmation = create_grant_confirmation(&self.keypair, &self.challenge)
            .map_err(|e| AuthError::BleError(format!("Failed to create confirmation: {}", e)))?;

        // Wrap in WrapperMessage
        let wrapper = wrap_grant_confirmation(confirmation);

        // Serialize wrapper
        let plaintext = wrapper.encode_to_vec();

        // Encrypt using CSK with a random, prepended nonce
        let ciphertext = encrypt_with_csk_and_random_nonce(&csk, &plaintext)
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

    /// Internal shutdown routine shared by send_cancel and finalize
    async fn shutdown_impl(&self) -> Result<(), AuthError> {
        // Step 1 - Disconnect all connected BLE devices
        let mut disconnected_count = 0;
        let devices_to_disconnect = self.connected_devices.lock().await;

        let adapter = self.adapter.clone();

        for (addr, _device_in_map) in devices_to_disconnect.iter() {
            tracing::debug!("Attempting to explicitly disconnect device {}", addr);

            match adapter.device(*addr) {
                Ok(device) => {
                    if let Err(e) = device.disconnect().await {
                        tracing::warn!("Failed to explicitly disconnect device {}: {}", addr, e);
                    } else {
                        tracing::info!("Successfully disconnected device {}", addr);
                        disconnected_count += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to re-fetch device {} for disconnect: {}", addr, e);
                }
            }
        }

        if disconnected_count > 0 {
            tracing::debug!("Disconnected {} BLE device(s).", disconnected_count);
        } else if !devices_to_disconnect.is_empty() {
            tracing::warn!("Failed to disconnect any connected BLE devices.");
        } else {
            tracing::trace!("No connected BLE devices to disconnect.");
        }

        // Step 2 - Stop advertising to prevent new connections
        if self.adv_handle.lock().await.take().is_some() {
            tracing::trace!("BLE advertising stopped.");
        } else {
            tracing::trace!("BLE advertising was not active or already stopped.");
        }

        // Step 3 - Unregister GATT server to remove services
        if self.gatt_handle.lock().await.take().is_some() {
            tracing::trace!("BLE GATT server unregistered.");
        } else {
            tracing::trace!("BLE GATT server was not active or already stopped.");
        }

        Ok(())
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
        // Note: The handles (adv_handle, gatt_handle) will be dropped here
        // automatically by Rust, which cleans up the adv/GATT server.
        tracing::debug!("BLE transport explicitly closed, cleaning up resources.");

        if let Some(mutex) = Arc::get_mut(&mut self.connected_devices) {
            let map = mutex.get_mut();
            let device_count = map.len();

            if device_count > 0 {
                tracing::warn!(
                    "BleTransport dropped with {} connected device(s) still tracked. \
                     Call send_cancel() for explicit cleanup.",
                    device_count
                );
            }
        } else {
            // Devices are still shared, meaning a task might still be running.
            // We can't easily clean up here without a more complex shutdown mechanism.
            tracing::trace!(
                "BleTransport dropped. Handles will be released. \
                Cannot check for connected devices as Arc is still shared."
            );
        }
    }
}
