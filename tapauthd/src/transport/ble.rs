//! BLE transport using direct BlueZ access via D-Bus

use super::{ReceiveResult, Transport};
use crate::auth_handler::AuthHandlerError as AuthError;
use shared::protocol::pb::EncryptedPacket;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// BLE transport using direct BlueZ access via D-Bus
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
    // Idempotent shutdown flag
    shutdown_started: AtomicBool,
}

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
            shutdown_started: AtomicBool::new(false),
        })
    }

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

    /// Static shutdown implementation operating on cloned handles
    async fn do_shutdown(
        adapter: bluer::Adapter,
        adv_handle: Arc<tokio::sync::Mutex<Option<bluer::adv::AdvertisementHandle>>>,
        gatt_handle: Arc<tokio::sync::Mutex<Option<bluer::gatt::local::ApplicationHandle>>>,
        connected_devices: Arc<tokio::sync::Mutex<HashMap<bluer::Address, bluer::Device>>>,
    ) -> Result<(), AuthError> {
        // Step 1 - Disconnect all connected BLE devices
        let mut disconnected_count = 0;
        let mut devices_to_disconnect = connected_devices.lock().await;

        let adapter_clone = adapter.clone();

        for (addr, _device_in_map) in devices_to_disconnect.iter() {
            tracing::debug!("Attempting to explicitly disconnect device {}", addr);

            match adapter_clone.device(*addr) {
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

        // Clear tracked devices to avoid retaining stale references
        let tracked = devices_to_disconnect.len();
        devices_to_disconnect.clear();
        drop(devices_to_disconnect);

        if disconnected_count > 0 {
            tracing::debug!("Disconnected {} BLE device(s).", disconnected_count);
        } else if tracked > 0 {
            tracing::warn!(
                "Failed to disconnect any of the {} connected BLE device(s).",
                tracked
            );
        } else {
            tracing::trace!("No connected BLE devices to disconnect.");
        }

        // Step 2 - Stop advertising to prevent new connections
        if adv_handle.lock().await.take().is_some() {
            tracing::trace!("BLE advertising stopped.");
        } else {
            tracing::trace!("BLE advertising was not active or already stopped.");
        }

        // Step 3 - Unregister GATT server to remove services
        if gatt_handle.lock().await.take().is_some() {
            tracing::trace!("BLE GATT server unregistered.");
        } else {
            tracing::trace!("BLE GATT server was not active or already stopped.");
        }

        Ok(())
    }
}

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
                let dummy_addr = "0.0.0.0:0".parse().unwrap_or_else(|_| {
                    std::net::SocketAddr::from(([0, 0, 0, 0], 0))
                });
                return Ok(ReceiveResult::Response(encrypted_response, dummy_addr));
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
        // Ensure idempotent scheduling
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            // Determine grace window from env or default 300ms
            let grace_ms: u64 = std::env::var("TAPAUTH_BLE_GRACE_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(300);

            tracing::debug!(
                "BLE transport: send_cancel called, scheduling cleanup in {} ms",
                grace_ms
            );

            let adapter = self.adapter.clone();
            let adv_handle = self.adv_handle.clone();
            let gatt_handle = self.gatt_handle.clone();
            let connected_devices = self.connected_devices.clone();

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(grace_ms)).await;
                if let Err(e) =
                    BleTransport::do_shutdown(adapter, adv_handle, gatt_handle, connected_devices)
                        .await
                {
                    tracing::warn!("BLE delayed shutdown failed: {}", e);
                } else {
                    tracing::debug!("BLE delayed shutdown completed");
                }
            });
        } else {
            tracing::trace!("BLE transport: send_cancel called, but shutdown already scheduled");
        }

        Ok(())
    }

    async fn finalize(&self) -> Result<(), AuthError> {
        // Trigger immediate background shutdown if not yet started
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            tracing::debug!("BLE transport: finalize called, scheduling immediate cleanup");
            let adapter = self.adapter.clone();
            let adv_handle = self.adv_handle.clone();
            let gatt_handle = self.gatt_handle.clone();
            let connected_devices = self.connected_devices.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    BleTransport::do_shutdown(adapter, adv_handle, gatt_handle, connected_devices)
                        .await
                {
                    tracing::warn!("BLE finalize shutdown failed: {}", e);
                } else {
                    tracing::trace!("BLE finalize shutdown completed");
                }
            });
        } else {
            tracing::trace!("BLE transport: finalize called, but shutdown already scheduled");
        }
        Ok(())
    }
}

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
