//! BLE authentication handler for the daemon
//!
//! This module handles the actual BLE authentication flow using the
//! advertiser/peripheral role with GATT server.

use crate::dbus_interface::AuthRequest;
use bluer::{
    adv::Advertisement,
    gatt::local::{Application, Characteristic, CharacteristicRead, CharacteristicWrite, Service},
    Adapter, Session,
};
use prost::Message as ProstMessage;
use shared::AuthResult;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct BleAuthHandler {
    #[allow(dead_code)]
    session: Session, // should persist for lifetime of the handler
    adapter: Adapter,
}

impl BleAuthHandler {
    /// Create a new BLE authentication handler
    pub async fn new() -> anyhow::Result<Self> {
        tracing::info!("Initializing BLE authentication handler");

        let session = Session::new().await?;
        let adapter_names = session.adapter_names().await?;
        let adapter_name = adapter_names
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Bluetooth adapter found"))?;

        tracing::info!("Using Bluetooth adapter: {}", adapter_name);
        let adapter = session.adapter(adapter_name)?;

        // Ensure adapter is powered on
        adapter.set_powered(true).await?;
        tracing::info!("Bluetooth adapter powered on");

        Ok(Self { session, adapter })
    }

    /// Handle an authentication request
    pub async fn handle_authentication(&self, request: AuthRequest) -> AuthResult {
        tracing::info!(
            "Starting BLE authentication (timeout={}s)",
            request.timeout_secs
        );

        // Start advertising with temporal ID
        // Only advertise service data to stay within 31-byte BLE advertisement limit
        // The SERVICE_UUID is used as the key in the service_data map, with the
        // 10-byte temporal identifier as the value. This identifies the advertisement
        // as TapAuth while keeping the packet size minimal.
        let advertisement = Advertisement {
            // Do NOT include service_uuids - it adds 18 bytes and causes packet overflow
            service_data: [(
                shared::models::ble::SERVICE_UUID.parse().unwrap(),
                request.temporal_id.to_vec(),
            )]
            .into_iter()
            .collect(),
            discoverable: Some(true),
            // Empty local name to save bytes (would add 10+ bytes)
            local_name: Some("".to_string()),
            ..Default::default()
        };

        // Retry advertising up to 5 times with increasing delays
        // This handles the "Busy" error that can occur when the adapter hasn't
        // fully released previous advertisements or bluetoothd is temporarily busy
        let mut adv_handle = None;
        const MAX_ATTEMPTS: u32 = 5;

        for attempt in 1..=MAX_ATTEMPTS {
            match self.adapter.advertise(advertisement.clone()).await {
                Ok(h) => {
                    if attempt > 1 {
                        tracing::info!(
                            "BLE advertising started (succeeded on attempt {})",
                            attempt
                        );
                    } else {
                        tracing::info!("BLE advertising started");
                    }
                    adv_handle = Some(h);
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
                            // Use longer delay for "Busy" errors to allow bluetoothd to clean up
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            tracing::warn!(
                                "Failed to start BLE advertising (attempt {}): {}. Retrying...",
                                attempt,
                                e
                            );
                            // Use shorter delay for other errors
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    } else {
                        tracing::error!(
                            "Failed to start BLE advertising after {} attempts: {}",
                            attempt,
                            e
                        );
                        if is_busy {
                            tracing::error!(
                                "Bluetooth advertising slots are full or not releasing properly."
                            );
                            tracing::error!("This usually means:");
                            tracing::error!(
                                "  1. Another application is using all advertising slots"
                            );
                            tracing::error!(
                                "  2. Previous daemon instances didn't shut down cleanly"
                            );
                            tracing::error!("  3. bluetoothd needs to be restarted");
                            tracing::error!("Try: sudo systemctl restart bluetooth");
                        } else {
                            tracing::error!(
                                "Check if other applications are using Bluetooth advertising"
                            );
                        }
                        return AuthResult::Error;
                    }
                }
            }
        }

        let adv_handle = adv_handle.expect("adv_handle should be set if loop succeeded");

        // Set up GATT server
        let result = self
            .run_gatt_server(&request, Duration::from_secs(request.timeout_secs))
            .await;

        // Stop advertising
        drop(adv_handle);
        tracing::info!("BLE advertising stopped");

        result
    }

    /// Run GATT server and wait for authentication response
    async fn run_gatt_server(&self, request: &AuthRequest, timeout: Duration) -> AuthResult {
        use shared::models::ble::{
            CLIENT_COMMAND_CHAR_UUID, CLIENT_CONFIRMATION_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID,
            SERVICE_UUID,
        };

        tracing::info!("Setting up GATT server");

        // Shared state for receiving response
        let response_data: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let response_data_clone = response_data.clone();

        // Shared state for sending confirmation
        let confirmation_data: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let confirmation_data_for_read = confirmation_data.clone();

        // Prepare request data
        let request_data = Arc::new(request.encrypted_packet.clone());

        // Create GATT characteristics
        let service_uuid = SERVICE_UUID.parse().unwrap();
        let client_cmd_uuid = CLIENT_COMMAND_CHAR_UUID.parse().unwrap();
        let server_resp_uuid = SERVER_RESPONSE_CHAR_UUID.parse().unwrap();
        let client_conf_uuid = CLIENT_CONFIRMATION_CHAR_UUID.parse().unwrap();

        // Client Command Characteristic - Server (Android Central) READS auth request from this
        // Desktop (Peripheral) provides the authentication request here
        // NOTE: Spec says WRITE property, but that's backwards - Central needs to READ from Peripheral
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

        // Server Response Characteristic - Server (Android Central) WRITES response to this
        // Desktop (Peripheral) receives the authentication response here
        // NOTE: Spec says NOTIFY property, but that's backwards - Central needs to WRITE to Peripheral
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

        // Client Confirmation Characteristic - Server (Android Central) READS confirmation from this
        // Desktop (Peripheral) provides the GrantConfirmation here
        let client_conf_char = Characteristic {
            uuid: client_conf_uuid,
            read: Some(CharacteristicRead {
                read: true,
                fun: Box::new(move |_req| {
                    let conf_data = confirmation_data_for_read.clone();
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
        let app_handle = match self.adapter.serve_gatt_application(app).await {
            Ok(h) => {
                tracing::info!("GATT server registered and waiting for connections");
                h
            }
            Err(e) => {
                tracing::error!("Failed to register GATT server: {}", e);
                return AuthResult::Error;
            }
        };

        // Wait for response with timeout
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                tracing::warn!("BLE authentication timeout");
                drop(app_handle);
                return AuthResult::Timeout;
            }

            // Check if we received a response
            {
                let mut response_lock = response_data.lock().await;
                if let Some(ref response_bytes) = *response_lock {
                    tracing::info!("Processing received response");
                    let result = self.process_response(response_bytes).await;

                    match result {
                        AuthResult::Granted | AuthResult::Denied => {
                            // Valid response - create and store confirmation per spec
                            tracing::debug!(
                                "Creating GrantConfirmation to halt server retransmissions"
                            );
                            if let Ok(conf_bytes) =
                                self.create_confirmation(&request.encrypted_packet).await
                            {
                                *confirmation_data.lock().await = Some(conf_bytes);
                                tracing::debug!(
                                    "GrantConfirmation stored and ready for server to read"
                                );
                            } else {
                                tracing::warn!("Failed to create GrantConfirmation");
                            }

                            // Keep GATT server alive briefly to allow server to read confirmation
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            drop(app_handle);
                            return result;
                        }
                        AuthResult::Error => {
                            // Malformed response - log and continue waiting for other devices
                            tracing::warn!("Received malformed response, clearing and waiting for other devices");
                            *response_lock = None;
                            // Continue loop - keep GATT server running
                        }
                        AuthResult::Timeout => {
                            // Shouldn't happen here, but handle it
                            tracing::warn!("Timed out, clearing and waiting for other devices ");
                            *response_lock = None;
                        }
                    }
                }
            }

            // Sleep briefly before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Process the BLE response from server
    async fn process_response(&self, response_bytes: &[u8]) -> AuthResult {
        use shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce;
        use shared::protocol::pb::{wrapper_message, EncryptedPacket};

        // Parse encrypted packet
        let encrypted_packet = match EncryptedPacket::decode(response_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to decode response: {}", e);
                return AuthResult::Error;
            }
        };

        tracing::debug!("Response packet decoded successfully");

        // Load CSK from config to decrypt the response
        // This allows us to determine if it's a Grant or Denial
        let config_manager = shared::config::ClientConfigManager::new();

        let csk = match config_manager.load_csk() {
            Ok(csk) => csk,
            Err(e) => {
                tracing::error!("Failed to load CSK: {}", e);
                return AuthResult::Error;
            }
        };

        // Decrypt the packet using CSK-based nonce
        let wrapper = match decrypt_encrypted_packet_with_csk_nonce(&csk, &encrypted_packet) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to decrypt response: {}", e);
                return AuthResult::Error;
            }
        };

        // Check what type of message we received
        match wrapper.payload {
            Some(wrapper_message::Payload::AuthGrant(_)) => {
                tracing::info!("Received authentication grant from server");
                AuthResult::Granted
            }
            Some(wrapper_message::Payload::AuthDenial(_)) => {
                tracing::warn!("Received authentication denial from server");
                AuthResult::Denied
            }
            _ => {
                tracing::error!("Received unexpected message type in response");
                AuthResult::Error
            }
        }
    }

    /// Create a GrantConfirmation message to send back to the server
    async fn create_confirmation(&self, request_packet: &[u8]) -> Result<Vec<u8>, String> {
        use prost::Message;
        use shared::config::ClientConfigManager;
        use shared::protocol::messages::create_grant_confirmation;
        use shared::protocol::packet::{
            create_encrypted_packet_with_csk_nonce, wrap_grant_confirmation,
        };
        use shared::protocol::pb::EncryptedPacket;

        // Decode the original request to extract the challenge
        let request_encrypted_packet = EncryptedPacket::decode(request_packet)
            .map_err(|e| format!("Failed to decode request packet: {}", e))?;

        // We need to decrypt it to get the challenge
        let config_manager = ClientConfigManager::new();
        let csk = config_manager
            .load_csk()
            .map_err(|e| format!("Failed to load CSK: {}", e))?;

        let request_wrapper = shared::protocol::packet::decrypt_encrypted_packet_with_csk_nonce(
            &csk,
            &request_encrypted_packet,
        )
        .map_err(|e| format!("Failed to decrypt request: {}", e))?;

        // Extract challenge from the request
        let challenge = shared::protocol::packet::extract_challenge(&request_wrapper)
            .ok_or_else(|| "No challenge in request".to_string())?;

        if challenge.len() != 32 {
            return Err(format!("Invalid challenge length: {}", challenge.len()));
        }

        let mut challenge_array = [0u8; 32];
        challenge_array.copy_from_slice(&challenge);

        // Load keypair to sign the confirmation
        let keypair = config_manager
            .load_keypair()
            .map_err(|e| format!("Failed to load keypair: {}", e))?;

        // Create and sign the confirmation
        let confirmation = create_grant_confirmation(&keypair, &challenge_array)
            .map_err(|e| format!("Failed to create confirmation: {}", e))?;

        // Wrap and encrypt it
        let wrapper = wrap_grant_confirmation(confirmation);
        let encrypted_packet = create_encrypted_packet_with_csk_nonce(&csk, &wrapper)
            .map_err(|e| format!("Failed to encrypt confirmation: {}", e))?;

        // Serialize to bytes
        let mut bytes = Vec::new();
        encrypted_packet
            .encode(&mut bytes)
            .map_err(|e| format!("Failed to encode confirmation: {}", e))?;

        Ok(bytes)
    }
}
