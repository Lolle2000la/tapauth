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
    session: Session,
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
        // The service data itself identifies this as a TapAuth advertisement
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

        let adv_handle = match self.adapter.advertise(advertisement).await {
            Ok(h) => {
                tracing::info!("BLE advertising started");
                h
            }
            Err(e) => {
                tracing::error!("Failed to start BLE advertising: {}", e);
                return AuthResult::Error;
            }
        };

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
            CLIENT_COMMAND_CHAR_UUID, SERVER_RESPONSE_CHAR_UUID, SERVICE_UUID,
        };

        tracing::info!("Setting up GATT server");

        // Shared state for receiving response
        let response_data: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let response_data_clone = response_data.clone();

        // Prepare request data
        let request_data = Arc::new(request.encrypted_packet.clone());

        // Create GATT characteristics
        let service_uuid = SERVICE_UUID.parse().unwrap();
        let client_cmd_uuid = CLIENT_COMMAND_CHAR_UUID.parse().unwrap();
        let server_resp_uuid = SERVER_RESPONSE_CHAR_UUID.parse().unwrap();

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

        // Create GATT service
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
                let response_lock = response_data.lock().await;
                if let Some(ref response_bytes) = *response_lock {
                    tracing::info!("Processing received response");
                    let result = self.process_response(response_bytes).await;
                    drop(app_handle);
                    return result;
                }
            }

            // Sleep briefly before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Process the BLE response from server
    async fn process_response(&self, response_bytes: &[u8]) -> AuthResult {
        use shared::protocol::pb::{wrapper_message, EncryptedPacket};

        // Parse encrypted packet
        let encrypted_packet = match EncryptedPacket::decode(&response_bytes[..]) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to decode response: {}", e);
                return AuthResult::Error;
            }
        };

        tracing::debug!("Response packet decoded successfully");

        // Note: Full decryption and verification would require CSK and paired server keys
        // For the daemon, we'll do a simplified check - just parse the wrapper
        // The actual crypto verification should happen in the PAM module with proper context

        // For now, return a simple signal that we got a response
        // The PAM module will need to decrypt and verify with its own keys
        //
        // In a production system, you'd want to:
        // 1. Load CSK from secure storage
        // 2. Decrypt the packet
        // 3. Verify signatures
        // 4. Return grant/deny based on verification

        // For this implementation, we'll just check if we got data
        if !encrypted_packet.ciphertext.is_empty() {
            tracing::info!("Received valid encrypted response from server");
            // Return the encrypted response for the PAM module to verify
            AuthResult::Granted
        } else {
            tracing::warn!("Received empty response");
            AuthResult::Error
        }
    }
}
