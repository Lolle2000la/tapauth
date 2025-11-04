//! Authentication request handler that creates on-demand transports and runs auth flow.

use crate::transport::{ReceiveResult, Transport};
use shared::{
    config::ClientConfigManager,
    crypto::{ClientSymmetricKey, CryptoError, Ed25519KeyPair},
    network::get_session_timeout,
    protocol::{messages::*, packet::*, pb::EncryptedPacket, ProtocolError},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[cfg(feature = "ble")]
use tokio::sync::Mutex;

#[cfg(feature = "ble")]
use shared::crypto::generate_current_temporal_identifier_ble;

use shared::ipc::pb as ipc;

#[derive(Debug, thiserror::Error)]
pub enum AuthHandlerError {
    #[error("Configuration error: {0}")]
    Config(#[from] shared::config::ConfigError),
    #[error("Network error: {0}")]
    Network(#[from] shared::network::NetworkError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Authentication timeout")]
    Timeout,
    #[error("Authentication denied")]
    Denied,
    #[error("Authentication explicitly denied by user")]
    ExplicitDenial,
    #[error("No paired devices")]
    NoPairedDevices,
    #[error("BLE error: {0}")]
    BleError(String),
}

/// Shared state for daemon - loaded once at startup
pub struct DaemonState {
    pub config_manager: ClientConfigManager,
    pub keypair: Ed25519KeyPair,
    pub csk: ClientSymmetricKey,
    pub hostname: String,
    pub udp_socket: Arc<tokio::net::UdpSocket>,
}

impl DaemonState {
    pub fn new(udp_socket: tokio::net::UdpSocket) -> Result<Self, AuthHandlerError> {
        let config_manager = ClientConfigManager::new();

        let keypair = config_manager
            .load_keypair()
            .map_err(AuthHandlerError::Config)?;

        let csk = config_manager
            .load_csk()
            .map_err(AuthHandlerError::Config)?;

        let config = config_manager.load_config()?;
        let hostname = config.hostname;

        Ok(Self {
            config_manager,
            keypair,
            csk,
            hostname,
            udp_socket: Arc::new(udp_socket),
        })
    }
}

#[cfg(feature = "ble")]
type CancelRegistry = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

#[cfg(not(feature = "ble"))]
type CancelRegistry = Arc<HashMap<String, oneshot::Sender<()>>>;

/// Per-request authentication session
pub struct AuthSession {
    state: Arc<DaemonState>,
    username: String,
    challenge: [u8; 32],
    #[allow(dead_code)] // Used in select! macro via cancel_rx local variable
    cancel_rx: Option<oneshot::Receiver<()>>,
    cancel_registry: Option<CancelRegistry>,
    request_id: Option<String>,
}

impl AuthSession {
    pub fn new(state: Arc<DaemonState>, username: String) -> Result<Self, std::io::Error> {
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("random generation failed: {}", e),
            )
        })?;

        Ok(Self {
            state,
            username,
            challenge,
            cancel_rx: None,
            cancel_registry: None,
            request_id: None,
        })
    }

    /// Handle PamAuthenticateRequest - creates transports on-demand, runs auth flow
    pub async fn handle_authenticate(
        mut self,
        timeout_seconds: Option<u32>,
        request_id: Option<String>,
        #[cfg(feature = "ble")] cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
        #[cfg(not(feature = "ble"))] cancel_registry: Arc<HashMap<String, oneshot::Sender<()>>>,
    ) -> Result<ipc::PamAuthenticateResponse, AuthHandlerError> {
        // Record cancel context for targeted cancellation
        self.request_id = request_id;
        self.cancel_registry = Some(cancel_registry);
        // Check if we have any paired devices
        let paired_servers = self.state.config_manager.load_paired_servers()?;
        if paired_servers.is_empty() {
            // No configuration/pairings yet: do not block other PAM methods
            return Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Ignore as i32,
                detail: "No paired devices configured".to_string(),
                challenge: self.challenge.to_vec(),
            });
        }

        // Filter servers that are allowed to authenticate this user
        let allowed_servers: Vec<_> = paired_servers
            .iter()
            .filter(|(_, server)| server.is_user_allowed(&self.username))
            .collect();

        if allowed_servers.is_empty() {
            tracing::warn!("No paired servers authorized for user: {}", self.username);
            return Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Ignore as i32,
                detail: format!("No servers authorized for user {}", self.username),
                challenge: self.challenge.to_vec(),
            });
        }

        tracing::info!(
            "{} server(s) authorized for user {}",
            allowed_servers.len(),
            self.username
        );

        // Create the authentication request
        let request = create_auth_request_with_challenge(
            &self.username,
            &self.state.hostname,
            &self.challenge,
        )?;
        let mut wrapper = wrap_auth_request(request);
        sign_wrapper_message(&mut wrapper, &self.state.keypair)?;
        let packet = create_encrypted_packet_with_csk_nonce(&self.state.csk, &wrapper)?;

        // Run authentication with timeout
        let timeout_duration = Duration::from_secs(timeout_seconds.unwrap_or(30) as u64);

        let auth_result =
            tokio::time::timeout(timeout_duration, self.try_parallel_authentication(&packet)).await;

        match auth_result {
            Ok(Ok(())) => Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Success as i32,
                detail: format!("Authenticated user {} successfully", self.username),
                challenge: self.challenge.to_vec(),
            }),
            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                tracing::warn!(
                    "Authentication explicitly denied by user for: {}",
                    self.username
                );
                Ok(ipc::PamAuthenticateResponse {
                    outcome: ipc::PamOutcome::Denied as i32,
                    detail: "Authentication explicitly denied by user".to_string(),
                    challenge: self.challenge.to_vec(),
                })
            }
            Ok(Err(e)) => {
                tracing::error!("Authentication failed: {}", e);
                Ok(ipc::PamAuthenticateResponse {
                    outcome: ipc::PamOutcome::Denied as i32,
                    detail: format!("Authentication failed: {}", e),
                    challenge: self.challenge.to_vec(),
                })
            }
            Err(_) => {
                tracing::warn!("Authentication timeout for user {}", self.username);
                Ok(ipc::PamAuthenticateResponse {
                    outcome: ipc::PamOutcome::Timeout as i32,
                    detail: "Authentication timeout".to_string(),
                    challenge: self.challenge.to_vec(),
                })
            }
        }
    }

    #[cfg(feature = "ble")]
    async fn try_parallel_authentication(
        &mut self,
        packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        use tokio::select;

        // Import transport implementations (we'll create them on-demand)
        use crate::transport::{BleTransport, UdpTransport};

        let temporal_id = generate_current_temporal_identifier_ble(&self.state.csk)?;
        let timeout = get_session_timeout();

        tracing::info!("Starting parallel discovery over UDP and BLE");

        // Use global UDP socket
        let config = self.state.config_manager.load_config()?;
        let udp_transport =
            UdpTransport::from_socket(self.state.udp_socket.clone(), config.udp_port);

        let config_manager = Arc::new(ClientConfigManager::new());
        let keypair = Arc::new(self.state.keypair.clone());
        let challenge = self.challenge;

        // Try to initialize BLE; if it fails, fall back to UDP-only
        let ble_attempt =
            BleTransport::new(temporal_id, timeout, config_manager, keypair, challenge).await;

        let udp_transport_shared = Arc::new(udp_transport);
        let ble_transport_shared: Option<Arc<BleTransport>> = match ble_attempt {
            Ok(ble) => Some(Arc::new(ble)),
            Err(e) => {
                tracing::warn!(
                    "BLE initialization failed ({}). Falling back to UDP-only.",
                    e
                );
                None
            }
        };

        // Create cancel channel
        let (cancel_tx, mut cancel_rx) = oneshot::channel();

        // Register cancel sender if we have a request_id
        if let (Some(reg), Some(id)) = (self.cancel_registry.as_ref(), self.request_id.as_ref()) {
            reg.lock().await.insert(id.clone(), cancel_tx);
        }

        // Pre-compute cancel packet to dismiss notifications
        let cancel_packet = {
            let msg = create_auth_cancel(&self.challenge)?;
            let mut wrapper = wrap_auth_cancel(msg);
            sign_wrapper_message(&mut wrapper, &self.state.keypair)?;
            create_encrypted_packet_with_csk_nonce(&self.state.csk, &wrapper)?
        };

        // Spawn BLE task if available
        let mut ble_handle = if let Some(ble_transport_task) = ble_transport_shared.clone() {
            let packet_ble = packet.clone();
            let csk = self.state.csk.clone();
            let keypair_clone = self.state.keypair.clone();
            let challenge = self.challenge;
            let cfg = Arc::new(ClientConfigManager::new());
            tokio::spawn(async move {
                Self::authenticate_with_transport(
                    ble_transport_task,
                    &packet_ble,
                    &csk,
                    &keypair_clone,
                    &challenge,
                    cfg,
                )
                .await
            })
        } else {
            tokio::spawn(async { Err(AuthHandlerError::BleError("BLE disabled".into())) })
        };

        // Spawn UDP task
        let packet_udp = packet.clone();
        let csk_udp = self.state.csk.clone();
        let keypair_udp = self.state.keypair.clone();
        let challenge_udp = self.challenge;
        let cfg = Arc::new(ClientConfigManager::new());
        let udp_transport_for_task = udp_transport_shared.clone();
        let mut udp_handle = tokio::spawn(async move {
            Self::authenticate_with_transport(
                udp_transport_for_task,
                &packet_udp,
                &csk_udp,
                &keypair_udp,
                &challenge_udp,
                cfg,
            )
            .await
        });
        let ble_abort = ble_handle.abort_handle();
        let udp_abort = udp_handle.abort_handle();

        // Wait for first success or both failures or cancellation
        select! {
            result = &mut ble_handle => {
                match result {
                    Ok(Ok(())) => {
                        tracing::info!("BLE authentication succeeded");
                        // Notify other devices via cancel and finalize resources (non-blocking for BLE)
                        if let Some(ble_shared) = &ble_transport_shared {
                            let ble = ble_shared.clone();
                            let cancel_clone = cancel_packet.clone();
                            tokio::spawn(async move {
                                let _ = ble.send_cancel(&cancel_clone).await;
                                let _ = ble.finalize().await;
                            });
                        }
                        let _ = udp_transport_shared.send_cancel(&cancel_packet).await;
                        udp_abort.abort();
                        Ok(())
                    }
                    Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                        tracing::warn!("BLE authentication explicitly denied by user");
                        // Broadcast cancellation to other devices
                        udp_abort.abort();
                        if let Some(ble_shared) = &ble_transport_shared {
                            let ble = ble_shared.clone();
                            tokio::spawn(async move { let _ = ble.finalize().await; });
                        }

                        let _ = udp_transport_shared.send_cancel(&cancel_packet).await;

                        Err(AuthHandlerError::ExplicitDenial)
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("BLE authentication failed: {}", e);
                        // Wait for UDP
                        match udp_handle.await {
                            Ok(Ok(())) => {
                                tracing::info!("UDP authentication succeeded");
                                if let Some(ble_shared) = &ble_transport_shared {
                                    let ble = ble_shared.clone();
                                    let cancel_clone = cancel_packet.clone();
                                    tokio::spawn(async move {
                                        let _ = ble.send_cancel(&cancel_clone).await;
                                        let _ = ble.finalize().await;
                                    });
                                }
                                let _ = udp_transport_shared.send_cancel(&cancel_packet).await;
                                Ok(())
                            }
                            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                                // UDP also got explicit denial, broadcast cancellation
                                if let Some(ble_shared) = &ble_transport_shared {
                                    let ble = ble_shared.clone();
                                    tokio::spawn(async move { let _ = ble.finalize().await; });
                                }

                                let _ = udp_transport_shared.send_cancel(&cancel_packet).await;

                                Err(AuthHandlerError::ExplicitDenial)
                            }
                            Ok(Err(e)) => {
                                tracing::error!("UDP authentication also failed: {}", e);
                                Err(AuthHandlerError::Denied)
                            }
                            Err(_) => Err(AuthHandlerError::Denied),
                        }
                    }
                    Err(_) => {
                        // Task panicked
                        tracing::error!("BLE task panicked");
                        match udp_handle.await {
                            Ok(Ok(())) => Ok(()),
                            _ => Err(AuthHandlerError::Denied),
                        }
                    }
                }
            }
            result = &mut udp_handle => {
                match result {
                    Ok(Ok(())) => {
                        tracing::info!("UDP authentication succeeded");
                        ble_abort.abort();
                        // Notify via cancel and finalize BLE if initialized (non-blocking)
                        if let Some(ble_shared) = &ble_transport_shared {
                            let ble = ble_shared.clone();
                            let cancel_clone = cancel_packet.clone();
                            tokio::spawn(async move {
                                let _ = ble.send_cancel(&cancel_clone).await;
                                let _ = ble.finalize().await;
                            });
                        }
                        let _ = udp_transport_shared.send_cancel(&cancel_packet).await;
                        Ok(())
                    }
                    Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                        tracing::warn!("UDP authentication explicitly denied by user");
                        // Broadcast cancellation to other devices
                        ble_abort.abort();
                        if let Some(ble_shared) = &ble_transport_shared {
                            let ble = ble_shared.clone();
                            tokio::spawn(async move { let _ = ble.finalize().await; });
                        }

                        let _ = udp_transport_shared.send_cancel(&cancel_packet).await;

                        Err(AuthHandlerError::ExplicitDenial)
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("UDP authentication failed: {}", e);
                        // Wait for BLE
                        match ble_handle.await {
                            Ok(Ok(())) => {
                                tracing::info!("BLE authentication succeeded");
                                if let Some(ble_shared) = &ble_transport_shared {
                                    let ble = ble_shared.clone();
                                    let cancel_clone = cancel_packet.clone();
                                    tokio::spawn(async move {
                                        let _ = ble.send_cancel(&cancel_clone).await;
                                        let _ = ble.finalize().await;
                                    });
                                }
                                let _ = udp_transport_shared.send_cancel(&cancel_packet).await;
                                Ok(())
                            }
                            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                                // BLE also got explicit denial, broadcast cancellation
                                if let Some(ble_shared) = &ble_transport_shared {
                                    let ble = ble_shared.clone();
                                    tokio::spawn(async move { let _ = ble.finalize().await; });
                                }

                                let _ = udp_transport_shared.send_cancel(&cancel_packet).await;

                                Err(AuthHandlerError::ExplicitDenial)
                            }
                            Ok(Err(e)) => {
                                tracing::error!("BLE authentication also failed: {}", e);
                                Err(AuthHandlerError::Denied)
                            }
                            Err(_) => Err(AuthHandlerError::Denied),
                        }
                    }
                    Err(_) => {
                        tracing::error!("UDP task panicked");
                        match ble_handle.await {
                            Ok(Ok(())) => Ok(()),
                            _ => Err(AuthHandlerError::Denied),
                        }
                    }
                }
            }
            _ = &mut cancel_rx => {
                let rid = self.request_id.as_deref().unwrap_or("-");
                tracing::info!("Authentication cancelled (user={}, id={})", self.username, rid);

                // Broadcast cancel using UDP transport
                tracing::info!("Broadcasting AuthenticationCancel over UDP");

                if let Err(e) = udp_transport_shared.send_cancel(&cancel_packet).await {
                    tracing::warn!("UDP cancel broadcast failed: {}", e);
                } else {
                    tracing::debug!("UDP cancel broadcast sent");
                }

                // Disconnect BLE clients explicitly (non-blocking)
                if let Some(ble_shared) = &ble_transport_shared {
                    tracing::debug!("Disconnecting BLE clients (background)");
                    let ble = ble_shared.clone();
                    tokio::spawn(async move { let _ = ble.finalize().await; });
                }

                // Give network stack time to transmit packets
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                // Now abort the tasks
                ble_abort.abort();
                udp_abort.abort();

                Err(AuthHandlerError::Denied)
            }
        }
    }

    #[cfg(not(feature = "ble"))]
    async fn try_parallel_authentication(
        &mut self,
        packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        use crate::transport::{Transport, UdpTransport};

        let config = self.state.config_manager.load_config()?;
        let transport = UdpTransport::from_socket(self.state.udp_socket.clone(), config.udp_port);
        let transport_arc = Arc::new(transport);
        let cfg = Arc::new(ClientConfigManager::new());
        Self::authenticate_with_transport(
            transport_arc,
            packet,
            &self.state.csk,
            &self.state.keypair,
            &self.challenge,
            cfg,
        )
        .await
    }

    /// Authenticate using any Transport
    async fn authenticate_with_transport<T: Transport + Send + Sync + 'static>(
        transport: Arc<T>,
        packet: &EncryptedPacket,
        csk: &ClientSymmetricKey,
        keypair: &Ed25519KeyPair,
        challenge: &[u8; 32],
        config_manager: Arc<ClientConfigManager>,
    ) -> Result<(), AuthHandlerError> {
        let timeout = get_session_timeout();
        let start = Instant::now();
        let mut attempt = 0u32;

        loop {
            if start.elapsed() >= timeout {
                // Ensure transport is finalized before returning timeout
                let _ = transport.finalize().await;
                return Err(AuthHandlerError::Timeout);
            }

            // Send request
            if let Err(e) = transport.send_request(packet).await {
                let _ = transport.finalize().await;
                return Err(e);
            }

            // Wait for response with retry interval
            let retry_interval = shared::network::get_client_retry_interval(attempt);

            loop {
                match transport.receive_response(retry_interval).await {
                    Err(e) => {
                        let _ = transport.finalize().await;
                        return Err(e);
                    }
                    Ok(ReceiveResult::Response(response_packet, server_addr)) => {
                        // Decrypt the packet
                        let wrapper =
                            decrypt_encrypted_packet_with_csk_nonce(csk, &response_packet)?;

                        tracing::debug!("Received message from {}", server_addr);

                        // Verify wrapper signature against any paired server key
                        let paired_servers = config_manager.load_paired_servers()?;
                        let mut signature_valid = false;
                        for (_id, server) in paired_servers.iter() {
                            if let Ok(pub_key_bytes) = hex::decode(&server.public_key) {
                                if pub_key_bytes.len() == 32 {
                                    let mut pub_key = [0u8; 32];
                                    pub_key.copy_from_slice(&pub_key_bytes);
                                    if verify_wrapper_signature(&wrapper, &pub_key).is_ok() {
                                        signature_valid = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if !signature_valid {
                            tracing::warn!(
                                "Message signature verification failed from {}; continuing to wait for valid response",
                                server_addr
                            );
                            continue;
                        }

                        // Now check message type and handle appropriately
                        match &wrapper.payload {
                            Some(shared::protocol::pb::wrapper_message::Payload::AuthGrant(
                                _grant,
                            )) => {
                                // For grants, also verify the signed_challenge
                                let mut grant_valid = false;
                                for (_id, server) in paired_servers.iter() {
                                    if let Ok(pub_key_bytes) = hex::decode(&server.public_key) {
                                        if pub_key_bytes.len() == 32 {
                                            let mut pub_key = [0u8; 32];
                                            pub_key.copy_from_slice(&pub_key_bytes);
                                            if verify_auth_grant(&wrapper, challenge, &pub_key)
                                                .is_ok()
                                            {
                                                grant_valid = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if grant_valid {
                                    tracing::info!(
                                        "Authentication granted by server: {}",
                                        server_addr
                                    );
                                    // Send confirmation in background and finalize without blocking PAM
                                    let confirmation = create_grant_confirmation(challenge)?;
                                    let mut conf_wrapper = wrap_grant_confirmation(confirmation);
                                    sign_wrapper_message(&mut conf_wrapper, keypair)?;
                                    let conf_packet =
                                        create_encrypted_packet_with_csk_nonce(csk, &conf_wrapper)?;

                                    let t = transport.clone();
                                    tokio::spawn(async move {
                                        // Best-effort: up to 3 sends within ~450ms total
                                        let _ = t.send_confirmation(&conf_packet).await;
                                        tokio::time::sleep(Duration::from_millis(150)).await;
                                        let _ = t.send_confirmation(&conf_packet).await;
                                        tokio::time::sleep(Duration::from_millis(150)).await;
                                        let _ = t.send_confirmation(&conf_packet).await;
                                        let _ = t.finalize().await;
                                    });
                                    return Ok(());
                                } else {
                                    tracing::warn!("Grant challenge verification failed; continuing to wait for valid response");
                                }
                            }
                            Some(shared::protocol::pb::wrapper_message::Payload::AuthDenial(
                                _denial,
                            )) => {
                                // Signature already verified above
                                tracing::warn!(
                                    "Authentication explicitly denied by server: {}",
                                    server_addr
                                );

                                // Send confirmation even for denial in background and finalize
                                let confirmation = create_grant_confirmation(challenge)?;
                                let mut conf_wrapper = wrap_grant_confirmation(confirmation);
                                sign_wrapper_message(&mut conf_wrapper, keypair)?;
                                let conf_packet =
                                    create_encrypted_packet_with_csk_nonce(csk, &conf_wrapper)?;

                                let t = transport.clone();
                                tokio::spawn(async move {
                                    let _ = t.send_confirmation(&conf_packet).await;
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    let _ = t.send_confirmation(&conf_packet).await;
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                    let _ = t.send_confirmation(&conf_packet).await;
                                    let _ = t.finalize().await;
                                });
                                return Err(AuthHandlerError::ExplicitDenial);
                            }
                            _ => {
                                tracing::debug!(
                                    "Unexpected message type, waiting for valid response"
                                );
                            }
                        }
                    }
                    Ok(ReceiveResult::Timeout) => {
                        attempt += 1;
                        break; // Retry send
                    }
                }
            }
        }
    }
}
