//! Authentication request handler that creates on-demand transports and runs auth flow.

use crate::transport::{ReceiveResult, Transport, UdpTransport};
use shared::{
    config::{ClientConfigManager, PairedServer},
    crypto::{ClientSymmetricKey, CryptoError, Ed25519KeyPair},
    network::get_session_timeout,
    protocol::{messages::*, packet::*, pb::EncryptedPacket, ProtocolError},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};

#[cfg(feature = "ble")]
use crate::transport::BleTransport;
#[cfg(feature = "ble")]
use shared::crypto::generate_current_temporal_identifier_ble;
#[cfg(feature = "ble")]
use tokio::select;

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

/// Type alias for transport task handles
#[cfg(feature = "ble")]
type TransportHandles = (
    tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
    tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
);

/// Parameters for awaiting authentication result
#[cfg(feature = "ble")]
struct AwaitAuthParams<'a> {
    ble_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
    udp_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
    cancel_rx: oneshot::Receiver<()>,
    ble_abort: tokio::task::AbortHandle,
    udp_abort: tokio::task::AbortHandle,
    ble_transport: &'a Option<Arc<crate::transport::BleTransport>>,
    udp_transport: &'a Arc<crate::transport::UdpTransport>,
    cancel_packet: &'a EncryptedPacket,
}

/// Shared state for daemon - loaded once at startup
pub struct DaemonState {
    pub config_manager: Arc<ClientConfigManager>,
    pub paired_servers: Arc<HashMap<String, PairedServer>>,
    pub keypair: Option<Ed25519KeyPair>, // None if TPM unsealing failed
    pub csk: Option<ClientSymmetricKey>,
    pub hostname: String,
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    pub init_error: Option<String>, // Stores TPM or other initialization errors
}

impl DaemonState {
    pub fn new(udp_socket: tokio::net::UdpSocket) -> Result<Self, AuthHandlerError> {
        let config_manager = Arc::new(ClientConfigManager::new());

        // Try to load keypair - if it fails due to TPM, enter degraded mode
        let (keypair, init_error) = match config_manager.load_keypair() {
            Ok(kp) => (Some(kp), None),
            Err(e) => {
                let error_msg = format!("Failed to load keypair: {}. Please open tapauth-config GUI to regenerate keys.", e);
                tracing::error!("{}", error_msg);
                (None, Some(error_msg))
            }
        };

        let (csk, init_error) = match config_manager.load_csk() {
            Ok(csk) => (Some(csk), init_error),
            Err(e) => {
                let error_msg = format!(
                    "Failed to load CSK: {}. Please open tapauth-config GUI to configure keys.",
                    e
                );
                tracing::error!("{}", error_msg);
                let combined = match init_error {
                    Some(prev) => Some(format!("{}; {}", prev, error_msg)),
                    None => Some(error_msg),
                };
                (None, combined)
            }
        };

        let paired_servers = Arc::new(config_manager.load_paired_servers()?);

        let config = config_manager.load_config()?;
        let hostname = config.hostname;

        Ok(Self {
            config_manager,
            paired_servers,
            keypair,
            csk,
            hostname,
            udp_socket: Arc::new(udp_socket),
            init_error,
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.keypair.is_some() && self.csk.is_some()
    }

    /// Get error message for degraded state
    pub fn get_init_error(&self) -> Option<&str> {
        self.init_error.as_deref()
    }

    /// Reload in-memory state from disk after admin configuration changes.
    /// Reuses the existing UDP socket (port changes require daemon restart).
    pub fn reload(&self) -> Arc<DaemonState> {
        let keypair = match self.config_manager.load_keypair() {
            Ok(kp) => Some(kp),
            Err(e) => {
                tracing::error!("Failed to reload keypair: {}", e);
                self.keypair.clone()
            }
        };

        let csk = self
            .config_manager
            .load_csk()
            .map(Some)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to reload CSK: {}, keeping existing value", e);
                self.csk.clone()
            });

        let paired_servers = self
            .config_manager
            .load_paired_servers()
            .map(Arc::new)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to reload paired servers: {}", e);
                self.paired_servers.clone()
            });

        let config = self.config_manager.load_config().unwrap_or_else(|e| {
            tracing::error!("Failed to reload config: {}", e);
            shared::config::ClientConfig {
                hostname: self.hostname.clone(),
            }
        });

        let init_error = if keypair.is_some() && csk.is_some() {
            None
        } else {
            let mut missing = Vec::new();
            if keypair.is_none() {
                missing.push("Keypair");
            }
            if csk.is_none() {
                missing.push("CSK");
            }
            Some(format!(
                "{} unavailable after reload. Use tapauth-config to regenerate keys.",
                missing.join(" and ")
            ))
        };

        Arc::new(DaemonState {
            config_manager: self.config_manager.clone(),
            paired_servers,
            keypair,
            csk,
            hostname: config.hostname,
            udp_socket: self.udp_socket.clone(),
            init_error,
        })
    }
}

type CancelRegistry = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

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
        getrandom::fill(&mut challenge)
            .map_err(|e| std::io::Error::other(format!("random generation failed: {}", e)))?;

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
        cancel_registry: CancelRegistry,
    ) -> Result<ipc::PamAuthenticateResponse, AuthHandlerError> {
        // Check if daemon is in degraded state (TPM key load failure)
        if !self.state.is_healthy() {
            let error_detail = self
                .state
                .get_init_error()
                .unwrap_or("Keypair unavailable. Please run tapauth-config to regenerate keys.");

            return Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Error as i32,
                detail: error_detail.to_string(),
                challenge: self.challenge.to_vec(),
            });
        }

        // Record cancel context for targeted cancellation
        self.request_id = request_id;
        self.cancel_registry = Some(cancel_registry);
        // Check if we have any paired devices
        let paired_servers = self.state.paired_servers.clone();
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
        // Safety: keypair is Some after health check
        let keypair = self
            .state
            .keypair
            .as_ref()
            .unwrap_or_else(|| unreachable!("keypair checked in health check"));
        sign_wrapper_message(&mut wrapper, keypair)?;
        let packet = create_encrypted_packet_with_csk_nonce(
            self.state
                .csk
                .as_ref()
                .unwrap_or_else(|| unreachable!("csk checked in health check")),
            &wrapper,
        )?;

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
                // Broadcast AuthenticationCancel so servers stop retransmitting
                if let Ok(cancel_packet) = self.create_cancel_packet() {
                    let udp_socket = self.state.udp_socket.clone();
                    let toml_config = shared::config::TapAuthConfig::load();
                    let port = toml_config.udp_port;
                    tokio::spawn(async move {
                        let transport = UdpTransport::from_socket(udp_socket, port);
                        let _ = transport.send_cancel(&cancel_packet).await;
                    });
                }
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
        let temporal_id = generate_current_temporal_identifier_ble(
            self.state
                .csk
                .as_ref()
                .unwrap_or_else(|| unreachable!("csk checked in health check")),
        )?;
        let timeout = get_session_timeout();

        tracing::info!("Starting parallel discovery over UDP and BLE");

        // Initialize transports
        let (udp_transport, ble_transport) =
            self.initialize_transports(temporal_id, timeout).await?;

        // Setup cancellation mechanism
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.register_cancel_handler(cancel_tx).await;

        // Pre-compute cancel packet
        let cancel_packet = self.create_cancel_packet()?;

        // Spawn authentication tasks
        let (ble_handle, udp_handle) =
            self.spawn_auth_tasks(&ble_transport, &udp_transport, packet);

        let ble_abort = ble_handle.abort_handle();
        let udp_abort = udp_handle.abort_handle();

        // Wait for first success, both failures, or cancellation
        self.await_auth_result(AwaitAuthParams {
            ble_handle,
            udp_handle,
            cancel_rx,
            ble_abort,
            udp_abort,
            ble_transport: &ble_transport,
            udp_transport: &udp_transport,
            cancel_packet: &cancel_packet,
        })
        .await
    }

    #[cfg(feature = "ble")]
    async fn initialize_transports(
        &self,
        temporal_id: [u8; 10],
        timeout: Duration,
    ) -> Result<
        (
            Arc<crate::transport::UdpTransport>,
            Option<Arc<crate::transport::BleTransport>>,
        ),
        AuthHandlerError,
    > {
        let toml_config = shared::config::TapAuthConfig::load();
        let udp_transport =
            UdpTransport::from_socket(self.state.udp_socket.clone(), toml_config.udp_port);

        // Safety: keypair is Some after health check in handle_authenticate
        let keypair = Arc::new(
            self.state
                .keypair
                .as_ref()
                .unwrap_or_else(|| unreachable!("keypair checked in health check"))
                .clone(),
        );
        let csk = self
            .state
            .csk
            .clone()
            .unwrap_or_else(|| unreachable!("csk checked in health check"));
        let challenge = self.challenge;

        let ble_transport =
            match BleTransport::new(temporal_id, timeout, csk, keypair, challenge).await {
                Ok(ble) => Some(Arc::new(ble)),
                Err(e) => {
                    tracing::warn!(
                        "BLE initialization failed ({}). Falling back to UDP-only.",
                        e
                    );
                    None
                }
            };

        Ok((Arc::new(udp_transport), ble_transport))
    }

    #[cfg(feature = "ble")]
    async fn register_cancel_handler(&mut self, cancel_tx: oneshot::Sender<()>) {
        if let (Some(reg), Some(id)) = (self.cancel_registry.as_ref(), self.request_id.as_ref()) {
            reg.lock().await.insert(id.clone(), cancel_tx);
        }
    }

    fn create_cancel_packet(&self) -> Result<EncryptedPacket, AuthHandlerError> {
        let msg = create_auth_cancel(&self.challenge)?;
        let mut wrapper = wrap_auth_cancel(msg);
        // Safety: keypair is Some after health check in handle_authenticate
        let keypair = self
            .state
            .keypair
            .as_ref()
            .unwrap_or_else(|| unreachable!("keypair checked in health check"));
        sign_wrapper_message(&mut wrapper, keypair)?;
        Ok(create_encrypted_packet_with_csk_nonce(
            self.state
                .csk
                .as_ref()
                .unwrap_or_else(|| unreachable!("csk checked in health check")),
            &wrapper,
        )?)
    }

    #[cfg(feature = "ble")]
    fn spawn_auth_tasks(
        &self,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        packet: &EncryptedPacket,
    ) -> TransportHandles {
        let ble_handle = if let Some(ble) = ble_transport.clone() {
            let packet = packet.clone();
            let csk = self
                .state
                .csk
                .clone()
                .unwrap_or_else(|| unreachable!("csk checked in health check"));
            // Safety: keypair is Some after health check in handle_authenticate
            let keypair = self
                .state
                .keypair
                .as_ref()
                .unwrap_or_else(|| unreachable!("keypair checked in health check"))
                .clone();
            let challenge = self.challenge;
            let servers = self.state.paired_servers.clone();
            tokio::spawn(async move {
                Self::authenticate_with_transport(ble, &packet, &csk, &keypair, &challenge, servers)
                    .await
            })
        } else {
            tokio::spawn(async { Err(AuthHandlerError::BleError("BLE disabled".into())) })
        };

        let udp_handle = {
            let packet = packet.clone();
            let csk = self
                .state
                .csk
                .clone()
                .unwrap_or_else(|| unreachable!("csk checked in health check"));
            // Safety: keypair is Some after health check in handle_authenticate
            let keypair = self
                .state
                .keypair
                .as_ref()
                .unwrap_or_else(|| unreachable!("keypair checked in health check"))
                .clone();
            let challenge = self.challenge;
            let servers = self.state.paired_servers.clone();
            let udp = udp_transport.clone();
            tokio::spawn(async move {
                Self::authenticate_with_transport(udp, &packet, &csk, &keypair, &challenge, servers)
                    .await
            })
        };

        (ble_handle, udp_handle)
    }

    #[cfg(feature = "ble")]
    async fn await_auth_result(&self, params: AwaitAuthParams<'_>) -> Result<(), AuthHandlerError> {
        let AwaitAuthParams {
            mut ble_handle,
            mut udp_handle,
            mut cancel_rx,
            ble_abort,
            udp_abort,
            ble_transport,
            udp_transport,
            cancel_packet,
        } = params;

        select! {
            result = &mut ble_handle => {
                self.handle_ble_result(result, udp_handle, udp_abort, ble_transport, udp_transport, cancel_packet).await
            }
            result = &mut udp_handle => {
                self.handle_udp_result(result, ble_handle, ble_abort, ble_transport, udp_transport, cancel_packet).await
            }
            _ = &mut cancel_rx => {
                self.handle_cancellation(ble_abort, udp_abort, ble_transport, udp_transport, cancel_packet).await
            }
        }
    }

    #[cfg(feature = "ble")]
    async fn handle_ble_result(
        &self,
        result: Result<Result<(), AuthHandlerError>, tokio::task::JoinError>,
        udp_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
        udp_abort: tokio::task::AbortHandle,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        match result {
            Ok(Ok(())) => {
                tracing::info!("BLE authentication succeeded");
                self.broadcast_cancel_on_success(ble_transport, udp_transport, cancel_packet)
                    .await;
                udp_abort.abort();
                Ok(())
            }
            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                tracing::warn!("BLE authentication explicitly denied by user");
                udp_abort.abort();
                self.cleanup_transports(ble_transport, udp_transport, cancel_packet)
                    .await;
                Err(AuthHandlerError::ExplicitDenial)
            }
            Ok(Err(e)) => {
                tracing::debug!("BLE authentication failed: {}", e);
                self.handle_udp_fallback(udp_handle, ble_transport, udp_transport, cancel_packet)
                    .await
            }
            Err(_) => {
                tracing::error!("BLE task panicked");
                match udp_handle.await {
                    Ok(Ok(())) => Ok(()),
                    _ => Err(AuthHandlerError::Denied),
                }
            }
        }
    }

    #[cfg(feature = "ble")]
    async fn handle_udp_result(
        &self,
        result: Result<Result<(), AuthHandlerError>, tokio::task::JoinError>,
        ble_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
        ble_abort: tokio::task::AbortHandle,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        match result {
            Ok(Ok(())) => {
                tracing::info!("UDP authentication succeeded");
                ble_abort.abort();
                self.broadcast_cancel_on_success(ble_transport, udp_transport, cancel_packet)
                    .await;
                Ok(())
            }
            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                tracing::warn!("UDP authentication explicitly denied by user");
                ble_abort.abort();
                self.cleanup_transports(ble_transport, udp_transport, cancel_packet)
                    .await;
                Err(AuthHandlerError::ExplicitDenial)
            }
            Ok(Err(e)) => {
                tracing::debug!("UDP authentication failed: {}", e);
                self.handle_ble_fallback(ble_handle, ble_transport, udp_transport, cancel_packet)
                    .await
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

    #[cfg(feature = "ble")]
    async fn handle_udp_fallback(
        &self,
        udp_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        match udp_handle.await {
            Ok(Ok(())) => {
                tracing::info!("UDP authentication succeeded");
                self.broadcast_cancel_on_success(ble_transport, udp_transport, cancel_packet)
                    .await;
                Ok(())
            }
            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                self.cleanup_transports(ble_transport, udp_transport, cancel_packet)
                    .await;
                Err(AuthHandlerError::ExplicitDenial)
            }
            Ok(Err(e)) => {
                tracing::error!("UDP authentication also failed: {}", e);
                Err(AuthHandlerError::Denied)
            }
            Err(_) => Err(AuthHandlerError::Denied),
        }
    }

    #[cfg(feature = "ble")]
    async fn handle_ble_fallback(
        &self,
        ble_handle: tokio::task::JoinHandle<Result<(), AuthHandlerError>>,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        match ble_handle.await {
            Ok(Ok(())) => {
                tracing::info!("BLE authentication succeeded");
                self.broadcast_cancel_on_success(ble_transport, udp_transport, cancel_packet)
                    .await;
                Ok(())
            }
            Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                self.cleanup_transports(ble_transport, udp_transport, cancel_packet)
                    .await;
                Err(AuthHandlerError::ExplicitDenial)
            }
            Ok(Err(e)) => {
                tracing::error!("BLE authentication also failed: {}", e);
                Err(AuthHandlerError::Denied)
            }
            Err(_) => Err(AuthHandlerError::Denied),
        }
    }

    #[cfg(feature = "ble")]
    async fn broadcast_cancel_on_success(
        &self,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) {
        if let Some(ble) = ble_transport {
            let ble = ble.clone();
            let cancel = cancel_packet.clone();
            tokio::spawn(async move {
                let _ = ble.send_cancel(&cancel).await;
                let _ = ble.finalize().await;
            });
        }
        let _ = udp_transport.send_cancel(cancel_packet).await;
    }

    #[cfg(feature = "ble")]
    async fn cleanup_transports(
        &self,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) {
        if let Some(ble) = ble_transport {
            let ble = ble.clone();
            tokio::spawn(async move {
                let _ = ble.finalize().await;
            });
        }
        let _ = udp_transport.send_cancel(cancel_packet).await;
    }

    #[cfg(feature = "ble")]
    async fn handle_cancellation(
        &self,
        ble_abort: tokio::task::AbortHandle,
        udp_abort: tokio::task::AbortHandle,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        let rid = self.request_id.as_deref().unwrap_or("-");
        tracing::info!(
            "Authentication cancelled (user={}, id={})",
            self.username,
            rid
        );

        tracing::info!("Broadcasting AuthenticationCancel over UDP");
        if let Err(e) = udp_transport.send_cancel(cancel_packet).await {
            tracing::warn!("UDP cancel broadcast failed: {}", e);
        } else {
            tracing::debug!("UDP cancel broadcast sent");
        }

        // Disconnect BLE clients (non-blocking)
        if let Some(ble) = ble_transport {
            tracing::debug!("Disconnecting BLE clients (background)");
            let ble = ble.clone();
            tokio::spawn(async move {
                let _ = ble.finalize().await;
            });
        }

        // Give network stack time to transmit packets
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Abort the tasks
        ble_abort.abort();
        udp_abort.abort();

        Err(AuthHandlerError::Denied)
    }

    #[cfg(not(feature = "ble"))]
    async fn try_parallel_authentication(
        &mut self,
        packet: &EncryptedPacket,
    ) -> Result<(), AuthHandlerError> {
        let toml_config = shared::config::TapAuthConfig::load();
        let transport =
            UdpTransport::from_socket(self.state.udp_socket.clone(), toml_config.udp_port);
        let transport_arc = Arc::new(transport);
        let servers = self.state.paired_servers.clone();
        // Safety: keypair is Some after health check in handle_authenticate
        let keypair = self
            .state
            .keypair
            .as_ref()
            .unwrap_or_else(|| unreachable!("keypair checked in health check"));
        let csk = self
            .state
            .csk
            .as_ref()
            .unwrap_or_else(|| unreachable!("csk checked in health check"));
        Self::authenticate_with_transport(
            transport_arc,
            packet,
            csk,
            keypair,
            &self.challenge,
            servers,
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
        paired_servers: Arc<HashMap<String, PairedServer>>,
    ) -> Result<(), AuthHandlerError> {
        let timeout = get_session_timeout();
        let start = Instant::now();
        let mut attempt = 0u32;
        let mut nonce_cache: HashSet<Vec<u8>> = HashSet::new();

        loop {
            if start.elapsed() >= timeout {
                let _ = transport.finalize().await;
                return Err(AuthHandlerError::Timeout);
            }

            // Send authentication request
            if let Err(e) = transport.send_request(packet).await {
                let _ = transport.finalize().await;
                return Err(e);
            }

            // Wait for response
            let retry_interval = shared::network::get_client_retry_interval(attempt);
            match Self::wait_for_response(
                &transport,
                retry_interval,
                csk,
                &paired_servers,
                &mut nonce_cache,
            )
            .await
            {
                Ok(Some((wrapper, server_addr))) => {
                    // Process the authenticated response
                    match Self::process_auth_response(
                        &wrapper,
                        &transport,
                        challenge,
                        keypair,
                        csk,
                        &paired_servers,
                        server_addr,
                    )
                    .await
                    {
                        Ok(result) => return result,
                        Err(ResponseError::InvalidMessage) => {
                            // Continue waiting for valid response
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    // Timeout - retry
                    attempt += 1;
                }
                Err(e) => {
                    let _ = transport.finalize().await;
                    return Err(e);
                }
            }
        }
    }

    async fn wait_for_response<T: Transport + Send + Sync>(
        transport: &Arc<T>,
        retry_interval: Duration,
        csk: &ClientSymmetricKey,
        paired_servers: &HashMap<String, PairedServer>,
        nonce_cache: &mut HashSet<Vec<u8>>,
    ) -> Result<Option<(shared::protocol::pb::WrapperMessage, String)>, AuthHandlerError> {
        match transport.receive_response(retry_interval).await {
            Err(e) => Err(e),
            Ok(ReceiveResult::Timeout) => Ok(None),
            Ok(ReceiveResult::Response(response_packet, server_addr)) => {
                let nonce_fingerprint = {
                    let mut data = response_packet.temporal_identifier.clone();
                    data.extend_from_slice(&response_packet.ciphertext);
                    data
                };
                if !nonce_cache.insert(nonce_fingerprint) {
                    tracing::warn!("Replayed packet detected from {}, ignoring", server_addr);
                    return Ok(None);
                }

                let wrapper = decrypt_encrypted_packet_with_csk_nonce(csk, &response_packet)?;
                let addr_str = server_addr.to_string();
                tracing::debug!("Received message from {}", addr_str);

                // Verify signature
                if Self::verify_response_signature(&wrapper, paired_servers)? {
                    Ok(Some((wrapper, addr_str)))
                } else {
                    tracing::warn!(
                        "Message signature verification failed from {}; continuing to wait for valid response",
                        addr_str
                    );
                    Ok(None)
                }
            }
        }
    }

    fn verify_response_signature(
        wrapper: &shared::protocol::pb::WrapperMessage,
        paired_servers: &HashMap<String, PairedServer>,
    ) -> Result<bool, AuthHandlerError> {
        for (_id, server) in paired_servers.iter() {
            if let Ok(pub_key_bytes) = hex::decode(&server.public_key) {
                if pub_key_bytes.len() == 32 {
                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);
                    if verify_wrapper_signature(wrapper, &pub_key).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    async fn process_auth_response<T: Transport + Send + Sync + 'static>(
        wrapper: &shared::protocol::pb::WrapperMessage,
        transport: &Arc<T>,
        challenge: &[u8; 32],
        keypair: &Ed25519KeyPair,
        csk: &ClientSymmetricKey,
        paired_servers: &HashMap<String, PairedServer>,
        server_addr: String,
    ) -> Result<Result<(), AuthHandlerError>, ResponseError> {
        match &wrapper.payload {
            Some(shared::protocol::pb::wrapper_message::Payload::AuthGrant(_)) => {
                Self::handle_auth_grant(
                    wrapper,
                    transport,
                    challenge,
                    keypair,
                    csk,
                    paired_servers,
                    server_addr,
                )
                .await
            }
            Some(shared::protocol::pb::wrapper_message::Payload::AuthDenial(_)) => {
                Self::handle_auth_denial(wrapper, transport, challenge, keypair, csk, server_addr)
                    .await
            }
            _ => {
                tracing::debug!("Unexpected message type, waiting for valid response");
                Err(ResponseError::InvalidMessage)
            }
        }
    }

    async fn handle_auth_grant<T: Transport + Send + Sync + 'static>(
        wrapper: &shared::protocol::pb::WrapperMessage,
        transport: &Arc<T>,
        challenge: &[u8; 32],
        keypair: &Ed25519KeyPair,
        csk: &ClientSymmetricKey,
        paired_servers: &HashMap<String, PairedServer>,
        server_addr: String,
    ) -> Result<Result<(), AuthHandlerError>, ResponseError> {
        // Verify signed_challenge
        let grant_valid = paired_servers.iter().any(|(_id, server)| {
            if let Ok(pub_key_bytes) = hex::decode(&server.public_key) {
                if pub_key_bytes.len() == 32 {
                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);
                    return verify_auth_grant(wrapper, challenge, &pub_key).is_ok();
                }
            }
            false
        });

        if grant_valid {
            tracing::info!("Authentication granted by server: {}", server_addr);
            Self::send_confirmation_background(transport.clone(), challenge, keypair, csk);
            Ok(Ok(()))
        } else {
            tracing::warn!(
                "Grant challenge verification failed; continuing to wait for valid response"
            );
            Err(ResponseError::InvalidMessage)
        }
    }

    async fn handle_auth_denial<T: Transport + Send + Sync + 'static>(
        wrapper: &shared::protocol::pb::WrapperMessage,
        transport: &Arc<T>,
        challenge: &[u8; 32],
        keypair: &Ed25519KeyPair,
        csk: &ClientSymmetricKey,
        server_addr: String,
    ) -> Result<Result<(), AuthHandlerError>, ResponseError> {
        let denial = match &wrapper.payload {
            Some(shared::protocol::pb::wrapper_message::Payload::AuthDenial(d)) => d,
            _ => return Err(ResponseError::InvalidMessage),
        };
        if denial.challenge.as_slice() != challenge.as_slice() {
            tracing::warn!(
                "AuthDenial challenge mismatch from {}, ignoring",
                server_addr
            );
            return Err(ResponseError::InvalidMessage);
        }
        tracing::info!(
            "Authentication explicitly denied by server: {}",
            server_addr
        );
        Self::send_confirmation_background(transport.clone(), challenge, keypair, csk);
        Ok(Err(AuthHandlerError::ExplicitDenial))
    }

    fn send_confirmation_background<T: Transport + Send + Sync + 'static>(
        transport: Arc<T>,
        challenge: &[u8; 32],
        keypair: &Ed25519KeyPair,
        csk: &ClientSymmetricKey,
    ) {
        let confirmation = match create_grant_confirmation(challenge) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create confirmation: {}", e);
                return;
            }
        };

        let mut conf_wrapper = wrap_grant_confirmation(confirmation);
        if let Err(e) = sign_wrapper_message(&mut conf_wrapper, keypair) {
            tracing::error!("Failed to sign confirmation: {}", e);
            return;
        }

        let conf_packet = match create_encrypted_packet_with_csk_nonce(csk, &conf_wrapper) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to encrypt confirmation: {}", e);
                return;
            }
        };

        tokio::spawn(async move {
            // Best-effort: up to 3 sends within ~450ms total
            let _ = transport.send_confirmation(&conf_packet).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = transport.send_confirmation(&conf_packet).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = transport.send_confirmation(&conf_packet).await;
            let _ = transport.finalize().await;
        });
    }
}

/// Error type for response processing
enum ResponseError {
    /// Invalid message that should be ignored (wait for another response)
    InvalidMessage,
}
