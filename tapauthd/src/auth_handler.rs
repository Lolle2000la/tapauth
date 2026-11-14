//! Authentication request handler that creates on-demand transports and runs auth flow.

use crate::caller_context::CallerContext;
use crate::transport::{ReceiveResult, Transport, UdpTransport, NOTIFY_SETTLE};
use shared::{
    config::{ClientConfigManager, CskMetadata, PairedServer},
    crypto::{ClientSymmetricKey, CryptoError, Ed25519KeyPair},
    firewall::{FirewallGuard, Protocol as FwProtocol},
    network::get_session_timeout,
    protocol::{
        messages::*,
        packet::*,
        pb::{EncryptedPacket, PayloadType, WrapperMessage},
        ProtocolError,
    },
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex};

#[cfg(feature = "ble")]
use crate::transport::BleTransport;
#[cfg(feature = "ble")]
use crate::transport::ServerVerifier;
#[cfg(feature = "ble")]
use shared::crypto::generate_current_ble_temporal_identifier_with_alg;

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
    #[error("Transport disabled by configuration")]
    TransportDisabled,
    #[error("BLE error: {0}")]
    BleError(String),
}

/// Which transports may be used for an authentication attempt.
///
/// Read from the TOML configuration at the start of each attempt so that
/// toggling BLE / Local Network connectivity takes effect without a daemon
/// restart.
#[derive(Debug, Clone, Copy)]
struct TransportsEnabled {
    /// Local Network (UDP multicast) transport
    network: bool,
    /// Bluetooth Low Energy transport (always false when the daemon is
    /// built without the `ble` feature)
    ble: bool,
}

impl TransportsEnabled {
    fn from_config() -> Self {
        let config = shared::config::TapAuthConfig::load();
        Self {
            network: config.enable_network,
            ble: cfg!(feature = "ble") && config.enable_ble,
        }
    }

    /// Whether at least one transport can be used.
    fn any(self) -> bool {
        self.network || self.ble
    }
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

/// How long the `GrantConfirmation` task may hold the concluding transport
/// before it releases it anyway.
///
/// The three sends, the two 150 ms pauses between them and the [`NOTIFY_SETTLE`]
/// pause after the last one take ~500 ms; the rest is slack for a slow
/// controller. It is a bound, not a schedule: the task owns the transport's
/// lifetime, so a hung `notify` must not leave the GATT application and the
/// advertisement registered.
const CONFIRMATION_LIFETIME: Duration = Duration::from_secs(2);

/// Which transport delivered the answer that concluded the session.
#[cfg(feature = "ble")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinningTransport {
    Ble,
    Udp,
}

/// What the *losing* transports still have to do once a session has concluded.
///
/// Pure data so the policy can be tested without a transport. The invariant
/// every consumer relies on: the transport that concluded the session is never
/// cancelled or released from here — its acknowledgement is still in flight, and
/// [`AuthSession::send_confirmation_background`] owns its teardown.
#[cfg(feature = "ble")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Teardown {
    /// Multicast `AuthenticationCancel` over UDP.
    cancel_udp: bool,
    /// `send_cancel` on the BLE link before releasing it.
    cancel_ble: bool,
    /// Release the BLE link: disconnect the phone, drop the GATT application and
    /// the advertisement.
    finalize_ble: bool,
}

/// Teardown for a session that ended in a **grant**.
///
/// The winner is left alone: a UDP winner already answered over UDP, so it gets
/// no second `AuthenticationCancel`, and a BLE winner keeps its whole lifetime —
/// last notification included — in the confirmation task.
#[cfg(feature = "ble")]
fn success_teardown(winner: WinningTransport) -> Teardown {
    Teardown {
        cancel_udp: winner != WinningTransport::Udp,
        cancel_ble: winner != WinningTransport::Ble,
        finalize_ble: winner != WinningTransport::Ble,
    }
}

/// Teardown for a session that ended without a grant.
///
/// The winning transport is left alone for the same reason as in
/// [`success_teardown`] — a denial is acknowledged on the same link, and that
/// acknowledgement is still in flight. The difference is UDP: no grant was
/// delivered, so the cancel goes out whatever concluded the session, and the
/// losing BLE link is only released (it has nothing to be told).
#[cfg(feature = "ble")]
fn denial_teardown(winner: WinningTransport) -> Teardown {
    Teardown {
        cancel_udp: true,
        cancel_ble: false,
        finalize_ble: winner != WinningTransport::Ble,
    }
}

/// Immutable inputs shared by every transport task of one authentication attempt.
///
/// Grouping them keeps the per-attempt values (CSK, negotiated algorithms,
/// challenge, and the servers authorized for *this* user) in one place, so no
/// call site can accidentally fall back to the full paired-server set.
struct AuthRunParams {
    keypair: Ed25519KeyPair,
    csk: ClientSymmetricKey,
    /// The CSK's negotiated algorithm pair, read once per attempt.
    csk_meta: CskMetadata,
    challenge: [u8; 32],
    /// The account this session authenticates.
    username: String,
    /// Paired servers permitted to answer for `username`, and only those.
    allowed_servers: Arc<Vec<PairedServer>>,
}

/// What one wait for a Server response produced.
///
/// The distinction between an unheard request and a heard-but-unusable frame
/// matters for retransmission: only [`WaitOutcome::Timeout`] means the request
/// itself went unanswered, so only it may widen the interval. Any paired device
/// can put a decryptable frame on the link, and treating that as a timeout would
/// let it thin the requests aimed at the phone that is allowed to answer.
enum WaitOutcome {
    /// A response whose signature belongs to a Server authorized for this user.
    Response(WrapperMessage, String),
    /// Nothing arrived within the retry interval.
    Timeout,
    /// A decryptable frame arrived, but no Server authorized for this user signed
    /// it. The interval stays where it is, and the request that frame interrupted
    /// still gets its whole interval before the next one goes out: the frame
    /// answered nothing, so it earns neither a wider interval nor an early
    /// re-request.
    Unattributable,
}

impl WaitOutcome {
    /// Whether the request itself went unanswered, i.e. whether the next attempt
    /// should wait longer than this one did.
    fn retransmission_unanswered(&self) -> bool {
        matches!(self, Self::Timeout)
    }
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
    /// Caller-derived display context (PAM service, process, command), resolved
    /// from `SO_PEERCRED` and /proc when the request arrived.
    caller: CallerContext,
    /// Whether the PAM conversation had a terminal.
    tty_present: bool,
    /// The CSK's negotiated algorithm pair, read once for the whole attempt so
    /// every packet builder and transport call agrees on it.
    csk_meta: CskMetadata,
    /// Paired servers allowed to authenticate `username`. Every response check
    /// is made against this set, never against `state.paired_servers`.
    allowed_servers: Arc<Vec<PairedServer>>,
    /// Transports enabled for this attempt (read from config when the
    /// attempt starts)
    transports: TransportsEnabled,
    cancel_registry: Option<CancelRegistry>,
    request_id: Option<String>,
}

impl AuthSession {
    pub fn new(
        state: Arc<DaemonState>,
        username: String,
        caller: CallerContext,
        tty_present: bool,
    ) -> Result<Self, std::io::Error> {
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge)
            .map_err(|e| std::io::Error::other(format!("random generation failed: {}", e)))?;

        // One read per attempt: the negotiated algorithms are client-wide, and a
        // failure here must fail the attempt rather than silently downgrade.
        let csk_meta = state
            .config_manager
            .load_csk_metadata()
            .map_err(|e| std::io::Error::other(format!("CSK metadata unreadable: {}", e)))?;

        Ok(Self {
            state,
            username,
            challenge,
            caller,
            tty_present,
            csk_meta,
            allowed_servers: Arc::new(Vec::new()),
            transports: TransportsEnabled {
                network: true,
                ble: cfg!(feature = "ble"),
            },
            cancel_registry: None,
            request_id: None,
        })
    }

    /// Resolve which paired Servers may answer for this session's user, and make
    /// that the set the whole attempt verifies against.
    ///
    /// This is the only place `allowed_users` is applied to an attempt, so it is
    /// also the only place a test has to drive to prove the filter reaches the
    /// transports: the value it returns *and* the value it stores are the same
    /// filtered set, and [`Self::run_params`] hands out the stored one.
    ///
    /// SECURITY: a phone paired for another account must be unable to grant *or*
    /// deny a session for this user, so nothing below may fall back to
    /// `DaemonState::paired_servers`.
    fn authorize(
        &mut self,
        paired_servers: &HashMap<String, PairedServer>,
    ) -> Arc<Vec<PairedServer>> {
        let allowed_servers = Arc::new(servers_authorized_for(paired_servers, &self.username));
        self.allowed_servers = allowed_servers.clone();
        allowed_servers
    }

    /// Handle PamAuthenticateRequest - creates transports on-demand, runs auth flow
    pub async fn handle_authenticate(
        mut self,
        timeout_seconds: Option<u32>,
        request_id: Option<String>,
        cancel_registry: CancelRegistry,
    ) -> Result<ipc::PamAuthenticateResponse, AuthHandlerError> {
        // Record cancel context for targeted cancellation
        self.request_id = request_id;
        self.cancel_registry = Some(cancel_registry);

        // Read transport toggles fresh from the TOML config so that changes
        // made via the GUI/admin IPC take effect without a daemon restart.
        self.transports = TransportsEnabled::from_config();
        if !self.transports.any() {
            tracing::info!("All transports (BLE and Local Network) are disabled by configuration");
            return Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Ignore as i32,
                detail: "All transports (BLE and Local Network) are disabled".to_string(),
                challenge: self.challenge.to_vec(),
            });
        }

        // Check if we have any paired devices first — if not, return Ignore
        // silently so PAM falls through to other methods without noisy errors.
        let paired_servers = self.state.paired_servers.clone();
        if paired_servers.is_empty() {
            return Ok(ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Ignore as i32,
                detail: "No paired devices configured".to_string(),
                challenge: self.challenge.to_vec(),
            });
        }

        // Only check if daemon is unhealthy when paired devices exist.
        // On a fresh install with no keys, paired_servers is also empty,
        // so we never reach this point to pollute logs with Error outcomes.
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

        // Filter servers that are allowed to authenticate this user.
        //
        // SECURITY: this filtered set — not `state.paired_servers` — must reach
        // every response check below. A phone paired for another account must be
        // unable to grant *or* deny a session for `self.username`.
        let allowed_servers = self.authorize(&paired_servers);

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

        // Open firewall port for the duration of this authentication attempt.
        // The guard auto-closes the port when dropped (i.e. when auth finishes,
        // times out, or is cancelled), keeping the port closed when idle.
        // Only needed when the Local Network (UDP) transport is in use.
        let port = match self.state.udp_socket.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                tracing::error!("Failed to get local address of UDP socket: {}", e);
                shared::config::TapAuthConfig::load().udp_port
            }
        };
        let _fw_guard = if self.transports.network {
            match tokio::task::spawn_blocking(move || FirewallGuard::new(port, FwProtocol::Udp))
                .await
            {
                Ok(Ok(g)) => Some(g),
                Ok(Err(e)) => {
                    tracing::warn!(
                        "Failed to open firewall port for auth (continuing anyway): {}",
                        e
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to join firewall port opening task (continuing anyway): {}",
                        e
                    );
                    None
                }
            }
        } else {
            tracing::debug!("Local Network transport disabled - not opening firewall port");
            None
        };

        // Create the authentication request, carrying the resolved caller
        // context so the phone can show what is being approved.
        let request = create_auth_request_with_context(
            &self.username,
            &self.state.hostname,
            &self.challenge,
            &self.caller.pam_service,
            &self.caller.process_name,
            &self.caller.command_preview,
            self.tty_present,
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
            self.csk_meta.symmetric_algorithm,
            self.csk_meta.hash_algorithm,
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
                    outcome: ipc::PamOutcome::Ignore as i32,
                    detail: format!("Authentication failed: {}", e),
                    challenge: self.challenge.to_vec(),
                })
            }
            Err(_) => {
                tracing::warn!("Authentication timeout for user {}", self.username);
                // Multicast AuthenticationCancel so servers stop retransmitting
                if let Ok(cancel_packet) = self.create_cancel_packet() {
                    if self.transports.network {
                        let udp_socket = self.state.udp_socket.clone();
                        let toml_config = shared::config::TapAuthConfig::load();
                        let port = toml_config.udp_port;
                        tokio::spawn(async move {
                            let transport = UdpTransport::from_socket(udp_socket, port);
                            let _ = transport.send_cancel(&cancel_packet).await;
                        });
                    }
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
        let temporal_id = generate_current_ble_temporal_identifier_with_alg(
            self.state
                .csk
                .as_ref()
                .unwrap_or_else(|| unreachable!("csk checked in health check")),
            self.csk_meta.hash_algorithm,
        )?;

        tracing::info!("Starting parallel discovery over UDP and BLE");

        // Initialize transports
        let (udp_transport, ble_transport) = self.initialize_transports(temporal_id).await?;

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

        // Safety: csk is Some after the health check in handle_authenticate
        let csk = self
            .state
            .csk
            .clone()
            .unwrap_or_else(|| unreachable!("csk checked in health check"));

        // Skip BLE entirely when disabled by configuration
        let ble_transport = if !self.transports.ble {
            tracing::debug!("BLE transport disabled by configuration");
            None
        } else {
            // The BLE transport verifies every response it hands back, so it gets
            // the same filtered server set as the UDP path — never every pairing.
            let verifiers = ServerVerifier::from_paired_servers(&self.allowed_servers_by_key());
            match BleTransport::new(temporal_id, csk, verifiers).await {
                Ok(ble) => Some(Arc::new(ble)),
                Err(e) => {
                    tracing::warn!(
                        "BLE initialization failed ({}). Falling back to UDP-only.",
                        e
                    );
                    None
                }
            }
        };

        Ok((Arc::new(udp_transport), ble_transport))
    }

    /// The authorized servers keyed by public key, the shape
    /// [`ServerVerifier::from_paired_servers`] consumes (the key itself is
    /// unused: one verifier is built per value).
    #[cfg(feature = "ble")]
    fn allowed_servers_by_key(&self) -> HashMap<String, PairedServer> {
        self.allowed_servers
            .iter()
            .map(|server| (server.public_key.clone(), server.clone()))
            .collect()
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
            self.csk_meta.symmetric_algorithm,
            self.csk_meta.hash_algorithm,
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
        let run = Arc::new(self.run_params());

        let ble_handle = if let Some(ble) = ble_transport.clone() {
            let packet = packet.clone();
            let run = run.clone();
            tokio::spawn(async move { Self::authenticate_with_transport(ble, &packet, run).await })
        } else {
            tokio::spawn(async { Err(AuthHandlerError::TransportDisabled) })
        };

        let udp_handle = if self.transports.network {
            let packet = packet.clone();
            let udp = udp_transport.clone();
            tokio::spawn(async move { Self::authenticate_with_transport(udp, &packet, run).await })
        } else {
            tokio::spawn(async { Err(AuthHandlerError::TransportDisabled) })
        };

        (ble_handle, udp_handle)
    }

    /// Snapshot the per-attempt inputs both transport tasks need.
    ///
    /// `allowed_servers` is the filtered set: the tasks never see
    /// `state.paired_servers`.
    fn run_params(&self) -> AuthRunParams {
        AuthRunParams {
            // Safety: keypair/csk are Some after the health check in handle_authenticate
            keypair: self
                .state
                .keypair
                .as_ref()
                .unwrap_or_else(|| unreachable!("keypair checked in health check"))
                .clone(),
            csk: self
                .state
                .csk
                .clone()
                .unwrap_or_else(|| unreachable!("csk checked in health check")),
            csk_meta: self.csk_meta,
            challenge: self.challenge,
            username: self.username.clone(),
            allowed_servers: self.allowed_servers.clone(),
        }
    }

    /// Wait for the first transport to finish, for both transports to fail,
    /// or for a PAM cancel.
    ///
    /// The cancel branch must stay armed across transport fallbacks: when BLE
    /// is disabled (or its task fails immediately, e.g. transport disabled by
    /// configuration) the remaining transport is awaited HERE, and a nested
    /// plain `.await` would silently drop `PamCancelRequest` until the session
    /// timed out.
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

        // Non-terminal transport failures (disabled by configuration, timeouts,
        // panics) hand control to the remaining transport; the loop keeps the
        // cancel branch live throughout.
        let mut ble_failed = false;
        let mut udp_failed = false;

        loop {
            if ble_failed && udp_failed {
                // Both transports failed with non-terminal errors and no
                // cancel arrived: the session cannot succeed.
                return Err(AuthHandlerError::Denied);
            }
            tokio::select! {
                result = &mut ble_handle, if !ble_failed => {
                    match result {
                        Ok(Ok(())) => {
                            tracing::info!("BLE authentication succeeded");
                            udp_abort.abort();
                            self.multicast_cancel_on_success(
                                WinningTransport::Ble,
                                ble_transport,
                                udp_transport,
                                cancel_packet,
                            )
                            .await;
                            return Ok(());
                        }
                        Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                            tracing::warn!("BLE authentication explicitly denied by user");
                            udp_abort.abort();
                            self.cleanup_transports(
                                WinningTransport::Ble,
                                ble_transport,
                                udp_transport,
                                cancel_packet,
                            )
                            .await;
                            return Err(AuthHandlerError::ExplicitDenial);
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("BLE authentication failed: {}", e);
                            ble_failed = true;
                        }
                        Err(_) => {
                            tracing::error!("BLE task panicked");
                            ble_failed = true;
                        }
                    }
                }
                result = &mut udp_handle, if !udp_failed => {
                    match result {
                        Ok(Ok(())) => {
                            tracing::info!("UDP authentication succeeded");
                            ble_abort.abort();
                            self.multicast_cancel_on_success(
                                WinningTransport::Udp,
                                ble_transport,
                                udp_transport,
                                cancel_packet,
                            )
                            .await;
                            return Ok(());
                        }
                        Ok(Err(AuthHandlerError::ExplicitDenial)) => {
                            tracing::warn!("UDP authentication explicitly denied by user");
                            ble_abort.abort();
                            self.cleanup_transports(
                                WinningTransport::Udp,
                                ble_transport,
                                udp_transport,
                                cancel_packet,
                            )
                            .await;
                            return Err(AuthHandlerError::ExplicitDenial);
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("UDP authentication failed: {}", e);
                            udp_failed = true;
                        }
                        Err(_) => {
                            tracing::error!("UDP task panicked");
                            udp_failed = true;
                        }
                    }
                }
                _ = &mut cancel_rx => {
                    return self
                        .handle_cancellation(ble_abort, udp_abort, ble_transport, udp_transport, cancel_packet)
                        .await;
                }
            }
        }
    }

    /// Dismiss the other transport once one of them has concluded the session.
    ///
    /// The winning transport is skipped deliberately: its peer is the Server
    /// that just authenticated this client, and a cancel there would tear down
    /// the session that is still exchanging the `GrantConfirmation` (and, on
    /// BLE, would notify the very server that won).
    ///
    /// A BLE winner is not even released here. `ble-gatt-specification.md` §2
    /// item 3 (Client Confirmation Characteristic) requires the GATT link to stay
    /// up until confirmation delivery succeeds or times out, so its whole
    /// lifetime — last notification included — belongs to the task
    /// [`Self::send_confirmation_background`] spawns; that task and nothing else
    /// calls `finalize` on it. The decision itself is the [`success_teardown`]
    /// table; this function only applies it.
    #[cfg(feature = "ble")]
    async fn multicast_cancel_on_success(
        &self,
        winner: WinningTransport,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) {
        // Both grant paths funnel through here, so this is the one line that
        // names the transport which carried the grant. NOTE: the exact phrase and
        // `WinningTransport`'s Debug output ("Ble"/"Udp") are asserted by E2E
        // Phase 3 (BLE only) and Phase 4 (either winner), in
        // `scripts/test-e2e.sh`; keep the format specifier a `{:?}` of the
        // winner if you rename a variant.
        tracing::info!("Authentication granted over {:?}", winner);
        self.dismiss_losing_transports(
            success_teardown(winner),
            ble_transport,
            udp_transport,
            cancel_packet,
        )
        .await;
    }

    /// Dismiss the losing transport when the session ended without a grant.
    ///
    /// `winner` is the transport that concluded the session (the one that
    /// delivered the phone's denial). Its acknowledgement is still in flight, so
    /// its teardown belongs to [`Self::send_confirmation_background`]'s task, for
    /// the same reason as in [`Self::multicast_cancel_on_success`]. The decision
    /// is the [`denial_teardown`] table; this function only applies it.
    #[cfg(feature = "ble")]
    async fn cleanup_transports(
        &self,
        winner: WinningTransport,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) {
        self.dismiss_losing_transports(
            denial_teardown(winner),
            ble_transport,
            udp_transport,
            cancel_packet,
        )
        .await;
    }

    /// Apply a [`Teardown`] decision to the transports that no longer own the
    /// session.
    #[cfg(feature = "ble")]
    async fn dismiss_losing_transports(
        &self,
        teardown: Teardown,
        ble_transport: &Option<Arc<crate::transport::BleTransport>>,
        udp_transport: &Arc<crate::transport::UdpTransport>,
        cancel_packet: &EncryptedPacket,
    ) {
        if let Some(ble) = ble_transport {
            if teardown.cancel_ble || teardown.finalize_ble {
                let ble = ble.clone();
                let cancel = cancel_packet.clone();
                tokio::spawn(async move {
                    if teardown.cancel_ble {
                        let _ = ble.send_cancel(&cancel).await;
                    }
                    if teardown.finalize_ble {
                        let _ = ble.finalize().await;
                    }
                });
            }
        }
        if teardown.cancel_udp && self.transports.network {
            let _ = udp_transport.send_cancel(cancel_packet).await;
        }
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

        if self.transports.network {
            // UdpTransport logs per-interface multicast failures internally, so
            // there is no error to act on here.
            tracing::info!("Multicasting AuthenticationCancel over UDP");
            let _ = udp_transport.send_cancel(cancel_packet).await;
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
        let run = Arc::new(self.run_params());
        let result = Self::authenticate_with_transport(transport_arc, packet, run).await;
        if result.is_ok() {
            // Same phrase as the dual-transport build's grant line in
            // `multicast_cancel_on_success` (E2E Phases 3 and 4 match it): with
            // the `ble` feature off, the network path is the only one that can
            // conclude a session.
            tracing::info!("Authentication granted over Network");
        }
        result
    }

    /// Authenticate using any Transport
    async fn authenticate_with_transport<T: Transport + Send + Sync + 'static>(
        transport: Arc<T>,
        packet: &EncryptedPacket,
        run: Arc<AuthRunParams>,
    ) -> Result<(), AuthHandlerError> {
        let timeout = get_session_timeout();
        let start = Instant::now();
        // When the request on the wire may be followed by another one. Set by
        // every send, read only when a frame ends a wait early.
        let mut next_send_at: Instant;
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
            let retry_interval = shared::network::get_client_retry_interval(attempt);
            next_send_at = Instant::now() + retry_interval;

            // Wait for response
            match Self::wait_for_response(&transport, retry_interval, &run, &mut nonce_cache).await
            {
                Ok(WaitOutcome::Response(wrapper, server_addr)) => {
                    // Process the authenticated response
                    match Self::process_auth_response(&wrapper, &transport, &run, server_addr).await
                    {
                        Ok(result) => return result,
                        Err(ResponseError::InvalidMessage) => {
                            // Continue waiting for valid response
                            continue;
                        }
                    }
                }
                Ok(outcome) => {
                    // Only a request nobody answered widens the interval. A frame
                    // that arrived but is unattributable must not: any device on
                    // the link can emit one, and letting it thin our requests
                    // would slow down the phone that is allowed to answer.
                    if outcome.retransmission_unanswered() {
                        attempt += 1;
                    } else {
                        // ...and it does not buy a request either. The frame
                        // ended this wait early, but the request it interrupted
                        // still owns its interval: a device that holds the CSK
                        // can emit one fresh frame after another, and re-sending
                        // per frame would hand it one client request per frame
                        // for the whole session. Nothing is lost by waiting —
                        // the verdict is unchanged and the session keeps
                        // waiting.
                        if let Some(remaining) = next_send_at.checked_duration_since(Instant::now())
                        {
                            tokio::time::sleep(remaining).await;
                        }
                    }
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
        run: &AuthRunParams,
        nonce_cache: &mut HashSet<Vec<u8>>,
    ) -> Result<WaitOutcome, AuthHandlerError> {
        match transport
            .receive_response(retry_interval, &run.csk_meta)
            .await
        {
            Err(e) => Err(e),
            Ok(ReceiveResult::Timeout) => Ok(WaitOutcome::Timeout),
            Ok(ReceiveResult::Response(response_packet, server_addr)) => {
                let nonce_fingerprint = {
                    let mut data = response_packet.temporal_identifier.clone();
                    data.extend_from_slice(&response_packet.ciphertext);
                    data
                };
                if !nonce_cache.insert(nonce_fingerprint) {
                    // NOTE: This exact log phrase is asserted by E2E test Phase 2d (nonce replay check).
                    tracing::warn!("Replayed packet detected from {}, ignoring", server_addr);
                    return Ok(WaitOutcome::Timeout);
                }

                let wrapper = match decrypt_encrypted_packet_with_csk_nonce(
                    &run.csk,
                    run.csk_meta.symmetric_algorithm,
                    &response_packet,
                ) {
                    Ok(wrapper) => wrapper,
                    Err(e) => {
                        // Audit log: an authenticated-looking packet failed AEAD verification.
                        // This is the expected outcome for tampered/corrupted datagrams.
                        // NOTE: This exact log phrase ("Failed to decrypt response packet") is asserted by E2E test Phase 2d.
                        tracing::warn!(
                            "Failed to decrypt response packet from {} ({} ciphertext bytes): {}; rejecting it",
                            server_addr,
                            response_packet.ciphertext.len(),
                            e
                        );
                        return Err(e.into());
                    }
                };
                let addr_str = server_addr.to_string();
                tracing::debug!("Received message from {}", addr_str);

                // Only an authorized Server's signature may take part in the
                // decision below.
                if Self::response_signature_authorized(&run.allowed_servers, &wrapper) {
                    Ok(WaitOutcome::Response(wrapper, addr_str))
                } else {
                    tracing::warn!(
                        "Response from {} is not signed by a server authorized for this request; ignoring it",
                        addr_str
                    );
                    Ok(WaitOutcome::Unattributable)
                }
            }
        }
    }

    /// Whether any Server authorized for this user signed `wrapper`.
    ///
    /// Each candidate is checked with *its own* negotiated signature algorithm,
    /// so a Server cannot claim an algorithm the pairing did not agree on.
    fn response_signature_authorized(
        allowed_servers: &[PairedServer],
        wrapper: &WrapperMessage,
    ) -> bool {
        allowed_servers.iter().any(|server| {
            server_public_key(server).is_some_and(|public_key| {
                verify_wrapper_signature(wrapper, &public_key, server.signature_algorithm as i32)
                    .is_ok()
            })
        })
    }

    async fn process_auth_response<T: Transport + Send + Sync + 'static>(
        wrapper: &WrapperMessage,
        transport: &Arc<T>,
        run: &AuthRunParams,
        server_addr: String,
    ) -> Result<Result<(), AuthHandlerError>, ResponseError> {
        match classify_server_response(&run.allowed_servers, &run.challenge, wrapper) {
            ServerResponseVerdict::Grant => {
                tracing::info!("Authentication granted by server: {}", server_addr);
                Self::send_confirmation_background(transport.clone(), run).await;
                Ok(Ok(()))
            }
            ServerResponseVerdict::Denial => {
                tracing::info!(
                    "Authentication explicitly denied by server: {}",
                    server_addr
                );
                Self::send_confirmation_background(transport.clone(), run).await;
                Ok(Err(AuthHandlerError::ExplicitDenial))
            }
            ServerResponseVerdict::Unattributed => {
                // `wait_for_response` already attributed this wrapper's signature
                // to a server authorized for this user, so anything that still
                // cannot be attributed is a response for a *different* session
                // (a replayed or injected grant) or not a decision at all.
                if wrapper.payload_type == PayloadType::AuthGrant as i32 {
                    // NOTE: This exact log phrase is asserted by E2E test Phase 2d
                    // (a captured grant from an old session must not be accepted).
                    tracing::warn!(
                        "Grant challenge verification failed; continuing to wait for valid response"
                    );
                } else if wrapper.payload_type == PayloadType::AuthDenial as i32 {
                    tracing::warn!(
                        "Denial from {} does not answer the session for user {}; continuing to wait",
                        server_addr,
                        run.username
                    );
                } else {
                    tracing::debug!("Unexpected message type, waiting for valid response");
                }
                Err(ResponseError::InvalidMessage)
            }
        }
    }

    /// Send the `GrantConfirmation` on `transport` in the background, then
    /// release `transport`.
    ///
    /// This function and the task it spawns are the **only** owners of the
    /// concluding transport's teardown: every path out of here — including the
    /// ones that cannot even build the confirmation — finalizes it exactly once,
    /// so nothing else may tear the winner down (see
    /// [`Self::multicast_cancel_on_success`]).
    ///
    /// The task notifies three times, then takes a [`NOTIFY_SETTLE`] pause, and
    /// only then finalizes. On BLE that pause is what lets the last notification
    /// reach the air: `CharacteristicNotifier::publish` returns once BlueZ has
    /// accepted the value, and `finalize` disconnects the phone in the same
    /// tick, so a release issued right after the third `send_confirmation`
    /// drops the frame instead of transmitting it — the same pause
    /// `publish_cancel` and `PairingBleSession::settle` take before their own
    /// teardown. Function-call order alone does not put the value on the air.
    ///
    /// Both conclusions go through here — a grant and an explicit denial alike —
    /// because both have an acknowledgement in flight: a denial is answered with
    /// the same confirmation frame, and the phone that denied is the one whose
    /// link must survive until it arrives.
    async fn send_confirmation_background<T: Transport + Send + Sync + 'static>(
        transport: Arc<T>,
        run: &AuthRunParams,
    ) {
        let confirmation = match create_grant_confirmation(&run.challenge) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to create confirmation: {}", e);
                let _ = transport.finalize().await;
                return;
            }
        };

        let mut conf_wrapper = wrap_grant_confirmation(confirmation);
        if let Err(e) = sign_wrapper_message(&mut conf_wrapper, &run.keypair) {
            tracing::error!("Failed to sign confirmation: {}", e);
            let _ = transport.finalize().await;
            return;
        }

        let conf_packet = match create_encrypted_packet_with_csk_nonce(
            &run.csk,
            run.csk_meta.symmetric_algorithm,
            run.csk_meta.hash_algorithm,
            &conf_wrapper,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to encrypt confirmation: {}", e);
                let _ = transport.finalize().await;
                return;
            }
        };

        let csk_meta = run.csk_meta;
        tokio::spawn(async move {
            // Best-effort: up to 3 sends within ~500ms total. Bounded because
            // this task now owns the transport: a BlueZ notification that never
            // returns must not keep the advertisement and GATT application up.
            let _ = tokio::time::timeout(CONFIRMATION_LIFETIME, async {
                let _ = transport.send_confirmation(&conf_packet, &csk_meta).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = transport.send_confirmation(&conf_packet, &csk_meta).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = transport.send_confirmation(&conf_packet, &csk_meta).await;
                // The last `notify` only means BlueZ accepted the value, not that
                // the controller transmitted it. Disconnecting now would drop it,
                // so give the link the same pause `publish_cancel` takes.
                tokio::time::sleep(NOTIFY_SETTLE).await;
            })
            .await;
            let _ = transport.finalize().await;
        });
    }
}

/// The paired servers that may answer for `username`.
///
/// This is the single place the `allowed_users` filter is applied; everything
/// that verifies a Server response consumes its output rather than
/// `DaemonState::paired_servers`.
fn servers_authorized_for(
    paired_servers: &HashMap<String, PairedServer>,
    username: &str,
) -> Vec<PairedServer> {
    paired_servers
        .values()
        .filter(|server| server.is_user_allowed(username))
        .cloned()
        .collect()
}

/// What a decrypted Server response means for this authentication session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerResponseVerdict {
    /// A Server authorized for this user signed a matching `AuthenticationGrant`.
    Grant,
    /// A Server authorized for this user signed a matching `AuthenticationDenial`.
    Denial,
    /// Not an answer this client may act on: nobody signed it that is allowed to
    /// answer for this user, or the challenge does not match, or it is not a
    /// grant/denial at all.
    Unattributed,
}

/// Decide what a decrypted Server response means for this session.
///
/// Pure — no I/O and no clock — so the authorization decision can be tested
/// directly. Every check runs against `allowed_servers` only: a Server paired for
/// a different account is not in that slice, so its grant cannot authenticate
/// this user and its denial cannot cancel the prompt for it.
fn classify_server_response(
    allowed_servers: &[PairedServer],
    challenge: &[u8; 32],
    wrapper: &WrapperMessage,
) -> ServerResponseVerdict {
    let payload_type = wrapper.payload_type;

    if payload_type == PayloadType::AuthGrant as i32 {
        let granted = allowed_servers.iter().any(|server| {
            server_public_key(server).is_some_and(|public_key| {
                verify_auth_grant(
                    wrapper,
                    challenge,
                    &public_key,
                    server.signature_algorithm as i32,
                )
                .is_ok()
            })
        });
        if granted {
            return ServerResponseVerdict::Grant;
        }
    } else if payload_type == PayloadType::AuthDenial as i32 {
        let denied = allowed_servers.iter().any(|server| {
            server_public_key(server).is_some_and(|public_key| {
                verify_auth_denial(
                    wrapper,
                    challenge,
                    &public_key,
                    server.signature_algorithm as i32,
                )
                .is_ok()
            })
        });
        if denied {
            return ServerResponseVerdict::Denial;
        }
    }

    ServerResponseVerdict::Unattributed
}

/// Decode a paired server's Ed25519 public key.
fn server_public_key(server: &PairedServer) -> Option<[u8; 32]> {
    let bytes = hex::decode(&server.public_key).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Some(public_key)
}

/// Error type for response processing
enum ResponseError {
    /// Invalid message that should be ignored (wait for another response)
    InvalidMessage,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use shared::protocol::pb::SignatureAlgorithm;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn paired_server(name: &str, keypair: &Ed25519KeyPair, allowed_users: &[&str]) -> PairedServer {
        PairedServer {
            name: name.to_string(),
            public_key: hex::encode(keypair.verifying_key_bytes()),
            allowed_users: allowed_users.iter().map(|user| user.to_string()).collect(),
            paired_at: chrono::Utc::now(),
            signature_algorithm: SignatureAlgorithm::Ed25519,
        }
    }

    /// The production filter: the servers that may answer for `username`.
    fn allowed_for(servers: &[PairedServer], username: &str) -> Vec<PairedServer> {
        let map: HashMap<String, PairedServer> = servers
            .iter()
            .map(|server| (server.name.clone(), server.clone()))
            .collect();
        servers_authorized_for(&map, username)
    }

    /// Two paired phones, each bound to one account.
    fn two_phones() -> (PairedServer, PairedServer, Ed25519KeyPair, Ed25519KeyPair) {
        let phone_a = Ed25519KeyPair::generate().unwrap();
        let phone_b = Ed25519KeyPair::generate().unwrap();
        (
            paired_server("phone-a", &phone_a, &["bob"]),
            paired_server("phone-b", &phone_b, &["alice"]),
            phone_a,
            phone_b,
        )
    }

    /// Phone B is paired for `alice`; the session authenticates `bob`, who is
    /// only allowed on phone A. Phone B's grant must not authenticate `bob`, and
    /// phone A's must.
    ///
    /// The defect this catches: response verification running against
    /// `state.paired_servers` (every paired phone) instead of the
    /// `allowed_users`-filtered set, which lets any paired device grant any
    /// account on the host.
    #[test]
    fn second_phone_cannot_grant_or_deny_for_another_user() {
        let (phone_a, phone_b, key_a, key_b) = two_phones();
        let servers = vec![phone_a, phone_b];
        let allowed = allowed_for(&servers, "bob");
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed.first().map(|s| s.name.as_str()), Some("phone-a"));

        let challenge = [0x42u8; 32];

        // Phone B signs a perfectly valid grant for this challenge.
        let grant_from_b = create_signed_auth_grant(challenge, &key_b).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &challenge, &grant_from_b),
            ServerResponseVerdict::Unattributed,
            "phone B must not grant a session for bob"
        );
        assert!(
            !AuthSession::response_signature_authorized(&allowed, &grant_from_b),
            "phone B's signature must not pass the authorized-server filter"
        );

        // The same response from phone A is a grant.
        let grant_from_a = create_signed_auth_grant(challenge, &key_a).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &challenge, &grant_from_a),
            ServerResponseVerdict::Grant
        );
        assert!(AuthSession::response_signature_authorized(
            &allowed,
            &grant_from_a
        ));

        // The filter is per-user, not per-key: with `alice` as the subject,
        // phone B is the authorized one and phone A is not.
        let allowed_alice = allowed_for(&servers, "alice");
        assert_eq!(
            classify_server_response(&allowed_alice, &challenge, &grant_from_b),
            ServerResponseVerdict::Grant
        );
        assert_eq!(
            classify_server_response(&allowed_alice, &challenge, &grant_from_a),
            ServerResponseVerdict::Unattributed
        );
    }

    /// A denial from a phone that is not allowed to answer for the user must not
    /// end that user's session: otherwise any paired device could veto logins
    /// for accounts it is not bound to.
    #[test]
    fn denial_from_a_disallowed_phone_cannot_deny_another_users_session() {
        let (phone_a, phone_b, key_a, key_b) = two_phones();
        let servers = vec![phone_a, phone_b];
        let allowed = allowed_for(&servers, "bob");
        let challenge = [0x43u8; 32];

        let denial_from_b = create_signed_auth_denial(challenge, "user rejected", &key_b).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &challenge, &denial_from_b),
            ServerResponseVerdict::Unattributed,
            "phone B must not deny a session for bob"
        );

        let denial_from_a = create_signed_auth_denial(challenge, "user rejected", &key_a).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &challenge, &denial_from_a),
            ServerResponseVerdict::Denial
        );
    }

    /// A response signed for a different session's challenge is not an answer to
    /// this one, even from an authorized phone.
    #[test]
    fn response_for_a_foreign_challenge_is_not_attributed() {
        let (phone_a, phone_b, key_a, _key_b) = two_phones();
        let servers = vec![phone_a, phone_b];
        let allowed = allowed_for(&servers, "bob");

        let this_session = [0x10u8; 32];
        let other_session = [0x11u8; 32];

        let foreign_grant = create_signed_auth_grant(other_session, &key_a).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &this_session, &foreign_grant),
            ServerResponseVerdict::Unattributed
        );

        let foreign_denial =
            create_signed_auth_denial(other_session, "user rejected", &key_a).unwrap();
        assert_eq!(
            classify_server_response(&allowed, &this_session, &foreign_denial),
            ServerResponseVerdict::Unattributed
        );
    }

    /// Verification uses the algorithm negotiated at pairing time, taken from the
    /// `PairedServer`, not a hardcoded Ed25519: a server whose pairing recorded
    /// an unspecified algorithm cannot answer with an Ed25519 signature.
    #[test]
    fn declared_signature_algorithm_is_enforced_per_server() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let mut server = paired_server("phone", &keypair, &["bob"]);
        server.signature_algorithm = SignatureAlgorithm::Unspecified;

        let challenge = [0x44u8; 32];
        let grant = create_signed_auth_grant(challenge, &keypair).unwrap();
        assert_eq!(
            classify_server_response(&[server], &challenge, &grant),
            ServerResponseVerdict::Unattributed
        );
    }

    /// A non-grant/denial payload (a replayed request, a confirmation) must never
    /// be read as a decision.
    #[test]
    fn non_decision_payload_is_unattributed() {
        let (phone_a, phone_b, key_a, _key_b) = two_phones();
        let servers = vec![phone_a, phone_b];
        let allowed = allowed_for(&servers, "bob");
        let challenge = [0x45u8; 32];

        let confirmation = create_grant_confirmation(&challenge).unwrap();
        let mut wrapper = wrap_grant_confirmation(confirmation);
        sign_wrapper_message(&mut wrapper, &key_a).unwrap();

        assert_eq!(
            classify_server_response(&allowed, &challenge, &wrapper),
            ServerResponseVerdict::Unattributed
        );
        // The signature itself is valid for an authorized server, so only the
        // payload-type check stands between a confirmation and a grant.
        assert!(AuthSession::response_signature_authorized(
            &allowed, &wrapper
        ));
    }

    /// The transport tasks must be handed the authorized subset, never the full
    /// paired-server map.
    ///
    /// The defect this catches: `run_params` (or its caller) reading
    /// `state.paired_servers` again, which silently re-introduces the bypass even
    /// though `handle_authenticate` filtered correctly.
    #[tokio::test]
    async fn run_params_carries_only_the_servers_authorized_for_the_user() {
        let (phone_a, phone_b, _key_a, _key_b) = two_phones();
        let mut paired = HashMap::new();
        paired.insert("phone-a".to_string(), phone_a);
        paired.insert("phone-b".to_string(), phone_b);

        let state = Arc::new(DaemonState {
            config_manager: Arc::new(ClientConfigManager::new()),
            paired_servers: Arc::new(paired.clone()),
            keypair: Some(Ed25519KeyPair::generate().unwrap()),
            csk: Some(ClientSymmetricKey::generate().unwrap()),
            hostname: "host".to_string(),
            udp_socket: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            init_error: None,
        });

        let session = AuthSession {
            allowed_servers: Arc::new(servers_authorized_for(&paired, "bob")),
            state,
            username: "bob".to_string(),
            challenge: [0x46u8; 32],
            caller: CallerContext {
                pam_service: "sudo".to_string(),
                process_name: "sudo".to_string(),
                command_preview: "sudo -i".to_string(),
            },
            tty_present: true,
            csk_meta: CskMetadata::default(),
            transports: TransportsEnabled {
                network: true,
                ble: false,
            },
            cancel_registry: None,
            request_id: None,
        };

        let run = session.run_params();
        assert_eq!(
            run.allowed_servers.len(),
            1,
            "the transport tasks must not receive every paired server"
        );
        assert_eq!(
            run.allowed_servers.first().map(|s| s.name.as_str()),
            Some("phone-a")
        );
        assert_eq!(run.username, "bob");
        assert_eq!(run.challenge, [0x46u8; 32]);
    }

    /// The same `DaemonState` every test in this module shares: healthy keys, the
    /// fixture's paired servers, and a loopback socket.
    async fn test_state(paired: HashMap<String, PairedServer>) -> DaemonState {
        DaemonState {
            config_manager: Arc::new(ClientConfigManager::new()),
            paired_servers: Arc::new(paired),
            keypair: Some(Ed25519KeyPair::generate().unwrap()),
            csk: Some(ClientSymmetricKey::generate().unwrap()),
            hostname: "host".to_string(),
            udp_socket: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            init_error: None,
        }
    }

    fn caller() -> CallerContext {
        CallerContext {
            pam_service: "sudo".to_string(),
            process_name: "sudo".to_string(),
            command_preview: "sudo -i".to_string(),
        }
    }

    /// The real session — built by the production constructor and authorized by
    /// the production filter — must hand the transports only the phone paired for
    /// *this* user, and no verification may consult the other one.
    ///
    /// The defect this catches: `AuthSession` storing `state.paired_servers`
    /// instead of the `allowed_users`-filtered set (in `authorize` or in whatever
    /// `handle_authenticate` calls instead of it), which lets the second phone
    /// grant *or* deny another account's session and hands it a BLE verifier.
    #[tokio::test]
    async fn a_second_phone_never_reaches_verification_for_another_users_session() {
        let (phone_a, phone_b, key_a, key_b) = two_phones();
        // Only the BLE assertion below consumes the second phone's key.
        #[cfg(feature = "ble")]
        let other_key = phone_b.public_key.clone();
        let mut paired = HashMap::new();
        paired.insert("phone-a".to_string(), phone_a);
        paired.insert("phone-b".to_string(), phone_b);

        let state = Arc::new(test_state(paired.clone()).await);
        let mut session =
            AuthSession::new(state, "bob".to_string(), caller(), true).expect("session");

        // Production authorization, not a set this test assembled itself.
        session.authorize(&paired);

        assert_eq!(
            session.allowed_servers.len(),
            1,
            "the session must hold exactly the phone paired for bob"
        );
        assert_eq!(
            session.allowed_servers.first().map(|s| s.name.as_str()),
            Some("phone-a")
        );

        #[cfg(feature = "ble")]
        {
            // The BLE transport builds one verifier per entry of this map, so it
            // must carry phone-a's key and nothing else.
            let by_key = session.allowed_servers_by_key();
            assert_eq!(by_key.len(), 1);
            assert!(
                !by_key.contains_key(&other_key),
                "phone-b must not get a BLE verifier for bob's session"
            );
        }

        // What the transport tasks actually receive.
        let run = session.run_params();
        assert_eq!(run.allowed_servers.len(), 1);
        assert_eq!(run.allowed_servers[0].name, "phone-a");
        assert_eq!(run.username, "bob");

        // ...and phone-b's grant for this very challenge does not pass either
        // check the transport path makes with that set.
        let grant_from_b = create_signed_auth_grant(run.challenge, &key_b).unwrap();
        assert!(
            !AuthSession::response_signature_authorized(&run.allowed_servers, &grant_from_b),
            "phone-b's signature must not pass the filter run_params handed out"
        );
        assert_eq!(
            classify_server_response(&run.allowed_servers, &run.challenge, &grant_from_b),
            ServerResponseVerdict::Unattributed
        );

        // The allowed phone still works through the same set.
        let grant_from_a = create_signed_auth_grant(run.challenge, &key_a).unwrap();
        assert_eq!(
            classify_server_response(&run.allowed_servers, &run.challenge, &grant_from_a),
            ServerResponseVerdict::Grant
        );
    }

    /// A transport that records the order of the calls it receives.
    struct RecordingTransport {
        events: Mutex<Vec<&'static str>>,
    }

    impl Transport for RecordingTransport {
        async fn send_request(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            Ok(())
        }

        async fn receive_response(
            &self,
            _timeout: Duration,
            _csk_meta: &CskMetadata,
        ) -> Result<ReceiveResult, AuthHandlerError> {
            Ok(ReceiveResult::Timeout)
        }

        async fn send_confirmation(
            &self,
            _packet: &EncryptedPacket,
            _csk_meta: &CskMetadata,
        ) -> Result<(), AuthHandlerError> {
            self.events.lock().await.push("confirmation");
            Ok(())
        }

        async fn send_cancel(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            self.events.lock().await.push("cancel");
            Ok(())
        }

        async fn finalize(&self) -> Result<(), AuthHandlerError> {
            self.events.lock().await.push("finalize");
            Ok(())
        }
    }

    /// The transport that concluded the session is released only after its last
    /// confirmation send, and only after that send has had time to reach the
    /// air.
    ///
    /// The defect this catches: any teardown ahead of the last `send`, which on
    /// BLE (`finalize` → `do_shutdown` → `device.disconnect`) disconnects the
    /// phone before the notification reaches it — the phone then retransmits its
    /// grant for 10 s and reports failure — an early return that releases it not
    /// at all, and a release issued immediately after the third `send`, which
    /// drops the frame instead of transmitting it (the elapsed-time assertion
    /// below: two 150 ms pauses plus the [`NOTIFY_SETTLE`] pause is 350 ms).
    #[tokio::test]
    async fn the_concluding_transport_is_released_only_after_its_last_confirmation() {
        let transport = Arc::new(RecordingTransport {
            events: Mutex::new(Vec::new()),
        });
        let run = AuthRunParams {
            keypair: Ed25519KeyPair::generate().unwrap(),
            csk: ClientSymmetricKey::generate().unwrap(),
            csk_meta: CskMetadata::default(),
            challenge: [0x48u8; 32],
            username: "bob".to_string(),
            allowed_servers: Arc::new(Vec::new()),
        };

        let started = Instant::now();
        AuthSession::send_confirmation_background(transport.clone(), &run).await;

        // The three sends happen in the spawned task.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if transport.events.lock().await.last() == Some(&"finalize") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the confirmation task never released the transport"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            *transport.events.lock().await,
            vec!["confirmation", "confirmation", "confirmation", "finalize"],
            "the transport must outlive every confirmation send"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "the last notification was not given time to reach the air: released after {:?}, \
             which is less than the 2 x 150 ms between the sends plus the {NOTIFY_SETTLE:?} settle",
            started.elapsed()
        );
    }

    /// The teardown table itself, for both winners and both conclusions.
    ///
    /// The defect this catches: `finalize_ble` or `cancel_ble` becoming `true`
    /// for a BLE winner (the `winner != WinningTransport::Ble` guard dropped from
    /// the caller's branch), which disconnects the phone that just granted or
    /// denied while its last notification — and, on a denial, the
    /// acknowledgement — is still in flight.
    #[cfg(feature = "ble")]
    #[test]
    fn the_winning_transport_is_never_dismissed_by_the_losing_side() {
        assert_eq!(
            success_teardown(WinningTransport::Ble),
            Teardown {
                cancel_udp: true,
                cancel_ble: false,
                finalize_ble: false,
            },
            "a BLE winner keeps its link: the confirmation task owns its teardown"
        );
        assert_eq!(
            denial_teardown(WinningTransport::Ble),
            Teardown {
                cancel_udp: true,
                cancel_ble: false,
                finalize_ble: false,
            },
            "a BLE winner keeps its link until its denial acknowledgement is out"
        );

        assert_eq!(
            success_teardown(WinningTransport::Udp),
            Teardown {
                cancel_udp: false,
                cancel_ble: true,
                finalize_ble: true,
            },
            "a granted UDP winner is not re-cancelled, and the BLE loser is cancelled and released"
        );
        assert_eq!(
            denial_teardown(WinningTransport::Udp),
            Teardown {
                cancel_udp: true,
                cancel_ble: false,
                finalize_ble: true,
            },
            "a UDP denial still cancels over UDP, and only releases the BLE loser"
        );
    }

    /// A transport that hands back one canned frame, then times out.
    struct ScriptedTransport {
        frame: Mutex<Option<(EncryptedPacket, std::net::SocketAddr)>>,
    }

    impl Transport for ScriptedTransport {
        async fn send_request(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            Ok(())
        }

        async fn receive_response(
            &self,
            _timeout: Duration,
            _csk_meta: &CskMetadata,
        ) -> Result<ReceiveResult, AuthHandlerError> {
            match self.frame.lock().await.take() {
                Some((packet, addr)) => Ok(ReceiveResult::Response(packet, addr)),
                None => Ok(ReceiveResult::Timeout),
            }
        }

        async fn send_confirmation(
            &self,
            _packet: &EncryptedPacket,
            _csk_meta: &CskMetadata,
        ) -> Result<(), AuthHandlerError> {
            Ok(())
        }

        async fn send_cancel(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            Ok(())
        }
    }

    /// A decryptable frame from a phone that may not answer for this user is not
    /// an unanswered request: the retransmission interval must stay where it is.
    ///
    /// The defect this catches: `wait_for_response` reporting "unattributable" as
    /// a timeout (`Ok(None)`/`WaitOutcome::Timeout`), which makes the retry loop
    /// double the interval on every frame any paired phone emits and thins the
    /// requests aimed at the phone that is allowed to grant.
    #[tokio::test]
    async fn an_unattributable_frame_does_not_advance_the_retransmission_backoff() {
        let (phone_a, phone_b, _key_a, key_b) = two_phones();
        assert!(
            !phone_b.is_user_allowed("bob"),
            "phone-b must be paired for another account for this test to mean anything"
        );
        let csk = ClientSymmetricKey::generate().unwrap();
        let csk_meta = CskMetadata::default();
        let challenge = [0x47u8; 32];

        // Phone B, which is paired for alice, signs a perfectly valid grant for
        // bob's session.
        let grant_from_b = create_signed_auth_grant(challenge, &key_b).unwrap();
        let packet = create_encrypted_packet_with_csk_nonce(
            &csk,
            csk_meta.symmetric_algorithm,
            csk_meta.hash_algorithm,
            &grant_from_b,
        )
        .unwrap();

        let transport = Arc::new(ScriptedTransport {
            frame: Mutex::new(Some((
                packet,
                std::net::SocketAddr::from(([127, 0, 0, 1], 40_000)),
            ))),
        });
        let run = AuthRunParams {
            keypair: Ed25519KeyPair::generate().unwrap(),
            csk,
            csk_meta,
            challenge,
            username: "bob".to_string(),
            // Only phone-a may answer for bob; phone-b is the interloper.
            allowed_servers: Arc::new(vec![phone_a]),
        };
        let mut nonce_cache = HashSet::new();

        let outcome = AuthSession::wait_for_response(
            &transport,
            Duration::from_millis(1),
            &run,
            &mut nonce_cache,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, WaitOutcome::Unattributable),
            "phone-b is paired but not allowed to answer for bob"
        );
        assert!(
            !outcome.retransmission_unanswered(),
            "an unattributable frame must not advance the backoff"
        );

        // The same wait with nothing left to deliver is a real timeout, and that
        // one does advance it.
        let outcome = AuthSession::wait_for_response(
            &transport,
            Duration::from_millis(1),
            &run,
            &mut nonce_cache,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, WaitOutcome::Timeout));
        assert!(outcome.retransmission_unanswered());
    }

    /// A transport that answers every request with a fresh frame signed by a
    /// phone that may not answer for this user, counting the requests it is
    /// asked to send.
    struct UnattributableFlood {
        csk: ClientSymmetricKey,
        grant: WrapperMessage,
        sends: AtomicUsize,
    }

    /// How many requests the flood will answer before it gives up. Only a loop
    /// that re-sends per frame ever reaches it; it exists so such a loop fails
    /// the test instead of running to the 120 s session timeout.
    const FLOOD_CAP: usize = 64;

    impl Transport for UnattributableFlood {
        async fn send_request(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            let sent = self.sends.fetch_add(1, Ordering::SeqCst);
            if sent >= FLOOD_CAP {
                // Bound a broken loop: once the count is already fatal there is
                // no point spinning for the rest of the session timeout.
                return Err(AuthHandlerError::BleError("flood cap reached".to_string()));
            }
            Ok(())
        }

        async fn receive_response(
            &self,
            _timeout: Duration,
            csk_meta: &CskMetadata,
        ) -> Result<ReceiveResult, AuthHandlerError> {
            // A fresh nonce per frame, so the replay cache does not turn these
            // into timeouts: this is what a paired device holding the CSK can
            // put on the link.
            let packet = create_encrypted_packet_with_csk_nonce(
                &self.csk,
                csk_meta.symmetric_algorithm,
                csk_meta.hash_algorithm,
                &self.grant,
            )
            .unwrap();
            Ok(ReceiveResult::Response(
                packet,
                std::net::SocketAddr::from(([127, 0, 0, 1], 40_000)),
            ))
        }

        async fn send_confirmation(
            &self,
            _packet: &EncryptedPacket,
            _csk_meta: &CskMetadata,
        ) -> Result<(), AuthHandlerError> {
            Ok(())
        }

        async fn send_cancel(&self, _packet: &EncryptedPacket) -> Result<(), AuthHandlerError> {
            Ok(())
        }
    }

    /// A paired device that holds the CSK must not buy one client request per
    /// frame it emits.
    ///
    /// The defect this catches: the retry loop re-sending immediately after an
    /// `Unattributable` frame instead of letting the current retransmission
    /// interval elapse, which lets such a device drive the client's request rate
    /// for the whole session timeout.
    ///
    /// The session runs on its own worker because the broken loop never awaits
    /// anything that is pending: it would starve a current-thread runtime and
    /// turn this measurement into a 120 s spin instead of a 550 ms one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unattributable_frame_does_not_buy_an_extra_request() {
        let (phone_a, _phone_b, _key_a, key_b) = two_phones();
        let csk = ClientSymmetricKey::generate().unwrap();
        let csk_meta = CskMetadata::default();
        let challenge = [0x49u8; 32];

        let grant = create_signed_auth_grant(challenge, &key_b).unwrap();
        let request = create_encrypted_packet_with_csk_nonce(
            &csk,
            csk_meta.symmetric_algorithm,
            csk_meta.hash_algorithm,
            &grant,
        )
        .unwrap();

        let transport = Arc::new(UnattributableFlood {
            csk: csk.clone(),
            grant,
            sends: AtomicUsize::new(0),
        });
        let run = Arc::new(AuthRunParams {
            keypair: Ed25519KeyPair::generate().unwrap(),
            csk,
            csk_meta,
            challenge,
            username: "bob".to_string(),
            // Only phone-a may answer for bob; phone-b floods the session.
            allowed_servers: Arc::new(vec![phone_a]),
        });

        let win = transport.clone();
        let session = tokio::spawn(async move {
            AuthSession::authenticate_with_transport(win, &request, run).await
        });

        // The session itself runs until its 120 s timeout; only this window is
        // measured.
        let window = Duration::from_millis(550);
        tokio::time::sleep(window).await;
        let sends = transport.sends.load(Ordering::SeqCst);
        let still_waiting = !session.is_finished();
        session.abort();

        assert!(sends >= 1, "the loop must have sent at least one request");
        assert!(
            sends <= 3,
            "{} requests in {:?}: an unattributable frame must not buy a request \
             (200 ms retry interval, so only the sends at 0, 200 and 400 ms fit in the window)",
            sends,
            window
        );
        assert!(
            still_waiting,
            "the session concluded inside the window, so nothing was measured"
        );
    }
}
