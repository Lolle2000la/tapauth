#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod admin_handler;
mod auth_handler;
mod fprintd;
mod logging;
mod peer_identity;
mod transport;

use admin_handler::PairingState;
use auth_handler::{AuthSession, DaemonState};
use bytes::{BufMut, BytesMut};
use fprintd::AuthState;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{setgid, setuid, Gid, Uid, User};
use prost::Message;
use shared::ipc::pb as ipc;
use std::env;
use std::io;
use std::io::ErrorKind;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
use tokio::signal::unix::{self as sigunix, SignalKind};

#[cfg(feature = "fallback-socket")]
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "fallback-socket")]
use std::path::Path;

#[cfg(feature = "fallback-socket")]
const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd.sock";

#[derive(thiserror::Error, Debug)]
pub enum DaemonError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex, RwLock};

/// Which channel started an authentication broadcast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlightChannel {
    Pam,
    Fprintd,
}

/// Tracks the state of an authentication broadcast for one username.
///
/// Guarantees at most one concurrent authentication broadcast per user. The
/// PAM IPC channel and the virtual fprintd bridge are two independent entry
/// points into the same daemon and may occasionally overlap in time:
///
/// - A PAM request arriving while a fprintd flight is in flight — or within
///   `PAM_DEDUP_WINDOW` of a PAM flight's start — is answered with `Ignore`
///   immediately, so the requesting PAM stack falls through to its next auth
///   method instead of triggering a second phone prompt.
/// - A fprintd `VerifyStart` arriving while any flight is in flight reports
///   `verify-no-match` immediately instead of broadcasting; the desktop's UI
///   resets and the user can retry with a fresh buzz.
///
/// Outcomes are never mirrored to concurrent requesters: a latecomer never
/// rides another flight's grant — a grant only ever authenticates the request
/// that owns the broadcast.
pub(crate) struct AuthFlight {
    pub(crate) channel: FlightChannel,
    started: Instant,
}

/// Longest time an in-flight entry may survive without a completion marker
/// (safety purge for crashed sessions; pam_operation_timeout_secs defaults
/// to 120 and is clamped well below this).
const MAX_FLIGHT_SECS: u64 = 300;

/// PAM-PAM dedup window: a second PAM request for the same user within 1s of
/// the first request's start is treated as a duplicate. There is deliberately
/// no completion cooldown — back-to-back same-user PAM auths more than 1s
/// apart each broadcast normally.
const PAM_DEDUP_WINDOW: Duration = Duration::from_secs(1);

pub(crate) type AuthFlightRegistry = Arc<Mutex<HashMap<String, AuthFlight>>>;

/// Drops flight entries whose broadcast started too long ago without ever
/// being finished (safety purge for crashed sessions).
fn purge_stale_flights(flights: &mut HashMap<String, AuthFlight>, now: Instant) {
    flights.retain(|_, flight| {
        now.duration_since(flight.started) < Duration::from_secs(MAX_FLIGHT_SECS)
    });
}

/// Returns true if a request for `username` on channel `incoming` must be
/// deduplicated as a latecomer to the active flight for that user (if any).
/// Rule (the asymmetry is intentional):
///
/// - PAM during PAM: duplicate only within `PAM_DEDUP_WINDOW` of the active
///   flight's start — beyond that, both requests broadcast normally.
/// - Anything else (PAM during fprintd, fprintd during PAM, fprintd during
///   fprintd): always a duplicate, regardless of age.
///
/// Also purges expired entries.
pub(crate) async fn auth_flight_is_duplicate(
    registry: &AuthFlightRegistry,
    username: &str,
    incoming: FlightChannel,
) -> bool {
    let now = Instant::now();
    let mut flights = registry.lock().await;
    purge_stale_flights(&mut flights, now);
    match flights.get(username) {
        Some(flight) => match (flight.channel, incoming) {
            (FlightChannel::Pam, FlightChannel::Pam) => {
                now.duration_since(flight.started) < PAM_DEDUP_WINDOW
            }
            _ => true,
        },
        None => false,
    }
}

/// Registers the start of an authentication broadcast for `username`.
pub(crate) async fn auth_flight_start(
    registry: &AuthFlightRegistry,
    username: &str,
    channel: FlightChannel,
) {
    registry.lock().await.insert(
        username.to_string(),
        AuthFlight {
            channel,
            started: Instant::now(),
        },
    );
}

/// Marks the authentication for `username` as completed (success, denial,
/// error or cancellation alike) by removing the flight entry — there is no
/// completion cooldown.
pub(crate) async fn auth_flight_finish(registry: &AuthFlightRegistry, username: &str) {
    registry.lock().await.remove(username);
}

/// Server shared state (daemon runtime + cancel registry + deduplication + pairing)
struct ServerState {
    daemon: Arc<RwLock<Arc<DaemonState>>>,
    cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    auth_flights: AuthFlightRegistry,
    pending_pairing: Arc<Mutex<Option<PairingState>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_logging();

    tracing::info!("tapauthd starting...");

    // Load TOML configuration to get UDP port
    let toml_config = shared::config::TapAuthConfig::load();
    let udp_port = toml_config.udp_port;

    if !toml_config.enable_network {
        tracing::info!("Local Network (UDP) transport disabled by configuration");
    }
    if !toml_config.enable_ble {
        tracing::info!("BLE transport disabled by configuration");
    }

    // Create global UDP socket for the daemon's lifetime.
    // Created even when the Local Network transport is disabled so that
    // re-enabling it at runtime does not require a daemon restart.
    let udp_socket = shared::network::create_broadcast_socket(udp_port).await?;
    tracing::info!("Created global UDP socket on port {}", udp_port);

    // Load daemon state (config, keys, etc.)
    let daemon_state = match DaemonState::new(udp_socket) {
        Ok(state) => Arc::new(state),
        Err(e) => {
            tracing::error!("Failed to initialize daemon state: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!("Loaded config and keys successfully");

    // Attempt to adopt systemd socket (FD#3) - this is the production mode
    let (listener, using_systemd_socket) = match adopt_systemd_socket()? {
        Some(l) => {
            tracing::info!("Adopted systemd socket (FD#3)");
            (l, true)
        }
        None => {
            #[cfg(feature = "fallback-socket")]
            {
                // Development/testing fallback: bind socket manually
                // Production deployments should use systemd socket activation (see systemd/tapauthd.socket)
                tracing::warn!("fallback-socket feature enabled - binding socket manually for development/testing");

                let sock_path = std::env::var("TAPAUTHD_SOCK")
                    .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

                // Clean up stale path if we own it
                if Path::new(&sock_path).exists() {
                    let _ = tokio::fs::remove_file(&sock_path).await;
                }

                let listener = UnixListener::bind(&sock_path)?;
                tracing::info!("Bound socket at {}", sock_path);

                // Set permissions to 0660 for manual (non-systemd) runs
                #[allow(unused_imports)]
                {
                    if let Err(e) =
                        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o660))
                    {
                        tracing::warn!("Failed to set socket permissions on {}: {}", sock_path, e);
                    }
                }
                (listener, false)
            }
            #[cfg(not(feature = "fallback-socket"))]
            {
                // Production mode: require systemd socket activation
                tracing::error!("No systemd socket provided (LISTEN_FDS not set)");
                tracing::error!("Production builds require systemd socket activation.");
                tracing::error!("Please ensure tapauthd.socket is enabled and started:");
                tracing::error!("  sudo systemctl enable --now tapauthd.socket");
                tracing::error!("For development/testing, rebuild with --features fallback-socket");
                return Err(
                    "Systemd socket activation required - see systemd/tapauthd.socket".into(),
                );
            }
        }
    };
    // The flag is only consulted by the fallback-socket shutdown path.
    #[cfg(not(feature = "fallback-socket"))]
    let _ = using_systemd_socket;

    // Drop privileges to tapauthd:tapauthd
    // Note: When running under systemd with User=tapauthd, this is redundant but harmless
    // as long as we don't fail if already dropped.
    if let Err(e) = drop_privileges_to_tapauthd() {
        tracing::warn!(
            "Failed to drop privileges (might already be running as user): {}",
            e
        );
    } else {
        tracing::info!("Dropped privileges to tapauthd user");
    }

    // Create shared daemon handle used by both the IPC dispatcher and fprintd.
    // Wrapped in RwLock so admin reloads are immediately visible to all consumers.
    let shared_daemon = Arc::new(RwLock::new(daemon_state.clone()));

    // Shared auth-flight registry (at most one concurrent authentication
    // broadcast per username), used by both the PAM IPC channel and the
    // virtual fprintd bridge.
    let auth_flights: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));

    // Shared IPC cancel registry (targeted PamCancel / disconnect handling).
    let cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Start the virtual fprintd D-Bus service (non-fatal: daemon functions without it).
    // The daemon claims net.reactivated.Fprint by default; set
    // enable_fprintd_bridge = false if you use a real local fingerprint reader
    // (real fprintd then owns the bus name).
    let _fprintd_conn = if toml_config.enable_fprintd_bridge {
        match fprintd::start_fprintd_service(AuthState {
            daemon: shared_daemon.clone(),
            auth_flights: auth_flights.clone(),
        })
        .await
        {
            Ok(conn) => {
                tracing::info!("Virtual fprintd D-Bus service registered successfully");
                Some(conn)
            }
            Err(e) => {
                tracing::warn!(
                    "Virtual fprintd D-Bus service failed to register: {} (check that real fprintd is stopped and D-Bus policy is installed)",
                    e
                );
                None
            }
        }
    } else {
        tracing::debug!(
            "Virtual fprintd D-Bus bridge is disabled in configuration (enable_fprintd_bridge = false)"
        );
        None
    };

    let server_state = Arc::new(ServerState {
        daemon: shared_daemon,
        cancel_registry,
        auth_flights,
        pending_pairing: Arc::new(Mutex::new(None)),
    });

    let server = {
        let server_state = server_state.clone();
        async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        tracing::debug!("Accepted connection: {:?}", addr);
                        let daemon = server_state.daemon.read().await.clone();
                        let server_state = server_state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, daemon, server_state).await {
                                tracing::warn!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = server => {}
        _ = signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down");
        }
        _ = async {
            #[cfg(unix)]
            {
                let sigterm_handle = sigunix::signal(SignalKind::terminate());
                if let Ok(mut sigterm) = sigterm_handle {
                    sigterm.recv().await;
                    tracing::info!("Received SIGTERM, shutting down");
                } else {
                    std::future::pending::<()>().await;
                }
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        } => {}
    }

    // Cleanup socket on exit only if we created it ourselves. Without the
    // fallback-socket feature this branch is unreachable: a production build
    // refuses to start without systemd socket activation, so there is never a
    // self-created socket (nor a TAPAUTHD_SOCK read) to clean up.
    #[cfg(feature = "fallback-socket")]
    if !using_systemd_socket {
        // Try to read the path from env; safe to fail silently
        if let Ok(sock_path) = std::env::var("TAPAUTHD_SOCK") {
            let _ = tokio::fs::remove_file(&sock_path).await;
        } else {
            let _ = tokio::fs::remove_file(DEFAULT_SOCKET_PATH).await;
        }
    }
    tracing::info!("tapauthd shut down cleanly");

    Ok(())
}

// Try to adopt a pre-opened Unix socket from systemd (FD#3)
fn adopt_systemd_socket() -> Result<Option<UnixListener>, Box<dyn std::error::Error>> {
    let listen_fds: i32 = match env::var("LISTEN_FDS").ok().and_then(|v| v.parse().ok()) {
        Some(n) if n > 0 => n,
        _ => return Ok(None),
    };
    let listen_pid: i32 = env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let pid = std::process::id() as i32;
    if listen_pid != pid {
        return Ok(None);
    }
    // Use only the first FD (3)
    if listen_fds >= 1 {
        let std_listener = unsafe {
            <std::os::unix::net::UnixListener as std::os::unix::io::FromRawFd>::from_raw_fd(3)
        };
        std_listener.set_nonblocking(true)?;
        let tokio_listener = UnixListener::from_std(std_listener)?;
        return Ok(Some(tokio_listener));
    }
    Ok(None)
}

fn drop_privileges_to_tapauthd() -> Result<(), Box<dyn std::error::Error>> {
    let target_user =
        User::from_name("tapauthd").map_err(|e| format!("Failed to query user database: {}", e))?;
    let user = target_user.ok_or("User 'tapauthd' not found")?;

    let target_uid = Uid::from_raw(user.uid.as_raw());
    let target_gid = Gid::from_raw(user.gid.as_raw());

    let current_euid = nix::unistd::geteuid();
    if current_euid == target_uid {
        return Ok(());
    }

    setgid(target_gid).map_err(|e| format!("setgid failed: {}", e))?;
    setuid(target_uid).map_err(|e| format!("setuid failed: {}", e))?;

    Ok(())
}

async fn handle_conn(
    mut stream: UnixStream,
    daemon: Arc<DaemonState>,
    server_state: Arc<ServerState>,
) -> Result<(), DaemonError> {
    let (caller_pid, caller_uid) = {
        let raw_fd = stream.as_raw_fd();
        let fd_arg = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        match getsockopt(&fd_arg, PeerCredentials) {
            Ok(creds) => (creds.pid(), creds.uid()),
            Err(e) => {
                tracing::warn!("Failed to get peer credentials: {}", e);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer cred unavailable",
                )
                .into());
            }
        }
    };

    tracing::debug!("Connection from PID={} UID={}", caller_pid, caller_uid);

    // 3-second timeout to prevent malicious clients from holding connections open
    let req_bytes =
        match tokio::time::timeout(std::time::Duration::from_secs(3), read_framed(&mut stream))
            .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                tracing::warn!("IPC read timeout - client failed to send request within 3 seconds");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "IPC read timeout").into());
            }
        };

    // Zero-length frames are used by health checks — don't loop back
    // through the IPC dispatch, just close the connection silently.
    if req_bytes.is_empty() {
        return Ok(());
    }

    // All messages arrive wrapped in IpcEnvelope for unambiguous dispatch.
    // PAM auth/cancel requests skip PolKit by design: the PAM module runs
    // *during* authentication and the subject hasn't been verified yet.
    // Access is gated by socket permissions (root:tapauthd-clients 0660).
    if let Ok(envelope) = ipc::IpcEnvelope::decode(req_bytes.as_slice()) {
        match envelope.msg {
            Some(ipc::ipc_envelope::Msg::PamAuthenticate(auth_req)) => {
                let req_id = auth_req.request_id.clone();
                let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
                {
                    let mut reg = server_state.cancel_registry.lock().await;
                    reg.insert(req_id.clone(), cancel_tx);
                }
                let cancel_reg = server_state.cancel_registry.clone();

                let auth_fut = handle_pam_authenticate(auth_req, &daemon, &server_state, cancel_rx);
                tokio::pin!(auth_fut);

                let mut eof_buf = [0u8; 1];
                let (response, client_disconnected) = tokio::select! {
                    resp = &mut auth_fut => (Some(resp), false),
                    read_res = stream.read(&mut eof_buf) => {
                        match read_res {
                            Ok(0) | Err(_) => {
                                tracing::info!(
                                    "IPC client disconnected while authentication '{}' was in-flight",
                                    req_id
                                );
                                // Plain disconnect-cancel: the caller's own
                                // flight (and broadcast) is torn down.
                                let mut reg = cancel_reg.lock().await;
                                if let Some(tx) = reg.remove(&req_id) {
                                    let _ = tx.send(());
                                }
                                drop(reg);
                                let _ = auth_fut.await;
                                (None, true)
                            }
                            Ok(_) => {
                                tracing::warn!(
                                    "Unexpected data received from client during authentication '{}' — cancelling request",
                                    req_id
                                );
                                let mut reg = cancel_reg.lock().await;
                                if let Some(tx) = reg.remove(&req_id) {
                                    let _ = tx.send(());
                                }
                                drop(reg);
                                let _ = auth_fut.await;
                                (None, true)
                            }
                        }
                    }
                };

                if let Some(response) = response {
                    if !client_disconnected {
                        return write_response(
                            &mut stream,
                            &envelope_pam_response(response),
                            "PAM",
                        )
                        .await;
                    }
                }
                return Ok(());
            }
            Some(ipc::ipc_envelope::Msg::PamCancel(cancel_req)) => {
                let response = handle_pam_cancel(cancel_req, &server_state).await;
                return write_response(&mut stream, &envelope_pam_response(response), "PAM").await;
            }
            Some(ipc::ipc_envelope::Msg::AdminRequest(admin_req)) => {
                let admin_resp = admin_handler::handle_admin_request(
                    admin_req,
                    &server_state.daemon,
                    &server_state.pending_pairing,
                    caller_pid,
                    caller_uid,
                )
                .await;
                return write_response(&mut stream, &envelope_admin_response(admin_resp), "Admin")
                    .await;
            }
            None => {
                tracing::debug!("Empty IpcEnvelope");
            }
            Some(ipc::ipc_envelope::Msg::PamResponse(_))
            | Some(ipc::ipc_envelope::Msg::AdminResponse(_)) => {
                tracing::warn!("Received response-type message from client — ignoring");
            }
        }
    }

    tracing::warn!("Unrecognized IPC data — not a valid IpcEnvelope");
    let response = ipc::PamAuthenticateResponse {
        outcome: ipc::PamOutcome::Error as i32,
        detail: "Unknown IPC message".to_string(),
        challenge: Vec::new(),
    };

    write_response(&mut stream, &envelope_pam_response(response), "Client").await
}

async fn handle_pam_authenticate(
    req: ipc::PamAuthenticateRequest,
    daemon: &Arc<DaemonState>,
    server_state: &Arc<ServerState>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> ipc::PamAuthenticateResponse {
    if auth_flight_is_duplicate(
        &server_state.auth_flights,
        &req.username,
        FlightChannel::Pam,
    )
    .await
    {
        tracing::warn!(
            "Duplicate authentication request for user '{}' - another auth is in flight; ignoring",
            req.username
        );
        let mut reg = server_state.cancel_registry.lock().await;
        reg.remove(&req.request_id);
        drop(reg);
        return ipc::PamAuthenticateResponse {
            outcome: ipc::PamOutcome::Ignore as i32,
            detail: "Duplicate request - another authentication is in progress".to_string(),
            challenge: Vec::new(),
        };
    }
    auth_flight_start(
        &server_state.auth_flights,
        &req.username,
        FlightChannel::Pam,
    )
    .await;

    let timeout = Some(req.timeout_seconds);
    let auth_fut = match AuthSession::new(daemon.clone(), req.username.clone()) {
        Ok(sess) => Box::pin(sess.handle_authenticate(
            timeout,
            Some(req.request_id.clone()),
            server_state.cancel_registry.clone(),
            cancel_rx,
        )),
        Err(e) => {
            let mut reg = server_state.cancel_registry.lock().await;
            reg.remove(&req.request_id);
            drop(reg);
            auth_flight_finish(&server_state.auth_flights, &req.username).await;
            tracing::error!("Failed to create authentication session: {}", e);
            return ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Error as i32,
                detail: format!("Failed to create auth session: {}", e),
                challenge: Vec::new(),
            };
        }
    };

    // The PAM request owns its flight end-to-end: await the session outcome,
    // then free the flight slot. Other channels never join or abort it.
    let result = auth_fut.await;
    auth_flight_finish(&server_state.auth_flights, &req.username).await;
    flatten_auth_result(result)
}

/// Maps an `AuthSession` result to the IPC response (handler errors become
/// outcome=Error responses, as before).
fn flatten_auth_result(
    result: Result<ipc::PamAuthenticateResponse, auth_handler::AuthHandlerError>,
) -> ipc::PamAuthenticateResponse {
    match result {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Authentication handler error: {}", e);
            ipc::PamAuthenticateResponse {
                outcome: ipc::PamOutcome::Error as i32,
                detail: format!("Internal error: {}", e),
                challenge: Vec::new(),
            }
        }
    }
}

async fn handle_pam_cancel(
    req: ipc::PamCancelRequest,
    server_state: &Arc<ServerState>,
) -> ipc::PamAuthenticateResponse {
    let mut reg = server_state.cancel_registry.lock().await;
    if let Some(tx) = reg.remove(&req.request_id) {
        let _ = tx.send(());
        return ipc::PamAuthenticateResponse {
            outcome: ipc::PamOutcome::Ignore as i32,
            detail: "Cancel forwarded".to_string(),
            challenge: Vec::new(),
        };
    }
    ipc::PamAuthenticateResponse {
        outcome: ipc::PamOutcome::Ignore as i32,
        detail: "No matching request to cancel".to_string(),
        challenge: Vec::new(),
    }
}

async fn write_framed<M: Message>(stream: &mut UnixStream, msg: &M) -> Result<(), DaemonError> {
    let mut buf = BytesMut::with_capacity(256);

    // Encode message to temporary buffer first to get length
    let msg_bytes = msg.encode_to_vec();
    let len = msg_bytes.len() as u32;

    // Write length prefix (u32 BE)
    buf.put_u32(len);
    // Write message
    buf.extend_from_slice(&msg_bytes);

    stream.write_all(&buf).await?;
    Ok(())
}

async fn write_response<M: Message>(
    stream: &mut UnixStream,
    msg: &M,
    client_label: &str,
) -> Result<(), DaemonError> {
    match write_framed(stream, msg).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if let DaemonError::Io(ref ioe) = e {
                match ioe.kind() {
                    ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::UnexpectedEof => {
                        tracing::debug!(
                            "{} client disconnected before response could be sent: {}",
                            client_label,
                            ioe
                        );
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(e)
        }
    }
}

fn envelope_pam_response(response: ipc::PamAuthenticateResponse) -> ipc::IpcEnvelope {
    ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::PamResponse(response)),
    }
}

fn envelope_admin_response(response: ipc::AdminResponse) -> ipc::IpcEnvelope {
    ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::AdminResponse(response)),
    }
}

async fn read_framed(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > (10 * 1024 * 1024) {
        // 10 MiB sanity limit
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large").into());
    }

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

// ── Auth-flight registry tests ──

#[cfg(test)]
mod auth_flight_tests {
    use super::*;

    /// Backdates the flight for `username` by `age` (test helper; the registry
    /// records `Instant::now()` at start).
    async fn backdate_flight(registry: &AuthFlightRegistry, username: &str, age: Duration) {
        if let Some(flight) = registry.lock().await.get_mut(username) {
            flight.started = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        }
    }

    #[tokio::test]
    async fn pam_pam_duplicate_within_window() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "user", FlightChannel::Pam).await;
        backdate_flight(&registry, "user", Duration::from_millis(500)).await;
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
    }

    #[tokio::test]
    async fn pam_pam_allowed_after_window() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "user", FlightChannel::Pam).await;
        backdate_flight(&registry, "user", Duration::from_secs(2)).await;
        // Past the 1s window: PAM may broadcast again (no completion cooldown).
        assert!(!auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
    }

    #[tokio::test]
    async fn pam_defers_to_fprintd_regardless_of_age() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "user", FlightChannel::Fprintd).await;
        backdate_flight(&registry, "user", Duration::from_secs(60)).await;
        // A fprintd flight is always a duplicate for PAM, any age.
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
    }

    #[tokio::test]
    async fn fprintd_defers_to_any_flight_regardless_of_age() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        // fprintd during a fresh PAM flight: duplicate.
        auth_flight_start(&registry, "user", FlightChannel::Pam).await;
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Fprintd).await);
        // fprintd during an aged-out PAM flight: still a duplicate (only the
        // PAM-during-PAM pair honours the dedup window).
        backdate_flight(&registry, "user", Duration::from_secs(60)).await;
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Fprintd).await);
        // fprintd during a fprintd flight: duplicate.
        auth_flight_start(&registry, "user", FlightChannel::Fprintd).await;
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Fprintd).await);
    }

    #[tokio::test]
    async fn stale_in_flight_purged() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "user", FlightChannel::Pam).await;
        backdate_flight(&registry, "user", Duration::from_secs(400)).await;
        assert!(!auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
    }

    #[tokio::test]
    async fn different_users_independent() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "u1", FlightChannel::Pam).await;
        assert!(!auth_flight_is_duplicate(&registry, "u2", FlightChannel::Pam).await);
        assert!(!auth_flight_is_duplicate(&registry, "u2", FlightChannel::Fprintd).await);
    }

    #[tokio::test]
    async fn finish_frees_the_flight_slot() {
        let registry: AuthFlightRegistry = Arc::new(Mutex::new(HashMap::new()));
        auth_flight_start(&registry, "user", FlightChannel::Pam).await;
        assert!(auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
        auth_flight_finish(&registry, "user").await;
        // A request after the flight finished broadcasts fresh, any channel.
        assert!(!auth_flight_is_duplicate(&registry, "user", FlightChannel::Pam).await);
        assert!(!auth_flight_is_duplicate(&registry, "user", FlightChannel::Fprintd).await);
    }
}
