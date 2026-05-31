#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod admin_handler;
mod auth_handler;
mod logging;
mod peer_identity;
mod transport;

use admin_handler::PairingState;
use auth_handler::{AuthSession, DaemonState};
use bytes::{BufMut, BytesMut};

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

const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd.sock";

#[derive(thiserror::Error, Debug)]
pub enum DaemonError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("prost: {0}")]
    Prost(#[from] prost::DecodeError),
    #[error("auth handler: {0}")]
    AuthHandler(#[from] auth_handler::AuthHandlerError),
}

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex, RwLock};

/// Tracks recent authentication requests to prevent duplicates
#[derive(Clone)]
struct RecentAuthRequest {
    timestamp: Instant,
}

/// Server shared state (daemon runtime + cancel registry + deduplication + pairing)
struct ServerState {
    daemon: RwLock<Arc<DaemonState>>,
    cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    recent_requests: Arc<Mutex<HashMap<String, RecentAuthRequest>>>,
    pending_pairing: Arc<Mutex<Option<PairingState>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_logging();

    tracing::info!("tapauthd starting...");

    // Load TOML configuration to get UDP port
    let toml_config = shared::config::TapAuthConfig::load();
    let udp_port = toml_config.udp_port;

    // Create global UDP socket for the daemon's lifetime
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

    let server_state = Arc::new(ServerState {
        daemon: RwLock::new(daemon_state.clone()),
        cancel_registry: Arc::new(Mutex::new(HashMap::new())),
        recent_requests: Arc::new(Mutex::new(HashMap::new())),
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

    // Cleanup socket on exit only if we created it ourselves
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
                let response = handle_pam_authenticate(auth_req, &daemon, &server_state).await;
                return write_response(&mut stream, &envelope_pam_response(response), "PAM").await;
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
) -> ipc::PamAuthenticateResponse {
    const DEDUP_WINDOW: Duration = Duration::from_secs(1);
    let now = Instant::now();
    let mut recent_requests = server_state.recent_requests.lock().await;

    recent_requests.retain(|_, entry| now.duration_since(entry.timestamp) < Duration::from_secs(2));

    let is_duplicate = recent_requests
        .get(&req.username)
        .map(|r| now.duration_since(r.timestamp) < DEDUP_WINDOW)
        .unwrap_or(false);

    if is_duplicate {
        let elapsed_ms = recent_requests
            .get(&req.username)
            .map(|r| now.duration_since(r.timestamp).as_millis())
            .unwrap_or(0);
        tracing::warn!(
            "Duplicate authentication request for user '{}' within {}ms - ignoring",
            req.username,
            elapsed_ms
        );
        return ipc::PamAuthenticateResponse {
            outcome: ipc::PamOutcome::Ignore as i32,
            detail: "Duplicate request - another authentication is in progress".to_string(),
            challenge: Vec::new(),
        };
    }

    recent_requests.insert(req.username.clone(), RecentAuthRequest { timestamp: now });
    drop(recent_requests);

    let timeout = Some(req.timeout_seconds);
    match AuthSession::new(daemon.clone(), req.username.clone()) {
        Ok(sess) => match sess
            .handle_authenticate(
                timeout,
                Some(req.request_id.clone()),
                server_state.cancel_registry.clone(),
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Authentication handler error: {}", e);
                ipc::PamAuthenticateResponse {
                    outcome: ipc::PamOutcome::Error as i32,
                    detail: format!("Internal error: {}", e),
                    challenge: Vec::new(),
                }
            }
        },
        Err(e) => {
            tracing::error!("Failed to create auth session: {}", e);
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
