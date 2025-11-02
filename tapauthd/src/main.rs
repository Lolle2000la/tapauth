mod auth_handler;
mod transport;

use auth_handler::{AuthSession, DaemonState};
use bytes::{BufMut, BytesMut};
use nix::unistd::{setgid, setuid, Gid, Uid, User};
use prost::Message;
use shared::ipc::pb as ipc;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
// use tokio::sync::Mutex; // no longer needed without session tracking
use tracing_subscriber::EnvFilter;

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
use tokio::sync::{oneshot, Mutex};

/// Server shared state (daemon runtime + cancel registry)
struct ServerState {
    daemon: Arc<DaemonState>,
    cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tracing::info!("tapauthd starting...");

    // Load configuration to get UDP port
    let config_manager = shared::config::ClientConfigManager::new();
    let config = config_manager.load_config().map_err(|e| {
        tracing::error!("Failed to load configuration: {}", e);
        std::io::Error::other(e.to_string())
    })?;

    // Create global UDP socket for the daemon's lifetime
    let udp_socket = shared::network::create_broadcast_socket(config.udp_port).await?;
    tracing::info!("Created global UDP socket on port {}", config.udp_port);

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

                use std::path::Path;
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
                    use std::os::unix::fs::PermissionsExt;
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
    drop_privileges_to_tapauthd()?;
    tracing::info!("Dropped privileges to tapauthd user");

    let server_state = Arc::new(ServerState {
        daemon: daemon_state.clone(),
        cancel_registry: Arc::new(Mutex::new(HashMap::new())),
    });

    let server = {
        let server_state = server_state.clone();
        async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        tracing::debug!("Accepted connection: {:?}", addr);
                        let server_state = server_state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, server_state).await {
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
    use std::env;

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

fn drop_privileges_to_tapauthd() -> Result<(), String> {
    // Look up tapauthd user
    let target_user = User::from_name("tapauthd")
        .map_err(|e| format!("Failed to query user database: {}", e))?
        .ok_or_else(|| "User 'tapauthd' not found".to_string())?;

    let target_uid = Uid::from_raw(target_user.uid.as_raw());
    let target_gid = Gid::from_raw(target_user.gid.as_raw());

    // Check if already running as target user
    let current_euid = nix::unistd::geteuid();
    if current_euid == target_uid {
        return Ok(());
    }

    // Drop group first, then user
    setgid(target_gid).map_err(|e| format!("setgid failed: {}", e))?;
    setuid(target_uid).map_err(|e| format!("setuid failed: {}", e))?;

    Ok(())
}

async fn handle_conn(
    mut stream: UnixStream,
    server_state: Arc<ServerState>,
) -> Result<(), DaemonError> {
    // Read a length-prefixed request (u32 BE) then message with 3-second timeout
    // to prevent malicious clients from holding connections without sending data
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

    // Try to parse as PamAuthenticateRequest first
    let auth_req = ipc::PamAuthenticateRequest::decode(&mut &req_bytes[..]);

    let response = match auth_req {
        Ok(req) => {
            tracing::info!("Handling PamAuthenticateRequest for user: {}", req.username);

            // Run authentication
            let timeout = Some(req.timeout_seconds);
            let sess = AuthSession::new(server_state.daemon.clone(), req.username.clone());
            let result = sess
                .handle_authenticate(
                    timeout,
                    Some(req.request_id.clone()),
                    server_state.cancel_registry.clone(),
                )
                .await;

            match result {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("Authentication handler error: {}", e);
                    ipc::PamAuthenticateResponse {
                        outcome: ipc::PamOutcome::Error as i32,
                        detail: format!("Internal error: {}", e),
                        challenge: Vec::new(), // Error case, no challenge
                    }
                }
            }
        }
        Err(_) => {
            // Try PamCancelRequest
            let cancel_req = ipc::PamCancelRequest::decode(&mut &req_bytes[..]);
            if let Ok(req) = cancel_req {
                tracing::info!(
                    "Handling PamCancelRequest (id={}): {}",
                    req.request_id,
                    req.reason
                );
                // Look up in-flight session by request_id and notify cancel
                let mut reg = server_state.cancel_registry.lock().await;
                if let Some(tx) = reg.remove(&req.request_id) {
                    let _ = tx.send(());
                    ipc::PamAuthenticateResponse {
                        outcome: ipc::PamOutcome::Ignore as i32,
                        detail: "Cancel forwarded".to_string(),
                        challenge: Vec::new(), // Cancel doesn't need challenge
                    }
                } else {
                    ipc::PamAuthenticateResponse {
                        outcome: ipc::PamOutcome::Ignore as i32,
                        detail: "No matching request to cancel".to_string(),
                        challenge: Vec::new(),
                    }
                }
            } else {
                tracing::warn!("Unknown IPC message type");
                ipc::PamAuthenticateResponse {
                    outcome: ipc::PamOutcome::Error as i32,
                    detail: "Unknown IPC message".to_string(),
                    challenge: Vec::new(),
                }
            }
        }
    };

    // Frame and write response
    if let Err(e) = write_framed(&mut stream, &response).await {
        // Gracefully ignore common disconnect races
        if let DaemonError::Io(ref ioe) = e {
            use std::io::ErrorKind::*;
            match ioe.kind() {
                BrokenPipe | ConnectionReset | UnexpectedEof => {
                    tracing::debug!("Client disconnected before response could be sent: {}", ioe);
                    return Ok(());
                }
                _ => {}
            }
        }
        tracing::warn!("Connection error: {}", e);
        return Err(e);
    }
    Ok(())
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

async fn read_framed(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonError> {
    use tokio::io::AsyncReadExt;

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
