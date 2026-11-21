#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod admin_handler;
mod auth_handler;
mod caller_context;
mod ipc_server;
mod logging;
mod pairing;
mod peer_identity;
mod transport;

use auth_handler::DaemonState;
use nix::unistd::{setgid, setuid, Gid, Uid, User};
use std::env;
use std::io;
use std::sync::Arc;
use tokio::net::UnixListener;
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
    #[error("prost: {0}")]
    Prost(#[from] prost::DecodeError),
    #[error("auth handler: {0}")]
    AuthHandler(#[from] auth_handler::AuthHandlerError),
}

use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (listener, server_state, using_systemd_socket) = bootstrap().await?;
    // The flag is only consulted by the fallback-socket shutdown path.
    #[cfg(not(feature = "fallback-socket"))]
    let _ = using_systemd_socket;

    tokio::select! {
        _ = ipc_server::serve(listener, server_state) => {}
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

/// Everything the daemon does before it starts accepting IPC connections, in
/// the order it must happen: load config and keys, adopt (or bind) the socket,
/// then drop privileges, then build the shared state.
///
/// The privilege drop must stay between the socket setup and the accept loop:
/// the listener is created while still privileged, and no connection may be
/// served before the process has become `tapauthd:tapauthd`.
async fn bootstrap(
) -> Result<(UnixListener, Arc<ipc_server::ServerState>, bool), Box<dyn std::error::Error>> {
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
    let udp_socket = shared::network::create_multicast_socket(udp_port).await?;
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

    let server_state = Arc::new(ipc_server::ServerState {
        daemon: RwLock::new(daemon_state.clone()),
        cancel_registry: Arc::new(Mutex::new(HashMap::new())),
        recent_requests: Arc::new(Mutex::new(HashMap::new())),
        pending_pairing: Arc::new(Mutex::new(None)),
    });

    Ok((listener, server_state, using_systemd_socket))
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
