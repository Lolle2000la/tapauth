use crate::auth_handler::DaemonState;
use crate::polkitauth::{check_authorization, resolve_peer};
use shared::{
    config::{ClientConfig, PairedServer},
    firewall::{FirewallGuard, Protocol},
    ipc::pb as ipc,
    models::pairing::generate_pairing_url,
    protocol::ClientPairingSession,
};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum AdminError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(#[from] shared::config::ConfigError),
    #[error("{0}")]
    Other(String),
}

fn err_resp(status: ipc::AdminStatus, msg: impl Into<String>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: status as i32,
        error_message: msg.into(),
        payload: None,
    }
}

fn empty_success() -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: None,
    }
}

fn get_servers_success(servers: Vec<ipc::PairedServerInfo>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::GetServers(
            ipc::GetServersResponse { servers },
        )),
    }
}

fn start_pairing_success(url: String, port: u32) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::StartPairing(
            ipc::StartPairingResponse { url, port },
        )),
    }
}

fn wait_pairing_success(sas_code: String, port: u32) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::WaitForPairing(
            ipc::WaitForPairingResponse { sas_code, port },
        )),
    }
}

fn complete_pairing_success(server_hex: String) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::CompletePairing(
            ipc::CompletePairingResponse { server_hex },
        )),
    }
}

pub struct PendingPairing {
    pub listener: TcpListener,
    pub firewall_guard: FirewallGuard,
    pub session: ClientPairingSession,
    #[allow(dead_code)]
    pub url: String,
    pub port: u16,
}

pub struct ActivePairing {
    pub stream: TcpStream,
    pub session: ClientPairingSession,
    pub server_public_key: [u8; 32],
    pub server_device_name: String,
    #[allow(dead_code)]
    pub firewall_guard: FirewallGuard,
}

pub enum PairingState {
    Pending(PendingPairing),
    Active(ActivePairing),
}

pub async fn handle_admin_request(
    request: ipc::AdminRequest,
    daemon_lock: &RwLock<Arc<DaemonState>>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    caller_pid: i32,
    caller_uid: u32,
) -> ipc::AdminResponse {
    let daemon = daemon_lock.read().await.clone();
    let identity = match resolve_peer(caller_pid, caller_uid) {
        Ok(id) => id,
        Err(e) => return err_resp(ipc::AdminStatus::AdminError, e),
    };

    if let Err(e) = check_authorization(&identity).await {
        return err_resp(ipc::AdminStatus::AdminUnauthorized, e);
    }

    let username = identity.username;

    let (response, needs_reload) = match request.payload {
        Some(ipc::admin_request::Payload::GetServers(_)) => {
            (handle_get_servers(&daemon, &username).await, false)
        }
        Some(ipc::admin_request::Payload::StartPairing(_)) => {
            (handle_start_pairing(pairing_state).await, false)
        }
        Some(ipc::admin_request::Payload::WaitForPairing(req)) => {
            (handle_wait_for_pairing(pairing_state, req).await, false)
        }
        Some(ipc::admin_request::Payload::CompletePairing(_req)) => (
            handle_complete_pairing(&daemon, pairing_state, &username).await,
            true,
        ),
        Some(ipc::admin_request::Payload::RemoveDevice(req)) => {
            (handle_remove_device(&daemon, &username, req).await, true)
        }
        Some(ipc::admin_request::Payload::RotateCsk(_)) => (handle_rotate_csk(&daemon).await, true),
        Some(ipc::admin_request::Payload::SaveConfig(req)) => {
            (handle_save_config(&daemon, req).await, true)
        }
        Some(ipc::admin_request::Payload::RecoverTpm(_)) => {
            (handle_recover_tpm(&daemon).await, true)
        }
        None => (
            err_resp(ipc::AdminStatus::AdminError, "Empty admin request"),
            false,
        ),
    };

    if needs_reload {
        let new_daemon = daemon.reload();
        *daemon_lock.write().await = new_daemon;
        tracing::info!("Daemon state reloaded after admin operation");
    }

    response
}

async fn handle_get_servers(daemon: &Arc<DaemonState>, username: &str) -> ipc::AdminResponse {
    match daemon.config_manager.load_paired_servers() {
        Ok(servers) => {
            let infos: Vec<ipc::PairedServerInfo> = servers
                .into_iter()
                .filter(|(_, s)| s.is_user_allowed(username))
                .map(|(pk, s)| ipc::PairedServerInfo {
                    name: s.name,
                    public_key: pk,
                    allowed_users: s.allowed_users,
                    paired_at: s.paired_at.to_rfc3339(),
                })
                .collect();
            get_servers_success(infos)
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to load servers: {}", e),
        ),
    }
}

async fn handle_start_pairing(
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
) -> ipc::AdminResponse {
    use shared::crypto::Ed25519KeyPair;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let keypair = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Key generation failed: {}", e),
            )
        }
    };

    let ipv4_addr = match local_ip_address::local_ip() {
        Ok(std::net::IpAddr::V4(ip)) => ip,
        Ok(std::net::IpAddr::V6(_)) => Ipv4Addr::new(127, 0, 0, 1),
        Err(_) => Ipv4Addr::new(127, 0, 0, 1),
    };

    let ipv6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

    let listener = match TcpListener::bind("0.0.0.0:0").await {
        Ok(l) => l,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to bind TCP listener: {}", e),
            )
        }
    };

    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to get port: {}", e),
            )
        }
    };

    let firewall_guard = match FirewallGuard::new(port, Protocol::Tcp) {
        Ok(g) => g,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Firewall error: {}", e),
            )
        }
    };

    let session = match ClientPairingSession::new(keypair) {
        Ok(s) => s,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Session creation failed: {}", e),
            )
        }
    };

    let x25519_pubkey_hex = hex::encode(session.x25519_public_key());
    let url = generate_pairing_url(&x25519_pubkey_hex, port, Some(ipv4_addr), Some(ipv6_addr));

    let pending = PendingPairing {
        listener,
        firewall_guard,
        session,
        url: url.clone(),
        port,
    };

    *pairing_state.lock().await = Some(PairingState::Pending(pending));

    spawn_pairing_timeout(pairing_state);

    start_pairing_success(url, port as u32)
}

fn spawn_pairing_timeout(pairing_state: &Arc<Mutex<Option<PairingState>>>) {
    let state = pairing_state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        let mut guard = state.lock().await;
        if matches!(*guard, Some(PairingState::Pending(_))) {
            tracing::warn!("Pending pairing timed out, cleaning up");
            *guard = None;
        }
    });
}

fn spawn_active_pairing_timeout(pairing_state: &Arc<Mutex<Option<PairingState>>>) {
    let state = pairing_state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        let mut guard = state.lock().await;
        if matches!(*guard, Some(PairingState::Active(_))) {
            tracing::warn!("Active pairing (SAS verification) timed out, cleaning up");
            *guard = None;
        }
    });
}

async fn handle_wait_for_pairing(
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    req: ipc::WaitForPairingRequest,
) -> ipc::AdminResponse {
    let mut guard = pairing_state.lock().await;

    let pending = match guard.take() {
        Some(PairingState::Pending(p)) => p,
        Some(PairingState::Active(_)) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "Pairing already in active phase",
            )
        }
        None => return err_resp(ipc::AdminStatus::AdminError, "No pending pairing session"),
    };

    if req.port != 0 && req.port != pending.port as u32 {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!("Port mismatch: expected {}, got {}", pending.port, req.port),
        );
    }

    drop(guard);

    let accept_result = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        pending.listener.accept(),
    )
    .await;

    let (stream, _addr) = match accept_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return err_resp(ipc::AdminStatus::AdminError, format!("Accept error: {}", e))
        }
        Err(_) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "Timeout waiting for connection",
            )
        }
    };

    let client_device_name = daemon_hostname();

    let mut session = pending.session;

    match session.initiate_pairing(stream, &client_device_name).await {
        Ok((stream, server_public_key, server_device_name, sas)) => {
            let sas_display = shared::crypto::format_sas(&sas);

            let active = ActivePairing {
                stream,
                session,
                server_public_key,
                server_device_name,
                firewall_guard: pending.firewall_guard,
            };

            *pairing_state.lock().await = Some(PairingState::Active(active));

            spawn_active_pairing_timeout(pairing_state);

            wait_pairing_success(sas_display, pending.port as u32)
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Pairing initiation failed: {}", e),
        ),
    }
}

fn daemon_hostname() -> String {
    whoami::hostname().unwrap_or_else(|_| "Unknown".to_string())
}

async fn handle_complete_pairing(
    daemon: &Arc<DaemonState>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    username: &str,
) -> ipc::AdminResponse {
    let mut guard = pairing_state.lock().await;

    let active = match guard.take() {
        Some(PairingState::Active(a)) => a,
        Some(PairingState::Pending(_)) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "Pairing still pending, wait for connection first",
            )
        }
        None => return err_resp(ipc::AdminStatus::AdminError, "No active pairing session"),
    };

    drop(guard);

    let csk = match daemon.config_manager.load_csk() {
        Ok(c) => c,
        Err(_) => match daemon.config_manager.generate_and_save_csk() {
            Ok(c) => c,
            Err(e) => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    format!(
                        "CSK generation failed: {}. Ensure tapauthd is installed and the \
                         'tapauthd' user and group exist, then retry pairing.",
                        e
                    ),
                )
            }
        },
    };

    let mut session = active.session;

    match session.finish_pairing(active.stream, &csk, username).await {
        Ok(()) => {}
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Pairing completion failed: {}", e),
            )
        }
    }

    if let Err(e) = daemon.config_manager.save_csk(&csk) {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!(
                "Paired on phone, but saving local key failed: {}. \
                 Ensure tapauthd is installed and the 'tapauthd' user and group exist, \
                 then retry pairing.",
                e
            ),
        );
    }

    let server_hex = hex::encode(active.server_public_key);
    let paired_server = PairedServer {
        name: active.server_device_name,
        public_key: server_hex.clone(),
        paired_at: chrono::Utc::now(),
        allowed_users: vec![username.to_string()],
    };

    match daemon
        .config_manager
        .add_paired_server(server_hex.clone(), paired_server)
    {
        Ok(()) => complete_pairing_success(server_hex),
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save paired server: {}", e),
        ),
    }
}

async fn handle_remove_device(
    daemon: &Arc<DaemonState>,
    username: &str,
    req: ipc::RemoveDeviceRequest,
) -> ipc::AdminResponse {
    match daemon
        .config_manager
        .remove_user_from_pairing(&req.public_key, username)
    {
        Ok(entire_pairing_removed) => {
            tracing::info!(
                "{} pairing for device {}",
                if entire_pairing_removed {
                    "Removed entire"
                } else {
                    "Removed user from"
                },
                req.public_key
            );
            empty_success()
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to remove device: {}", e),
        ),
    }
}

async fn handle_rotate_csk(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    match daemon.config_manager.rotate_csk() {
        Ok(_) => {
            tracing::info!("CSK rotated successfully");
            empty_success()
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to rotate CSK: {}", e),
        ),
    }
}

async fn handle_save_config(
    daemon: &Arc<DaemonState>,
    req: ipc::SaveConfigRequest,
) -> ipc::AdminResponse {
    let port = req.udp_port as u16;
    if port == 0 {
        return err_resp(
            ipc::AdminStatus::AdminError,
            "Invalid UDP port: must be 1-65535",
        );
    }

    let client_config = ClientConfig {
        hostname: req.hostname,
    };

    if let Err(e) = daemon.config_manager.save_config(&client_config) {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save client config: {}", e),
        );
    }

    let mut toml_config = shared::config::TapAuthConfig::load();
    toml_config.udp_port = port;
    if let Err(e) = toml_config.save_to_path(shared::config::DEFAULT_CONFIG_PATH) {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save TOML config: {}", e),
        );
    }

    empty_success()
}

async fn handle_recover_tpm(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    #[cfg(feature = "tpm")]
    {
        match daemon.config_manager.recover_from_tpm_failure() {
            Ok(()) => {
                tracing::info!("TPM recovery complete");
                empty_success()
            }
            Err(e) => err_resp(
                ipc::AdminStatus::AdminError,
                format!("TPM recovery failed: {}", e),
            ),
        }
    }
    #[cfg(not(feature = "tpm"))]
    {
        let _ = daemon;
        err_resp(ipc::AdminStatus::AdminError, "TPM support not compiled in")
    }
}
