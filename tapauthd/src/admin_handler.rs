use crate::auth_handler::DaemonState;
use crate::peer_identity::{check_authorization, resolve_peer};
use shared::{
    config::{ClientConfig, CskMetadata, PairedServer},
    crypto::keys::ClientSymmetricKey,
    ipc::pb as ipc,
    protocol::pairing::ServerPairingState,
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::pairing::{self, CompletedPairing, SessionPhase};

pub use crate::pairing::PairingState;

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

fn start_pairing_success(url: String, port: u32, session_id: Vec<u8>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::StartPairing(
            ipc::StartPairingResponse {
                url,
                port,
                session_id,
            },
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

fn cancel_pairing_success() -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::CancelPairing(
            ipc::CancelPairingResponse {},
        )),
    }
}

fn get_config_success(
    hostname: String,
    udp_port: u32,
    enable_ble: bool,
    enable_network: bool,
) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::GetConfig(
            ipc::GetConfigResponse {
                hostname,
                udp_port,
                enable_ble,
                enable_network,
            },
        )),
    }
}

fn daemon_status_success(tpm_enabled: bool, tpm_error: String) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::GetDaemonStatus(
            ipc::GetDaemonStatusResponse {
                tpm_enabled,
                tpm_error,
            },
        )),
    }
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
        Err(e) => return err_resp(ipc::AdminStatus::AdminError, e.to_string()),
    };

    // Daemon-side PolKit authorization: the daemon calls CheckAuthorization
    // using the peer's PID/start-time as the subject.  This is the canonical
    // enforcement point — no client can bypass it by skipping their own
    // PolKit check.  The tapauthd user must be registered as an action owner
    // via org.freedesktop.policykit.owner in the policy file.
    if let Err(e) = check_authorization(&identity).await {
        tracing::warn!(
            "Unauthorized admin request from uid={} (pid={}, user={}): {}",
            identity.uid,
            identity.pid,
            identity.username,
            e
        );
        return err_resp(ipc::AdminStatus::AdminUnauthorized, e.to_string());
    }

    let username = identity.username;

    let (response, needs_reload) = match request.payload {
        Some(ipc::admin_request::Payload::GetServers(_)) => {
            (handle_get_servers(&daemon, &username).await, false)
        }
        Some(ipc::admin_request::Payload::StartPairing(_)) => {
            (handle_start_pairing(&daemon, pairing_state).await, false)
        }
        Some(ipc::admin_request::Payload::WaitForPairing(req)) => {
            (handle_wait_for_pairing(pairing_state, req).await, false)
        }
        Some(ipc::admin_request::Payload::CompletePairing(req)) => (
            handle_complete_pairing(&daemon, pairing_state, &username, req).await,
            true,
        ),
        Some(ipc::admin_request::Payload::CancelPairing(req)) => {
            (handle_cancel_pairing(pairing_state, req).await, false)
        }
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
        Some(ipc::admin_request::Payload::GetConfig(_)) => {
            (handle_get_config(&daemon).await, false)
        }
        Some(ipc::admin_request::Payload::GetDaemonStatus(_)) => {
            (handle_get_daemon_status(&daemon).await, false)
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

/// Loads paired servers directly from disk (not the in-memory snapshot).
/// This ensures `GetServers` always returns fresh data, even between daemon
/// reloads. Auth requests use the in-memory snapshot (DaemonState.paired_servers)
/// which may be slightly stale — the snapshots are refreshed on each reconnect.
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

/// Start a v2 pairing session: ephemeral dual-stack UDP socket, BLE pairing
/// advertisement, and one background worker driving the handshake.
async fn handle_start_pairing(
    daemon: &Arc<DaemonState>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
) -> ipc::AdminResponse {
    // The Ed25519 keypair identifies this client to the server during pairing.
    // It MUST be the daemon's persistent keypair — otherwise the server stores
    // a transient public key and subsequent auth requests fail signature verification.
    let keypair = match daemon.config_manager.load_keypair() {
        Ok(kp) => kp,
        Err(shared::config::ConfigError::InvalidConfig) => {
            match daemon.config_manager.generate_and_save_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    return err_resp(
                        ipc::AdminStatus::AdminError,
                        format!("Keypair generation failed: {}", e),
                    )
                }
            }
        }
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to load keypair: {}", e),
            )
        }
    };

    let ipv4 = match local_ip_address::local_ip() {
        Ok(std::net::IpAddr::V4(ip)) if !ip.is_loopback() => Some(ip),
        _ => find_non_loopback_ipv4(),
    };

    let ipv6 = find_non_loopback_ipv6();

    // A session that already ended must not block the next attempt: the worker
    // publishes a terminal phase but only this side can retire the handle.
    {
        let mut guard = pairing_state.lock().await;
        if matches!(guard.as_ref(), Some(session) if session.is_ended()) {
            tracing::debug!("Retiring the finished pairing session before starting a new one");
            *guard = None;
        }
        if guard.is_some() {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "A pairing session is already in progress. Cancel or complete it first.",
            );
        }
    }

    let udp = match pairing::bind_pairing_socket().await {
        Ok(socket) => socket,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to bind the pairing UDP socket: {}", e),
            )
        }
    };
    let local_port = match udp.local_addr() {
        Ok(address) => address.port(),
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to read the pairing port: {}", e),
            )
        }
    };

    // Opening the pairing firewall port is best-effort only in test builds
    // (containers/user-namespaces without usable iptables). Production builds
    // abort pairing rather than leaving the ephemeral socket unreachable.
    let firewall_guard = match pairing::open_pairing_firewall(local_port) {
        Ok(guard) => guard,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Firewall error: {}", e),
            )
        }
    };

    let (state, started) = match ServerPairingState::start(
        keypair,
        &daemon.hostname,
        local_port,
        ipv4,
        ipv6,
        pairing::pinned_algorithms(daemon),
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Pairing session creation failed: {}", e),
            )
        }
    };

    // Everything the IPC reply carries comes from the state machine's own
    // `StartedPairing`: the URL is the one the phone will parse, not a
    // re-generated lookalike.
    let session_id = started.session_id;
    let qr_url = started.qr_url.clone();
    let generation = pairing::next_generation();
    let enable_ble = shared::config::TapAuthConfig::load().enable_ble;
    let pairing = pairing::spawn(pairing::SessionSetup {
        state,
        started,
        udp,
        local_port,
        firewall_guard,
        enable_ble,
        generation,
    });

    let mut guard = pairing_state.lock().await;
    if guard.is_some() {
        // Another StartPairing won the race while we were binding. Dropping the
        // handle stops this session's worker, socket and advertisement.
        return err_resp(
            ipc::AdminStatus::AdminError,
            "A pairing session is already in progress. Cancel or complete it first.",
        );
    }
    *guard = Some(pairing);
    drop(guard);

    tracing::info!(
        "Started pairing session on UDP port {} (session {})",
        local_port,
        hex::encode(session_id)
    );

    start_pairing_success(qr_url, u32::from(local_port), session_id.to_vec())
}

/// Wait for the phone's `PairingInit` and return the SAS to display.
///
/// The wait does not hold the pairing lock (a `CompletePairing` must be able to
/// run meanwhile), and it is tied to the generation it subscribed to: a wait that
/// outlives its session fails instead of answering a newer one.
async fn handle_wait_for_pairing(
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    req: ipc::WaitForPairingRequest,
) -> ipc::AdminResponse {
    let (mut phases, port, generation) = {
        let guard = pairing_state.lock().await;
        let Some(session) = guard.as_ref() else {
            return err_resp(ipc::AdminStatus::AdminError, "No pending pairing session");
        };
        if req.port != 0 && req.port != u32::from(session.port()) {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!(
                    "Port mismatch: expected {}, got {}",
                    session.port(),
                    req.port
                ),
            );
        }
        (
            session.phase_receiver(),
            session.port(),
            session.generation(),
        )
    };

    let deadline =
        tokio::time::sleep(pairing::SESSION_DEADLINE + std::time::Duration::from_secs(5));
    tokio::pin!(deadline);

    loop {
        let phase = phases.borrow().clone();
        match phase {
            SessionPhase::AwaitingSas(sas) => {
                return wait_pairing_success(sas, u32::from(port));
            }
            SessionPhase::Finished => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    "Pairing session already finished",
                )
            }
            SessionPhase::Failed(reason) => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    format!("Pairing session failed: {}", reason),
                )
            }
            SessionPhase::AwaitingPhone => {}
        }

        tokio::select! {
            changed = phases.changed() => {
                if changed.is_err() {
                    return err_resp(
                        ipc::AdminStatus::AdminError,
                        "Pairing session ended before the phone connected",
                    );
                }
            }
            _ = &mut deadline => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    "Timeout waiting for the phone to connect",
                )
            }
        }

        let still_current = {
            let guard = pairing_state.lock().await;
            guard
                .as_ref()
                .map(PairingState::generation)
                .is_some_and(|current| current == generation)
        };
        if !still_current {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "Pairing session was superseded by a newer request",
            );
        }
    }
}

fn find_non_loopback_ipv4() -> Option<std::net::Ipv4Addr> {
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in interfaces {
            if let IpAddr::V4(ipv4) = ip {
                if !ipv4.is_loopback() {
                    return Some(ipv4);
                }
            }
        }
    }
    None
}

fn find_non_loopback_ipv6() -> Option<std::net::Ipv6Addr> {
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in interfaces {
            if let IpAddr::V6(ipv6) = ip {
                if !ipv6.is_loopback() && !ipv6.is_unspecified() {
                    return Some(ipv6);
                }
            }
        }
    }
    None
}

/// Provision the CSK to the phone and record the pairing.
///
/// The worker retransmits `PairingConfirmClient` (immediately on every keepalive)
/// until the phone proves it received the CSK; only then is anything written to
/// disk, so a failed pairing never leaves a half-written state directory.
async fn handle_complete_pairing(
    daemon: &Arc<DaemonState>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    username: &str,
    req: ipc::CompletePairingRequest,
) -> ipc::AdminResponse {
    let session = {
        let guard = pairing_state.lock().await;
        let Some(current) = guard.as_ref() else {
            return err_resp(
                ipc::AdminStatus::AdminError,
                "No pairing session in progress",
            );
        };
        if req.port != 0 && req.port != u32::from(current.port()) {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!(
                    "Port mismatch: expected {}, got {}",
                    current.port(),
                    req.port
                ),
            );
        }
        match current.phase() {
            SessionPhase::AwaitingPhone => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    "Pairing still pending, wait for the phone to connect first",
                )
            }
            SessionPhase::AwaitingSas(_) => {}
            SessionPhase::Finished => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    "Pairing session already finished",
                )
            }
            SessionPhase::Failed(reason) => {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    format!("Pairing session failed: {}", reason),
                )
            }
        }
        // Only a clone of the command channel is taken out of the lock, so the
        // session stays steerable (a concurrent CancelPairing still reaches the
        // worker) while this call waits for the phone.
        current.command_sender()
    };

    let csk = match daemon.config_manager.load_csk() {
        Ok(c) => c,
        Err(shared::config::ConfigError::InvalidConfig) => {
            if daemon.config_manager.has_csk_file() {
                return err_resp(
                    ipc::AdminStatus::AdminError,
                    "CSK file is corrupt.  Use `Rotate CSK` in settings to regenerate \
                     (this will invalidate all existing pairings).",
                );
            }
            match ClientSymmetricKey::generate() {
                Ok(c) => c,
                Err(e) => {
                    return err_resp(
                        ipc::AdminStatus::AdminError,
                        format!("CSK generation failed: {}", e),
                    )
                }
            }
        }
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Failed to load CSK: {}", e),
            )
        }
    };

    let client_hostname = daemon.hostname.clone();
    let completed = match pairing::request_completion(
        &session,
        *csk.as_bytes(),
        username.to_string(),
        client_hostname,
    )
    .await
    {
        Ok(completed) => completed,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Pairing completion failed: {}", e),
            )
        }
    };

    persist_pairing(daemon, username, &csk, completed)
}

/// Write the CSK, its algorithms and the new server after a proven pairing.
fn persist_pairing(
    daemon: &Arc<DaemonState>,
    username: &str,
    csk: &ClientSymmetricKey,
    completed: CompletedPairing,
) -> ipc::AdminResponse {
    if let Err(e) = daemon.config_manager.save_csk(csk) {
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

    // The symmetric and hash algorithms belong to the CSK: every paired server
    // must be able to decrypt the one broadcast, so they are stored with it.
    let metadata = CskMetadata {
        symmetric_algorithm: completed.negotiated.symmetric_algorithm,
        hash_algorithm: completed.negotiated.hash_algorithm,
    };
    if let Err(e) = daemon.config_manager.save_csk_metadata(&metadata) {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!(
                "Paired on phone, but saving local CSK metadata failed: {}",
                e
            ),
        );
    }

    let server_hex = hex::encode(completed.server_public_key);
    let paired_server = PairedServer {
        name: completed.server_device_name,
        public_key: server_hex.clone(),
        allowed_users: vec![username.to_string()],
        paired_at: chrono::Utc::now(),
        signature_algorithm: completed.negotiated.signature_algorithm,
    };

    match daemon
        .config_manager
        .add_paired_server(server_hex.clone(), paired_server)
    {
        Ok(()) => {
            tracing::info!("Paired server {} saved for user {}", server_hex, username);
            complete_pairing_success(server_hex)
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save paired server: {}", e),
        ),
    }
}

/// Abandon a pairing session: send an authenticated `PairingAbort` and tear the
/// socket and advertisement down before answering.
async fn handle_cancel_pairing(
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    req: ipc::CancelPairingRequest,
) -> ipc::AdminResponse {
    let session = {
        let guard = pairing_state.lock().await;
        let Some(current) = guard.as_ref() else {
            // Nothing to cancel: the GUI drops its session as soon as the screen
            // is torn down, possibly after the session already ended.
            return cancel_pairing_success();
        };
        if req.port != 0 && req.port != u32::from(current.port()) {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!(
                    "Port mismatch: expected {}, got {}",
                    current.port(),
                    req.port
                ),
            );
        }
        if !req.session_id.is_empty()
            && req.session_id.as_slice() != current.session_id().as_slice()
        {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!(
                    "Session id mismatch: expected {}, got {}",
                    hex::encode(current.session_id()),
                    hex::encode(&req.session_id)
                ),
            );
        }
        if current.is_ended() {
            // The session is over and its worker has answered (or is stopping the
            // advertisement): there is nothing left to abort, and the next
            // StartPairing retires the handle.
            return cancel_pairing_success();
        }
        (current.command_sender(), current.port())
    };

    let (commands, port) = session;
    match pairing::request_cancellation(&commands).await {
        Ok(()) => {
            tracing::info!("Cancelled the pairing session on UDP port {}", port);
            cancel_pairing_success()
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to cancel the pairing session: {}", e),
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
    // `rotate_csk` clears every paired server, writes a fresh CSK and resets the
    // CSK algorithm metadata to the baseline (`ClientConfigManager::rotate_csk`).
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

/// Writes config to disk, saving TOML (port, requires restart) first
/// before ClientConfig (hostname, takes effect immediately).
/// If TOML save fails, nothing is written. If ClientConfig save fails,
/// the port change is still persisted (correct, just needs restart).
///
/// Transport toggles (BLE / Local Network) are only written when the request
/// carries them (explicit presence), so older clients cannot accidentally
/// disable transports.
async fn handle_save_config(
    daemon: &Arc<DaemonState>,
    req: ipc::SaveConfigRequest,
) -> ipc::AdminResponse {
    if req.udp_port == 0 || req.udp_port > 65535 {
        return err_resp(
            ipc::AdminStatus::AdminError,
            "Invalid UDP port: must be 1-65535",
        );
    }
    let hostname = req.hostname.trim().to_string();
    if hostname.is_empty() {
        return err_resp(ipc::AdminStatus::AdminError, "Hostname must not be empty");
    }
    let port = req.udp_port as u16;

    let mut toml_config = shared::config::TapAuthConfig::load();
    toml_config.udp_port = port;
    if let Some(enable_ble) = req.enable_ble {
        toml_config.enable_ble = enable_ble;
    }
    if let Some(enable_network) = req.enable_network {
        toml_config.enable_network = enable_network;
    }
    if let Err(e) = toml_config.save() {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save TOML config: {}", e),
        );
    }

    let client_config = ClientConfig { hostname };
    if let Err(e) = daemon.config_manager.save_config(&client_config) {
        return err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to save client config: {}", e),
        );
    }
    tracing::info!(
        "UDP port changed to {} — will take effect on next daemon restart",
        port
    );
    tracing::info!(
        "Transports: BLE={}, LocalNetwork={} — takes effect on next authentication attempt",
        toml_config.enable_ble,
        toml_config.enable_network
    );

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

async fn handle_get_config(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    let client_config = daemon.config_manager.load_config().unwrap_or_default();
    let toml_config = shared::config::TapAuthConfig::load();
    get_config_success(
        client_config.hostname,
        toml_config.udp_port as u32,
        toml_config.enable_ble,
        toml_config.enable_network,
    )
}

async fn handle_get_daemon_status(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    let tpm_enabled = cfg!(feature = "tpm");
    let tpm_error = if tpm_enabled && daemon.keypair.is_none() {
        daemon
            .get_init_error()
            .unwrap_or("TPM key unseal failed")
            .to_string()
    } else {
        String::new()
    };
    daemon_status_success(tpm_enabled, tpm_error)
}
