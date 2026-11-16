//! The pairing verbs: start, wait, complete and cancel one session, and the local
//! record a completed one leaves behind.
//!
//! The session itself lives in `crate::pairing`; this module only drives it from the
//! IPC surface.

use crate::auth_handler::DaemonState;
use crate::pairing::{CompletedPairing, PairingState, SessionPhase};
use crate::transport::EnabledTransports;
use shared::{
    config::{CskMetadata, PairedServer},
    crypto::keys::ClientSymmetricKey,
    ipc::pb as ipc,
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::response::{
    cancel_pairing_success, complete_pairing_success, err_resp, start_pairing_success,
    wait_pairing_success,
};

/// Start a v2 pairing session: ephemeral dual-stack UDP socket, BLE pairing
/// advertisement, and one background worker driving the handshake.
///
/// `transports` is the configuration the session may use, resolved by the caller
/// (`handle_admin_request`) from the TOML config — the same split
/// `AuthSession::handle_authenticate` uses, and what lets a test drive this
/// decision without a config file.
pub(super) async fn handle_start_pairing(
    daemon: &Arc<DaemonState>,
    pairing_state: &Arc<Mutex<Option<PairingState>>>,
    transports: EnabledTransports,
) -> ipc::AdminResponse {
    // A session with neither transport can never be reached: no UDP socket is
    // bound, so the QR code carries no endpoint and no firewall rule exists, and no
    // BLE advertisement goes out — the phone has nothing to answer, and the GUI
    // would hold a session that can only expire. Refused here, before anything is
    // keyed, bound or spawned. `enable_ble` alone does not make BLE available: a
    // daemon built without the `ble` feature has no advertisement to start, which is
    // why `EnabledTransports` gates it on the feature too.
    if let Some(reason) = transports.refusal() {
        tracing::info!("Refusing StartPairing: {}", reason);
        return err_resp(ipc::AdminStatus::AdminError, reason);
    }

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

    // The config decided which transports this session may use (`transports`); with
    // the network transport disabled there is no UDP pairing socket, no firewall
    // rule and no reachable address in the QR code, so the phone pairs over BLE
    // only.
    //
    // Opening the pairing firewall port is best-effort only in test builds
    // (containers/user-namespaces without usable iptables). Production builds
    // abort pairing rather than leaving the ephemeral socket unreachable.
    let ports = match crate::pairing::open_transports(
        transports,
        crate::pairing::bind_pairing_socket,
        crate::pairing::open_pairing_firewall,
    )
    .await
    {
        Ok(ports) => ports,
        Err(e) => return err_resp(ipc::AdminStatus::AdminError, e.to_string()),
    };
    let (state, started) = match crate::pairing::start_session_state(
        keypair,
        &daemon.hostname,
        ports.endpoint(ipv4, ipv6),
        crate::pairing::pinned_algorithms(daemon),
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return err_resp(
                ipc::AdminStatus::AdminError,
                format!("Pairing session creation failed: {}", e),
            )
        }
    };
    let (udp, local_port, firewall_guard) = (ports.udp, ports.local_port, ports.firewall_guard);

    // Everything the IPC reply carries comes from the state machine's own
    // `StartedPairing`: the URL is the one the phone will parse, not a
    // re-generated lookalike.
    let session_id = started.session_id;
    let qr_url = started.qr_url.clone();
    let generation = crate::pairing::next_generation();
    let pairing = crate::pairing::spawn(crate::pairing::SessionSetup {
        state,
        started,
        udp,
        local_port,
        firewall_guard,
        enable_ble: transports.ble,
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
pub(super) async fn handle_wait_for_pairing(
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
        tokio::time::sleep(crate::pairing::SESSION_DEADLINE + std::time::Duration::from_secs(5));
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
pub(super) async fn handle_complete_pairing(
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
    let completed = match crate::pairing::request_completion(
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
pub(super) async fn handle_cancel_pairing(
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
    let result = crate::pairing::request_cancellation(&commands).await;
    if result.is_ok() {
        tracing::info!("Cancelled the pairing session on UDP port {}", port);
    }
    cancel_outcome(result)
}

/// What a `CancelPairing` answers for `result`.
///
/// `Ended` is a success: the worker retired between the phase check and the
/// command (its teardown had already closed the command channel), so there is
/// nothing left to abort — which is what the caller asked for. Every other error
/// keeps the failure answer.
pub(super) fn cancel_outcome(
    result: Result<(), crate::pairing::PairingError>,
) -> ipc::AdminResponse {
    match result {
        Ok(()) => cancel_pairing_success(),
        Err(crate::pairing::PairingError::Ended(_)) => {
            tracing::debug!("Cancellation raced the session teardown; nothing left to abort");
            cancel_pairing_success()
        }
        Err(e) => err_resp(
            ipc::AdminStatus::AdminError,
            format!("Failed to cancel the pairing session: {}", e),
        ),
    }
}
