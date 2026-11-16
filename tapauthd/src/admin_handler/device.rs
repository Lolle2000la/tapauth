//! Device and configuration verbs: the paired-server list, its mutations, the TOML
//! and client config the GUI edits, and the daemon's own status.

use crate::auth_handler::DaemonState;
use shared::{config::ClientConfig, ipc::pb as ipc};
use std::sync::Arc;

use super::response::{
    daemon_status_success, empty_success, err_resp, get_config_success, get_servers_success,
};

/// Loads paired servers directly from disk (not the in-memory snapshot).
/// This ensures `GetServers` always returns fresh data, even between daemon
/// reloads. Auth requests use the in-memory snapshot (DaemonState.paired_servers)
/// which may be slightly stale — the snapshots are refreshed on each reconnect.
pub(super) async fn handle_get_servers(
    daemon: &Arc<DaemonState>,
    username: &str,
) -> ipc::AdminResponse {
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

pub(super) async fn handle_remove_device(
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

pub(super) async fn handle_rotate_csk(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    // `rotate_csk` clears every paired server, deletes the CSK algorithm metadata
    // (nothing is left that the negotiated suite could be pinned to) and writes a
    // fresh CSK (`ClientConfigManager::rotate_csk`).
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
pub(super) async fn handle_save_config(
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

pub(super) async fn handle_recover_tpm(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
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

pub(super) async fn handle_get_config(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
    let client_config = daemon.config_manager.load_config().unwrap_or_default();
    let toml_config = shared::config::TapAuthConfig::load();
    get_config_success(
        client_config.hostname,
        toml_config.udp_port as u32,
        toml_config.enable_ble,
        toml_config.enable_network,
    )
}

pub(super) async fn handle_get_daemon_status(daemon: &Arc<DaemonState>) -> ipc::AdminResponse {
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
