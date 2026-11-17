//! The `AdminResponse` builders: one per IPC reply shape.
//!
//! Every arm of the admin dispatch answers with one of these, so the wire shape of a
//! reply is decided here rather than at each handler's return.

use shared::ipc::pb as ipc;

pub(super) fn err_resp(status: ipc::AdminStatus, msg: impl Into<String>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: status as i32,
        error_message: msg.into(),
        payload: None,
    }
}

pub(super) fn empty_success() -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: None,
    }
}

pub(super) fn get_servers_success(servers: Vec<ipc::PairedServerInfo>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::GetServers(
            ipc::GetServersResponse { servers },
        )),
    }
}

pub(super) fn start_pairing_success(
    url: String,
    port: Option<u32>,
    session_id: Vec<u8>,
) -> ipc::AdminResponse {
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

/// `port` is `None` for a session with no UDP socket (BLE-only): the reply leaves
/// the field unset rather than sending the `0` sentinel this wire used to carry.
pub(super) fn wait_pairing_success(sas_code: String, port: Option<u32>) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::WaitForPairing(
            ipc::WaitForPairingResponse { sas_code, port },
        )),
    }
}

pub(super) fn complete_pairing_success(server_hex: String) -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::CompletePairing(
            ipc::CompletePairingResponse { server_hex },
        )),
    }
}

pub(super) fn cancel_pairing_success() -> ipc::AdminResponse {
    ipc::AdminResponse {
        status: ipc::AdminStatus::AdminSuccess as i32,
        error_message: String::new(),
        payload: Some(ipc::admin_response::Payload::CancelPairing(
            ipc::CancelPairingResponse {},
        )),
    }
}

pub(super) fn get_config_success(
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

pub(super) fn daemon_status_success(tpm_enabled: bool, tpm_error: String) -> ipc::AdminResponse {
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
