use bytes::BytesMut;
use prost::Message;
use shared::ipc::framing;
use shared::ipc::pb as ipc;
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const DEFAULT_SOCKET: &str = "/run/tapauthd/tapauthd.sock";

/// Read timeout for `CompletePairing`, the admin request that waits on a
/// pairing worker.
///
/// It must outlive the daemon's own bound: the worker answers a pending
/// pairing at most `SESSION_REPLY_TIMEOUT` (135 s — `SESSION_DEADLINE`, 120 s,
/// plus 5 s of slack) after `StartPairing`, see `tapauthd/src/pairing.rs`. A
/// client read timeout at or below `SESSION_DEADLINE` therefore races the
/// daemon into a spurious `ResponseTimeout` for a slow-but-legitimate pairing.
/// `wait_for_pairing` keeps its own, longer 300 s read timeout.
///
/// The invariant is **not** compiler-enforced — the GUI cannot depend on
/// `tapauthd` — so recheck `SESSION_DEADLINE`/`SESSION_REPLY_TIMEOUT` whenever
/// this value changes.
const PAIRING_REPLY_READ_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(thiserror::Error, Debug, Clone)]
pub enum GuiIpcError {
    #[error("timed out connecting to daemon socket")]
    ConnectionTimeout,
    #[error("failed to connect to daemon: {0}")]
    ConnectionFailed(String),
    #[error("timed out sending request")]
    SendTimeout,
    #[error("failed to send request: {0}")]
    SendFailed(String),
    #[error("timed out waiting for response")]
    ResponseTimeout,
    #[error("failed to read response: {0}")]
    ReadFailed(String),
    #[error("failed to decode response: {0}")]
    DecodeFailed(String),
    #[error("daemon returned unexpected envelope type")]
    UnexpectedEnvelope,
    #[error("{0}")]
    DaemonError(String),
    #[error("unexpected response type")]
    UnexpectedResponse,
}

impl GuiIpcError {
    pub fn localized(&self, l10n: &crate::l10n::L10n) -> String {
        match self {
            GuiIpcError::ConnectionTimeout => l10n.tr("error-ipc-connection-timeout"),
            GuiIpcError::ConnectionFailed(detail) => {
                l10n.tr_args("error-ipc-connection-failed", &[("detail", detail)])
            }
            GuiIpcError::SendTimeout => l10n.tr("error-ipc-send-timeout"),
            GuiIpcError::SendFailed(detail) => {
                l10n.tr_args("error-ipc-send-failed", &[("detail", detail)])
            }
            GuiIpcError::ResponseTimeout => l10n.tr("error-ipc-response-timeout"),
            GuiIpcError::ReadFailed(detail) => {
                l10n.tr_args("error-ipc-read-failed", &[("detail", detail)])
            }
            GuiIpcError::DecodeFailed(detail) => {
                l10n.tr_args("error-ipc-decode-failed", &[("detail", detail)])
            }
            GuiIpcError::UnexpectedEnvelope => l10n.tr("error-ipc-unexpected-envelope"),
            GuiIpcError::DaemonError(detail) => detail.clone(),
            GuiIpcError::UnexpectedResponse => l10n.tr("error-ipc-unexpected-response"),
        }
    }
}

fn socket_path() -> String {
    #[cfg(feature = "dev-socket-override")]
    {
        if let Ok(p) = std::env::var("TAPAUTHD_SOCK") {
            return p;
        }
    }
    DEFAULT_SOCKET.to_string()
}

pub async fn daemon_socket() -> io::Result<UnixStream> {
    let path = socket_path();
    UnixStream::connect(Path::new(&path)).await
}

async fn write_framed(stream: &mut UnixStream, msg: &[u8]) -> io::Result<()> {
    let prefix = framing::encode_len(msg.len())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut buf = BytesMut::with_capacity(4 + msg.len());
    buf.extend_from_slice(&prefix);
    buf.extend_from_slice(msg);
    stream.write_all(&buf).await
}

async fn read_framed(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = framing::decode_len(len_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

fn err_msg(resp: &ipc::AdminResponse) -> String {
    if resp.error_message.is_empty() {
        "Unknown error".to_string()
    } else {
        resp.error_message.clone()
    }
}

pub async fn send_admin_request(
    request: ipc::AdminRequest,
) -> Result<ipc::AdminResponse, GuiIpcError> {
    send_admin_request_with_read_timeout(request, Duration::from_secs(120)).await
}

async fn send_admin_request_with_read_timeout(
    request: ipc::AdminRequest,
    read_timeout: Duration,
) -> Result<ipc::AdminResponse, GuiIpcError> {
    let envelope = ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::AdminRequest(request)),
    };

    let mut stream = timeout(Duration::from_secs(10), daemon_socket())
        .await
        .map_err(|_| GuiIpcError::ConnectionTimeout)?
        .map_err(|e| GuiIpcError::ConnectionFailed(format!("{}", e)))?;

    let req_bytes = envelope.encode_to_vec();
    timeout(
        Duration::from_secs(5),
        write_framed(&mut stream, &req_bytes),
    )
    .await
    .map_err(|_| GuiIpcError::SendTimeout)?
    .map_err(|e| GuiIpcError::SendFailed(format!("{}", e)))?;

    let result = timeout(read_timeout, read_framed(&mut stream))
        .await
        .map_err(|_| GuiIpcError::ResponseTimeout)?
        .map_err(|e| GuiIpcError::ReadFailed(format!("{}", e)))?;

    let envelope = ipc::IpcEnvelope::decode(&mut &result[..])
        .map_err(|e| GuiIpcError::DecodeFailed(format!("{}", e)))?;
    match envelope.msg {
        Some(ipc::ipc_envelope::Msg::AdminResponse(resp)) => Ok(resp),
        _ => Err(GuiIpcError::UnexpectedEnvelope),
    }
}

pub async fn get_paired_servers() -> Result<Vec<ipc::PairedServerInfo>, GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::GetServers(
            ipc::GetServersRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::GetServers(resp)) => Ok(resp.servers),
        _ => Err(GuiIpcError::UnexpectedResponse),
    }
}

/// A pairing session opened by `StartPairing`.
///
/// `session_id` together with `port` identifies the session to the daemon, so
/// an abandoned pairing attempt can be cancelled instead of holding its UDP
/// socket and BLE advertisement until the daemon's own timeout.
#[derive(Debug, Clone)]
pub struct PairingSession {
    /// The v2 `tapauth://pair?...` URL to render as a QR code.
    pub url: String,
    /// Ephemeral UDP pairing port the daemon listens on.
    pub port: u16,
    /// The 16-byte session identifier carried by the QR URL's `sid`.
    pub session_id: Vec<u8>,
}

pub async fn start_pairing() -> Result<PairingSession, GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::StartPairing(
            ipc::StartPairingRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::StartPairing(resp)) => Ok(PairingSession {
            url: resp.url,
            port: resp.port as u16,
            session_id: resp.session_id,
        }),
        _ => Err(GuiIpcError::UnexpectedResponse),
    }
}

/// Build the admin request that abandons the pairing session identified by
/// `port` and `session_id` (see `proto/ipc.proto`'s `CancelPairingRequest`).
fn cancel_pairing_request(port: u16, session_id: &[u8]) -> ipc::AdminRequest {
    ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::CancelPairing(
            ipc::CancelPairingRequest {
                port: port as u32,
                session_id: session_id.to_vec(),
            },
        )),
    }
}

pub async fn cancel_pairing(port: u16, session_id: Vec<u8>) -> Result<(), GuiIpcError> {
    let response = send_admin_request(cancel_pairing_request(port, &session_id)).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    Ok(())
}

pub async fn wait_for_pairing(port: u32) -> Result<(String, u16), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::WaitForPairing(
            ipc::WaitForPairingRequest { port },
        )),
    };

    let response = send_admin_request_with_read_timeout(request, Duration::from_secs(300)).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::WaitForPairing(resp)) => {
            Ok((resp.sas_code, resp.port as u16))
        }
        _ => Err(GuiIpcError::UnexpectedResponse),
    }
}

pub async fn complete_pairing(port: u32) -> Result<String, GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::CompletePairing(
            ipc::CompletePairingRequest { port },
        )),
    };

    let response =
        send_admin_request_with_read_timeout(request, PAIRING_REPLY_READ_TIMEOUT).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::CompletePairing(resp)) => Ok(resp.server_hex),
        _ => Err(GuiIpcError::UnexpectedResponse),
    }
}

pub async fn remove_device(public_key: String) -> Result<(), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RemoveDevice(
            ipc::RemoveDeviceRequest { public_key },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    Ok(())
}

pub async fn rotate_csk() -> Result<(), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RotateCsk(
            ipc::RotateCskRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    Ok(())
}

pub async fn save_config(
    client_hostname: String,
    udp_port: u16,
    enable_ble: bool,
    enable_network: bool,
) -> Result<(), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::SaveConfig(
            ipc::SaveConfigRequest {
                hostname: client_hostname,
                udp_port: udp_port as u32,
                enable_ble: Some(enable_ble),
                enable_network: Some(enable_network),
            },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn recover_tpm() -> Result<(), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RecoverTpm(
            ipc::RecoverTpmRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    Ok(())
}

#[cfg(feature = "tpm")]
pub async fn get_daemon_status() -> Result<(bool, String), GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::GetDaemonStatus(
            ipc::GetDaemonStatusRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    let status = response
        .payload
        .and_then(|p| match p {
            ipc::admin_response::Payload::GetDaemonStatus(s) => Some(s),
            _ => None,
        })
        .ok_or(GuiIpcError::UnexpectedResponse)?;

    Ok((status.tpm_enabled, status.tpm_error))
}

/// Client configuration values exchanged with the daemon via admin IPC.
#[derive(Debug, Clone)]
pub struct ClientConfigValues {
    pub hostname: String,
    pub udp_port: u16,
    /// Whether the BLE transport may be used for authentication
    pub enable_ble: bool,
    /// Whether the Local Network (UDP) transport may be used for authentication
    pub enable_network: bool,
}

pub async fn get_config() -> Result<ClientConfigValues, GuiIpcError> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::GetConfig(
            ipc::GetConfigRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(GuiIpcError::DaemonError(err_msg(&response)));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::GetConfig(resp)) => Ok(ClientConfigValues {
            hostname: resp.hostname,
            udp_port: resp.udp_port as u16,
            enable_ble: resp.enable_ble,
            enable_network: resp.enable_network,
        }),
        _ => Err(GuiIpcError::UnexpectedResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's own source, compiled into this test binary: the GUI cannot
    /// depend on `tapauthd`, but the timeout it must outlive lives there, and
    /// parsing the real file is what keeps the two from drifting apart.
    const DAEMON_PAIRING_SRC: &str = include_str!("../../tapauthd/src/pairing.rs");

    /// The seconds of `tapauthd/src/pairing.rs`'s `const <name>: Duration =
    /// Duration::from_secs(<n>)`.
    ///
    /// Deliberately literal: the point is to notice a change to the daemon's
    /// bound, so a rewrite this cannot read must fail loudly rather than skip.
    fn daemon_duration_secs(name: &str) -> u64 {
        let marker = format!("const {name}: Duration = Duration::from_secs(");
        let start = DAEMON_PAIRING_SRC.find(&marker).unwrap_or_else(|| {
            panic!(
                "`{name}` is not declared as `const {name}: Duration = \
                 Duration::from_secs(<n>)` in tapauthd/src/pairing.rs any more; \
                 re-read that file and update this test"
            )
        }) + marker.len();
        let rest = &DAEMON_PAIRING_SRC[start..];
        let end = rest.find(')').unwrap_or_else(|| {
            panic!("`{name}` in tapauthd/src/pairing.rs has no closing parenthesis")
        });
        rest[..end].trim().parse().unwrap_or_else(|_| {
            panic!("`{name}` in tapauthd/src/pairing.rs is not a plain number of seconds")
        })
    }

    #[test]
    fn complete_pairing_read_timeout_outlives_the_daemon_deadline() {
        let deadline = Duration::from_secs(daemon_duration_secs("SESSION_DEADLINE"));
        let reply = Duration::from_secs(daemon_duration_secs("SESSION_REPLY_TIMEOUT"));

        // What this is really guarding: the daemon answers `CompletePairing` at
        // or before its reply bound, so the client must wait longer than that.
        assert!(
            PAIRING_REPLY_READ_TIMEOUT > reply,
            "CompletePairing would time out at {PAIRING_REPLY_READ_TIMEOUT:?}, before the \
             daemon's {reply:?} reply bound"
        );
        assert!(
            PAIRING_REPLY_READ_TIMEOUT >= deadline + Duration::from_secs(5),
            "CompletePairing would time out at {PAIRING_REPLY_READ_TIMEOUT:?}, within the \
             daemon's {deadline:?} session deadline plus its slack"
        );
        assert_eq!(PAIRING_REPLY_READ_TIMEOUT, Duration::from_secs(150));
    }

    #[test]
    fn cancel_pairing_request_carries_the_port_and_session_id() {
        let session_id: Vec<u8> = (0u8..16).collect();

        match cancel_pairing_request(41234, &session_id).payload {
            Some(ipc::admin_request::Payload::CancelPairing(request)) => {
                assert_eq!(request.port, 41234);
                assert_eq!(request.session_id, session_id);
            }
            other => panic!("expected a CancelPairing payload, got {other:?}"),
        }
    }
}
