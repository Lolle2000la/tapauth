//! The privileged IPC server: shared state, the accept loop and the
//! per-connection framing.
//!
//! Everything here runs after `main`'s bootstrap has adopted (or bound) the
//! socket and dropped privileges, so a connection accepted by [`serve`] is
//! already served as `tapauthd:tapauthd`.

use crate::admin_handler;
use crate::admin_handler::PairingState;
use crate::auth_handler::{AuthSession, DaemonState};
use crate::caller_context;
use crate::DaemonError;
use bytes::BytesMut;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use prost::Message;
use shared::ipc::framing;
use shared::ipc::pb as ipc;
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex, RwLock};

/// Tracks recent authentication requests to prevent duplicates
#[derive(Clone)]
pub(crate) struct RecentAuthRequest {
    timestamp: Instant,
}

/// Server shared state (daemon runtime + cancel registry + deduplication + pairing)
pub(crate) struct ServerState {
    pub(crate) daemon: RwLock<Arc<DaemonState>>,
    pub(crate) cancel_registry: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    pub(crate) recent_requests: Arc<Mutex<HashMap<String, RecentAuthRequest>>>,
    pub(crate) pending_pairing: Arc<Mutex<Option<PairingState>>>,
}

/// Accept IPC connections for the lifetime of the daemon.
///
/// Each accepted stream is handed to [`handle_conn`] on its own task, so a
/// single slow client cannot stall the listener.
pub(crate) async fn serve(listener: UnixListener, server_state: Arc<ServerState>) {
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
                let response =
                    handle_pam_authenticate(auth_req, &daemon, &server_state, caller_pid).await;
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
    caller_pid: i32,
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

    // Resolve the display context from the kernel's view of the caller now: the
    // process may be gone by the time the Server answers. The self-reported
    // fields of `req` are only a fallback (see `caller_context`).
    let caller = caller_context::CallerContext::resolve(caller_pid, &req);
    let tty_present = req.tty_present;

    let timeout = Some(req.timeout_seconds);
    match AuthSession::new(daemon.clone(), req.username.clone(), caller, tty_present) {
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
    // Encode message to temporary buffer first to get length
    let msg_bytes = msg.encode_to_vec();
    // Refuse to emit a frame our own IPC clients would reject: the cap is
    // enforced on the way out as well as on the way in.
    let prefix = framing::encode_len(msg_bytes.len())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("frame too large: {e}")))?;

    let mut buf = BytesMut::with_capacity(4 + msg_bytes.len());
    // Write length prefix (u32 BE)
    buf.extend_from_slice(&prefix);
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
    let len = framing::decode_len(len_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("frame too large: {e}")))?;

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

// reason: test module; the crate root denies unwrap/expect/panic.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The daemon's reader consumes exactly the bytes `shared::ipc::framing`
    /// produces, so the socket carries the shared wire format rather than a
    /// local copy of it.
    #[tokio::test]
    async fn read_framed_round_trips_a_frame_from_the_shared_encoder() {
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        let body = b"tapauth-envelope".to_vec();
        let prefix = framing::encode_len(body.len()).unwrap();

        tx.write_all(&prefix).await.unwrap();
        tx.write_all(&body).await.unwrap();

        assert_eq!(read_framed(&mut rx).await.unwrap(), body);
    }

    /// One byte past the shared cap is refused on the length alone, before any
    /// body is reserved for it.
    #[tokio::test]
    async fn read_framed_rejects_a_frame_past_the_shared_cap() {
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        let over = framing::MAX_FRAME_LEN + 1;
        tx.write_all(&(over as u32).to_be_bytes()).await.unwrap();

        match read_framed(&mut rx).await.unwrap_err() {
            DaemonError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// The daemon cannot emit a reply its own clients refuse: a body above the
    /// shared cap is rejected and no prefix reaches the socket, so the peer is
    /// never left waiting on a body that will not come.
    #[tokio::test]
    async fn write_framed_refuses_a_reply_past_the_shared_cap() {
        let (mut tx, rx) = UnixStream::pair().unwrap();
        let response = ipc::AdminResponse {
            status: ipc::AdminStatus::AdminSuccess as i32,
            error_message: "x".repeat(framing::MAX_FRAME_LEN),
            payload: None,
        };

        match write_framed(&mut tx, &response).await.unwrap_err() {
            DaemonError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("unexpected error: {other:?}"),
        }

        let mut buf = [0u8; 1];
        match rx.try_read(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("daemon emitted bytes for a refused frame: {other:?}"),
        }
    }
}
