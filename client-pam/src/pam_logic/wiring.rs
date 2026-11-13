//! The platform values behind the transaction's effects: the one file that names the calls
//! [`authenticate`](super::authenticate) binds into [`Effects`](crate::transaction::Effects).
//! No PAM conversation call lives here, and tests substitute a field of `Effects` instead of
//! calling these, so none of them has a test of its own.

use crate::ipc_client::{IpcClient, IpcError};
use crate::transaction::SendParams;
use std::time::Duration;

/// The module's single `/dev/tty` open.
///
/// An `Effects` field rather than a direct call, so a test can count the probe without a
/// terminal.
pub(super) fn probe_tty() -> Option<std::fs::File> {
    std::fs::File::open("/dev/tty").ok()
}

/// The production `connect`: a nonblocking dial of the daemon socket.
///
/// A wrapper rather than a re-export: an inherent associated function cannot be named by a
/// `use` path.
pub(super) fn connect() -> Result<IpcClient, IpcError> {
    IpcClient::connect_nonblocking()
}

/// The production `send`: the authenticate request, on the connected client.
pub(super) fn send_authenticate_request(
    ipc: &mut IpcClient,
    request: &SendParams<'_>,
) -> Result<(), IpcError> {
    ipc.send_authenticate_start(
        request.username,
        request.has_tty,
        request.timeout_secs,
        request.request_id,
        request.pam_service,
        request.process_name,
    )
}

/// The production `cancel`: a *fresh* short-timeout connection, never the live one.
///
/// The two exits that cancel — the terminal Enter skip and the no-terminal IPC error — either
/// no longer need the request or just watched the socket fail, so a write on `Armed.ipc` would
/// be a guaranteed no-op while the phone keeps buzzing until the daemon's own deadline. Best
/// effort: a daemon that cannot be reached takes the same path as one that never got the
/// cancel.
pub(super) fn cancel_on_fresh_connection(reason: &str, request_id: &str) {
    if let Ok(mut client) = IpcClient::connect(Duration::from_millis(100)) {
        let _ = client.send_cancel(reason, request_id);
    }
}
