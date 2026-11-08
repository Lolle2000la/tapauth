//! The production values behind the transaction's effects.
//!
//! [`authenticate`](super::authenticate) binds these into
//! [`Effects`](crate::transaction::Effects), and this is the only file that
//! knows both the PAM host and `IpcClient`: the `/dev/tty` probe, the
//! authenticate request on the connected socket, and the best-effort cancel on
//! a fresh connection. Splitting them out of `super` keeps the ordering policy
//! and the platform calls readable apart; every test substitutes a field of
//! `Effects` instead of calling one of these, so none of them has a test of its
//! own.

use crate::ipc_client::{IpcClient, IpcError};
use crate::transaction::SendParams;
use std::time::Duration;

/// The module's single `/dev/tty` open.
///
/// Injected into [`orchestrate`](super::orchestrate) as a closure, the same
/// seam `Armed::open`'s `connect`/`send` have, so tests can count the probe
/// without a terminal.
pub(super) fn probe_tty() -> Option<std::fs::File> {
    std::fs::File::open("/dev/tty").ok()
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
    )
}

/// The production `cancel`: a *fresh* short-timeout connection, never the live
/// one.
///
/// The two exits that cancel — the terminal Enter skip and the no-terminal IPC
/// error — either no longer need the request or just watched the socket fail, so
/// a write on `Armed.ipc` would be a guaranteed no-op and the phone would keep
/// buzzing until the daemon's own deadline. It is best effort: a daemon that
/// cannot be reached takes the same path as one that never got the cancel.
pub(super) fn cancel_on_fresh_connection(reason: &str, request_id: &str) {
    if let Ok(mut client) = IpcClient::connect(Duration::from_millis(100)) {
        let _ = client.send_cancel(reason, request_id);
    }
}
