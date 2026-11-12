//! The conversation-driver layer: one body per PAM conversation shape — threaded,
//! sequential, and the pre-collected handoff — around the exit type they share.
//! The set is closed by the PAM ABI and dispatched by a plain `match`, never a
//! trait object, so the compiler can see which bodies take a plan.
//!
//! # Contract
//!
//! No body takes the caller's captured identity or the module's configuration:
//! identity cannot be re-derived and the deadline cannot be recomputed inside
//! one, so a mechanism can never disagree with the policy that selected it.
//! Everything arrives as `&mut Armed`, `&Plan`, the resolved `deadline_at`, and
//! — only where needed — the PAM handle, `/dev/tty`, the injected `cancel`
//! closure or [`crate::transaction::HostIo`]. The threaded body receives the
//! plan for uniformity alone and never opens the tty.
//!
//! No body emits a user-visible message: the verdict's one `Outcome::notice`
//! comes from `transaction::host_io::finish` and the plan's announcements from
//! `transaction::run`, so the text and the style of a failure are a property of
//! the reason, not of the loop that observed it.
//!
//! Every body returns a [`MechanismEnd`], never an
//! [`Outcome`](crate::outcome::Outcome): only
//! [`Armed::conclude`](crate::transaction::Armed::conclude) mints one.

pub(crate) mod handoff;
pub(crate) mod sequential;
pub(crate) mod threaded;

use crate::outcome::{ErrorReason, Outcome, UnavailableReason};

/// A mechanism's exit: the daemon's response, or why there is none.
///
/// `Error` is only for the threaded shape's two local-resource failures
/// (`pipe2`, `pthread_create`), which must keep concluding `PAM_AUTH_ERR`.
#[derive(Debug)]
pub(crate) enum MechanismEnd {
    Response(shared::ipc::pb::PamAuthenticateResponse),
    Reason(UnavailableReason),
    Error(ErrorReason),
}

/// The one mapping from a mechanism's exit to the verdict it names.
///
/// Used by [`Armed::conclude`](crate::transaction::Armed::conclude) for a
/// transaction that reached the daemon, and by `run`'s pre-collected arm, which
/// has no request to conclude. Keeping it beside the exit it maps is what lets
/// `outcome.rs` stay clear of the mechanism contract.
impl From<MechanismEnd> for Outcome {
    fn from(end: MechanismEnd) -> Outcome {
        match end {
            MechanismEnd::Response(resp) => Outcome::from_daemon(resp),
            MechanismEnd::Reason(reason) => Outcome::Unavailable(reason),
            MechanismEnd::Error(reason) => Outcome::Error(reason),
        }
    }
}

/// The shared reason pair: the two IPC failures both loops name the same way.
///
/// Only the *reason* is shared, because that is what selects the text and the
/// style (`Outcome::notice`); which observed event counts as a hangup stays in
/// the loop that observed it, next to the `revents` test that decided it.
///
/// The poll-error arm is deliberately not here, because the loops answer it
/// differently: the threaded loop records `IpcLoopError` and stops, while the
/// sequential loop logs it and keeps waiting on the terminal shape and collapses
/// it into `IpcError` (with a `gui-ipc-error` cancel) on the no-terminal one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcFault {
    /// The peer closed the connection, with or without a partial frame.
    Hangup,
    /// A read on the socket failed.
    DecodeError,
}

impl IpcFault {
    /// The reason both loops show for this failure.
    fn reason(self) -> UnavailableReason {
        match self {
            IpcFault::Hangup => UnavailableReason::IpcConnectionLost,
            IpcFault::DecodeError => UnavailableReason::IpcLoopError,
        }
    }
}
