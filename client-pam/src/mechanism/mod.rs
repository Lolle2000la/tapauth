//! The three ways to answer a PAM ABI conversation, one per module.
//!
//! * [`threaded`] drives the host's conversation from a native worker thread
//!   while the calling thread multiplexes the daemon socket and a self-pipe.
//! * [`sequential`] leaves the conversation to the calling thread; it polls the
//!   daemon socket (plus `/dev/tty` when the plan gave it a terminal) and never
//!   touches `pam_conv`.
//! * [`handoff`] is the pre-collected host: the token the host already holds is
//!   read on the calling thread and handed to the next module, without any
//!   daemon request.
//!
//! The set is closed by the PAM ABI, and no member is a trait object: the
//! compiler can see that `PreCollected` needs no `Plan`.
//!
//! # The interface is closed
//!
//! No mechanism takes the caller's captured identity or the module's
//! configuration: identity cannot be re-derived and the deadline cannot be
//! recomputed inside one, so a mechanism can never disagree with the policy that
//! selected it. Everything a body needs arrives as `&mut Armed`,
//! `&Plan`, the resolved `deadline_at`, and — only where the body needs it —
//! the PAM handle, the `/dev/tty` file, the injected `cancel` closure, or
//! [`crate::transaction::HostIo`].
//!
//! No mechanism emits a user-visible message either: the conversation is only
//! touched by `transaction::run` (its one `Outcome::notice` per finished
//! transaction and the plan's announcements), so the text and the style of a
//! failure are a property of the reason, not of the loop that observed it.
//!
//! Each body returns a [`MechanismEnd`] — the daemon's owned response, an
//! unavailability reason, or a local error reason — never an
//! [`Outcome`](crate::outcome::Outcome): only
//! [`Armed::conclude`](crate::transaction::Armed::conclude) may turn one into a
//! conclusion, so a mechanism cannot mint one of its own.

pub(crate) mod handoff;
pub(crate) mod sequential;
pub(crate) mod threaded;

use crate::outcome::{ErrorReason, UnavailableReason};

/// A mechanism's exit.
///
/// It carries the daemon's response, an unavailability reason, or a local error
/// reason — never an [`Outcome`](crate::outcome::Outcome): only
/// [`Armed::conclude`](crate::transaction::Armed::conclude) may turn one into a
/// conclusion, so a mechanism cannot mint one of its own. `Error` exists for the
/// two local-resource failures the threaded mechanism owns (`pipe2`,
/// `pthread_create`), which must keep returning `PAM_AUTH_ERR` and must keep
/// being recorded. The response is owned, because a mechanism cannot return a
/// borrow of its own local.
#[derive(Debug)]
pub(crate) enum MechanismEnd {
    Response(shared::ipc::pb::PamAuthenticateResponse),
    Reason(UnavailableReason),
    Error(ErrorReason),
}

/// The two IPC failures both loops name the same way.
///
/// This is the whole of the duplicated failure table: a hangup is
/// [`UnavailableReason::IpcConnectionLost`] and a decode error is
/// [`UnavailableReason::IpcLoopError`], in the threaded loop and the sequential
/// loop alike. The shared part is the *reason*, because that is what selects the
/// text and the style (`Outcome::notice`); which observed event counts as a
/// hangup stays in the loop that observed it, next to the `revents` test that
/// decided it, and each loop maps its own local vocabulary onto this pair.
///
/// The poll-error arm is deliberately not here, because the two mechanisms
/// answer it differently: the threaded loop records
/// [`UnavailableReason::IpcLoopError`] and stops, while the sequential loop logs
/// it and keeps waiting on the terminal shape and collapses it into
/// [`UnavailableReason::IpcError`] (with a `gui-ipc-error` cancel) on the
/// no-terminal one. There is no single reason to share for it.
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
