//! The armed→concluded state machine: a conclusion can only be minted from a request that
//! reached the wire.
//!
//! [`Armed::open`] is the only producer of an [`Armed`], [`Armed::conclude`] of a fresh
//! [`Concluded`], and [`Concluded::replay`] of [`Via::Replay`], which
//! [`ConclusionCache::record`](crate::conclusion_cache::ConclusionCache::record) refuses.

use crate::context::ServiceName;
use crate::ipc_client::{IpcError, IpcResponseReader};
use crate::mechanism::MechanismEnd;
use crate::outcome::Outcome;

/// The result of one authentication transaction.
pub(crate) enum Finished {
    /// A conclusion was reached, with the provenance that decides whether it may be recorded.
    Concluded(Concluded),
    /// No conclusion: the call ended before a request could be put on the wire.
    Unrecorded(Outcome),
}

/// A conclusion, and how it was reached.
///
/// The fields stay private: the cache owner reads them only through
/// [`Concluded::into_parts`], and no constructor outside this module is reachable except
/// [`Armed::conclude`] and [`Concluded::replay`].
pub(crate) struct Concluded {
    pub(super) outcome: Outcome,
    pub(super) username: String,
    pub(super) service: Option<ServiceName>,
    pub(super) via: Via,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// This call's own request reached the daemon.
    Daemon,
    /// A copy of a conclusion this process recorded earlier, inside the reuse window. Never
    /// re-recorded.
    Replay,
}

impl Finished {
    /// The verdict this result carries, whatever the arm. Test-only: production matches the arm.
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        match self {
            Finished::Concluded(concluded) => concluded.outcome(),
            Finished::Unrecorded(outcome) => outcome,
        }
    }
}

impl Concluded {
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    #[cfg(test)]
    pub(crate) fn via(&self) -> Via {
        self.via
    }

    /// The recording gate's inputs, moved out for the cache owner, which applies the gate and
    /// stores the four values.
    pub(crate) fn into_parts(self) -> (Outcome, String, Option<ServiceName>, Via) {
        (self.outcome, self.username, self.service, self.via)
    }

    /// The replay constructor, and the only producer of [`Via::Replay`].
    ///
    /// It copies the *recorded* verdict through `Outcome::replayed` and marks the token
    /// `Via::Replay`, which `ConclusionCache::record` refuses: the marker, not a local flag, is
    /// what refuses the re-record.
    pub(crate) fn replay(recorded: Outcome, username: Box<str>, service: ServiceName) -> Concluded {
        Concluded {
            outcome: Outcome::replayed(&recorded),
            username: username.into(),
            service: Some(service),
            via: Via::Replay,
        }
    }
}

/// Why a transaction never reached the daemon.
///
/// The arms keep separate notices: `Connect` maps to `Unavailable(DaemonUnreachable)`
/// (`cannot_connect`) and `Send` to `Unavailable(DaemonSendFailed)` (`communication_error`), so
/// a reader can tell a missing socket from a failed write.
pub(crate) enum StartError {
    Connect(IpcError),
    Send(IpcError),
}

/// A request that is on the wire, with the client and the request id the mechanism needs.
///
/// [`Armed::open`] is the only producer: it runs the injected `connect` and then `send` and
/// returns an `Armed` only when *both* succeeded. A local IPC failure is not a verdict about the
/// phone, so it can neither arm the record nor produce a conclusion.
pub(crate) struct Armed<I: IpcResponseReader> {
    ipc: I,
    request_id: Box<str>,
}

impl<I: IpcResponseReader> Armed<I> {
    /// Connect, put the authenticate request on the wire, and only then produce the `Armed`.
    ///
    /// The ordering is the point: the record exists so a duplicate `pam_authenticate` can
    /// replay a conclusion *the daemon* reached, so a missing socket or a failed write must not
    /// arm it — a later duplicate would inherit that `PAM_AUTHINFO_UNAVAIL` without ever
    /// asking, and a genuine retry must dial the socket again.
    pub(crate) fn open(
        connect: &mut dyn FnMut() -> Result<I, IpcError>,
        send: &mut dyn FnMut(&mut I) -> Result<(), IpcError>,
        request_id: Box<str>,
    ) -> Result<Self, StartError> {
        let mut ipc = connect().map_err(StartError::Connect)?;
        send(&mut ipc).map_err(StartError::Send)?;
        Ok(Armed { ipc, request_id })
    }

    /// The conclusion this request reached.
    ///
    /// Consuming the `Armed` keeps a conclusion from outliving the fact that a request was on
    /// the wire, and consuming the [`MechanismEnd`] is what maps the daemon's answer to a
    /// verdict here and nowhere else: a mechanism cannot mint a `Granted` or a `Denied` of its
    /// own. The mapping itself is `impl From<MechanismEnd> for Outcome`, beside the exit type it
    /// maps.
    pub(crate) fn conclude(
        self,
        end: MechanismEnd,
        username: &str,
        service: Option<ServiceName>,
    ) -> Concluded {
        Concluded {
            outcome: end.into(),
            username: username.to_owned(),
            service,
            via: Via::Daemon,
        }
    }

    /// The client and the request id, for the mechanism that drives the wait.
    ///
    /// One accessor rather than two, so no caller can hold the client's mutable borrow and the
    /// id's shared borrow at once.
    pub(crate) fn parts(&mut self) -> (&mut I, &str) {
        (&mut self.ipc, &self.request_id)
    }
}

/// The test carrier over a fake reader; no test opens a real daemon socket.
#[cfg(test)]
pub(crate) fn armed_for_test<I: IpcResponseReader>(ipc: I, request_id: &str) -> Armed<I> {
    Armed {
        ipc,
        request_id: request_id.into(),
    }
}
