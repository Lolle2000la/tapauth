//! The armed→concluded state machine: a conclusion cannot exist without a
//! request on the wire.
//!
//! [`Armed::open`] is the only producer of an [`Armed`], [`Armed::conclude`] the
//! only producer of a fresh [`Concluded`], and [`Concluded::replay`] the only
//! producer of [`Via::Replay`]. [`Finished`] is the transaction's result, and its
//! two arms are the whole contract with the orchestration: only `Concluded` may
//! be recorded in the 500 ms reuse record.
//!
//! A local IPC failure is not a verdict about the phone, so it can neither arm
//! the record ([`StartError`]) nor produce a conclusion.

use crate::context::ServiceName;
use crate::ipc_client::{IpcError, IpcResponseReader};
use crate::mechanism::MechanismEnd;
use crate::outcome::Outcome;

/// The result of one authentication transaction.
pub(crate) enum Finished {
    /// A conclusion was reached, with the provenance needed to decide whether
    /// it may be recorded.
    Concluded(Concluded),
    /// No conclusion: the call ended before a request could be put on the wire.
    Unrecorded(Outcome),
}

/// A conclusion, and how it was reached.
///
/// The fields are private to `transaction`: `username`, `service` and `via` are
/// the recording gate's inputs, and the cache owner reads them only through
/// [`Concluded::into_parts`]. There is deliberately no constructor that a
/// caller outside this module can reach except [`Armed::conclude`] and
/// [`Concluded::replay`]. `outcome` and `via` are also read by the one emission
/// site ([`crate::transaction::HostIo`]'s `finish`), which needs the verdict and
/// its provenance to decide whether anything is shown.
pub(crate) struct Concluded {
    pub(super) outcome: Outcome,
    pub(super) username: String,
    pub(super) service: Option<ServiceName>,
    pub(super) via: Via,
}

/// How a conclusion was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Via {
    /// This call's own request reached the daemon.
    Daemon,
    /// A copy of a conclusion this process recorded earlier, inside the reuse
    /// window. Never re-recorded.
    Replay,
}

impl Finished {
    /// The verdict this result carries, whatever the arm.
    ///
    /// Test-only: production reads the arm it matched and records through
    /// [`crate::conclusion_cache::record`], so nothing outside a test needs the
    /// verdict detached from the provenance.
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        match self {
            Finished::Concluded(concluded) => concluded.outcome(),
            Finished::Unrecorded(outcome) => outcome,
        }
    }
}

impl Concluded {
    /// The verdict.
    #[cfg(test)]
    pub(crate) fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// How the conclusion was reached.
    #[cfg(test)]
    pub(crate) fn via(&self) -> Via {
        self.via
    }

    /// The recording gate's inputs, moved out for the cache owner.
    ///
    /// The fields stay private to `transaction` so only it can build a
    /// `Concluded`; the cache (`crate::conclusion_cache`) is the one reader
    /// outside it, and it applies the gate and stores the record with these
    /// four values.
    pub(crate) fn into_parts(self) -> (Outcome, String, Option<ServiceName>, Via) {
        (self.outcome, self.username, self.service, self.via)
    }

    /// The replay constructor, and the only producer of [`Via::Replay`].
    ///
    /// It takes the *recorded* `Outcome` — a value [`Armed::conclude`] produced
    /// earlier in this process — copies it through `Outcome::replayed`, and
    /// marks the token `Via::Replay`, which
    /// [`ConclusionCache::record`](crate::conclusion_cache::ConclusionCache::record)
    /// refuses. Its production caller is the cache hit in
    /// [`replay_for`](crate::conclusion_cache::replay_for); a test may build one
    /// directly, which is how `a_from_cache_verdict_is_not_recorded` pins that
    /// the marker — not a local flag — is what refuses the re-record.
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
/// The two arms keep their own notices: the caller maps
/// `Connect` to `Unavailable(DaemonUnreachable)` (`cannot_connect`) and `Send`
/// to `Unavailable(DaemonSendFailed)` (`communication_error`), so a reader can
/// tell a missing socket from a failed write.
pub(crate) enum StartError {
    Connect(IpcError),
    Send(IpcError),
}

/// A request that is on the wire, with the client and the request id the
/// mechanism needs.
///
/// [`Armed::open`] is the only producer: it runs the injected `connect` and
/// then `send`, and it returns `Armed` only when *both* succeeded. A local IPC
/// failure is not a verdict about the phone, so it can neither arm the record
/// nor produce a conclusion.
pub(crate) struct Armed<I: IpcResponseReader> {
    ipc: I,
    request_id: Box<str>,
}

impl<I: IpcResponseReader> Armed<I> {
    /// Connect, put the authenticate request on the wire, and only then produce
    /// the `Armed`.
    ///
    /// The ordering is the point: the record exists so a duplicate
    /// `pam_authenticate` can replay a conclusion *the daemon* reached, so it
    /// must not be armed by a local IPC failure. A missing socket or a failed
    /// write says nothing about the phone — arming there would let a later
    /// duplicate inherit that `PAM_AUTHINFO_UNAVAIL` without ever asking, and a
    /// genuine retry must dial the socket again instead of being answered from
    /// the record.
    ///
    /// `connect` and `send` are borrowed effects so both failure paths are
    /// testable without a daemon (`pam_logic::tests::reuse`); production passes
    /// `pam_logic::wiring`'s `connect` and `send_authenticate_request`. They are
    /// `&mut dyn` rather than type parameters so the reader stays this type's
    /// only generic argument.
    pub(crate) fn open(
        connect: &mut dyn FnMut() -> Result<I, IpcError>,
        send: &mut dyn FnMut(&mut I) -> Result<(), IpcError>,
        request_id: Box<str>,
    ) -> Result<Self, StartError> {
        let mut ipc = connect().map_err(StartError::Connect)?;
        send(&mut ipc).map_err(StartError::Send)?;
        // The request is on the wire, so a daemon conclusion is now possible.
        // Nothing above this line can produce one.
        Ok(Armed { ipc, request_id })
    }

    /// The conclusion this request reached.
    ///
    /// Consumes the `Armed`, so a conclusion cannot outlive the fact that a
    /// request was on the wire, and consumes the mechanism's [`MechanismEnd`],
    /// so the daemon's answer is mapped to a verdict here and nowhere else: a
    /// mechanism cannot mint a `Granted` or a `Denied` of its own (§3.5.2
    /// layer 4). The mapping itself is
    /// `impl From<MechanismEnd> for Outcome`, which lives in `mechanism/mod.rs`
    /// beside the exit type it maps.
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
    /// One call rather than two accessors, so a caller cannot hold the client's
    /// mutable borrow and the id's shared borrow separately.
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
