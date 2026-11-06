//! What one authentication transaction produced: a conclusion with its
//! provenance, or nothing to record.
//!
//! The two arms are the whole contract between the orchestration and its
//! caller. `Finished::Concluded` carries a [`Concluded`] — the verdict, the
//! subject, the service and how the verdict was reached — and only that arm may
//! be recorded in the 500 ms reuse record. `Finished::Unrecorded` carries an
//! [`Outcome`] that was reached before a request was on the wire (a skip, a
//! missing username, a pre-collected handoff, a connect failure), so recording
//! it could only answer a later duplicate with a verdict the daemon never
//! reached.
//!
//! [`Concluded::outcome`] is the only way the orchestration's caller reads a
//! verdict out of this type, and `Outcome::to_pam` the only way it becomes a
//! `PAM_*` code, so a code cannot travel beside the verdict.
//!
//! Step 5 of the adoption path replaces the `Via`/`Concluded` pair's owner: the
//! cache moves here as `ConclusionCache`, `Concluded::replay` becomes the only
//! producer of [`Via::Replay`], and `Armed::conclude` the only producer of
//! [`Via::Daemon`]. The types in this file are already the shape that requires.

use crate::context::ServiceName;
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
/// `username`, `service` and `via` are the recording gate's inputs: a
/// conclusion with no resolved service is not recorded (there would be no cache
/// key), and a [`Via::Replay`] one is never re-recorded (that would slide the
/// fixed window). They are read by the recording path in step 5, so the fields
/// are exempt from the dead-code lint until then.
#[allow(dead_code)]
pub(crate) struct Concluded {
    pub(crate) outcome: Outcome,
    pub(crate) username: String,
    pub(crate) service: Option<ServiceName>,
    pub(crate) via: Via,
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
    pub(crate) fn outcome(&self) -> &Outcome {
        match self {
            Finished::Concluded(concluded) => concluded.outcome(),
            Finished::Unrecorded(outcome) => outcome,
        }
    }
}

impl Concluded {
    /// The verdict.
    pub(crate) fn outcome(&self) -> &Outcome {
        &self.outcome
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::outcome::{GrantVia, UnavailableReason};

    fn concluded(outcome: Outcome, via: Via) -> Concluded {
        Concluded {
            outcome,
            username: "alice".to_owned(),
            service: Some(ServiceName::new("sudo")),
            via,
        }
    }

    /// Both arms report the verdict they carry, and a `Concluded` keeps its
    /// provenance.
    ///
    /// The defect this catches: a `Finished` accessor that reads only one arm
    /// (so a caller mapping `outcome()` would silently turn an unrecorded
    /// connect failure into something else), and a provenance field that cannot
    /// distinguish a fresh conclusion from a replay — which is what `record`
    /// refuses in step 5.
    #[test]
    fn finished_reports_its_outcome_and_provenance() {
        let grant = Outcome::granted_from_daemon();
        let finished = Finished::Concluded(concluded(grant.clone(), Via::Daemon));
        assert_eq!(finished.outcome(), &grant);
        assert_eq!(
            finished.outcome().clone().to_pam(),
            crate::pam_sys::PAM_SUCCESS
        );

        let unreachable = Outcome::Unavailable(UnavailableReason::DaemonUnreachable);
        let unrecorded = Finished::Unrecorded(unreachable.clone());
        assert_eq!(unrecorded.outcome(), &unreachable);
        assert_eq!(
            unrecorded.outcome().clone().to_pam(),
            crate::pam_sys::PAM_AUTHINFO_UNAVAIL
        );

        let replay = Outcome::replayed(&grant);
        let replayed = concluded(replay.clone(), Via::Replay);
        assert_eq!(replayed.outcome(), &replay);
        assert_eq!(replayed.via, Via::Replay);
        assert_eq!(replayed.username, "alice");
        assert_eq!(
            replayed.service.as_ref().map(ServiceName::original),
            Some("sudo")
        );
        assert_eq!(grant, Outcome::Granted(GrantVia::PhoneTap));
    }
}
