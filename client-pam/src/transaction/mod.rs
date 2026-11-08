//! What one authentication transaction produced.
//!
//! The two arms of [`Finished`] are the whole contract between the
//! orchestration and its caller. `Finished::Concluded` carries a [`Concluded`] —
//! the verdict, the subject, the service and how the verdict was reached — and
//! only that arm may be recorded in the 500 ms reuse record.
//! `Finished::Unrecorded` carries an [`Outcome`](crate::outcome::Outcome) that
//! was reached before a request was on the wire (a skip, a missing username, a
//! pre-collected handoff, a connect failure), so recording it could only answer
//! a later duplicate with a verdict the daemon never reached.
//!
//! A fresh [`Concluded`] has exactly one producer, [`Armed::conclude`], and an
//! [`Armed`] exists only when a request is on the wire, so a conclusion cannot
//! be minted without one. [`Concluded::replay`] is the only producer of
//! [`Via::Replay`], and
//! [`ConclusionCache::record`](crate::conclusion_cache::ConclusionCache::record)
//! refuses it — which is what keeps the fixed 500 ms window fixed.
//!
//! [`Concluded::outcome`] is the only way the orchestration's caller reads a
//! verdict out of this type in a test build, and `Outcome::into_pam` the only way
//! it becomes a `PAM_*` code, so a code cannot travel beside the verdict.
//!
//! ## Layout
//!
//! * [`run()`] and [`Effects`] — the driver and the seam it takes (the
//!   transaction itself, from the classification to the conclusion);
//! * [`Armed`], [`Concluded`], [`Via`], [`StartError`] — the armed→concluded
//!   state machine, where a conclusion cannot exist without a request on the
//!   wire;
//! * [`HostIo`] and `finish` — the PAM host surface and the crate's single
//!   emission site.
//!
//! The names below are re-exported so `crate::transaction::X` keeps resolving
//! from the modules that already import them; the files themselves are private
//! to this module.

mod host_io;
mod lifecycle;
mod run;

pub(crate) use host_io::HostIo;
pub(crate) use lifecycle::{Armed, Concluded, Finished, StartError, Via};
pub(crate) use run::{run, Effects, SendParams};

// The two carriers other modules use in their own test builds: the recording
// sink and the fake-reader constructor.
#[cfg(test)]
pub(crate) use host_io::Emitted;
#[cfg(test)]
pub(crate) use lifecycle::armed_for_test;

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
pub(crate) mod tests;
