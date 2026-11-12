//! What one authentication transaction produced.
//!
//! The two arms of [`Finished`] are the whole contract between the orchestration and its
//! caller: only `Finished::Concluded` may be recorded in the 500 ms reuse record, because an
//! `Unrecorded` verdict was reached before a request was on the wire and recording it could
//! only answer a later duplicate with an answer the daemon never gave.
//!
//! A fresh [`Concluded`] has exactly one producer, [`Armed::conclude`], and an [`Armed`] exists
//! only while a request is on the wire, so a conclusion cannot be minted without one.

mod host_io;
mod lifecycle;
mod run;

// Re-exported so `crate::transaction::X` keeps resolving; the files stay private.
pub(crate) use host_io::HostIo;
pub(crate) use lifecycle::{Armed, Concluded, Finished, StartError, Via};
pub(crate) use run::{run, Effects, SendParams};

// The two carriers other modules' own test builds use.
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
