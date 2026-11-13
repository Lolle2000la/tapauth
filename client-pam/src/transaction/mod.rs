//! What one authentication transaction produced, and what may be recorded from it.
//!
//! Only `Finished::Concluded` may be recorded in the 500 ms reuse record: an `Unrecorded` verdict
//! was reached before a request was on the wire, so recording it could only answer a later
//! duplicate with an answer the daemon never gave.

mod host_io;
mod lifecycle;
mod run;

pub(crate) use host_io::HostIo;
pub(crate) use lifecycle::{Armed, Concluded, Finished, StartError, Via};
pub(crate) use run::{run, Effects, SendParams};

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
