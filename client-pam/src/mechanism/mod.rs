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
//! Each body returns a [`crate::transaction::MechanismEnd`] — the daemon's
//! owned response, an unavailability reason, or a local error reason — never an
//! [`crate::outcome::Outcome`]: only `Armed::conclude` may turn one into a
//! conclusion, so a mechanism cannot mint one of its own.

pub(crate) mod handoff;
pub(crate) mod sequential;
pub(crate) mod threaded;

/// Why a poll loop stopped waiting.
///
/// Shared by the threaded loop (which has two more ways out: the user typed a
/// password, or dismissed the dialog) and the sequential loop, because both
/// distinguish "the deadline passed" from "the IPC layer said no". The variants
/// are not verdicts: the caller maps them to a
/// [`crate::outcome::UnavailableReason`], which is where the message and its
/// style come from.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExitReason {
    Timeout,
    IpcResponseReceived,
    IpcError,
    PasswordEntered,
    PasswordFailed,
}
