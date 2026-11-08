//! The pre-collected handoff: the host already holds the password, so the token
//! is read on the calling thread and handed to the next module.
//!
//! Pre-collected hosts (swaylock, gtklock, i3lock) read the password before
//! they call `pam_authenticate`; their conversation is a synchronous replay of
//! it, so `pam_get_authtok` returns immediately and never waits for the user.
//! Collect the token on the calling thread — a worker thread would only
//! reintroduce the cross-thread libpam pattern the threaded path has to join
//! around — and let it be cached in `PAM_AUTHTOK`, which is what the next module
//! (`pam_unix` with `try_first_pass`/`use_first_pass`) verifies.
//!
//! This is deliberately not a wait: the user has already typed the password, so
//! ringing the phone would be misleading and could only ever end in a timeout.
//! The handoff returns `PAM_AUTHINFO_UNAVAIL` (never `PAM_IGNORE`): a
//! `sufficient` line treats that as `ignore`, exactly as `PAM_IGNORE` would, so
//! the next module still runs; a `required` line fails closed. If the token
//! cannot be read (the host's conversation refused it, or nothing was
//! collected) the next module simply prompts as it would without this module.
//!
//! It never contacts the daemon, never reads or writes the reuse record, and
//! never emits a message.

use crate::mechanism::MechanismEnd;
use crate::outcome::UnavailableReason;
use crate::pam_sys;
use crate::transaction::HostIo;

/// Read the host's pre-collected token and hand it on.
///
/// The only PAM handle use in this crate's mechanisms: the token must be read on
/// this thread, which is what `HostIo` carries the handle for.
pub(crate) fn perform(host: &mut HostIo<'_>) -> MechanismEnd {
    // The read goes through the host's injected reader — production passes
    // `pam_sys::read_authtok_for_handoff` — so this is the one PAM handle use a
    // mechanism makes, and a test can count it rather than infer it.
    let (res, authtok) = host.read_authtok();
    if res != pam_sys::PAM_SUCCESS || authtok.is_null() {
        tracing::warn!(
            "TapAuth: pre-collected host supplied no password token ({res}); \
             falling through to the next PAM module"
        );
    } else {
        tracing::info!(
            "TapAuth: pre-collected password cached for the next PAM module; \
             the phone is not consulted"
        );
    }
    MechanismEnd::Reason(UnavailableReason::PasswordHandoff)
}
