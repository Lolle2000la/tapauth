//! The pre-collected handoff: the host already holds the password, so the token
//! is read on the calling thread and handed on to the next PAM module.
//!
//! swaylock, gtklock and i3lock read the password before calling
//! `pam_authenticate`, so their conversation is a synchronous replay of it and
//! `pam_get_authtok` returns immediately. Reading it here caches it in
//! `PAM_AUTHTOK` for the next module (`pam_unix` with `try_first_pass`/
//! `use_first_pass`), and it must stay on this thread: a worker would only
//! reintroduce the cross-thread libpam pattern the threaded shape joins around.
//! Ringing the phone for a typed password could only end in a timeout.
//!
//! It returns `PAM_AUTHINFO_UNAVAIL`, never `PAM_IGNORE`: a `sufficient` line
//! treats it as `ignore` and the next module still runs, a `required` line fails
//! closed. It never contacts the daemon, never writes the reuse record (a recorded
//! `PAM_AUTHINFO_UNAVAIL` would let a duplicate skip `pam_get_authtok` and leave
//! `PAM_AUTHTOK` unset) and emits no message.

use crate::mechanism::MechanismEnd;
use crate::outcome::UnavailableReason;
use crate::pam_sys;
use crate::transaction::HostIo;

/// The only PAM handle use a mechanism makes: the token must be read on this
/// thread, which is what `HostIo` carries the handle for.
pub(crate) fn perform(host: &mut HostIo<'_>) -> MechanismEnd {
    // Through the host's injected reader — production passes
    // `pam_sys::read_authtok_for_handoff` — so a test can count it.
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
