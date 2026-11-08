//! The PAM host surface, and the crate's single emission site.
//!
//! [`HostIo`] is the handle, the conversation, the messages and the one
//! pre-collected token read — the only thing a transaction touches on the host.
//! [`HostIo::emit`] is the one place a user-visible message is shown, and
//! [`finish`] is the one place that decides which message a finished
//! transaction shows, so no early return can lose a message or double it.

use super::lifecycle::{Finished, Via};
use crate::outcome::{Notice, NoticeStyle};
use crate::pam_messages::PamMessages;
use crate::pam_sys::{PamConversation, PamHandle, ReadAuthtok};
use std::os::raw::{c_char, c_int};

/// One thing [`HostIo::emit`] was asked to show, with the style it was shown in.
///
/// The recording sink's entry: the text alone would let an `Error`-style
/// message be asserted where an `Info` one belongs, which is exactly the
/// distinction `Outcome::notice` exists to keep.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Emitted {
    pub(crate) style: NoticeStyle,
    pub(crate) text: String,
}

/// The PAM handle and the messages the orchestration built, plus — in
/// production only — the conversation they belong to.
///
/// `new` is the only production constructor and always passes `Some`; `for_test`
/// is its `#[cfg(test)]` counterpart and passes `None`, which makes
/// [`HostIo::emit`] a no-op, so a test never opens a real PAM handle. A test that
/// needs to *see* the emission order uses `for_test_recording`, which records
/// text and style instead.
///
/// The type deliberately owns no terminal: the `/dev/tty` file is `run`'s local
/// and is consumed by the sequential mechanism.
pub(crate) struct HostIo<'a> {
    pamh: *mut PamHandle,
    conv: Option<&'a PamConversation<'a>>,
    /// The messages the orchestration loaded. Read by `run` for the plan's
    /// announcements as well as by [`finish`] for the verdict's message.
    pub(super) msgs: &'a PamMessages,
    /// The handoff's one handle read, injected like the other effects so a test
    /// can count it: production passes
    /// [`crate::pam_sys::read_authtok_for_handoff`].
    read_authtok: ReadAuthtok,
    /// Test-only record of what `emit` was asked to show.
    #[cfg(test)]
    emitted: Option<&'a std::cell::RefCell<Vec<Emitted>>>,
}

impl<'a> HostIo<'a> {
    pub(crate) fn new(
        pamh: *mut PamHandle,
        conv: &'a PamConversation<'a>,
        msgs: &'a PamMessages,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv: Some(conv),
            msgs,
            read_authtok,
            #[cfg(test)]
            emitted: None,
        }
    }

    /// The handle a mechanism needs for its one conversation call, if any.
    pub(crate) fn pamh(&self) -> *mut PamHandle {
        self.pamh
    }

    /// Read the host's pre-collected token, through the injected reader.
    pub(crate) fn read_authtok(&self) -> (c_int, *const c_char) {
        // SAFETY: the reader is the caller's `pam_get_authtok` wrapper, which
        // takes the live handle this host carries; the conversation belongs to
        // this thread.
        unsafe { (self.read_authtok)(self.pamh) }
    }

    /// Show one notice, if there is one.
    ///
    /// The one emission site in the crate: `try_info`/`try_error` swallow a
    /// failing conversation, so a broken host conversation cannot change the
    /// verdict, and the style comes from the notice's reason rather than from
    /// the site that observed the failure.
    pub(crate) fn emit(&self, notice: Option<Notice<'_>>) {
        let Some(notice) = notice else {
            return;
        };
        #[cfg(test)]
        if let Some(log) = self.emitted {
            log.borrow_mut().push(Emitted {
                style: notice.style,
                text: notice.text.to_string(),
            });
        }
        let Some(conv) = self.conv else {
            return;
        };
        match notice.style {
            NoticeStyle::Info => conv.try_info(&notice.text),
            NoticeStyle::Error => conv.try_error(&notice.text),
        }
    }

    /// A host with no conversation: every emission is a no-op.
    #[cfg(test)]
    pub(crate) fn for_test(
        pamh: *mut PamHandle,
        conv: Option<&'a PamConversation<'a>>,
        msgs: &'a PamMessages,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv,
            msgs,
            read_authtok,
            emitted: None,
        }
    }

    /// A host that records what it was asked to show, in order, with styles.
    ///
    /// The only way an ordering or a message assertion can see what the
    /// transaction emitted without a real PAM handle, which is what
    /// `announcement_order_matches_today` and `unrecorded_paths_emit_their_notice`
    /// need.
    #[cfg(test)]
    pub(crate) fn for_test_recording(
        pamh: *mut PamHandle,
        msgs: &'a PamMessages,
        emitted: &'a std::cell::RefCell<Vec<Emitted>>,
        read_authtok: ReadAuthtok,
    ) -> Self {
        HostIo {
            pamh,
            conv: None,
            msgs,
            read_authtok,
            emitted: Some(emitted),
        }
    }
}

/// The transaction's one emission site: show `finished`'s message through
/// `host`, then hand it back.
///
/// Every return in [`run()`](crate::transaction::run()) goes through here, so the
/// message is decided by the verdict *and by how it was reached*, never by the
/// site that produced it. `Concluded`'s [`Via`] is what suppresses it: a replay
/// is a copy of a conclusion this process already announced when it first
/// reached it, so it must say nothing — and it must say nothing because of its
/// provenance, not because the cache-hit arm happens to return early, so a
/// restructure that routed a replayed `Unavailable(..)` or `Error(..)` through
/// an ordinary return still could not speak.
pub(super) fn finish(host: &HostIo<'_>, finished: Finished) -> Finished {
    let notice = match &finished {
        Finished::Concluded(concluded) if concluded.via == Via::Replay => None,
        Finished::Concluded(concluded) => concluded.outcome.notice(host.msgs),
        Finished::Unrecorded(outcome) => outcome.notice(host.msgs),
    };
    host.emit(notice);
    finished
}
