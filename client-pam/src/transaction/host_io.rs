//! The PAM host surface, and the crate's single emission site.
//!
//! [`HostIo`] is everything a transaction touches on the host, and every return of
//! [`run()`](crate::transaction::run()) passes through [`finish`], so no early return can lose a
//! message or show it twice.

use super::lifecycle::{Finished, Via};
use crate::outcome::{Notice, NoticeStyle};
use crate::pam_messages::PamMessages;
use crate::pam_sys::{PamConversation, PamHandle, ReadAuthtok};
use std::os::raw::{c_char, c_int};

/// The recording sink's entry: the style is recorded too, so an `Error`-style message cannot be
/// asserted where an `Info` one belongs.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Emitted {
    pub(crate) style: NoticeStyle,
    pub(crate) text: String,
}

/// The PAM handle and the messages the orchestration built, plus — in production only — the
/// conversation they belong to.
///
/// A conversation-less host makes [`HostIo::emit`] a no-op, so a test never opens a real PAM
/// handle.
///
/// The type deliberately owns no terminal: the `/dev/tty` file is `run`'s local and is consumed
/// by the sequential mechanism.
pub(crate) struct HostIo<'a> {
    pamh: *mut PamHandle,
    conv: Option<&'a PamConversation<'a>>,
    /// Read by `run` for the plan's announcements and by [`finish`] for the verdict's message.
    pub(super) msgs: &'a PamMessages,
    /// The handoff's one handle read, injected so a test can count it.
    read_authtok: ReadAuthtok,
    #[cfg(test)]
    emitted: Option<&'a std::cell::RefCell<Vec<Emitted>>>,
}

impl<'a> HostIo<'a> {
    pub(crate) fn new(
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
            #[cfg(test)]
            emitted: None,
        }
    }

    pub(crate) fn pamh(&self) -> *mut PamHandle {
        self.pamh
    }

    pub(crate) fn read_authtok(&self) -> (c_int, *const c_char) {
        // SAFETY: the reader is the caller's `pam_get_authtok` wrapper, which takes the live
        // handle this host carries; the conversation belongs to this thread.
        unsafe { (self.read_authtok)(self.pamh) }
    }

    /// Show one notice, if there is one.
    ///
    /// `try_info`/`try_error` swallow a failing conversation, so a broken host conversation
    /// cannot change the verdict; the style comes from the notice's reason, not from the site
    /// that observed the failure.
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

    /// A host that records what it was asked to show, in order, with styles.
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

/// Show `finished`'s message through `host`, then hand `finished` back.
///
/// The message is decided by the verdict *and by how it was reached*, never by the site that
/// produced it: a `Via::Replay` conclusion stays silent because of its provenance, not because
/// its return happens to be early, so a restructure that routed a replayed `Unavailable(..)` or
/// `Error(..)` through an ordinary return still could not speak.
pub(super) fn finish(host: &HostIo<'_>, finished: Finished) -> Finished {
    let notice = match &finished {
        Finished::Concluded(concluded) if concluded.via == Via::Replay => None,
        Finished::Concluded(concluded) => concluded.outcome.notice(host.msgs),
        Finished::Unrecorded(outcome) => outcome.notice(host.msgs),
    };
    host.emit(notice);
    finished
}
