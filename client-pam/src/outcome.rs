//! The verdict as data, and the one place it becomes a `PAM_*` code.
//!
//! [`Outcome::to_pam`] is an exhaustive match with no wildcard, so a sixth
//! outcome variant is a compile error rather than a silent fallthrough. Every
//! other `PAM_*` value in the crate comes from it — the `lib.rs` ABI stubs and
//! the `pam_sys` plumbing excepted — which is what
//! `only_outcome_rs_returns_pam_constants` asserts once every call site has been
//! converted.
//!
//! Two constructors produce a grant, and only two:
//!
//! * [`Outcome::granted_from_daemon`] — this call's daemon `PamOutcome::Success`;
//! * [`Outcome::replayed`] — a copy of a conclusion this process already
//!   recorded, marked [`GrantVia::VerdictReplay`].
//!
//! A `Granted` therefore cannot be minted by a mechanism, a skip or a local
//! error, and `Outcome::replayed` is the only way a grant exists without a fresh
//! round trip.
//!
//! [`Outcome::notice`] is the pure half of the messaging: which single message
//! (if any) an outcome shows, and in which style. Emission itself stays at the
//! one place that owns the conversation (`try_info`/`try_error`), so the text
//! and the style are a property of the reason and not of the caller. A replayed
//! conclusion emits nothing, which is what keeps a cache hit silent.

use crate::pam_messages::PamMessages;
use crate::pam_sys;
use crate::policy::SkipPolicy;
use std::borrow::Cow;
use std::os::raw::c_int;

/// What this call decided, and (for the two verdicts) how it was reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Authentication succeeded. Constructible only through
    /// [`Outcome::granted_from_daemon`] or [`Outcome::replayed`].
    Granted(GrantVia),
    /// The phone explicitly denied the request, or a recorded denial was
    /// replayed.
    Denied(DenyVia),
    /// The credential could not be obtained. Maps to `PAM_AUTHINFO_UNAVAIL`.
    Unavailable(UnavailableReason),
    /// This attempt failed while it was being processed. Maps to
    /// `PAM_AUTH_ERR`.
    Error(ErrorReason),
    /// No username to ask about. Maps to `PAM_USER_UNKNOWN`.
    UserUnknown,
}

/// How a grant was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantVia {
    /// This call's daemon response was `PamOutcome::Success`.
    PhoneTap,
    /// A copy of a conclusion this process recorded inside the reuse window.
    VerdictReplay,
}

/// How a denial was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenyVia {
    /// This call's daemon response was `PamOutcome::Denied`.
    PhoneDenial,
    /// A copy of a conclusion this process recorded inside the reuse window.
    VerdictReplay,
}

/// Why the credential could not be obtained.
///
/// The set is deliberately finer than the code it maps to, because the *text
/// and the style* of the message are a property of the reason: the threaded and
/// terminal loops announce a hangup with `connection_lost` through `try_info`
/// while the no-terminal sequential path collapses every IPC failure into
/// `communication_error` through `try_error`. A single `IpcError` could recover
/// neither the text nor the style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnavailableReason {
    /// R2: the display manager's own stack must populate `PAM_AUTHTOK`.
    KeyringBypass,
    /// R8: the host already collected the password; the token was handed on.
    PasswordHandoff,
    /// R1: the module does not take part in a remote authentication.
    RemoteAuthentication,
    /// The daemon socket could not be opened.
    DaemonUnreachable,
    /// The request could not be written to the daemon socket.
    DaemonSendFailed,
    /// The daemon answered `PamOutcome::Ignore`.
    DaemonIgnored,
    /// The daemon answered `PamOutcome::Timeout`.
    DaemonTimedOut,
    /// The daemon closed the connection before answering (hangup).
    IpcConnectionLost,
    /// A read or poll on the daemon socket failed.
    IpcLoopError,
    /// Any IPC failure on the no-terminal sequential path.
    IpcError,
    /// A response arrived without the payload it promised, or the terminal the
    /// plan required vanished.
    ProtocolError,
    /// The configured deadline passed.
    TimedOut,
    /// The user pressed Enter on the terminal.
    Skipped,
    /// The user chose the password route on a threaded host.
    PasswordChosen,
    /// The user dismissed the password dialog on a threaded host.
    PasswordDismissed,
}

/// Why this attempt failed while it was being processed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ErrorReason {
    /// The daemon reported an internal error. The detail is the daemon's own.
    Daemon(Box<str>),
    /// `PamConversation::new` failed: there is nowhere to talk to the user.
    ConversationLookup,
    /// The request id could not be generated.
    RequestId,
    /// A local resource could not be created (`pipe2`, `pthread_create`).
    LocalResource,
}

/// How a message is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoticeStyle {
    /// `PAM_TEXT_INFO` (`try_info`).
    Info,
    /// `PAM_ERROR_MSG` (`try_error`).
    Error,
}

/// One message, with the style it is emitted in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Notice<'a> {
    pub(crate) style: NoticeStyle,
    pub(crate) text: Cow<'a, str>,
}

impl Outcome {
    /// The one conversion from a verdict to a `PAM_*` code.
    ///
    /// Five exhaustive arms and no wildcard: a new variant cannot inherit a
    /// neighbour's code silently. It consumes the verdict on purpose — that is
    /// the token the caller spends to obtain the code — so the `self`-by-value
    /// convention clippy wants for a `to_*` method does not apply.
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_pam(self) -> c_int {
        match self {
            Outcome::Granted(_) => pam_sys::PAM_SUCCESS,
            Outcome::Denied(_) => pam_sys::PAM_PERM_DENIED,
            Outcome::Unavailable(_) => pam_sys::PAM_AUTHINFO_UNAVAIL,
            Outcome::Error(_) => pam_sys::PAM_AUTH_ERR,
            Outcome::UserUnknown => pam_sys::PAM_USER_UNKNOWN,
        }
    }

    /// The grant this call's daemon `Success` produces.
    ///
    /// One of exactly two grant producers in the crate. The `match` in
    /// [`Outcome::from_daemon`] is explicit per variant, so a proto variant
    /// added later forces a decision here instead of defaulting to a grant.
    pub(crate) fn granted_from_daemon() -> Outcome {
        Outcome::Granted(GrantVia::PhoneTap)
    }

    /// A copy of a conclusion this process recorded earlier, marked as a
    /// replay.
    ///
    /// A structural copy, not a mapper: a `Granted` can only come out of a
    /// `Granted` input, so a replay can never upgrade an unavailability into a
    /// grant. `replay_never_upgrades` asserts that exhaustively.
    pub(crate) fn replayed(recorded: &Outcome) -> Outcome {
        match recorded {
            Outcome::Granted(_) => Outcome::Granted(GrantVia::VerdictReplay),
            Outcome::Denied(_) => Outcome::Denied(DenyVia::VerdictReplay),
            Outcome::Unavailable(reason) => Outcome::Unavailable(*reason),
            Outcome::Error(reason) => Outcome::Error(reason.clone()),
            Outcome::UserUnknown => Outcome::UserUnknown,
        }
    }

    /// The skip policy's verdict.
    ///
    /// The only mapping of a [`SkipPolicy`], so a skip cannot reach a different
    /// code through a second match in the orchestration.
    pub(crate) fn from_skip(policy: SkipPolicy) -> Outcome {
        match policy {
            SkipPolicy::RemoteAuthentication => {
                Outcome::Unavailable(UnavailableReason::RemoteAuthentication)
            }
            SkipPolicy::KeyringNeedsAuthtok => {
                Outcome::Unavailable(UnavailableReason::KeyringBypass)
            }
        }
    }

    /// The daemon's answer as a verdict.
    ///
    /// The raw `outcome` field is read, not prost's generated accessor: that
    /// accessor is `try_from(self.outcome).unwrap_or_default()`, and the
    /// default variant is `SUCCESS`, so an unknown value would decode as a
    /// *grant*. Unknown values fail closed as [`ErrorReason::Daemon`], which
    /// maps to `PAM_AUTH_ERR`.
    pub(crate) fn from_daemon(resp: shared::ipc::pb::PamAuthenticateResponse) -> Outcome {
        let detail = resp.detail;
        match outcome_from_raw(resp.outcome) {
            shared::ipc::pb::PamOutcome::Success => {
                tracing::info!("Authentication successful");
                Outcome::granted_from_daemon()
            }
            shared::ipc::pb::PamOutcome::Denied => {
                tracing::info!("Authentication explicitly denied");
                Outcome::Denied(DenyVia::PhoneDenial)
            }
            shared::ipc::pb::PamOutcome::Timeout => {
                tracing::info!("Authentication timed out");
                Outcome::Unavailable(UnavailableReason::DaemonTimedOut)
            }
            shared::ipc::pb::PamOutcome::Ignore => {
                tracing::info!("Daemon indicated IGNORE");
                Outcome::Unavailable(UnavailableReason::DaemonIgnored)
            }
            shared::ipc::pb::PamOutcome::Error => {
                tracing::error!("Daemon reported error: {}", detail);
                Outcome::Error(ErrorReason::Daemon(detail.into_boxed_str()))
            }
        }
    }

    /// The single message (if any) this outcome shows, and its style.
    ///
    /// Pure: no conversation, no PAM handle, no emission. The caller emits at
    /// most one of these per finished transaction, which is what the
    /// `Finished` emission rule relies on.
    pub(crate) fn notice<'a>(&self, msgs: &'a PamMessages) -> Option<Notice<'a>> {
        match self {
            Outcome::Granted(GrantVia::PhoneTap) => Some(Notice {
                style: NoticeStyle::Info,
                text: Cow::Borrowed(msgs.auth_successful()),
            }),
            // A replayed conclusion emits nothing: the message was shown when
            // the conclusion was first reached.
            Outcome::Granted(GrantVia::VerdictReplay) => None,
            Outcome::Denied(DenyVia::PhoneDenial) => Some(Notice {
                style: NoticeStyle::Info,
                text: Cow::Borrowed(msgs.auth_denied()),
            }),
            Outcome::Denied(DenyVia::VerdictReplay) => None,
            Outcome::Unavailable(reason) => match reason {
                UnavailableReason::KeyringBypass
                | UnavailableReason::PasswordHandoff
                | UnavailableReason::RemoteAuthentication
                | UnavailableReason::DaemonIgnored
                | UnavailableReason::ProtocolError
                | UnavailableReason::PasswordChosen
                | UnavailableReason::PasswordDismissed => None,
                UnavailableReason::DaemonUnreachable => Some(Notice {
                    style: NoticeStyle::Error,
                    text: Cow::Borrowed(msgs.cannot_connect()),
                }),
                // The no-terminal sequential path collapses every IPC failure
                // into this one reason, and it is the one path that shows its
                // text as an error rather than as information.
                UnavailableReason::DaemonSendFailed | UnavailableReason::IpcError => Some(Notice {
                    style: NoticeStyle::Error,
                    text: Cow::Borrowed(msgs.communication_error()),
                }),
                // §3.5.3's two timeout rows, which differ in silence: the
                // daemon's own `PamOutcome::Timeout` is `DaemonTimedOut` and
                // shows **no** message (it only leaves a `tracing::info!` behind,
                // in `from_daemon`), while `TimedOut` is this module's own
                // deadline and is the one the user is told about.
                UnavailableReason::DaemonTimedOut => None,
                UnavailableReason::TimedOut => Some(Notice {
                    style: NoticeStyle::Info,
                    text: Cow::Borrowed(msgs.timed_out()),
                }),
                UnavailableReason::IpcConnectionLost => Some(Notice {
                    style: NoticeStyle::Info,
                    text: Cow::Borrowed(msgs.connection_lost()),
                }),
                UnavailableReason::IpcLoopError => Some(Notice {
                    style: NoticeStyle::Info,
                    text: Cow::Borrowed(msgs.communication_error()),
                }),
                UnavailableReason::Skipped => Some(Notice {
                    style: NoticeStyle::Info,
                    text: Cow::Borrowed(msgs.skipped()),
                }),
            },
            Outcome::Error(reason) => match reason {
                ErrorReason::Daemon(detail) => Some(Notice {
                    style: NoticeStyle::Error,
                    text: Cow::Owned(msgs.error(detail)),
                }),
                ErrorReason::ConversationLookup
                | ErrorReason::RequestId
                | ErrorReason::LocalResource => None,
            },
            Outcome::UserUnknown => None,
        }
    }
}

/// Map the raw protobuf `outcome` field to a [`shared::ipc::pb::PamOutcome`],
/// failing closed on a value this build does not know.
fn outcome_from_raw(raw: i32) -> shared::ipc::pb::PamOutcome {
    use shared::ipc::pb::PamOutcome;

    // `PamOutcome::try_from` is the authority for "known variant"; a proto
    // variant makes this match go non-exhaustive, forcing a decision here.
    // Arms are spelled out, not `unwrap_or(...)`, to stay auditable.
    match PamOutcome::try_from(raw) {
        Ok(PamOutcome::Success) => PamOutcome::Success,
        Ok(PamOutcome::Denied) => PamOutcome::Denied,
        Ok(PamOutcome::Timeout) => PamOutcome::Timeout,
        Ok(PamOutcome::Ignore) => PamOutcome::Ignore,
        Ok(PamOutcome::Error) => PamOutcome::Error,
        Err(_) => PamOutcome::Error,
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

    fn messages() -> PamMessages {
        PamMessages::new("en")
    }

    fn response(
        outcome: shared::ipc::pb::PamOutcome,
        detail: &str,
    ) -> shared::ipc::pb::PamAuthenticateResponse {
        shared::ipc::pb::PamAuthenticateResponse {
            outcome: outcome as i32,
            detail: detail.to_owned(),
            challenge: Vec::new(),
        }
    }

    /// Every reason's code and message, in one table.
    ///
    /// The defects this catches: a reason mapped to the wrong `PAM_*` code (a
    /// daemon `Timeout` becoming a denial, or `Ignore` becoming a grant); a
    /// message move — `cannot_connect` shown as information instead of an
    /// error, `connection_lost` replaced by `communication_error` — and a
    /// message gained or lost on a path that had none. It also enumerates every
    /// `UnavailableReason` and `ErrorReason`, so a new variant with no row
    /// fails on the count rather than passing unnoticed.
    #[test]
    fn outcome_table_code_and_notice() {
        let msgs = messages();

        // Every unavailability, all of which map to AUTHINFO_UNAVAIL.
        let unavailabilities = [
            (UnavailableReason::KeyringBypass, None),
            (UnavailableReason::PasswordHandoff, None),
            (UnavailableReason::RemoteAuthentication, None),
            (
                UnavailableReason::DaemonUnreachable,
                Some((NoticeStyle::Error, msgs.cannot_connect())),
            ),
            (
                UnavailableReason::DaemonSendFailed,
                Some((NoticeStyle::Error, msgs.communication_error())),
            ),
            (UnavailableReason::DaemonIgnored, None),
            (
                // §3.5.3: the daemon's own `Timeout` row has no message; only
                // the local deadline (`TimedOut`, below) is announced.
                UnavailableReason::DaemonTimedOut,
                None,
            ),
            (
                UnavailableReason::IpcConnectionLost,
                Some((NoticeStyle::Info, msgs.connection_lost())),
            ),
            (
                UnavailableReason::IpcLoopError,
                Some((NoticeStyle::Info, msgs.communication_error())),
            ),
            (
                UnavailableReason::IpcError,
                Some((NoticeStyle::Error, msgs.communication_error())),
            ),
            (UnavailableReason::ProtocolError, None),
            (
                UnavailableReason::TimedOut,
                Some((NoticeStyle::Info, msgs.timed_out())),
            ),
            (
                UnavailableReason::Skipped,
                Some((NoticeStyle::Info, msgs.skipped())),
            ),
            (UnavailableReason::PasswordChosen, None),
            (UnavailableReason::PasswordDismissed, None),
        ];
        let mut seen_reasons: Vec<UnavailableReason> = Vec::new();
        for (reason, expected) in unavailabilities {
            if !seen_reasons.contains(&reason) {
                seen_reasons.push(reason);
            }
            assert_eq!(
                Outcome::Unavailable(reason).to_pam(),
                pam_sys::PAM_AUTHINFO_UNAVAIL,
                "{reason:?} must be an unavailable service, not another verdict"
            );
            assert_notice(&Outcome::Unavailable(reason), &msgs, expected);
        }
        assert_eq!(
            seen_reasons.len(),
            15,
            "the table must cover every UnavailableReason exactly once"
        );

        // Every local/daemon error, all of which map to AUTH_ERR.
        let daemon_detail_message = msgs.error("boom");
        let errors = [
            (
                ErrorReason::Daemon("boom".into()),
                Some((NoticeStyle::Error, daemon_detail_message.as_str())),
            ),
            (ErrorReason::ConversationLookup, None),
            (ErrorReason::RequestId, None),
            (ErrorReason::LocalResource, None),
        ];
        let mut seen_errors: Vec<ErrorReason> = Vec::new();
        for (reason, expected) in errors {
            if !seen_errors.contains(&reason) {
                seen_errors.push(reason.clone());
            }
            assert_eq!(
                Outcome::Error(reason.clone()).to_pam(),
                pam_sys::PAM_AUTH_ERR,
                "{reason:?} must be a processing failure"
            );
            assert_notice(&Outcome::Error(reason), &msgs, expected);
        }
        assert_eq!(
            seen_errors.len(),
            4,
            "the table must cover every ErrorReason exactly once"
        );

        // The two verdicts, with and without a replay.
        let granted = Outcome::granted_from_daemon();
        assert_eq!(granted.clone().to_pam(), pam_sys::PAM_SUCCESS);
        assert_notice(
            &granted,
            &msgs,
            Some((NoticeStyle::Info, msgs.auth_successful())),
        );
        let replayed_grant = Outcome::replayed(&granted);
        assert_eq!(replayed_grant.clone().to_pam(), pam_sys::PAM_SUCCESS);
        assert_notice(&replayed_grant, &msgs, None);

        let denied = Outcome::Denied(DenyVia::PhoneDenial);
        assert_eq!(denied.clone().to_pam(), pam_sys::PAM_PERM_DENIED);
        assert_notice(
            &denied,
            &msgs,
            Some((NoticeStyle::Info, msgs.auth_denied())),
        );
        let replayed_denial = Outcome::replayed(&denied);
        assert_eq!(replayed_denial.clone().to_pam(), pam_sys::PAM_PERM_DENIED);
        assert_notice(&replayed_denial, &msgs, None);

        assert_eq!(Outcome::UserUnknown.to_pam(), pam_sys::PAM_USER_UNKNOWN);
        assert_notice(&Outcome::UserUnknown, &msgs, None);
    }

    fn assert_notice(outcome: &Outcome, msgs: &PamMessages, expected: Option<(NoticeStyle, &str)>) {
        let actual = outcome.notice(msgs).map(|n| (n.style, n.text.into_owned()));
        let expected = expected.map(|(style, text)| (style, text.to_owned()));
        assert_eq!(actual, expected, "{outcome:?} must show {expected:?}");
    }

    /// The daemon's five answers, and an unknown raw value, map to the
    /// documented outcomes.
    ///
    /// The defect this catches: `from_daemon` defaulting an unrecognised raw
    /// value to `SUCCESS` (which is what prost's generated accessor does), or
    /// collapsing `Ignore` into a grant.
    #[test]
    fn from_daemon_maps_every_answer() {
        use shared::ipc::pb::PamOutcome;

        // A grant is the only success, and it carries the phone-tap
        // provenance.
        let granted = Outcome::from_daemon(response(PamOutcome::Success, "ok"));
        assert_eq!(granted, Outcome::Granted(GrantVia::PhoneTap));

        assert_eq!(
            Outcome::from_daemon(response(PamOutcome::Denied, "no")),
            Outcome::Denied(DenyVia::PhoneDenial)
        );
        assert_eq!(
            Outcome::from_daemon(response(PamOutcome::Timeout, "")),
            Outcome::Unavailable(UnavailableReason::DaemonTimedOut)
        );
        assert_eq!(
            Outcome::from_daemon(response(PamOutcome::Ignore, "")),
            Outcome::Unavailable(UnavailableReason::DaemonIgnored)
        );
        assert_eq!(
            Outcome::from_daemon(response(PamOutcome::Error, "boom")),
            Outcome::Error(ErrorReason::Daemon("boom".into()))
        );

        // An unknown raw value fails closed, with the daemon's detail kept for
        // the message.
        for raw in [-1, 5, 99, 255, i32::MAX, i32::MIN] {
            let resp = shared::ipc::pb::PamAuthenticateResponse {
                outcome: raw,
                detail: "unknown".to_owned(),
                challenge: Vec::new(),
            };
            let outcome = Outcome::from_daemon(resp);
            assert_eq!(
                outcome,
                Outcome::Error(ErrorReason::Daemon("unknown".into())),
                "raw outcome {raw} must fail closed"
            );
            assert_eq!(outcome.to_pam(), pam_sys::PAM_AUTH_ERR);
        }
    }

    /// `Outcome::replayed` yields a grant if and only if its input was one.
    ///
    /// The defect this catches: a replay constructor that "replays" an
    /// unavailability into a grant, or that keeps the original provenance so a
    /// cache hit cannot be told apart from a fresh tap (which would re-emit the
    /// message and re-record the conclusion).
    #[test]
    fn replay_never_upgrades() {
        let granted = Outcome::granted_from_daemon();
        let cases: Vec<Outcome> = vec![
            granted.clone(),
            Outcome::Denied(DenyVia::PhoneDenial),
            Outcome::Unavailable(UnavailableReason::DaemonUnreachable),
            Outcome::Unavailable(UnavailableReason::IpcConnectionLost),
            Outcome::Unavailable(UnavailableReason::TimedOut),
            Outcome::Unavailable(UnavailableReason::Skipped),
            Outcome::Error(ErrorReason::ConversationLookup),
            Outcome::Error(ErrorReason::Daemon("detail".into())),
            Outcome::UserUnknown,
        ];
        for recorded in &cases {
            let replayed = Outcome::replayed(recorded);
            assert_eq!(
                matches!(replayed, Outcome::Granted(_)),
                matches!(recorded, Outcome::Granted(_)),
                "{recorded:?} must not change verdict through a replay"
            );
            assert_eq!(
                replayed.to_pam(),
                recorded.clone().to_pam(),
                "{recorded:?} must replay the same code"
            );
        }

        // A replayed verdict is marked as such: that is what suppresses the
        // message and (in step 5) the re-recording.
        assert_eq!(
            Outcome::replayed(&granted),
            Outcome::Granted(GrantVia::VerdictReplay)
        );
        assert_eq!(
            Outcome::replayed(&Outcome::Denied(DenyVia::PhoneDenial)),
            Outcome::Denied(DenyVia::VerdictReplay)
        );
    }

    /// Both skip policies map to their own unavailability.
    ///
    /// The defect this catches: R1's refusal mapped to R2's reason (or to a
    /// bare `AUTHINFO_UNAVAIL` with no reason at all), which only
    /// `remote_under_dm` distinguishes by rule id, so an inverted mapping would
    /// otherwise pass.
    #[test]
    fn skip_policy_maps_to_outcome() {
        assert_eq!(
            Outcome::from_skip(SkipPolicy::RemoteAuthentication),
            Outcome::Unavailable(UnavailableReason::RemoteAuthentication)
        );
        assert_eq!(
            Outcome::from_skip(SkipPolicy::KeyringNeedsAuthtok),
            Outcome::Unavailable(UnavailableReason::KeyringBypass)
        );
        // Neither skip shows a message: the log line names the rule, and a
        // `PAM_TEXT_INFO` on a greeter or on sshd's stack would be noise.
        let msgs = messages();
        assert!(Outcome::from_skip(SkipPolicy::RemoteAuthentication)
            .notice(&msgs)
            .is_none());
        assert!(Outcome::from_skip(SkipPolicy::KeyringNeedsAuthtok)
            .notice(&msgs)
            .is_none());
    }
}
