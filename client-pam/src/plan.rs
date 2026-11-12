//! The timed plan for a conversation: deadline, announcement and `/dev/tty` use.
//! A dependency leaf — it names no policy or caller type, only [`PamConfig`] for
//! the resolved timeouts.

use crate::config::PamConfig;

/// What a conversation may do with time, wording and the terminal.
///
/// Config-free so two plans can be compared for equality in a test; the
/// configured seconds only enter through [`Deadline::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) deadline: Deadline,
    pub(crate) announcement: Announcement,
    pub(crate) tty_use: TtyUse,
}

/// How the wait is bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Deadline {
    /// `pam_operation_timeout_secs` alone.
    Operation,
    /// `pam_gui_timeout_secs`, clamped to `pam_operation_timeout_secs`: a
    /// sequential host *without* a terminal cannot offer a concurrent password
    /// field, so its wait is the shorter of the two.
    GuiBounded,
}

impl Deadline {
    /// The effective timeout in whole seconds, saturating at `u32::MAX`. This is the
    /// only place the clamp and the saturation exist; a sequential host **with** a
    /// terminal is bounded by `pam_operation_timeout_secs` alone.
    pub(crate) fn resolve(self, cfg: &PamConfig) -> u32 {
        let secs = match self {
            Deadline::Operation => cfg.pam_operation_timeout_secs,
            Deadline::GuiBounded => cfg.pam_gui_timeout_secs.min(cfg.pam_operation_timeout_secs),
        };
        secs.min(u64::from(u32::MAX)) as u32
    }
}

/// Which `PAM_TEXT_INFO` the user is shown, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Announcement {
    /// The threaded wait: emitted before the request.
    Wait,
    /// The terminal wait: emitted before the request.
    WaitSkipHint,
    /// The no-terminal sequential wait: emitted *after* the request is on the
    /// wire, because such a host reveals its password entry only once a PAM
    /// message arrives and must already be blocked when it does.
    WaitThenPassword,
}

/// Whether this conversation polls `/dev/tty`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TtyUse {
    /// Never open `/dev/tty`: the host drives its own conversation.
    DoNotOpen,
    /// Poll `/dev/tty` for a key, and treat Enter as "skip".
    PollForKey,
}

/// The two conversations that have a timed plan.
///
/// There is deliberately no `PreCollected` variant: the handoff returns at the
/// call site before a plan exists, so [`Plannable::plan`] matches exactly the two
/// conversations that are waited for and has no unreachable arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plannable {
    Threaded,
    Sequential,
}

impl Plannable {
    /// The probe gate: the single source of "does this conversation open
    /// `/dev/tty`", so the mode test does not appear a second time at the probe.
    pub(crate) fn tty_use(self) -> TtyUse {
        match self {
            Plannable::Threaded => TtyUse::DoNotOpen,
            Plannable::Sequential => TtyUse::PollForKey,
        }
    }

    /// The plan, total over `Plannable × bool`.
    pub(crate) fn plan(self, has_tty: bool) -> Plan {
        match (self, has_tty) {
            (Plannable::Threaded, _) => Plan {
                deadline: Deadline::Operation,
                announcement: Announcement::Wait,
                tty_use: TtyUse::DoNotOpen,
            },
            (Plannable::Sequential, true) => Plan {
                deadline: Deadline::Operation,
                announcement: Announcement::WaitSkipHint,
                tty_use: TtyUse::PollForKey,
            },
            (Plannable::Sequential, false) => Plan {
                deadline: Deadline::GuiBounded,
                announcement: Announcement::WaitThenPassword,
                tty_use: TtyUse::DoNotOpen,
            },
        }
    }
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn config(operation: u64, gui: u64) -> PamConfig {
        PamConfig {
            pam_operation_timeout_secs: operation,
            pam_gui_timeout_secs: gui,
            ..PamConfig::default()
        }
    }

    /// Every `Plannable × has_tty` cell, and the three distinct plans it produces.
    ///
    /// The defect this catches: a cell with the wrong announcement (the terminal
    /// wait emitted after the request, or none for the no-terminal host),
    /// `PollForKey` for a conversation that must not open the terminal, and
    /// `GuiBounded` on a host with a terminal, which would shorten a `sudo` wait
    /// that has a working password field.
    #[test]
    fn plan_table() {
        let threaded = Plan {
            deadline: Deadline::Operation,
            announcement: Announcement::Wait,
            tty_use: TtyUse::DoNotOpen,
        };
        let sequential_tty = Plan {
            deadline: Deadline::Operation,
            announcement: Announcement::WaitSkipHint,
            tty_use: TtyUse::PollForKey,
        };
        let sequential_no_tty = Plan {
            deadline: Deadline::GuiBounded,
            announcement: Announcement::WaitThenPassword,
            tty_use: TtyUse::DoNotOpen,
        };

        let cells = [
            (Plannable::Threaded, true, threaded),
            (Plannable::Threaded, false, threaded),
            (Plannable::Sequential, true, sequential_tty),
            (Plannable::Sequential, false, sequential_no_tty),
        ];
        let mut distinct: Vec<Plan> = Vec::new();
        for (plannable, has_tty, expected) in cells {
            let plan = plannable.plan(has_tty);
            assert_eq!(
                plan, expected,
                "{plannable:?} with has_tty={has_tty} must plan {expected:?}"
            );
            if !distinct.contains(&plan) {
                distinct.push(plan);
            }
        }
        assert_eq!(distinct.len(), 3, "the table has exactly three cells");
    }

    /// The `has_tty` value must not reach a threaded plan: with the probe or the
    /// mode test moved before the plan, a threaded host that happens to have a
    /// terminal gets the terminal announcement or a terminal-bounded deadline.
    #[test]
    fn threaded_plan_ignores_has_tty() {
        assert_eq!(
            Plannable::Threaded.plan(true),
            Plannable::Threaded.plan(false)
        );
    }

    /// `GuiBounded` is `min(gui, operation)`, in all four shapes.
    ///
    /// The defect this catches: `min` written as `max` — every integration test in
    /// the repository still passes, because the host-cases shape sets gui 2 s / op
    /// 4 s and never discriminates the two — and the clamp applied to an
    /// `Operation` host.
    #[test]
    fn gui_deadline_is_min() {
        let below = config(120, 30);
        assert_eq!(Deadline::GuiBounded.resolve(&below), 30);
        assert_eq!(Deadline::Operation.resolve(&below), 120);

        let above = config(10, 30);
        assert_eq!(Deadline::GuiBounded.resolve(&above), 10);

        let equal = config(30, 30);
        assert_eq!(Deadline::GuiBounded.resolve(&equal), 30);

        // An operation timeout of zero bounds every host at zero, which is the
        // "never wait" configuration.
        let zero = config(0, 30);
        assert_eq!(Deadline::GuiBounded.resolve(&zero), 0);
        assert_eq!(Deadline::Operation.resolve(&zero), 0);
    }

    /// Seconds beyond `u32::MAX` saturate instead of wrapping.
    ///
    /// The defect this catches: an `as u32` cast without the saturation, which
    /// turns a configured 2^32 seconds into an immediate zero-second deadline.
    #[test]
    fn deadline_saturates_at_u32_max() {
        let huge = config(u64::MAX, u64::MAX);
        assert_eq!(Deadline::Operation.resolve(&huge), u32::MAX);
        assert_eq!(Deadline::GuiBounded.resolve(&huge), u32::MAX);

        // One just past the limit, from the gui side only.
        let just_past = config(u64::MAX, u64::from(u32::MAX) + 1);
        assert_eq!(Deadline::GuiBounded.resolve(&just_past), u32::MAX);

        let fits = config(u64::from(u32::MAX), 5);
        assert_eq!(Deadline::Operation.resolve(&fits), u32::MAX);
        assert_eq!(Deadline::GuiBounded.resolve(&fits), 5);
    }
}
