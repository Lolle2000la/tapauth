//! The decision record: `RULES`, one row per host.
//!
//! What the rules *are*. A row carries the class it was authored against (the
//! failure direction it protects), the in-tree evidence for the behaviour it
//! preserves, its predicate and its decision; the taxonomy those values are
//! written in lives in the parent module, and the first-match engine that walks
//! this table lives there too.

use crate::context::{CallerContext, ProcessIdentity};

use super::{
    Classification, Conversation, Decision, FailureDirection, Participation, RuleId, SkipPolicy,
};

/// One row of the table.
///
/// `name` and `evidence` are the justification record: the shipped binary does
/// not read them, and the policy tests do (uniqueness, corpus coverage and
/// citation resolution), so they are exempt from the dead-code lint rather than
/// dropped.
// reason: name/evidence are the shipped audit record; only the policy tests read them.
#[allow(dead_code)]
pub(super) struct Rule {
    pub(crate) id: RuleId,
    /// The rule's symbolic name (`dm_login_bypass`, …).
    pub(crate) name: &'static str,
    pub(crate) class: FailureDirection,
    /// `file:line` citations the rule must be able to defend. Entries prefixed
    /// `external:` cite something outside this tree and are exempt from
    /// resolution.
    pub(crate) evidence: &'static [&'static str],
    pub(crate) predicate: fn(&CallerContext) -> bool,
    pub(crate) decision: Decision,
}

/// The conversation policy, in order. R1 precedes every other rule (a remote
/// call is refused whatever its process or service is), R2 precedes everything
/// after it (the keyring constraint belongs to the service, not to the process),
/// and R10 is last and unconditional.
pub(super) static RULES: [Rule; 10] = [
    Rule {
        id: RuleId::R1,
        name: "remote_refuse",
        class: FailureDirection::RefuseRemote,
        evidence: &[
            "external:pam_set_item(3) - PAM_RHOST is the remote requesting host, \
             and OpenSSH sets it (auth-pam.c); sshd is PAMServiceName's default",
            "external:OpenSSH PAMServiceName defaults to `sshd`, so the service \
             name is a compile-time default, not a constant of the protocol",
        ],
        predicate: remote_refuse,
        decision: Decision::Skip(SkipPolicy::RemoteAuthentication),
    },
    Rule {
        id: RuleId::R2,
        name: "dm_login_bypass",
        class: FailureDirection::Keyring,
        evidence: &[
            "client-pam/src/policy/table.rs:223",
            "client-pam/src/outcome.rs:79",
        ],
        predicate: dm_login_bypass,
        decision: Decision::Skip(SkipPolicy::KeyringNeedsAuthtok),
    },
    Rule {
        id: RuleId::R3,
        name: "gdm_reauth_worker",
        class: FailureDirection::DeadlockAvoidance,
        evidence: &[
            "client-pam/src/policy/table.rs:230",
            "client-pam/src/context.rs:74",
        ],
        predicate: gdm_reauth_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R4,
        name: "polkit_agent",
        class: FailureDirection::DeadlockAvoidance,
        evidence: &[
            "client-pam/src/policy/table.rs:241",
            "client-pam/src/mechanism/threaded.rs:227",
        ],
        predicate: polkit_agent,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R5,
        name: "kscreenlocker_worker",
        class: FailureDirection::DeadlockAvoidance,
        evidence: &[
            "client-pam/src/policy/table.rs:249",
            "client-pam/src/mechanism/threaded.rs:191",
        ],
        predicate: kscreenlocker_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R6,
        name: "hyprlock",
        class: FailureDirection::AlwaysRing,
        evidence: &[
            "client-pam/src/policy/table.rs:257",
            "client-pam/src/mechanism/threaded.rs:191",
        ],
        predicate: hyprlock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R7,
        name: "xsecurelock",
        class: FailureDirection::AlwaysRing,
        evidence: &[
            "client-pam/src/policy/table.rs:262",
            "client-pam/src/mechanism/threaded.rs:191",
        ],
        predicate: xsecurelock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R8,
        name: "precollected_locks",
        class: FailureDirection::NeverRing,
        evidence: &[
            "client-pam/src/policy/table.rs:267",
            "client-pam/src/mechanism/handoff.rs:31",
        ],
        predicate: precollected_locks,
        decision: Decision::Participate(Conversation::PreCollected),
    },
    Rule {
        id: RuleId::R9,
        name: "polkit_service_without_proc",
        class: FailureDirection::DeadlockAvoidance,
        evidence: &[
            "client-pam/src/policy/table.rs:279",
            "client-pam/src/context.rs:160",
        ],
        predicate: polkit_service_without_proc,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R10,
        name: "default_sequential",
        class: FailureDirection::DeadlockAvoidance,
        evidence: &[
            "client-pam/src/policy/table.rs:285",
            "client-pam/src/mechanism/threaded.rs:203",
        ],
        predicate: default_sequential,
        decision: Decision::Participate(Conversation::Sequential),
    },
];

/// R10's result, and the value `classify` falls back to.
///
/// R10's predicate is `|_| true`, so `find` always returns and this value is
/// unreachable; it exists so `classify` is total without a panic path
/// (`clippy::panic` and `clippy::unwrap_used` are denied crate-wide).
/// `unreachable_rule_rows` asserts it is exactly what the table's last row
/// produces, so the two cannot drift.
pub(super) const DEFAULT_SEQUENTIAL: Classification = Classification::Participate(Participation {
    conversation: Conversation::Sequential,
    failure_direction: FailureDirection::DeadlockAvoidance,
});

/// The service names R1 refuses (`shared::config::DEFAULT_PAM_REFUSED_SERVICES`).
///
/// `sshd` is OpenSSH's compiled-in `PAMServiceName` default; `sshd-session` is
/// the name its per-connection session binary uses on current releases. Both are
/// a *default*, not a constant of the protocol: a deployment that renames the
/// service falls through to R10, which is the documented false negative (see
/// `svc_sshd_near_miss` in the corpus). A rename is declared by adding the new
/// name to `pam_refused_services`; R1 itself keeps the built-ins.
///
/// The comparison is ASCII case-insensitive, because `PAM_SERVICE` is a
/// `pam.d` filename and case folding here cannot over-match: a service literally
/// named `SSHD` is sshd's stack whatever its spelling.
const REMOTE_SERVICES: &[&str] = shared::config::DEFAULT_PAM_REFUSED_SERVICES;

/// R1 — refuse a remote authentication, keyed on the service name.
///
/// The module never reads `PAM_RHOST`: `sudo` sets it to the local hostname
/// (`Defaults pam_rhost`), so a presence-only rule would silence the module on
/// `sudo`. Keying on the service keeps the refusal to the stacks that exist to
/// authenticate a remote peer. An unresolved service name never matches.
fn remote_refuse(ctx: &CallerContext) -> bool {
    ctx.service().is_some_and(|service| {
        REMOTE_SERVICES
            .iter()
            .any(|remote| service.eq_ignore_ascii_case(remote))
    })
}

/// The display-manager prefixes.
///
/// A service matches when its ASCII-lowercased name is a prefix exactly, or the
/// prefix followed by a `-` boundary: `gdm`, `gdm3` and `gdm-password` qualify,
/// `gdmfoo` does not. The match is `ServiceName::dm_prefixed`, and the folding
/// is `to_ascii_lowercase` only — see
/// [`ServiceName`](crate::context::ServiceName) — so U+212A KELVIN SIGN is
/// *not* folded to `k`.
const DM_PREFIXES: [&str; 13] = [
    "sddm",
    "gdm",
    "gdm3",
    "lightdm",
    "lxdm",
    "slim",
    "xdm",
    "kdm",
    "greetd",
    "ly",
    "nodm",
    "entrance",
    "plasmalogin",
];

/// R2 — the display-manager bypass, with the GDM reauthentication exemption.
///
/// The prefix match is `ServiceName::dm_prefixed`, reached only through
/// `ctx.service()`, so an absent service never matches.
fn dm_login_bypass(ctx: &CallerContext) -> bool {
    ctx.service()
        .is_some_and(|service| DM_PREFIXES.iter().any(|prefix| service.dm_prefixed(prefix)))
        && !ctx.is_gdm_reauth()
}

/// R3 — a GDM reauthentication driven by the session worker.
fn gdm_reauth_worker(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("gdm-session-worker" | "gdm-session-wor")
    ) && ctx
        .service()
        .is_some_and(|service| service.eq_ignore_ascii_case("gdm-password"))
        && ctx.is_gdm_reauth()
}

/// R4 — polkit's agent helper, full and `/proc/self/comm`-truncated spellings.
fn polkit_agent(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("polkit-agent-helper-1" | "polkit-agent-he")
    )
}

/// R5 — kscreenlocker's worker, full and truncated spellings.
fn kscreenlocker_worker(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("kscreenlocker_worker" | "kscreenlocker_w")
    )
}

/// R6 — hyprlock.
///
/// Accepted risk: the host answers from a worker `std::thread` with a
/// mutex/condvar — a genuine concurrent race, accepted with an unsynchronised
/// `resetConversation`/`checkWaiting`.
fn hyprlock(ctx: &CallerContext) -> bool {
    matches!(ctx.process().name(), Some("hyprlock"))
}

/// R7 — xsecurelock's helper.
///
/// Accepted risk: the conversation is answered by the helper's own thread pool,
/// and `CallPAMWithRetries` can re-run the module up to three times.
fn xsecurelock(ctx: &CallerContext) -> bool {
    matches!(ctx.process().name(), Some("authproto_pam"))
}

/// R8 — hosts that collected the password before calling `pam_authenticate`.
fn precollected_locks(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("swaylock" | "gtklock" | "i3lock")
    )
}

/// R9 — polkit with an unreadable `/proc`.
///
/// The service comparison is exact bytes, deliberately: `POLKIT-1` with an
/// unreadable `/proc` stays sequential, which is the comparison this rule has
/// always made.
fn polkit_service_without_proc(ctx: &CallerContext) -> bool {
    matches!(ctx.process(), ProcessIdentity::Unknown)
        && ctx.service().is_some_and(|service| service.is("polkit-1"))
}

/// R10 — the sequential default. Unconditional, and last.
fn default_sequential(_ctx: &CallerContext) -> bool {
    true
}
