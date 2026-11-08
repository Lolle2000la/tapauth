//! The decision record: `RULES`, one row per host, and its audit record.
//!
//! What the rules *are*. A row carries the class it was authored against (the
//! failure direction it protects), its predicate and its decision; the taxonomy
//! those values are written in lives in the parent module, and the first-match
//! engine that walks this table lives there too.
//!
//! The human-readable half — each rule's symbolic name, the sentence saying why
//! it exists, and the in-tree evidence for the behaviour it preserves — is the
//! audit record at the bottom of this file, compiled only for tests. No string
//! in it is read by the shipped binary, so the table needs no lint exemption;
//! the policy tests read the record for name uniqueness, corpus coverage and
//! citation resolution.

use crate::context::{CallerContext, ProcessIdentity};

use super::{
    Classification, Conversation, Decision, FailureDirection, Participation, RuleId, SkipPolicy,
};

/// One row of the table: everything the shipped binary reads.
///
/// The id `classify` returns next to the classification, the class that lands
/// on the participation, the predicate the engine walks, and the decision it
/// converts. The row's justification is the audit record (`audit`, at the
/// bottom of this file), which is compiled only for tests; a field nothing but
/// the tests read does not belong in the shipped table.
pub(super) struct Rule {
    pub(crate) id: RuleId,
    pub(crate) class: FailureDirection,
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
        class: FailureDirection::RefuseRemote,
        predicate: remote_refuse,
        decision: Decision::Skip(SkipPolicy::RemoteAuthentication),
    },
    Rule {
        id: RuleId::R2,
        class: FailureDirection::Keyring,
        predicate: dm_login_bypass,
        decision: Decision::Skip(SkipPolicy::KeyringNeedsAuthtok),
    },
    Rule {
        id: RuleId::R3,
        class: FailureDirection::DeadlockAvoidance,
        predicate: gdm_reauth_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R4,
        class: FailureDirection::DeadlockAvoidance,
        predicate: polkit_agent,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R5,
        class: FailureDirection::DeadlockAvoidance,
        predicate: kscreenlocker_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R6,
        class: FailureDirection::AlwaysRing,
        predicate: hyprlock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R7,
        class: FailureDirection::AlwaysRing,
        predicate: xsecurelock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R8,
        class: FailureDirection::NeverRing,
        predicate: precollected_locks,
        decision: Decision::Participate(Conversation::PreCollected),
    },
    Rule {
        id: RuleId::R9,
        class: FailureDirection::DeadlockAvoidance,
        predicate: polkit_service_without_proc,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R10,
        class: FailureDirection::DeadlockAvoidance,
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

/// One rule's audit record: its symbolic name, why it exists, and the in-tree
/// evidence for the behaviour it preserves.
///
/// Test-only by construction, not by lint exemption. `Rule` used to carry
/// `name` and `evidence` and needed `#[allow(dead_code)]` because the shipped
/// binary reads neither; a record only the tests read is not production data,
/// so it lives behind `cfg(test)` and the shipped table carries no escape.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct Audit {
    /// The rule's symbolic name (`dm_login_bypass`, …). It must be the name of
    /// the row's own predicate: `evidence_citations_resolve` requires the
    /// row's `policy/table.rs` predicate citation to land on `fn <name>`.
    pub(super) name: &'static str,
    /// Why the rule exists, in one sentence. The predicate's doc comment keeps
    /// the long form, including every accepted risk.
    pub(super) why: &'static str,
    /// `file:line` citations the rule must be able to defend. Entries prefixed
    /// `external:` cite something outside this tree and are exempt from
    /// resolution.
    pub(super) evidence: &'static [&'static str],
}

/// `id`'s audit record.
///
/// The `match` is exhaustive over `RuleId` with no wildcard, so a rule added to
/// the enum does not compile until its audit record is written. The other
/// direction — a record whose row was deleted from `RULES` — is
/// `audit_covers_rules` (`policy/mod.rs`).
#[cfg(test)]
pub(super) fn audit(id: RuleId) -> Audit {
    match id {
        RuleId::R1 => Audit {
            name: "remote_refuse",
            why: "the sshd stack authenticates a remote peer, so ringing the phone \
                  for it can only add a wait nobody is sitting at",
            evidence: &[
                "external:pam_set_item(3) - PAM_RHOST is the remote requesting host, \
                 and OpenSSH sets it (auth-pam.c); sshd is PAMServiceName's default",
                "external:OpenSSH PAMServiceName defaults to `sshd`, so the service \
                 name is a compile-time default, not a constant of the protocol",
            ],
        },
        RuleId::R2 => Audit {
            name: "dm_login_bypass",
            why: "the login manager has to populate `PAM_AUTHTOK` for the session \
                  keyring, and a grant without it is useless",
            evidence: &[
                "client-pam/src/policy/table.rs:170",
                "client-pam/src/outcome.rs:82",
            ],
        },
        RuleId::R3 => Audit {
            name: "gdm_reauth_worker",
            why: "a GDM reauthentication is driven by the session worker, whose \
                  conversation stays answerable while a worker thread waits",
            evidence: &[
                "client-pam/src/policy/table.rs:177",
                "client-pam/src/context.rs:74",
            ],
        },
        RuleId::R4 => Audit {
            name: "polkit_agent",
            why: "polkit's agent helper feeds its conversation from a separate \
                  process, so it can be answered while the caller waits",
            evidence: &[
                "client-pam/src/policy/table.rs:188",
                "client-pam/src/mechanism/threaded.rs:227",
            ],
        },
        RuleId::R5 => Audit {
            name: "kscreenlocker_worker",
            why: "kscreenlocker 6.8's worker answers on Qt's D-Bus daemon thread, so \
                  the conversation survives the calling thread blocking",
            evidence: &[
                "client-pam/src/policy/table.rs:196",
                "client-pam/src/mechanism/threaded.rs:191",
            ],
        },
        RuleId::R6 => Audit {
            name: "hyprlock",
            why: "hyprlock answers from a worker thread; its unsynchronised \
                  `resetConversation`/`checkWaiting` race is the accepted risk",
            evidence: &[
                "client-pam/src/policy/table.rs:208",
                "client-pam/src/mechanism/threaded.rs:191",
            ],
        },
        RuleId::R7 => Audit {
            name: "xsecurelock",
            why: "xsecurelock's helper answers from its own thread pool, at the cost \
                  of up to three rings when `CallPAMWithRetries` re-runs the module",
            evidence: &[
                "client-pam/src/policy/table.rs:216",
                "client-pam/src/mechanism/threaded.rs:191",
            ],
        },
        RuleId::R8 => Audit {
            name: "precollected_locks",
            why: "these hosts collected the password before `pam_authenticate`, so \
                  the phone must not be rung and the token is handed on instead",
            evidence: &[
                "client-pam/src/policy/table.rs:221",
                "client-pam/src/mechanism/handoff.rs:31",
            ],
        },
        RuleId::R9 => Audit {
            name: "polkit_service_without_proc",
            why: "polkit with an unreadable `/proc` cannot be shown to answer \
                  concurrently, so it keeps the historic threaded behaviour",
            evidence: &[
                "client-pam/src/policy/table.rs:233",
                "client-pam/src/context.rs:160",
            ],
        },
        RuleId::R10 => Audit {
            name: "default_sequential",
            why: "every other caller is driven sequentially on the calling thread, \
                  which is slower but can never wedge the host's event loop",
            evidence: &[
                "client-pam/src/policy/table.rs:239",
                "client-pam/src/mechanism/threaded.rs:219",
            ],
        },
    }
}
