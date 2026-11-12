//! The decision record: `RULES`, one row per host, plus the test-only audit
//! record that names each rule and cites the evidence for it.

use crate::context::{CallerContext, ProcessIdentity};

use super::{
    Classification, Conversation, Decision, FailureDirection, Participation, RuleId, SkipPolicy,
};

/// One row of the table: the id `classify` reports, the class that lands on the
/// participation, the predicate the engine walks, and the decision it converts.
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
///
/// Adding a host edits: a `Rule` row in `RULES`, whose length is the `[Rule; 10]` type;
/// the predicate it names, with both its full and its `/proc/self/comm`-truncated
/// (15-byte) spelling for a name that long; the `RuleId` variant, `RuleId::ALL` and
/// `RuleId::as_str`; the `audit` arm, whose `evidence` cites
/// `policy/table.rs:<line of fn ...>`; a `callers.csv` row with `expected_rule` and
/// `expected_policy`; an `EXPECTED_TTY` entry only for a `threaded` or `sequential`
/// row, since one for any other fails `corpus_characterises_the_decision_table`;
/// its `(1..=10)` bound; and the key set in `rules_are_process_disjoint`, the one
/// edit whose omission nothing fails loudly on. A service-keyed host (a display manager)
/// is not a new `Rule`, only one `DM_PREFIXES` entry (bump `[&str; 13]`) plus one corpus
/// row per prefix; an `e2e=1` row also needs `exe` set (the corpus reader fails a row
/// without one) and a `case` arm in `scripts/ci/test-pam-conv-thread.sh`, which the Rust
/// suite does not check.
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

/// R10's result, and the value `classify` falls back to. R10's predicate is
/// unconditional, so `find` always returns and this value is unreachable; it
/// makes `classify` total without a panic path. `unreachable_rule_rows` asserts
/// it is exactly what the table's last row produces, so the two cannot drift.
pub(super) const DEFAULT_SEQUENTIAL: Classification = Classification::Participate(Participation {
    conversation: Conversation::Sequential,
    failure_direction: FailureDirection::DeadlockAvoidance,
});

/// The service names R1 refuses (`shared::config::DEFAULT_PAM_REFUSED_SERVICES`),
/// compared ASCII case-insensitively: `PAM_SERVICE` is a `pam.d` filename, so a
/// service literally named `SSHD` is sshd's stack whatever its spelling.
///
/// `sshd` is OpenSSH's compiled-in `PAMServiceName` default and `sshd-session`
/// its per-connection session service. Both are defaults, not constants of the
/// protocol: a deployment that renames the service falls through to R10 (the
/// documented false negative, `svc_sshd_near_miss`) unless it declares the new
/// name in `pam_refused_services`.
const REMOTE_SERVICES: &[&str] = shared::config::DEFAULT_PAM_REFUSED_SERVICES;

/// R1 — refuse a remote authentication, keyed on the service name.
///
/// The module never reads `PAM_RHOST`: `sudo` sets it to the local hostname
/// (`Defaults pam_rhost`), so a presence-only rule would silence the module on
/// `sudo`. Keying on the service keeps the refusal to the stacks that exist to
/// authenticate a remote peer.
fn remote_refuse(ctx: &CallerContext) -> bool {
    ctx.service().is_some_and(|service| {
        REMOTE_SERVICES
            .iter()
            .any(|remote| service.eq_ignore_ascii_case(remote))
    })
}

/// The display-manager prefixes. A service matches when its ASCII-lowercased
/// name is a prefix exactly, or the prefix followed by a `-` boundary: `gdm`,
/// `gdm3` and `gdm-password` qualify, `gdmfoo` does not. The folding is
/// `to_ascii_lowercase` only (`ServiceName::dm_prefixed`), so U+212A KELVIN
/// SIGN is *not* folded to `k`.
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
/// unreadable `/proc` stays sequential.
fn polkit_service_without_proc(ctx: &CallerContext) -> bool {
    matches!(ctx.process(), ProcessIdentity::Unknown)
        && ctx.service().is_some_and(|service| service.is("polkit-1"))
}

/// R10 — the sequential default. Unconditional, and last.
fn default_sequential(_ctx: &CallerContext) -> bool {
    true
}

/// One rule's audit record: its symbolic name, why it exists, and the in-tree
/// evidence for the behaviour it preserves. Test-only by construction: a record
/// only the tests read is not production data, so the shipped table carries no
/// `dead_code` exemption.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct Audit {
    /// The rule's symbolic name (`dm_login_bypass`, …), which must be the row's
    /// own predicate: its citation has to land on `fn <name>`.
    pub(super) name: &'static str,
    /// Why the rule exists, in one sentence. The predicate's doc comment keeps
    /// the long form, including every accepted risk.
    pub(super) why: &'static str,
    /// `file:line` citations the rule must be able to defend. Entries prefixed
    /// `external:` cite something outside this tree and are exempt from
    /// resolution.
    pub(super) evidence: &'static [&'static str],
}

/// `id`'s audit record. The `match` is exhaustive over `RuleId` with no wildcard,
/// so a rule added to the enum does not compile until its record is written; the
/// other direction — a record whose row was deleted from `RULES` — is
/// `audit_covers_rules`.
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
                "client-pam/src/policy/table.rs:156",
                "client-pam/src/outcome.rs:59",
            ],
        },
        RuleId::R3 => Audit {
            name: "gdm_reauth_worker",
            why: "a GDM reauthentication is driven by the session worker, whose \
                  conversation stays answerable while a worker thread waits",
            evidence: &[
                "client-pam/src/policy/table.rs:163",
                "client-pam/src/context.rs:80",
            ],
        },
        RuleId::R4 => Audit {
            name: "polkit_agent",
            why: "polkit's agent helper feeds its conversation from a separate \
                  process, so it can be answered while the caller waits",
            evidence: &[
                "client-pam/src/policy/table.rs:174",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::R5 => Audit {
            name: "kscreenlocker_worker",
            why: "kscreenlocker 6.8's worker answers on Qt's D-Bus daemon thread, so \
                  the conversation survives the calling thread blocking",
            evidence: &[
                "client-pam/src/policy/table.rs:182",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::R6 => Audit {
            name: "hyprlock",
            why: "hyprlock answers from a worker thread; its unsynchronised \
                  `resetConversation`/`checkWaiting` race is the accepted risk",
            evidence: &[
                "client-pam/src/policy/table.rs:194",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::R7 => Audit {
            name: "xsecurelock",
            why: "xsecurelock's helper answers from its own thread pool, at the cost \
                  of up to three rings when `CallPAMWithRetries` re-runs the module",
            evidence: &[
                "client-pam/src/policy/table.rs:202",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::R8 => Audit {
            name: "precollected_locks",
            why: "these hosts collected the password before `pam_authenticate`, so \
                  the phone must not be rung and the token is handed on instead",
            evidence: &[
                "client-pam/src/policy/table.rs:207",
                "client-pam/src/mechanism/handoff.rs:25",
            ],
        },
        RuleId::R9 => Audit {
            name: "polkit_service_without_proc",
            why: "polkit with an unreadable `/proc` cannot be shown to answer \
                  concurrently, so it stays on the threaded conversation",
            evidence: &[
                "client-pam/src/policy/table.rs:218",
                "client-pam/src/context.rs:164",
            ],
        },
        RuleId::R10 => Audit {
            name: "default_sequential",
            why: "every other caller is driven sequentially on the calling thread, \
                  which is slower but can never wedge the host's event loop",
            evidence: &[
                "client-pam/src/policy/table.rs:224",
                "client-pam/src/mechanism/sequential.rs:1",
            ],
        },
    }
}
