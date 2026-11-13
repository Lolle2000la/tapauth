//! The decision record: `RULES`, an ordered list of named rules over
//! `CallerContext`, matched first-wins and keyed on whichever caller fact
//! identifies the host or service — the service name for `remote_refuse` and
//! `dm_login_bypass`, the process name for the rest — plus the test-only audit
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

/// The conversation policy, in order: `remote_refuse` first (a remote call is
/// refused whatever its process or service), `dm_login_bypass` next (its keyring
/// constraint is the service's), `default_sequential` last and unconditional.
///
/// Adding a host edits the `Rule` row, the predicate with both its full and
/// its `/proc/self/comm`-truncated (15-byte) spelling, the `RuleId` variant
/// with its `ALL` entry and `as_str` arm, the `audit` arm (whose `evidence`
/// cites `policy/table.rs:<line of fn ...>`), a `callers.csv` row with
/// `expected_rule` and `expected_policy`, the `(1..=10)` bound, and the
/// `rules_are_process_disjoint` key set — the one edit nothing fails loudly
/// on. An `EXPECTED_TTY` entry belongs only to a `threaded` or `sequential`
/// row, or `corpus_characterises_the_decision_table` fails. A display manager
/// is not a new `Rule`: one `DM_PREFIXES` entry (bump `[&str; 13]`) plus a
/// corpus row per prefix. An `e2e=1` row also needs `exe` and a `case` arm in
/// `scripts/ci/test-pam-conv-thread.sh`, which no Rust test checks.
pub(super) static RULES: [Rule; 10] = [
    Rule {
        id: RuleId::RemoteRefuse,
        class: FailureDirection::RefuseRemote,
        predicate: remote_refuse,
        decision: Decision::Skip(SkipPolicy::RemoteAuthentication),
    },
    Rule {
        id: RuleId::DmLoginBypass,
        class: FailureDirection::Keyring,
        predicate: dm_login_bypass,
        decision: Decision::Skip(SkipPolicy::KeyringNeedsAuthtok),
    },
    Rule {
        id: RuleId::GdmReauthWorker,
        class: FailureDirection::DeadlockAvoidance,
        predicate: gdm_reauth_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::PolkitAgent,
        class: FailureDirection::DeadlockAvoidance,
        predicate: polkit_agent,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::KscreenlockerWorker,
        class: FailureDirection::DeadlockAvoidance,
        predicate: kscreenlocker_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::Hyprlock,
        class: FailureDirection::AlwaysRing,
        predicate: hyprlock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::Xsecurelock,
        class: FailureDirection::AlwaysRing,
        predicate: xsecurelock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::PreCollectedLocks,
        class: FailureDirection::NeverRing,
        predicate: precollected_locks,
        decision: Decision::Participate(Conversation::PreCollected),
    },
    Rule {
        id: RuleId::PolkitServiceWithoutProc,
        class: FailureDirection::DeadlockAvoidance,
        predicate: polkit_service_without_proc,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::DefaultSequential,
        class: FailureDirection::DeadlockAvoidance,
        predicate: default_sequential,
        decision: Decision::Participate(Conversation::Sequential),
    },
];

/// The `default_sequential` row's result, and the value `classify` falls back to.
/// Its predicate is unconditional, so this value is unreachable: it makes
/// `classify` total without a panic path, and `unreachable_rule_rows` asserts it
/// is what the table's last row produces.
pub(super) const DEFAULT_SEQUENTIAL: Classification = Classification::Participate(Participation {
    conversation: Conversation::Sequential,
    failure_direction: FailureDirection::DeadlockAvoidance,
});

/// The service names `remote_refuse` refuses (`shared::config::DEFAULT_PAM_REFUSED_SERVICES`),
/// compared ASCII case-insensitively: `PAM_SERVICE` is a `pam.d` filename, so
/// a service literally named `SSHD` is sshd's stack whatever its spelling.
///
/// `sshd` is OpenSSH's compiled-in `PAMServiceName` default and
/// `sshd-session` its per-connection session service, so a deployment that
/// renames the service falls through to `default_sequential` (the documented
/// false negative, `svc_sshd_near_miss`) unless it declares the new name in
/// `pam_refused_services`.
const REMOTE_SERVICES: &[&str] = shared::config::DEFAULT_PAM_REFUSED_SERVICES;

/// `remote_refuse` — refuse a remote authentication, keyed on the service name.
///
/// The module never reads `PAM_RHOST`: `sudo` sets it to the local hostname
/// (`Defaults pam_rhost`), so a presence-only rule would silence the module
/// on `sudo`. The service keeps the refusal to the stacks that exist to
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

fn dm_login_bypass(ctx: &CallerContext) -> bool {
    ctx.service()
        .is_some_and(|service| DM_PREFIXES.iter().any(|prefix| service.dm_prefixed(prefix)))
        && !ctx.is_gdm_reauth()
}

fn gdm_reauth_worker(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("gdm-session-worker" | "gdm-session-wor")
    ) && ctx
        .service()
        .is_some_and(|service| service.eq_ignore_ascii_case("gdm-password"))
        && ctx.is_gdm_reauth()
}

fn polkit_agent(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("polkit-agent-helper-1" | "polkit-agent-he")
    )
}

fn kscreenlocker_worker(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("kscreenlocker_worker" | "kscreenlocker_w")
    )
}

/// `hyprlock` — the lock screen's worker thread.
///
/// Accepted risk: the host answers from a worker `std::thread` with a
/// mutex/condvar — a genuine concurrent race — and an unsynchronised
/// `resetConversation`/`checkWaiting`.
fn hyprlock(ctx: &CallerContext) -> bool {
    matches!(ctx.process().name(), Some("hyprlock"))
}

/// `xsecurelock` — the helper's own thread pool.
///
/// Accepted risk: the conversation is answered by the helper's own thread pool,
/// and `CallPAMWithRetries` can re-run the module up to three times.
fn xsecurelock(ctx: &CallerContext) -> bool {
    matches!(ctx.process().name(), Some("authproto_pam"))
}

/// `precollected_locks` — hosts that collect the password before `pam_authenticate`.
fn precollected_locks(ctx: &CallerContext) -> bool {
    matches!(
        ctx.process().name(),
        Some("swaylock" | "gtklock" | "i3lock")
    )
}

/// `polkit_service_without_proc` — polkit with an unreadable `/proc`.
///
/// The service comparison is exact bytes, deliberately: `POLKIT-1` with an
/// unreadable `/proc` stays sequential.
fn polkit_service_without_proc(ctx: &CallerContext) -> bool {
    matches!(ctx.process(), ProcessIdentity::Unknown)
        && ctx.service().is_some_and(|service| service.is("polkit-1"))
}

fn default_sequential(_ctx: &CallerContext) -> bool {
    true
}

/// One rule's audit record: its symbolic name, why it exists, and the in-tree
/// evidence for the behaviour it preserves. Test-only by construction, so the
/// shipped table carries no `dead_code` exemption.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct Audit {
    /// The rule's symbolic name (`dm_login_bypass`, …), which must be the row's
    /// own predicate: its citation has to land on `fn <name>`.
    pub(super) name: &'static str,
    /// Why the rule exists, in one sentence. An accepted risk stays on the
    /// predicate's own doc comment (`hyprlock`, `xsecurelock`).
    pub(super) why: &'static str,
    /// `file:line` citations the rule must be able to defend. Entries prefixed
    /// `external:` cite something outside this tree and are exempt from
    /// resolution.
    pub(super) evidence: &'static [&'static str],
}

/// `id`'s audit record. The `match` is exhaustive over `RuleId` with no
/// wildcard, so a rule added to the enum does not compile until its record is
/// written; the other direction — a record whose row was deleted from `RULES`
/// — is `audit_covers_rules`.
#[cfg(test)]
pub(super) fn audit(id: RuleId) -> Audit {
    match id {
        RuleId::RemoteRefuse => Audit {
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
        RuleId::DmLoginBypass => Audit {
            name: "dm_login_bypass",
            why: "the login manager has to populate `PAM_AUTHTOK` for the session \
                  keyring, and a grant without it is useless",
            evidence: &[
                "client-pam/src/policy/table.rs:155",
                "client-pam/src/outcome.rs:59",
            ],
        },
        RuleId::GdmReauthWorker => Audit {
            name: "gdm_reauth_worker",
            why: "a GDM reauthentication is driven by the session worker, whose \
                  conversation stays answerable while a worker thread waits",
            evidence: &[
                "client-pam/src/policy/table.rs:161",
                "client-pam/src/context.rs:80",
            ],
        },
        RuleId::PolkitAgent => Audit {
            name: "polkit_agent",
            why: "polkit's agent helper feeds its conversation from a separate \
                  process, so it can be answered while the caller waits",
            evidence: &[
                "client-pam/src/policy/table.rs:171",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::KscreenlockerWorker => Audit {
            name: "kscreenlocker_worker",
            why: "kscreenlocker 6.8's worker answers on Qt's D-Bus daemon thread, so \
                  the conversation survives the calling thread blocking",
            evidence: &[
                "client-pam/src/policy/table.rs:178",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::Hyprlock => Audit {
            name: "hyprlock",
            why: "hyprlock answers from a worker thread; its unsynchronised \
                  `resetConversation`/`checkWaiting` race is the accepted risk",
            evidence: &[
                "client-pam/src/policy/table.rs:190",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::Xsecurelock => Audit {
            name: "xsecurelock",
            why: "xsecurelock's helper answers from its own thread pool, at the cost \
                  of up to three rings when `CallPAMWithRetries` re-runs the module",
            evidence: &[
                "client-pam/src/policy/table.rs:198",
                "client-pam/src/mechanism/threaded.rs:170",
            ],
        },
        RuleId::PreCollectedLocks => Audit {
            name: "precollected_locks",
            why: "these hosts collected the password before `pam_authenticate`, so \
                  the phone must not be rung and the token is handed on instead",
            evidence: &[
                "client-pam/src/policy/table.rs:203",
                "client-pam/src/mechanism/handoff.rs:25",
            ],
        },
        RuleId::PolkitServiceWithoutProc => Audit {
            name: "polkit_service_without_proc",
            why: "polkit with an unreadable `/proc` cannot be shown to answer \
                  concurrently, so it stays on the threaded conversation",
            evidence: &[
                "client-pam/src/policy/table.rs:214",
                "client-pam/src/context.rs:164",
            ],
        },
        RuleId::DefaultSequential => Audit {
            name: "default_sequential",
            why: "every other caller is driven sequentially on the calling thread, \
                  which is slower but can never wedge the host's event loop",
            evidence: &[
                "client-pam/src/policy/table.rs:219",
                "client-pam/src/mechanism/sequential.rs:1",
            ],
        },
    }
}
