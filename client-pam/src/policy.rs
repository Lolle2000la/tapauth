//! The conversation policy: one ordered table of rules over
//! [`CallerContext`](crate::context::CallerContext).
//!
//! `RULES` is the single decision record. Each row carries its class (the
//! failure direction it is protecting), the one-line reason a reader consults,
//! the in-tree evidence for the behaviour it preserves, its predicate and its
//! decision. `classify` walks the table in order and takes the first row whose
//! predicate matches.
//!
//! Two types come out of `classify` — [`Classification::Skip`] and
//! [`Classification::Participate`] — so a skip cannot acquire a deadline, a plan
//! or a mechanism: [`SkipPolicy`] carries none of them. R10's predicate is
//! unconditional, so `classify` is total.
//!
//! Rule R2–R10 only: R1 (`remote_refuse`) arrives with the remote-presence
//! capture, which does not exist in this tree yet.

use crate::context::{CallerContext, ProcessIdentity, ServiceName};

/// What the module does with the call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classification {
    Skip(SkipPolicy),
    Participate(Participation),
}

/// Why the phone is not consulted at all.
///
/// `KeyringNeedsAuthtok` is R2's: the display manager's own stack has to
/// populate `PAM_AUTHTOK`, and issuing a second `PAM_PROMPT_ECHO_OFF` on a
/// greeter handle is what the bypass exists to prevent.
///
/// The *other* no-daemon path — R8's pre-collected handoff, which calls
/// `pam_get_authtok` and caches `PAM_AUTHTOK` — is deliberately **not** a skip:
/// it is `Participation { conversation: PreCollected }`, so the handoff can only
/// be reached through a participation and never through this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SkipPolicy {
    KeyringNeedsAuthtok,
}

/// How the host's PAM conversation may be driven.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Conversation {
    /// The conversation can be driven from a worker thread while the calling
    /// thread waits for the daemon.
    Threaded,
    /// The conversation must be left to the calling thread/host event loop.
    Sequential,
    /// The host collected the password before calling `pam_authenticate` and
    /// its conversation only replays it, so the phone is not consulted.
    PreCollected,
}

/// The failure direction a rule protects, stated once per class.
///
/// `Keyring` is orthogonal to the three failure directions: it is about the
/// value of a grant rather than the risk of asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FailureDirection {
    /// The phone must not be consulted at all.
    NeverRing,
    /// The conversation must not be driven from a second thread (or not driven
    /// at all); the wrong direction is a hang, so the safe one is "slower,
    /// never wedged".
    DeadlockAvoidance,
    /// The phone is offered concurrently; the host can answer while we wait.
    AlwaysRing,
    /// A grant would be useless without `PAM_AUTHTOK`.
    Keyring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Skip(SkipPolicy),
    Participate(Conversation),
}

/// A rule that matched, with the class it was authored against.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Participation {
    /// Which rule fired. Read by the policy tests today; consumed by the
    /// transaction's plan assertion once `transaction::run` exists.
    #[allow(dead_code)]
    pub(crate) rule: RuleId,
    pub(crate) conversation: Conversation,
    /// The rule's class, copied here so the failure direction is part of the
    /// value and not only of the table (`class_agrees_with_conversation`).
    #[allow(dead_code)]
    pub(crate) failure_direction: FailureDirection,
}

/// A rule's stable id. The fixture corpus names it in its `expected_rule`
/// column.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RuleId {
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
}

impl RuleId {
    /// The spelling the fixture corpus uses (`R2` … `R10`).
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RuleId::R2 => "R2",
            RuleId::R3 => "R3",
            RuleId::R4 => "R4",
            RuleId::R5 => "R5",
            RuleId::R6 => "R6",
            RuleId::R7 => "R7",
            RuleId::R8 => "R8",
            RuleId::R9 => "R9",
            RuleId::R10 => "R10",
        }
    }
}

/// One row of the table.
///
/// `name`, `why` and `evidence` are the justification record: the shipped binary
/// does not read them, and the policy tests do (uniqueness, corpus coverage and
/// citation resolution), so they are exempt from the dead-code lint rather than
/// dropped.
#[allow(dead_code)]
pub(crate) struct Rule {
    pub(crate) id: RuleId,
    /// The rule's symbolic name (`dm_login_bypass`, …).
    pub(crate) name: &'static str,
    pub(crate) class: FailureDirection,
    /// One line: why this host is answered this way.
    pub(crate) why: &'static str,
    /// `file:line` citations the rule must be able to defend. Entries prefixed
    /// `external:` cite something outside this tree and are exempt from
    /// resolution.
    pub(crate) evidence: &'static [&'static str],
    pub(crate) predicate: fn(&CallerContext) -> bool,
    pub(crate) decision: Decision,
}

/// The conversation policy, in order. R2 precedes everything after it (the
/// keyring constraint belongs to the service, not to the process), and R10 is
/// last and unconditional.
pub(crate) static RULES: [Rule; 9] = [
    Rule {
        id: RuleId::R2,
        name: "dm_login_bypass",
        class: FailureDirection::Keyring,
        why: "a grant without PAM_AUTHTOK breaks pam_kwallet6/pam_gnome_keyring auto-unlock",
        evidence: &[
            "client-pam/src/policy.rs:306",
            "client-pam/src/pam_logic.rs:1350",
        ],
        predicate: dm_login_bypass,
        decision: Decision::Skip(SkipPolicy::KeyringNeedsAuthtok),
    },
    Rule {
        id: RuleId::R3,
        name: "gdm_reauth_worker",
        class: FailureDirection::DeadlockAvoidance,
        why: "the worker's GLib loop answers on another thread, but only for a \
              reauthentication; a login is bypassed by R2",
        evidence: &[
            "client-pam/src/policy.rs:319",
            "client-pam/src/context.rs:74",
        ],
        predicate: gdm_reauth_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R4,
        name: "polkit_agent",
        class: FailureDirection::DeadlockAvoidance,
        why: "the conversation is a plain fd fed by the separate agent process",
        evidence: &[
            "client-pam/src/policy.rs:330",
            "client-pam/src/pam_logic.rs:287",
        ],
        predicate: polkit_agent,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R5,
        name: "kscreenlocker_worker",
        class: FailureDirection::DeadlockAvoidance,
        why: "the >= 6.8 helper answers on Qt's daemon thread; no version is parsed, \
              and kscreenlocker_greet stays sequential",
        evidence: &[
            "client-pam/src/policy.rs:338",
            "client-pam/src/pam_logic.rs:288",
        ],
        predicate: kscreenlocker_worker,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R6,
        name: "hyprlock",
        class: FailureDirection::AlwaysRing,
        why: "a worker std::thread with mutex/condvar: a genuine concurrent race, \
              accepted with an unsynchronised resetConversation/checkWaiting",
        evidence: &[
            "client-pam/src/policy.rs:346",
            "client-pam/src/pam_logic.rs:285",
        ],
        predicate: hyprlock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R7,
        name: "xsecurelock",
        class: FailureDirection::AlwaysRing,
        why: "answered by the helper's own thread pool; CallPAMWithRetries can \
              re-run the module up to three times",
        evidence: &[
            "client-pam/src/policy.rs:351",
            "client-pam/src/pam_logic.rs:286",
        ],
        predicate: xsecurelock,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R8,
        name: "precollected_locks",
        class: FailureDirection::NeverRing,
        why: "the password predates pam_authenticate (swaylock pam.c:51, gtklock \
              auth.c:61, i3lock.c:836), so the phone must not be rung",
        evidence: &[
            "client-pam/src/policy.rs:356",
            "client-pam/src/pam_logic.rs:294",
        ],
        predicate: precollected_locks,
        decision: Decision::Participate(Conversation::PreCollected),
    },
    Rule {
        id: RuleId::R9,
        name: "polkit_service_without_proc",
        class: FailureDirection::DeadlockAvoidance,
        why: "with /proc unreadable, keep the historic polkit behaviour instead \
              of silently changing how it drives its conversation",
        evidence: &[
            "client-pam/src/policy.rs:368",
            "client-pam/src/context.rs:160",
        ],
        predicate: polkit_service_without_proc,
        decision: Decision::Participate(Conversation::Threaded),
    },
    Rule {
        id: RuleId::R10,
        name: "default_sequential",
        class: FailureDirection::DeadlockAvoidance,
        why: "the safe default: an unknown host keeps the behaviour that cannot \
              deadlock, at the cost of the shorter GUI timeout",
        evidence: &[
            "client-pam/src/policy.rs:374",
            "client-pam/src/pam_logic.rs:302",
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
const DEFAULT_SEQUENTIAL: Classification = Classification::Participate(Participation {
    rule: RuleId::R10,
    conversation: Conversation::Sequential,
    failure_direction: FailureDirection::DeadlockAvoidance,
});

/// The display-manager prefixes.
///
/// A service matches when its ASCII-lowercased name is a prefix exactly, or the
/// prefix followed by a `-` boundary: `gdm`, `gdm3` and `gdm-password` qualify,
/// `gdmfoo` does not. Folding is `to_ascii_lowercase` only — see
/// [`ServiceName`] — so U+212A KELVIN SIGN is *not* folded to `k`.
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

/// Whether `service` names a primary display manager; an absent service never
/// matches.
pub(crate) fn is_dm_service(service: &str) -> bool {
    let service = ServiceName::new(service);
    DM_PREFIXES.iter().any(|prefix| service.dm_prefixed(prefix))
}

/// R2 — the display-manager bypass, with the GDM reauthentication exemption.
fn dm_login_bypass(ctx: &CallerContext) -> bool {
    ctx.service()
        .is_some_and(|service| is_dm_service(service.original()))
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
fn hyprlock(ctx: &CallerContext) -> bool {
    matches!(ctx.process().name(), Some("hyprlock"))
}

/// R7 — xsecurelock's helper.
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

/// The first rule that matches wins; R10 is unconditional, so this is total.
pub(crate) fn classify(ctx: &CallerContext) -> Classification {
    RULES
        .iter()
        .find(|rule| (rule.predicate)(ctx))
        .map_or(DEFAULT_SEQUENTIAL, classification_of)
}

fn classification_of(rule: &Rule) -> Classification {
    match rule.decision {
        Decision::Skip(policy) => Classification::Skip(policy),
        Decision::Participate(conversation) => Classification::Participate(Participation {
            rule: rule.id,
            conversation,
            failure_direction: rule.class,
        }),
    }
}

/// The conversation the *process-keyed* rules choose, i.e. today's
/// `conversation_mode`.
///
/// R2 is excluded because it never ran inside `conversation_mode`: the bypass
/// preceded it, so the process rule applies even to a display-manager service.
/// This is the step-1 compatibility shim for that function and goes away with
/// it.
#[cfg(test)]
pub(crate) fn conversation_mode_of(ctx: &CallerContext) -> Conversation {
    RULES
        .iter()
        .filter(|rule| rule.id != RuleId::R2)
        .find_map(|rule| match rule.decision {
            Decision::Participate(conversation) if (rule.predicate)(ctx) => Some(conversation),
            _ => None,
        })
        .unwrap_or(Conversation::Sequential)
}

/// The fixture corpus (`client-pam/tests/fixtures/callers.csv`) is this table's
/// oracle, and the policy tests below are its consumers.
///
/// The rows were authored against the *pre-refactor* functions (the
/// characterisation step), so a row is an expectation written before the code
/// that has to satisfy it. What the corpus pins and what it does not: it feeds
/// the table *literal* inputs — the service string, `classify_identity(exe,
/// comm)` from the two identity columns and `GdmReauth::from_env` from the
/// `env` column. It does not pin the reads that produce those inputs
/// (`/proc/self/exe`, `/proc/self/comm`, `GDM_SESSION_FOR_REAUTH`): no unit test
/// can characterise a `/proc` read portably, and a test that called `set_var`
/// would race every other test in this binary that reads the environment. The
/// end-to-end shapes in `scripts/ci/test-pam-conv-thread.sh` stay the proof for
/// the reads.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::context::{classify_identity, GdmReauth};
    use std::ffi::OsStr;
    use std::path::Path;

    const CORPUS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/callers.csv");

    /// The schema the corpus parser demands, in column order.
    const HEADER: &str = "id,service,exe,comm,env,tty,expected_rule,expected_policy,why,e2e";

    /// What the module decides to do with a call.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Policy {
        SkipRemote,
        SkipKeyring,
        Threaded,
        Sequential,
        PreCollected,
    }

    /// Where the resolved process name came from.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Provenance {
        Exe,
        Comm,
        Unknown,
    }

    struct Row {
        id: String,
        service: Option<String>,
        exe: Option<String>,
        comm: Option<String>,
        env: Option<String>,
        tty: bool,
        expected_rule: String,
        expected_policy: Policy,
        why: String,
        e2e: bool,
    }

    fn parse_bool(field: &str) -> bool {
        match field {
            "0" => false,
            "1" => true,
            other => panic!("{other:?} is not a 0/1 column value"),
        }
    }

    /// `-` is "unreadable"/"unset"; `~` is the literal empty string, which is a
    /// different input from a missing one.
    fn name_field(field: &str) -> Option<String> {
        match field {
            "-" => None,
            "~" => Some(String::new()),
            other => Some(other.to_owned()),
        }
    }

    fn optional_field(field: &str) -> Option<String> {
        match field {
            "-" => None,
            other => Some(other.to_owned()),
        }
    }

    fn parse_policy(field: &str) -> Policy {
        match field {
            "skip_remote" => Policy::SkipRemote,
            "skip_keyring" => Policy::SkipKeyring,
            "threaded" => Policy::Threaded,
            "sequential" => Policy::Sequential,
            "precollected" => Policy::PreCollected,
            other => panic!("{other:?} is not a known expected_policy"),
        }
    }

    fn parse_row(line: &str) -> Row {
        let fields: Vec<&str> = line.split(',').collect();
        // A `why` containing a comma is a parse error, not a quoted field.
        assert_eq!(
            fields.len(),
            10,
            "row {line}: a field contains a comma (10 columns expected)"
        );
        Row {
            id: fields[0].to_owned(),
            service: optional_field(fields[1]),
            exe: name_field(fields[2]),
            comm: name_field(fields[3]),
            env: optional_field(fields[4]),
            tty: parse_bool(fields[5]),
            expected_rule: fields[6].to_owned(),
            expected_policy: parse_policy(fields[7]),
            why: fields[8].to_owned(),
            e2e: parse_bool(fields[9]),
        }
    }

    fn rows() -> Vec<Row> {
        let text =
            std::fs::read_to_string(CORPUS_PATH).expect("the fixture corpus must be readable");
        let header = text
            .lines()
            .next()
            .expect("the fixture corpus has a header");
        assert_eq!(header, HEADER, "the fixture corpus changed its schema");
        let rows: Vec<Row> = text
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(parse_row)
            .collect();
        assert!(!rows.is_empty(), "the fixture corpus has no rows");
        for (index, row) in rows.iter().enumerate() {
            assert!(
                !rows.iter().skip(index + 1).any(|other| other.id == row.id),
                "duplicate row id {:?}",
                row.id
            );
        }
        rows
    }

    fn provenance(identity: &ProcessIdentity) -> Provenance {
        match identity {
            ProcessIdentity::Exe(_) => Provenance::Exe,
            ProcessIdentity::Comm(_) => Provenance::Comm,
            ProcessIdentity::Unknown => Provenance::Unknown,
        }
    }

    /// The provenance the two identity columns imply: a non-empty `exe` wins,
    /// otherwise a non-blank `comm`, otherwise nothing.
    fn expected_provenance(row: &Row) -> Provenance {
        if row.exe.as_deref().is_some_and(|exe| !exe.is_empty()) {
            Provenance::Exe
        } else if row
            .comm
            .as_deref()
            .is_some_and(|comm| !comm.trim().is_empty())
        {
            Provenance::Comm
        } else {
            Provenance::Unknown
        }
    }

    /// The context a row describes, built from the row's columns.
    fn row_context(row: &Row, identity: &ProcessIdentity, reauth: GdmReauth) -> CallerContext {
        CallerContext::from_parts(row.service.as_deref(), identity.clone(), reauth)
    }

    /// The rule that classified a row. Every skip policy belongs to exactly one
    /// rule (`Classification` carries no rule id for a skip), so the mapping is
    /// explicit here: `KeyringNeedsAuthtok` is R2's.
    fn rule_of(classification: &Classification) -> Option<RuleId> {
        match classification {
            Classification::Participate(participation) => Some(participation.rule),
            Classification::Skip(SkipPolicy::KeyringNeedsAuthtok) => Some(RuleId::R2),
        }
    }

    fn policy_of(classification: &Classification) -> Policy {
        match classification {
            Classification::Skip(SkipPolicy::KeyringNeedsAuthtok) => Policy::SkipKeyring,
            Classification::Participate(participation) => match participation.conversation {
                Conversation::Threaded => Policy::Threaded,
                Conversation::Sequential => Policy::Sequential,
                Conversation::PreCollected => Policy::PreCollected,
            },
        }
    }

    fn rule_by_id(id: RuleId) -> Option<&'static Rule> {
        RULES.iter().find(|rule| rule.id == id)
    }

    /// A context in which `name` should fire rule `id`.
    fn context_for_process(id: RuleId, name: &str) -> CallerContext {
        let process = ProcessIdentity::Exe(name.into());
        match id {
            RuleId::R3 => {
                CallerContext::from_parts(Some("gdm-password"), process, GdmReauth::Present)
            }
            _ => CallerContext::from_parts(Some("kde"), process, GdmReauth::Absent),
        }
    }

    #[test]
    fn corpus_characterises_the_decision_table() {
        for row in rows() {
            assert!(!row.why.is_empty(), "row {} has no justification", row.id);
            assert!(
                row.expected_rule.strip_prefix('R').is_some_and(|number| {
                    number.parse::<u8>().is_ok_and(|n| (1..=10).contains(&n))
                }),
                "row {}: expected_rule {:?} is not R1..R10",
                row.id,
                row.expected_rule
            );
            // `/dev/tty` is only probed for a sequential conversation, so a
            // host that never reaches that branch cannot carry a terminal.
            assert!(
                !row.tty || matches!(row.expected_policy, Policy::Sequential | Policy::Threaded),
                "row {}: a pre-collected or skipped host has no terminal branch",
                row.id
            );
            // A shape the shell harness must run needs a binary name to copy
            // the harness to.
            assert!(
                !row.e2e || row.exe.is_some(),
                "row {}: an e2e row must set its exe column",
                row.id
            );

            let identity =
                classify_identity(row.exe.as_deref().map(Path::new), row.comm.as_deref());
            assert_eq!(
                provenance(&identity),
                expected_provenance(&row),
                "row {}: exe {:?} / comm {:?} resolved to the wrong source",
                row.id,
                row.exe,
                row.comm
            );

            let reauth = GdmReauth::from_env(row.env.as_deref().map(OsStr::new));
            assert_eq!(
                reauth == GdmReauth::Present,
                row.env.is_some(),
                "row {}: GDM_SESSION_FOR_REAUTH is presence-only, so {} is present",
                row.id,
                row.env.as_deref().unwrap_or("-")
            );

            let classification = classify(&row_context(&row, &identity, reauth));
            assert_eq!(
                rule_of(&classification).map(RuleId::as_str),
                Some(row.expected_rule.as_str()),
                "row {} ({}): classify fired the wrong rule",
                row.id,
                row.why
            );
            assert_eq!(
                policy_of(&classification),
                row.expected_policy,
                "row {} ({}): classify produced the wrong policy",
                row.id,
                row.why
            );
        }
    }

    /// Every rule in the table has at least one corpus row that names it.
    ///
    /// The check iterates `RULES`, not the corpus: iterating the corpus cannot
    /// see a rule added without a fixture, which is the case that matters.
    #[test]
    fn corpus_covers_every_rule() {
        let rows = rows();
        for rule in RULES.iter() {
            assert!(
                rows.iter().any(|row| row.expected_rule == rule.id.as_str()),
                "rule {} ({}) has no corpus row: add one to \
                 client-pam/tests/fixtures/callers.csv",
                rule.id.as_str(),
                rule.name
            );
            assert_eq!(
                RULES.iter().filter(|other| other.name == rule.name).count(),
                1,
                "rule name {:?} is used twice",
                rule.name
            );
        }
    }

    /// A rule's class and its conversation must agree; a class/conversation
    /// pair that does not is a table defect rather than a comment nobody reads.
    #[test]
    fn class_agrees_with_conversation() {
        for rule in RULES.iter() {
            assert!(
                class_permits(rule.class, &rule.decision),
                "rule {} ({}) pairs {:?} with a decision it does not permit",
                rule.id.as_str(),
                rule.name,
                rule.class
            );
        }

        for row in rows() {
            let identity =
                classify_identity(row.exe.as_deref().map(Path::new), row.comm.as_deref());
            let reauth = GdmReauth::from_env(row.env.as_deref().map(OsStr::new));
            match classify(&row_context(&row, &identity, reauth)) {
                Classification::Participate(participation) => assert!(
                    class_permits(
                        participation.failure_direction,
                        &Decision::Participate(participation.conversation)
                    ),
                    "row {}: {:?} cannot be answered with {:?}",
                    row.id,
                    participation.failure_direction,
                    participation.conversation
                ),
                Classification::Skip(_) => {
                    let rule = rule_of(&classify(&row_context(&row, &identity, reauth)))
                        .and_then(rule_by_id);
                    assert_eq!(
                        rule.map(|rule| rule.class),
                        Some(FailureDirection::Keyring),
                        "row {}: only a Keyring rule may skip the phone",
                        row.id
                    );
                }
            }
        }
    }

    fn class_permits(class: FailureDirection, decision: &Decision) -> bool {
        matches!(
            (class, decision),
            (FailureDirection::Keyring, Decision::Skip(_))
                | (
                    FailureDirection::NeverRing,
                    Decision::Participate(Conversation::PreCollected)
                )
                | (
                    FailureDirection::AlwaysRing,
                    Decision::Participate(Conversation::Threaded)
                )
                | (
                    FailureDirection::DeadlockAvoidance,
                    Decision::Participate(_)
                )
        )
    }

    /// The process-keyed rules own disjoint literal sets, so their order is not
    /// load-bearing; R9 keys on a *missing* identity instead.
    ///
    /// The literals are declared here rather than derived from the table
    /// because a set cannot be read back out of a `fn` pointer; the test then
    /// checks the *predicates* against them, so a spelling added to a second
    /// rule, or a rule whose predicate drifts off its declared set, fails.
    #[test]
    fn rules_are_process_disjoint() {
        let keys: &[(RuleId, &[&str])] = &[
            (RuleId::R3, &["gdm-session-worker", "gdm-session-wor"]),
            (RuleId::R4, &["polkit-agent-helper-1", "polkit-agent-he"]),
            (RuleId::R5, &["kscreenlocker_worker", "kscreenlocker_w"]),
            (RuleId::R6, &["hyprlock"]),
            (RuleId::R7, &["authproto_pam"]),
            (RuleId::R8, &["swaylock", "gtklock", "i3lock"]),
        ];

        for (index, (id_a, keys_a)) in keys.iter().enumerate() {
            for (id_b, keys_b) in keys.iter().skip(index + 1) {
                for key in *keys_a {
                    assert!(
                        !keys_b.contains(key),
                        "{key:?} is a key of both {id_a:?} and {id_b:?}"
                    );
                }
            }
        }

        for (id, owned) in keys {
            for key in *owned {
                let ctx = context_for_process(*id, key);
                let fired = RULES
                    .iter()
                    .find(|rule| (rule.predicate)(&ctx))
                    .map(|rule| rule.id);
                assert_eq!(
                    fired,
                    Some(*id),
                    "{key:?} must fire {id:?}, not the rule that matched"
                );
            }
        }

        for name in ["sh", "kscreenlocker_worker2", "polkit-agent-helper"] {
            let ctx = CallerContext::from_parts(
                Some("kde"),
                ProcessIdentity::Exe(name.into()),
                GdmReauth::Absent,
            );
            assert_eq!(
                rule_of(&classify(&ctx)),
                Some(RuleId::R10),
                "{name:?} is nobody's key and must fall to the default"
            );
        }

        // R9's key is the absence of a process name, and its service comparison
        // is exact bytes.
        let unknown_polkit = CallerContext::from_parts(
            Some("polkit-1"),
            ProcessIdentity::Unknown,
            GdmReauth::Absent,
        );
        assert_eq!(rule_of(&classify(&unknown_polkit)), Some(RuleId::R9));
        let named_polkit = context_for_process(RuleId::R5, "kscreenlocker_worker");
        assert_eq!(rule_of(&classify(&named_polkit)), Some(RuleId::R5));
    }

    /// A rule placed after the unconditional R10 is dead, and no other rule may
    /// be unconditional.
    #[test]
    fn unreachable_rule_rows() {
        // The null context matches nothing but the default: no service, no
        // process name, no reauth flag.
        let null = CallerContext::from_parts(None, ProcessIdentity::Unknown, GdmReauth::Absent);

        let last = RULES.last().expect("the rule table is not empty");
        assert_eq!(
            last.id,
            RuleId::R10,
            "R10 must be the last row, or the rows after it are dead"
        );
        assert!(
            (last.predicate)(&null),
            "R10's predicate must be unconditional"
        );
        for rule in RULES.iter().filter(|rule| rule.id != RuleId::R10) {
            assert!(
                !(rule.predicate)(&null),
                "rule {} ({}) matches the null context, so it is unconditional and \
                 every row after it is dead",
                rule.id.as_str(),
                rule.name
            );
        }

        // The fallback `classify` uses if the table ever stops matching is
        // exactly what R10 produces.
        assert_eq!(classify(&null), DEFAULT_SEQUENTIAL);
    }

    /// Every `evidence` citation resolves in this tree, and the scan reports
    /// which files it checked so a relocated or emptied table cannot pass
    /// silently. Entries marked `external:` cite a specification or an
    /// out-of-tree program and are exempt.
    #[test]
    fn evidence_citations_resolve() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("client-pam lives in the workspace root");
        let mut checked: Vec<&str> = Vec::new();

        for rule in RULES.iter() {
            assert!(
                !rule.evidence.is_empty(),
                "rule {} ({}) has no evidence",
                rule.id.as_str(),
                rule.name
            );
            for citation in rule.evidence {
                if let Some(external) = citation.strip_prefix("external:") {
                    assert!(
                        !external.trim().is_empty(),
                        "rule {} has an empty external citation",
                        rule.name
                    );
                    continue;
                }
                let (file, range) = citation
                    .rsplit_once(':')
                    .unwrap_or_else(|| panic!("rule {}: {citation:?} is not file:line", rule.name));
                let text = std::fs::read_to_string(root.join(file)).unwrap_or_else(|error| {
                    panic!(
                        "rule {}: citation {citation:?} does not resolve: {error}",
                        rule.name
                    )
                });
                let total = text.lines().count();
                let number = |field: &str| {
                    field.trim().parse::<usize>().unwrap_or_else(|_| {
                        panic!("rule {}: {citation:?} has a non-numeric line", rule.name)
                    })
                };
                let (start, end) = match range.split_once('-') {
                    Some((start, end)) => (number(start), number(end)),
                    None => {
                        let line = number(range);
                        (line, line)
                    }
                };
                assert!(
                    start >= 1 && end >= start && end <= total,
                    "rule {}: citation {citation:?} is outside {file} ({total} lines)",
                    rule.name
                );
                assert!(
                    text.lines()
                        .nth(start - 1)
                        .is_some_and(|line| !line.trim().is_empty()),
                    "rule {}: citation {citation:?} points at a blank line",
                    rule.name
                );
                checked.push(file);
            }
        }

        assert!(
            checked.contains(&"client-pam/src/policy.rs"),
            "the citation scan never looked at this table's own file: {checked:?}"
        );
    }
}
