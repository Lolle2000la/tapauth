//! The conversation policy: one ordered table of rules over
//! [`CallerContext`](crate::context::CallerContext), and the two phases that
//! consume it.
//!
//! Three responsibilities, three files:
//!
//! * `table.rs` is the decision record: `RULES`, one row per host, carrying the
//!   class the row was authored against (the failure direction it protects), the
//!   in-tree evidence for the behaviour it preserves, its predicate and its
//!   decision.
//! * this file is the taxonomy those rows are written in ([`Classification`],
//!   [`Decision`], [`Participation`], [`Conversation`], [`FailureDirection`],
//!   [`SkipPolicy`]) and the first-match engine: `classify` walks the table in
//!   order and returns the id of the row that matched, next to the
//!   classification that row produces.
//! * `refine.rs` is the config-dependent second phase, which may only add a
//!   skip.
//!
//! Two types come out of `classify` — [`Classification::Skip`] and
//! [`Classification::Participate`] — so a skip cannot acquire a deadline, a plan
//! or a mechanism: [`SkipPolicy`] carries none of them. R10's predicate is
//! unconditional, so `classify` is total.
//!
//! R1 (`remote_refuse`) keys on the PAM service name alone: the module never
//! reads `PAM_RHOST`, because `sudo` sets it to the local hostname
//! (`Defaults pam_rhost`), so a presence-only rule would silence the module on
//! `sudo`. R2 keys only on the display-manager prefixes, so R1's and R2's
//! predicates are disjoint and their relative order is unobservable; what is
//! load-bearing is R1 before the process rules (R3–R8) and before R10.

use crate::context::CallerContext;

mod refine;
mod table;

pub(crate) use refine::refine;

use table::{Rule, DEFAULT_SEQUENTIAL, RULES};

/// What the module does with the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Classification {
    Skip(SkipPolicy),
    Participate(Participation),
}

/// Why the phone is not consulted at all.
///
/// `RemoteAuthentication` is R1's: the module must not take part in a remote
/// authentication at all, and the skip happens before any config read, username
/// lookup, conversation construction or message load.
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
    RemoteAuthentication,
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
/// `Keyring` and `RefuseRemote` are orthogonal to the three failure directions:
/// `Keyring` is about the value of a grant rather than the risk of asking, and
/// `RefuseRemote` is a scope decision — this call is not ours to answer at all.
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
    /// The module must not participate in a remote authentication. Its
    /// under-match (a remote caller classified local) is the security cost —
    /// the phone is rung for a login nobody is sitting at — and its over-match
    /// (a local caller classified remote) silences the phone for a local login.
    RefuseRemote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Skip(SkipPolicy),
    Participate(Conversation),
}

/// A rule that matched, with the class it was authored against.
///
/// Which rule matched is not part of the value: `classify` returns its id next
/// to it, so no field is carried that only the tests would read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Participation {
    pub(crate) conversation: Conversation,
    /// The rule's class, copied here so the failure direction is part of the
    /// value and not only of the table (`class_agrees_with_conversation`). Read
    /// in production by `transaction::run`'s class/plan assertion.
    pub(crate) failure_direction: FailureDirection,
}

/// A rule's stable id. The fixture corpus names it in its `expected_rule`
/// column.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RuleId {
    R1,
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
    /// The spelling the fixture corpus uses (`R1` … `R10`).
    #[cfg(test)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RuleId::R1 => "R1",
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

/// The first rule that matches wins; R10 is unconditional, so this is total.
///
/// The id comes back next to the classification: the row is what a failing test
/// names, and a `Participation` carrying it would carry a field nothing in the
/// shipped binary reads.
pub(crate) fn classify(ctx: &CallerContext) -> (RuleId, Classification) {
    RULES
        .iter()
        .find(|rule| (rule.predicate)(ctx))
        .map_or((RuleId::R10, DEFAULT_SEQUENTIAL), |rule| {
            (rule.id, classification_of(rule))
        })
}

fn classification_of(rule: &Rule) -> Classification {
    match rule.decision {
        Decision::Skip(policy) => Classification::Skip(policy),
        Decision::Participate(conversation) => Classification::Participate(Participation {
            conversation,
            failure_direction: rule.class,
        }),
    }
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
// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::refine::refused_service;
    use super::*;
    use crate::config::PamConfig;
    use crate::context::{classify_identity, GdmReauth, ProcessIdentity, ServiceName};
    use crate::plan::{Announcement, Deadline, Plan, Plannable, TtyUse};
    use std::ffi::OsStr;
    use std::path::Path;

    const CORPUS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/callers.csv");

    /// The decision record, relative to the workspace root.
    const TABLE_PATH: &str = "client-pam/src/policy/table.rs";

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

    /// The rule an id-less classification belongs to. `classify` reports the id
    /// itself; `refine` returns a bare `Classification`, so its skip is mapped
    /// back through the policy, which belongs to exactly one rule
    /// (`RemoteAuthentication` is R1's and `KeyringNeedsAuthtok` is R2's). A
    /// participation carries no id at all, so it maps to nothing here.
    fn skip_rule(classification: &Classification) -> Option<RuleId> {
        match classification {
            Classification::Skip(SkipPolicy::RemoteAuthentication) => Some(RuleId::R1),
            Classification::Skip(SkipPolicy::KeyringNeedsAuthtok) => Some(RuleId::R2),
            Classification::Participate(_) => None,
        }
    }

    fn policy_of(classification: &Classification) -> Policy {
        match classification {
            Classification::Skip(policy) => policy_for_decision(&Decision::Skip(*policy)),
            Classification::Participate(participation) => {
                policy_for_decision(&Decision::Participate(participation.conversation))
            }
        }
    }

    /// The corpus spelling of a table decision.
    fn policy_for_decision(decision: &Decision) -> Policy {
        match decision {
            Decision::Skip(SkipPolicy::RemoteAuthentication) => Policy::SkipRemote,
            Decision::Skip(SkipPolicy::KeyringNeedsAuthtok) => Policy::SkipKeyring,
            Decision::Participate(Conversation::Threaded) => Policy::Threaded,
            Decision::Participate(Conversation::Sequential) => Policy::Sequential,
            Decision::Participate(Conversation::PreCollected) => Policy::PreCollected,
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

    /// The terminal state each participating row models, written out by hand.
    ///
    /// This is the oracle the corpus's `tty` column is checked against, and it
    /// is a literal for a reason: the §3.4.1 plan cell is a function of `tty`,
    /// so an expected plan derived from the column under test agrees with a
    /// wrong value by construction. Derived that way, only a row whose column
    /// contradicted its own `expected_policy` could fail; a fixture row whose
    /// `tty` simply misdescribed its host stayed green. The literal names the
    /// host instead, so flipping any row's value — `sequential_with_tty`
    /// losing its `1`, or `threaded_no_tty` gaining one — fails here.
    ///
    /// Every row whose `expected_policy` is `Threaded` or `Sequential` (the only
    /// rows that reach a `Plan`) must appear exactly once; no other row may
    /// appear. `daemon_timeout` is the e2e row proving a daemon-side timeout is
    /// silent: R5, threaded, no terminal.
    const EXPECTED_TTY: &[(&str, bool)] = &[
        // Threaded.  The plan is Operation/Wait/DoNotOpen whatever the value,
        // and the hosts are lock-screen, polkit and GDM helpers that own no
        // terminal — except `threaded_with_tty_unreachable`, which carries a `1`
        // precisely to show the column cannot change a threaded decision.
        ("daemon_timeout", false),
        ("reauth_zero_value", false),
        ("mixed_case_gdm", false),
        ("threaded_gdm_worker_truncated", false),
        ("threaded_polkit_agent", false),
        ("threaded_polkit_agent_truncated", false),
        ("comm_only_fallback", false),
        ("exe_beats_comm", false),
        ("kscreenlocker_truncated", false),
        ("service_unknown", false),
        ("threaded_no_tty", false),
        ("threaded_with_tty_unreachable", true),
        ("threaded_hyprlock", false),
        ("threaded_xsecurelock", false),
        ("proc_unreadable_polkit", false),
        // Sequential.  `sequential_with_tty` is the `login`/`su` shape where the
        // Enter skip exists; every other row is a screen saver, an unknown
        // binary or a near miss with no terminal on the calling side.
        ("dm_ly_not", false),
        ("dm_kelvin", false),
        ("sddmfoo_not_dm", false),
        ("unknown_binary", false),
        ("renamed_binary", false),
        ("reauth_wrong_service", false),
        ("proc_unreadable_polkit_upper", false),
        ("proc_unreadable_other", false),
        ("empty_process_name", false),
        ("kscreenlocker_greet", false),
        ("service_unknown_polkit", false),
        ("sequential_with_tty", true),
        ("sequential_no_tty", false),
        ("service_case_sudo", false),
        ("service_case_SUDO", false),
        ("svc_sshd_near_miss", false),
        ("svc_unknown_not_sshd", false),
        ("kscreenlocker_g", false),
        ("xfce4_screensav", false),
        ("mate_screensaver_dialog", false),
        ("mate_screensave", false),
    ];

    /// The terminal state `EXPECTED_TTY` gives a row, or a panic naming the row.
    ///
    /// Callers only reach it for a participating row, after the set check in
    /// `corpus_characterises_the_decision_table`.
    fn expected_tty(id: &str) -> bool {
        EXPECTED_TTY
            .iter()
            .find(|(name, _)| *name == id)
            .map(|(_, tty)| *tty)
            .unwrap_or_else(|| panic!("row {id} is missing from EXPECTED_TTY"))
    }

    /// Every corpus row classifies to the rule and policy it names, and a
    /// participating row's `tty` column matches the host it models.
    ///
    /// What the column-by-column feeding covers: the `exe`/`comm` pair is fed to
    /// `classify_identity` before `classify`, so a precedence or `(deleted)`
    /// regression fails at the column that caused it; `env` goes through
    /// `GdmReauth::from_env`, so presence-only parsing is exercised rather than
    /// assumed. The `tty` column is checked against `EXPECTED_TTY`, a literal
    /// independent of the fixture, and only then fed to `Plannable::plan` — the
    /// column cannot be its own oracle, because the plan is a function of it
    /// (see `EXPECTED_TTY`). `skip_*` and `precollected` rows have no `Plan` —
    /// the skip returns before a plan exists and the handoff returns before the
    /// probe — so they assert the classification only.
    #[test]
    fn corpus_characterises_the_decision_table() {
        let rows = rows();

        // The literal table and the set of rows that carry a plan must be the
        // same set: one entry per participating row, and no entry for a row that
        // is missing or carries no plan.
        let participating: Vec<&Row> = rows
            .iter()
            .filter(|row| matches!(row.expected_policy, Policy::Threaded | Policy::Sequential))
            .collect();
        for row in &participating {
            let entries = EXPECTED_TTY.iter().filter(|(id, _)| *id == row.id).count();
            assert_eq!(
                entries, 1,
                "row {}: EXPECTED_TTY must carry exactly one entry for it, found {}",
                row.id, entries
            );
        }
        for (id, _) in EXPECTED_TTY {
            assert!(
                participating.iter().any(|row| row.id == *id),
                "{id}: EXPECTED_TTY names a row that is missing or has no plan"
            );
        }

        for row in &rows {
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
                expected_provenance(row),
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

            let (rule, classification) = classify(&row_context(row, &identity, reauth));
            assert_eq!(
                rule.as_str(),
                row.expected_rule.as_str(),
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

            // The `tty` column is `plan`'s only input, so it is first checked
            // against the host it models (`EXPECTED_TTY`, a literal) and the
            // §3.4.1 cell is then derived from that expectation — never from the
            // column, which would make a drifted value agree with itself.
            match row.expected_policy {
                Policy::Threaded | Policy::Sequential => {
                    assert_eq!(
                        row.tty,
                        expected_tty(&row.id),
                        "row {} ({}): the tty column disagrees with the host it models",
                        row.id,
                        row.why
                    );
                    let tty = expected_tty(&row.id);
                    match row.expected_policy {
                        Policy::Threaded => assert_eq!(
                            Plannable::Threaded.plan(tty),
                            Plan {
                                deadline: Deadline::Operation,
                                announcement: Announcement::Wait,
                                tty_use: TtyUse::DoNotOpen,
                            },
                            "row {}: a threaded host plans Operation/Wait/DoNotOpen for \
                             either tty value",
                            row.id
                        ),
                        _ => assert_eq!(
                            Plannable::Sequential.plan(tty),
                            Plan {
                                deadline: if tty {
                                    Deadline::Operation
                                } else {
                                    Deadline::GuiBounded
                                },
                                announcement: if tty {
                                    Announcement::WaitSkipHint
                                } else {
                                    Announcement::WaitThenPassword
                                },
                                tty_use: if tty {
                                    TtyUse::PollForKey
                                } else {
                                    TtyUse::DoNotOpen
                                },
                            },
                            "row {} ({}): the sequential plan must match the host's terminal",
                            row.id,
                            row.why
                        ),
                    }
                }
                // A skip returns before a plan exists and the pre-collected
                // handoff returns before the probe, so neither has a cell.
                Policy::SkipRemote | Policy::SkipKeyring | Policy::PreCollected => {}
            }
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
            let (rule, classification) = classify(&row_context(&row, &identity, reauth));
            match &classification {
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
                Classification::Skip(policy) => {
                    // A skip must come from a rule that declares a skip, and
                    // the policy the caller sees must be that rule's own: R1 and
                    // R2 are the only two skipping rules, and they carry
                    // different policies.
                    let rule = rule_by_id(rule);
                    assert_eq!(
                        rule.map(|rule| rule.decision),
                        Some(Decision::Skip(*policy)),
                        "row {}: the skip policy must be the one its rule declares",
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
                | (FailureDirection::RefuseRemote, Decision::Skip(_))
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
                classify(&ctx).0,
                RuleId::R10,
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
        assert_eq!(classify(&unknown_polkit).0, RuleId::R9);
        let named_polkit = context_for_process(RuleId::R5, "kscreenlocker_worker");
        assert_eq!(classify(&named_polkit).0, RuleId::R5);
    }

    /// A context for `service`/`process` with no reauth flag.
    fn context(service: Option<&str>, process: Option<&str>) -> CallerContext {
        let process = match process {
            Some(name) => ProcessIdentity::Exe(name.into()),
            None => ProcessIdentity::Unknown,
        };
        CallerContext::from_parts(service, process, GdmReauth::Absent)
    }

    /// R1's predicate: the two remote service names, ASCII case-insensitively,
    /// and nothing else — and it outranks every process rule.
    ///
    /// The defects this catches: R1 missing or inverted (an `sshd` call would
    /// then be rung and would wait out the GUI timeout), a case-sensitive
    /// comparison (`SSHD` would escape), a substring or prefix match
    /// (`my-sshd` would be refused, silencing a local stack), an unresolved
    /// service matching, and R1 losing its precedence (a `swaylock` under an
    /// `sshd` service would be handed off instead of refused).
    #[test]
    fn remote_rules() {
        for service in ["sshd", "sshd-session", "SSHD", "Sshd-Session"] {
            for process in [
                Some("sh"),
                Some("swaylock"),
                Some("gdm-session-worker"),
                Some("kscreenlocker_worker"),
                None,
            ] {
                assert_eq!(
                    classify(&context(Some(service), process)).0,
                    RuleId::R1,
                    "{service:?} with process {process:?} must be refused before any process rule"
                );
            }
        }

        for service in [Some("my-sshd"), Some("sshd-old"), Some("SSH"), None] {
            assert_ne!(
                classify(&context(service, Some("sh"))).0,
                RuleId::R1,
                "{service:?} is not a remote service and must take the normal path"
            );
        }

        // The near miss by value, not merely "not R1": a renamed service on an
        // `sshd`-looking process is the documented false negative.
        assert_eq!(
            classify(&context(Some("my-sshd"), Some("sshd"))).0,
            RuleId::R10
        );
    }

    /// The configured-refusal matcher's fixture table.
    ///
    /// The CSV corpus has no column for a runtime config, so this literal table
    /// is the fixture for the configured half of R1: a renamed `PAMServiceName`
    /// is refused only when it is declared, the match is ASCII case-insensitive,
    /// a near miss is not a prefix/substring match, and a malformed entry left
    /// in the slice matches nothing. The last row is the shape
    /// `PamConfig::effective_refused_services` hands over (built-ins included),
    /// which is what proves the built-ins still match through this function.
    ///
    /// The defect this catches: a matcher that returns true for any
    /// participating call (the rename would be refused without being declared,
    /// which is the negative control in `pam_logic`); one that compares
    /// case-sensitively (`SSHD-RENAMED` would escape); one that prefix-matches
    /// (`my-sshd` would be refused, silencing a local stack); and one that
    /// lets an empty configured entry match.
    #[test]
    fn configured_refused_services_match_only_declared_names() {
        let cases: &[(&str, &[&str], bool)] = &[
            // A renamed service is refused only when it is declared.
            ("sshd-renamed", &["sshd-renamed"], true),
            ("sshd-renamed", &[], false),
            // Case variants, in both directions.
            ("SSHD-RENAMED", &["sshd-renamed"], true),
            ("sshd-renamed", &["SSHD-RENAMED"], true),
            // Near misses: not a prefix, not a substring, not a sibling name.
            ("my-sshd", &["sshd-renamed"], false),
            ("sshd-renamed", &["sshd"], false),
            ("sshd-renamed", &["sshd-renamed-old"], false),
            // A malformed entry left in the slice matches nothing.
            ("sshd-renamed", &["", "sshd/x", "ssh d"], false),
            // The built-ins still match when they are in the slice, which is the
            // list `effective_refused_services` always produces.
            ("sshd", &["sshd", "sshd-session"], true),
            ("Sshd-Session", &["sshd", "sshd-session"], true),
        ];

        for (name, configured, expected) in cases {
            let configured: Vec<String> =
                configured.iter().map(|entry| (*entry).to_owned()).collect();
            let service = ServiceName::new(name);
            assert_eq!(
                refused_service(Some(&service), &configured),
                *expected,
                "service {name:?} against configured {configured:?}"
            );
        }

        // An unresolved service never matches, whatever is configured.
        assert!(!refused_service(None, &["sshd".to_owned()]));
    }

    /// The mechanism a classification fixes, and — for the two conversations
    /// that reach a plan — the plan for `tty`. `None` for a skip, which has no
    /// mechanism and no deadline.
    fn mechanism_and_plan(
        classification: &Classification,
        tty: bool,
    ) -> Option<(Conversation, Option<Plan>)> {
        match classification {
            Classification::Participate(participation) => {
                let plan = match participation.conversation {
                    Conversation::Threaded => Some(Plannable::Threaded.plan(tty)),
                    Conversation::Sequential => Some(Plannable::Sequential.plan(tty)),
                    Conversation::PreCollected => None,
                };
                Some((participation.conversation, plan))
            }
            Classification::Skip(_) => None,
        }
    }

    /// The refinement may add a skip and nothing else.
    ///
    /// Walks the whole fixture corpus through `classify` and then `refine` with
    /// the three configs that matter — the default, an empty configured list,
    /// and a list naming every participating row's service — and asserts, per
    /// row and per config:
    ///
    /// * a skipped row stays skipped, with its own rule and policy;
    /// * a participating row whose service is *not* configured comes back by
    ///   value unchanged (rule, conversation, class, hence the same deadline);
    /// * a participating row whose service *is* configured becomes R1's
    ///   `Skip(RemoteAuthentication)`, and nothing else changes policy.
    ///
    /// The defect this catches: a refinement that rebuilds the participation
    /// — a different conversation (which moves the plan and the deadline), or
    /// the same conversation with another rule or class, which only `run`'s
    /// `debug_assert!` would see — one that "unrefuses" a skip, and one that
    /// keys on the process name rather than the service.
    #[test]
    fn refinement_cannot_change_a_participation() {
        let rows = rows();
        let all_participating_services: Vec<String> = rows
            .iter()
            .filter(|row| {
                matches!(
                    row.expected_policy,
                    Policy::Threaded | Policy::Sequential | Policy::PreCollected
                )
            })
            .filter_map(|row| row.service.clone())
            .collect();

        let configs: [(&str, Vec<String>); 3] = [
            (
                "the default",
                PamConfig::default().effective_refused_services(),
            ),
            (
                "an empty configured list",
                PamConfig {
                    pam_refused_services: vec![],
                    ..PamConfig::default()
                }
                .effective_refused_services(),
            ),
            (
                "every participating service",
                PamConfig {
                    pam_refused_services: all_participating_services.clone(),
                    ..PamConfig::default()
                }
                .effective_refused_services(),
            ),
        ];

        // The third config has to be able to refuse a participating row, or its
        // clauses would be satisfied by every implementation.
        assert!(
            all_participating_services.iter().any(|name| {
                !shared::config::DEFAULT_PAM_REFUSED_SERVICES
                    .iter()
                    .any(|built_in| built_in.eq_ignore_ascii_case(name))
            }),
            "the corpus must name a participating service that is not a built-in"
        );

        let mut flips = [0usize; 3];
        for (index, (label, configured)) in configs.iter().enumerate() {
            for row in &rows {
                let identity =
                    classify_identity(row.exe.as_deref().map(Path::new), row.comm.as_deref());
                let reauth = GdmReauth::from_env(row.env.as_deref().map(OsStr::new));
                let ctx = row_context(row, &identity, reauth);

                let (rule, before) = classify(&ctx);
                let before_policy = policy_of(&before);
                let before_mechanism = mechanism_and_plan(&before, row.tty);
                let refused = row.service.as_deref().is_some_and(|service| {
                    configured
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(service))
                });
                let after = refine(before.clone(), ctx.service(), configured);
                let after_policy = policy_of(&after);

                let was_skipped = before_mechanism.is_none();
                if was_skipped {
                    assert_eq!(
                        after_policy, before_policy,
                        "{label}: row {} ({}) is skipped and must stay skipped",
                        row.id, row.why
                    );
                    assert_eq!(
                        skip_rule(&after),
                        Some(rule),
                        "{label}: row {} must keep its own skip rule",
                        row.id
                    );
                } else if refused {
                    flips[index] += 1;
                    assert_eq!(
                        after_policy,
                        Policy::SkipRemote,
                        "{label}: a configured service must be refused through R1's policy",
                    );
                    assert_eq!(
                        skip_rule(&after),
                        Some(RuleId::R1),
                        "{label}: row {} must be refused through R1, not another rule",
                        row.id
                    );
                } else {
                    // Whole-value equality, not just the conversation and the
                    // plan derived from it: the failure direction is part of the
                    // value, so a refine that rebuilt the participation with the
                    // same conversation but another class fails here rather than
                    // only in `run`'s `debug_assert!`, which release builds drop.
                    assert_eq!(
                        after, before,
                        "{label}: row {} ({}) must come back from the \
                         refinement unchanged, class included",
                        row.id, row.why
                    );
                }
            }
        }

        assert!(
            flips[2] > 0,
            "the all-participating config must flip at least one row to a skip, or \
             its case proves nothing"
        );
    }

    /// Moving a rule must move exactly the rows it should, by value, and leave
    /// every other row where it was.
    ///
    /// Two load-bearing orderings:
    /// * R2 after R8 — `swaylock_under_sddm` and `i3lock_under_gdm_login`
    ///   become R8/pre-collected, because a process rule would then outrank the
    ///   keyring constraint.
    /// * R1 after R8 — `svc_sshd_under_swaylock` becomes R8/pre-collected,
    ///   because R1 must precede the process rules.
    ///
    /// R1-after-R2 is deliberately *not* a case: R1 keys on the service names
    /// `sshd`/`sshd-session` and R2 on the display-manager prefixes, so the two
    /// predicates are disjoint and that swap changes no row at all — a vacuous
    /// case, not a gate.
    #[test]
    fn rule_permutation_moves_named_rows() {
        assert_moved_rows(
            &reordered(RuleId::R2, RuleId::R8),
            &[
                ("swaylock_under_sddm", (RuleId::R8, Policy::PreCollected)),
                ("i3lock_under_gdm_login", (RuleId::R8, Policy::PreCollected)),
            ],
        );
        assert_moved_rows(
            &reordered(RuleId::R1, RuleId::R8),
            &[(
                "svc_sshd_under_swaylock",
                (RuleId::R8, Policy::PreCollected),
            )],
        );
    }

    /// `RULES` with `moved` taken out and re-inserted directly after `after`.
    fn reordered(moved: RuleId, after: RuleId) -> Vec<&'static Rule> {
        let rule = rule_by_id(moved).expect("the moved rule exists");
        let mut rules: Vec<&'static Rule> = RULES.iter().filter(|rule| rule.id != moved).collect();
        let anchor = rules
            .iter()
            .position(|rule| rule.id == after)
            .expect("the anchor rule exists");
        rules.insert(anchor + 1, rule);
        rules
    }

    fn classify_with(ordered: &[&'static Rule], ctx: &CallerContext) -> (RuleId, Policy) {
        let rule = ordered
            .iter()
            .find(|rule| (rule.predicate)(ctx))
            .expect("the table always ends with the unconditional R10");
        (rule.id, policy_for_decision(&rule.decision))
    }

    /// Assert `changed` for the named rows and "unchanged from `RULES`" for every
    /// other corpus row.
    fn assert_moved_rows(ordered: &[&'static Rule], changed: &[(&str, (RuleId, Policy))]) {
        let rows = rows();
        for (id, _) in changed {
            assert!(
                rows.iter().any(|row| row.id == *id),
                "{id} is not a corpus row, so this permutation case is vacuous"
            );
        }
        for row in &rows {
            let identity =
                classify_identity(row.exe.as_deref().map(Path::new), row.comm.as_deref());
            let reauth = GdmReauth::from_env(row.env.as_deref().map(OsStr::new));
            let ctx = row_context(row, &identity, reauth);
            let (rule, baseline_classification) = classify(&ctx);
            let baseline = (rule, policy_of(&baseline_classification));
            let permuted = classify_with(ordered, &ctx);
            match changed.iter().find(|(id, _)| *id == row.id) {
                Some((_, expected)) => {
                    assert_eq!(permuted, *expected, "row {} must move", row.id);
                }
                None => assert_eq!(
                    permuted, baseline,
                    "row {} must not move under this permutation",
                    row.id
                ),
            }
        }
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
        // exactly what R10 produces, id included.
        assert_eq!(classify(&null), (RuleId::R10, DEFAULT_SEQUENTIAL));
    }

    /// The symbol `line` declares, as `(keyword, name)`, or `None` when the
    /// line declares nothing.
    ///
    /// A doc comment is never a declaration, whatever words it uses, and a
    /// citation into the decision record is only meaningful when it lands on
    /// the declaration it claims: the drift this distinguishes is a doc comment
    /// or a closing brace sitting where a predicate used to be.
    fn declared_symbol(line: &str) -> Option<(&'static str, &str)> {
        const DECLARATIONS: [&str; 7] = ["fn", "const", "static", "type", "struct", "enum", "mod"];
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            return None;
        }
        let mut tokens = trimmed
            .split(|character: char| {
                character.is_whitespace() || character == '(' || character == ')'
            })
            .filter(|token| !token.is_empty());
        while let Some(token) = tokens.next() {
            if let Some(keyword) = DECLARATIONS.iter().find(|keyword| **keyword == token) {
                return tokens
                    .next()
                    .map(|name| (*keyword, name.trim_end_matches(':')));
            }
        }
        None
    }

    /// Why a `policy/table.rs` citation does not name the symbol this row
    /// declares there, or `None` when it does.
    ///
    /// `fn <rule name>` is the row's own predicate, which is what every row
    /// cites; any other `fn` is a different row's predicate reached by a shift.
    /// A citation to some other table declaration (`const`, `struct`, …) is
    /// accepted as long as it lands on a declaration, but never on a doc
    /// comment, a brace or a bare expression.
    fn table_citation_problem(
        rule_name: &str,
        citation: &str,
        text: &str,
        start: usize,
    ) -> Option<String> {
        let line = text.lines().nth(start - 1).unwrap_or_default();
        match declared_symbol(line) {
            Some(("fn", symbol)) if symbol == rule_name => None,
            Some(("fn", symbol)) => Some(format!(
                "rule {rule_name}: citation {citation:?} lands on `fn {symbol}`, not on this \
                 rule's own `fn {rule_name}`"
            )),
            Some(_) => None,
            None => Some(format!(
                "rule {rule_name}: citation {citation:?} lands on {line:?}, which declares no \
                 symbol"
            )),
        }
    }

    /// Every `evidence` citation resolves in this tree, and the scan reports
    /// which files it checked so a relocated or emptied table cannot pass
    /// silently. Entries marked `external:` cite a specification or an
    /// out-of-tree program and are exempt.
    ///
    /// A citation into `policy/table.rs` must land on the declaration it
    /// claims, not merely on a non-blank line: the row's own predicate
    /// citation must hit `fn <rule name>`, and any other table citation must at
    /// least hit a declaration ([`table_citation_problem`]). The plant-and-
    /// revert control at the end is what keeps the strengthening honest.
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
                if file == TABLE_PATH {
                    if let Some(problem) = table_citation_problem(rule.name, citation, &text, start)
                    {
                        panic!("{problem}");
                    }
                }
                checked.push(file);
            }
        }

        // Positive control: plant one line of drift under R6's own citation in
        // an in-memory copy of the decision record and observe the strengthened
        // check reject it, then revert the plant and observe it accept again.
        // Without the plant, everything above would also pass a check that
        // accepted any non-blank line.
        let r6 = RULES
            .iter()
            .find(|rule| rule.id == RuleId::R6)
            .expect("the table has an R6 row");
        let citation = r6
            .evidence
            .iter()
            .find(|citation| citation.starts_with("client-pam/src/policy/table.rs:"))
            .expect("R6 cites its own predicate");
        let line_number: usize = citation
            .rsplit_once(':')
            .and_then(|(_, line)| line.parse().ok())
            .expect("R6's table citation ends in a line number");
        let table = std::fs::read_to_string(root.join(TABLE_PATH))
            .expect("the decision record is readable");
        let mut drifted: Vec<&str> = table.lines().collect();
        let planted = drifted[line_number - 1];
        assert!(
            table_citation_problem(r6.name, citation, &table, line_number).is_none(),
            "control precondition: R6's citation resolves before the plant"
        );
        drifted[line_number - 1] = "/// R6 — hyprlock.";
        assert!(
            table_citation_problem(r6.name, citation, &drifted.join("\n"), line_number).is_some(),
            "positive control: a one-line drift onto R6's doc comment must be rejected"
        );
        drifted[line_number - 1] = "fn xsecurelock(ctx: &CallerContext) -> bool {";
        assert!(
            table_citation_problem(r6.name, citation, &drifted.join("\n"), line_number).is_some(),
            "positive control: a shift onto another row's predicate must be rejected too"
        );
        drifted[line_number - 1] = planted;
        assert!(
            table_citation_problem(r6.name, citation, &drifted.join("\n"), line_number).is_none(),
            "reverted plant: R6's citation resolves again"
        );

        assert!(
            checked.contains(&TABLE_PATH),
            "the citation scan never looked at this table's own file: {checked:?}"
        );
    }
}
