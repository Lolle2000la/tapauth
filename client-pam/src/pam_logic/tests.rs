//! The orchestration's behaviour: the ordering tests count calls through `OrchestrationIo` and
//! `Effects` instead of asserting promises. The 500 ms reuse corpus lives in `reuse`.

use super::*;
use crate::ipc_client::IpcClient;
use crate::logging;
use crate::transaction::tests::{no_daemon, NullIpc};
use crate::transaction::SendParams;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_logging_init() {
    logging::init_logging();
    logging::init_logging();
}

/// The four calls `classify` must precede, counted.
///
/// The context reaches `orchestrate` already captured, so these tests need no PAM handle and no
/// daemon: whatever the body does after the four calls, the counters are decided before it.
static CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);
static USER_CALLS: AtomicUsize = AtomicUsize::new(0);
static CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);
static MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Timeouts of zero: these tests assert call counts, not waiting.
fn zero_timeouts() -> PamConfig {
    PamConfig {
        pam_operation_timeout_secs: 0,
        pam_gui_timeout_secs: 0,
        ..PamConfig::default()
    }
}

fn counting_config() -> PamConfig {
    CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
    zero_timeouts()
}

unsafe fn counting_get_user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
    USER_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok("classification-test-user".to_owned())
}

unsafe fn counting_conversation(
    _pamh: *mut pam_sys::PamHandle,
) -> Result<pam_sys::PamConversation<'static>, c_int> {
    CONVERSATION_CALLS.fetch_add(1, Ordering::SeqCst);
    // A conversation over no handle: every emission is a no-op, which is all this test needs.
    Ok(unsafe { pam_sys::PamConversation::dummy() })
}

fn counting_messages(_username: &str) -> pam_messages::PamMessages {
    MESSAGE_CALLS.fetch_add(1, Ordering::SeqCst);
    pam_messages::load_for_user("classification-test-user")
}

fn counting_io() -> OrchestrationIo {
    OrchestrationIo {
        load_config: counting_config,
        get_user: counting_get_user,
        new_conversation: counting_conversation,
        load_messages: counting_messages,
        read_authtok: crate::transaction::tests::unused_authtok,
    }
}

fn context(service: Option<&str>, process: Option<&str>) -> CallerContext {
    let process = match process {
        Some(name) => crate::context::ProcessIdentity::Exe(name.into()),
        None => crate::context::ProcessIdentity::Unknown,
    };
    CallerContext::from_parts(service, process, crate::context::GdmReauth::Absent)
}

/// An `OrchestrationIo` that counts nothing, for the tests about the tty probe.
fn inert_io() -> OrchestrationIo {
    unsafe fn user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
        Ok("tty-probe-test-user".to_owned())
    }
    unsafe fn conversation(
        _pamh: *mut pam_sys::PamHandle,
    ) -> Result<pam_sys::PamConversation<'static>, c_int> {
        Ok(unsafe { pam_sys::PamConversation::dummy() })
    }
    OrchestrationIo {
        load_config: zero_timeouts,
        get_user: user,
        new_conversation: conversation,
        load_messages: |_username| pam_messages::load_for_user("tty-probe-test-user"),
        read_authtok: crate::transaction::tests::unused_authtok,
    }
}

/// The defect this catches: a skip decided late enough to dial the socket, or one that sends
/// the request and only then refuses. The counters are the assertion: an outcome equality cannot
/// tell a refusal that never connected from one that returned the same code after a full
/// transaction.
#[test]
fn remote_skip_never_reaches_the_daemon() {
    for service in ["sshd", "sshd-session"] {
        let connects = AtomicUsize::new(0);
        let sends = AtomicUsize::new(0);
        let ctx = context(Some(service), Some("sshd"));

        let finished = orchestrate(
            std::ptr::null_mut(),
            &ctx,
            &inert_io(),
            &mut Effects {
                probe_tty: &mut probe_tty,
                connect: &mut || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    Err::<NullIpc, _>(no_daemon())
                },
                send: &mut |_: &mut NullIpc, _: &SendParams<'_>| {
                    sends.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                cancel: &|_, _| {},
            },
        );

        assert_eq!(
            connects.load(Ordering::SeqCst),
            0,
            "service {service}: a remote skip must not dial the daemon"
        );
        assert_eq!(
            sends.load(Ordering::SeqCst),
            0,
            "service {service}: a remote skip must put no request on the wire"
        );
        assert!(
            matches!(
                &finished,
                Finished::Unrecorded(Outcome::Unavailable(
                    crate::outcome::UnavailableReason::RemoteAuthentication
                ))
            ),
            "service {service}: R1 is an unrecorded RemoteAuthentication verdict"
        );
        assert_eq!(
            finished.outcome().clone().into_pam(),
            pam_sys::PAM_AUTHINFO_UNAVAIL,
            "service {service}: R1 must report the service as unavailable"
        );
    }
}

/// The defect this catches: a message added to one of these reasons (say a `PAM_TEXT_INFO` for
/// the keyring bypass). Those paths return before `PamConversation::new`, so there is nothing to
/// emit through and the message would vanish silently instead of the omission being decided
/// here.
#[test]
fn outcomes_that_precede_the_conversation_are_silent() {
    let msgs = pam_messages::load_for_user("pre-conversation-test-user");
    for outcome in [
        Outcome::from_skip(crate::policy::SkipPolicy::RemoteAuthentication),
        Outcome::from_skip(crate::policy::SkipPolicy::KeyringNeedsAuthtok),
        Outcome::UserUnknown,
        Outcome::Error(crate::outcome::ErrorReason::ConversationLookup),
    ] {
        assert!(
            outcome.notice(&msgs).is_none(),
            "{outcome:?} is returned before a conversation exists, so it must show nothing"
        );
    }
}

/// Run `orchestrate` for `ctx` and return the four call counters in the order `config, user,
/// conversation, messages`.
fn side_effects_of(ctx: &CallerContext) -> [usize; 4] {
    CONFIG_CALLS.store(0, Ordering::SeqCst);
    USER_CALLS.store(0, Ordering::SeqCst);
    CONVERSATION_CALLS.store(0, Ordering::SeqCst);
    MESSAGE_CALLS.store(0, Ordering::SeqCst);
    let _finished = orchestrate(
        std::ptr::null_mut(),
        ctx,
        &counting_io(),
        &mut Effects {
            probe_tty: &mut probe_tty,
            connect: &mut || Err::<IpcClient, _>(no_daemon()),
            send: &mut |_: &mut IpcClient, _: &SendParams<'_>| Ok(()),
            cancel: &|_, _| {},
        },
    );
    [
        CONFIG_CALLS.load(Ordering::SeqCst),
        USER_CALLS.load(Ordering::SeqCst),
        CONVERSATION_CALLS.load(Ordering::SeqCst),
        MESSAGE_CALLS.load(Ordering::SeqCst),
    ]
}

/// The defect this catches: moving `classify` below any of the four — the natural place is
/// "after the config read", where the timeouts are known. Nothing else fails then: a
/// display-manager login would still return `PAM_AUTHINFO_UNAVAIL`, it would just pay a config
/// read, two PAM item lookups, an NSS lookup and a root-side home read first, and a skip on a
/// null user would come back as `PAM_USER_UNKNOWN` instead.
#[test]
fn classify_before_side_effects() {
    // R1: a remote service name is refused before anything is read.
    assert_eq!(
        side_effects_of(&context(Some("sshd"), Some("sshd"))),
        [0, 0, 0, 0],
        "a remote skip must not load config, user, conversation or messages"
    );

    // R2: the display-manager bypass.
    assert_eq!(
        side_effects_of(&context(Some("sddm"), Some("sh"))),
        [0, 0, 0, 0],
        "a display-manager skip must not load config, user, conversation or messages"
    );

    // The control: a `Participate` reaches all four, so the counters above are not zero merely
    // because the harness never increments them.
    assert_eq!(
        side_effects_of(&context(Some("sudo"), Some("totally-unknown"))),
        [1, 1, 1, 1],
        "a participating call must reach every one of the four calls"
    );
}

/// The four side effects the configured-refusal test counts, on their own statics so the two
/// tests cannot race.
static RENAMED_CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);
static RENAMED_USER_CALLS: AtomicUsize = AtomicUsize::new(0);
static RENAMED_CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);
static RENAMED_MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// A config that declares the renamed service, the shape a deployment with `PAMServiceName
/// sshd-renamed` writes.
fn renamed_config() -> PamConfig {
    RENAMED_CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
    PamConfig {
        pam_refused_services: vec!["sshd-renamed".to_owned()],
        ..zero_timeouts()
    }
}

/// The same config without the extra name: the negative control's input.
fn no_extras_config() -> PamConfig {
    RENAMED_CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
    PamConfig {
        pam_refused_services: vec![],
        ..zero_timeouts()
    }
}

unsafe fn renamed_get_user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
    RENAMED_USER_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok("renamed-service-test-user".to_owned())
}

unsafe fn renamed_conversation(
    _pamh: *mut pam_sys::PamHandle,
) -> Result<pam_sys::PamConversation<'static>, c_int> {
    RENAMED_CONVERSATION_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(unsafe { pam_sys::PamConversation::dummy() })
}

fn renamed_messages(_username: &str) -> pam_messages::PamMessages {
    RENAMED_MESSAGE_CALLS.fetch_add(1, Ordering::SeqCst);
    pam_messages::load_for_user("renamed-service-test-user")
}

/// One `orchestrate` call for a context, with every side effect counted.
struct RenamedRun {
    config: usize,
    user: usize,
    conversation: usize,
    messages: usize,
    connects: usize,
    sends: usize,
    finished: Finished,
}

/// Serialises the two `run_renamed` tests: they share the counters above and `cargo test` runs
/// tests in parallel threads, so one resetting mid-run would make the other's count
/// meaningless. A poisoned lock is reused: a panic in one test must not fail the other for the
/// wrong reason.
static RENAMED_RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_renamed(ctx: &CallerContext, load_config: fn() -> PamConfig) -> RenamedRun {
    let _guard = RENAMED_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    RENAMED_CONFIG_CALLS.store(0, Ordering::SeqCst);
    RENAMED_USER_CALLS.store(0, Ordering::SeqCst);
    RENAMED_CONVERSATION_CALLS.store(0, Ordering::SeqCst);
    RENAMED_MESSAGE_CALLS.store(0, Ordering::SeqCst);
    let connects = AtomicUsize::new(0);
    let sends = AtomicUsize::new(0);

    let io = OrchestrationIo {
        load_config,
        get_user: renamed_get_user,
        new_conversation: renamed_conversation,
        load_messages: renamed_messages,
        read_authtok: crate::transaction::tests::unused_authtok,
    };
    let finished = orchestrate(
        std::ptr::null_mut(),
        ctx,
        &io,
        &mut Effects {
            probe_tty: &mut probe_tty,
            connect: &mut || {
                connects.fetch_add(1, Ordering::SeqCst);
                Err::<NullIpc, _>(no_daemon())
            },
            send: &mut |_: &mut NullIpc, _: &SendParams<'_>| {
                sends.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            cancel: &|_, _| {},
        },
    );

    RenamedRun {
        config: RENAMED_CONFIG_CALLS.load(Ordering::SeqCst),
        user: RENAMED_USER_CALLS.load(Ordering::SeqCst),
        conversation: RENAMED_CONVERSATION_CALLS.load(Ordering::SeqCst),
        messages: RENAMED_MESSAGE_CALLS.load(Ordering::SeqCst),
        connects: connects.load(Ordering::SeqCst),
        sends: sends.load(Ordering::SeqCst),
        finished,
    }
}

/// The defect this catches, in both directions: without the enforcement point a renamed
/// `PAMServiceName` is classified R10 and a remote login rings the phone and waits out the GUI
/// timeout (the counters would be non-zero and the verdict `DaemonUnreachable`); an enforcement
/// point that runs before the config read cannot see the configured list at all, and one placed
/// after the username lookup, the conversation or the messages would still pay them — and would
/// emit through a live `HostIo`, which is why the verdict's notice is asserted `None` here.
#[test]
fn a_configured_renamed_service_is_refused_after_the_config_read() {
    let ctx = context(Some("sshd-renamed"), Some("sshd"));
    let run = run_renamed(&ctx, renamed_config);

    assert_eq!(
        run.config, 1,
        "the configured list only exists after the one config read"
    );
    assert_eq!(
        run.user, 0,
        "a configured refusal must not resolve a username"
    );
    assert_eq!(
        run.conversation, 0,
        "a configured refusal must not look up the conversation"
    );
    assert_eq!(
        run.messages, 0,
        "a configured refusal must not load the messages"
    );
    assert_eq!(
        run.connects, 0,
        "a configured refusal must not dial the daemon"
    );
    assert_eq!(
        run.sends, 0,
        "a configured refusal must put no request on the wire"
    );
    assert_eq!(
        run.finished.outcome(),
        &Outcome::Unavailable(crate::outcome::UnavailableReason::RemoteAuthentication),
        "a configured refusal keeps R1's verdict"
    );
    assert_eq!(
        run.finished.outcome().clone().into_pam(),
        pam_sys::PAM_AUTHINFO_UNAVAIL,
        "a configured refusal reports the service as unavailable"
    );
    let msgs = pam_messages::load_for_user("renamed-service-test-user");
    assert!(
        run.finished.outcome().notice(&msgs).is_none(),
        "the refusal is silent: it returns before a HostIo exists"
    );
}

/// The negative control: the same caller with no configured extras is a participating call
/// (R10) and does reach `get_user`.
///
/// The defect this catches: a harness that counts nothing — the zeros above would then also
/// pass for a `get_user` that is never wired in — and an enforcement point that refuses on the
/// *process* name (`sshd`) rather than the service name, which would silence a local stack that
/// happens to be named `sshd-renamed`.
#[test]
fn a_renamed_service_without_config_participates() {
    let ctx = context(Some("sshd-renamed"), Some("sshd"));
    let run = run_renamed(&ctx, no_extras_config);

    assert_eq!(run.config, 1);
    assert_eq!(
        run.user, 1,
        "without the configured name the call is local (R10) and resolves the username"
    );
    assert_eq!(
        run.conversation, 1,
        "a participating call builds its conversation"
    );
    assert_eq!(run.messages, 1, "a participating call loads its messages");
    assert_eq!(
        run.finished.outcome(),
        &Outcome::Unavailable(crate::outcome::UnavailableReason::DaemonUnreachable),
        "the control gets past the refusal and fails at the absent daemon"
    );
}

/// The conversation lookups a skip must not perform, on their own static so nothing races.
static SKIP_CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);

/// The handoff token reads, on their own static so a concurrent test cannot skew the count.
static HANDOFF_TOKEN_READS: AtomicUsize = AtomicUsize::new(0);

unsafe fn skip_conversation(
    _pamh: *mut pam_sys::PamHandle,
) -> Result<pam_sys::PamConversation<'static>, c_int> {
    SKIP_CONVERSATION_CALLS.fetch_add(1, Ordering::SeqCst);
    Ok(unsafe { pam_sys::PamConversation::dummy() })
}

/// The injected handoff reader: counts the read and supplies no token.
///
/// A successful read with a null token is the handoff's "nothing was collected" branch, so only
/// the log line changes — the count is what the test asserts.
unsafe fn counting_authtok(_pamh: *mut pam_sys::PamHandle) -> (c_int, *const std::os::raw::c_char) {
    HANDOFF_TOKEN_READS.fetch_add(1, Ordering::SeqCst);
    (pam_sys::PAM_SUCCESS, std::ptr::null())
}

fn skip_io() -> OrchestrationIo {
    unsafe fn user(_pamh: *mut pam_sys::PamHandle) -> Result<String, c_int> {
        Ok("skip-test-user".to_owned())
    }
    OrchestrationIo {
        load_config: zero_timeouts,
        get_user: user,
        new_conversation: skip_conversation,
        load_messages: |_username| pam_messages::load_for_user("skip-test-user"),
        read_authtok: counting_authtok,
    }
}

/// The defect this catches: a skip routed through the participation path, so a display-manager
/// login or a remote call reads the token (and answers `PasswordHandoff` instead of its own
/// reason). The read is counted where it happens, through the reader `transaction::HostIo`
/// carries, not inferred from the absence of a conversation.
///
/// R1 and R2 skip the handle entirely (no plan, no deadline, no conversation), while R8's
/// pre-collected handoff *must* touch it — it calls `pam_get_authtok` on the calling thread and
/// leaves `PAM_AUTHTOK` for the next module.
#[test]
fn skip_never_hands_off() {
    for (service, process, expected) in [
        (
            "sddm",
            "sh",
            crate::outcome::UnavailableReason::KeyringBypass,
        ),
        (
            "sshd",
            "sshd",
            crate::outcome::UnavailableReason::RemoteAuthentication,
        ),
    ] {
        SKIP_CONVERSATION_CALLS.store(0, Ordering::SeqCst);
        HANDOFF_TOKEN_READS.store(0, Ordering::SeqCst);
        let connects = AtomicUsize::new(0);
        let sends = AtomicUsize::new(0);

        let finished = orchestrate(
            std::ptr::null_mut(),
            &context(Some(service), Some(process)),
            &skip_io(),
            &mut Effects {
                probe_tty: &mut probe_tty,
                connect: &mut || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    Err::<NullIpc, _>(no_daemon())
                },
                send: &mut |_: &mut NullIpc, _: &SendParams<'_>| {
                    sends.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                cancel: &|_, _| {},
            },
        );

        assert_eq!(
            SKIP_CONVERSATION_CALLS.load(Ordering::SeqCst),
            0,
            "service {service}: a skip must not look up a conversation"
        );
        assert_eq!(
            HANDOFF_TOKEN_READS.load(Ordering::SeqCst),
            0,
            "service {service}: a skip must not read the handoff token"
        );
        assert_eq!(
            connects.load(Ordering::SeqCst),
            0,
            "service {service}: a skip must not dial the daemon"
        );
        assert_eq!(
            sends.load(Ordering::SeqCst),
            0,
            "service {service}: a skip must put no request on the wire"
        );
        assert_eq!(
            finished.outcome(),
            &Outcome::Unavailable(expected),
            "service {service}: a skip keeps its own reason and never hands off"
        );
    }

    // The positive control: R8's pre-collected host reaches the handoff, so the same reader
    // counts exactly one read and the verdict is the handoff's. Without it the two zeros above
    // would also pass for a reader that is never wired into the handoff at all.
    HANDOFF_TOKEN_READS.store(0, Ordering::SeqCst);
    let finished = orchestrate(
        std::ptr::null_mut(),
        &context(Some("test-service"), Some("swaylock")),
        &skip_io(),
        &mut Effects {
            probe_tty: &mut probe_tty,
            connect: &mut || Err::<NullIpc, _>(no_daemon()),
            send: &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            cancel: &|_, _| {},
        },
    );
    assert_eq!(
        HANDOFF_TOKEN_READS.load(Ordering::SeqCst),
        1,
        "a pre-collected host must read the token exactly once"
    );
    assert_eq!(
        finished.outcome(),
        &Outcome::Unavailable(crate::outcome::UnavailableReason::PasswordHandoff),
        "the pre-collected host's call is the handoff's verdict"
    );
}

/// Emit `outcome`'s one message through the crate's one emission site, then take its code.
///
/// The emission site is [`HostIo::emit`], so the host built here is the one `orchestrate`
/// builds; the dummy conversation makes the emission itself a no-op, so the pair these tests pin
/// is the verdict and the code.
fn emit_then_code(
    conv: &pam_sys::PamConversation<'_>,
    msgs: &pam_messages::PamMessages,
    outcome: Outcome,
) -> c_int {
    HostIo::new(
        std::ptr::null_mut(),
        Some(conv),
        msgs,
        crate::transaction::tests::unused_authtok,
    )
    .emit(outcome.notice(msgs));
    outcome.into_pam()
}

#[test]
fn test_map_pam_outcome_matrix() {
    let conv = unsafe { pam_sys::PamConversation::dummy() };
    let msgs = pam_messages::load_for_user("testuser");
    // The daemon-answer path as the call sites run it: the verdict, its one message and its
    // code, from the response alone.
    let map = |resp: shared::ipc::pb::PamAuthenticateResponse| {
        emit_then_code(&conv, &msgs, Outcome::from_daemon(resp))
    };

    let resp_for = |outcome: shared::ipc::pb::PamOutcome,
                    detail: &str|
     -> shared::ipc::pb::PamAuthenticateResponse {
        shared::ipc::pb::PamAuthenticateResponse {
            outcome: outcome as i32,
            detail: detail.to_string(),
            challenge: vec![],
        }
    };

    // A grant is the only success.
    assert_eq!(
        map(resp_for(shared::ipc::pb::PamOutcome::Success, "Success")),
        pam_sys::PAM_SUCCESS
    );

    // An explicit phone denial must stay a denial: it fails in both the `required` and the
    // `[success=done default=bad]` stack shapes.
    assert_eq!(
        map(resp_for(shared::ipc::pb::PamOutcome::Denied, "Denied")),
        pam_sys::PAM_PERM_DENIED
    );

    // No usable answer from the service (timeout, skip, no paired device): the auth service
    // could not be consulted.
    for outcome in [
        shared::ipc::pb::PamOutcome::Timeout,
        shared::ipc::pb::PamOutcome::Ignore,
    ] {
        assert_eq!(
            map(resp_for(outcome, "detail")),
            pam_sys::PAM_AUTHINFO_UNAVAIL,
            "{outcome:?} must report the service as unavailable"
        );
    }

    assert_eq!(
        map(resp_for(shared::ipc::pb::PamOutcome::Error, "boom")),
        pam_sys::PAM_AUTH_ERR
    );
}

/// The `outcome` field is a raw `i32` on the wire, so a peer can put any value in it; unknown
/// values must fail closed rather than decode to `PamOutcome::default()` = `SUCCESS`.
#[test]
fn test_unknown_outcome_raw_values_fail_closed() {
    use crate::outcome::DenyVia;
    use crate::outcome::ErrorReason;
    use crate::outcome::GrantVia;
    use crate::outcome::Outcome;
    use crate::outcome::UnavailableReason;

    let from_raw = |raw: i32| {
        Outcome::from_daemon(shared::ipc::pb::PamAuthenticateResponse {
            outcome: raw,
            detail: "detail".to_owned(),
            challenge: vec![],
        })
    };

    for raw in [-1, 5, 99, 255, i32::MAX, i32::MIN] {
        let outcome = from_raw(raw);
        assert_eq!(
            outcome,
            Outcome::Error(ErrorReason::Daemon("detail".into())),
            "raw outcome {raw} must fail closed instead of {outcome:?}"
        );
    }

    // Known values keep exactly today's mapping.
    for (raw, expected) in [
        (0, Outcome::Granted(GrantVia::PhoneTap)),
        (1, Outcome::Denied(DenyVia::PhoneDenial)),
        (2, Outcome::Unavailable(UnavailableReason::DaemonTimedOut)),
        (3, Outcome::Unavailable(UnavailableReason::DaemonIgnored)),
        (4, Outcome::Error(ErrorReason::Daemon("detail".into()))),
    ] {
        assert_eq!(
            from_raw(raw),
            expected,
            "raw outcome {raw} must keep its mapping"
        );
    }
}

/// Wire-level counterpart of the test above: hand-encode the unknown value, decode it with prost
/// and drive the real PAM mapping.
///
/// Layout (proto3): `outcome` is field 1, varint, so the tag byte is `(1 << 3) | 0 == 0x08`,
/// followed by the value's base-128 varint. `detail` and `challenge` are empty and therefore
/// absent from the encoding.
#[test]
fn test_undecodable_wire_outcome_never_grants() {
    use prost::Message;

    /// Base-128 varint encoding of `value`.
    fn varint(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    let conv = unsafe { pam_sys::PamConversation::dummy() };
    let msgs = pam_messages::load_for_user("testuser");

    for raw in [99_i32, i32::MAX] {
        let mut bytes = vec![0x08_u8];
        bytes.extend(varint(raw as u32));

        let resp = shared::ipc::pb::PamAuthenticateResponse::decode(bytes.as_slice()).unwrap();
        // The hand-built bytes really did carry the unknown outcome.
        assert_eq!(resp.outcome, raw, "hand-encoded bytes decode as expected");

        let code = emit_then_code(&conv, &msgs, Outcome::from_daemon(resp));
        assert_ne!(
            code,
            pam_sys::PAM_SUCCESS,
            "unknown outcome {raw} must not grant access"
        );
        assert_eq!(
            code,
            pam_sys::PAM_AUTH_ERR,
            "unknown outcome {raw} must be a processing failure"
        );
    }
}

/// Regression test for the `PAM_IGNORE` authentication bypass: Linux-PAM records no failure for
/// `PAM_IGNORE`, so in a stack shaped like `auth required pam_tapauth.so` + `auth optional
/// pam_permit` + `auth required pam_env` the `optional` module's success vote grants the whole
/// stack without any phone approval. No daemon outcome may map to `PAM_IGNORE`.
#[test]
fn test_no_pam_outcome_maps_to_pam_ignore() {
    let conv = unsafe { pam_sys::PamConversation::dummy() };
    let msgs = pam_messages::load_for_user("testuser");

    // Every variant of the IPC enum. This list is not compiler-enforced: the `match` in
    // `Outcome::from_daemon` is exhaustive but this array is not, so extend this list by hand
    // when adding a variant.
    let all_outcomes = [
        shared::ipc::pb::PamOutcome::Success,
        shared::ipc::pb::PamOutcome::Denied,
        shared::ipc::pb::PamOutcome::Timeout,
        shared::ipc::pb::PamOutcome::Ignore,
        shared::ipc::pb::PamOutcome::Error,
    ];

    for outcome in all_outcomes {
        let resp = shared::ipc::pb::PamAuthenticateResponse {
            outcome: outcome as i32,
            detail: "detail".to_string(),
            challenge: vec![],
        };
        let code = emit_then_code(&conv, &msgs, Outcome::from_daemon(resp));
        // `PAM_IGNORE` is 25 and is deliberately absent from this list: it is not a verdict, so
        // a later `optional pam_permit` can still make the whole stack succeed.
        let is_real_verdict = [
            pam_sys::PAM_SUCCESS,
            pam_sys::PAM_PERM_DENIED,
            pam_sys::PAM_AUTHINFO_UNAVAIL,
            pam_sys::PAM_AUTH_ERR,
        ]
        .contains(&code);
        assert!(
            is_real_verdict,
            "{outcome:?} mapped to {code}, which is not a real PAM verdict \
             (PAM_IGNORE is 25)"
        );
    }
}

#[cfg(test)]
mod reuse;
