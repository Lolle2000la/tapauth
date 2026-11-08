//! PAM authentication logic for TapAuth.
//!
//! Implements the core authentication flow that integrates with Linux PAM.
//! Supports both terminal (with skip detection via Enter key) and GUI contexts
//! (e.g., Polkit dialogs).
//!
//! ## Flow
//!
//! 1. Load paired devices for the user
//! 2. Send authentication request via BLE/UDP multicast
//! 3. Wait for phone tap or user skip (terminal only)
//! 4. On skip, send IPC cancel to daemon (best effort) plus network cancel
//! 5. Return `PAM_SUCCESS` on authentication; every other outcome returns a
//!    real verdict (`PAM_PERM_DENIED`, `PAM_AUTHINFO_UNAVAIL` or `PAM_AUTH_ERR`),
//!    never `PAM_IGNORE`: Linux-PAM records no failure for that code, so a later
//!    `optional` module voting success (e.g. `pam_permit`) would grant the stack.
//!
//! ## Threading
//!
//! Uses a shared async runtime to avoid the ~100ms overhead of creating a new
//! runtime per authentication attempt. A separate thread monitors `/dev/tty`
//! for skip signals in terminal contexts. TTY-less (GUI) hosts are split into
//! three conversation modes by the policy table in `policy`; only allowlisted hosts get
//! the worker thread, hosts that collect the password before calling into PAM
//! get a synchronous replay and no daemon request at all, and everyone else
//! keeps the conversation on the caller's thread.
//!
//! ## Return-code mapping
//!
//! | Transition | Code |
//! | :--- | :--- |
//! | Phone approved the request | `PAM_SUCCESS` |
//! | Phone explicitly denied | `PAM_PERM_DENIED` |
//! | Timeout, dialog dismissed, IPC error, no paired device, skip, DM bypass | `PAM_AUTHINFO_UNAVAIL` |
//! | Daemon reported an internal error, or a local failure (conversation lookup, RNG, pipe/thread spawn) | `PAM_AUTH_ERR` |
//! | Username lookup failed | `PAM_USER_UNKNOWN` |

use crate::config::PamConfig;
use crate::context::{CallerContext, ServiceName};
use crate::ipc_client::{IpcClient, IpcError, IpcResponseReader};
use crate::logging;
use crate::outcome::Outcome;
use crate::pam_messages;
use crate::pam_sys;
use crate::policy;
use crate::transaction::{Effects, Finished, HostIo, SendParams};
use std::os::raw::c_int;
use std::time::{Duration, Instant};

/// Main PAM authentication entry point.
///
/// ## Returns
///
/// The orchestration returns a [`Finished`], whose two arms both carry an
/// [`Outcome`]; `Outcome::into_pam` is the only conversion, and the `match` below
/// is its only caller. Which reasons reach which code is the table in
/// `Outcome::into_pam` / `Outcome::notice`, not a per-call decision here:
///
/// - `PAM_SUCCESS`: this call's daemon response was a phone tap, or a duplicate
///   answered from this process's 500 ms reuse record (a replay, which records
///   nothing and shows nothing)
/// - `PAM_PERM_DENIED`: The user explicitly denied the request on the phone
/// - `PAM_AUTHINFO_UNAVAIL`: The authentication service could not be consulted —
///   no paired devices, the user skipped, the daemon is unreachable, the
///   attempt timed out, a display-manager login or a remote caller was skipped,
///   or a pre-collected host's token was handed on. On a `sufficient` line
///   (which expands to
///   `[success=done new_authtok_reqd=done default=ignore]`) this still falls
///   through to the next module, so password fallback is preserved
/// - `PAM_AUTH_ERR`: This attempt failed while being processed — the daemon
///   reported an internal error, the conversation lookup failed, the request id
///   could not be generated, or a local resource could not be created
/// - `PAM_USER_UNKNOWN`: Failed to retrieve username from PAM
///
/// `PAM_IGNORE` is deliberately never returned.  Linux-PAM records no failure
/// for it, so a later `optional` module that votes success (e.g. `pam_permit`)
/// turns the whole stack into `PAM_SUCCESS` — an authentication bypass.  That is
/// a `required`-line hazard, and it is the shape this protects: there
/// `PAM_IGNORE` is explicitly `ignore` while `PAM_AUTHINFO_UNAVAIL` is `bad`.
/// On a `sufficient` line both codes are `ignore` and a following
/// `optional pam_permit` grants either way, so there the stack's own
/// configuration, not the return code, is what prevents the grant.
pub fn authenticate(pamh: *mut pam_sys::PamHandle) -> c_int {
    logging::init_logging();
    tracing::info!("TapAuth PAM module called (custom bindings)");

    // The caller facts are read once, here, and every consumer reads the
    // captured values — the policy, the log line in `capture`, the verdict
    // cache's key and the skip's decision. No second resolution exists.
    let ctx = unsafe { CallerContext::capture(pamh) };
    // The orchestration returns the verdict, never a code. This is the one
    // place a `PAM_*` value is produced from it: `into_pam` is exhaustive, so an
    // arm cannot be forgotten and a code cannot travel beside the verdict. A
    // conclusion is recorded here — after the body returned, which is what
    // anchors the 500 ms reuse window to *this module's return* — and `record`
    // hands the verdict back so it becomes a code exactly once. Neither arm
    // emits: `run` already emitted its outcome's one notice.
    //
    // The outside world this call asks for, as one value: the `/dev/tty` probe,
    // the nonblocking daemon dial, the authenticate request and the
    // fresh-connection cancel. Each function is bound to a local first so the
    // struct borrows a named place rather than a temporary.
    let mut probe = probe_tty;
    let mut connect = IpcClient::connect_nonblocking;
    let mut send = send_authenticate_request;
    let mut effects = Effects {
        probe_tty: &mut probe,
        connect: &mut connect,
        send: &mut send,
        cancel: cancel_on_fresh_connection,
    };
    match orchestrate(pamh, &ctx, &OrchestrationIo::production(), &mut effects) {
        Finished::Concluded(concluded) => {
            crate::conclusion_cache::record(concluded, Instant::now()).into_pam()
        }
        Finished::Unrecorded(outcome) => outcome.into_pam(),
    }
}

/// The four side-effecting calls `classify` must precede, injected so they can
/// be counted without a PAM handle.
///
/// `classify_before_side_effects` drives `orchestrate` with this table replaced
/// by counting wrappers and asserts every counter reads zero on a `Skip`. The
/// context is passed in already captured, so the test can hand `orchestrate` a
/// `CallerContext::from_parts` directly.
pub(crate) struct OrchestrationIo {
    pub load_config: fn() -> PamConfig,
    pub get_user: unsafe fn(*mut pam_sys::PamHandle) -> Result<String, c_int>,
    pub new_conversation:
        unsafe fn(*mut pam_sys::PamHandle) -> Result<pam_sys::PamConversation<'static>, c_int>,
    pub load_messages: fn(&str) -> pam_messages::PamMessages,
    /// The pre-collected handoff's token read. Injected here as well as on
    /// `HostIo` so a test that drives `orchestrate` end to end can count the
    /// read, which is the only observable the handoff has.
    pub read_authtok: pam_sys::ReadAuthtok,
}

impl OrchestrationIo {
    /// The real functions. The only constructor production uses.
    pub(crate) fn production() -> Self {
        OrchestrationIo {
            load_config: PamConfig::load,
            get_user: pam_sys::get_user,
            new_conversation: pam_sys::PamConversation::new,
            load_messages: pam_messages::load_for_user,
            read_authtok: pam_sys::read_authtok_for_handoff,
        }
    }
}

/// The module's single `/dev/tty` open.
///
/// Injected into `authenticate_inner` as a closure, the same seam
/// `Armed::open`'s `connect`/`send` have, so tests can count the probe
/// without a terminal.
fn probe_tty() -> Option<std::fs::File> {
    std::fs::File::open("/dev/tty").ok()
}

/// Run one authentication: capture the caller facts, classify, resolve the
/// inputs a participation needs, and hand the transaction to
/// [`crate::transaction::run`].
///
/// The body decides and acts; recording is the caller's (`authenticate`), so the
/// 500 ms reuse window stays anchored to *this module's return* rather than to
/// the moment the transaction concluded.
///
/// The order is load-bearing and is asserted by `classify_before_side_effects`:
/// `classify` runs **before** `PamConfig::load`, `get_user`,
/// `PamConversation::new` and `PamMessages::load_for_user`, so a `Skip` (a
/// display-manager login, a remote caller) pays none of them. `HostIo` is built
/// after those four calls and borrows what they produced, so it cannot exist on
/// a skip path.
///
/// `effects` is the transaction's outside world — the `/dev/tty` probe, the
/// daemon dial, the request on the wire and the cancel, the same seam
/// [`Armed::open`](crate::transaction::Armed::open) has. Production passes
/// `IpcClient::connect_nonblocking`, [`send_authenticate_request`] and
/// [`cancel_on_fresh_connection`] (built by [`authenticate`]), and a test passes
/// counting closures or failures, so "the skip never reaches the daemon", "a
/// connect failure records nothing" and "a timeout cancels nothing" are
/// assertions rather than promises.
fn orchestrate<T: IpcResponseReader>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    effects: &mut Effects<'_, T>,
) -> Finished {
    // The conversation policy is decided from the caller facts `capture` read,
    // and it is decided *first*: a `Skip` returns before the config read, the
    // username lookup, the conversation and the messages, which is the order
    // the display-manager bypass has always had. `classify_before_side_effects`
    // counts those four calls, because nothing in the types stops a later edit
    // from moving the decision below them.
    let (_rule, classification) = policy::classify(ctx);

    // The built-in skips — R1's service names and R2's display managers — return
    // here, before the config read. A skip is a static policy decision about the
    // caller, not a conclusion about credentials: it never reaches
    // `Armed::open`, never touches the recorded conclusion, and must not clobber
    // the last real one. `skip_finished` is the one return for either phase's
    // skip.
    if let policy::Classification::Skip(skip) = &classification {
        return skip_finished(ctx, *skip);
    }

    // Load configuration for timeouts
    let config = (io.load_config)();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

    // The second decision phase. `classify` sees only the built-in refused
    // names, so a deployment that renames OpenSSH's `PAMServiceName` arrives
    // here as a participating call; `policy::refine` is the one entry point for
    // the configured half of R1. It runs immediately after the config read and
    // before the username lookup, the conversation, the messages and the
    // transaction, and it can only add a skip: the participation it returns
    // unchanged is the one `classify` produced, mechanism and deadline
    // included.
    let participation = match policy::refine(
        classification,
        ctx.service(),
        &config.effective_refused_services(),
    ) {
        policy::Classification::Participate(participation) => participation,
        policy::Classification::Skip(skip) => return skip_finished(ctx, skip),
    };

    let username = unsafe {
        match (io.get_user)(pamh) {
            Ok(user) => {
                tracing::info!("Got username from PAM: {}", user);
                user
            }
            Err(code) => {
                tracing::error!("Failed to get username, PAM error code: {}", code);
                return Finished::Unrecorded(Outcome::UserUnknown);
            }
        }
    };

    tracing::info!("TapAuth: Authenticating user: {}", username);

    let pam_conv = unsafe {
        match (io.new_conversation)(pamh) {
            Ok(conv) => conv,
            Err(e) => {
                tracing::error!("Failed to get PAM conversation function: {}", e);
                return Finished::Unrecorded(Outcome::Error(
                    crate::outcome::ErrorReason::ConversationLookup,
                ));
            }
        }
    };

    // No explicit root check here; shared config enforces file ownership/permissions.

    let msgs = (io.load_messages)(&username);

    let mut host = HostIo::new(pamh, &pam_conv, &msgs, io.read_authtok);
    crate::transaction::run(ctx, &username, &participation, &mut host, &config, effects)
}

/// The one return for a skip, whichever of the two decision phases produced it.
///
/// `Skip` is a static decision about the caller, not a conclusion about
/// credentials: it returns before `Armed::open`, so it is never recorded, and
/// `Outcome::from_skip` is the only mapping of a `SkipPolicy` to a verdict. The
/// two log lines are the ones the module has always written for R1 and R2.
fn skip_finished(ctx: &CallerContext, skip: policy::SkipPolicy) -> Finished {
    let service = ctx.service().map(ServiceName::original).unwrap_or_default();
    match skip {
        policy::SkipPolicy::KeyringNeedsAuthtok => tracing::info!(
            "TapAuth: Service '{}' is a primary display manager. \
             Skipping to avoid breaking keyring auto-unlock.",
            service
        ),
        policy::SkipPolicy::RemoteAuthentication => tracing::info!(
            "TapAuth: Service '{}' authenticates a remote caller. \
             Skipping: this module does not take part in remote authentication.",
            service
        ),
    }
    Finished::Unrecorded(Outcome::from_skip(skip))
}

/// The production `send`: the authenticate request, on the connected client.
fn send_authenticate_request(
    ipc: &mut IpcClient,
    request: &SendParams<'_>,
) -> Result<(), IpcError> {
    ipc.send_authenticate_start(
        request.username,
        request.has_tty,
        request.timeout_secs,
        request.request_id,
    )
}

/// The production `cancel`: a *fresh* short-timeout connection, never the live
/// one.
///
/// The two exits that cancel — the terminal Enter skip and the no-terminal IPC
/// error — either no longer need the request or just watched the socket fail, so
/// a write on `Armed.ipc` would be a guaranteed no-op and the phone would keep
/// buzzing until the daemon's own deadline. It is best effort: a daemon that
/// cannot be reached takes the same path as one that never got the cancel.
fn cancel_on_fresh_connection(reason: &str, request_id: &str) {
    if let Ok(mut client) = IpcClient::connect(Duration::from_millis(100)) {
        let _ = client.send_cancel(reason, request_id);
    }
}

/// Emit an outcome's one message, then hand the outcome back.
///
/// Test-only since `HostIo::emit` became the production site: the tests below
/// drive an outcome through a real (dummy) conversation to pin the code pairs,
/// which is what `emit_notice` still expresses most directly.
#[cfg(test)]
///
/// Every return of `run` emits through this, so the message is decided by the
/// verdict and not by the site that produced it, and `into_pam` is called exactly
/// once — by `authenticate`. The emission itself is the two calls the module has
/// always made: `try_info` for information, `try_error` for an error, both of
/// which swallow a failing conversation. A replayed verdict's notice is `None`,
/// which is what keeps a cache hit silent.
fn emit_notice(
    pam_conv: &pam_sys::PamConversation,
    msgs: &pam_messages::PamMessages,
    outcome: Outcome,
) -> Outcome {
    if let Some(notice) = outcome.notice(msgs) {
        match notice.style {
            crate::outcome::NoticeStyle::Info => pam_conv.try_info(&notice.text),
            crate::outcome::NoticeStyle::Error => pam_conv.try_error(&notice.text),
        }
    }
    outcome
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
    use crate::logging;
    use crate::transaction::tests::{no_daemon, NullIpc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_logging_init() {
        logging::init_logging();
        logging::init_logging();
    }

    // ------------------------------------------------------------------
    // The ordering and single-read guarantees of `authenticate`
    // ------------------------------------------------------------------

    /// The four calls `classify` must precede, counted.
    ///
    /// The context is passed to `orchestrate` already captured, so these tests
    /// need no PAM handle and no daemon: whatever the body does after the four
    /// calls, the counters are decided before it.
    static CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);
    static USER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Timeouts of zero, so a path that gets as far as the IPC connect returns
    /// without waiting: these tests assert call counts, not waiting.
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
        // A conversation over no handle: every emission is a no-op, which is
        // all this test needs.
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

    /// An `OrchestrationIo` that counts nothing and needs no PAM handle, for the
    /// tests about the tty probe rather than about call order.
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

    /// R1 refuses a remote call before anything reaches the daemon.
    ///
    /// The defect this catches: a skip decided late enough to dial the socket,
    /// or one that sends the request and only then refuses — the phone must not
    /// be rung for a login nobody is sitting at, and the daemon must not see a
    /// request for it. The counters are the assertion: an outcome equality
    /// cannot tell a refusal that never connected from one that returned the
    /// same code after a full transaction.
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
                    cancel: |_, _| {},
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

    /// Every verdict `run` can return before a conversation exists is silent.
    ///
    /// The defect this catches: a message added to one of these reasons (say a
    /// `PAM_TEXT_INFO` for the keyring bypass). Those paths return before
    /// `PamConversation::new`, so there is nothing to emit through, and the
    /// message would be dropped silently instead of the omission being a
    /// compile-time or test-time decision.
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

    /// Run `orchestrate` for `ctx` and return the four call counters in the
    /// order `config, user, conversation, messages`.
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
                cancel: |_, _| {},
            },
        );
        [
            CONFIG_CALLS.load(Ordering::SeqCst),
            USER_CALLS.load(Ordering::SeqCst),
            CONVERSATION_CALLS.load(Ordering::SeqCst),
            MESSAGE_CALLS.load(Ordering::SeqCst),
        ]
    }

    /// `classify` runs before `PamConfig::load`, `get_user`,
    /// `PamConversation::new` and `PamMessages::load_for_user`, so a skip costs
    /// none of them.
    ///
    /// The defect this catches: moving `classify` below any of the four — the
    /// natural place is "after the config read", where the timeouts are known.
    /// Nothing else fails then: a display-manager login would still return
    /// `PAM_AUTHINFO_UNAVAIL`, it would just pay a config read, two PAM item
    /// lookups, an NSS lookup and a root-side home read first, and a skip on a
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

        // The control: a `Participate` reaches all four, so the counters above
        // are not zero merely because the harness never increments them.
        assert_eq!(
            side_effects_of(&context(Some("sudo"), Some("totally-unknown"))),
            [1, 1, 1, 1],
            "a participating call must reach every one of the four calls"
        );
    }

    // ------------------------------------------------------------------
    // Gap 8: a configured (renamed) remote service is refused after the
    // config read and before every other side effect.
    // ------------------------------------------------------------------

    /// The four side effects the configured-refusal test counts, kept on their
    /// own statics so the test cannot race `classify_before_side_effects`.
    static RENAMED_CONFIG_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RENAMED_USER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RENAMED_CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RENAMED_MESSAGE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// A config that declares the renamed service, the shape a deployment with
    /// `PAMServiceName sshd-renamed` writes.
    fn renamed_config() -> PamConfig {
        RENAMED_CONFIG_CALLS.fetch_add(1, Ordering::SeqCst);
        PamConfig {
            pam_refused_services: vec!["sshd-renamed".to_owned()],
            ..zero_timeouts()
        }
    }

    /// The same config without the extra name: the pre-gap-8 situation, and the
    /// negative control's input.
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

    /// Serialises the two `run_renamed` tests: they share the counters above and
    /// `cargo test` runs tests in parallel threads, so one resetting mid-run
    /// would make the other's count meaningless. A poisoned lock is reused: a
    /// panic in one test must not fail the other for the wrong reason.
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
                cancel: |_, _| {},
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

    /// A service name added to `pam_refused_services` is refused exactly like a
    /// built-in one: R1's verdict, after the config read, before every other
    /// side effect.
    ///
    /// The defect this catches, in both directions: without the enforcement
    /// point a renamed `PAMServiceName` is classified R10 and a remote login
    /// rings the phone and waits out the GUI timeout (the counters would be
    /// non-zero and the verdict `DaemonUnreachable`); an enforcement point that
    /// runs before the config read cannot see the configured list at all, and
    /// one placed after the username lookup, the conversation or the messages
    /// would still pay them — and would emit through a live `HostIo`, which is
    /// why the verdict's notice is asserted `None` here (the refusal returns
    /// before a `HostIo` exists).
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

    /// The negative control: the same caller with no configured extras is a
    /// participating call (R10) and does reach `get_user`.
    ///
    /// The defect this catches: a harness that counts nothing — the zeros above
    /// would then also pass for a `get_user` that is never wired in — and an
    /// enforcement point that refuses on the *process* name (`sshd`) rather than
    /// the service name, which would silence a local stack that happens to be
    /// named `sshd-renamed`.
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

    /// The conversation lookups a skip must not perform, counted separately from
    /// `counting_io` so the two tests cannot race on one static.
    static SKIP_CONVERSATION_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// The handoff token reads, counted separately from the other statics so a
    /// concurrent test cannot make the count meaningless.
    static HANDOFF_TOKEN_READS: AtomicUsize = AtomicUsize::new(0);

    unsafe fn skip_conversation(
        _pamh: *mut pam_sys::PamHandle,
    ) -> Result<pam_sys::PamConversation<'static>, c_int> {
        SKIP_CONVERSATION_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(unsafe { pam_sys::PamConversation::dummy() })
    }

    /// The injected handoff reader: counts the read and supplies no token.
    ///
    /// A successful read with a null token is the handoff's "nothing was
    /// collected" branch, so the only thing this reader's answer changes is the
    /// log line — the count is what the test asserts.
    unsafe fn counting_authtok(
        _pamh: *mut pam_sys::PamHandle,
    ) -> (c_int, *const std::os::raw::c_char) {
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

    /// A skip never reaches the handoff, which is asserted on the token read
    /// itself.
    ///
    /// The two no-daemon paths are not one category: R1 and R2 skip the handle
    /// entirely (no plan, no deadline, no conversation), while R8's pre-collected
    /// handoff *must* touch it — it calls `pam_get_authtok` on the calling thread
    /// and leaves `PAM_AUTHTOK` for the next module. The defect this catches: a
    /// skip routed through the participation path, so a display-manager login or
    /// a remote call reads the token (and answers `PasswordHandoff` instead of
    /// its own reason). The read is counted where it happens — through the
    /// reader `transaction::HostIo` carries — rather than inferred from the
    /// absence of a conversation; the R8 control at the end is what proves the
    /// counter fires at all, so the two zeros cannot be vacuous.
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
                    cancel: |_, _| {},
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

        // The positive control: R8's pre-collected host reaches the handoff, so
        // the same reader counts exactly one read and the verdict is the
        // handoff's. Without it the two zeros above would also pass for a reader
        // that is never wired into the handoff at all.
        HANDOFF_TOKEN_READS.store(0, Ordering::SeqCst);
        let finished = orchestrate(
            std::ptr::null_mut(),
            &context(Some("test-service"), Some("swaylock")),
            &skip_io(),
            &mut Effects {
                probe_tty: &mut probe_tty,
                connect: &mut || Err::<NullIpc, _>(no_daemon()),
                send: &mut |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
                cancel: |_, _| {},
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

    #[test]
    fn test_map_pam_outcome_matrix() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");
        // The daemon-answer path as the call sites run it: the verdict, its one
        // message and its code, from the response alone.
        let map = |resp: shared::ipc::pb::PamAuthenticateResponse| {
            emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).into_pam()
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

        // An explicit phone denial must stay a denial: it fails in both the
        // `required` and the `[success=done default=bad]` stack shapes.
        assert_eq!(
            map(resp_for(shared::ipc::pb::PamOutcome::Denied, "Denied")),
            pam_sys::PAM_PERM_DENIED
        );

        // No usable answer from the service (timeout, skip, no paired device):
        // the auth service could not be consulted.
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

        // The daemon answered but could not process the attempt.
        assert_eq!(
            map(resp_for(shared::ipc::pb::PamOutcome::Error, "boom")),
            pam_sys::PAM_AUTH_ERR
        );
    }

    /// The `outcome` field is a raw `i32` on the wire, so a peer can put any
    /// value in it. Unknown values must fail closed (`Error` → `PAM_AUTH_ERR`)
    /// rather than decode to `PamOutcome::default()` = `SUCCESS`.
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

    /// Wire-level version of the test above: hand-encode a
    /// `PamAuthenticateResponse` whose `outcome` field is an unknown value,
    /// decode it with prost and drive the real PAM mapping.
    ///
    /// Layout (proto3): `outcome` is field 1, varint, so the tag byte is
    /// `(1 << 3) | 0 == 0x08`, followed by the value's base-128 varint. `detail`
    /// and `challenge` are empty and therefore absent from the encoding.
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

            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).into_pam();
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

    /// Regression test for the `PAM_IGNORE` authentication bypass.
    ///
    /// Linux-PAM records no failure for `PAM_IGNORE`, so in a stack shaped like
    /// `auth required pam_tapauth.so` + `auth optional pam_permit` +
    /// `auth required pam_env` the `optional` module's success vote turned the
    /// whole stack into `PAM_SUCCESS` — a grant without any phone approval.
    /// No daemon outcome may map to `PAM_IGNORE`.
    #[test]
    fn test_no_pam_outcome_maps_to_pam_ignore() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");

        // Every variant of the IPC enum. This list is not compiler-enforced:
        // the `match` in `Outcome::from_daemon` is exhaustive but this array is
        // not, so extend this list by hand when adding a variant.
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
            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).into_pam();
            // `PAM_IGNORE` is 25 and is deliberately absent from this list: it
            // is not a verdict, so a later `optional pam_permit` can still make
            // the whole stack succeed.
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
}

/// The verdict-reuse record: the 500 ms window, its `(username, service)` key,
/// and the two gates that decide what may be recorded.
///
/// Every case drives the real `conclusion_cache::record` /
/// `conclusion_cache::replay_for`
/// pair, so the assertions are about the record `authenticate` writes and reads
/// and not about a parallel copy of its logic; each case holds
/// `conclusion_cache::CACHE_SLOT_LOCK` for its whole body, because the record is one
/// slot for the process.
// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod verdict_reuse_tests {
    use super::*;
    use crate::conclusion_cache::{record, replay_for};
    use crate::outcome::{DenyVia, UnavailableReason};
    use crate::transaction::tests::{no_daemon, NullIpc};
    use crate::transaction::{Armed, Concluded, StartError, Via};

    const SERVICE: &str = "tapauth-test";

    /// The three verdicts these tests replay: a grant, an unavailable service
    /// and an explicit denial. They are the three the daemon can reach, and the
    /// record stores the verdict itself now, so a replay cannot re-enter the
    /// code path.
    fn granted() -> Outcome {
        Outcome::granted_from_daemon()
    }

    fn unavailable() -> Outcome {
        Outcome::Unavailable(UnavailableReason::TimedOut)
    }

    fn denied() -> Outcome {
        Outcome::Denied(DenyVia::PhoneDenial)
    }

    /// The mechanism exit a recorded verdict arrives as.
    ///
    /// `Armed::conclude` takes a `MechanismEnd` now — a mechanism never mints an
    /// `Outcome` — so a test that records one of the three verdicts the daemon
    /// can reach has to name the exit that produces it.
    fn end_of(outcome: &Outcome) -> crate::transaction::MechanismEnd {
        use crate::transaction::MechanismEnd;
        match outcome {
            Outcome::Granted(_) => {
                let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
                resp.set_outcome(shared::ipc::pb::PamOutcome::Success);
                MechanismEnd::Response(resp)
            }
            Outcome::Denied(_) => {
                let mut resp = shared::ipc::pb::PamAuthenticateResponse::default();
                resp.set_outcome(shared::ipc::pb::PamOutcome::Denied);
                MechanismEnd::Response(resp)
            }
            Outcome::Unavailable(reason) => MechanismEnd::Reason(*reason),
            other => unreachable!(
                "the daemon reaches a grant, a denial or an unavailability, not {other:?}"
            ),
        }
    }

    /// The single process-wide slot, held for the whole case.
    fn slot() -> std::sync::MutexGuard<'static, ()> {
        crate::conclusion_cache::CACHE_SLOT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `outcome` for `(user, service)` as if it had concluded `ms_ago`,
    /// through the same `Armed` — conclude — record path `authenticate` uses,
    /// and hand back the instant the lookup should use.
    fn record_ago(ms_ago: u64, user: &str, service: Option<&str>, outcome: Outcome) -> Instant {
        let now = Instant::now();
        let concluded = crate::transaction::armed_for_test(NullIpc, "reuse-test-request").conclude(
            end_of(&outcome),
            user,
            service.map(ServiceName::new),
        );
        let _ = record(concluded, now - Duration::from_millis(ms_ago));
        now
    }

    /// The verdict a lookup returns for `(user, service)` at `now`.
    ///
    /// A hit is `Outcome::replayed(..)` of what was recorded: the marker is the
    /// provenance this step adds, and `record` is what refuses it.
    fn replayable(user: &str, service: &str, now: Instant) -> Option<Outcome> {
        replay_for(user, service, now).map(|concluded| concluded.outcome().clone())
    }

    #[test]
    fn a_success_inside_the_window_is_reused() {
        let _slot = slot();
        let now = record_ago(400, "alice", Some(SERVICE), granted());
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&granted())),
            "a success 400 ms old must still be replayable inside the 500 ms window"
        );
    }

    #[test]
    fn a_success_after_the_window_is_not_reused() {
        let _slot = slot();
        let now = record_ago(600, "alice", Some(SERVICE), granted());
        assert_eq!(
            replayable("alice", SERVICE, now),
            None,
            "a success 600 ms old is outside the window and must start a new transaction"
        );
    }

    #[test]
    fn an_unavailability_inside_the_window_is_reused() {
        let _slot = slot();
        let now = record_ago(400, "alice", Some(SERVICE), unavailable());
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "the duplicate is queued while the first transaction runs, so the \
             unavailability it just reached must be replayed instead of ringing \
             the phone for a second full timeout"
        );
    }

    #[test]
    fn a_denial_inside_the_window_is_reused() {
        let _slot = slot();
        let now = record_ago(400, "alice", Some(SERVICE), denied());
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&denied())),
            "a concluded denial must be replayed for the duplicate, not re-asked"
        );
    }

    #[test]
    fn an_unavailability_after_the_window_is_not_reused() {
        let _slot = slot();
        let now = record_ago(600, "alice", Some(SERVICE), unavailable());
        assert_eq!(
            replayable("alice", SERVICE, now),
            None,
            "outside the window a failure must be re-derived: this is what keeps a \
             human retry from being answered by a stale verdict"
        );
    }

    #[test]
    fn another_users_conclusion_is_never_reused() {
        let _slot = slot();
        for outcome in [granted(), unavailable(), denied()] {
            let code = outcome.clone().into_pam();
            let now = record_ago(1, "alice", Some(SERVICE), outcome);
            assert_eq!(
                replayable("bob", SERVICE, now),
                None,
                "code {code} recorded for alice must never answer for bob"
            );
        }
    }

    #[test]
    fn another_services_conclusion_is_never_reused() {
        let _slot = slot();
        for outcome in [granted(), unavailable(), denied()] {
            let code = outcome.clone().into_pam();
            let now = record_ago(1, "alice", Some("kscreenlocker"), outcome);
            assert_eq!(
                replayable("alice", "polkit-1", now),
                None,
                "code {code} recorded for one service must never answer a \
                 different service: only the transaction the host is retrying may \
                 be replayed, every other stack must ring the phone"
            );
        }
    }

    #[test]
    fn recording_a_failure_replaces_the_cached_success() {
        let _slot = slot();
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "replace-success-request")
            .conclude(end_of(&granted()), "alice", Some(ServiceName::new(SERVICE)));
        record(recorded, now);
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&granted()))
        );

        let recorded = crate::transaction::armed_for_test(NullIpc, "replace-failure-request")
            .conclude(
                end_of(&unavailable()),
                "alice",
                Some(ServiceName::new(SERVICE)),
            );
        record(recorded, now);
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "the record holds the *last* conclusion, so a later failure must \
             overwrite the earlier success"
        );
    }

    /// A connect failure says nothing about the phone, so it must leave the
    /// process-wide record unarmed — and a retry must therefore be able to start
    /// a real transaction instead of replaying a verdict that never existed.
    ///
    /// The key is unique to this test: the record is process-wide and other
    /// tests in this module write to it in parallel.
    ///
    /// Not covered here: a *caller* that records before opening a request —
    /// `record` takes a `Concluded` by value and `Armed::conclude` is its only
    /// fresh producer, so that shape is a move error rather than something a
    /// test has to look for. `armed_requires_both_connect_and_send` covers the
    /// arming itself.
    #[test]
    fn a_failed_connect_records_nothing_and_the_retry_dials_again() {
        let _slot = slot();

        const USER: &str = "failed-connect-user";
        const UNIQUE_SERVICE: &str = "failed-connect-service";
        let now = Instant::now();

        let first = Armed::<NullIpc>::open(
            &mut || Err(no_daemon()),
            &mut |_: &mut NullIpc| Ok(()),
            "failed-connect-request".into(),
        );
        assert!(
            matches!(first, Err(StartError::Connect(_))),
            "a refused connect must surface as a connect failure"
        );
        assert!(
            replayable(USER, UNIQUE_SERVICE, now).is_none(),
            "a local IPC failure is not a verdict about the phone: recording one \
             would let the duplicate inherit PAM_AUTHINFO_UNAVAIL without the \
             phone ever being asked"
        );

        // The retry: with nothing recorded it must dial again and arm a real
        // transaction, whose conclusion *is* recorded.
        let Ok(armed) = Armed::<NullIpc>::open(
            &mut || Ok(NullIpc),
            &mut |_: &mut NullIpc| Ok(()),
            "retry-request".into(),
        ) else {
            panic!("the retry must be able to connect after the failed attempt");
        };
        let concluded = armed.conclude(
            end_of(&unavailable()),
            USER,
            Some(ServiceName::new(UNIQUE_SERVICE)),
        );
        assert_eq!(
            concluded.via(),
            Via::Daemon,
            "the armed request is this call's own, so `record` must accept its conclusion"
        );
        assert_eq!(record(concluded, now), unavailable());
        assert_eq!(
            replayable(USER, UNIQUE_SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "the retry's conclusion must be recorded, unlike the failed connect"
        );
    }

    /// A verdict replayed from the record must not be recorded again: that would
    /// refresh the timestamp and turn the fixed 500 ms window into a sliding one.
    #[test]
    fn a_from_cache_verdict_is_not_recorded() {
        let _slot = slot();

        const USER: &str = "from-cache-user";
        const UNIQUE_SERVICE: &str = "from-cache-service";
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "original-request").conclude(
            end_of(&denied()),
            USER,
            Some(ServiceName::new(UNIQUE_SERVICE)),
        );
        record(recorded, now);

        // A replay carrying a *different* verdict, recorded again on purpose: if
        // `record` accepted it, the slot would hold the grant instead of the
        // denial and the assertion below would see it.
        let replay = Concluded::replay(granted(), USER.into(), ServiceName::new(UNIQUE_SERVICE));
        assert_eq!(record(replay, now), Outcome::replayed(&granted()));
        assert_eq!(
            replayable(USER, UNIQUE_SERVICE, now),
            Some(Outcome::replayed(&denied())),
            "a cache hit must not be re-recorded: it would overwrite the original \
             code and refresh the timestamp, making the window sliding"
        );
    }

    /// An unresolved service is never cached: the empty string would collapse
    /// every such call into one key.
    #[test]
    fn an_unresolved_service_is_not_recorded() {
        let _slot = slot();

        const USER: &str = "unresolved-service-user";
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "unresolved-service-request")
            .conclude(end_of(&unavailable()), USER, None);
        assert_eq!(record(recorded, now), unavailable());
        assert!(
            replayable(USER, "", now).is_none(),
            "a call without a service name must record nothing: an empty string \
             would merge unrelated services into one key"
        );
    }

    #[test]
    fn a_future_timestamp_does_not_panic() {
        let _slot = slot();
        let now = Instant::now();

        let recorded = crate::transaction::armed_for_test(NullIpc, "future-timestamp-request")
            .conclude(
                end_of(&unavailable()),
                "alice",
                Some(ServiceName::new(SERVICE)),
            );
        record(recorded, now + Duration::from_millis(50));
        // `saturating_duration_since` reads a clock anomaly as "no time has
        // passed", so the conclusion still counts as fresh.  The point of the
        // test is that it must not panic.
        assert_eq!(
            replayable("alice", SERVICE, now),
            Some(Outcome::replayed(&unavailable())),
            "a record stamped in the future must read as fresh, not panic"
        );
    }
}
