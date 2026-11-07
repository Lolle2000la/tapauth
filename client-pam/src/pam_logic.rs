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
use crate::transaction::{Finished, HostIo, SendParams};
use std::os::raw::c_int;
use std::time::{Duration, Instant};

/// Main PAM authentication entry point.
///
/// ## Returns
///
/// The orchestration returns a [`Finished`], whose two arms both carry an
/// [`Outcome`]; `Outcome::to_pam` is the only conversion, and the `match` below
/// is its only caller. Which reasons reach which code is the table in
/// `Outcome::to_pam` / `Outcome::notice`, not a per-call decision here:
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
    // place a `PAM_*` value is produced from it: `to_pam` is exhaustive, so an
    // arm cannot be forgotten and a code cannot travel beside the verdict. A
    // conclusion is recorded here — after the body returned, which is what
    // anchors the 500 ms reuse window to *this module's return* — and `record`
    // hands the verdict back so it becomes a code exactly once. Neither arm
    // emits: `run` already emitted its outcome's one notice.
    match orchestrate(
        pamh,
        &ctx,
        &OrchestrationIo::production(),
        IpcClient::connect_nonblocking,
        send_authenticate_request,
        cancel_on_fresh_connection,
    ) {
        Finished::Concluded(concluded) => {
            crate::transaction::record(concluded, Instant::now()).to_pam()
        }
        Finished::Unrecorded(outcome) => outcome.to_pam(),
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
/// `connect`, `send` and `cancel` are the transaction's injected effects, the
/// same seam `Armed::open` has: production passes
/// `IpcClient::connect_nonblocking`, [`send_authenticate_request`] and
/// [`cancel_on_fresh_connection`], and a test passes counting closures or
/// failures, so "the skip never reaches the daemon", "a connect failure records
/// nothing" and "a timeout cancels nothing" are assertions rather than promises.
fn orchestrate<T, C, S>(
    pamh: *mut pam_sys::PamHandle,
    ctx: &CallerContext,
    io: &OrchestrationIo,
    connect: C,
    send: S,
    cancel: fn(&str, &str),
) -> Finished
where
    T: IpcResponseReader,
    C: FnOnce() -> Result<T, IpcError>,
    S: FnOnce(&mut T, &SendParams<'_>) -> Result<(), IpcError>,
{
    // The conversation policy is decided from the caller facts `capture` read,
    // and it is decided *first*: a `Skip` returns before the config read, the
    // username lookup, the conversation and the messages, which is the order
    // the display-manager bypass has always had. `classify_before_side_effects`
    // counts those four calls, because nothing in the types stops a later edit
    // from moving the decision below them.
    let classification = policy::classify(ctx);

    let participation = match classification {
        policy::Classification::Participate(participation) => participation,
        // The two skip policies — a display-manager login (R2) and a remote
        // caller (R1) — return here, before the username is resolved, so a skip
        // never reaches `Armed::open` and never touches the recorded
        // conclusion.  That is deliberate: it is a static policy decision about
        // the caller, not a conclusion about credentials.  Only a daemon-path
        // conclusion is ever recorded, and a pre-IPC path must not clobber the
        // last real one.  `Outcome::from_skip` is the only mapping of a
        // `SkipPolicy` to a verdict.
        policy::Classification::Skip(skip) => {
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
            return Finished::Unrecorded(Outcome::from_skip(skip));
        }
    };

    // Load configuration for timeouts
    let config = (io.load_config)();
    tracing::debug!(
        "PAM operation timeout: {}s",
        config.pam_operation_timeout_secs
    );

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
    crate::transaction::run(
        ctx,
        &username,
        &participation,
        &mut host,
        &config,
        probe_tty,
        connect,
        send,
        cancel,
    )
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
/// verdict and not by the site that produced it, and `to_pam` is called exactly
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
                || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    Err::<NullIpc, _>(no_daemon())
                },
                |_: &mut NullIpc, _: &SendParams<'_>| {
                    sends.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                |_, _| {},
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
                finished.outcome().clone().to_pam(),
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
            || Err::<IpcClient, _>(no_daemon()),
            |_: &mut IpcClient, _: &SendParams<'_>| Ok(()),
            |_, _| {},
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
                || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    Err::<NullIpc, _>(no_daemon())
                },
                |_: &mut NullIpc, _: &SendParams<'_>| {
                    sends.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                |_, _| {},
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
            || Err::<NullIpc, _>(no_daemon()),
            |_: &mut NullIpc, _: &SendParams<'_>| Ok(()),
            |_, _| {},
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

    /// `PAM_SERVICE` is read at exactly one call site, in `CallerContext::capture`.
    ///
    /// The defect this catches: a second `pam_sys::get_service_name(pamh)` call
    /// reappearing in `pam_logic.rs`. The pre-refactor tree resolved the service
    /// twice — once in the display-manager bypass and once for the conversation
    /// mode, the cache key and the request — so the bypass could decide from one
    /// string while the cache keyed on another.
    ///
    /// Same technique and the same positive-control discipline as
    /// `test_module_source_contains_no_pam_ignore_return`: the source is stripped
    /// of comments and literals first, and the detector is proved to fire on an
    /// in-memory snippet so an emptied or relocated scan cannot pass silently.
    #[test]
    fn only_one_get_service_name_call_site() {
        const NEEDLE: &str = "get_service_name";
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        // The shared recursive walk, not one `read_dir` level: a second read
        // could appear in `mechanism/`, which is a directory with no `rs`
        // extension, and a single-level scan would stay green while missing it.
        for required in [
            "context.rs",
            "pam_sys.rs",
            "mechanism/sequential.rs",
            "mechanism/threaded.rs",
        ] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        let mut definitions = 0usize;
        let mut call_sites: Vec<String> = Vec::new();
        for path in &files {
            let cleaned = production_source(path);
            let name = &relative_to_src(path);
            for (line, text) in identifier_hits(&cleaned, NEEDLE) {
                if text.contains("fn get_service_name") {
                    definitions += 1;
                } else {
                    call_sites.push(format!("{name}:{line}: {text}"));
                }
            }
        }

        assert_eq!(
            definitions, 1,
            "expected exactly one definition of {NEEDLE}, found {definitions}"
        );
        assert_eq!(
            call_sites.len(),
            1,
            "PAM_SERVICE must be read at exactly one call site, found:\n{}",
            call_sites.join("\n")
        );
        let only = call_sites.first().map(String::as_str).unwrap_or_default();
        assert!(
            only.starts_with("context.rs:"),
            "the single read must be `CallerContext::capture`, found {only}"
        );

        // Positive control: two planted call sites must both be reported, or a
        // scan that stopped matching would pass the assertion above.
        let planted = stripped_source(
            "let a = pam_sys::get_service_name(pamh);\n\
             let b = pam_sys::get_service_name(pamh);\n",
        );
        assert_eq!(
            identifier_hits(&planted, NEEDLE).len(),
            2,
            "the detector must report both planted call sites"
        );
    }

    /// The remote-user item is read nowhere in this crate's production code.
    ///
    /// The defect this catches: the retired `PAM_RUSER` fallback reappearing,
    /// either by identifier or by the item's numeric value — `pam_get_item(pamh,
    /// 8, ..)` is the same read without the name, which a name-only scan would
    /// miss. A resolved name for the wrong account is the whole reason the
    /// fallback is gone: it became the daemon request's username, the cache key
    /// and the locale lookup's NSS name.
    ///
    /// Only the production half of each file is scanned, because the test that
    /// pins the removal names the item in strings.
    #[test]
    fn no_ruser_read() {
        const ITEM: &str = "PAM_RUSER";
        // The item's numeric value, spelled arithmetically so this test's own
        // source carries no literal for its own scan to find.
        let item_number: u128 = 2 * 2 * 2;

        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        // The shared recursive walk and the same `#[cfg(test)]`-module split as
        // the other scans, so a read in `mechanism/` is covered and this file's
        // own test module is exempt.
        for required in ["pam_sys.rs", "mechanism/sequential.rs"] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}, home of the user item: {names:?}"
            );
        }

        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let name = relative_to_src(path);
            let cleaned = production_source(path);
            for (line, text) in identifier_hits(&cleaned, ITEM) {
                findings.push(format!("{name}:{line}: {ITEM} read in: {text}"));
            }
            for (line, text) in numeric_literals_equal_to(&cleaned, item_number) {
                findings.push(format!(
                    "{name}:{line}: item value {item_number} used in: {text}"
                ));
            }
        }
        assert!(
            findings.is_empty(),
            "a null PAM_USER must fail closed, not fall back to another item:\n{}",
            findings.join("\n")
        );

        // Positive control: both detectors must fire on an in-memory snippet, or
        // an emptied or broken scan passes for the wrong reason.
        let planted = stripped_source(
            "let a = pam_get_item(pamh, 8, &mut item);\n\
             let b = ffi::PAM_RUSER;\n",
        );
        assert_eq!(
            identifier_hits(&planted, ITEM).len(),
            1,
            "the identifier detector must report the planted item"
        );
        assert_eq!(
            numeric_literals_equal_to(&planted, item_number),
            vec![(1, "8".to_owned())],
            "the numeric detector must report the planted item value"
        );
    }

    #[test]
    fn test_map_pam_outcome_matrix() {
        let conv = unsafe { pam_sys::PamConversation::dummy() };
        let msgs = pam_messages::load_for_user("testuser");
        // The daemon-answer path as the call sites run it: the verdict, its one
        // message and its code, from the response alone.
        let map = |resp: shared::ipc::pb::PamAuthenticateResponse| {
            emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam()
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

            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam();
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
            let code = emit_notice(&conv, &msgs, Outcome::from_daemon(resp)).to_pam();
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

    /// Blank every comment, string literal and char literal, keeping the
    /// newlines so that the reported line numbers still match the file on disk.
    ///
    /// The docs in this crate deliberately name the forbidden code in prose, and
    /// the test's own assertions quote both needles, so scanning raw source
    /// would flag those instead of the return site it is looking for.
    ///
    /// Runs over bytes: every delimiter involved is ASCII, and the crate's
    /// sources are ASCII apart from localisation strings, which are blanked
    /// here.  A non-ASCII *char* literal would be taken for a lifetime and
    /// copied verbatim, which can only hide a needle, never invent one.
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn stripped_source(source: &str) -> String {
        let b = source.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0usize;
        while i < b.len() {
            // Line comment.
            if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Block comment (Rust nests them).
            if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        if b[i] == b'\n' {
                            out.push(b'\n');
                        }
                        i += 1;
                    }
                }
                continue;
            }
            // Raw strings: `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`.
            let raw_at = if b[i] == b'r' {
                Some(i + 1)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'r') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(at) = raw_at {
                let mut hashes = 0usize;
                while b.get(at + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if b.get(at + hashes) == Some(&b'"') {
                    let mut j = at + hashes + 1;
                    let mut end = b.len();
                    while j < b.len() {
                        if b[j] == b'"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&b'#')) {
                            end = j + 1 + hashes;
                            break;
                        }
                        j += 1;
                    }
                    out.extend(blank(b, i, end));
                    i = end;
                    continue;
                }
            }
            // Normal and byte strings, honouring backslash escapes.
            let quote_at = if b[i] == b'"' {
                Some(i)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'"') {
                Some(i + 1)
            } else {
                None
            };
            if let Some(q) = quote_at {
                let mut j = q + 1;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2;
                    } else if b[j] == b'"' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                let end = j.min(b.len());
                out.extend(blank(b, i, end));
                i = end;
                continue;
            }
            // Char literals and byte chars.  A tick that does not open a
            // one-character or escaped literal is a lifetime (`'a`) and is
            // copied verbatim.
            let tick_at = if b[i] == b'\'' {
                Some(i)
            } else if b[i] == b'b' && b.get(i + 1) == Some(&b'\'') {
                Some(i + 1)
            } else {
                None
            };
            if let Some(t) = tick_at {
                let opens_literal = matches!(
                    (b.get(t + 1), b.get(t + 2)),
                    (Some(&b'\\'), _) | (Some(_), Some(&b'\''))
                );
                if !opens_literal {
                    out.push(b[i]);
                    i += 1;
                    continue;
                }
                let mut j = t + 1;
                if b.get(j) == Some(&b'\\') {
                    j += 2;
                    // `'\u{1F600}'`
                    if b.get(j - 1) == Some(&b'u') && b.get(j) == Some(&b'{') {
                        while j < b.len() && b[j] != b'}' {
                            j += 1;
                        }
                        j += 1;
                    }
                } else {
                    j += 1;
                }
                if b.get(j) == Some(&b'\'') {
                    j += 1;
                }
                let end = j.min(b.len());
                out.extend(blank(b, i, end));
                i = end;
                continue;
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// `bytes[start..end]` as spaces, keeping its newlines.
    #[allow(clippy::indexing_slicing)]
    fn blank(bytes: &[u8], start: usize, end: usize) -> Vec<u8> {
        bytes[start..end]
            .iter()
            .map(|&c| if c == b'\n' { b'\n' } else { b' ' })
            .collect()
    }

    /// The source line containing byte offset `at`, trimmed.
    fn line_at(source: &str, at: usize) -> String {
        let start = source[..at].rfind('\n').map_or(0, |n| n + 1);
        let end = source[at..].find('\n').map_or(source.len(), |n| at + n);
        source[start..end].trim().to_owned()
    }

    /// Every occurrence of `needle` used as a whole identifier, as
    /// `(line, source line)`.
    #[allow(clippy::indexing_slicing)]
    fn identifier_hits(cleaned: &str, needle: &str) -> Vec<(usize, String)> {
        let b = cleaned.as_bytes();
        let mut hits = Vec::new();
        let mut from = 0usize;
        while let Some(offset) = cleaned[from..].find(needle) {
            let start = from + offset;
            let end = start + needle.len();
            let is_ident_char = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
            let whole_word = !(start > 0 && is_ident_char(&b[start - 1]))
                && !(end < b.len() && is_ident_char(&b[end]));
            if whole_word {
                let line = cleaned[..start].matches('\n').count() + 1;
                hits.push((line, line_at(cleaned, start)));
            }
            from = end;
        }
        hits
    }

    /// Every occurrence of `PAM_IGNORE` used as an identifier, as
    /// `(line, source line)`.
    fn pam_ignore_identifiers(cleaned: &str) -> Vec<(usize, String)> {
        identifier_hits(cleaned, "PAM_IGNORE")
    }

    /// Every numeric literal in `cleaned` whose value equals `code`, as
    /// `(line, token)`.
    ///
    /// The literal is evaluated rather than substring-matched, so `0.25`
    /// (rounded float), `0x25` (hex 37) and `1_025` (1025) are not hits while
    /// `25u32` is.
    #[allow(clippy::indexing_slicing)]
    fn numeric_literals_equal_to(cleaned: &str, code: u128) -> Vec<(usize, String)> {
        let b = cleaned.as_bytes();
        let mut hits = Vec::new();
        let mut i = 0usize;
        while i < b.len() {
            // Skip a digit that continues an identifier (`foo25`).
            let begins_literal = b[i].is_ascii_digit()
                && !(i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'));
            if !begins_literal {
                i += 1;
                continue;
            }
            let (value, next) = read_numeric_literal(b, i);
            if value == Some(code) {
                let line = cleaned[..i].matches('\n').count() + 1;
                hits.push((line, cleaned[i..next].to_owned()));
            }
            i = next.max(i + 1);
        }
        hits
    }

    /// Read the numeric literal starting at `start` as `(value, end)`, with
    /// `None` for floats.
    #[allow(clippy::indexing_slicing)]
    fn read_numeric_literal(b: &[u8], start: usize) -> (Option<u128>, usize) {
        let mut i = start;
        let radix = if b[i] == b'0' {
            match b.get(i + 1).copied() {
                Some(b'x' | b'X') => Some(16u32),
                Some(b'o' | b'O') => Some(8u32),
                Some(b'b' | b'B') => Some(2u32),
                _ => None,
            }
        } else {
            None
        };
        if let Some(radix) = radix {
            i += 2;
            let mut digits = String::new();
            while let Some(&c) = b.get(i) {
                if c == b'_' {
                    i += 1;
                } else if (c as char).is_digit(radix) {
                    digits.push(c as char);
                    i += 1;
                } else {
                    break;
                }
            }
            while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
                i += 1;
            }
            return (u128::from_str_radix(&digits, radix).ok(), i);
        }

        let mut digits = String::new();
        let mut is_float = false;
        while let Some(&c) = b.get(i) {
            if c == b'_' {
                i += 1;
            } else if c.is_ascii_digit() {
                digits.push(c as char);
                i += 1;
            } else {
                break;
            }
        }
        if b.get(i) == Some(&b'.') && matches!(b.get(i + 1), Some(c) if c.is_ascii_digit()) {
            is_float = true;
            i += 1;
            while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
                i += 1;
            }
        }
        if matches!(b.get(i).copied(), Some(b'e' | b'E'))
            && matches!(b.get(i + 1).copied(), Some(c) if c.is_ascii_digit() || c == b'+' || c == b'-')
        {
            is_float = true;
            i += 2;
            while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
                i += 1;
            }
        }
        // Integer/float suffix (`25u32`, `1.5f64`).
        while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
            i += 1;
        }
        if is_float {
            return (None, i);
        }
        (digits.parse::<u128>().ok(), i)
    }

    // ------------------------------------------------------------------
    // The two scans step 4d turns on: no PAM code outside `outcome.rs`, and
    // no grant outside the two constructors.
    // ------------------------------------------------------------------

    /// Every `client-pam/src/**/*.rs`, sorted, so a new module cannot be added
    /// and stay outside the scans.
    ///
    /// Recursive: `src/mechanism/` is a directory with no `rs` extension, so a
    /// single-level `read_dir` would silently stop covering the mechanisms once
    /// step 6 creates them.
    pub(crate) fn source_files() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            let mut paths: Vec<std::path::PathBuf> = entries
                .map(|entry| entry.expect("readable dir entry").path())
                .collect();
            paths.sort();
            for path in paths {
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut files = Vec::new();
        walk(src, &mut files);
        files.sort();
        files
    }

    /// A source file's path relative to `src`, e.g. `outcome.rs` or
    /// `mechanism/threaded.rs`. Every exemption below is written against this,
    /// never against a bare file name.
    pub(crate) fn relative_to_src(path: &std::path::Path) -> String {
        let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        path.strip_prefix(src)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    /// The production half of a source file: everything before the first
    /// `#[cfg(test)]` **module**.
    ///
    /// The tests below quote every forbidden token, so scanning the whole file
    /// would flag the assertions instead of the code. Cutting at the test
    /// *module* rather than at the first `#[cfg(test)]` item is what keeps the
    /// production code above it in the scan: a file that carries a test-only
    /// accessor early (`transaction.rs`'s `Finished::outcome`, `context.rs`'s
    /// `from_parts`, `pam_sys.rs`'s `dummy`) would otherwise be scanned only up
    /// to that item, and every assertion over the file would pass vacuously.
    pub(crate) fn production_source(path: &std::path::Path) -> String {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let end = test_module_start(&source).unwrap_or(source.len());
        stripped_source(&source[..end])
    }

    /// The byte offset of the first `#[cfg(test)]` **module**, i.e. the start
    /// of the file's test module.
    ///
    /// Only an attribute that decorates a `mod` item counts — not a test-only
    /// `fn`, accessor or `impl`, which sits inside the production half and must
    /// stay in the scanned text. The attribute block may carry further
    /// attributes (`#[allow(..)]`, which is what every test module here uses)
    /// and indentation, so the item is found by skipping to the first line that
    /// is not itself an attribute, a doc comment or blank.
    fn test_module_start(source: &str) -> Option<usize> {
        let lines: Vec<&str> = source.split_inclusive('\n').collect();
        let mut offsets = Vec::with_capacity(lines.len() + 1);
        let mut offset = 0usize;
        for line in &lines {
            offsets.push(offset);
            offset += line.len();
        }
        offsets.push(offset);

        for (index, line) in lines.iter().enumerate() {
            if line.trim() != "#[cfg(test)]" {
                continue;
            }
            let mut next = index + 1;
            // Square-bracket depth, so a multi-line `#[allow(..)]` between the
            // `cfg` and the `mod` does not look like the item. Comments are
            // skipped without counting, so a doc block quoting `[` cannot push
            // the scan past the item it is looking for.
            let mut depth = 0i64;
            while let Some(ahead) = lines.get(next) {
                let trimmed = ahead.trim();
                if trimmed.starts_with("//") {
                    next += 1;
                    continue;
                }
                if depth == 0 && (trimmed.is_empty() || !trimmed.starts_with("#[")) {
                    break;
                }
                depth += trimmed.matches('[').count() as i64;
                depth -= trimmed.matches(']').count() as i64;
                next += 1;
            }
            let item = lines.get(next).map(|line| line.trim()).unwrap_or("");
            let is_mod = item == "mod"
                || [
                    "mod ",
                    "pub mod ",
                    "pub(crate) mod ",
                    "pub(super) mod ",
                    "pub(in ",
                ]
                .iter()
                .any(|prefix| item.starts_with(prefix));
            if is_mod {
                return Some(offsets[index]);
            }
        }
        None
    }

    /// Assert a scan reached the code its assertion is about.
    ///
    /// The defect this catches: a truncated or relocated scan. Every assertion
    /// over a production half is "no forbidden token is present", which is also
    /// true of an empty string — so each scan names the declarations it must
    /// have seen, and this is the one place the message lives. The needles are
    /// substrings of the declarations as written (`run` is generic, so it reads
    /// `fn run<T, C, S, X>(`).
    pub(crate) fn assert_scan_reaches(rel: &str, cleaned: &str, needles: &[&str]) {
        for needle in needles {
            assert!(
                cleaned.contains(needle),
                "the scanned text of {rel} does not contain {needle:?}: the scan \
                 must stop at the first `#[cfg(test)]` module, not at the first \
                 test-only item"
            );
        }
    }

    /// `pam_sys` constants that are not return codes: they name an item type, so
    /// a line holding one is an argument (`pam_get_authtok(.., PAM_AUTHTOK, ..)`,
    /// which rustfmt may put on its own line), never a verdict.
    const NON_CODE_PAM_CONSTANTS: [&str; 1] = ["pam_sys::PAM_AUTHTOK"];

    /// The `pam_sys::PAM_*` values this crate returns, as `(byte offset, line)`.
    ///
    /// A site is a line of the *stripped* source that either returns one
    /// (`return pam_sys::PAM_X`) or is a bare code in tail position
    /// (`pam_sys::PAM_X` / `pam_sys::PAM_X,` — a match arm or a function tail).
    /// Comparisons and arguments (`res != pam_sys::PAM_SUCCESS`,
    /// `pam_get_authtok(.., pam_sys::PAM_AUTHTOK, ..)`) are not sites: they
    /// consume a code, they do not produce one.
    fn pam_code_sites(cleaned: &str) -> Vec<(usize, String)> {
        let mut hits = Vec::new();
        let mut offset = 0usize;
        for line in cleaned.lines() {
            let trimmed = line.trim();
            if trimmed.contains("pam_sys::PAM_") {
                let bare_token = trimmed.trim_end_matches([',', ';']).trim();
                let bare = !NON_CODE_PAM_CONSTANTS.contains(&bare_token)
                    && bare_token
                        .strip_prefix("pam_sys::PAM_")
                        .is_some_and(|rest| {
                            !rest.is_empty()
                                && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        });
                if trimmed.contains("return ") || bare {
                    hits.push((offset, trimmed.to_owned()));
                }
            }
            offset += line.len() + 1;
        }
        hits
    }

    /// The name of the function whose body contains `at`, as written.
    ///
    /// Used only for the `lib.rs` exemption, which names the six ABI functions
    /// (`guard`'s panic arm and the five constant stubs) — never a line number,
    /// so an edit above them cannot silently move the exemption.
    fn enclosing_fn(cleaned: &str, at: usize) -> Option<String> {
        let before = cleaned.get(..at)?;
        let start = before.rfind("fn ")? + "fn ".len();
        let name: String = before[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// The `lib.rs` functions allowed to answer with a constant: the five
    /// constant ABI stubs and `guard`'s panic arm.
    ///
    /// These are the whole ABI surface: they convert no verdict, never see an
    /// `Outcome`, and are not part of any authentication decision.
    const LIB_PAM_EXEMPTIONS: [&str; 6] = [
        "guard",
        "pam_sm_setcred",
        "pam_sm_acct_mgmt",
        "pam_sm_open_session",
        "pam_sm_close_session",
        "pam_sm_chauthtok",
    ];

    /// No `pam_sys::PAM_*` value is produced outside `outcome.rs`, except the
    /// six `lib.rs` ABI sites named above.
    ///
    /// The defect this catches: a return code minted at the site that observed
    /// the failure instead of through `Outcome::to_pam` — the 24 `pam_logic.rs`
    /// sites this step removes. Such a site can return `PAM_SUCCESS`, can return
    /// a code the verdict does not imply, and adds a path no outcome test
    /// covers. The exemption is by *function name* and the scan asserts it
    /// covered `outcome.rs` (by path), `lib.rs`, the orchestration, the
    /// transaction and every mechanism module, so a moved or emptied scan cannot
    /// pass vacuously.
    #[test]
    fn only_outcome_rs_returns_pam_constants() {
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        for required in [
            "outcome.rs",
            "lib.rs",
            "pam_logic.rs",
            "transaction.rs",
            "mechanism/mod.rs",
            "mechanism/threaded.rs",
            "mechanism/sequential.rs",
            "mechanism/handoff.rs",
        ] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        let mut findings: Vec<String> = Vec::new();
        let mut exempted = 0usize;
        for path in &files {
            let rel = relative_to_src(path);
            // Exempt by path, not by file name: a future `mechanism/outcome.rs`
            // must not inherit this file's exemption.
            if rel == "outcome.rs" {
                continue;
            }
            let cleaned = production_source(path);
            if rel == "transaction.rs" {
                // Guard against a re-truncated scan: this test's claim is that
                // `run` and the reuse cache produce no code of their own, so the
                // scan must actually have seen both (see `production_source`).
                assert_scan_reaches(&rel, &cleaned, &["fn run", "impl ConclusionCache"]);
            }
            for (offset, text) in pam_code_sites(&cleaned) {
                if rel == "lib.rs" {
                    let enclosing = enclosing_fn(&cleaned, offset).unwrap_or_default();
                    if LIB_PAM_EXEMPTIONS.contains(&enclosing.as_str()) {
                        exempted += 1;
                        continue;
                    }
                }
                findings.push(format!("{rel}: {text}"));
            }
        }

        assert!(
            findings.is_empty(),
            "every PAM code must come from `Outcome::to_pam`, found:\n{}",
            findings.join("\n")
        );
        assert_eq!(
            exempted, 6,
            "the six `lib.rs` ABI sites (guard's panic arm and the five constant \
             stubs) are the only exemption; found {exempted}"
        );
    }

    /// The grant constructors, and any hand-built `Outcome::Granted`, as
    /// findings for the file `rel`.
    ///
    /// `outcome.rs` is where both constructors are defined, and the
    /// orchestration (`pam_logic.rs` now, `transaction.rs` once the cache moves
    /// there) is the only code allowed to call them. A mechanism, a rule, a
    /// plan or a test helper calling either — or building `Outcome::Granted`
    /// by hand — is a second way to mint a grant.
    fn grant_findings(rel: &str, cleaned: &str) -> Vec<String> {
        let mut findings = Vec::new();
        for (line, text) in identifier_hits(cleaned, "granted_from_daemon")
            .into_iter()
            .chain(identifier_hits(cleaned, "replayed"))
            .chain(identifier_hits(cleaned, "Granted"))
        {
            let call = text.contains("granted_from_daemon")
                || text.contains("Outcome::replayed")
                || text.contains("fn replayed");
            let allowed = match rel {
                "outcome.rs" => true,
                "pam_logic.rs" | "transaction.rs" => call,
                _ => false,
            };
            if !allowed {
                findings.push(format!("{rel}:{line}: {text}"));
            }
        }
        findings
    }

    /// A `Granted` is minted only by `Outcome::granted_from_daemon` or
    /// `Outcome::replayed`, from the orchestration, and nowhere else.
    ///
    /// The defect this catches: a mechanism (or anything else outside the
    /// orchestration) building `Outcome::Granted(..)` directly, or calling one
    /// of the two constructors, which would be a second grant path beside the
    /// daemon's `Success` and the replay. The retired check — "the token
    /// `Outcome::Granted` appears only in `outcome.rs`" — is not used: it
    /// passes for the very code that defines the constructors, so it cannot
    /// catch a grant minted inside that module or reached from a mechanism.
    #[test]
    fn granted_only_from_daemon() {
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        for required in [
            "outcome.rs",
            "pam_logic.rs",
            "transaction.rs",
            "mechanism/mod.rs",
            "mechanism/threaded.rs",
            "mechanism/sequential.rs",
            "mechanism/handoff.rs",
        ] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        let mut findings: Vec<String> = Vec::new();
        let mut definitions = 0usize;
        for path in &files {
            let rel = relative_to_src(path);
            let cleaned = production_source(path);
            if rel == "transaction.rs" {
                // Guard against a re-truncated scan: the two grant constructors
                // are reached from `run` and refused by the cache, so the scan
                // must have seen both halves of this file.
                assert_scan_reaches(&rel, &cleaned, &["fn run", "impl ConclusionCache"]);
            }
            if rel == "outcome.rs" {
                definitions += cleaned.matches("fn granted_from_daemon").count();
                definitions += cleaned.matches("fn replayed").count();
                continue;
            }
            findings.extend(grant_findings(&rel, &cleaned));
        }

        assert!(
            findings.is_empty(),
            "only the orchestration may reach a grant constructor, and only \
             `outcome.rs` may build a `Granted`:\n{}",
            findings.join("\n")
        );
        assert_eq!(
            definitions, 2,
            "the two grant constructors — granted_from_daemon and replayed — are \
             defined once, in outcome.rs"
        );
    }

    /// The `PAM_*` return-site detector fires on a planted return and on a
    /// planted bare arm, and not on a comparison or on prose.
    ///
    /// Without this, a detector that stopped matching would make
    /// `only_outcome_rs_returns_pam_constants` pass for every tree.
    #[test]
    fn pam_return_scan_detects_a_planted_return() {
        let planted = stripped_source(
            "fn returns_one() -> c_int {\n    return pam_sys::PAM_AUTH_ERR;\n}\n\
             fn tail_position() -> c_int {\n    pam_sys::PAM_SUCCESS\n}\n\
             fn compares_one(res: c_int) -> c_int {\n    if res != pam_sys::PAM_SUCCESS {}\n    0\n}\n",
        );
        let sites = pam_code_sites(&planted);
        assert_eq!(
            sites.len(),
            2,
            "the detector must report the return and the tail expression, and \
             not the comparison: {sites:?}"
        );
        assert_eq!(
            enclosing_fn(&planted, sites[0].0).as_deref(),
            Some("returns_one"),
            "the exemption is by enclosing function name"
        );
        assert_eq!(
            enclosing_fn(&planted, sites[1].0).as_deref(),
            Some("tail_position")
        );

        // Prose is not a site, which is what makes the whole-crate assertion
        // meaningful: this file's docs name the forbidden codes.
        let prose = stripped_source(
            "// return pam_sys::PAM_AUTH_ERR;\nlet s = \"return pam_sys::PAM_SUCCESS;\";\n",
        );
        assert!(pam_code_sites(&prose).is_empty());

        // An item type is not a verdict, even alone on its line: the whole-crate
        // scan would otherwise report `pam_get_authtok`'s argument.
        let item = stripped_source(
            "pam_get_authtok(\n    pamh,\n    pam_sys::PAM_AUTHTOK,\n    &mut tok,\n);\n",
        );
        assert!(
            pam_code_sites(&item).is_empty(),
            "an item-type constant is not a return code"
        );
    }

    /// The grant detector reports a hand-built `Granted` and a constructor call
    /// from a mechanism, and accepts `outcome.rs` and the orchestration.
    ///
    /// Without this, `granted_only_from_daemon` would pass for a tree in which
    /// the detector had stopped matching.
    #[test]
    fn granted_scan_detects_a_planted_construction() {
        let planted = stripped_source(
            "fn drive() -> Outcome {\n    Outcome::Granted(GrantVia::PhoneTap)\n}\n\
             fn other() -> Outcome {\n    Outcome::granted_from_daemon()\n}\n",
        );

        let mechanism = grant_findings("mechanism/threaded.rs", &planted);
        assert_eq!(
            mechanism.len(),
            2,
            "a mechanism must not build a grant or call a grant constructor: {mechanism:?}"
        );

        let orchestration = grant_findings("pam_logic.rs", &planted);
        assert_eq!(
            orchestration.len(),
            1,
            "the orchestration may call the constructor but may not build a \
             `Granted` by hand: {orchestration:?}"
        );
        assert!(orchestration[0].contains("Outcome::Granted"));

        assert!(
            grant_findings("outcome.rs", &planted).is_empty(),
            "outcome.rs defines both constructors, so it is exempt by path"
        );
    }

    /// The mapping above only covers daemon responses.  Guard *every* file of
    /// this crate — not just `pam_logic.rs` and `lib.rs` — against
    /// reintroducing `PAM_IGNORE`, by identifier and by its numeric value.
    ///
    /// The numeric half is the one that matters for regressions: the vectors
    /// that remain are a `pam_sys::PAM_IGNORE` re-export reaching a `return`, or
    /// a bare literal equal to PAM_IGNORE's value, in any `client-pam/src/**`
    /// — either is a single edit away from the bypass this guards, and a
    /// name-only scan would miss the numeric form.
    ///
    /// The walk is `source_files`, i.e. recursive: `src/mechanism/` is a
    /// directory with no `rs` extension, so a single-level `read_dir` would
    /// silently stop covering the modules that read daemon responses and the one
    /// that decides `PreCollected` — and the scan would stay green while the
    /// coverage it claims evaporated.
    #[test]
    fn test_module_source_contains_no_pam_ignore_return() {
        let files = source_files();
        let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
        // An empty or relocated scan must not pass silently: these files carry
        // the mechanism exits, the verdict mapping and the orchestration.
        for required in [
            "pam_logic.rs",
            "outcome.rs",
            "mechanism/sequential.rs",
            "mechanism/threaded.rs",
            "mechanism/handoff.rs",
        ] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }

        // Spelled arithmetically so this test's own source carries no literal
        // for its own scan to find.
        let ignore_code: u128 = 5 * 5;
        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let name = relative_to_src(path);
            let cleaned = stripped_source(&source);
            for (line, text) in pam_ignore_identifiers(&cleaned) {
                findings.push(format!("{name}:{line}: PAM_IGNORE identifier in: {text}"));
            }
            for (line, text) in numeric_literals_equal_to(&cleaned, ignore_code) {
                findings.push(format!(
                    "{name}:{line}: PAM_IGNORE value {ignore_code} used in: {text}"
                ));
            }
        }
        assert!(
            findings.is_empty(),
            "the module must never return PAM_IGNORE:\n{}",
            findings.join("\n")
        );
    }

    /// The whole-crate scan above returns empty for two independent reasons —
    /// every `PAM_IGNORE` in this crate is prose inside a comment, and no bare
    /// literal holds its value — so it would stay green even if the stripper or
    /// either detector were broken.  Prove both detectors fire on a synthetic
    /// snippet, and that a comment or a string naming the code does not count.
    #[test]
    fn test_pam_ignore_scan_detects_a_real_return() {
        // Spelled arithmetically so this test's own source carries no literal
        // for its own scan to find (as in the whole-crate scan above).
        let ignore_code: u128 = 5 * 5;

        let source = format!(
            "// PAM_IGNORE in a comment is prose, not a return.\n\
             /* PAM_IGNORE and {ignore_code} in a block comment, too. */\n\
             let prose = \"return pam_sys::PAM_IGNORE; return {ignore_code};\";\n\
             let code = {{ let x = pam_sys::PAM_IGNORE; x }};\n\
             return pam_sys::PAM_IGNORE;\n\
             return {ignore_code}u32;\n"
        );
        let cleaned = stripped_source(&source);

        assert_eq!(
            pam_ignore_identifiers(&cleaned),
            vec![
                (
                    4,
                    "let code = { let x = pam_sys::PAM_IGNORE; x };".to_owned()
                ),
                (5, "return pam_sys::PAM_IGNORE;".to_owned()),
            ],
            "the identifier scan must report the bare identifier and the real \
             return, and neither the comment nor the string"
        );

        assert_eq!(
            numeric_literals_equal_to(&cleaned, ignore_code),
            vec![(6, format!("{ignore_code}u32"))],
            "the numeric scan must report the bare value and neither the \
             comment nor the string"
        );

        // The negative half: prose alone must never be reported, which is what
        // makes the whole-crate assertion meaningful today.
        assert_eq!(
            pam_ignore_identifiers(&stripped_source("// PAM_IGNORE\n")),
            Vec::new(),
            "a comment naming PAM_IGNORE is not a return"
        );
    }
}

/// The verdict-reuse record: the 500 ms window, its `(username, service)` key,
/// and the two gates that decide what may be recorded.
///
/// Every case drives the real `transaction::record` / `transaction::replay_for`
/// pair, so the assertions are about the record `authenticate` writes and reads
/// and not about a parallel copy of its logic; each case holds
/// `transaction::CACHE_SLOT_LOCK` for its whole body, because the record is one
/// slot for the process.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod verdict_reuse_tests {
    use super::*;
    use crate::outcome::{DenyVia, UnavailableReason};
    use crate::transaction::tests::{no_daemon, NullIpc};
    use crate::transaction::{record, replay_for, Armed, Concluded, StartError, Via};

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
        crate::transaction::CACHE_SLOT_LOCK
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
            let code = outcome.clone().to_pam();
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
            let code = outcome.clone().to_pam();
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
            || Err(no_daemon()),
            |_: &mut NullIpc| Ok(()),
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
            || Ok(NullIpc),
            |_: &mut NullIpc| Ok(()),
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

    /// **Smoke test only.**  It compares source byte offsets, so it would still
    /// pass if the lookup sat behind a branch that never executes.
    ///
    /// The authoritative coverage is the `duplicate`, `duplicate-unavailable`,
    /// `duplicate-cross-user` and `duplicate-cross-service` shapes in
    /// `scripts/ci/test-pam-conv-thread.sh`, which count the connections the
    /// fake daemon accepted: this ordering is what makes those counts
    /// meaningful.
    #[test]
    fn cache_lookup_precedes_daemon_contact() {
        let source = include_str!("transaction.rs");
        // Only the production half of the file: the test module contains the
        // same identifiers, which would otherwise satisfy the searches no matter
        // what the production code does. The split is on the test *module*
        // declaration — `transaction.rs` also carries individual `#[cfg(test)]`
        // items above `run` (`HostIo::for_test`, the two test accessors), which a
        // bare `split_once("#[cfg(test)]")` would stop at.
        let production = source
            .split_once("\n#[cfg(test)]\n#[allow(")
            .map(|(before, _)| before)
            .unwrap_or(source);

        // The call, not the `if let` that contains it: rustfmt is free to break
        // the pattern across lines.
        let lookup = production
            .find("replay_for(username, service_name.original(), Instant::now())")
            .unwrap_or_else(|| panic!("invariant broken: the reuse lookup is gone from `run`"));

        let daemon_contact = production
            .find("let request = SendParams {")
            .unwrap_or_else(|| {
                panic!("invariant broken: production call to the IPC connect not found")
            });

        assert!(
            lookup < daemon_contact,
            "invariant broken: the verdict-reuse lookup (byte {}) must run before the \
             module contacts the daemon (byte {}), otherwise a duplicate transaction \
             still sends a request and rings the phone",
            lookup,
            daemon_contact
        );
    }

    /// The reuse suite is the fifteen named cases, and no test in the crate is
    /// ignored (the fork experiment is fixed and runs normally).
    ///
    /// The defect this catches: a rewritten suite that silently drops a case —
    /// presence is asserted by name, so a deleted test fails here rather than
    /// passing as "all green with fewer tests". The ignore rule is the other
    /// half: if `#[ignore]` could be used to silence a broken case, a defect
    /// could ship as "green", so the crate must contain none.
    #[test]
    fn reuse_suite_is_intact() {
        let files = super::tests::source_files();
        let names: Vec<String> = files
            .iter()
            .map(|path| super::tests::relative_to_src(path))
            .collect();
        for required in ["pam_logic.rs", "transaction.rs"] {
            assert!(
                names.iter().any(|name| name == required),
                "the scan did not cover {required}: {names:?}"
            );
        }
        // Comment- and string-stripped, so a doc comment that quotes a name or
        // an attribute is not a finding, and this test's own literals cannot
        // satisfy its searches.
        let sources: String = files
            .iter()
            .map(|path| {
                let source = std::fs::read_to_string(path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                super::tests::stripped_source(&source)
            })
            .collect();

        // The fifteen: the fourteen cases that survived the retargeting, plus
        // `armed_requires_both_connect_and_send`, which replaces
        // `the_verdict_record_is_armed_only_inside_the_helper` — that one is
        // deleted below because the by-value `Concluded` makes its source scan
        // redundant, and a replacement asserting "the type is constructed here"
        // would be strictly weaker than the type.
        const REUSE_CASES: [&str; 15] = [
            "a_success_inside_the_window_is_reused",
            "a_success_after_the_window_is_not_reused",
            "an_unavailability_inside_the_window_is_reused",
            "a_denial_inside_the_window_is_reused",
            "an_unavailability_after_the_window_is_not_reused",
            "another_users_conclusion_is_never_reused",
            "another_services_conclusion_is_never_reused",
            "recording_a_failure_replaces_the_cached_success",
            "a_failed_connect_records_nothing_and_the_retry_dials_again",
            "a_from_cache_verdict_is_not_recorded",
            "an_unresolved_service_is_not_recorded",
            "a_poisoned_lock_reads_as_a_cache_miss",
            "a_future_timestamp_does_not_panic",
            "cache_lookup_precedes_daemon_contact",
            "armed_requires_both_connect_and_send",
        ];
        for name in REUSE_CASES {
            assert!(
                sources.contains(&format!("fn {name}(")),
                "the reuse case `{name}` is missing: the suite may not be \
                 rewritten by dropping a case"
            );
        }
        assert!(
            !sources.contains(concat!(
                "fn the_verdict_record_is_armed_only_inside_the",
                "_helper("
            )),
            "the arming source scan is deleted, not renamed: the by-value \
             `Concluded` replaces it, and a weaker copy must not return"
        );

        // The new cases this step adds, so a dropped one fails like any other.
        for name in [
            "reuse_key_is_case_sensitive",
            "replay_notice_is_silent",
            "cache_owner_is_local",
            "conclusion_cache_survives_fork",
        ] {
            assert!(
                sources.contains(&format!("fn {name}(")),
                "the new reuse case `{name}` is missing"
            );
        }

        // No ignored test in the crate: the fork experiment was the last one,
        // and `#[ignore]` may not be reused to silence a broken case.
        let ignored = sources.matches("#[ignore").count();
        assert_eq!(
            ignored, 0,
            "no test may be ignored (the fork experiment now runs); found {ignored}"
        );
    }

    /// No other module may name the reuse record's lock or its static.
    ///
    /// The defect this catches: a second file reaching `LAST_CONCLUSION` (or
    /// any `.lock()` on it), or this module handing the guard out through a
    /// non-test `pub(crate)` getter — either defeats the ownership that keeps a
    /// fork fix (an `atfork` reinit, an atomic cell, or dropping the cache)
    /// inside one file. The scan is over the comment- and string-stripped
    /// production half of every `src/**/*.rs`, so `#[cfg(test)]` code is exempt
    /// by construction and a doc comment that quotes the token is not a
    /// finding. The positive control runs the detector over an in-memory
    /// string, never a planted file under `src/`, which would race the parallel
    /// recursive walk.
    #[test]
    fn cache_owner_is_local() {
        let files = super::tests::source_files();
        let names: Vec<String> = files
            .iter()
            .map(|path| super::tests::relative_to_src(path))
            .collect();
        assert!(
            names.iter().any(|name| name == "transaction.rs"),
            "the scan did not cover the cache's own module: {names:?}"
        );

        let mut findings: Vec<String> = Vec::new();
        for path in &files {
            let rel = super::tests::relative_to_src(path);
            let production = super::tests::production_source(path);
            if rel == "transaction.rs" {
                // Guard against a re-truncated scan: the whole claim is about
                // what the owner's module may do, and an empty production half
                // satisfies "no other module names the lock" vacuously.
                super::tests::assert_scan_reaches(
                    &rel,
                    &production,
                    &["fn run", "impl ConclusionCache", "LAST_CONCLUSION"],
                );
                // The owner may lock the static; it may not hand the lock, the
                // guard or the record out.
                for (line, text) in production.lines().enumerate() {
                    let leaks_guard = text.contains("MutexGuard");
                    let exposes_record =
                        text.contains("pub(crate) fn") && text.contains("LastConclusion");
                    if leaks_guard || exposes_record {
                        findings.push(format!("{rel}:{}: {}", line + 1, text.trim()));
                    }
                }
                continue;
            }
            for hit in lock_references(&production) {
                findings.push(format!("{rel}: {hit}"));
            }
        }
        assert!(
            findings.is_empty(),
            "only `transaction.rs` may name the reuse record's lock:\n{}",
            findings.join("\n")
        );

        // Positive control: the detector fires on a planted reach.
        let planted = super::tests::stripped_source(
            "fn steal() -> Option<Outcome> {\n    let guard = LAST_CONCLUSION.lock().ok()?;\n    None\n}\n",
        );
        assert!(
            !lock_references(&planted).is_empty(),
            "the detector must report a planted `LAST_CONCLUSION.lock()`"
        );
        let getter = lock_references(&super::tests::stripped_source(
            "pub(crate) fn guard() -> MutexGuard<'static, ()> { CACHE_SLOT_LOCK.lock().unwrap() }\n",
        ));
        assert!(
            !getter.is_empty(),
            "the detector must report a getter that hands the guard out"
        );
        // Negative control: prose and strings are not reaches.
        let prose = super::tests::stripped_source(
            "// LAST_CONCLUSION.lock() is what this module forbids elsewhere\n\
             let doc = \"LAST_CONCLUSION\";\n",
        );
        assert!(
            lock_references(&prose).is_empty(),
            "comments and string literals are not lock references"
        );
    }

    /// Every line of `source` that reaches the cache's lock or its static.
    fn lock_references(source: &str) -> Vec<String> {
        const TOKENS: [&str; 5] = [
            ".lock()",
            ".try_lock()",
            ".try_lock_for",
            "LAST_CONCLUSION",
            "MutexGuard",
        ];
        source
            .lines()
            .enumerate()
            .filter(|(_, line)| TOKENS.iter().any(|token| line.contains(token)))
            .map(|(line, text)| format!("line {}: {}", line + 1, text.trim()))
            .collect()
    }
}
