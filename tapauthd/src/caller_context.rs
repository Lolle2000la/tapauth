//! Caller context for a PAM authentication request.
//!
//! The context shown on the Server (phone) is derived from two sources: the
//! kernel-visible identity of the calling process and the self-reported fields of
//! `PamAuthenticateRequest`. The kernel-visible identity wins wherever it can
//! answer, because it is not something the request can set; the self-report is
//! only a fallback.
//!
//! None of this is an authorization boundary, and it must not be read as one.
//! `argv[0]` is whatever the caller passed to `execve`, and `comm` is settable
//! through `prctl(PR_SET_NAME)`, so a local caller can still name itself
//! `polkit-agent-helper-1`. The property implemented here is narrower: the IPC
//! request's self-reported fields are never consulted for the PolKit display, so
//! a caller cannot pick that display from the request alone. Who may authenticate
//! whom is decided by `allowed_users` in the daemon, not by what this module
//! resolves; the prompt is a human-readable hint.
//!
//! The kernel is asked in three steps, in this order: `/proc/<pid>/exe`, the
//! `argv[0]` of `/proc/<pid>/cmdline`, and `/proc/<pid>/comm`. Their
//! reachability differs, and that is why all three exist:
//! `read_link("/proc/<pid>/exe")` goes through `ptrace_may_access`, so it fails
//! `EACCES` for every other-UID caller of the shipped unit (which runs as
//! `User=tapauthd` without `CAP_SYS_PTRACE`), while `cmdline` (0444) and `comm`
//! (0644) are world-readable. In production the executable path is therefore
//! normally unavailable and the command line and `comm` are not — so the `EACCES`
//! on `exe` is logged at `debug` as the expected path, while a failure of the
//! world-readable entries is logged at `warn` as the anomaly it is.
//!
//! Every field leaves this module through
//! [`sanitize_context_string`], so controls and Bidi overrides written by a
//! caller can never reshape the prompt it is asking the user to approve.

use shared::ipc::pb as ipc;
use shared::protocol::messages::{
    sanitize_context_string, COMMAND_PREVIEW_MAX_BYTES, PAM_SERVICE_MAX_BYTES,
    PROCESS_NAME_MAX_BYTES,
};
use std::io;
use std::path::{Path, PathBuf};

/// procfs root used in production.
const PROC_ROOT: &str = "/proc";

/// The PAM service PolKit's authentication agent helper runs under.
const POLKIT_HELPER: &str = "polkit-agent-helper-1";
/// The helper's `comm`, i.e. [`POLKIT_HELPER`] as the kernel truncates it:
/// `TASK_COMM_LEN` is 16 bytes including the NUL terminator, and that size has
/// been part of the kernel ABI since 2.6, so this truncation is stable.
const POLKIT_HELPER_COMM: &str = "polkit-agent-he";
/// Service name displayed (and shown on the phone) for a PolKit prompt.
const POLKIT_SERVICE: &str = "polkit-1";
/// Suffix the kernel appends to `/proc/<pid>/exe` once the image is unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// The kernel's answers about one process, behind a seam.
///
/// The failure kinds differ with the caller's UID — the production `EACCES` on
/// another user's `exe` cannot be produced from a single-UID test — so the
/// resolution rules are driven from a fake in the tests instead.
trait ProcFs {
    /// `read_link("/proc/<pid>/exe")`.
    fn exe_link(&self, pid: i32) -> io::Result<PathBuf>;
    /// The raw NUL-separated `/proc/<pid>/cmdline`.
    fn cmdline(&self, pid: i32) -> io::Result<Vec<u8>>;
    /// `/proc/<pid>/comm` with the trailing newline removed.
    fn comm(&self, pid: i32) -> io::Result<String>;
    /// Whether procfs still has the pid at all.
    fn pid_exists(&self, pid: i32) -> bool;
    /// How to name one entry in a log line.
    fn describe(&self, pid: i32, entry: &str) -> String {
        format!("/proc/{pid}/{entry}")
    }
}

/// The real procfs, optionally rooted somewhere else for tests.
struct RealProcFs {
    root: PathBuf,
}

impl RealProcFs {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn path(&self, pid: i32, entry: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(entry)
    }
}

impl ProcFs for RealProcFs {
    fn exe_link(&self, pid: i32) -> io::Result<PathBuf> {
        std::fs::read_link(self.path(pid, "exe"))
    }

    fn cmdline(&self, pid: i32) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(pid, "cmdline"))
    }

    fn comm(&self, pid: i32) -> io::Result<String> {
        // `comm` is arbitrary bytes: a process may rename itself to anything that
        // fits, so this is lossy rather than a `read_to_string` failure.
        let bytes = std::fs::read(self.path(pid, "comm"))?;
        Ok(String::from_utf8_lossy(&bytes)
            .trim_end_matches('\n')
            .to_string())
    }

    fn pid_exists(&self, pid: i32) -> bool {
        self.path(pid, "stat").exists()
    }

    fn describe(&self, pid: i32, entry: &str) -> String {
        self.path(pid, entry).display().to_string()
    }
}

/// What the kernel could tell us about one process.
#[derive(Debug, Default)]
struct KernelIdentity {
    /// Basename of the executable image, from `/proc/<pid>/exe`.
    exe: Option<String>,
    /// Basename of `cmdline`'s `argv[0]`.
    argv0: Option<String>,
    /// `/proc/<pid>/comm`, the kernel's truncated task name.
    comm: Option<String>,
    /// `cmdline` joined by single spaces; empty when unreadable.
    command_preview: String,
    /// Read failures that the shipped unit does not explain, with the entry they
    /// came from.
    unexpected: Vec<(&'static str, io::Error)>,
    /// Whether procfs knew the pid *when the context was first resolved*.
    ///
    /// Sampled once, before the reads, so it is only a hint: a process can exit
    /// between this sample and any of them, which turns each read into `ENOENT`.
    /// [`Self::warn_if_unexpected`] therefore samples liveness again at
    /// classification time — only a pid that is still there *then* can have failed
    /// unexpectedly.
    alive: bool,
}

impl KernelIdentity {
    fn probe(procfs: &dyn ProcFs, pid: i32) -> Self {
        if pid <= 0 {
            return Self::default();
        }
        let mut identity = Self {
            alive: procfs.pid_exists(pid),
            ..Self::default()
        };

        match procfs.exe_link(pid) {
            Ok(target) => identity.exe = exe_basename(&target),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Not a fault: `exe` is guarded by `ptrace_may_access` and the
                // shipped unit has no `CAP_SYS_PTRACE`, so every other-UID caller
                // lands here. The two world-readable entries below still answer.
                tracing::debug!(
                    "{} for pid {} is unreadable ({}): another UID's exe needs \
                     CAP_SYS_PTRACE, which the shipped unit does not have. Falling back to the \
                     command line, then comm, for the process name.",
                    procfs.describe(pid, "exe"),
                    pid,
                    e
                );
            }
            Err(e) => identity.unexpected.push(("exe", e)),
        }

        match procfs.cmdline(pid) {
            Ok(bytes) => {
                let args = split_cmdline(&bytes);
                identity.argv0 = args.first().and_then(|arg| argv_basename(arg));
                identity.command_preview = args.join(" ");
            }
            Err(e) => identity.unexpected.push(("cmdline", e)),
        }

        match procfs.comm(pid) {
            Ok(comm) if !comm.is_empty() => identity.comm = Some(comm),
            Ok(_) => {}
            Err(e) => identity.unexpected.push(("comm", e)),
        }

        identity
    }

    /// The process name, from the first kernel source that answered.
    fn display_name(&self) -> Option<&str> {
        self.exe
            .as_deref()
            .or(self.argv0.as_deref())
            .or(self.comm.as_deref())
    }

    /// Whether the *kernel-visible* name says this is PolKit's authentication
    /// agent helper.
    ///
    /// What this guarantees is narrow, and it is what the code below does: the
    /// IPC request's self-reported `process_name` and `pam_service` are never
    /// consulted, here or in the fallback that used to exist, so a member of
    /// `tapauthd-clients` cannot pick the PolKit display — and the dropped argv
    /// that comes with it — from the request alone. It is **not** an
    /// impersonation barrier: `argv[0]` is the caller's own `execve` argument and
    /// `comm` is settable through `prctl(PR_SET_NAME)`, so a local caller can
    /// still present one of those names. This is a display heuristic, not an
    /// authorization boundary; authorization is decided by `allowed_users` in
    /// the daemon.
    ///
    /// `comm` is compared against the kernel's 15-byte truncation, see
    /// [`POLKIT_HELPER_COMM`].
    fn is_polkit_helper(&self) -> bool {
        self.exe.as_deref() == Some(POLKIT_HELPER)
            || self.argv0.as_deref() == Some(POLKIT_HELPER)
            || self.comm.as_deref() == Some(POLKIT_HELPER_COMM)
    }

    /// One `warn` for a pid that is still there and whose entries could not be
    /// read for a reason the shipped unit does not explain.
    ///
    /// `EACCES` on `exe` never reaches here (see [`Self::probe`]), and neither
    /// does a departed pid. Liveness is sampled **again** here, not reused from
    /// [`Self::probe`]: a caller can exit between that sample and the reads, which
    /// turns every read into the `ENOENT` of a process that is gone — the normal
    /// race, never the anomaly this warning exists for.
    fn warn_if_unexpected(&self, procfs: &dyn ProcFs, pid: i32) {
        if self.unexpected.is_empty() {
            return;
        }
        // The second sample is the one that decides: `self.alive` only says the
        // pid was there before the reads, and an exit in between produces exactly
        // the same `ENOENT`s as a genuinely unreadable entry.
        if !self.alive || !procfs.pid_exists(pid) {
            tracing::debug!(
                "pid {} left procfs before its caller context was resolved; the phone will show \
                 the caller's self-reported name",
                pid
            );
            return;
        }

        let failures = self
            .unexpected
            .iter()
            .map(|(entry, e)| format!("{}: {}", procfs.describe(pid, entry), e))
            .collect::<Vec<_>>()
            .join("; ");
        let mut unavailable: Vec<&str> = Vec::new();
        if self.exe.is_none() {
            unavailable.push("the executable path");
        }
        if self.command_preview.is_empty() {
            unavailable.push("the command line");
        }
        if self.comm.is_none() {
            unavailable.push("comm");
        }
        // The request has no command field: `command_preview` is built from
        // `cmdline` alone, so an unreadable `cmdline` leaves no command to show
        // rather than a command the caller supplied.
        tracing::warn!(
            "Unexpected failure reading the caller's proc entries for pid {} ({}). Unavailable: \
             {}. The process name is taken from /proc/<pid>/exe, then cmdline argv[0], then comm, \
             and only from the caller's self-reported name when none of them can be read; the \
             request carries no command field, so an unreadable cmdline leaves no command \
             preview. Reading another UID's exe needs CAP_SYS_PTRACE, which the shipped unit \
             deliberately does not have, and that case is logged at debug.",
            pid,
            failures,
            unavailable.join(", ")
        );
    }
}

/// Basename of an `exe` link target, or `None` when it has no usable file name.
///
/// The link target carries `" (deleted)"` once the image file is gone (a
/// replaced or removed binary), which is not part of the process name.
fn exe_basename(target: &Path) -> Option<String> {
    let target = target.to_str()?;
    let stripped = target.strip_suffix(DELETED_SUFFIX).unwrap_or(target);
    non_empty_basename(stripped)
}

/// Basename of a single `argv[0]`, which may be a plain name or a path.
fn argv_basename(arg: &str) -> Option<String> {
    non_empty_basename(arg)
}

fn non_empty_basename(path: &str) -> Option<String> {
    let name = Path::new(path).file_name()?.to_str()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// `cmdline` split into its arguments.
///
/// The file is NUL-separated with a trailing NUL; empty (zero-length) arguments
/// are dropped rather than turned into double spaces.
fn split_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// Sanitized, display-only context describing the caller as the phone shows it.
///
/// A hint for the human approving the prompt, never an authorization input: the
/// daemon decides who may authenticate whom from `allowed_users`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    /// PAM service of the request (`sudo`, `su`, `polkit-1`, …).
    pub pam_service: String,
    /// Name of the calling process image: the kernel-visible one when it answers,
    /// the request's claim only when nothing kernel-visible did.
    pub process_name: String,
    /// The caller's argv, joined by single spaces, from the kernel `cmdline` only.
    pub command_preview: String,
}

impl CallerContext {
    /// Resolve against the real procfs.
    pub fn resolve(caller_pid: i32, req: &ipc::PamAuthenticateRequest) -> Self {
        Self::resolve_with_root(caller_pid, req, Path::new(PROC_ROOT))
    }

    /// Resolve against an injected procfs root, so the resolution rules are
    /// testable without a live process tree.
    pub fn resolve_with_root(
        caller_pid: i32,
        req: &ipc::PamAuthenticateRequest,
        proc_root: &Path,
    ) -> Self {
        Self::resolve_with_procfs(&RealProcFs::new(proc_root), caller_pid, req)
    }

    /// Resolve against an injected [`ProcFs`], which is how the tests drive the
    /// cross-UID failure kinds a single-UID process cannot produce.
    fn resolve_with_procfs(
        procfs: &dyn ProcFs,
        caller_pid: i32,
        req: &ipc::PamAuthenticateRequest,
    ) -> Self {
        let identity = KernelIdentity::probe(procfs, caller_pid);
        identity.warn_if_unexpected(procfs, caller_pid);

        // PolKit's helper runs under its own name, and the phone should display
        // the service it authenticates (`polkit-1`) rather than the helper's own
        // argv. Only the kernel-visible identity decides (see
        // `KernelIdentity::is_polkit_helper`): the request's self-reported
        // `pam_service` and `process_name` are never consulted, so a caller cannot
        // select this display from the request. A local caller can still name its
        // own binary or `comm` after the helper — this is a display heuristic, not
        // an authorization boundary.
        let is_polkit_helper = identity.is_polkit_helper();

        let pam_service = if is_polkit_helper {
            POLKIT_SERVICE
        } else {
            req.pam_service.as_str()
        };

        // A self-reported process name is untrusted: prefer what the kernel says
        // the caller's image is, falling back only when no proc entry can answer.
        let process_name = identity
            .display_name()
            .unwrap_or(req.process_name.as_str())
            .to_string();

        // The helper's argv only repeats the service name it is already
        // displayed under (`polkit-agent-helper-1 polkit-1 …`), so it is omitted.
        let command_preview = if is_polkit_helper {
            String::new()
        } else {
            identity.command_preview
        };

        Self {
            pam_service: sanitize_context_string(pam_service, PAM_SERVICE_MAX_BYTES),
            process_name: sanitize_context_string(&process_name, PROCESS_NAME_MAX_BYTES),
            command_preview: sanitize_context_string(&command_preview, COMMAND_PREVIEW_MAX_BYTES),
        }
    }
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
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT_ID: AtomicU32 = AtomicU32::new(0);

    /// A scripted procfs.
    ///
    /// The interesting production shape cannot be reproduced from real files:
    /// `read_link("/proc/<pid>/exe")` returns `EACCES` only for another UID's
    /// process, and a single-UID test run can read everything it creates. So the
    /// failure kinds are injected instead of the files.
    struct FakeProc {
        alive: bool,
        /// Successive answers to `pid_exists`, for the race between sampling
        /// liveness and reading the entries; the last answer repeats.
        alive_samples: Vec<bool>,
        alive_samples_taken: std::sync::atomic::AtomicUsize,
        exe: Result<&'static str, io::ErrorKind>,
        cmdline: Result<Vec<&'static str>, io::ErrorKind>,
        comm: Result<&'static str, io::ErrorKind>,
    }

    impl Default for FakeProc {
        /// The production shape: the pid is alive, `exe` is `EACCES`, and the two
        /// world-readable entries answer.
        fn default() -> Self {
            Self {
                alive: true,
                alive_samples: Vec::new(),
                alive_samples_taken: std::sync::atomic::AtomicUsize::new(0),
                exe: Err(io::ErrorKind::PermissionDenied),
                cmdline: Ok(Vec::new()),
                comm: Ok("sudo"),
            }
        }
    }

    impl FakeProc {
        fn with_exe(mut self, target: &'static str) -> Self {
            self.exe = Ok(target);
            self
        }

        fn with_exe_error(mut self, kind: io::ErrorKind) -> Self {
            self.exe = Err(kind);
            self
        }

        fn with_cmdline(mut self, argv: &[&'static str]) -> Self {
            self.cmdline = Ok(argv.to_vec());
            self
        }

        fn with_cmdline_error(mut self, kind: io::ErrorKind) -> Self {
            self.cmdline = Err(kind);
            self
        }

        fn with_comm(mut self, comm: &'static str) -> Self {
            self.comm = Ok(comm);
            self
        }

        fn with_comm_error(mut self, kind: io::ErrorKind) -> Self {
            self.comm = Err(kind);
            self
        }

        fn gone(mut self) -> Self {
            self.alive = false;
            self.exe = Err(io::ErrorKind::NotFound);
            self.cmdline = Err(io::ErrorKind::NotFound);
            self.comm = Err(io::ErrorKind::NotFound);
            self
        }

        /// The pid is still there when the context is sampled, and gone by the
        /// time the failures are classified.
        fn alive_then_gone(mut self) -> Self {
            self.alive = true;
            self.alive_samples = vec![true, false];
            self
        }
    }

    impl ProcFs for FakeProc {
        fn exe_link(&self, _pid: i32) -> io::Result<PathBuf> {
            self.exe.map(PathBuf::from).map_err(io::Error::from)
        }

        fn cmdline(&self, _pid: i32) -> io::Result<Vec<u8>> {
            self.cmdline
                .clone()
                .map(|argv| {
                    let mut bytes = Vec::new();
                    for arg in argv {
                        bytes.extend_from_slice(arg.as_bytes());
                        bytes.push(0);
                    }
                    bytes
                })
                .map_err(io::Error::from)
        }

        fn comm(&self, _pid: i32) -> io::Result<String> {
            self.comm.map(str::to_string).map_err(io::Error::from)
        }

        fn pid_exists(&self, _pid: i32) -> bool {
            if self.alive_samples.is_empty() {
                return self.alive;
            }
            let taken = self
                .alive_samples_taken
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.alive_samples
                .get(taken)
                .or_else(|| self.alive_samples.last())
                .copied()
                .unwrap_or(self.alive)
        }
    }

    /// Resolve against a fake and return the context together with every event
    /// emitted while it was resolved.
    fn resolve_captured(
        procfs: &FakeProc,
        pid: i32,
        req: &ipc::PamAuthenticateRequest,
    ) -> (CallerContext, Vec<(tracing::Level, String)>) {
        let log = CapturedLog::default();
        let ctx = {
            let _guard = tracing::subscriber::set_default(log.clone());
            CallerContext::resolve_with_procfs(procfs, pid, req)
        };
        (ctx, log.events())
    }

    /// A scratch procfs root, removed when the test ends.
    struct TempProc {
        root: PathBuf,
    }

    impl TempProc {
        fn new() -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "tapauthd-caller-context-{}-{}",
                std::process::id(),
                id
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn process_dir(&self, pid: i32) -> PathBuf {
            let dir = self.root.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// Mark the pid as still known to procfs (every live process has a
        /// `stat`), without making any other entry readable.
        fn with_stat(&self, pid: i32) {
            std::fs::write(self.process_dir(pid).join("stat"), b"0 (x) S").unwrap();
        }

        fn with_exe(&self, pid: i32, target: &str) {
            symlink(target, self.process_dir(pid).join("exe")).unwrap();
        }

        fn with_cmdline(&self, pid: i32, argv: &[&str]) {
            let mut bytes = Vec::new();
            for arg in argv {
                bytes.extend_from_slice(arg.as_bytes());
                bytes.push(0);
            }
            std::fs::write(self.process_dir(pid).join("cmdline"), bytes).unwrap();
        }
    }

    impl Drop for TempProc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn request(pam_service: &str, process_name: &str) -> ipc::PamAuthenticateRequest {
        ipc::PamAuthenticateRequest {
            username: "luca".to_string(),
            tty_present: true,
            timeout_seconds: 30,
            request_id: "test".to_string(),
            pam_service: pam_service.to_string(),
            process_name: process_name.to_string(),
        }
    }

    /// Records every event the daemon emits while the guard is installed, so the
    /// one `warn` this module produces on the degraded `/proc` path can be
    /// asserted on level, count and wording instead of being taken on trust.
    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

    impl CapturedLog {
        fn events(&self) -> Vec<(tracing::Level, String)> {
            self.0.lock().unwrap().clone()
        }
    }

    /// The `message` field is the only one these assertions care about.
    struct MessageVisitor<'a>(&'a mut String);

    impl tracing::field::Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push_str(&format!("{value:?}"));
            }
        }
    }

    impl tracing::Subscriber for CapturedLog {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            self.0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), message));
        }
    }

    /// Run `resolve` under a capturing subscriber and return the lines it emitted
    /// at `WARN` or above — what an operator sees with the shipped journal filter.
    fn warnings_during(resolve: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        at_least_warn(&captured(resolve))
    }

    /// Every event emitted while `run` executes.
    fn captured(run: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        let log = CapturedLog::default();
        {
            let _guard = tracing::subscriber::set_default(log.clone());
            run();
        }
        log.events()
    }

    fn at_least_warn(events: &[(tracing::Level, String)]) -> Vec<(tracing::Level, String)> {
        events
            .iter()
            .filter(|(level, _)| matches!(*level, tracing::Level::WARN | tracing::Level::ERROR))
            .cloned()
            .collect()
    }

    fn debug_lines(events: &[(tracing::Level, String)]) -> Vec<String> {
        events
            .iter()
            .filter(|(level, _)| *level == tracing::Level::DEBUG)
            .map(|(_, message)| message.clone())
            .collect()
    }

    /// The production shape: the daemon runs as `tapauthd` without
    /// `CAP_SYS_PTRACE`, so `/proc/<pid>/exe` is `EACCES` for every PAM caller and
    /// only the world-readable `cmdline`/`comm` can answer.
    ///
    /// The defect this catches: on that path the process name came from the
    /// caller's own `process_name` while the command line was readable all along,
    /// and the `EACCES` was reported as a `warn` on every request although it is
    /// the shipped unit's normal operation.
    #[test]
    fn cross_uid_exe_eacces_names_the_process_from_cmdline_at_debug() {
        let proc = FakeProc::default().with_cmdline(&["sudo", "rm", "-rf", "/srv"]);
        let (ctx, events) = resolve_captured(&proc, 20_000, &request("sudo", "spoofed-name"));

        assert_eq!(
            ctx.process_name, "sudo",
            "argv[0] names the process when exe is EACCES"
        );
        assert_eq!(ctx.command_preview, "sudo rm -rf /srv");
        let warnings = at_least_warn(&events);
        assert!(
            warnings.is_empty(),
            "the expected cross-UID path must not warn: {warnings:?}"
        );
        let debug = debug_lines(&events);
        assert!(
            debug.iter().any(|m| m.contains("CAP_SYS_PTRACE")),
            "the EACCES fallback must still be visible at debug: {debug:?}"
        );
    }

    /// `cmdline` unreadable, `comm` readable: `comm` names the process.
    ///
    /// The defect this catches: no `comm` fallback at all, so the name reverts to
    /// the caller's self-report although the kernel could still answer.
    #[test]
    fn comm_names_the_process_when_the_command_line_is_unreadable() {
        let proc = FakeProc::default()
            .with_cmdline_error(io::ErrorKind::NotFound)
            .with_comm("firefox");
        let (ctx, events) = resolve_captured(&proc, 20_001, &request("sudo", "spoofed-name"));

        assert_eq!(ctx.process_name, "firefox");
        assert_eq!(ctx.command_preview, "");
        let warnings = at_least_warn(&events);
        assert_eq!(
            warnings.len(),
            1,
            "a live pid whose world-readable cmdline fails is unexpected: {warnings:?}"
        );
        let (_, message) = warnings.first().expect("length asserted above");
        assert!(message.contains("cmdline"), "{message}");
    }

    /// A caller that self-reports the PolKit helper's name — in both fields it
    /// controls — must not be treated as the helper when the kernel names it
    /// something else.
    ///
    /// The defect this catches: gating `is_polkit_helper` on `req.process_name` or
    /// `req.pam_service` when `exe` is unreadable (the production case), which lets
    /// any member of `tapauthd-clients` relabel itself `polkit-1` and have its argv
    /// dropped from the prompt the user is asked to approve.
    #[test]
    fn a_self_reported_helper_name_cannot_suppress_the_command_preview() {
        let proc = FakeProc::default().with_cmdline(&["sudo", "rm", "-rf", "/srv"]);
        let (ctx, _) = resolve_captured(&proc, 20_002, &request(POLKIT_HELPER, POLKIT_HELPER));

        assert_eq!(
            ctx.pam_service, POLKIT_HELPER,
            "the kernel names the caller sudo, so no PolKit display applies"
        );
        assert_eq!(ctx.process_name, "sudo");
        assert_eq!(ctx.command_preview, "sudo rm -rf /srv");
    }

    /// With no kernel source at all the self-reported name is displayed (the
    /// prompt must not be blank), and it still buys no PolKit treatment.
    ///
    /// The defect this catches: the removed `None => req.pam_service == POLKIT_HELPER
    /// || req.process_name == POLKIT_HELPER` fallback, which made an unreadable
    /// `/proc` — i.e. every root caller of the shipped unit — a licence to be
    /// displayed as `polkit-1`.
    #[test]
    fn a_self_report_is_never_enough_to_be_treated_as_the_helper() {
        let proc = FakeProc::default()
            .with_cmdline_error(io::ErrorKind::PermissionDenied)
            .with_comm_error(io::ErrorKind::PermissionDenied);
        let (ctx, events) = resolve_captured(&proc, 20_003, &request(POLKIT_HELPER, POLKIT_HELPER));

        assert_eq!(
            ctx.process_name, POLKIT_HELPER,
            "the name falls back to the self-report"
        );
        assert_eq!(
            ctx.pam_service, POLKIT_HELPER,
            "the service must not be rewritten from a claim"
        );
        assert_eq!(ctx.command_preview, "");
        assert_eq!(
            at_least_warn(&events).len(),
            1,
            "both world-readable entries failing on a live pid is one anomaly report: {events:?}"
        );
    }

    /// A genuine helper is recognised from each kernel source in turn.
    ///
    /// The defect this catches: identifying the helper by `exe` alone. In
    /// production `exe` is `EACCES`, so the real helper would be shown with its own
    /// argv (`polkit-agent-helper-1 polkit-1`) and its own service name.
    #[test]
    fn the_helper_is_recognised_from_exe_argv0_and_comm() {
        let cases = [
            (
                "exe",
                FakeProc::default()
                    .with_exe("/usr/lib/polkit-1/polkit-agent-helper-1")
                    .with_cmdline(&[
                        "/usr/lib/polkit-1/polkit-agent-helper-1",
                        "polkit-1",
                        "luca",
                    ]),
                POLKIT_HELPER,
            ),
            (
                "argv0",
                FakeProc::default().with_cmdline(&["polkit-agent-helper-1", "polkit-1", "luca"]),
                POLKIT_HELPER,
            ),
            (
                "comm",
                FakeProc::default().with_comm(POLKIT_HELPER_COMM),
                POLKIT_HELPER_COMM,
            ),
        ];

        for (source, proc, expected_name) in cases {
            let (ctx, _) = resolve_captured(&proc, 20_004, &request("polkit-1", ""));
            assert_eq!(
                ctx.pam_service, POLKIT_SERVICE,
                "the helper was not recognised from {source}"
            );
            assert_eq!(
                ctx.command_preview, "",
                "the helper's argv must be omitted when it is recognised from {source}"
            );
            assert_eq!(
                ctx.process_name, expected_name,
                "process name from {source}"
            );
        }
    }

    /// `comm` is compared against the kernel's truncation of the name, not the
    /// whole name: `TASK_COMM_LEN` is 16 bytes including the NUL, so the helper's
    /// `comm` is always exactly [`POLKIT_HELPER_COMM`].
    ///
    /// The defect this catches: a `comm` constant that is not the real truncation
    /// (the full name, or a hand-counted prefix), which leaves the real helper
    /// unrecognised on the production path and its argv on the phone.
    #[test]
    fn the_helper_comm_constant_is_the_kernels_truncation() {
        assert_eq!(POLKIT_HELPER_COMM, &POLKIT_HELPER[..15]);
        assert_eq!(POLKIT_HELPER_COMM.len(), 15);
    }

    /// A failure `EACCES` does not explain is operator-visible, and the warning
    /// must say what is actually unavailable.
    ///
    /// The defect this catches: the previous wording, which claimed the command
    /// came from the caller's self-report although `cmdline` is world-readable and
    /// `PamAuthenticateRequest` carries no command field at all.
    #[test]
    fn a_non_permission_exe_failure_warns_with_the_real_consequence() {
        let proc = FakeProc::default()
            .with_exe_error(io::ErrorKind::NotFound)
            .with_cmdline(&["sudo", "true"]);
        let (ctx, events) = resolve_captured(&proc, 20_005, &request("sudo", "spoofed-name"));

        assert_eq!(ctx.process_name, "sudo", "argv[0] still answers");
        let warnings = at_least_warn(&events);
        assert_eq!(
            warnings.len(),
            1,
            "one warn per resolved context: {warnings:?}"
        );
        let (level, message) = warnings.first().expect("length asserted above");
        assert_eq!(*level, tracing::Level::WARN);
        assert!(message.contains("exe"), "{message}");
        assert!(
            message.contains("no command field"),
            "the request carries none: {message}"
        );
        assert!(
            !message.contains("command) instead of"),
            "the old wording claimed the command came from the caller: {message}"
        );
    }

    /// A pid that left procfs between the request and the resolution is a race,
    /// not an anomaly: it must not reach the journal as a `warn`.
    #[test]
    fn a_departed_pid_is_not_an_anomaly() {
        let proc = FakeProc::default().gone();
        let (ctx, events) = resolve_captured(&proc, 20_006, &request("sudo", "sudo-wrapper"));

        assert_eq!(ctx.process_name, "sudo-wrapper");
        assert!(
            at_least_warn(&events).is_empty(),
            "a departed pid must stay at debug: {events:?}"
        );
    }

    /// The same race a few microseconds later: the caller is still there when
    /// liveness is sampled, and gone by the time every read has returned `ENOENT`
    /// — the exact window a single up-front sample cannot see.
    ///
    /// The defect this catches: reusing the first `pid_exists` sample for the
    /// classification, so a process that exits between the sample and the reads is
    /// reported as a live process with unreadable entries — the production `warn`
    /// this module exists to keep out of the journal.
    #[test]
    fn a_pid_that_exits_between_sampling_and_reading_is_not_an_anomaly() {
        let proc = FakeProc::default().gone().alive_then_gone();
        let (ctx, events) = resolve_captured(&proc, 20_007, &request("sudo", "sudo-wrapper"));

        assert_eq!(ctx.process_name, "sudo-wrapper");
        assert!(
            at_least_warn(&events).is_empty(),
            "a pid that exited during resolution must stay at debug: {events:?}"
        );
        assert!(
            debug_lines(&events)
                .iter()
                .any(|line| line.contains("left procfs")),
            "the race is still explained at debug: {events:?}"
        );
    }

    /// The same anomaly through the real filesystem: a pid procfs still knows
    /// (`stat` present) whose entries cannot be opened at all.
    #[test]
    fn a_live_pid_with_missing_entries_warns_once_that_no_kernel_identity_is_available() {
        let proc = TempProc::new();
        proc.with_stat(9100);

        let mut ctx = None;
        let warnings = warnings_during(|| {
            ctx = Some(CallerContext::resolve_with_root(
                9100,
                &request("sudo", "spoofed-name"),
                proc.path(),
            ));
        });

        assert_eq!(ctx.unwrap().process_name, "spoofed-name");
        assert_eq!(
            warnings.len(),
            1,
            "one warn per resolved context, not one per unreadable field: {warnings:?}"
        );
        let (level, message) = warnings.first().expect("length asserted above");
        assert_eq!(*level, tracing::Level::WARN);
        // The consequence and the remedy, so the line is actionable.
        assert!(message.contains("self-reported"), "{message}");
        assert!(message.contains("CAP_SYS_PTRACE"), "{message}");
    }

    /// The warn is for the exceptional path only: a readable `/proc` entry must not
    /// produce it, or every `sudo` on the host would train operators to ignore it.
    #[test]
    fn a_readable_proc_entry_emits_no_warning() {
        let proc = TempProc::new();
        proc.with_exe(9101, "/usr/bin/sudo");
        proc.with_cmdline(9101, &["sudo", "true"]);

        let mut ctx = None;
        let warnings = warnings_during(|| {
            ctx = Some(CallerContext::resolve_with_root(
                9101,
                &request("sudo", "spoofed-name"),
                proc.path(),
            ));
        });

        assert_eq!(ctx.unwrap().process_name, "sudo");
        assert!(warnings.is_empty(), "no warning expected: {warnings:?}");
    }

    /// The kernel appends `" (deleted)"` to the exe link once the image file is
    /// gone. Leaving it on would show `"sudo (deleted)"` on the prompt and would
    /// also defeat the process-name comparison against the self-report.
    #[test]
    fn deleted_suffix_is_stripped_from_the_kernel_exe_name() {
        let proc = TempProc::new();
        proc.with_exe(4242, "/usr/bin/sudo (deleted)");

        let ctx = CallerContext::resolve_with_root(4242, &request("sudo", "spoofed"), proc.path());

        assert_eq!(ctx.process_name, "sudo");
        assert_eq!(ctx.pam_service, "sudo");
    }

    /// `cmdline` is NUL-separated with a trailing NUL: the filter must join
    /// arguments with exactly one space and not leave a trailing separator.
    #[test]
    fn cmdline_arguments_are_joined_with_a_single_space() {
        let proc = TempProc::new();
        proc.with_exe(5150, "/usr/bin/sudo");
        proc.with_cmdline(5150, &["sudo", "apt", "install", "vim"]);

        let ctx = CallerContext::resolve_with_root(5150, &request("sudo", "sudo"), proc.path());

        assert_eq!(ctx.command_preview, "sudo apt install vim");
    }

    /// An unreadable cmdline yields an empty preview rather than stale text or a
    /// partial argument.
    #[test]
    fn missing_cmdline_yields_an_empty_preview() {
        let proc = TempProc::new();
        proc.with_exe(5151, "/usr/bin/su");

        let ctx = CallerContext::resolve_with_root(5151, &request("su", "su"), proc.path());

        assert_eq!(ctx.command_preview, "");
    }

    /// Controls and Bidi overrides in any field must never reach the prompt: a
    /// right-to-left override is how a caller makes `"evil"` display as `"sudo"`.
    #[test]
    fn control_and_bidi_characters_are_stripped_from_every_field() {
        let proc = TempProc::new();
        proc.with_exe(6000, "/usr/bin/su\u{202e}do");
        proc.with_cmdline(6000, &["su\u{7f}", "-\u{9b}c\u{0}leaning"]);

        let ctx = CallerContext::resolve_with_root(
            6000,
            &request("po\u{202e}lk\u{0}it-1", "su\u{202e}do"),
            proc.path(),
        );

        assert_eq!(ctx.process_name, "sudo");
        assert_eq!(ctx.pam_service, "polkit-1");
        // The embedded NUL splits argv into two arguments; DEL/C1 are stripped
        // from the surviving ones.
        assert_eq!(ctx.command_preview, "su -c leaning");
    }

    /// Every field is truncated to its byte budget, on a char boundary, with the
    /// ellipsis marker inside the budget.
    #[test]
    fn over_long_values_are_truncated_on_a_char_boundary() {
        let proc = TempProc::new();
        // Three-byte characters: truncation must not split one in half.
        let long_arg = "\u{20ac}".repeat(200);
        proc.with_exe(7000, "/usr/bin/\u{20ac}");
        proc.with_cmdline(7000, &[long_arg.as_str()]);

        let ctx = CallerContext::resolve_with_root(
            7000,
            &request(&"p".repeat(200), &"n".repeat(200)),
            proc.path(),
        );

        assert_eq!(ctx.pam_service.len(), PAM_SERVICE_MAX_BYTES);
        assert!(ctx.pam_service.ends_with('\u{2026}'));
        assert_eq!(ctx.process_name, "\u{20ac}", "one 3-byte char fits in 32B");
        // 125 content bytes available (128 - 3 for the ellipsis), i.e. 41
        // three-byte characters: the 42nd would overflow the budget.
        assert_eq!(ctx.command_preview.len(), 41 * 3 + 3);
        assert!(ctx.command_preview.len() <= COMMAND_PREVIEW_MAX_BYTES);
        assert!(ctx.command_preview.ends_with('\u{2026}'));
        // Whole characters survived, so the content before the ellipsis is a
        // multiple of the character width.
        let content = ctx.command_preview.trim_end_matches('\u{2026}');
        assert_eq!(content.len() % 3, 0);
    }

    /// When /proc cannot answer (dead or unknown pid), the self-reported name is
    /// used so the prompt is not blank.
    #[test]
    fn unknown_pid_falls_back_to_the_self_reported_name() {
        let proc = TempProc::new();

        let ctx = CallerContext::resolve_with_root(
            999_999,
            &request("sudo", "sudo-wrapped"),
            proc.path(),
        );

        assert_eq!(ctx.process_name, "sudo-wrapped");
        assert_eq!(ctx.pam_service, "sudo");
        assert_eq!(ctx.command_preview, "");
    }

    /// A non-positive pid must not be turned into `/proc/0/exe`.
    #[test]
    fn non_positive_pid_falls_back_to_the_self_reported_name() {
        let proc = TempProc::new();

        let ctx = CallerContext::resolve_with_root(0, &request("su", "su"), proc.path());

        assert_eq!(ctx.process_name, "su");
        assert_eq!(ctx.command_preview, "");
    }

    /// PolKit's helper is displayed as the `polkit-1` service and does not repeat
    /// its own argv. The kernel's view alone is enough to trigger this, so a
    /// caller that mislabels the service cannot suppress it.
    #[test]
    fn polkit_helper_service_is_overridden_and_argv_omitted() {
        let proc = TempProc::new();
        proc.with_exe(8000, "/usr/lib/polkit-1/polkit-agent-helper-1");
        proc.with_cmdline(8000, &["polkit-agent-helper-1", "luca"]);

        let ctx = CallerContext::resolve_with_root(8000, &request("sudo", ""), proc.path());

        assert_eq!(ctx.pam_service, "polkit-1");
        assert_eq!(ctx.process_name, "polkit-agent-helper-1");
        assert_eq!(ctx.command_preview, "");
    }

    /// When the kernel *can* name the image, its name decides: a caller running
    /// as `sudo` may not claim to be the PolKit helper to be displayed as
    /// `polkit-1` and to have its argv hidden from the user approving it.
    #[test]
    fn a_readable_kernel_name_cannot_be_overridden_by_the_self_report() {
        let proc = TempProc::new();
        proc.with_exe(8200, "/usr/bin/sudo");
        proc.with_cmdline(8200, &["sudo", "rm", "-rf", "/srv"]);

        // The lie: name both self-reported fields after the helper.
        let ctx = CallerContext::resolve_with_root(
            8200,
            &request(POLKIT_HELPER, POLKIT_HELPER),
            proc.path(),
        );

        assert_eq!(
            ctx.pam_service, POLKIT_HELPER,
            "the kernel name is `sudo`, so the PolKit display must not apply"
        );
        assert_eq!(ctx.process_name, "sudo");
        assert_eq!(
            ctx.command_preview, "sudo rm -rf /srv",
            "the argv must not be dropped for a caller that is not the helper"
        );
    }
}
