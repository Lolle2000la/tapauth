//! Caller context for a PAM authentication request.
//!
//! The context shown on the Server (phone) is derived from two sources with very
//! different trust levels: the kernel's view of the calling process
//! (`/proc/<pid>/exe`, `/proc/<pid>/cmdline`) and the self-reported fields of
//! `PamAuthenticateRequest`. The kernel wins wherever it can answer; the
//! self-report is only a fallback, because a compromised `client-pam` can claim
//! to be any process it likes.
//!
//! Every field leaves this module through
//! [`sanitize_context_string`], so controls and Bidi overrides written by a
//! caller can never reshape the prompt it is asking the user to approve.

use shared::ipc::pb as ipc;
use shared::protocol::messages::{
    sanitize_context_string, COMMAND_PREVIEW_MAX_BYTES, PAM_SERVICE_MAX_BYTES,
    PROCESS_NAME_MAX_BYTES,
};
use std::path::{Path, PathBuf};

/// procfs root used in production.
const PROC_ROOT: &str = "/proc";

/// The PAM service PolKit's authentication agent helper runs under.
const POLKIT_HELPER: &str = "polkit-agent-helper-1";
/// Service name displayed (and shown on the phone) for a PolKit prompt.
const POLKIT_SERVICE: &str = "polkit-1";
/// Suffix the kernel appends to `/proc/<pid>/exe` once the image is unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// Sanitized, display-only context describing who asked for authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    /// PAM service of the request (`sudo`, `su`, `polkit-1`, …).
    pub pam_service: String,
    /// Name of the calling process image.
    pub process_name: String,
    /// The caller's argv, joined by single spaces.
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
        let exe_name = kernel_exe_basename(proc_root, caller_pid);

        // One `warn` per resolved context, not one per failed read: `exe` and
        // `cmdline` fail together in the cross-UID `EACCES` case, and the debug
        // lines inside the two readers already carry the errno. Escalated from
        // `debug` because the consequence is a trust downgrade an operator has to
        // know about: both display fields then come from the caller, so the name
        // and command the phone shows are claims, not the kernel's.
        if caller_pid > 0 && exe_name.is_none() {
            tracing::warn!(
                "Cannot read {} for pid {}: the phone will display the caller's self-reported \
                 process name (and command) instead of the kernel-verified ones. The shipped \
                 unit runs without CAP_SYS_PTRACE, so this is expected for another user's \
                 process and is not a failure; grant that capability only if kernel-verified \
                 display context is required.",
                proc_dir(proc_root, caller_pid).join("exe").display(),
                caller_pid
            );
        }

        // PolKit's helper runs under its own name, and the phone should display
        // the service it authenticates (`polkit-1`) rather than the helper's own
        // argv. The kernel's view of the image decides whenever it can answer:
        // both self-reported fields are untrusted, so a caller whose kernel name
        // is `sudo` must not be able to relabel itself as the helper and have its
        // argv dropped from the prompt by doing so. The self-report is honoured
        // only in the degraded case where /proc could not be read at all — which
        // is the normal case for the shipped daemon, whose `User=` and capability
        // set leave another UID's `/proc/<pid>/exe` unreadable.
        let is_polkit_helper = match exe_name.as_deref() {
            Some(name) => name == POLKIT_HELPER,
            None => req.pam_service == POLKIT_HELPER || req.process_name == POLKIT_HELPER,
        };

        let pam_service = if is_polkit_helper {
            POLKIT_SERVICE
        } else {
            req.pam_service.as_str()
        };

        // A self-reported process name is untrusted: prefer what the kernel says
        // the caller's image is, falling back only when /proc cannot answer.
        let process_name = match exe_name {
            Some(name) => name,
            None => req.process_name.clone(),
        };

        // The helper's argv only repeats the service name it is already
        // displayed under (`polkit-agent-helper-1 polkit-1 …`), so it is omitted.
        let command_preview = if is_polkit_helper {
            String::new()
        } else {
            kernel_cmdline(proc_root, caller_pid)
        };

        Self {
            pam_service: sanitize_context_string(pam_service, PAM_SERVICE_MAX_BYTES),
            process_name: sanitize_context_string(&process_name, PROCESS_NAME_MAX_BYTES),
            command_preview: sanitize_context_string(&command_preview, COMMAND_PREVIEW_MAX_BYTES),
        }
    }
}

/// Basename of `/proc/<pid>/exe`, or `None` when the kernel cannot answer.
///
/// The link target carries `" (deleted)"` once the image file is gone (a
/// replaced or removed binary), which is not part of the process name.
///
/// Reading another user's `/proc/<pid>/exe` needs `CAP_SYS_PTRACE`, which the
/// shipped unit deliberately does not grant, so a failure here is the normal
/// degradation rather than a bug — but it is logged, because it silently makes
/// the prompt fall back to what the caller about itself reported. The errno is
/// logged here at `debug`; [`CallerContext::resolve_with_root`] emits one `warn`
/// per resolved context with the consequence.
fn kernel_exe_basename(proc_root: &Path, pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let path = proc_dir(proc_root, pid).join("exe");
    let target = match std::fs::read_link(&path) {
        Ok(target) => target,
        Err(e) => {
            tracing::debug!(
                "Cannot read {} for pid {} ({}); using the caller's self-reported process name",
                path.display(),
                pid,
                e
            );
            return None;
        }
    };
    let target = target.to_str()?;
    let stripped = target.strip_suffix(DELETED_SUFFIX).unwrap_or(target);
    let name = Path::new(stripped).file_name()?.to_str()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// `/proc/<pid>/cmdline` as a single line, or an empty string when unreadable.
///
/// The file is NUL-separated with a trailing NUL; empty (zero-length) arguments
/// are dropped rather than turned into double spaces.
///
/// Same `/proc` reachability rule as [`kernel_exe_basename`]: a read failure is
/// the expected cross-UID case, and the phone then shows no command preview, so
/// it is logged rather than passed over in silence.
fn kernel_cmdline(proc_root: &Path, pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    let path = proc_dir(proc_root, pid).join("cmdline");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!(
                "Cannot read {} for pid {} ({}); the command preview will be empty",
                path.display(),
                pid,
                e
            );
            return String::new();
        }
    };
    let mut args: Vec<std::borrow::Cow<'_, str>> = Vec::new();
    for arg in bytes.split(|byte| *byte == 0) {
        if arg.is_empty() {
            continue;
        }
        args.push(String::from_utf8_lossy(arg));
    }
    args.join(" ")
}

fn proc_dir(proc_root: &Path, pid: i32) -> PathBuf {
    proc_root.join(pid.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT_ID: AtomicU32 = AtomicU32::new(0);

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
        let log = CapturedLog::default();
        {
            let _guard = tracing::subscriber::set_default(log.clone());
            resolve();
        }
        log.events()
            .into_iter()
            .filter(|(level, _)| matches!(*level, tracing::Level::WARN | tracing::Level::ERROR))
            .collect()
    }

    /// The production degradation: the shipped unit lacks `CAP_SYS_PTRACE`, so a
    /// caller from another UID has an unreadable `/proc/<pid>/exe` and the phone
    /// is shown the caller's own claim. That must be a single visible `warn` per
    /// resolved context — one line covering both reads, not one per field — and it
    /// must say what the operator is looking at and what would change it.
    #[test]
    fn an_unreadable_proc_entry_warns_once_that_the_display_is_caller_supplied() {
        let proc = TempProc::new();
        // The pid exists but nothing under it is readable: the cross-UID shape.
        proc.process_dir(9100);

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

    /// The self-reported service name alone also selects the PolKit display, for
    /// callers whose /proc entry is unreadable.
    #[test]
    fn self_reported_polkit_helper_name_is_normalised() {
        let proc = TempProc::new();

        let ctx = CallerContext::resolve_with_root(
            8001,
            &request(POLKIT_HELPER, POLKIT_HELPER),
            proc.path(),
        );

        assert_eq!(ctx.pam_service, "polkit-1");
        assert_eq!(ctx.command_preview, "");
    }

    /// The honest helper keeps its display under both readings: the kernel's name
    /// when /proc answers, the self-report when it does not (the production case,
    /// where the daemon cannot read a root caller's exe).
    #[test]
    fn a_genuine_polkit_helper_is_displayed_as_polkit_with_no_argv() {
        let proc = TempProc::new();
        proc.with_exe(8100, "/usr/lib/polkit-1/polkit-agent-helper-1");
        proc.with_cmdline(8100, &["polkit-agent-helper-1", "polkit-1", "luca"]);

        let ctx = CallerContext::resolve_with_root(
            8100,
            &request(POLKIT_HELPER, "polkit-agent-helper-1"),
            proc.path(),
        );

        assert_eq!(ctx.pam_service, POLKIT_SERVICE);
        assert_eq!(ctx.process_name, POLKIT_HELPER);
        assert_eq!(ctx.command_preview, "");

        // Unreadable /proc: the self-report is all there is, so it decides.
        let unreadable = TempProc::new();
        let ctx = CallerContext::resolve_with_root(
            8101,
            &request(POLKIT_HELPER, POLKIT_HELPER),
            unreadable.path(),
        );

        assert_eq!(ctx.pam_service, POLKIT_SERVICE);
        assert_eq!(ctx.process_name, POLKIT_HELPER);
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
