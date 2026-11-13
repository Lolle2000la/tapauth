//! The caller facts the conversation policy is decided on, read once per call:
//! the service name, the process identity and the GDM reauthentication flag.
//! All are local — none leaves the module, and `policy::classify` never re-reads.

use crate::pam_sys;
use std::ffi::OsStr;
use std::path::Path;

/// The caller facts, captured before any other work in `authenticate`.
///
/// R1 is keyed on the service name alone (see `policy::table::remote_refuse`),
/// so this type carries no remote-presence fact: nothing reads `PAM_RHOST`.
pub(crate) struct CallerContext {
    service: Option<ServiceName>,
    process: ProcessIdentity,
    gdm_reauth: GdmReauth,
}

impl CallerContext {
    /// The single site that reads `PAM_SERVICE`, `/proc` and the environment.
    ///
    /// # Safety
    ///
    /// `pamh` must be the live handle libpam passed to this module's
    /// `pam_sm_authenticate`; every read below is a handle read or a `/proc`
    /// read of this process.
    pub(crate) unsafe fn capture(pamh: *mut pam_sys::PamHandle) -> CallerContext {
        let service = unsafe { pam_sys::get_service_name(pamh) };
        // `get_service_name` rejects a non-UTF-8 item (its `to_str` fails), so
        // the name is never converted lossily: a lossy string would become a
        // real prefix candidate and a real cache key.
        let service = service.as_deref().map(ServiceName::new);
        let process = identity_from_proc();
        let gdm_reauth = GdmReauth::from_env(std::env::var_os("GDM_SESSION_FOR_REAUTH").as_deref());

        // The module's one debug line, emitted before any decision: a log reader
        // sees the three facts `classify` is about to consume, never a
        // conclusion that was not acted on.
        tracing::debug!(
            service = service.as_ref().map(ServiceName::original).unwrap_or("-"),
            process = process.name().unwrap_or("-"),
            "gdm_reauth_present" = gdm_reauth == GdmReauth::Present,
            "TapAuth caller"
        );

        CallerContext {
            service,
            process,
            gdm_reauth,
        }
    }

    /// Test-only, so no production caller can fabricate an identity: `capture` is
    /// the only way in.
    #[cfg(test)]
    pub(crate) fn from_parts(
        service: Option<&str>,
        process: ProcessIdentity,
        gdm_reauth: GdmReauth,
    ) -> CallerContext {
        CallerContext {
            service: service.map(ServiceName::new),
            process,
            gdm_reauth,
        }
    }

    pub(crate) fn service(&self) -> Option<&ServiceName> {
        self.service.as_ref()
    }

    pub(crate) fn process(&self) -> &ProcessIdentity {
        &self.process
    }

    /// A GDM reauthentication: the flag is present **and** the service is
    /// `gdm-password`. Both conditions here so every consumer reads one answer.
    pub(crate) fn is_gdm_reauth(&self) -> bool {
        self.gdm_reauth == GdmReauth::Present
            && self
                .service
                .as_ref()
                .is_some_and(|service| service.eq_ignore_ascii_case("gdm-password"))
    }
}

/// A PAM service name, in the two forms the policy compares.
///
/// `original` is the bytes libpam returned and is the verdict cache's key, so
/// `sudo` and `SUDO` stay distinct. `ascii_lower` serves the case-insensitive
/// comparisons only, folded with `to_ascii_lowercase` — never `str::to_lowercase`,
/// which maps U+212A KELVIN SIGN to `k` and would make `\u{212a}dm` match `kdm`.
#[derive(Clone)]
pub(crate) struct ServiceName {
    original: Box<str>,
    ascii_lower: Box<str>,
}

impl ServiceName {
    pub(crate) fn new(service: &str) -> ServiceName {
        ServiceName {
            original: service.into(),
            ascii_lower: service.to_ascii_lowercase().into(),
        }
    }

    /// The bytes libpam returned, and the verdict cache's key.
    pub(crate) fn original(&self) -> &str {
        &self.original
    }

    /// Exact-bytes comparison, for the rules whose literal is deliberately
    /// case-sensitive (`polkit-1`, `sshd`).
    pub(crate) fn is(&self, literal: &str) -> bool {
        self.original.as_ref() == literal
    }

    /// ASCII case-insensitive comparison (`gdm-password`): ASCII-only by
    /// construction, so no Unicode folding is involved.
    pub(crate) fn eq_ignore_ascii_case(&self, literal: &str) -> bool {
        self.ascii_lower.eq_ignore_ascii_case(literal)
    }

    /// Whether the name is `prefix` exactly, or `prefix` followed by a `-`
    /// boundary. `ly` therefore matches `ly` and `ly-*` but not `lyfoo`.
    pub(crate) fn dm_prefixed(&self, prefix: &str) -> bool {
        let name = self.ascii_lower.as_ref();
        name == prefix
            || (name.starts_with(prefix) && name.as_bytes().get(prefix.len()) == Some(&b'-'))
    }
}

/// Which source the process name came from, once resolved.
///
/// `Exe`/`Comm` is **provenance only**: every rule matches on the name for both
/// variants, so a real binary literally named `kscreenlocker_w` still matches
/// the worker rule. The distinction lets a test assert the `(deleted)` strip and
/// the `comm` fallback independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProcessIdentity {
    Exe(Box<str>),
    Comm(Box<str>),
    Unknown,
}

impl ProcessIdentity {
    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            ProcessIdentity::Exe(name) | ProcessIdentity::Comm(name) => Some(name),
            ProcessIdentity::Unknown => None,
        }
    }
}

/// Resolve this process's identity from `/proc`.
///
/// `/proc/self/exe` (authoritative, untruncated) is preferred; `/proc/self/comm`
/// is read only when `exe` yielded no name and holds at most `TASK_COMM_LEN - 1`
/// (15) bytes, which is why the policy accepts both the full and the truncated
/// spelling of each process name.
pub(crate) fn identity_from_proc() -> ProcessIdentity {
    let exe = std::fs::read_link("/proc/self/exe").ok();
    let from_exe = classify_identity(exe.as_deref(), None);
    if matches!(from_exe, ProcessIdentity::Exe(_)) {
        return from_exe;
    }
    let comm = std::fs::read_to_string("/proc/self/comm").ok();
    classify_identity(None, comm.as_deref())
}

/// Resolve an identity from the two `/proc` sources.
///
/// Pure, so the `(deleted)` strip, the empty-name rejection and the
/// `exe`-before-`comm` precedence are unit-testable without a `/proc` read.
pub(crate) fn classify_identity(exe: Option<&Path>, comm: Option<&str>) -> ProcessIdentity {
    if let Some(exe) = exe {
        if let Some(name) = exe.file_name() {
            let name = name.to_string_lossy();
            // The kernel suffixes " (deleted)" once the binary is unlinked.
            let name = name.strip_suffix(" (deleted)").unwrap_or(name.as_ref());
            if !name.is_empty() {
                return ProcessIdentity::Exe(name.into());
            }
        }
    }
    if let Some(comm) = comm {
        let comm = comm.trim();
        if !comm.is_empty() {
            return ProcessIdentity::Comm(comm.into());
        }
    }
    ProcessIdentity::Unknown
}

/// Whether the calling process carries `GDM_SESSION_FOR_REAUTH`.
///
/// Presence only (`var_os(..).is_some()`), so a set variable holding `0` counts;
/// there is no value parse to get wrong. `from_env` is pure and `capture` is its
/// only caller, so the interpretation is testable without `set_var`, which would
/// race every other test in this binary that reads the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GdmReauth {
    Present,
    Absent,
}

impl GdmReauth {
    pub(crate) fn from_env(value: Option<&OsStr>) -> GdmReauth {
        if value.is_some() {
            GdmReauth::Present
        } else {
            GdmReauth::Absent
        }
    }
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

    /// `GDM_SESSION_FOR_REAUTH` is read for its *presence* only, so a set variable
    /// holding `0` or `""` is as present as one holding `1`. The value is passed
    /// in, so this pins the interpretation without `set_var`; the read itself is
    /// covered by the `gdm-password login`/`reauth` e2e shapes.
    #[test]
    fn gdm_reauth_env_parsing() {
        let cases: &[(Option<&OsStr>, GdmReauth)] = &[
            (None, GdmReauth::Absent),
            (Some(OsStr::new("")), GdmReauth::Present),
            (Some(OsStr::new("0")), GdmReauth::Present),
            (Some(OsStr::new("1")), GdmReauth::Present),
        ];
        for &(value, expected) in cases {
            assert_eq!(GdmReauth::from_env(value), expected, "value {value:?}");
        }
    }

    /// The defect this catches: the strip dropped, so an upgraded or swapped
    /// binary (`swaylock (deleted)`) no longer matches R8, falls through to R10 and
    /// rings the phone for a host that already collected the password.
    #[test]
    fn strip_deleted_suffix() {
        assert_eq!(
            classify_identity(Some(Path::new("/usr/bin/swaylock (deleted)")), None),
            ProcessIdentity::Exe("swaylock".into())
        );
        assert_eq!(
            classify_identity(Some(Path::new("/usr/bin/swaylock")), None),
            ProcessIdentity::Exe("swaylock".into())
        );
        // Only a trailing suffix is the kernel's; a directory named like one is
        // not.
        assert_eq!(
            classify_identity(Some(Path::new("/opt/swaylock (deleted)/bin/x")), None),
            ProcessIdentity::Exe("x".into())
        );
        // A basename that is *only* the suffix strips to empty, so `exe` yields
        // nothing and `comm` becomes the only source.
        assert_eq!(
            classify_identity(Some(Path::new("/x/ (deleted)")), Some("sh")),
            ProcessIdentity::Comm("sh".into())
        );
    }

    /// The defect this catches: `trim()` dropped, so `/proc/self/comm`'s trailing
    /// newline becomes part of the name, no rule matches the truncated spelling and
    /// a threaded host silently becomes Sequential; or a blank `comm` accepted as
    /// `Comm("")`, claiming a provenance for a name no rule can match.
    #[test]
    fn comm_fallback_trims_and_rejects_empty() {
        let trimmed = classify_identity(None, Some("  kscreenlocker_w \n"));
        assert_eq!(trimmed, ProcessIdentity::Comm("kscreenlocker_w".into()));
        // The name the policy matches, not just the shape of the value: the
        // trimmed spelling is what R5 sees.
        let ctx = CallerContext::from_parts(Some("kde"), trimmed, GdmReauth::Absent);
        let (rule, classification) = crate::policy::classify(&ctx);
        assert!(
            matches!(
                classification,
                crate::policy::Classification::Participate(_)
            ) && rule == crate::policy::RuleId::R5,
            "the trimmed comm spelling must reach R5"
        );

        assert_eq!(
            classify_identity(None, Some("   \n")),
            ProcessIdentity::Unknown,
            "a blank comm is no name at all"
        );
        assert_eq!(classify_identity(None, Some("")), ProcessIdentity::Unknown);
    }

    /// The defect this catches: `comm` consulted before `exe` (or `exe` treated as
    /// a fallback), so a process whose truncated `comm` spelling is a near-miss is
    /// classified from the wrong name.
    #[test]
    fn exe_wins_over_comm() {
        assert_eq!(
            classify_identity(Some(Path::new("/usr/bin/kscreenlocker_worker")), Some("sh")),
            ProcessIdentity::Exe("kscreenlocker_worker".into())
        );
        // Even a `(deleted)` `exe` that still has a name outranks `comm`.
        assert_eq!(
            classify_identity(Some(Path::new("/usr/bin/swaylock (deleted)")), Some("sh")),
            ProcessIdentity::Exe("swaylock".into())
        );
        assert_eq!(
            classify_identity(Some(Path::new("/")), Some("sh")),
            ProcessIdentity::Comm("sh".into())
        );
    }

    /// The defect this catches: `is_gdm_reauth` testing only
    /// `GDM_SESSION_FOR_REAUTH`, so the variable alone exempts any display manager
    /// from R2 — an `sddm` login with the variable set would participate instead of
    /// populating `PAM_AUTHTOK`, leaving its keyring locked.
    #[test]
    fn gdm_reauth_requires_service() {
        let worker = || ProcessIdentity::Exe("gdm-session-worker".into());

        let reauth = CallerContext::from_parts(Some("gdm-password"), worker(), GdmReauth::Present);
        assert!(reauth.is_gdm_reauth(), "gdm-password plus the flag is R3's");

        let login = CallerContext::from_parts(Some("gdm-password"), worker(), GdmReauth::Absent);
        assert!(
            !login.is_gdm_reauth(),
            "the flag is a conjunct, not the whole rule"
        );

        // A display manager *other than* `gdm-password` keeps its keyring
        // bypass even with the variable set: the flag alone must not turn a
        // skip into a participation.
        let sddm = CallerContext::from_parts(
            Some("sddm"),
            ProcessIdentity::Exe("sddm".into()),
            GdmReauth::Present,
        );
        assert!(!sddm.is_gdm_reauth());
        assert!(
            matches!(
                crate::policy::classify(&sddm).1,
                crate::policy::Classification::Skip(crate::policy::SkipPolicy::KeyringNeedsAuthtok)
            ),
            "an sddm login with GDM_SESSION_FOR_REAUTH set must still be the \
             keyring bypass, not a participation"
        );

        let unknown = CallerContext::from_parts(None, worker(), GdmReauth::Present);
        assert!(!unknown.is_gdm_reauth());
    }
}
