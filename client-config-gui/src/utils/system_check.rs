/// System prerequisite checks for the TapAuth configuration GUI
use nix::unistd::{getgroups, Group, User};

/// Reasons why a system prerequisite check can fail.
///
/// Each variant maps to a distinct user-visible message in the Fluent bundle
/// and determines whether the failure is fatal (exit) or a non-blocking warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The `tapauthd` system user does not exist (fatal).
    TapauthdUserMissing,
    /// The `tapauthd-clients` system group does not exist (fatal).
    TapauthdClientsGroupMissing,
    /// Current user is not a member of the `tapauthd-clients` group (warning).
    NotInTapauthdClientsGroup,
}

impl ValidationError {
    /// Fluent key for the dialog title.
    pub fn title_key(&self) -> &'static str {
        match self {
            Self::TapauthdUserMissing => "error-user-missing-title",
            Self::TapauthdClientsGroupMissing => "error-group-missing-title",
            Self::NotInTapauthdClientsGroup => "warn-group-missing-title",
        }
    }

    /// Fluent key for the dialog body.
    pub fn message_key(&self) -> &'static str {
        match self {
            Self::TapauthdUserMissing => "error-user-missing-message",
            Self::TapauthdClientsGroupMissing => "error-group-missing-message",
            Self::NotInTapauthdClientsGroup => "warn-group-missing-message",
        }
    }

    /// Whether this error should cause the process to exit.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::TapauthdUserMissing | Self::TapauthdClientsGroupMissing
        )
    }
}

/// Validates that the `tapauthd` system user exists
///
/// The daemon (running as the `tapauthd` user) is the single writer of all
/// config files.  If this user doesn't exist, the daemon can't run — the GUI
/// checks early so it can show a helpful error before trying IPC operations.
pub fn validate_tapauthd_user() -> Result<(), ValidationError> {
    match User::from_name("tapauthd") {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(ValidationError::TapauthdUserMissing),
        Err(err) => {
            tracing::error!("Failed to lookup 'tapauthd' user: {err}");
            Err(ValidationError::TapauthdUserMissing)
        }
    }
}

/// Validates that the current user is a member of the `tapauthd-clients` group
///
/// The daemon socket (`/run/tapauthd/tapauthd.sock`) has permissions
/// `root:tapauthd-clients 0660`, enforced by the kernel.  Only members of
/// this group can connect to the daemon — the GUI checks early so it can
/// show a helpful warning before the user tries IPC operations.
///
/// Root bypasses this check (socket is owned by root).
///
/// Returns `TapauthdClientsGroupMissing` (fatal) when the group itself does
/// not exist, and `NotInTapauthdClientsGroup` (warning) when the current
/// user is not a member of an existing group.
pub fn validate_tapauthd_clients_group() -> Result<(), ValidationError> {
    let group = match Group::from_name("tapauthd-clients") {
        Ok(Some(g)) => g,
        Ok(None) => return Err(ValidationError::TapauthdClientsGroupMissing),
        Err(err) => {
            tracing::error!("Failed to lookup 'tapauthd-clients' group: {err}");
            return Err(ValidationError::TapauthdClientsGroupMissing);
        }
    };

    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }

    let target_gid = group.gid;

    if nix::unistd::getegid() == target_gid {
        return Ok(());
    }

    let groups = getgroups().map_err(|err| {
        tracing::error!("Failed to retrieve supplementary groups: {err}");
        ValidationError::NotInTapauthdClientsGroup
    })?;
    if groups.contains(&target_gid) {
        return Ok(());
    }

    Err(ValidationError::NotInTapauthdClientsGroup)
}

/// Run all system prerequisite checks.
///
/// Returns a list of validation results in the order they should be
/// presented to the user (fatal errors first, then warnings).
pub fn validate_all() -> Vec<Result<(), ValidationError>> {
    vec![validate_tapauthd_user(), validate_tapauthd_clients_group()]
}
