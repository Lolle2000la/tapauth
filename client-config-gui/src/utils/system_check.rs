/// System prerequisite checks for the TapAuth configuration GUI
use nix::unistd::{getgroups, Group, User};

/// Marker error type for system prerequisite failures.
/// The actual user-visible messages are served by the Fluent bundle
/// so they render in the current locale.
#[derive(Debug, Clone)]
pub struct ValidationError;

/// Validates that the `tapauthd` system user exists
///
/// The daemon (running as the `tapauthd` user) is the single writer of all
/// config files.  If this user doesn't exist, the daemon can't run — the GUI
/// checks early so it can show a helpful error before trying IPC operations.
pub fn validate_tapauthd_user() -> Result<(), ValidationError> {
    match User::from_name("tapauthd") {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => Err(ValidationError),
    }
}

/// Validates that the current user is a member of the `tapauthd-clients` group
///
/// The daemon socket (`/run/tapauthd/tapauthd.sock`) has permissions
/// `root:tapauthd-clients 0660`, enforced by the kernel.  Only members of
/// this group can connect to the daemon — the GUI checks early so it can
/// show a helpful warning before the user tries IPC operations.
pub fn validate_tapauthd_clients_group() -> Result<(), ValidationError> {
    let group = match Group::from_name("tapauthd-clients") {
        Ok(Some(g)) => g,
        Ok(None) | Err(_) => return Err(ValidationError),
    };

    let target_gid = group.gid;

    if nix::unistd::getegid() == target_gid {
        return Ok(());
    }

    let groups = getgroups().map_err(|_| ValidationError)?;
    if groups.contains(&target_gid) {
        return Ok(());
    }

    Err(ValidationError)
}
