/// System prerequisite checks for the TapAuth configuration GUI
use nix::unistd::User;

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
