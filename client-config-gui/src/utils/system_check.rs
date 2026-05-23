/// System prerequisite checks for the TapAuth configuration GUI
use nix::unistd::User;

/// Marker error type for system prerequisite failures.
/// The actual user-visible messages are served by the Fluent bundle
/// so they render in the current locale.
#[derive(Debug, Clone)]
pub struct ValidationError;

/// Validates that the `tapauthd` system user exists
///
/// The GUI requires root privileges to create configuration files, and those files
/// must be owned by the `tapauthd` user so the daemon can access them.
///
/// Returns an error with helpful instructions if the user doesn't exist.
pub fn validate_tapauthd_user() -> Result<(), ValidationError> {
    match User::from_name("tapauthd") {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => Err(ValidationError),
    }
}
