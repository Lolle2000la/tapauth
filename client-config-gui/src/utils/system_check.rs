/// System prerequisite checks for the TapAuth configuration GUI
use nix::unistd::User;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub title: String,
    pub message: String,
}

/// Validates that the `tapauthd` system user exists
///
/// The GUI requires root privileges to create configuration files, and those files
/// must be owned by the `tapauthd` user so the daemon can access them.
///
/// Returns an error with helpful instructions if the user doesn't exist.
pub fn validate_tapauthd_user() -> Result<(), ValidationError> {
    match User::from_name("tapauthd") {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => Err(ValidationError {
            title: "System User Missing".to_string(),
            message: "The 'tapauthd' system user is required but was not found.\n\n\
                This user should have been created during installation.\n\n\
                Recommended action:\n\
                1. Log out and log back in (or restart your system)\n\
                2. Try launching the application again\n\n\
                If the problem persists, you may need to create the user manually:\n\
                    sudo useradd --system --no-create-home tapauthd"
                .to_string(),
        }),
    }
}
