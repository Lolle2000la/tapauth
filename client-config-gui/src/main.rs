mod app;
mod logging;
mod screens;
mod utils;

fn main() -> iced::Result {
    // Get the original user BEFORE any logging or other initialization
    let original_user = utils::elevation::get_original_user();

    // Check if running as root - if not, attempt elevation
    if !utils::elevation::is_root() {
        // This function does not return - it exec's pkexec/sudo
        utils::elevation::attempt_privilege_elevation(&original_user);
    }

    // At this point, we should be running as root (via pkexec/sudo)
    // Store the original username in environment for app to use
    std::env::set_var("TAPAUTH_ORIGINAL_USER", &original_user);

    // Validate system prerequisites before continuing
    if let Err(err) = utils::system_check::validate_tapauthd_user() {
        // Show a native GUI error dialog since users typically launch from desktop
        use native_dialog::{DialogBuilder, MessageLevel};
        let _ = DialogBuilder::message()
            .set_title(&err.title)
            .set_text(&err.message)
            .set_level(MessageLevel::Error)
            .alert()
            .show();
        std::process::exit(1);
    }

    // Initialize logging
    logging::init_logging();

    tracing::info!("Starting TapAuth Configuration GUI");
    tracing::info!(
        "Running GUI for user: {} (elevated for privileged operations)",
        original_user
    );

    // Run the application
    iced::application(
        "TapAuth Configuration",
        app::TapAuthConfig::update,
        app::TapAuthConfig::view,
    )
    .theme(app::TapAuthConfig::theme)
    .run_with(app::TapAuthConfig::new)
}
