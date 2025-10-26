mod app;
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

    // At this point, we're running as root
    // Store the original username in environment for app to use
    std::env::set_var("TAPAUTH_ORIGINAL_USER", &original_user);

    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // Use debug level in debug builds, info level in release builds
                if cfg!(debug_assertions) {
                    tracing_subscriber::EnvFilter::new("debug")
                } else {
                    tracing_subscriber::EnvFilter::new("info")
                }
            }),
        )
        .init();

    tracing::info!("Starting TapAuth Configuration GUI");
    tracing::info!("Running as root for user: {}", original_user);

    // Run the application
    iced::application(
        "TapAuth Configuration",
        app::TapAuthConfig::update,
        app::TapAuthConfig::view,
    )
    .theme(app::TapAuthConfig::theme)
    .run_with(app::TapAuthConfig::new)
}
