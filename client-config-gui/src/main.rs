mod app;
mod screens;
mod utils;

fn main() -> iced::Result {
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

    // Run the application
    iced::application(
        "TapAuth Configuration",
        app::TapAuthConfig::update,
        app::TapAuthConfig::view,
    )
    .theme(app::TapAuthConfig::theme)
    .run_with(app::TapAuthConfig::new)
}
