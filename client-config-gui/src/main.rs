mod app;
mod l10n;
mod logging;
mod pairing;
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

    // Detect system locale early for pre-check logging and dialog errors
    let locale = l10n::detect_locale();
    let bootstrap_l10n = l10n::L10n::new(locale);

    // Validate system prerequisites before continuing
    if let Err(_err) = utils::system_check::validate_tapauthd_user() {
        use native_dialog::{DialogBuilder, MessageLevel};
        let _ = DialogBuilder::message()
            .set_title(bootstrap_l10n.tr("error-user-missing-title"))
            .set_text(bootstrap_l10n.tr("error-user-missing-message"))
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
    tracing::info!("Using locale: {}", locale);

    // Load window icon
    let icon_data = include_bytes!("../assets/icon-256.png");
    let icon =
        iced::window::icon::from_file_data(icon_data, None).expect("Failed to load TapAuth icon");

    let window_settings = iced::window::Settings {
        icon: Some(icon),
        ..iced::window::Settings::default()
    };

    // Run the application
    iced::application(
        move || app::TapAuthConfig::new(locale),
        app::TapAuthConfig::update,
        app::TapAuthConfig::view,
    )
    .title("TapAuth Configuration")
    .theme(app::TapAuthConfig::theme)
    .font(lucide_icons::LUCIDE_FONT_BYTES)
    .window(window_settings)
    .run()
}
