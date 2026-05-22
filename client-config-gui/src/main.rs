mod app;
mod l10n;
mod logging;
mod pairing;
mod screens;
mod utils;

fn main() -> iced::Result {
    // Parse target locale flag if passed via elevation re-exec
    let args: Vec<String> = std::env::args().collect();
    let mut forced_locale = None;
    if let Some(pos) = args.iter().position(|arg| arg == "--locale") {
        if pos + 1 < args.len() {
            forced_locale = Some(args[pos + 1].clone());
        }
    }

    let original_user = utils::elevation::get_original_user();

    if !utils::elevation::is_root() {
        // Detect locale before environment scrubbing happens
        let current_locale = l10n::detect_locale();
        utils::elevation::attempt_privilege_elevation(
            &original_user,
            &["--locale", current_locale],
        );
    }

    std::env::set_var("TAPAUTH_ORIGINAL_USER", &original_user);

    logging::init_logging();

    // Resolve locale prioritizing the preserved CLI argument
    let locale: &str = if let Some(ref loc) = forced_locale {
        // Map back to a static str to avoid leaking heap strings
        match loc.as_str() {
            "de" => "de",
            "ja" => "ja",
            _ => "en",
        }
    } else {
        l10n::detect_locale()
    };

    let bootstrap_l10n = l10n::L10n::new(locale);

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

    tracing::info!("Starting TapAuth Configuration GUI");
    tracing::info!(
        "Running GUI for user: {} (elevated for privileged operations)",
        original_user
    );
    tracing::info!("Using locale: {}", locale);

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
    .title(|state: &app::TapAuthConfig| state.title())
    .theme(app::TapAuthConfig::theme)
    .font(lucide_icons::LUCIDE_FONT_BYTES)
    .window(window_settings)
    .run()
}
