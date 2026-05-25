mod app;
mod ipc;
mod l10n;
mod logging;
mod screens;
mod utils;

fn main() -> iced::Result {
    let args: Vec<String> = std::env::args().collect();
    let mut forced_locale = None;
    if let Some(pos) = args.iter().position(|arg| arg == "--locale") {
        if pos + 1 < args.len() {
            forced_locale = Some(args[pos + 1].clone());
        }
    }

    let original_user = utils::identity::get_username();

    logging::init_logging();

    let locale: String = l10n::resolve_locale(forced_locale.as_deref(), &original_user);

    let bootstrap_l10n = l10n::L10n::new(&locale);

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
    tracing::info!("Running GUI as unprivileged user: {}", original_user);
    tracing::info!("Using locale: {}", locale);

    let icon_data = include_bytes!("../assets/icon-256.png");
    let icon =
        iced::window::icon::from_file_data(icon_data, None).expect("Failed to load TapAuth icon");

    let window_settings = iced::window::Settings {
        icon: Some(icon),
        ..iced::window::Settings::default()
    };

    let username = original_user;

    iced::application(
        move || app::TapAuthConfig::new(&locale, &username),
        app::TapAuthConfig::update,
        app::TapAuthConfig::view,
    )
    .title(|state: &app::TapAuthConfig| state.title())
    .theme(app::TapAuthConfig::theme)
    .font(lucide_icons::LUCIDE_FONT_BYTES)
    .window(window_settings)
    .run()
}
