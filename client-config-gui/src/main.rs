mod app;
mod ipc;
mod l10n;
mod logging;
mod screens;
mod utils;

use native_dialog::{DialogBuilder, MessageLevel};

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

    for err in utils::system_check::validate_all() {
        let level = if err.is_fatal() {
            MessageLevel::Error
        } else {
            MessageLevel::Warning
        };
        let title = bootstrap_l10n.tr(err.title_key());
        let message = bootstrap_l10n.tr(err.message_key());
        if let Err(dialog_err) = DialogBuilder::message()
            .set_title(&title)
            .set_text(&message)
            .set_level(level)
            .alert()
            .show()
        {
            tracing::error!("Failed to show dialog: {dialog_err}");
            eprintln!("[{level:?}] {title}: {message}");
        }
        if err.is_fatal() {
            std::process::exit(1);
        }
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
