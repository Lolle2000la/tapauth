use crate::l10n::{self, L10n};
use crate::screens::{Screen, ScreenMessage};
use iced::{Element, Task, Theme};

/// Main application state
pub struct TapAuthConfig {
    l10n: L10n,
    current_screen: Screen,
    /// Original (pre-elevation) username for per-user locale persistence
    username: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    ScreenMessage(ScreenMessage),
}

impl TapAuthConfig {
    pub fn new(locale: &str, username: &str) -> (Self, Task<Message>) {
        let l10n = L10n::new(locale);
        let (current_screen, init_task) = Screen::default_with_l10n(l10n.clone());
        (
            Self {
                l10n,
                current_screen,
                username: username.to_string(),
            },
            init_task.map(Message::ScreenMessage),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScreenMessage(screen_msg) => {
                if let ScreenMessage::LocaleChanged(ref locale) = screen_msg {
                    self.l10n = L10n::new(locale);
                    l10n::save_user_locale(&self.username, locale);
                }
                let task = self.current_screen.update(screen_msg, &self.l10n);
                task.map(Message::ScreenMessage)
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        self.current_screen.view().map(Message::ScreenMessage)
    }

    pub fn theme(&self) -> Theme {
        Theme::Light // Use Light theme so QR codes are black-on-white (required for scanning)
    }

    pub(crate) fn title(&self) -> String {
        self.l10n.tr("app-title")
    }
}
