use crate::l10n::L10n;
use crate::screens::{Screen, ScreenMessage};
use iced::{Element, Task, Theme};

/// Main application state
pub struct TapAuthConfig {
    l10n: L10n,
    current_screen: Screen,
}

#[derive(Debug, Clone)]
pub enum Message {
    ScreenMessage(ScreenMessage),
}

impl TapAuthConfig {
    pub fn new(locale: &str) -> (Self, Task<Message>) {
        let l10n = L10n::new(locale);
        (
            Self {
                l10n: l10n.clone(),
                current_screen: Screen::default_with_l10n(l10n),
            },
            Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScreenMessage(screen_msg) => {
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
}
