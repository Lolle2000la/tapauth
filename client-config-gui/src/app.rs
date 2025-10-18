use crate::screens::{Screen, ScreenMessage};
use iced::{Element, Task, Theme};

/// Main application state
pub struct TapAuthConfig {
    current_screen: Screen,
}

#[derive(Debug, Clone)]
pub enum Message {
    ScreenMessage(ScreenMessage),
}

impl TapAuthConfig {
    pub fn new() -> (Self, Task<Message>) {
        (
            Self {
                current_screen: Screen::default(),
            },
            Task::none(),
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScreenMessage(screen_msg) => {
                let task = self.current_screen.update(screen_msg);
                task.map(Message::ScreenMessage)
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        self.current_screen.view().map(Message::ScreenMessage)
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }
}
