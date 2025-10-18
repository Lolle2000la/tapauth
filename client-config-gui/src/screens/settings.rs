use super::ScreenMessage;
use iced::{
    widget::{button, column, container, text, Space},
    Task, Element, Length,
};
use shared::config::ClientConfigManager;

#[derive(Debug, Clone)]
pub struct SettingsScreen {
    rotating_csk: bool,
    error: Option<String>,
}

impl SettingsScreen {
    pub fn new() -> Self {
        Self {
            rotating_csk: false,
            error: None,
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::RotateCSK => {
                self.rotating_csk = true;
                Task::perform(
                    Self::rotate_csk(),
                    |result| match result {
                        Ok(_) => ScreenMessage::CSKRotated,
                        Err(e) => ScreenMessage::CSKRotationFailed(e),
                    }
                )
            }
            ScreenMessage::CSKRotated => {
                self.rotating_csk = false;
                self.error = None;
                Task::none()
            }
            ScreenMessage::CSKRotationFailed(error) => {
                self.rotating_csk = false;
                self.error = Some(error);
                Task::none()
            }
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let back_button = button(text("← Back").size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        let title = text("Settings").size(32);

        let rotate_button = if self.rotating_csk {
            button(text("Rotating...").size(16))
                .padding(15)
                .width(Length::Fixed(300.0))
        } else {
            button(text("Rotate Client Symmetric Key").size(16))
                .padding(15)
                .width(Length::Fixed(300.0))
                .on_press(ScreenMessage::RotateCSK)
        };

        let warning = text(
            "Warning: Rotating CSK will invalidate all paired devices.\nYou will need to re-pair them.",
        )
        .size(12);

        let error_text = if let Some(ref error) = self.error {
            text(format!("Error: {}", error)).size(14)
        } else {
            text("").size(14)
        };

        let content = column![
            back_button,
            Space::with_height(Length::Fixed(20.0)),
            title,
            Space::with_height(Length::Fixed(40.0)),
            text("Security").size(24),
            Space::with_height(Length::Fixed(20.0)),
            rotate_button,
            Space::with_height(Length::Fixed(10.0)),
            warning,
            Space::with_height(Length::Fixed(20.0)),
            error_text,
        ]
        .padding(20)
        .spacing(10)
        .width(Length::Fill)
        .align_x(iced::Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    async fn rotate_csk() -> Result<(), String> {
        let config = ClientConfigManager::new();

        config.rotate_csk()
            .map(|_| ()) // Discard the returned CSK, we just need success
            .map_err(|e| format!("Failed to rotate CSK: {}", e))
    }
}
