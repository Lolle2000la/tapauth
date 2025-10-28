use super::ScreenMessage;
use iced::{
    widget::{button, column, container, scrollable, text, text_input, Space},
    Element, Length, Task,
};
use shared::config::{ClientConfig, ClientConfigManager};

#[derive(Debug, Clone)]
pub struct SettingsScreen {
    rotating_csk: bool,
    error: Option<String>,
    success: Option<String>,
    config: ClientConfig,
    hostname_input: String,
    udp_port_input: String,
}

impl SettingsScreen {
    pub fn new() -> Self {
        let config_manager = ClientConfigManager::new();
        let config = config_manager.load_config().unwrap_or_default();

        Self {
            rotating_csk: false,
            error: None,
            success: None,
            hostname_input: config.hostname.clone(),
            udp_port_input: config.udp_port.to_string(),
            config,
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::RotateCSK => {
                self.rotating_csk = true;
                self.error = None;
                self.success = None;
                Task::perform(Self::rotate_csk(), |result| match result {
                    Ok(_) => ScreenMessage::CSKRotated,
                    Err(e) => ScreenMessage::CSKRotationFailed(e),
                })
            }
            ScreenMessage::CSKRotated => {
                self.rotating_csk = false;
                self.error = None;
                self.success =
                    Some("CSK rotated successfully. All pairings have been cleared.".to_string());
                Task::none()
            }
            ScreenMessage::CSKRotationFailed(error) => {
                self.rotating_csk = false;
                self.error = Some(error);
                self.success = None;
                Task::none()
            }
            ScreenMessage::HostnameChanged(hostname) => {
                self.hostname_input = hostname.clone();
                self.config.hostname = hostname;
                Task::none()
            }
            ScreenMessage::UdpPortChanged(port_str) => {
                self.udp_port_input = port_str.clone();
                if let Ok(port) = port_str.parse::<u16>() {
                    self.config.udp_port = port;
                }
                Task::none()
            }
            ScreenMessage::SaveConfig => {
                self.error = None;
                self.success = None;
                let config = self.config.clone();
                Task::perform(Self::save_config(config), |result| match result {
                    Ok(_) => ScreenMessage::ConfigSaved,
                    Err(e) => ScreenMessage::ConfigSaveFailed(e),
                })
            }
            ScreenMessage::ConfigSaved => {
                self.error = None;
                self.success = Some("Configuration saved successfully.".to_string());
                Task::none()
            }
            ScreenMessage::ConfigSaveFailed(error) => {
                self.error = Some(error);
                self.success = None;
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

        // Configuration section
        let config_title = text("Configuration").size(24);

        let hostname_label = text("Hostname:").size(16);
        let hostname_input = text_input("Enter hostname", &self.hostname_input)
            .on_input(ScreenMessage::HostnameChanged)
            .padding(10)
            .width(Length::Fixed(400.0));

        let udp_port_label = text("UDP Port:").size(16);
        let udp_port_input = text_input("Enter UDP port (default: 36692)", &self.udp_port_input)
            .on_input(ScreenMessage::UdpPortChanged)
            .padding(10)
            .width(Length::Fixed(400.0));

        let save_button = button(text("Save Configuration").size(16))
            .padding(15)
            .width(Length::Fixed(400.0))
            .on_press(ScreenMessage::SaveConfig);

        // Security section
        let security_title = text("Security").size(24);

        let rotate_button = if self.rotating_csk {
            button(text("Rotating...").size(16))
                .padding(15)
                .width(Length::Fixed(400.0))
        } else {
            button(text("Rotate Client Symmetric Key").size(16))
                .padding(15)
                .width(Length::Fixed(400.0))
                .on_press(ScreenMessage::RotateCSK)
        };

        let warning = text(
            "Warning: Rotating CSK will invalidate all paired devices.\nYou will need to re-pair them.",
        )
        .size(12);

        // Status messages
        let status_text = if let Some(ref error) = self.error {
            text(format!("Error: {}", error)).size(14)
        } else if let Some(ref success) = self.success {
            text(success).size(14)
        } else {
            text("").size(14)
        };

        let scrollable_content = column![
            config_title,
            Space::with_height(Length::Fixed(20.0)),
            hostname_label,
            hostname_input,
            Space::with_height(Length::Fixed(15.0)),
            udp_port_label,
            udp_port_input,
            Space::with_height(Length::Fixed(20.0)),
            save_button,
            Space::with_height(Length::Fixed(40.0)),
            security_title,
            Space::with_height(Length::Fixed(20.0)),
            rotate_button,
            Space::with_height(Length::Fixed(10.0)),
            warning,
            Space::with_height(Length::Fixed(20.0)),
            status_text,
        ]
        .spacing(10)
        .width(Length::Fill)
        .align_x(iced::Alignment::Center);

        let content = column![
            back_button,
            Space::with_height(Length::Fixed(20.0)),
            title,
            Space::with_height(Length::Fixed(20.0)),
            scrollable(scrollable_content),
        ]
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    async fn save_config(config: ClientConfig) -> Result<(), String> {
        let config_manager = ClientConfigManager::new();

        config_manager
            .save_config(&config)
            .map_err(|e| format!("Failed to save configuration: {}", e))
    }

    async fn rotate_csk() -> Result<(), String> {
        let config = ClientConfigManager::new();

        config
            .rotate_csk()
            .map(|_| ()) // Discard the returned CSK, we just need success
            .map_err(|e| format!("Failed to rotate CSK: {}", e))
    }
}
