use super::ScreenMessage;
use iced::{
    widget::{button, column, container, row, scrollable, text, text_input, Space},
    Element, Length, Task,
};
use shared::config::{ClientConfig, ClientConfigManager, TapAuthConfig, DEFAULT_CONFIG_PATH};

#[derive(Debug, Clone)]
pub struct SettingsScreen {
    rotating_csk: bool,
    error: Option<String>,
    success: Option<String>,
    client_config: ClientConfig,
    toml_config: TapAuthConfig,
    hostname_input: String,
    udp_port_input: String,
}

impl SettingsScreen {
    pub fn new() -> Self {
        let config_manager = ClientConfigManager::new();
        let client_config = config_manager.load_config().unwrap_or_default();
        let toml_config = TapAuthConfig::load();

        Self {
            rotating_csk: false,
            error: None,
            success: None,
            hostname_input: client_config.hostname.clone(),
            udp_port_input: toml_config.udp_port.to_string(),
            client_config,
            toml_config,
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
                self.client_config.hostname = hostname;
                Task::none()
            }
            ScreenMessage::UdpPortChanged(port_str) => {
                self.udp_port_input = port_str.clone();
                if let Ok(port) = port_str.parse::<u16>() {
                    self.toml_config.udp_port = port;
                }
                Task::none()
            }
            ScreenMessage::SaveConfig => {
                self.error = None;
                self.success = None;
                let client_config = self.client_config.clone();
                let toml_config = self.toml_config.clone();
                Task::perform(
                    Self::save_config(client_config, toml_config),
                    |result| match result {
                        Ok(_) => ScreenMessage::ConfigSaved,
                        Err(e) => ScreenMessage::ConfigSaveFailed(e),
                    },
                )
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
        let back_button = button(
            row![
                container(lucide_icons::iced::icon_arrow_left().size(16))
                    .padding(iced::Padding::ZERO.top(2)),
                text("Back").size(16),
            ]
                .align_y(iced::Alignment::Center)
                .spacing(5),
        )
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        let title = text("Settings").size(32);

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

    async fn save_config(
        client_config: ClientConfig,
        toml_config: TapAuthConfig,
    ) -> Result<(), String> {
        let config_manager = ClientConfigManager::new();

        // Save client state config (hostname)
        config_manager
            .save_config(&client_config)
            .map_err(|e| format!("Failed to save client configuration: {}", e))?;

        // Save TOML config (UDP port, TPM, etc.)
        toml_config
            .save_to_path(DEFAULT_CONFIG_PATH)
            .map_err(|e| format!("Failed to save TOML configuration: {}", e))?;

        // Restart service to apply changes
        crate::utils::service::restart_tapauthd_service().await?;

        Ok(())
    }

    async fn rotate_csk() -> Result<(), String> {
        let config = ClientConfigManager::new();

        config
            .rotate_csk()
            .map_err(|e| format!("Failed to rotate CSK: {}", e))?;

        // Restart service to apply changes
        crate::utils::service::restart_tapauthd_service().await?;

        Ok(())
    }
}
