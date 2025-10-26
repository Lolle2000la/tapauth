use super::ScreenMessage;
use crate::utils::elevation;
use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Element, Length, Task,
};
use shared::config::{ClientConfigManager, PairedServer};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DeviceListScreen {
    devices: HashMap<String, PairedServer>,
    current_username: String,
    loading: bool,
    error: Option<String>,
}

impl DeviceListScreen {
    pub fn new() -> (Self, Task<ScreenMessage>) {
        tracing::debug!("Creating new DeviceListScreen and starting load task");

        // Get original username (before any privilege escalation)
        let current_username = elevation::get_username();

        tracing::info!("Device list for user: {}", current_username);

        let screen = Self {
            devices: HashMap::new(),
            current_username,
            loading: true,
            error: None,
        };

        let task = Task::perform(Self::load_devices(), |result| match result {
            Ok(devices) => ScreenMessage::DevicesLoaded(devices),
            Err(e) => ScreenMessage::PairingFailed(e),
        });

        (screen, task)
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::NavigateToDeviceList => {
                tracing::debug!("NavigateToDeviceList message received");
                // Load devices when navigating to this screen
                self.loading = true;
                Task::perform(Self::load_devices(), |result| match result {
                    Ok(devices) => ScreenMessage::DevicesLoaded(devices),
                    Err(e) => ScreenMessage::PairingFailed(e),
                })
            }
            ScreenMessage::DevicesLoaded(devices) => {
                tracing::debug!(
                    "DevicesLoaded message received with {} devices",
                    devices.len()
                );
                self.devices = devices;
                self.loading = false;
                tracing::debug!("State updated, now have {} devices", self.devices.len());
                Task::none()
            }
            ScreenMessage::RemoveDevice(device_id) => {
                let username = self.current_username.clone();
                self.devices.remove(&device_id);
                Task::perform(
                    Self::remove_device_for_user(device_id, username),
                    |result| match result {
                        Ok(_) => ScreenMessage::NavigateToDeviceList,
                        Err(e) => ScreenMessage::PairingFailed(e),
                    },
                )
            }
            ScreenMessage::DeviceRemoved(_device_id) => {
                // Already removed from self.devices in RemoveDevice
                Task::none()
            }
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let back_button = button(text("← Back").size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        let title = text("Paired Devices").size(32);

        let username_info = text(format!("Current user: {}", self.current_username))
            .size(14)
            .color(iced::Color::from_rgb(0.5, 0.5, 0.5));

        // Filter devices to only show those that include current user
        let user_devices: HashMap<_, _> = self
            .devices
            .iter()
            .filter(|(_, server)| server.allowed_users.contains(&self.current_username))
            .collect();

        let device_list = if user_devices.is_empty() {
            column![text("No paired devices for current user").size(16)]
                .align_x(iced::Alignment::Center)
        } else {
            let mut devices_column = column![].spacing(10);

            for (device_id, server) in user_devices {
                let user_count = server.allowed_users.len();
                let user_info = if user_count > 1 {
                    format!(
                        " (shared with {} other user{})",
                        user_count - 1,
                        if user_count - 1 == 1 { "" } else { "s" }
                    )
                } else {
                    String::new()
                };

                let device_row = row![
                    column![
                        text(&server.name).size(18),
                        text(format!(
                            "ID: {}...{}",
                            &device_id[..8],
                            if device_id.len() > 8 { "..." } else { "" }
                        ))
                        .size(12)
                        .color(iced::Color::from_rgb(0.6, 0.6, 0.6)),
                        text(format!(
                            "Users: {}{}",
                            server.allowed_users.join(", "),
                            user_info
                        ))
                        .size(12)
                        .color(iced::Color::from_rgb(0.5, 0.5, 0.7)),
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    button(text("Remove").size(14))
                        .padding(8)
                        .on_press(ScreenMessage::RemoveDevice(device_id.clone())),
                ]
                .spacing(10)
                .padding(15)
                .width(Length::Fill);

                devices_column = devices_column.push(device_row);
            }

            devices_column
        };

        let content = column![
            back_button,
            Space::with_height(Length::Fixed(20.0)),
            title,
            Space::with_height(Length::Fixed(10.0)),
            username_info,
            Space::with_height(Length::Fixed(20.0)),
            scrollable(device_list),
        ]
        .padding(20)
        .spacing(10)
        .width(Length::Fill)
        .height(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    async fn load_devices() -> Result<HashMap<String, PairedServer>, String> {
        tracing::debug!("load_devices() called");
        let config = ClientConfigManager::new();

        let result = config
            .load_paired_servers()
            .map_err(|e| format!("Failed to load paired devices: {}", e));

        match &result {
            Ok(devices) => tracing::debug!("Loaded {} devices", devices.len()),
            Err(e) => tracing::error!("Error loading devices: {}", e),
        }

        result
    }

    async fn remove_device_for_user(device_id: String, username: String) -> Result<(), String> {
        let config = ClientConfigManager::new();

        let entire_pairing_removed = config
            .remove_user_from_pairing(&device_id, &username)
            .map_err(|e| format!("Failed to remove pairing: {}", e))?;

        if entire_pairing_removed {
            tracing::info!("Removed entire pairing for device {}", device_id);
        } else {
            tracing::info!(
                "Removed user {} from device {}, other users remain",
                username,
                device_id
            );
        }

        Ok(())
    }
}
