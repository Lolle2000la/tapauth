use super::ScreenMessage;
use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Task, Element, Length,
};
use shared::config::{ClientConfigManager, PairedServer};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DeviceListScreen {
    devices: HashMap<String, PairedServer>,
    loading: bool,
    error: Option<String>,
}

impl DeviceListScreen {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            loading: true,
            error: None,
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::NavigateToDeviceList => {
                // Load devices when navigating to this screen
                Task::perform(
                    Self::load_devices(),
                    |result| match result {
                        Ok(_devices) => ScreenMessage::NavigateToDeviceList,
                        Err(e) => ScreenMessage::PairingFailed(e),
                    }
                )
            }
            ScreenMessage::RemoveDevice(ref device_id) => {
                let id = device_id.clone();
                Task::perform(
                    Self::remove_device(id),
                    |result| match result {
                        Ok(_) => ScreenMessage::NavigateToDeviceList, // Reload list after removal
                        Err(e) => ScreenMessage::PairingFailed(e),
                    }
                )
            }
            ScreenMessage::DeviceRemoved(device_id) => {
                self.devices.remove(&device_id);
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

        let device_list = if self.devices.is_empty() {
            column![text("No paired devices").size(16)]
                .align_x(iced::Alignment::Center)
        } else {
            let mut devices_column = column![].spacing(10);
            
            for (device_id, server) in &self.devices {
                let device_row = row![
                    text(&server.name).size(18).width(Length::Fill),
                    text(device_id).size(12),
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
            Space::with_height(Length::Fixed(30.0)),
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
        let config = ClientConfigManager::new();

        config.load_paired_servers()
            .map_err(|e| format!("Failed to load paired devices: {}", e))
    }

    async fn remove_device(device_id: String) -> Result<(), String> {
        let config = ClientConfigManager::new();
        
        let mut servers = config.load_paired_servers()
            .map_err(|e| format!("Failed to load devices: {}", e))?;
        
        servers.remove(&device_id);
        
        config.save_paired_servers(&servers)
            .map_err(|e| format!("Failed to save devices: {}", e))
    }
}
