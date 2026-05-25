use super::ScreenMessage;
use crate::l10n::L10n;
use crate::utils::elevation;
use iced::{
    widget::{button, column, container, row, scrollable, text, Space},
    Element, Font, Length, Task,
};
use shared::config::PairedServer;
use shared::ipc::pb::PairedServerInfo;
use std::collections::HashMap;

fn convert_to_paired_server(info: &PairedServerInfo) -> (String, PairedServer) {
    let paired_at = chrono::Utc::now();
    let server = PairedServer {
        name: info.name.clone(),
        public_key: info.public_key.clone(),
        allowed_users: info.allowed_users.clone(),
        paired_at,
    };
    (info.public_key.clone(), server)
}

#[derive(Debug, Clone)]
pub struct DeviceListScreen {
    pub l10n: L10n,
    devices: HashMap<String, PairedServer>,
    current_username: String,
    loading: bool,
}

impl DeviceListScreen {
    pub fn new(l10n: L10n) -> (Self, Task<ScreenMessage>) {
        tracing::debug!("Creating new DeviceListScreen and starting load task");

        let current_username = elevation::get_username();

        tracing::info!("Device list for user: {}", current_username);

        let screen = Self {
            l10n,
            devices: HashMap::new(),
            current_username,
            loading: true,
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
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let back_button = button(
            row![
                container(
                    text(char::from(lucide_icons::Icon::ArrowLeft))
                        .font(Font::with_name("lucide"))
                        .size(16)
                )
                .padding(iced::Padding::ZERO.top(2)),
                text(self.l10n.tr("btn-back")).size(16),
            ]
            .align_y(iced::Alignment::Center)
            .spacing(5),
        )
        .padding(10)
        .on_press(ScreenMessage::NavigateToMainMenu);

        let title = text(self.l10n.tr("title-paired-devices")).size(32);

        let username_info = text(self.l10n.tr_args(
            "devices-current-user",
            &[("username", &self.current_username)],
        ))
        .size(14)
        .color(iced::Color::from_rgb(0.5, 0.5, 0.5));

        let user_devices: HashMap<_, _> = self
            .devices
            .iter()
            .filter(|(_, server)| server.allowed_users.contains(&self.current_username))
            .collect();

        let device_list = if user_devices.is_empty() {
            column![text(self.l10n.tr("devices-none-for-user")).size(16)]
                .align_x(iced::Alignment::Center)
        } else {
            let mut devices_column = column![].spacing(10);

            for (device_id, server) in user_devices {
                let user_count = server.allowed_users.len();
                let user_info = if user_count > 1 {
                    self.l10n.tr_args(
                        "devices-shared-info",
                        &[
                            ("count", &(user_count - 1).to_string()),
                            ("s", if user_count - 1 == 1 { "" } else { "s" }),
                        ],
                    )
                } else {
                    String::new()
                };

                let device_row = row![
                    column![
                        text(&server.name).size(18),
                        text(self.l10n.tr_args(
                            "devices-id-truncated",
                            &[
                                ("prefix", &device_id[..device_id.len().min(8)]),
                                ("suffix", if device_id.len() > 8 { "..." } else { "" }),
                            ],
                        ))
                        .size(12)
                        .color(iced::Color::from_rgb(0.6, 0.6, 0.6)),
                        text(self.l10n.tr_args(
                            "devices-users-list",
                            &[
                                ("users", &server.allowed_users.join(", ")),
                                ("info", &user_info),
                            ],
                        ))
                        .size(12)
                        .color(iced::Color::from_rgb(0.5, 0.5, 0.7)),
                    ]
                    .spacing(4)
                    .width(Length::Fill),
                    button(text(self.l10n.tr("btn-remove")).size(14))
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
            Space::new().height(Length::Fixed(20.0)),
            title,
            Space::new().height(Length::Fixed(10.0)),
            username_info,
            Space::new().height(Length::Fixed(20.0)),
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
        tracing::debug!("load_devices() called via IPC");
        let servers = crate::ipc::get_paired_servers().await?;
        let devices: HashMap<String, PairedServer> =
            servers.iter().map(convert_to_paired_server).collect();
        tracing::debug!("Loaded {} devices", devices.len());
        Ok(devices)
    }

    async fn remove_device_for_user(device_id: String, _username: String) -> Result<(), String> {
        crate::ipc::remove_device(device_id).await
    }
}
