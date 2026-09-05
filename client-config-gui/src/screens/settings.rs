use super::ScreenMessage;
use crate::ipc::GuiIpcError;
use crate::l10n::{self, L10n};
use iced::{
    widget::{
        button, checkbox, column, container, pick_list, row, scrollable, text, text_input, Space,
    },
    Element, Font, Length, Task,
};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocaleOption {
    code: &'static str,
    display: &'static str,
}

impl std::fmt::Display for LocaleOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display)
    }
}

fn locale_options() -> Vec<LocaleOption> {
    l10n::AVAILABLE_LOCALES
        .iter()
        .map(|&code| LocaleOption {
            code,
            display: l10n::locale_display_name(code),
        })
        .collect()
}

static LOCALE_OPTIONS: LazyLock<Vec<LocaleOption>> = LazyLock::new(locale_options);

#[derive(Debug, Clone)]
pub struct SettingsScreen {
    pub l10n: L10n,
    rotating_csk: bool,
    error: Option<String>,
    success: Option<String>,
    hostname_input: String,
    udp_port_input: String,
    ble_enabled: bool,
    network_enabled: bool,
    fprintd_bridge_enabled: bool,
}

impl SettingsScreen {
    pub fn new(l10n: L10n) -> Self {
        Self {
            l10n,
            rotating_csk: false,
            error: None,
            success: None,
            hostname_input: String::new(),
            udp_port_input: String::new(),
            ble_enabled: true,
            network_enabled: true,
            fprintd_bridge_enabled: true,
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
                self.success = Some(self.l10n.tr("settings-csk-rotated"));
                Task::none()
            }
            ScreenMessage::CSKRotationFailed(error) => {
                self.rotating_csk = false;
                self.error = Some(error.localized(&self.l10n));
                self.success = None;
                Task::none()
            }
            ScreenMessage::HostnameChanged(hostname) => {
                self.hostname_input = hostname.clone();
                Task::none()
            }
            ScreenMessage::UdpPortChanged(port_str) => {
                self.udp_port_input = port_str.clone();
                Task::none()
            }
            ScreenMessage::BleEnabledChanged(enabled) => {
                self.ble_enabled = enabled;
                Task::none()
            }
            ScreenMessage::NetworkEnabledChanged(enabled) => {
                self.network_enabled = enabled;
                Task::none()
            }
            ScreenMessage::FprintdBridgeEnabledChanged(enabled) => {
                self.fprintd_bridge_enabled = enabled;
                Task::none()
            }
            ScreenMessage::SaveConfig => {
                self.error = None;
                self.success = None;
                let hostname = self.hostname_input.clone();
                let udp_port = match self.udp_port_input.parse::<u16>() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        self.error = Some(self.l10n.tr("settings-invalid-port"));
                        return Task::none();
                    }
                };
                let ble_enabled = self.ble_enabled;
                let network_enabled = self.network_enabled;
                let fprintd_bridge_enabled = self.fprintd_bridge_enabled;
                Task::perform(
                    crate::ipc::save_config(
                        hostname,
                        udp_port,
                        ble_enabled,
                        network_enabled,
                        fprintd_bridge_enabled,
                    ),
                    |result| match result {
                        Ok(_) => ScreenMessage::ConfigSaved,
                        Err(e) => ScreenMessage::ConfigSaveFailed(e),
                    },
                )
            }
            ScreenMessage::ConfigSaved => {
                self.error = None;
                self.success = Some(self.l10n.tr("settings-config-saved"));
                Task::none()
            }
            ScreenMessage::ConfigSaveFailed(error) => {
                self.error = Some(error.localized(&self.l10n));
                self.success = None;
                Task::none()
            }
            ScreenMessage::ConfigLoaded(config) => {
                self.hostname_input = config.hostname;
                self.udp_port_input = config.udp_port.to_string();
                self.ble_enabled = config.enable_ble;
                self.network_enabled = config.enable_network;
                self.fprintd_bridge_enabled = config.enable_fprintd_bridge;
                Task::none()
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

        let title = text(self.l10n.tr("title-settings")).size(32);
        let config_title = text(self.l10n.tr("settings-config-section")).size(24);

        let hostname_label = text(self.l10n.tr("settings-hostname-label")).size(16);
        let hostname_input = text_input(
            &self.l10n.tr("settings-hostname-placeholder"),
            &self.hostname_input,
        )
        .on_input(ScreenMessage::HostnameChanged)
        .padding(10)
        .width(Length::Fixed(400.0));

        let udp_port_label = text(self.l10n.tr("settings-udp-port-label")).size(16);
        let udp_port_input = text_input(
            &self.l10n.tr("settings-udp-port-placeholder"),
            &self.udp_port_input,
        )
        .on_input(ScreenMessage::UdpPortChanged)
        .padding(10)
        .width(Length::Fixed(400.0));

        let connectivity_title = text(self.l10n.tr("settings-connectivity-section")).size(18);

        let network_checkbox = checkbox(self.network_enabled)
            .label(self.l10n.tr("settings-enable-network"))
            .on_toggle(ScreenMessage::NetworkEnabledChanged)
            .size(20)
            .text_size(16)
            .width(Length::Fixed(400.0));

        let ble_checkbox = checkbox(self.ble_enabled)
            .label(self.l10n.tr("settings-enable-ble"))
            .on_toggle(ScreenMessage::BleEnabledChanged)
            .size(20)
            .text_size(16)
            .width(Length::Fixed(400.0));

        let fprintd_checkbox = checkbox(self.fprintd_bridge_enabled)
            .label(self.l10n.tr("settings-enable-fprintd-bridge"))
            .on_toggle(ScreenMessage::FprintdBridgeEnabledChanged)
            .size(20)
            .text_size(16)
            .width(Length::Fixed(400.0));

        let connectivity_note = text(self.l10n.tr("settings-connectivity-note")).size(12);

        let save_button = button(text(self.l10n.tr("btn-save-config")).size(16))
            .padding(15)
            .width(Length::Fixed(400.0))
            .on_press(ScreenMessage::SaveConfig);

        let security_title = text(self.l10n.tr("settings-security-section")).size(24);

        let rotate_button = if self.rotating_csk {
            button(text(self.l10n.tr("label-rotating")).size(16))
                .padding(15)
                .width(Length::Fixed(400.0))
        } else {
            button(text(self.l10n.tr("btn-rotate-csk")).size(16))
                .padding(15)
                .width(Length::Fixed(400.0))
                .on_press(ScreenMessage::RotateCSK)
        };

        let warning = text(self.l10n.tr("settings-csk-warning")).size(12);

        let lang_title = text(self.l10n.tr("settings-language-section")).size(24);
        let current_code = self.l10n.locale();
        let selected = LOCALE_OPTIONS.iter().find(|o| o.code == current_code);

        let lang_pick_list = pick_list(LOCALE_OPTIONS.as_slice(), selected, |opt: LocaleOption| {
            ScreenMessage::LocaleChanged(opt.code.to_string())
        })
        .width(Length::Fixed(300.0));

        let status_text = if let Some(ref error) = self.error {
            text(
                self.l10n
                    .tr_args("settings-error-prefix", &[("message", error)]),
            )
            .size(14)
        } else if let Some(ref success) = self.success {
            text(success).size(14)
        } else {
            text("").size(14)
        };

        let scrollable_content = column![
            config_title,
            Space::new().height(Length::Fixed(20.0)),
            hostname_label,
            hostname_input,
            Space::new().height(Length::Fixed(15.0)),
            udp_port_label,
            udp_port_input,
            Space::new().height(Length::Fixed(20.0)),
            connectivity_title,
            Space::new().height(Length::Fixed(10.0)),
            network_checkbox,
            ble_checkbox,
            fprintd_checkbox,
            Space::new().height(Length::Fixed(5.0)),
            connectivity_note,
            Space::new().height(Length::Fixed(20.0)),
            save_button,
            Space::new().height(Length::Fixed(40.0)),
            lang_title,
            Space::new().height(Length::Fixed(15.0)),
            lang_pick_list,
            Space::new().height(Length::Fixed(40.0)),
            security_title,
            Space::new().height(Length::Fixed(20.0)),
            rotate_button,
            Space::new().height(Length::Fixed(10.0)),
            warning,
            Space::new().height(Length::Fixed(20.0)),
            status_text,
        ]
        .spacing(10)
        .width(Length::Fill)
        .align_x(iced::Alignment::Center);

        let content = column![
            back_button,
            Space::new().height(Length::Fixed(20.0)),
            title,
            Space::new().height(Length::Fixed(20.0)),
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

    async fn rotate_csk() -> Result<(), GuiIpcError> {
        crate::ipc::rotate_csk().await
    }
}
