use super::ScreenMessage;
use crate::l10n::L10n;
use iced::{
    widget::{button, column, container, pick_list, row, scrollable, text, text_input, Space},
    Element, Font, Length, Task,
};
use shared::config::{ClientConfig, TapAuthConfig};
use std::sync::LazyLock;

mod locales_list {
    include!(concat!(env!("OUT_DIR"), "/locales_list.rs"));
}

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
    locales_list::AVAILABLE_LOCALES
        .iter()
        .map(|&code| LocaleOption {
            code,
            display: locale_display_name(code),
        })
        .collect()
}

fn locale_display_name(code: &str) -> &'static str {
    match code {
        "de" => "Deutsch",
        "ja" => "日本語",
        _ => "English",
    }
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
}

impl SettingsScreen {
    pub fn new(l10n: L10n) -> Self {
        let client_config = ClientConfig::default();
        let toml_config = TapAuthConfig::load();

        Self {
            l10n,
            rotating_csk: false,
            error: None,
            success: None,
            hostname_input: client_config.hostname.clone(),
            udp_port_input: toml_config.udp_port.to_string(),
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
                self.error = Some(error);
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
            ScreenMessage::SaveConfig => {
                self.error = None;
                self.success = None;
                let hostname = self.hostname_input.clone();
                let udp_port = self.udp_port_input.parse::<u16>().unwrap_or(36692);
                Task::perform(
                    crate::ipc::save_config(hostname, udp_port),
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
                self.error = Some(error);
                self.success = None;
                Task::none()
            }
            ScreenMessage::LocaleChanged(_locale) => Task::none(),
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

    async fn rotate_csk() -> Result<(), String> {
        crate::ipc::rotate_csk().await
    }
}
