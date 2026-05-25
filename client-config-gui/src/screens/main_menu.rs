use super::ScreenMessage;
use crate::l10n::L10n;
use iced::{
    widget::{button, column, container, text, Space},
    Element, Length, Task,
};

#[cfg(feature = "tpm")]
use iced::Font;

#[derive(Debug, Clone)]
pub struct MainMenuScreen {
    pub l10n: L10n,
    #[cfg(feature = "tpm")]
    tpm_error: Option<String>,
    #[cfg(feature = "tpm")]
    recovery_status: Option<String>,
}

impl MainMenuScreen {
    #[cfg(feature = "tpm")]
    pub fn new(l10n: L10n) -> Self {
        Self {
            l10n,
            tpm_error: None,
            recovery_status: None,
        }
    }

    #[cfg(not(feature = "tpm"))]
    pub fn new(l10n: L10n) -> Self {
        Self { l10n }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::StartPairing => Task::done(ScreenMessage::NavigateToPairing),
            ScreenMessage::ViewDevices => Task::done(ScreenMessage::NavigateToDeviceList),
            ScreenMessage::OpenSettings => Task::done(ScreenMessage::NavigateToSettings),
            #[cfg(feature = "tpm")]
            ScreenMessage::RecoverFromTPMFailure => {
                self.recovery_status = Some(self.l10n.tr("label-recovering"));
                Task::perform(Self::perform_tpm_recovery(), |result| match result {
                    Ok(_) => ScreenMessage::TPMRecoveryComplete,
                    Err(e) => ScreenMessage::TPMRecoveryFailed(e),
                })
            }
            #[cfg(feature = "tpm")]
            ScreenMessage::TPMRecoveryComplete => {
                self.tpm_error = None;
                self.recovery_status = Some(self.l10n.tr("label-recovery-success"));
                Task::none()
            }
            #[cfg(feature = "tpm")]
            ScreenMessage::TPMRecoveryFailed(error) => {
                self.recovery_status = Some(
                    self.l10n
                        .tr_args("label-recovery-failed", &[("error", &error)]),
                );
                Task::none()
            }
            _ => Task::none(),
        }
    }

    #[cfg(feature = "tpm")]
    async fn perform_tpm_recovery() -> Result<(), String> {
        crate::ipc::recover_tpm().await
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let title = text(self.l10n.tr("title-main-menu"))
            .size(40)
            .width(Length::Fill)
            .center();

        let mut content_widgets = vec![
            Space::new().height(Length::Fixed(50.0)).into(),
            title.into(),
        ];

        #[cfg(feature = "tpm")]
        if let Some(ref error) = self.tpm_error {
            let error_display = self.l10n.tr_args("label-tpm-error", &[("error", error)]);
            let error_text = iced::widget::row![
                container(
                    text(char::from(lucide_icons::Icon::AlertTriangle))
                        .font(Font::with_name("lucide"))
                        .size(18)
                        .color(iced::Color::from_rgb(0.9, 0.2, 0.2)),
                )
                .padding(iced::Padding::ZERO.top(3)),
                text(error_display)
                    .size(16)
                    .style(|_theme| iced::widget::text::Style {
                        color: Some(iced::Color::from_rgb(0.9, 0.2, 0.2)),
                    })
                    .width(Length::Fixed(480.0)),
            ]
            .align_y(iced::Alignment::Center)
            .spacing(5);

            let recover_button = button(
                text(self.l10n.tr("btn-recover-keys"))
                    .size(18)
                    .center()
                    .width(Length::Fill),
            )
            .padding(15)
            .width(Length::Fixed(300.0))
            .on_press(ScreenMessage::RecoverFromTPMFailure);

            content_widgets.push(Space::new().height(Length::Fixed(30.0)).into());
            content_widgets.push(error_text.into());
            content_widgets.push(Space::new().height(Length::Fixed(15.0)).into());
            content_widgets.push(recover_button.into());
        }

        #[cfg(feature = "tpm")]
        if let Some(ref status) = self.recovery_status {
            let status_text = text(status).size(14).width(Length::Fixed(500.0));
            content_widgets.push(Space::new().height(Length::Fixed(15.0)).into());
            content_widgets.push(status_text.into());
        }

        #[cfg(feature = "tpm")]
        let tpm_error_present = self.tpm_error.is_some();
        #[cfg(not(feature = "tpm"))]
        let tpm_error_present = false;

        content_widgets.push(
            Space::new()
                .height(Length::Fixed(if tpm_error_present { 40.0 } else { 80.0 }))
                .into(),
        );

        let pair_button = button(
            text(self.l10n.tr("btn-pair-new-device"))
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .padding(20)
        .width(Length::Fixed(300.0))
        .on_press(ScreenMessage::StartPairing);

        let devices_button = button(
            text(self.l10n.tr("btn-manage-devices"))
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .padding(20)
        .width(Length::Fixed(300.0))
        .on_press(ScreenMessage::ViewDevices);

        let settings_button = button(
            text(self.l10n.tr("btn-settings"))
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .padding(20)
        .width(Length::Fixed(300.0))
        .on_press(ScreenMessage::OpenSettings);

        content_widgets.push(pair_button.into());
        content_widgets.push(Space::new().height(Length::Fixed(20.0)).into());
        content_widgets.push(devices_button.into());
        content_widgets.push(Space::new().height(Length::Fixed(20.0)).into());
        content_widgets.push(settings_button.into());

        let content = column(content_widgets)
            .width(Length::Fill)
            .align_x(iced::Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}
