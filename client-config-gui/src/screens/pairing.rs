use super::ScreenMessage;
use crate::l10n::L10n;
use iced::widget::qr_code::Data as QrData;
use iced::{
    widget::{button, column, container, row, scrollable, text, QRCode, Space},
    Color, Element, Font, Length, Task,
};
use std::rc::Rc;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum PairingState {
    Loading,
    ShowingQRCode { url: String, qr_data: Rc<QrData> },
    VerifyingSAS { sas: String, port: u16 },
    CompletingPairing,
    Success { device_id: String },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub struct PairingScreen {
    pub l10n: L10n,
    state: PairingState,
    cancel_wait: Option<Arc<tokio::sync::Notify>>,
}

impl PairingScreen {
    pub fn new(l10n: L10n) -> Self {
        Self {
            l10n,
            state: PairingState::Loading,
            cancel_wait: None,
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::PairingStarted => {
                self.state = PairingState::Loading;
                Task::perform(crate::ipc::start_pairing(), |result| match result {
                    Ok((url, _port)) => ScreenMessage::PairingComplete(url),
                    Err(e) => ScreenMessage::PairingFailed(e),
                })
            }
            ScreenMessage::PairingComplete(data) => {
                if data.starts_with("tapauth://") {
                    let qr_data = match QrData::new(&data) {
                        Ok(qr) => std::rc::Rc::new(qr),
                        Err(_) => {
                            return Task::done(ScreenMessage::PairingFailed(
                                "Failed to generate QR code".to_string(),
                            ));
                        }
                    };
                    self.state = PairingState::ShowingQRCode {
                        url: data.clone(),
                        qr_data,
                    };

                    if let Some(port_str) =
                        data.split("&p=").nth(1).and_then(|s| s.split('&').next())
                    {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let cancel = Arc::new(tokio::sync::Notify::new());
                            let cancel2 = cancel.clone();
                            self.cancel_wait = Some(cancel);

                            return Task::perform(
                                async move {
                                    tokio::select! {
                                        result = crate::ipc::wait_for_pairing(port as u32) => {
                                            match result {
                                                Ok((sas, port)) => ScreenMessage::PairingComplete(
                                                    format!("SAS:{}:{}", sas, port),
                                                ),
                                                Err(e) => ScreenMessage::PairingFailed(e),
                                            }
                                        }
                                        _ = cancel2.notified() => {
                                            ScreenMessage::PairingCancelled
                                        }
                                    }
                                },
                                |msg| msg,
                            );
                        }
                    }
                } else if data.starts_with("SAS:") {
                    self.cancel_wait = None;
                    let parts: Vec<&str> = data.splitn(3, ':').collect();
                    if parts.len() == 3 {
                        self.state = PairingState::VerifyingSAS {
                            sas: parts[1].to_string(),
                            port: parts[2].parse().unwrap_or(0),
                        };
                    }
                } else {
                    self.state = PairingState::Success { device_id: data };
                }
                Task::none()
            }
            ScreenMessage::PairingSASConfirmed => {
                if let PairingState::VerifyingSAS { port, .. } = &self.state {
                    let port = *port;
                    self.state = PairingState::CompletingPairing;
                    return Task::perform(
                        async move { crate::ipc::complete_pairing(port as u32).await },
                        |result| match result {
                            Ok(device_id) => ScreenMessage::PairingComplete(device_id),
                            Err(e) => ScreenMessage::PairingFailed(e),
                        },
                    );
                }
                Task::none()
            }
            ScreenMessage::PairingFailed(error) => {
                self.cancel_wait = None;
                self.state = PairingState::Error { message: error };
                Task::none()
            }
            ScreenMessage::PairingCancelled => {
                if let Some(cancel) = self.cancel_wait.take() {
                    cancel.notify_one();
                }
                Task::done(ScreenMessage::NavigateToMainMenu)
            }
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let content = match &self.state {
            PairingState::Loading => self.view_loading(),
            PairingState::ShowingQRCode { url, qr_data } => self.view_qr_code(url, qr_data),
            PairingState::VerifyingSAS { sas, .. } => self.view_sas_verification(sas),
            PairingState::CompletingPairing => self.view_completing(),
            PairingState::Success { device_id } => self.view_success(device_id),
            PairingState::Error { message } => self.view_error(message),
        };

        let centered_content = container(content)
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(40);

        container(scrollable(centered_content))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn view_loading(&self) -> Element<'_, ScreenMessage> {
        column![
            text(self.l10n.tr("pairing-preparing")).size(24),
            Space::new().height(Length::Fixed(20.0)),
            text(self.l10n.tr("label-please-wait")).size(16),
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_qr_code<'a>(
        &self,
        url: &'a str,
        qr_data: &'a Rc<QrData>,
    ) -> Element<'a, ScreenMessage> {
        let back_button = button(text(self.l10n.tr("btn-cancel")).size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text(self.l10n.tr("pairing-scan-qr")).size(24),
            Space::new().height(Length::Fixed(30.0)),
            container(QRCode::<iced::Theme>::new(qr_data.as_ref()).cell_size(4))
                .width(Length::Shrink)
                .height(Length::Shrink),
            Space::new().height(Length::Fixed(20.0)),
            text(self.l10n.tr("pairing-enter-manually")).size(14),
            text(url).size(10),
            Space::new().height(Length::Fixed(40.0)),
            back_button,
        ]
        .width(Length::Fill)
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_completing(&self) -> Element<'_, ScreenMessage> {
        column![
            text(self.l10n.tr("pairing-completing")).size(24),
            Space::new().height(Length::Fixed(20.0)),
            text(self.l10n.tr("label-please-wait")).size(16),
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_sas_verification<'a>(&self, sas: &'a str) -> Element<'a, ScreenMessage> {
        let confirm_button = button(text(self.l10n.tr("btn-confirm")).size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingSASConfirmed);

        let cancel_button = button(text(self.l10n.tr("btn-cancel")).size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text(self.l10n.tr("pairing-verify-sas-title")).size(24),
            Space::new().height(Length::Fixed(30.0)),
            text(self.l10n.tr("pairing-sas-ensure-match")).size(16),
            Space::new().height(Length::Fixed(20.0)),
            text(sas).size(48),
            Space::new().height(Length::Fixed(40.0)),
            confirm_button,
            Space::new().height(Length::Fixed(10.0)),
            cancel_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_success<'a>(&self, device_id: &'a str) -> Element<'a, ScreenMessage> {
        let done_button = button(text(self.l10n.tr("btn-done")).size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        column![
            row![
                container(
                    text(char::from(lucide_icons::Icon::Check))
                        .font(Font::with_name("lucide"))
                        .size(48)
                        .color(Color::from_rgb(0.0, 0.7, 0.0)),
                )
                .padding(iced::Padding::ZERO.top(8)),
                Space::new().width(Length::Fixed(15.0)),
                text(self.l10n.tr("pairing-success")).size(32),
            ]
            .align_y(iced::Alignment::Center),
            Space::new().height(Length::Fixed(20.0)),
            text(
                self.l10n
                    .tr_args("pairing-device-id", &[("device_id", device_id)])
            )
            .size(14),
            Space::new().height(Length::Fixed(40.0)),
            done_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_error<'a>(&self, message: &'a str) -> Element<'a, ScreenMessage> {
        let back_button = button(text(self.l10n.tr("btn-back")).size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        column![
            row![
                container(
                    text(char::from(lucide_icons::Icon::X))
                        .font(Font::with_name("lucide"))
                        .size(48)
                        .color(Color::from_rgb(0.8, 0.0, 0.0)),
                )
                .padding(iced::Padding::ZERO.top(8)),
                Space::new().width(Length::Fixed(15.0)),
                text(self.l10n.tr("pairing-failed")).size(32),
            ]
            .align_y(iced::Alignment::Center),
            Space::new().height(Length::Fixed(20.0)),
            text(message).size(14),
            Space::new().height(Length::Fixed(40.0)),
            back_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }
}
