use super::ScreenMessage;
use crate::pairing::{complete_pairing, start_pairing, wait_for_pairing_connection};
use iced::widget::qr_code::Data as QrData;
use iced::{
    widget::{button, column, container, row, scrollable, text, QRCode, Space},
    Color, Element, Length, Task,
};
use std::rc::Rc;

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
    state: PairingState,
}

impl PairingScreen {
    pub fn new() -> Self {
        Self {
            state: PairingState::Loading,
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::PairingStarted => {
                self.state = PairingState::Loading;
                Task::perform(start_pairing(), |result| match result {
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
                            return Task::perform(wait_for_pairing_connection(port), |result| {
                                match result {
                                    Ok((sas, port)) => ScreenMessage::PairingComplete(format!(
                                        "SAS:{}:{}",
                                        sas, port
                                    )),
                                    Err(e) => ScreenMessage::PairingFailed(e),
                                }
                            });
                        }
                    }
                } else if data.starts_with("SAS:") {
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
                    return Task::perform(complete_pairing(port), |result| match result {
                        Ok(device_id) => ScreenMessage::PairingComplete(device_id),
                        Err(e) => ScreenMessage::PairingFailed(e),
                    });
                }
                Task::none()
            }
            ScreenMessage::PairingFailed(error) => {
                self.state = PairingState::Error { message: error };
                Task::none()
            }
            ScreenMessage::PairingCancelled => Task::done(ScreenMessage::NavigateToMainMenu),
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
            text("Preparing pairing...").size(24),
            Space::with_height(Length::Fixed(20.0)),
            text("Please wait").size(16),
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_qr_code<'a>(
        &self,
        url: &'a str,
        qr_data: &'a Rc<QrData>,
    ) -> Element<'a, ScreenMessage> {
        let back_button = button(text("Cancel").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text("Scan this QR code with your phone").size(24),
            Space::with_height(Length::Fixed(30.0)),
            container(QRCode::<iced::Theme>::new(qr_data.as_ref()).cell_size(4))
                .width(Length::Shrink)
                .height(Length::Shrink),
            Space::with_height(Length::Fixed(20.0)),
            text("Or enter manually:").size(14),
            text(url).size(10),
            Space::with_height(Length::Fixed(40.0)),
            back_button,
        ]
        .width(Length::Fill)
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_completing(&self) -> Element<'_, ScreenMessage> {
        column![
            text("Completing pairing...").size(24),
            Space::with_height(Length::Fixed(20.0)),
            text("Please wait").size(16),
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_sas_verification<'a>(&self, sas: &'a str) -> Element<'a, ScreenMessage> {
        let confirm_button = button(text("Confirm").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingSASConfirmed);

        let cancel_button = button(text("Cancel").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text("Verify Short Authentication String").size(24),
            Space::with_height(Length::Fixed(30.0)),
            text("Ensure this code matches on your device:").size(16),
            Space::with_height(Length::Fixed(20.0)),
            text(sas).size(48),
            Space::with_height(Length::Fixed(40.0)),
            confirm_button,
            Space::with_height(Length::Fixed(10.0)),
            cancel_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_success<'a>(&self, device_id: &'a str) -> Element<'a, ScreenMessage> {
        let done_button = button(text("Done").size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        column![
            row![
                text("✓").size(48).color(Color::from_rgb(0.0, 0.7, 0.0)),
                Space::with_width(Length::Fixed(15.0)),
                text("Pairing Successful!").size(32),
            ]
            .align_y(iced::Alignment::Center),
            Space::with_height(Length::Fixed(20.0)),
            text(format!("Device ID: {}", device_id)).size(14),
            Space::with_height(Length::Fixed(40.0)),
            done_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_error<'a>(&self, message: &'a str) -> Element<'a, ScreenMessage> {
        let back_button = button(text("Back").size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        column![
            row![
                text("✗").size(48).color(Color::from_rgb(0.8, 0.0, 0.0)),
                Space::with_width(Length::Fixed(15.0)),
                text("Pairing Failed").size(32),
            ]
            .align_y(iced::Alignment::Center),
            Space::with_height(Length::Fixed(20.0)),
            text(message).size(14),
            Space::with_height(Length::Fixed(40.0)),
            back_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }
}
