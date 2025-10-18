use super::ScreenMessage;
use iced::{
    widget::{button, column, container, text, Space},
    Task, Element, Length,
};
use shared::{
    config::ClientConfigManager,
    models::pairing::generate_pairing_url,
    crypto::Ed25519KeyPair,
};
use crate::utils::{get_local_ipv4, get_local_ipv6};

#[derive(Debug, Clone)]
pub enum PairingState {
    Loading,
    ShowingQRCode {
        url: String,
    },
    WaitingForConnection,
    VerifyingSAS {
        sas: String,
    },
    Success {
        device_id: String,
    },
    Error {
        message: String,
    },
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
                // Generate QR code with pairing information
                Task::perform(
                    Self::generate_pairing_qr(),
                    |result| match result {
                        Ok((url, _)) => ScreenMessage::PairingComplete(url),
                        Err(e) => ScreenMessage::PairingFailed(e),
                    }
                )
            }
            ScreenMessage::PairingCancelled => Task::done(ScreenMessage::NavigateToMainMenu),
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let content = match &self.state {
            PairingState::Loading => self.view_loading(),
            PairingState::ShowingQRCode { url } => {
                self.view_qr_code(url)
            }
            PairingState::WaitingForConnection => self.view_waiting(),
            PairingState::VerifyingSAS { sas } => self.view_sas_verification(sas),
            PairingState::Success { device_id } => self.view_success(device_id),
            PairingState::Error { message } => self.view_error(message),
        };

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
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

    fn view_qr_code<'a>(&self, url: &'a str) -> Element<'a, ScreenMessage> {
        let back_button = button(text("Cancel").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text("Scan this QR code with your phone").size(24),
            Space::with_height(Length::Fixed(30.0)),
            text("(QR Code will be displayed here)").size(16),
            Space::with_height(Length::Fixed(20.0)),
            text(url).size(12),
            Space::with_height(Length::Fixed(40.0)),
            back_button,
        ]
        .width(Length::Fill)
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_waiting(&self) -> Element<'_, ScreenMessage> {
        let back_button = button(text("Cancel").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text("Waiting for device connection...").size(24),
            Space::with_height(Length::Fixed(20.0)),
            text("Please complete pairing on your device").size(16),
            Space::with_height(Length::Fixed(40.0)),
            back_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    fn view_sas_verification<'a>(&self, sas: &'a str) -> Element<'a, ScreenMessage> {
        let confirm_button = button(text("Confirm").size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingComplete(sas.to_string()));

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
            text("✓ Pairing Successful!").size(32),
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
            text("✗ Pairing Failed").size(32),
            Space::with_height(Length::Fixed(20.0)),
            text(message).size(14),
            Space::with_height(Length::Fixed(40.0)),
            back_button,
        ]
        .align_x(iced::Alignment::Center)
        .into()
    }

    async fn generate_pairing_qr() -> Result<(String, Ed25519KeyPair), String> {
        let _config = ClientConfigManager::new();

        // Get local IP addresses
        let ipv4 = get_local_ipv4().ok_or("Failed to get IPv4 address")?;
        let ipv6 = get_local_ipv6().ok_or("Failed to get IPv6 address")?;

        // Generate temporary keypair for this pairing session
        let keypair = Ed25519KeyPair::generate();

        // Use a fixed port for now (TODO: make configurable)
        let port = 8443;

        // Convert public key to hex
        let pubkey_hex = hex::encode(keypair.verifying_key.as_bytes());

        let url = generate_pairing_url(&pubkey_hex, port, Some(ipv4), Some(ipv6));

        Ok((url, keypair))
    }
}
