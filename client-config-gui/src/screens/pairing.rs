use super::ScreenMessage;
use crate::utils::{get_local_ipv4, get_local_ipv6};
use iced::widget::qr_code::Data as QrData;
use iced::{
    widget::{button, column, container, text, QRCode, Space},
    Element, Length, Task,
};
use shared::{
    config::{ClientConfigManager, PairedServer},
    crypto::Ed25519KeyPair,
    models::pairing::generate_pairing_url,
    protocol::ClientPairingSession,
};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub enum PairingState {
    Loading,
    ShowingQRCode { url: String, qr_data: Arc<QrData> },
    WaitingForConnection,
    VerifyingSAS { sas: String },
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
                // Start pairing and return URL + port
                Task::perform(Self::start_pairing(), |result| match result {
                    Ok((url, _port)) => {
                        // URL received, show QR code
                        ScreenMessage::PairingComplete(url)
                    }
                    Err(e) => ScreenMessage::PairingFailed(e),
                })
            }
            ScreenMessage::PairingComplete(data) => {
                // Check if this is URL (QR code ready) or SAS (verification needed)
                if data.starts_with("tapauth://") {
                    // This is the QR code URL - create QR data here in UI thread
                    let qr_data = match QrData::new(&data) {
                        Ok(qr) => Arc::new(qr),
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

                    // Extract port from URL to start connection waiter
                    if let Some(port_str) =
                        data.split("&p=").nth(1).and_then(|s| s.split('&').next())
                    {
                        if let Ok(port) = port_str.parse::<u16>() {
                            // Start waiting for connection in background
                            return Task::perform(
                                Self::wait_for_pairing_connection(port),
                                |result| match result {
                                    Ok(sas) => ScreenMessage::PairingComplete(sas),
                                    Err(e) => ScreenMessage::PairingFailed(e),
                                },
                            );
                        }
                    }
                } else {
                    // This is the SAS
                    self.state = PairingState::VerifyingSAS { sas: data };
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

    fn view_qr_code<'a>(
        &self,
        url: &'a str,
        qr_data: &'a Arc<QrData>,
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

    async fn start_pairing() -> Result<(String, u16), String> {
        eprintln!("[DEBUG] Starting pairing...");
        let config = ClientConfigManager::new();

        // Load or generate Ed25519 keypair
        let keypair = config
            .load_keypair()
            .or_else(|_| config.generate_and_save_keypair())
            .map_err(|e| format!("Failed to load/generate keypair: {}", e))?;

        // Get local IP addresses
        eprintln!("[DEBUG] Getting local IP addresses...");
        let ipv4 = get_local_ipv4().ok_or("Failed to get IPv4 address")?;
        let ipv6 = get_local_ipv6().ok_or("Failed to get IPv6 address")?;
        eprintln!("[DEBUG] IPv4: {}, IPv6: {}", ipv4, ipv6);

        // Start TCP listener on ephemeral port
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind TCP listener: {}", e))?;

        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to get local address: {}", e))?
            .port();

        eprintln!("[DEBUG] TCP listener on port {}", port);

        // Generate pairing URL with X25519 public key
        let session = ClientPairingSession::new(keypair.clone());
        let x25519_pubkey_hex = hex::encode(session.x25519_public_key());

        let url = generate_pairing_url(&x25519_pubkey_hex, port, Some(ipv4), Some(ipv6));
        eprintln!("[DEBUG] Generated URL: {}", url);

        // Don't wait for connection here - just return URL and port
        Ok((url, port))
    }

    async fn wait_for_pairing_connection(port: u16) -> Result<String, String> {
        use std::time::Duration;
        use tokio::time::timeout;

        eprintln!("[DEBUG] Waiting for pairing connection on port {}...", port);

        let config = ClientConfigManager::new();

        // Load Ed25519 keypair
        let keypair = config
            .load_keypair()
            .map_err(|e| format!("Failed to load keypair: {}", e))?;

        // Bind and wait for connection (with 5 minute timeout)
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .map_err(|e| format!("Failed to bind: {}", e))?;

        let accept_result = timeout(Duration::from_secs(300), listener.accept()).await;

        let (stream, _addr) = match accept_result {
            Ok(Ok((s, a))) => {
                eprintln!("[DEBUG] Connection from {:?}", a);
                (s, a)
            }
            Ok(Err(e)) => return Err(format!("Accept error: {}", e)),
            Err(_) => return Err("Timeout waiting for connection".to_string()),
        };

        // Create pairing session
        let mut session = ClientPairingSession::new(keypair);

        // Complete pairing handshake
        let (csk, server_public_key, sas) = session
            .complete_pairing(stream)
            .await
            .map_err(|e| format!("Pairing failed: {}", e))?;

        eprintln!("[DEBUG] Pairing handshake complete. SAS: {}", sas);

        // Store CSK
        config
            .save_csk(&csk)
            .map_err(|e| format!("Failed to save CSK: {}", e))?;

        // Store paired server
        let server_hex = hex::encode(server_public_key);
        let paired_server = PairedServer {
            name: format!("Server {}", &server_hex[..8]),
            public_key: server_hex.clone(),
            paired_at: chrono::Utc::now(),
        };

        config
            .add_paired_server(server_hex, paired_server)
            .map_err(|e| format!("Failed to save paired server: {}", e))?;

        eprintln!("[DEBUG] Pairing complete!");

        Ok(shared::crypto::format_sas(&sas))
    }
}
