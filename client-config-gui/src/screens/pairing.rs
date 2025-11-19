use super::ScreenMessage;
use crate::utils::{get_local_ipv4, get_local_ipv6};
use iced::widget::qr_code::Data as QrData;
use iced::{
    widget::{button, column, container, row, scrollable, text, QRCode, Space},
    Color, Element, Length, Task,
};
use lazy_static::lazy_static;
use shared::{
    config::{ClientConfigManager, PairedServer},
    crypto::Ed25519KeyPair,
    models::pairing::generate_pairing_url,
    protocol::ClientPairingSession,
};
use std::process::Command;
use std::rc::Rc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

// ============================================================================
// FirewallGuard - RAII pattern for ephemeral firewall rules
// ============================================================================

pub struct FirewallGuard {
    port: u16,
}

impl FirewallGuard {
    pub fn new(port: u16) -> Result<Self, String> {
        // 1. Construct the command to INSERT (-I) the rule at position 1
        // Note: Running as root, so no 'sudo' needed
        let status = Command::new("iptables")
            .args([
                "-I",
                "INPUT",
                "1",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        if status.success() {
            tracing::info!("Firewall: Opened ephemeral port {}", port);
            Ok(Self { port })
        } else {
            Err(format!("Firewall command failed with status: {}", status))
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        // 2. Construct the command to DELETE (-D) the exact same rule
        // This runs automatically when the struct goes out of scope
        let _ = Command::new("iptables")
            .args([
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                &self.port.to_string(),
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| {
                tracing::error!("Failed to close firewall port {}: {}", self.port, e);
                e
            });

        tracing::info!("Firewall: Closed ephemeral port {}", self.port);
    }
}

// ============================================================================
// Session State Management
// ============================================================================

pub struct PendingPairingState {
    pub listener: TcpListener,
    pub firewall_guard: FirewallGuard,
    #[allow(dead_code)]
    pub pairing_url: String,
}

pub struct PairingSessionState {
    stream: TcpStream,
    session: ClientPairingSession,
    server_public_key: [u8; 32],
    server_device_name: String,
    #[allow(dead_code)]
    keypair: Ed25519KeyPair,
    // Keep firewall guard alive during active pairing
    #[allow(dead_code)]
    _firewall_guard: FirewallGuard,
}

pub enum SessionState {
    None,
    Pending(PendingPairingState),
    Active(Box<PairingSessionState>),
}

// Global state to store pairing session between lifecycle phases
lazy_static! {
    static ref SESSION_STATE: Mutex<SessionState> = Mutex::new(SessionState::None);
}

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

                    // Extract port from URL to start connection waiter
                    if let Some(port_str) =
                        data.split("&p=").nth(1).and_then(|s| s.split('&').next())
                    {
                        if let Ok(port) = port_str.parse::<u16>() {
                            // Start waiting for connection in background
                            return Task::perform(
                                Self::wait_for_pairing_connection(port),
                                |result| match result {
                                    Ok((sas, port)) => {
                                        // Return SAS with port for continuation
                                        ScreenMessage::PairingComplete(format!(
                                            "SAS:{}:{}",
                                            sas, port
                                        ))
                                    }
                                    Err(e) => ScreenMessage::PairingFailed(e),
                                },
                            );
                        }
                    }
                } else if data.starts_with("SAS:") {
                    // Parse SAS:sas_value:port format
                    let parts: Vec<&str> = data.splitn(3, ':').collect();
                    if parts.len() == 3 {
                        self.state = PairingState::VerifyingSAS {
                            sas: parts[1].to_string(),
                            port: parts[2].parse().unwrap_or(0),
                        };
                    }
                } else {
                    // This is a device_id (pairing success)
                    self.state = PairingState::Success { device_id: data };
                }
                Task::none()
            }
            ScreenMessage::PairingSASConfirmed => {
                // User confirmed SAS - complete pairing
                if let PairingState::VerifyingSAS { port, .. } = &self.state {
                    let port = *port;
                    self.state = PairingState::CompletingPairing;
                    return Task::perform(Self::complete_pairing(port), |result| match result {
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

        // Wrap content in a container with padding to center it vertically
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

    async fn start_pairing() -> Result<(String, u16), String> {
        tracing::debug!("Starting pairing...");
        let config = ClientConfigManager::new();

        // Load or generate Ed25519 keypair
        let keypair = config
            .load_keypair()
            .or_else(|_| config.generate_and_save_keypair())
            .map_err(|e| format!("Failed to load/generate keypair: {}", e))?;

        // Get local IP addresses
        tracing::debug!("Getting local IP addresses...");
        let ipv4 = get_local_ipv4().ok_or("Failed to get IPv4 address")?;
        let ipv6 = get_local_ipv6().ok_or("Failed to get IPv6 address")?;
        tracing::debug!("IPv4: {}, IPv6: {}", ipv4, ipv6);

        // 1. Bind ONCE. Keep this listener alive!
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to bind TCP listener: {}", e))?;

        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to get local address: {}", e))?
            .port();

        tracing::debug!("TCP listener bound to port {}", port);

        // 2. Create the Ephemeral Firewall Rule
        // The rule exists as long as this variable exists
        let firewall_guard = FirewallGuard::new(port)?;

        // Generate pairing URL with X25519 public key
        let session = ClientPairingSession::new(keypair.clone())
            .map_err(|e| format!("Failed to create pairing session: {}", e))?;
        let x25519_pubkey_hex = hex::encode(session.x25519_public_key());

        let url = generate_pairing_url(&x25519_pubkey_hex, port, Some(ipv4), Some(ipv6));
        tracing::debug!("Generated URL: {}", url);

        // 3. Store EVERYTHING in the global mutex
        let pending_state = PendingPairingState {
            listener,
            firewall_guard,
            pairing_url: url.clone(),
        };

        *SESSION_STATE.lock().await = SessionState::Pending(pending_state);

        Ok((url, port))
    }

    async fn wait_for_pairing_connection(port: u16) -> Result<(String, u16), String> {
        use std::time::Duration;
        use tokio::time::timeout;

        tracing::debug!("Waiting for pairing connection on port {}...", port);

        let config = ClientConfigManager::new();

        // Load Ed25519 keypair
        let keypair = config
            .load_keypair()
            .map_err(|e| format!("Failed to load keypair: {}", e))?;

        // 1. Retrieve the existing listener and firewall guard from global state
        let mut guard = SESSION_STATE.lock().await;

        let (listener, firewall_guard) = match std::mem::replace(&mut *guard, SessionState::None) {
            SessionState::Pending(state) => (state.listener, state.firewall_guard),
            _ => return Err("No pending session found".to_string()),
        };
        drop(guard); // Unlock mutex while we await connection

        // 2. Accept connection on the EXISTING listener
        // The firewall rule is still active because `firewall_guard` is still in scope
        let accept_result = timeout(Duration::from_secs(300), listener.accept()).await;

        let (stream, _addr) = match accept_result {
            Ok(Ok((s, a))) => {
                tracing::debug!("Connection from {:?}", a);
                (s, a)
            }
            Ok(Err(e)) => return Err(format!("Accept error: {}", e)),
            Err(_) => return Err("Timeout waiting for connection".to_string()),
        };

        // Create pairing session
        let mut session = ClientPairingSession::new(keypair.clone())
            .map_err(|e| format!("Failed to create pairing session: {}", e))?;

        // Get client device name (hostname)
        let client_device_name =
            whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());

        // Phase 1: Initiate pairing (receive Hello, send Response, compute SAS)
        let (stream, server_public_key, server_device_name, sas) = session
            .initiate_pairing(stream, &client_device_name)
            .await
            .map_err(|e| format!("Pairing initiation failed: {}", e))?;

        tracing::debug!(
            "Pairing initiated. Server: {}, SAS: {}",
            server_device_name,
            &sas
        );

        // 3. Transition to Active State
        // We MUST move `firewall_guard` into the new state so it doesn't drop yet!
        let state = PairingSessionState {
            stream,
            session,
            server_public_key,
            server_device_name: server_device_name.clone(),
            keypair: keypair.clone(),
            _firewall_guard: firewall_guard,
        };

        *SESSION_STATE.lock().await = SessionState::Active(Box::new(state));

        // Return SAS immediately to show to user
        Ok((shared::crypto::format_sas(&sas), port))
    }

    async fn complete_pairing(_port: u16) -> Result<String, String> {
        tracing::debug!("User confirmed SAS, completing pairing...");

        let config = ClientConfigManager::new();

        // Get the original username (before any privilege escalation)
        let username = crate::utils::elevation::get_username();

        tracing::info!("Pairing as user: {}", username);

        // Retrieve stored session state
        let mut state_guard = SESSION_STATE.lock().await;
        let state = match std::mem::replace(&mut *state_guard, SessionState::None) {
            SessionState::Active(s) => s,
            _ => return Err("No active pairing session in progress".to_string()),
        };
        drop(state_guard); // Release lock early

        let PairingSessionState {
            stream,
            mut session,
            server_public_key,
            server_device_name,
            keypair: _,
            _firewall_guard: _,
        } = *state;

        // Load or generate CSK
        let csk = config
            .load_csk()
            .or_else(|_| config.generate_and_save_csk())
            .map_err(|e| format!("Failed to load/generate CSK: {}", e))?;

        tracing::debug!("Loaded/generated CSK");

        // Phase 2: Finish pairing (send CSK with username, receive confirmation)
        session
            .finish_pairing(stream, &csk, &username)
            .await
            .map_err(|e| format!("Pairing completion failed: {}", e))?;

        tracing::debug!("Pairing handshake complete");

        // Store CSK (post-handshake). If saving fails, it's a local config issue — pairing on phone likely succeeded.
        config
            .save_csk(&csk)
            .map_err(|e| format!("Paired on phone, but saving local key failed: {}. Ensure tapauthd is installed and the 'tapauthd' user and group exist, then retry pairing.", e))?;

        // Store paired server with current user in allowed_users list
        let server_hex = hex::encode(server_public_key);
        let paired_server = PairedServer {
            name: server_device_name,
            public_key: server_hex.clone(),
            paired_at: chrono::Utc::now(),
            allowed_users: vec![username], // Store the pairing user
        };

        config
            .add_paired_server(server_hex.clone(), paired_server)
            .map_err(|e| format!("Failed to save paired server: {}", e))?;

        tracing::debug!("Pairing complete!");

        Ok(server_hex)
    }
}
