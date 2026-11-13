use super::ScreenMessage;
use crate::ipc::{GuiIpcError, PairingSession};
use crate::l10n::L10n;
use iced::widget::qr_code::Data as QrData;
use iced::{
    widget::{button, column, container, row, scrollable, text, QRCode, Space},
    Color, Element, Font, Length, Task,
};
use std::rc::Rc;
use std::sync::Arc;

/// Cell size in logical pixels for the pairing QR code.
///
/// The v2 URL is ~200 characters (`sid` + `pk` + port + IPv4 + full-form
/// IPv6), which yields a 57-module symbol at the medium error-correction level
/// `QrData::new` picks. At 4 px — the size the shorter v1 URL was tuned for —
/// that is a ~244 px code whose modules are barely 1 mm across on a 96 DPI
/// display; 8 px renders (57 + 2 * 2) * 8 = 488 px, still inside the content
/// area of the default 1024x768 window.
const QR_CELL_SIZE: f32 = 8.0;

/// Padding of the pairing content container, subtracted from the window width
/// when checking that the QR code fits (see `view`).
const CONTENT_PADDING: f32 = 40.0;

/// Width of `iced::window::Settings::default()`, the window `main` opens.
#[cfg(test)]
const WINDOW_WIDTH: f32 = 1024.0;

/// The two quiet-zone modules the `QRCode` widget draws on each side.
#[cfg(test)]
const QR_QUIET_ZONE: u16 = 2;

#[derive(Debug, Clone)]
pub enum PairingState {
    Loading,
    ShowingQRCode { url: String, qr_data: Rc<QrData> },
    VerifyingSAS { sas: String, port: u16 },
    CompletingPairing,
    Success { device_id: String },
    Error { error: GuiIpcError },
}

impl PairingState {
    /// Whether a pairing session may still be open on the daemon, so
    /// abandoning the screen must cancel it.
    ///
    /// `CompletingPairing` is excluded because `CompletePairing` has already
    /// consumed the session there — cancelling would race the completion that
    /// is about to add the device. `Error` is included because the failure that
    /// got us there (a `WaitForPairing` timeout, say) can leave the daemon's
    /// session open; a cancel for a session it already dropped is answered with
    /// an error this task ignores.
    fn session_in_flight(&self) -> bool {
        matches!(
            self,
            PairingState::ShowingQRCode { .. }
                | PairingState::VerifyingSAS { .. }
                | PairingState::Error { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub struct PairingScreen {
    pub l10n: L10n,
    state: PairingState,
    cancel_wait: Option<Arc<tokio::sync::Notify>>,
    /// The session returned by `StartPairing`, kept until it is completed or
    /// cancelled so the daemon can be told to drop it.
    session: Option<PairingSession>,
}

impl PairingScreen {
    pub fn new(l10n: L10n) -> Self {
        Self {
            l10n,
            state: PairingState::Loading,
            cancel_wait: None,
            session: None,
        }
    }

    /// Task that cancels the open pairing session, if one may still be
    /// waiting on the daemon. Called when the screen is torn down.
    pub fn take_cancel_task(&mut self) -> Task<ScreenMessage> {
        match self.session.take() {
            Some(session) if self.state.session_in_flight() => Task::perform(
                crate::ipc::cancel_pairing(session.port, session.session_id),
                |_| ScreenMessage::PairingCancelledOnDaemon,
            ),
            _ => Task::none(),
        }
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::PairingStarted => {
                self.state = PairingState::Loading;
                self.session = None;
                Task::perform(crate::ipc::start_pairing(), |result| match result {
                    Ok(session) => ScreenMessage::PairingSessionStarted(session),
                    Err(e) => ScreenMessage::PairingFailed(e),
                })
            }
            ScreenMessage::PairingSessionStarted(session) => {
                let qr_data = match QrData::new(&session.url) {
                    Ok(qr) => std::rc::Rc::new(qr),
                    Err(_) => {
                        return Task::done(ScreenMessage::PairingFailed(GuiIpcError::DaemonError(
                            "Failed to generate QR code".to_string(),
                        )));
                    }
                };
                self.state = PairingState::ShowingQRCode {
                    url: session.url.clone(),
                    qr_data,
                };

                let port = session.port;
                self.session = Some(session);

                let cancel = Arc::new(tokio::sync::Notify::new());
                let cancel2 = cancel.clone();
                self.cancel_wait = Some(cancel);

                Task::perform(
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
                )
            }
            ScreenMessage::PairingComplete(data) => {
                if data.starts_with("SAS:") {
                    self.cancel_wait = None;
                    let parts: Vec<&str> = data.splitn(3, ':').collect();
                    if parts.len() == 3 {
                        self.state = PairingState::VerifyingSAS {
                            sas: parts[1].to_string(),
                            port: parts[2].parse().unwrap_or(0),
                        };
                    }
                } else {
                    // `CompletePairing` persisted the device; the session is
                    // gone on the daemon side, so never cancel it.
                    self.session = None;
                    self.cancel_wait = None;
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
                self.state = PairingState::Error { error };
                Task::none()
            }
            ScreenMessage::PairingCancelled => {
                if let Some(cancel) = self.cancel_wait.take() {
                    cancel.notify_one();
                }
                // `NavigateToMainMenu` tears the screen down, which is where
                // the in-flight session is cancelled on the daemon.
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
            PairingState::Error { error } => self.view_error(error),
        };

        let centered_content = container(content)
            .width(Length::Fill)
            .center_x(Length::Fill)
            .padding(CONTENT_PADDING);

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
            container(QRCode::<iced::Theme>::new(qr_data.as_ref()).cell_size(QR_CELL_SIZE))
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

    fn view_error<'a>(&self, error: &'a GuiIpcError) -> Element<'a, ScreenMessage> {
        let back_button = button(text(self.l10n.tr("btn-back")).size(16))
            .padding(10)
            .on_press(ScreenMessage::NavigateToMainMenu);

        let message = error.localized(&self.l10n);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest URL the daemon's v2 QR format can produce: 16-byte `sid`
    /// and 32-byte key in hex, a 5-digit port, a dotted-quad IPv4 and a
    /// full-form IPv6 address.
    fn v2_url() -> String {
        format!(
            "tapauth://pair?v=2&sid={}&pk={}&p=65535&ip4=255.255.255.255&ip6=2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "ab".repeat(16),
            "cd".repeat(32),
        )
    }

    fn qr_state(url: &str) -> PairingState {
        PairingState::ShowingQRCode {
            url: url.to_string(),
            qr_data: Rc::new(QrData::new(url).expect("test URL must encode")),
        }
    }

    #[test]
    fn v2_qr_fits_the_window_at_the_configured_cell_size() {
        let url = v2_url();
        assert_eq!(url.len(), 195, "v2 URL length changed; re-check QR sizing");

        let code = qrcode::QrCode::new(url.as_bytes()).expect("v2 URL must encode");
        let side = (code.width() as u16 + 2 * QR_QUIET_ZONE) as f32 * QR_CELL_SIZE;
        let content_width = WINDOW_WIDTH - 2.0 * CONTENT_PADDING;

        assert!(
            side <= content_width,
            "QR renders {side} px wide, past the {content_width} px content area"
        );
        assert!(
            side >= 384.0,
            "QR renders only {side} px wide, so the {} modules are too small to scan",
            code.width()
        );
    }

    #[test]
    fn cancel_is_sent_only_while_a_pairing_session_is_in_flight() {
        assert!(qr_state("tapauth://pair?v=2").session_in_flight());
        assert!(PairingState::VerifyingSAS {
            sas: "123-456".to_string(),
            port: 41234,
        }
        .session_in_flight());

        // The daemon may still hold the session when the screen only failed.
        assert!(PairingState::Error {
            error: GuiIpcError::ResponseTimeout,
        }
        .session_in_flight());

        // No session has been opened yet, or `CompletePairing` already
        // consumed it.
        assert!(!PairingState::Loading.session_in_flight());
        assert!(!PairingState::CompletingPairing.session_in_flight());
        assert!(!PairingState::Success {
            device_id: "ab".to_string(),
        }
        .session_in_flight());
    }
}
