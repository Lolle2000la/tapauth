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
    VerifyingSAS { sas: String, port: Option<u16> },
    CompletingPairing,
    Success { device_id: String },
    Error { error: GuiIpcError },
}

impl PairingState {
    /// Whether a pairing session may still be open on the daemon, so abandoning
    /// the screen must cancel it.
    ///
    /// `CompletingPairing` is included: `CompletePairing` has been sent but has
    /// not answered yet, so the daemon still holds the session and dropping it
    /// silently leaves the worker running until `SESSION_DEADLINE`. That is why
    /// this state renders a Cancel control (a deliberate user choice to abort
    /// the completion). The *implicit* teardown — closing the window — must not
    /// cancel it: see [`close_action`]. `Error` is included because the failure
    /// that got us there (a `WaitForPairing` timeout, say) can leave the
    /// daemon's session open; a cancel for a session it already dropped is
    /// answered with success.
    fn session_in_flight(&self) -> bool {
        matches!(
            self,
            PairingState::ShowingQRCode { .. }
                | PairingState::VerifyingSAS { .. }
                | PairingState::CompletingPairing
                | PairingState::Error { .. }
        )
    }
}

/// What closing the window does about the session the pairing screen holds.
#[derive(Debug, Clone)]
pub enum CloseAction {
    /// Ask the daemon to drop this session before the window closes.
    Cancel(PairingSession),
    /// Close without telling the daemon anything.
    CloseNow,
}

/// The close decision for a pairing screen: `state` is what the screen shows and
/// `session` the session it captured from `StartPairing`, if any.
///
/// `CompletingPairing` closes without cancelling even though it counts as a
/// session in flight (so its Cancel *button* still cancels): by then the phone
/// has confirmed `PairingConfirmClient` and shows success, while `CompletePairing`
/// is still with the daemon persisting the device. A `CancelPairing` sent from
/// the close path reaches the worker first and ends the session as failed, so the
/// device would never be saved — a phone paired to a desktop that never recorded
/// it. Completion is left to finish on its own.
fn close_action(state: &PairingState, session: Option<PairingSession>) -> CloseAction {
    match (state, session) {
        (PairingState::CompletingPairing, _) => CloseAction::CloseNow,
        (state, Some(session)) if state.session_in_flight() => CloseAction::Cancel(session),
        _ => CloseAction::CloseNow,
    }
}

/// Run `fut` to completion, or give up as soon as `cancel` is notified.
///
/// `Some` carries the answer the future produced, `None` means the cancellation
/// won and the answer will never be used. Every cancellable task the screen
/// spawns is built on this, so the handle armed in `cancel_wait` and the future
/// it is supposed to abort cannot drift apart: they are two arguments of the
/// same call.
async fn await_completion_or_cancel<F: std::future::Future>(
    cancel: Arc<tokio::sync::Notify>,
    fut: F,
) -> Option<F::Output> {
    tokio::select! {
        output = fut => Some(output),
        _ = cancel.notified() => None,
    }
}

/// The `SAS:` message a verified SAS is reported as: `SAS:<sas>:<port>`, with an
/// empty tail for a session that has no port (BLE-only). Its reader is the
/// `PairingComplete` arm, which parses the tail back into an `Option<u16>`.
fn format_verified_sas(sas: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("SAS:{sas}:{port}"),
        None => format!("SAS:{sas}:"),
    }
}

/// The `(port, session_id)` pair a `CancelPairing` must carry to address the
/// session the screen holds, or the daemon-side wildcard.
///
/// A rejected `StartPairing` (the daemon still holds an older session) captures
/// no session, so the error screen's Cancel action has nothing to identify it
/// with: an absent port and an empty id mean "don't check that field" in
/// `tapauthd/src/admin_handler.rs`, which cancels whatever is still held. The port
/// is absent rather than `0`, which is no longer a port on that wire.
fn cancel_address(session: Option<PairingSession>) -> (Option<u16>, Vec<u8>) {
    match session {
        Some(session) => (session.port, session.session_id),
        None => (None, Vec::new()),
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
        match self.take_pending_session() {
            Some(session) => Task::perform(
                crate::ipc::cancel_pairing(session.port, session.session_id),
                |_| ScreenMessage::PairingCancelledOnDaemon,
            ),
            None => Task::none(),
        }
    }

    /// The session the daemon still holds, taken out of the screen so a single
    /// cancel is ever issued for it.
    ///
    /// `None` when no session was captured, or when the state says the daemon
    /// no longer has one (see [`PairingState::session_in_flight`]).
    pub fn take_pending_session(&mut self) -> Option<PairingSession> {
        let session = self.session.take()?;
        self.state.session_in_flight().then_some(session)
    }

    /// What closing the window must do about this screen's session.
    pub fn close_action(&mut self) -> CloseAction {
        close_action(&self.state, self.session.take())
    }

    /// A screen holding a session from `StartPairing`, for the close-path tests
    /// that need one without a daemon.
    #[cfg(test)]
    pub(crate) fn showing_qr_for_test(port: u16) -> Self {
        Self::for_test(
            PairingState::ShowingQRCode {
                url: "tapauth://pair?v=2".to_string(),
                qr_data: Rc::new(QrData::new("tapauth://pair?v=2").expect("test URL must encode")),
            },
            port,
        )
    }

    /// A screen whose `CompletePairing` is already with the daemon.
    #[cfg(test)]
    pub(crate) fn completing_for_test(port: u16) -> Self {
        Self::for_test(PairingState::CompletingPairing, port)
    }

    #[cfg(test)]
    fn for_test(state: PairingState, port: u16) -> Self {
        let mut screen = Self::new(L10n::new("en"));
        screen.state = state;
        screen.session = Some(PairingSession {
            url: "tapauth://pair?v=2".to_string(),
            port: Some(port),
            session_id: vec![0xab; 16],
        });
        screen
    }

    /// Take the address the error screen's Cancel action must hand to
    /// `CancelPairing`, and move the screen back to `Loading` so the
    /// `PairingStarted` that follows starts a fresh session.
    fn take_cancel_address(&mut self) -> (Option<u16>, Vec<u8>) {
        let address = cancel_address(self.session.take());
        self.cancel_wait = None;
        self.state = PairingState::Loading;
        address
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
                            result = crate::ipc::wait_for_pairing(port) => {
                                match result {
                                    Ok((sas, port)) => ScreenMessage::PairingComplete(
                                        format_verified_sas(&sas, port),
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
                            // The empty tail is a session with no port (BLE-only).
                            port: parts[2].parse().ok(),
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

                    // `CompletingPairing` is cancellable (see `session_in_flight`
                    // and the Cancel button in `view_completing`), so this task
                    // gets the same select as `wait_for_pairing` above. Without
                    // it, dropping the screen leaves the reply running, and
                    // `Screen::update` hands every non-navigation message to
                    // whichever screen is current — so the abandoned
                    // `CompletePairing`'s `PairingFailed` would land on the next
                    // `PairingScreen` and replace its QR code with an error.
                    let cancel = Arc::new(tokio::sync::Notify::new());
                    let cancel2 = cancel.clone();
                    self.cancel_wait = Some(cancel);

                    let completion = crate::ipc::complete_pairing(port);

                    return Task::perform(
                        async move {
                            match await_completion_or_cancel(cancel2, completion).await {
                                Some(Ok(device_id)) => ScreenMessage::PairingComplete(device_id),
                                Some(Err(e)) => ScreenMessage::PairingFailed(e),
                                // Inert on purpose: the screen that armed
                                // `cancel2` has been torn down, so this message
                                // reaches whichever screen is current now and
                                // must not act as a cancel there.
                                None => ScreenMessage::PairingCompletionAbandoned,
                            }
                        },
                        |msg| msg,
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
            ScreenMessage::PairingCancelRequested => {
                // The Cancel action of the error screen: drop whatever the
                // daemon still holds and start over, so a session orphaned by
                // an earlier run cannot keep answering `StartPairing` with
                // "A pairing session is already in progress".
                let (port, session_id) = self.take_cancel_address();

                Task::perform(
                    async move {
                        // The outcome is deliberately discarded: the retry
                        // reports the daemon's own state, and a failed cancel
                        // only means `StartPairing` will complain again.
                        let _ = crate::ipc::cancel_pairing(port, session_id).await;
                    },
                    |_| ScreenMessage::PairingStarted,
                )
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
        // `CompletePairing` is still unanswered, so the daemon still holds the
        // session; abandoning the screen cancels it (see `session_in_flight`).
        let cancel_button = button(text(self.l10n.tr("btn-cancel")).size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelled);

        column![
            text(self.l10n.tr("pairing-completing")).size(24),
            Space::new().height(Length::Fixed(20.0)),
            text(self.l10n.tr("label-please-wait")).size(16),
            Space::new().height(Length::Fixed(40.0)),
            cancel_button,
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

        // The failure may leave a session open on the daemon — including one
        // inherited from a GUI run that exited without cancelling — so offer to
        // drop it and start over instead of only reporting the error.
        let cancel_button = button(text(self.l10n.tr("btn-cancel-and-retry")).size(16))
            .padding(10)
            .on_press(ScreenMessage::PairingCancelRequested);

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
            cancel_button,
            Space::new().height(Length::Fixed(10.0)),
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

    fn session(port: u16) -> PairingSession {
        PairingSession {
            url: "tapauth://pair?v=2".to_string(),
            port: Some(port),
            session_id: vec![0xab; 16],
        }
    }

    fn screen_in(state: PairingState) -> PairingScreen {
        PairingScreen::for_test(state, 41234)
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
            port: Some(41234),
        }
        .session_in_flight());

        // The daemon may still hold the session when the screen only failed.
        assert!(PairingState::Error {
            error: GuiIpcError::ResponseTimeout,
        }
        .session_in_flight());

        // `CompletePairing` has been sent but not answered, so the daemon is
        // still holding the session: tearing the screen down must cancel it.
        assert!(PairingState::CompletingPairing.session_in_flight());

        // No session has been opened yet, or `CompletePairing` already
        // consumed it.
        assert!(!PairingState::Loading.session_in_flight());
        assert!(!PairingState::Success {
            device_id: "ab".to_string(),
        }
        .session_in_flight());
    }

    #[test]
    fn completing_pairing_hands_its_session_to_the_cancel() {
        let mut screen = screen_in(PairingState::CompletingPairing);

        let pending = screen
            .take_pending_session()
            .expect("a session completing on the daemon must be cancelled");
        assert_eq!(pending.port, Some(41234));
        assert_eq!(pending.session_id, vec![0xab; 16]);
        assert!(
            screen.take_pending_session().is_none(),
            "tearing the screen down twice must not cancel the session twice"
        );

        // `Success` means `CompletePairing` persisted the device: the session is
        // gone daemon-side, so nothing may be cancelled.
        let mut screen = screen_in(PairingState::Success {
            device_id: "ab".to_string(),
        });
        assert!(screen.take_pending_session().is_none());
        assert!(screen.session.is_none());
    }

    /// The `CompletePairing` sent from `PairingSASConfirmed` must be abortable,
    /// because `CompletingPairing` renders a Cancel button: the reply to a
    /// completion the user abandoned must not reach the screen that comes next.
    ///
    /// `Screen::update` routes every non-navigation message to whichever screen
    /// is current (`screens.rs:152-158`) and there is no screen instance id, so a
    /// task spawned by the torn-down screen delivers into the new one. Without an
    /// armed handle the abandoned future runs until the daemon answers, and its
    /// `PairingFailed` replaces the new screen's QR code with an error.
    #[tokio::test]
    async fn cancelling_a_completion_wakes_the_task_that_is_waiting_on_it() {
        let mut screen = screen_in(PairingState::VerifyingSAS {
            sas: "123-456".to_string(),
            port: Some(41234),
        });
        assert!(
            screen.cancel_wait.is_none(),
            "`wait_for_pairing` has already answered the SAS, so no handle is armed yet"
        );

        // The returned task is not polled here: the assertion is about the handle
        // it captured, which is the one `PairingCancelled` notifies.
        drop(screen.update(ScreenMessage::PairingSASConfirmed));
        assert!(
            matches!(screen.state, PairingState::CompletingPairing),
            "the screen must be in the state whose Cancel button is offered"
        );
        let armed = screen
            .cancel_wait
            .clone()
            .expect("an in-flight `CompletePairing` needs a cancel handle");

        drop(screen.update(ScreenMessage::PairingCancelled));
        assert!(
            screen.cancel_wait.is_none(),
            "the handle must be consumed, so one cancel wakes the task once"
        );

        // The completion task awaits exactly this handle, so a permit on it is
        // what aborts `complete_pairing` instead of letting it answer later.
        tokio::time::timeout(std::time::Duration::from_secs(5), armed.notified())
            .await
            .expect("Cancel during CompletingPairing must wake the completion task");
    }

    /// The cancelled arm of the select: a completion that never answers is
    /// abandoned as soon as the armed handle is notified, and reports `None`.
    ///
    /// The timeout is what turns "the cancellation arm was dropped, so the
    /// pending future is awaited forever" into a failure instead of a hang.
    #[tokio::test]
    async fn a_notified_cancel_abandons_a_completion_that_never_answers() {
        let cancel = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                await_completion_or_cancel(
                    cancel,
                    std::future::pending::<Result<String, GuiIpcError>>(),
                )
                .await
            }
        });

        // Park the task inside the `select!` before firing, so the notification
        // cannot be lost to a race against the spawn.
        tokio::task::yield_now().await;
        cancel.notify_one();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("notifying the armed handle must end the wait, not leave it pending")
            .expect("the waiting task must not panic");
        assert!(
            outcome.is_none(),
            "a cancelled completion must report `None`, not the future's answer"
        );
    }

    /// Only the handle the future was armed with may abandon it: notifying some
    /// other `Notify` leaves the completion waiting, and the passed one cancels.
    ///
    /// This is what keeps `cancel_wait` meaningful — a helper that invented its
    /// own `Notify`, or awaited a clone of a different one, would ignore the
    /// handle the Cancel button notifies.
    #[tokio::test]
    async fn only_the_handle_armed_with_the_completion_cancels_it() {
        let armed = Arc::new(tokio::sync::Notify::new());
        let unrelated = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn({
            let armed = armed.clone();
            async move { await_completion_or_cancel(armed, std::future::pending::<()>()).await }
        });

        tokio::task::yield_now().await;
        unrelated.notify_one();
        let mut task = task;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut task)
                .await
                .is_err(),
            "an unrelated `Notify` must not abandon the completion"
        );

        armed.notify_one();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
            .await
            .expect("the handle the completion was armed with must end the wait")
            .expect("the waiting task must not panic");
        assert!(outcome.is_none(), "the cancelled arm must be the one taken");
    }

    /// The other arm: an answer that is already there wins, and is handed back
    /// unchanged. A helper that awaited only the cancellation would hang here
    /// (the timeout reports it) and one that always returned `None` would lose
    /// the device id.
    #[tokio::test]
    async fn an_answer_that_arrives_first_is_handed_back() {
        let cancel = Arc::new(tokio::sync::Notify::new());
        let answer = std::future::ready(Ok::<String, GuiIpcError>("device-1".to_string()));

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            await_completion_or_cancel(cancel, answer),
        )
        .await
        .expect("a ready completion must not wait for a cancellation");

        assert_eq!(
            outcome.map(|result| result.expect("the ready answer is not an error")),
            Some("device-1".to_string())
        );
    }

    /// The abandoned completion reports itself as a message that changes nothing.
    ///
    /// `Screen::update` delivers a task's message to whichever screen is current
    /// (`screens.rs:152-158`), so this one can land on a *fresh* `PairingScreen`
    /// that already armed a cancel handle of its own. Reporting
    /// `PairingCancelled` there would consume that handle, wake the new session's
    /// wait and navigate away from a pairing the user did not abandon.
    #[tokio::test]
    async fn an_abandoned_completion_is_inert_on_whichever_screen_receives_it() {
        let mut fresh = screen_in(qr_state("tapauth://pair?v=2"));
        let armed = Arc::new(tokio::sync::Notify::new());
        fresh.cancel_wait = Some(armed.clone());

        let task = fresh.update(ScreenMessage::PairingCompletionAbandoned);

        assert_eq!(
            task.units(),
            0,
            "the deadline of a torn-down screen must not cause any work here"
        );
        assert!(
            matches!(fresh.state, PairingState::ShowingQRCode { .. }),
            "the fresh screen must stay on its QR code"
        );
        assert!(
            fresh.cancel_wait.is_some(),
            "its own cancel handle must stay armed"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), armed.notified())
                .await
                .is_err(),
            "the fresh session's wait must not be woken by the stale abandonment"
        );
    }

    /// `update` returns a `Task`, which is opaque, and the completion it wraps
    /// needs a daemon — so the wiring can only be pinned on the source: the
    /// `PairingSASConfirmed` arm must hand the completion future to
    /// [`await_completion_or_cancel`] rather than awaiting it directly, and must
    /// report an abandoned completion as the message that is inert on arrival.
    ///
    /// The state is meant to be checked this way: a partial fix that arms
    /// `cancel_wait` but leaves the bare `complete_pairing(...).await` spawned
    /// would pass every runtime assertion above.
    #[test]
    fn the_sas_confirmation_completes_through_the_cancel_helper() {
        const SOURCE: &str = include_str!("pairing.rs");

        let arm_start = SOURCE
            .find("ScreenMessage::PairingSASConfirmed => {\n                if let")
            .expect("the `PairingSASConfirmed` arm is not shaped as this guard reads it");
        let arm_end = SOURCE[arm_start..]
            .find("ScreenMessage::PairingFailed(error) =>")
            .expect("the arm after `PairingSASConfirmed` is not `PairingFailed`");
        let arm = &SOURCE[arm_start..arm_start + arm_end];

        assert!(
            arm.contains("await_completion_or_cancel(cancel2, completion)"),
            "the completion must be raced against its cancel handle, not awaited on its own"
        );
        assert!(
            !arm.contains("complete_pairing(port as u32).await"),
            "a bare `complete_pairing(...).await` cannot be cancelled"
        );
        assert!(
            arm.contains("None => ScreenMessage::PairingCompletionAbandoned"),
            "an abandoned completion must not be reported as a cancel of whatever \
             screen is current"
        );
    }

    #[test]
    fn the_error_screens_cancel_action_addresses_the_session_or_the_daemon_wildcard() {
        // This is the exact address the `PairingCancelRequested` arm hands to
        // `cancel_pairing`.
        //
        // A session captured by `StartPairing`: the cancel must name it, so a
        // newer session started meanwhile is not the one torn down.
        let mut screen = screen_in(PairingState::Error {
            error: GuiIpcError::ResponseTimeout,
        });
        assert_eq!(screen.take_cancel_address(), (Some(41234), vec![0xab; 16]));
        assert!(screen.session.is_none());
        assert!(
            matches!(screen.state, PairingState::Loading),
            "the error screen must return to `Loading` for the retry"
        );

        // `StartPairing` was rejected with "already in progress", so there is no
        // captured session to name: the cancel must still be issued, with the
        // daemon's wildcard, and the screen must go back to `Loading` so
        // `PairingStarted` retries.
        let mut screen = screen_in(PairingState::Error {
            error: GuiIpcError::DaemonError("A pairing session is already in progress.".into()),
        });
        screen.session = None;
        assert_eq!(screen.take_cancel_address(), (None, Vec::new()));
        assert!(
            matches!(screen.state, PairingState::Loading),
            "the error screen must return to `Loading` for the retry"
        );
    }

    #[test]
    fn closing_the_window_cancels_a_pending_session_but_never_an_in_flight_completion() {
        // Every state that may still hold a session cancels it on close...
        for state in [
            qr_state("tapauth://pair?v=2"),
            PairingState::VerifyingSAS {
                sas: "123-456".to_string(),
                port: Some(41234),
            },
            PairingState::Error {
                error: GuiIpcError::ResponseTimeout,
            },
        ] {
            match close_action(&state, Some(session(41234))) {
                CloseAction::Cancel(pending) => {
                    assert_eq!(pending.port, Some(41234));
                    assert_eq!(pending.session_id, vec![0xab; 16]);
                }
                CloseAction::CloseNow => panic!("{state:?} must cancel its session on close"),
            }
        }

        // ...except a completion already in flight: the phone has confirmed and
        // the daemon is persisting the device, so a cancel would throw it away.
        assert!(matches!(
            close_action(&PairingState::CompletingPairing, Some(session(41234))),
            CloseAction::CloseNow
        ));

        // Nothing captured, or the daemon already dropped the session.
        assert!(matches!(
            close_action(
                &PairingState::Error {
                    error: GuiIpcError::ResponseTimeout,
                },
                None
            ),
            CloseAction::CloseNow
        ));
        assert!(matches!(
            close_action(&PairingState::Loading, Some(session(41234))),
            CloseAction::CloseNow
        ));
        assert!(matches!(
            close_action(
                &PairingState::Success {
                    device_id: "ab".to_string(),
                },
                Some(session(41234))
            ),
            CloseAction::CloseNow
        ));

        // The screen forwards its own state and captured session.
        let mut screen = screen_in(PairingState::CompletingPairing);
        assert!(matches!(screen.close_action(), CloseAction::CloseNow));
        assert!(
            screen.session.is_none(),
            "the taken session must not be cancelled later by a teardown"
        );

        let mut screen = screen_in(qr_state("tapauth://pair?v=2"));
        assert!(matches!(screen.close_action(), CloseAction::Cancel(_)));
    }
}
