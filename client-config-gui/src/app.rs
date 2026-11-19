use crate::l10n::{self, L10n};
use crate::screens::{CloseAction, Screen, ScreenMessage};
use iced::{Element, Subscription, Task, Theme};
use std::time::Duration;

/// Upper bound on the best-effort `CancelPairing` sent when the window closes.
///
/// The cancel is a courtesy to the daemon (its answer is ignored), so a daemon
/// that accepts the connection but never answers must not hold the window open:
/// the regular IPC read timeout is 120 s.
const CLOSE_CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// Main application state
pub struct TapAuthConfig {
    l10n: L10n,
    current_screen: Screen,
    /// Current username for per-user locale persistence and UI display
    username: String,
    /// A close request has been accepted and its `CancelPairing` is on its way.
    ///
    /// While set, further close requests are ignored: closing the window now
    /// would end the iced runtime and drop that cancel mid-connect, leaving the
    /// daemon's session behind — the orphan this whole path exists to prevent.
    closing: bool,
}

/// What a window-close request resolved to.
#[derive(Debug, Clone)]
enum CloseTask {
    /// A previous close request is already being answered: do nothing.
    Ignored,
    /// Tell the daemon to drop this session, then close the window.
    Cancel(crate::ipc::PairingSession),
    /// Close the window now: there is nothing to cancel.
    CloseNow,
}

#[derive(Debug, Clone)]
pub enum Message {
    ScreenMessage(ScreenMessage),
    /// The window manager asked to close the window (title-bar button,
    /// Alt+F4, session logout). Answered by hand so an open pairing session can
    /// be handed back to the daemon first; see [`TapAuthConfig::update`].
    WindowCloseRequested(iced::window::Id),
    /// The daemon has been told about the session, if there was one: the
    /// window may now close.
    WindowCloseNow(iced::window::Id),
}

impl TapAuthConfig {
    pub fn new(locale: &str, username: &str) -> (Self, Task<Message>) {
        let l10n = L10n::new(locale);
        let (current_screen, init_task) = Screen::default_with_l10n(l10n.clone());
        (
            Self {
                l10n,
                current_screen,
                username: username.to_string(),
                closing: false,
            },
            init_task.map(Message::ScreenMessage),
        )
    }

    /// Decide what a window-close request does, at most once.
    ///
    /// The first request decides; every request after a cancel was accepted is
    /// [`CloseTask::Ignored`] and must not touch the screen (taking its session
    /// or closing the window early both lose the cancel).
    fn on_close_request(&mut self) -> CloseTask {
        if self.closing {
            return CloseTask::Ignored;
        }

        match self.current_screen.close_action() {
            CloseAction::Cancel(session) => {
                self.closing = true;
                CloseTask::Cancel(session)
            }
            CloseAction::CloseNow => CloseTask::CloseNow,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScreenMessage(screen_msg) => {
                if let ScreenMessage::LocaleChanged(ref locale) = screen_msg {
                    self.l10n = L10n::new(locale);
                    l10n::save_user_locale(&self.username, locale);
                }
                let task = self.current_screen.update(screen_msg, &self.l10n);
                task.map(Message::ScreenMessage)
            }
            Message::WindowCloseRequested(id) => {
                // Without this, a window closed mid-pairing leaves the daemon
                // holding the session (UDP socket, BLE advertisement) until
                // `SESSION_DEADLINE`, 120 s, and the next `StartPairing` is
                // rejected with "A pairing session is already in progress".
                // A completion already in flight is the exception: cancelling it
                // there would discard the device the phone has just paired.
                match self.on_close_request() {
                    // A cancel is already on its way: closing now would drop it
                    // with the runtime.
                    CloseTask::Ignored => Task::none(),
                    CloseTask::CloseNow => iced::window::close(id),
                    CloseTask::Cancel(session) => Task::perform(
                        async move {
                            let cancel =
                                crate::ipc::cancel_pairing(session.port, session.session_id);
                            // Best effort: the answer is irrelevant, and the
                            // close must not wait long on a wedged daemon.
                            let _ = tokio::time::timeout(CLOSE_CANCEL_TIMEOUT, cancel).await;
                        },
                        move |_| Message::WindowCloseNow(id),
                    ),
                }
            }
            Message::WindowCloseNow(id) => iced::window::close(id),
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        // The window is opened with `exit_on_close_request: false` (see `main`),
        // so iced never destroys it on its own: the close request arrives here
        // and `update` closes the window once the daemon has been told to drop
        // the pairing session.
        iced::window::close_requests().map(Message::WindowCloseRequested)
    }

    pub fn view(&self) -> Element<'_, Message> {
        self.current_screen.view().map(Message::ScreenMessage)
    }

    pub fn theme(&self) -> Theme {
        Theme::Light // Use Light theme so QR codes are black-on-white (required for scanning)
    }

    pub(crate) fn title(&self) -> String {
        self.l10n.tr("app-title")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::PairingScreen;

    fn app_with(screen: Screen) -> TapAuthConfig {
        TapAuthConfig {
            l10n: L10n::new("en"),
            current_screen: screen,
            username: "test".to_string(),
            closing: false,
        }
    }

    #[test]
    fn the_first_close_request_cancels_a_pending_session_and_locks_out_the_rest() {
        let mut app = app_with(Screen::Pairing(PairingScreen::showing_qr_for_test(41234)));

        // (a) First request in an in-flight state: cancel the captured session.
        match app.on_close_request() {
            CloseTask::Cancel(session) => {
                assert_eq!(session.port, Some(41234));
                assert_eq!(session.session_id, vec![0xab; 16]);
            }
            other => panic!("a pending session must be cancelled on close, got {other:?}"),
        }
        assert!(
            app.closing,
            "the accepted cancel must lock further close requests out"
        );

        // (b) A second request (double-click on the X, Alt+F4 again) must not
        // close early: that ends the runtime and drops the cancel mid-connect.
        assert!(matches!(app.on_close_request(), CloseTask::Ignored));
        assert!(matches!(app.on_close_request(), CloseTask::Ignored));
    }

    #[test]
    fn an_ignored_close_request_does_not_take_the_screens_session() {
        // A screen that still holds its session while a close is already being
        // answered: the ignored request must not consume it either, or a later
        // teardown would have nothing left to cancel.
        let mut app = app_with(Screen::Pairing(PairingScreen::showing_qr_for_test(41234)));
        app.closing = true;

        assert!(matches!(app.on_close_request(), CloseTask::Ignored));
        match app.current_screen.close_action() {
            CloseAction::Cancel(session) => assert_eq!(session.port, Some(41234)),
            CloseAction::CloseNow => {
                panic!("the ignored close request consumed the session")
            }
        }
    }

    #[test]
    fn a_close_request_with_nothing_to_cancel_closes_immediately() {
        // Not on the pairing screen at all.
        let mut app = TapAuthConfig::new("en", "test").0;
        assert!(matches!(app.on_close_request(), CloseTask::CloseNow));
        assert!(
            !app.closing,
            "nothing is in flight, so a later request must still be able to close"
        );

        // On the pairing screen, but the completion is with the daemon: it
        // finishes on its own, and cancelling it would discard the device.
        let mut app = app_with(Screen::Pairing(PairingScreen::completing_for_test(41234)));
        assert!(matches!(app.on_close_request(), CloseTask::CloseNow));
        assert!(!app.closing);
    }
}
