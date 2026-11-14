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
            },
            init_task.map(Message::ScreenMessage),
        )
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
                match self.current_screen.close_action() {
                    CloseAction::Cancel(session) => Task::perform(
                        async move {
                            let cancel =
                                crate::ipc::cancel_pairing(session.port, session.session_id);
                            // Best effort: the answer is irrelevant, and the
                            // close must not wait long on a wedged daemon.
                            let _ = tokio::time::timeout(CLOSE_CANCEL_TIMEOUT, cancel).await;
                        },
                        move |_| Message::WindowCloseNow(id),
                    ),
                    CloseAction::CloseNow => iced::window::close(id),
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
