mod device_list;
mod main_menu;
mod pairing;
mod settings;

pub use device_list::DeviceListScreen;
pub use main_menu::MainMenuScreen;
pub use pairing::PairingScreen;
pub use settings::SettingsScreen;

use iced::{Element, Task};

/// All possible screens in the application
#[derive(Debug, Clone)]
pub enum Screen {
    MainMenu(MainMenuScreen),
    Pairing(PairingScreen),
    DeviceList(DeviceListScreen),
    Settings(SettingsScreen),
}

impl Default for Screen {
    fn default() -> Self {
        Screen::MainMenu(MainMenuScreen::new())
    }
}

/// Messages that can be sent between screens
#[derive(Debug, Clone)]
pub enum ScreenMessage {
    // Navigation
    NavigateToMainMenu,
    NavigateToPairing,
    NavigateToDeviceList,
    NavigateToSettings,

    // Main Menu
    StartPairing,
    ViewDevices,
    OpenSettings,

    // Pairing
    PairingStarted,
    PairingComplete(String), // device_id or SAS
    PairingFailed(String),   // error message
    PairingCancelled,
    PairingSASConfirmed, // User confirmed SAS

    // Device List
    RemoveDevice(String), // device_id
    #[allow(dead_code)]
    DeviceRemoved(String), // device_id
    DevicesLoaded(std::collections::HashMap<String, shared::config::PairedServer>), // loaded devices

    // Settings
    RotateCSK,
    CSKRotated,
    CSKRotationFailed(String),
    HostnameChanged(String),
    UdpPortChanged(String),
    SaveConfig,
    ConfigSaved,
    ConfigSaveFailed(String),
}

impl Screen {
    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            // Navigation messages
            ScreenMessage::NavigateToMainMenu => {
                *self = Screen::MainMenu(MainMenuScreen::new());
                Task::none()
            }
            ScreenMessage::NavigateToPairing => {
                *self = Screen::Pairing(PairingScreen::new());
                // Automatically trigger pairing when navigating to the screen
                Task::done(ScreenMessage::PairingStarted)
            }
            ScreenMessage::NavigateToDeviceList => {
                tracing::debug!("NavigateToDeviceList - creating DeviceListScreen");
                let (screen, task) = DeviceListScreen::new();
                *self = Screen::DeviceList(screen);
                task
            }
            ScreenMessage::NavigateToSettings => {
                *self = Screen::Settings(SettingsScreen::new());
                Task::none()
            }

            // Screen-specific messages
            _ => match self {
                Screen::MainMenu(screen) => screen.update(message),
                Screen::Pairing(screen) => screen.update(message),
                Screen::DeviceList(screen) => screen.update(message),
                Screen::Settings(screen) => screen.update(message),
            },
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        match self {
            Screen::MainMenu(screen) => screen.view(),
            Screen::Pairing(screen) => screen.view(),
            Screen::DeviceList(screen) => screen.view(),
            Screen::Settings(screen) => screen.view(),
        }
    }
}
