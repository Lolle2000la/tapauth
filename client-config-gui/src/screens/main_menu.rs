use super::ScreenMessage;
use iced::{
    widget::{button, column, container, text, Space},
    Element, Length, Task,
};

#[derive(Debug, Clone)]
pub struct MainMenuScreen;

impl MainMenuScreen {
    pub fn new() -> Self {
        Self
    }

    pub fn update(&mut self, message: ScreenMessage) -> Task<ScreenMessage> {
        match message {
            ScreenMessage::StartPairing => Task::done(ScreenMessage::NavigateToPairing),
            ScreenMessage::ViewDevices => Task::done(ScreenMessage::NavigateToDeviceList),
            ScreenMessage::OpenSettings => Task::done(ScreenMessage::NavigateToSettings),
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, ScreenMessage> {
        let title = text("TapAuth Configuration")
            .size(40)
            .width(Length::Fill)
            .center();

        let pair_button = button(
            text("Pair New Device")
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .padding(20)
        .width(Length::Fixed(300.0))
        .on_press(ScreenMessage::StartPairing);

        let devices_button = button(text("Manage Devices").size(20).center().width(Length::Fill))
            .padding(20)
            .width(Length::Fixed(300.0))
            .on_press(ScreenMessage::ViewDevices);

        let settings_button = button(text("Settings").size(20).center().width(Length::Fill))
            .padding(20)
            .width(Length::Fixed(300.0))
            .on_press(ScreenMessage::OpenSettings);

        let content = column![
            Space::with_height(Length::Fixed(50.0)),
            title,
            Space::with_height(Length::Fixed(80.0)),
            pair_button,
            Space::with_height(Length::Fixed(20.0)),
            devices_button,
            Space::with_height(Length::Fixed(20.0)),
            settings_button,
        ]
        .width(Length::Fill)
        .align_x(iced::Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}
