// main.rs
// This is the entry point of our application. It sets up logging,
// initializes the GUI, and runs the application.

use crate::gui::Sniffer; // Corrected the module path
use iced::{Application, Settings};

mod capture;
mod dissector;
mod gui;

fn main() -> iced::Result {
    // Initialize a tracing subscriber for logging. This helps in debugging.
    tracing_subscriber::fmt::init();

    // Run the Iced application.
    // The Sniffer struct contains all our application's state and logic.
    Sniffer::run(Settings {
        window: iced::window::Settings {
            size: iced::Size::new(1200.0, 800.0), // Corrected to use iced::Size
            ..Default::default()
        },
        ..Settings::default()
    })
}
