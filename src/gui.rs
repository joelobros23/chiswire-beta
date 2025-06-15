// gui.rs
// This module contains all the GUI logic using the `iced` framework.
// It defines the application's state, messages (events), and the UI layout.

use crate::capture::start_capture;
use crate::dissector::{dissect_packet, PacketInfo};
use iced::widget::{
    button, column, container, row, scrollable, text, text_input,
};
use iced::{executor, time, Alignment, Application, Command, Element, Length, Subscription};
use pnet::datalink;
use std::sync::mpsc;
use std::time::Duration;

/// Represents the main state of our sniffer application.
pub struct Sniffer {
    is_capturing: bool,
    packets: Vec<PacketInfo>,
    filtered_packets: Vec<PacketInfo>,
    available_interfaces: Vec<String>,
    selected_interface: Option<String>,
    display_filter: String,
    selected_packet: Option<PacketInfo>,
    status_message: String,
    // We use a standard library channel to receive packets from the capture thread.
    packet_receiver: Option<mpsc::Receiver<Vec<u8>>>,
}

/// Defines the messages (events) that can occur in our application.
/// These are triggered by user interaction or background tasks.
#[derive(Debug, Clone)]
pub enum Message {
    SelectInterface(String),
    StartCapture,
    StopCapture,
    PacketReceived(Vec<u8>),
    Tick, // To check for new packets periodically
    FilterChanged(String),
    SelectPacket(usize), // usize is the index in the filtered_packets list
    IcedEvent(iced::Event), // To handle raw iced events if needed
}

// Helper method implementation block
impl Sniffer {
    /// Helper function to apply the current display filter.
    fn apply_display_filter(&mut self) {
        if self.display_filter.is_empty() {
            self.filtered_packets = self.packets.clone();
        } else {
            let filter_lower = self.display_filter.to_lowercase();
            self.filtered_packets = self.packets
                .iter()
                .filter(|p| {
                    // This is a very simple filter. A real implementation would
                    // need a proper parsing engine for wireshark-like filters.
                    p.source.to_lowercase().contains(&filter_lower) ||
                    p.destination.to_lowercase().contains(&filter_lower) ||
                    p.protocol.to_lowercase().contains(&filter_lower) ||
                    p.info.to_lowercase().contains(&filter_lower)
                })
                .cloned()
                .collect();
        }
         // After filtering, reset selection if it's no longer valid.
         if self.selected_packet.is_some() && !self.filtered_packets.contains(self.selected_packet.as_ref().unwrap()) {
            self.selected_packet = None;
         }
    }
}


impl Application for Sniffer {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = iced::Theme;
    type Flags = ();

    /// Initializes the application with its initial state.
    fn new(_flags: ()) -> (Self, Command<Message>) {
        let interfaces = datalink::interfaces()
            .into_iter()
            .map(|i| i.name)
            .collect::<Vec<String>>();
        let initial_interface = interfaces.first().cloned();

        (
            Self {
                is_capturing: false,
                packets: Vec::new(),
                filtered_packets: Vec::new(),
                available_interfaces: interfaces,
                selected_interface: initial_interface,
                display_filter: String::new(),
                selected_packet: None,
                status_message: "Ready. Select an interface and start capture.".to_string(),
                packet_receiver: None,
            },
            Command::none(),
        )
    }

    /// Returns the title of the application window.
    fn title(&self) -> String {
        String::from("Chiswire - A Simple Packet Sniffer")
    }

    /// The core logic of the application. It handles all messages and updates the state.
    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::SelectInterface(interface_name) => {
                if !self.is_capturing {
                    self.selected_interface = Some(interface_name);
                }
                Command::none()
            }
            Message::StartCapture => {
                if let Some(interface) = &self.selected_interface {
                    if !self.is_capturing {
                        self.is_capturing = true;
                        self.packets.clear();
                        self.filtered_packets.clear();
                        self.selected_packet = None;
                        self.status_message = format!("Capturing on {}...", interface);

                        let (tx, rx) = mpsc::channel();
                        self.packet_receiver = Some(rx);
                        let interface_name = interface.clone();

                        // Spawn a new thread for packet capture to avoid blocking the GUI.
                        std::thread::spawn(move || {
                            start_capture(interface_name, tx);
                        });
                    }
                } else {
                    self.status_message = "Error: No interface selected!".to_string();
                }
                Command::none()
            }
            Message::StopCapture => {
                self.is_capturing = false;
                self.packet_receiver = None; // This will cause the capture thread to terminate
                self.status_message = "Capture stopped.".to_string();
                Command::none()
            }
            Message::PacketReceived(packet_data) => {
                if let Some(packet_info) = dissect_packet(&packet_data) {
                    self.packets.push(packet_info);
                    // Re-apply filter when a new packet arrives
                    self.apply_display_filter();
                }
                Command::none()
            }
            Message::Tick => {
                // Try to receive all packets currently in the channel queue.
                if let Some(rx) = &self.packet_receiver {
                    // Use try_iter to drain the channel without blocking.
                    for packet_data in rx.try_iter() {
                        if let Some(packet_info) = dissect_packet(&packet_data) {
                            self.packets.push(packet_info);
                        }
                    }
                    self.apply_display_filter();
                }
                Command::none()
            }
            Message::FilterChanged(new_filter) => {
                self.display_filter = new_filter;
                self.apply_display_filter();
                Command::none()
            }
            Message::SelectPacket(index) => {
                self.selected_packet = self.filtered_packets.get(index).cloned();
                Command::none()
            }
            Message::IcedEvent(_) => Command::none(),
        }
    }
    
    /// Defines the subscription for background events, like our packet receiver.
    fn subscription(&self) -> Subscription<Message> {
        if self.is_capturing {
            // When capturing, we subscribe to a timer that sends a `Tick` message
            // every 50ms to check for new packets.
            time::every(Duration::from_millis(50)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }


    /// Renders the GUI layout.
    fn view(&self) -> Element<Message> {
        // --- Top Control Panel ---
        let interface_selector = self.available_interfaces.iter().fold(
            row![text("Interface:").width(Length::Shrink)]
                .spacing(10)
                .align_items(Alignment::Center),
            |r, name| {
                r.push(
                    button(text(name).size(16))
                        .style(if self.selected_interface.as_deref() == Some(name) {
                            iced::theme::Button::Primary
                        } else {
                            iced::theme::Button::Secondary
                        })
                        .on_press(Message::SelectInterface(name.clone())),
                )
            },
        );

        let controls = row![
            interface_selector,
            button(if self.is_capturing { "Stop" } else { "Start" })
                .padding(10)
                .on_press(if self.is_capturing {
                    Message::StopCapture
                } else {
                    Message::StartCapture
                }),
            text_input("Display filter (e.g., 'TCP' or '192.168.1.1')", &self.display_filter)
                .on_input(Message::FilterChanged)
                .padding(10)
        ]
        .spacing(20)
        .padding(10)
        .align_items(Alignment::Center);

        // --- Packet List Pane ---
        let packet_list_header = row![
            text("No.").width(Length::Fixed(50.0)),
            text("Source").width(Length::Fill),
            text("Destination").width(Length::Fill),
            text("Protocol").width(Length::Fixed(100.0)),
            text("Length").width(Length::Fixed(100.0)),
            text("Info").width(Length::Fill)
        ]
        .spacing(10);

        let packet_list: Element<Message> = self.filtered_packets
            .iter()
            .enumerate()
            .fold(column![].spacing(2), |col, (i, packet)| {
                let packet_row = row![
                    text(format!("{}", i + 1)).width(Length::Fixed(50.0)),
                    text(&packet.source).width(Length::Fill),
                    text(&packet.destination).width(Length::Fill),
                    text(&packet.protocol).width(Length::Fixed(100.0)),
                    text(format!("{}", packet.length)).width(Length::Fixed(100.0)),
                    text(&packet.info).width(Length::Fill),
                ]
                .spacing(10)
                .padding(2);

                col.push(
                    button(packet_row)
                        .style(iced::theme::Button::Text)
                        .width(Length::Fill)
                        .on_press(Message::SelectPacket(i)),
                )
            })
            .into();
        
        // --- Packet Detail & Hex View Panes ---
        let detail_view: Element<_> = if let Some(packet) = &self.selected_packet {
            text(packet.detailed_info.clone()).into()
        } else {
            container(text("Select a packet to see details").size(20))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .into()
        };

        let hex_view: Element<_> = if let Some(packet) = &self.selected_packet {
            text(packet.hex_dump.clone()).into()
        } else {
            container(text("Select a packet to see hex dump").size(20))
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .into()
        };

        // --- Main Layout ---
        let main_content = column![
            controls,
            container(packet_list_header).padding(5),
            scrollable(packet_list).height(Length::FillPortion(2)),
            text("Packet Details:").size(20),
            scrollable(detail_view).height(Length::FillPortion(1)),
            text("Hex Dump:").size(20),
            scrollable(hex_view).height(Length::FillPortion(1)),
            text(&self.status_message).size(16),
        ]
        .spacing(10)
        .padding(20);

        container(main_content).into()
    }
}
