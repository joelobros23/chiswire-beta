// capture.rs
// This module handles the low-level packet capture logic using the `pnet` crate.
// It runs on a separate thread to prevent blocking the GUI.

use pnet::datalink::{self, Channel};
use std::sync::mpsc::Sender;

/// Starts capturing packets on the specified interface and sends them to the GUI thread.
pub fn start_capture(interface_name: String, sender: Sender<Vec<u8>>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find the specified network interface.");

    // Create a new channel, dealing with layer 2 packets.
    // Promiscuous mode is enabled to capture all packets on the network segment.
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    tracing::info!("Starting packet capture on thread...");
    // Main capture loop.
    loop {
        match rx.next() {
            Ok(packet) => {
                // Send a clone of the packet data over the channel to the GUI.
                if sender.send(packet.to_vec()).is_err() {
                    // If sending fails, it means the receiver (GUI) has been dropped.
                    // We can break the loop and terminate the capture thread.
                    tracing::info!("GUI receiver dropped. Stopping capture thread.");
                    break;
                }
            }
            Err(e) => {
                // If an error occurs, we can panic or log the error.
                tracing::error!("An error occurred while reading: {}", e);
            }
        }
    }
}
