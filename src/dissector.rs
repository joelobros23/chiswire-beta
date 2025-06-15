// dissector.rs
// This module is responsible for Deep Packet Inspection (DPI).
// It takes raw packet bytes and parses them layer by layer.

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

/// A struct to hold the summarized information of a dissected packet.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketInfo {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
    pub detailed_info: String,
    pub hex_dump: String,
}

/// The main dissection function. It takes raw bytes and returns structured info.
pub fn dissect_packet(packet_data: &[u8]) -> Option<PacketInfo> {
    let ethernet_packet = EthernetPacket::new(packet_data)?;
    let mut detailed_info = format!("{:#?}", ethernet_packet);
    let hex_dump = pretty_hex::pretty_hex(&packet_data);

    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
            detailed_info.push_str(&format!("\n\n{:#?}", ipv4_packet));
            let (protocol, info) = handle_transport_layer(&ipv4_packet.get_next_level_protocol(), ipv4_packet.payload(), &mut detailed_info);
            Some(PacketInfo {
                source: ipv4_packet.get_source().to_string(),
                destination: ipv4_packet.get_destination().to_string(),
                protocol,
                length: packet_data.len(),
                info,
                detailed_info,
                hex_dump,
            })
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload())?;
            detailed_info.push_str(&format!("\n\n{:#?}", ipv6_packet));
            let (protocol, info) = handle_transport_layer(&ipv6_packet.get_next_header(), ipv6_packet.payload(), &mut detailed_info);
            Some(PacketInfo {
                source: ipv6_packet.get_source().to_string(),
                destination: ipv6_packet.get_destination().to_string(),
                protocol,
                length: packet_data.len(),
                info,
                detailed_info,
                hex_dump,
            })
        }
        EtherTypes::Arp => {
            let arp_packet = ArpPacket::new(ethernet_packet.payload())?;
            detailed_info.push_str(&format!("\n\n{:#?}", arp_packet));
            let info = format!(
                "Who has {}? Tell {}",
                arp_packet.get_target_proto_addr(),
                arp_packet.get_sender_proto_addr()
            );
            Some(PacketInfo {
                source: arp_packet.get_sender_hw_addr().to_string(),
                destination: "Broadcast".to_string(),
                protocol: "ARP".to_string(),
                length: packet_data.len(),
                info,
                detailed_info,
                hex_dump,
            })
        }
        _ => {
            // Placeholder for other L2 protocols
            Some(PacketInfo {
                source: ethernet_packet.get_source().to_string(),
                destination: ethernet_packet.get_destination().to_string(),
                protocol: format!("0x{:04x}", ethernet_packet.get_ethertype().0),
                length: packet_data.len(),
                info: "Unknown L3 protocol".to_string(),
                detailed_info,
                hex_dump,
            })
        }
    }
}

/// Handles parsing the transport layer (TCP, UDP, etc.).
fn handle_transport_layer(protocol: &IpNextHeaderProtocol, payload: &[u8], detailed_info: &mut String) -> (String, String) {
    match *protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(payload) {
                detailed_info.push_str(&format!("\n\n{:#?}", tcp_packet));
                let info = format!("{} -> {} Seq: {} Ack: {}", tcp_packet.get_source(), tcp_packet.get_destination(), tcp_packet.get_sequence(), tcp_packet.get_acknowledgement());
                // TODO: Add L7 protocol dissection here (HTTP, TLS, etc.) based on port number.
                ("TCP".to_string(), info)
            } else {
                ("TCP".to_string(), "Malformed Packet".to_string())
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(payload) {
                detailed_info.push_str(&format!("\n\n{:#?}", udp_packet));
                let info = format!("{} -> {} Len: {}", udp_packet.get_source(), udp_packet.get_destination(), udp_packet.get_length());
                 // TODO: Add L7 protocol dissection here (DNS, DHCP, etc.) based on port number.
                ("UDP".to_string(), info)
            } else {
                ("UDP".to_string(), "Malformed Packet".to_string())
            }
        }
        IpNextHeaderProtocols::Icmp => ("ICMP".to_string(), "ICMP Packet".to_string()),
        IpNextHeaderProtocols::Icmpv6 => ("ICMPv6".to_string(), "ICMPv6 Packet".to_string()),
        _ => (format!("Protocol: {}", protocol), "".to_string()),
    }
}
