//! Stateful conversation extraction and flow tracking.
//!
//! This module provides Wireshark-inspired bidirectional conversation tracking
//! with TCP state machine analysis, stream reassembly, and UDP timeout-based
//! pseudo-conversation tracking.
//!
//! # Architecture
//!
//! - **Canonical Key**: Bidirectional 5-tuple with deterministic IP/port ordering
//! - **Conversation Table**: DashMap-backed concurrent hash table
//! - **TCP State Machine**: RFC 793 connection states with per-endpoint sequence tracking
//! - **TCP Reassembly**: BTreeMap-based out-of-order segment management
//! - **UDP Tracking**: Timeout-based pseudo-conversations
//!
//! # Usage
//!
//! ```rust,no_run
//! use stackforge_core::flow::{extract_flows, FlowConfig};
//! use stackforge_core::pcap::rdpcap;
//!
//! let packets = rdpcap("capture.pcap").unwrap();
//! let conversations = extract_flows(&packets).unwrap();
//! for conv in &conversations {
//!     println!("{}: {} packets", conv.key, conv.total_packets());
//! }
//! ```

pub mod config;
pub mod error;
pub mod icmp_state;
pub mod key;
pub mod state;
pub mod table;
pub mod tcp_reassembly;
pub mod tcp_state;
pub mod udp_state;

// Re-exports
pub use config::FlowConfig;
pub use error::FlowError;
pub use icmp_state::IcmpFlowState;
pub use key::{
    CanonicalKey, FlowDirection, TransportProtocol, ZWaveKey, extract_key, extract_zwave_key,
};
pub use state::{
    ConversationState, ConversationStatus, DirectionStats, ProtocolState, ZWaveFlowState,
};
pub use table::ConversationTable;
pub use tcp_reassembly::{ReassemblyAction, TcpReassembler};
pub use tcp_state::{TcpConnectionState, TcpConversationState, TcpEndpointState};
pub use udp_state::UdpFlowState;

use std::collections::HashMap;

use crate::layer::LayerKind;
use crate::pcap::CapturedPacket;

/// Extract bidirectional conversations from a list of captured packets.
///
/// This is the primary entry point for flow extraction. It processes all
/// packets sequentially, groups them into bidirectional conversations using
/// canonical key normalization, tracks TCP connection state and performs
/// stream reassembly, and tracks UDP pseudo-conversations via timeouts.
///
/// Returns conversations sorted by start time.
pub fn extract_flows(packets: &[CapturedPacket]) -> Result<Vec<ConversationState>, FlowError> {
    extract_flows_with_config(packets, FlowConfig::default())
}

/// Extract flows with custom configuration.
pub fn extract_flows_with_config(
    packets: &[CapturedPacket],
    config: FlowConfig,
) -> Result<Vec<ConversationState>, FlowError> {
    let table = ConversationTable::new(config);

    for (index, captured) in packets.iter().enumerate() {
        let timestamp = captured.metadata.timestamp;
        table.ingest_packet(&captured.packet, timestamp, index)?;
    }

    Ok(table.into_conversations())
}

/// Extract Z-Wave conversations from a list of captured packets.
///
/// Z-Wave is a wireless protocol not carried over IP, so it needs its own
/// flow extraction separate from the IP-based `extract_flows()`. Packets
/// are grouped by home ID and canonical node pair (smaller node = `node_a`).
///
/// Non-Z-Wave packets are silently skipped.
pub fn extract_zwave_flows(
    packets: &[CapturedPacket],
) -> Result<Vec<ConversationState>, FlowError> {
    let mut conversations: HashMap<ZWaveKey, ConversationState> = HashMap::new();

    for (index, captured) in packets.iter().enumerate() {
        let timestamp = captured.metadata.timestamp;
        let packet = &captured.packet;

        // Skip packets without a Z-Wave layer
        if packet.get_layer(LayerKind::ZWave).is_none() {
            continue;
        }

        let (key, direction) = match extract_zwave_key(packet) {
            Ok(result) => result,
            Err(_) => continue,
        };

        let byte_count = packet.as_bytes().len() as u64;
        let buf = packet.as_bytes();

        let conv = conversations.entry(key.clone()).or_insert_with(|| {
            let mut state = ConversationState::new_zwave(key, timestamp);
            if let ProtocolState::ZWave(ref mut zw) = state.protocol_state
                && let Some(zwave) = packet.zwave()
            {
                zw.home_id = zwave.home_id(buf).unwrap_or(0);
            }
            state
        });

        conv.record_packet(direction, byte_count, timestamp, index);

        // Track ACK vs command frames
        if let ProtocolState::ZWave(ref mut zw) = conv.protocol_state
            && let Some(zwave) = packet.zwave()
        {
            if zwave.is_ack(buf) {
                zw.ack_count += 1;
            } else {
                zw.command_count += 1;
            }
        }
    }

    let mut result: Vec<ConversationState> = conversations.into_values().collect();
    result.sort_by_key(|c| c.start_time);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::stack::{LayerStack, LayerStackEntry};
    use crate::pcap::PcapMetadata;
    use crate::{EthernetBuilder, Ipv4Builder, MacAddress, Packet, TcpBuilder, UdpBuilder};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn make_captured(packet: Packet, timestamp_secs: u64) -> CapturedPacket {
        CapturedPacket {
            packet,
            metadata: PcapMetadata {
                timestamp: Duration::from_secs(timestamp_secs),
                orig_len: 0,
            },
        }
    }

    fn tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: &str,
    ) -> Packet {
        let mut builder = TcpBuilder::new()
            .src_port(sport)
            .dst_port(dport)
            .seq(1000)
            .ack_num(0)
            .window(65535);

        for c in flags.chars() {
            builder = match c {
                'S' => builder.syn(),
                'A' => builder.ack(),
                'F' => builder.fin(),
                'R' => builder.rst(),
                _ => builder,
            };
        }

        LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0, 1, 2, 3, 4, 5])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new().src(src_ip).dst(dst_ip),
            ))
            .push(LayerStackEntry::Tcp(builder))
            .build_packet()
    }

    fn udp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sport: u16, dport: u16) -> Packet {
        LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0, 1, 2, 3, 4, 5])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new().src(src_ip).dst(dst_ip),
            ))
            .push(LayerStackEntry::Udp(
                UdpBuilder::new().src_port(sport).dst_port(dport),
            ))
            .build_packet()
    }

    #[test]
    fn test_extract_flows_empty() {
        let result = extract_flows(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_flows_single_tcp() {
        let packets = vec![
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    80,
                    "S",
                ),
                1,
            ),
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(10, 0, 0, 1),
                    80,
                    12345,
                    "SA",
                ),
                2,
            ),
        ];

        let conversations = extract_flows(&packets).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].total_packets(), 2);
        assert_eq!(conversations[0].key.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn test_extract_flows_multiple_conversations() {
        let packets = vec![
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    80,
                    "S",
                ),
                1,
            ),
            make_captured(
                udp_packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 3),
                    54321,
                    53,
                ),
                2,
            ),
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(10, 0, 0, 1),
                    80,
                    12345,
                    "SA",
                ),
                3,
            ),
        ];

        let conversations = extract_flows(&packets).unwrap();
        assert_eq!(conversations.len(), 2);
        // Sorted by start time
        assert!(conversations[0].start_time <= conversations[1].start_time);
    }

    #[test]
    fn test_extract_flows_preserves_packet_indices() {
        let packets = vec![
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                    12345,
                    80,
                    "S",
                ),
                1,
            ),
            make_captured(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(10, 0, 0, 1),
                    80,
                    12345,
                    "SA",
                ),
                2,
            ),
        ];

        let conversations = extract_flows(&packets).unwrap();
        assert_eq!(conversations[0].packet_indices, vec![0, 1]);
    }
}
