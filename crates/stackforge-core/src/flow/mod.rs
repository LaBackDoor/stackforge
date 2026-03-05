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
pub mod spill;
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
use std::path::Path;
use std::time::Instant;

use crate::error::PacketError;
use crate::layer::LayerKind;
use crate::pcap::{CaptureIterator, CapturedPacket};

/// Format a byte count into a human-readable string.
fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format a count with commas (e.g. 1,234,567).
fn format_count(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result
}

/// Format duration as human-readable.
fn format_duration(secs: f64) -> String {
    if secs >= 3600.0 {
        let h = (secs / 3600.0).floor();
        let m = ((secs % 3600.0) / 60.0).floor();
        format!("{h:.0}h {m:.0}m")
    } else if secs >= 60.0 {
        let m = (secs / 60.0).floor();
        let s = secs % 60.0;
        format!("{m:.0}m {s:.0}s")
    } else {
        format!("{secs:.1}s")
    }
}

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
    let verbose = config.verbose;
    let interval = config.progress_interval.max(1);
    let total = packets.len();
    let table = ConversationTable::new(config);

    let wall_start = Instant::now();

    if verbose {
        eprintln!();
        eprintln!("[+] stackforge flow extraction engine");
        eprintln!("[+] Input: {} packets (in-memory)", format_count(total));
        eprintln!("[+] Processing...");
        eprintln!();
    }

    for (index, captured) in packets.iter().enumerate() {
        let timestamp = captured.metadata.timestamp;
        table.ingest_packet(&captured.packet, timestamp, index)?;

        if verbose && (index + 1) % interval == 0 {
            let elapsed = wall_start.elapsed().as_secs_f64();
            let rate = (index + 1) as f64 / elapsed;
            let pct = (index + 1) as f64 / total as f64 * 100.0;
            let remaining = (total - index - 1) as f64 / rate;
            let mem = table.memory_usage();
            eprintln!(
                "    [{:5.1}%] {} pkts | {} flows | {}/s | mem ~{} | ETA {}",
                pct,
                format_count(index + 1),
                format_count(table.conversation_count()),
                format_count(rate as usize),
                format_bytes(mem),
                format_duration(remaining),
            );
        }
    }

    if verbose {
        eprintln!();
    }
    let conversations = table.into_conversations();
    if verbose {
        let elapsed = wall_start.elapsed().as_secs_f64();
        let rate = total as f64 / elapsed;
        eprintln!(
            "[+] Complete: {} packets -> {} flows",
            format_count(total),
            format_count(conversations.len())
        );
        eprintln!(
            "[+] Wall time: {} ({}/s avg)",
            format_duration(elapsed),
            format_count(rate as usize)
        );
        eprintln!();
    }
    Ok(conversations)
}

/// Extract flows from a streaming packet source (iterator).
///
/// Does not require all packets in memory simultaneously — each packet is
/// processed and then dropped. Only conversation state (metadata + reassembly
/// buffers) is retained.
///
/// If `config.memory_budget` is set, reassembly buffers will be spilled to
/// disk when the budget is exceeded.
pub fn extract_flows_streaming<I>(
    packets: I,
    config: FlowConfig,
) -> Result<Vec<ConversationState>, FlowError>
where
    I: Iterator<Item = Result<CapturedPacket, PacketError>>,
{
    let verbose = config.verbose;
    let interval = config.progress_interval.max(1);
    let has_budget = config.memory_budget.is_some();
    let budget_str = config
        .memory_budget
        .map(|b| format_bytes(b))
        .unwrap_or_else(|| "unlimited".to_string());
    let table = ConversationTable::new(config);

    let wall_start = Instant::now();

    if verbose {
        eprintln!();
        eprintln!("[+] stackforge flow extraction engine");
        eprintln!("[+] Mode: streaming (packets read from disk on-the-fly)");
        if has_budget {
            eprintln!("[+] Memory budget: {budget_str}");
        }
        eprintln!("[+] Processing...");
        eprintln!();
    }

    let mut last_report = Instant::now();

    for (index, result) in packets.enumerate() {
        let captured = result.map_err(FlowError::PacketError)?;
        let timestamp = captured.metadata.timestamp;
        table.ingest_packet(&captured.packet, timestamp, index)?;
        // `captured` is dropped here — packet memory freed immediately

        if verbose && (index + 1) % interval == 0 {
            let now = Instant::now();
            let elapsed = wall_start.elapsed().as_secs_f64();
            let delta = now.duration_since(last_report).as_secs_f64();
            let overall_rate = (index + 1) as f64 / elapsed;
            let interval_rate = interval as f64 / delta;
            let mem = table.memory_usage();
            let spill_note = if has_budget && table.spill_count() > 0 {
                format!(" | {} spills", format_count(table.spill_count()))
            } else {
                String::new()
            };
            eprintln!(
                "    [{}] {} pkts | {} flows | {}/s (avg {}/s) | mem ~{}{}",
                format_duration(elapsed),
                format_count(index + 1),
                format_count(table.conversation_count()),
                format_count(interval_rate as usize),
                format_count(overall_rate as usize),
                format_bytes(mem),
                spill_note,
            );
            last_report = now;
        }
    }

    if verbose {
        eprintln!();
        eprintln!(
            "[+] Finalizing (sorting {} flows)...",
            format_count(table.conversation_count())
        );
    }
    let conversations = table.into_conversations();
    if verbose {
        let elapsed = wall_start.elapsed().as_secs_f64();
        eprintln!(
            "[+] Complete: {} flows extracted",
            format_count(conversations.len())
        );
        eprintln!("[+] Wall time: {}", format_duration(elapsed));
        eprintln!();
    }
    Ok(conversations)
}

/// Extract flows directly from a capture file (PCAP or PcapNG).
///
/// Streams packets from disk — never loads the entire file into memory.
/// The file format is auto-detected from magic bytes.
pub fn extract_flows_from_file(
    path: impl AsRef<Path>,
    config: FlowConfig,
) -> Result<Vec<ConversationState>, FlowError> {
    let verbose = config.verbose;
    let file_path = path.as_ref();
    if verbose {
        let file_size = std::fs::metadata(file_path)
            .map(|m| format_bytes(m.len() as usize))
            .unwrap_or_else(|_| "unknown".to_string());
        eprintln!("[+] File: {} ({})", file_path.display(), file_size);
    }
    let iter = CaptureIterator::open(file_path).map_err(FlowError::PacketError)?;
    extract_flows_streaming(iter, config)
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

        conv.record_packet(direction, byte_count, timestamp, index, false, false, true);

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
                ..Default::default()
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
