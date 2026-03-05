use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use crate::Packet;

use super::config::FlowConfig;
use super::error::FlowError;
use super::key::{CanonicalKey, extract_key};
use super::spill::MemoryTracker;
use super::state::{ConversationState, ProtocolState};

/// Thread-safe conversation tracking table backed by `DashMap`.
///
/// Supports concurrent packet ingestion from multiple threads while
/// maintaining per-conversation state including TCP state machines
/// and stream reassembly. Optionally tracks memory usage and spills
/// reassembly buffers to disk when a budget is exceeded.
pub struct ConversationTable {
    conversations: DashMap<CanonicalKey, ConversationState>,
    config: FlowConfig,
    memory_tracker: Arc<MemoryTracker>,
    spill_count: std::sync::atomic::AtomicUsize,
}

impl ConversationTable {
    /// Create a new table with the given configuration.
    #[must_use]
    pub fn new(config: FlowConfig) -> Self {
        let memory_tracker = Arc::new(MemoryTracker::new(config.memory_budget));
        Self {
            conversations: DashMap::new(),
            config,
            memory_tracker,
            spill_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Create a new table with default configuration.
    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(FlowConfig::default())
    }

    /// Number of tracked conversations.
    #[must_use]
    pub fn conversation_count(&self) -> usize {
        self.conversations.len()
    }

    /// Ingest a single parsed packet, updating or creating conversation state.
    ///
    /// `timestamp` is the packet capture timestamp (from PCAP metadata).
    /// `packet_index` is the index of this packet in the original capture
    /// (used for cross-referencing).
    pub fn ingest_packet(
        &self,
        packet: &Packet,
        timestamp: Duration,
        packet_index: usize,
    ) -> Result<(), FlowError> {
        let (key, direction) = match extract_key(packet) {
            Ok(result) => result,
            Err(FlowError::NoIpLayer | FlowError::NoTransportLayer) => {
                // Skip non-IP or non-TCP/UDP packets silently
                return Ok(());
            },
            Err(e) => return Err(e),
        };

        let byte_count = packet.as_bytes().len() as u64;

        // Use DashMap entry API for atomic get-or-insert + update
        let mut entry = self
            .conversations
            .entry(key.clone())
            .or_insert_with(|| ConversationState::new(key, timestamp));

        let conv = entry.value_mut();

        // Record packet stats
        conv.record_packet(
            direction,
            byte_count,
            timestamp,
            packet_index,
            self.config.track_max_packet_len,
            self.config.track_max_flow_len,
            self.config.store_packet_indices,
        );

        // Process protocol-specific state
        let buf = packet.as_bytes();
        match &mut conv.protocol_state {
            ProtocolState::Tcp(tcp_state) => {
                if let Some(tcp) = packet.tcp() {
                    tcp_state.process_packet(direction, &tcp, buf, &self.config)?;
                }
            },
            ProtocolState::Udp(udp_state) => {
                udp_state.process_packet();
            },
            ProtocolState::Icmp(icmp_state) => {
                // Get ICMP type and code from buffer
                if let Some(icmp_layer) = packet.get_layer(crate::layer::LayerKind::Icmp) {
                    if buf.len() >= icmp_layer.start + 2 {
                        let icmp_type = buf[icmp_layer.start];
                        let icmp_code = buf[icmp_layer.start + 1];
                        icmp_state.process_packet(packet, buf, icmp_type, icmp_code);
                    }
                }
            },
            ProtocolState::Icmpv6(icmpv6_state) => {
                // Get ICMPv6 type and code from buffer
                if let Some(icmpv6_layer) = packet.get_layer(crate::layer::LayerKind::Icmpv6) {
                    if buf.len() >= icmpv6_layer.start + 2 {
                        let icmpv6_type = buf[icmpv6_layer.start];
                        let icmpv6_code = buf[icmpv6_layer.start + 1];
                        icmpv6_state.process_packet(packet, buf, icmpv6_type, icmpv6_code);
                    }
                }
            },
            ProtocolState::ZWave(_) => {},
            ProtocolState::Other => {},
        }

        // Update conversation status from protocol state
        conv.update_status();

        // Track memory for TCP reassembly buffers (only for in-memory data)
        if self.memory_tracker.has_budget() {
            if let ProtocolState::Tcp(ref tcp_state) = conv.protocol_state {
                // Only track if at least one reassembler is still in memory
                let fwd_spilled = tcp_state.reassembler_fwd.is_spilled();
                let rev_spilled = tcp_state.reassembler_rev.is_spilled();
                if !fwd_spilled || !rev_spilled {
                    let tcp_payload_len = packet.tcp().map_or(0, |tcp| {
                        let data_offset = tcp.data_offset(buf).unwrap_or(5) as usize * 4;
                        let payload_start = tcp.index.start + data_offset;
                        buf.len().saturating_sub(payload_start)
                    });
                    if tcp_payload_len > 0 {
                        self.memory_tracker.add(tcp_payload_len);
                    }
                }
            }
        }

        // Drop the entry lock before spilling (which needs iter_mut)
        drop(entry);

        // Spill if over budget
        if self.memory_tracker.is_over_budget() {
            self.maybe_spill();
        }

        Ok(())
    }

    /// Spill reassembly buffers to disk until under budget.
    ///
    /// Two limits prevent runaway iteration:
    /// - `max_spills`: stop after spilling this many buffers (actual work done)
    /// - `max_skip`: stop after skipping this many already-spilled/non-TCP entries
    ///   without finding anything to free (avoids scanning the entire table when
    ///   most flows are already on disk)
    fn maybe_spill(&self) {
        let mut spills = 0;
        let max_spills = 64;
        let mut consecutive_skips = 0;
        let max_skip = 512;

        for mut entry in self.conversations.iter_mut() {
            if !self.memory_tracker.is_over_budget() || spills >= max_spills {
                break;
            }
            if consecutive_skips >= max_skip {
                // Most nearby entries are already spilled — stop scanning
                break;
            }

            if let ProtocolState::Tcp(ref mut tcp_state) = entry.value_mut().protocol_state {
                // Skip buffers already on disk
                if tcp_state.reassembler_fwd.is_spilled() && tcp_state.reassembler_rev.is_spilled()
                {
                    consecutive_skips += 1;
                    continue;
                }
                let freed_fwd = tcp_state
                    .reassembler_fwd
                    .spill(self.config.spill_dir.as_deref())
                    .unwrap_or(0);
                let freed_rev = tcp_state
                    .reassembler_rev
                    .spill(self.config.spill_dir.as_deref())
                    .unwrap_or(0);
                let total_freed = freed_fwd + freed_rev;
                if total_freed > 0 {
                    self.memory_tracker.subtract(total_freed);
                    self.spill_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    spills += 1;
                    consecutive_skips = 0; // Reset — we found something useful
                } else {
                    consecutive_skips += 1;
                }
            } else {
                consecutive_skips += 1;
            }
        }
    }

    /// Estimated memory usage of the flow table (tracked reassembly buffers).
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        self.memory_tracker.current_usage()
    }

    /// Number of spill operations performed.
    #[must_use]
    pub fn spill_count(&self) -> usize {
        self.spill_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get a read reference to a specific conversation.
    #[must_use]
    pub fn get_conversation(
        &self,
        key: &CanonicalKey,
    ) -> Option<dashmap::mapref::one::Ref<'_, CanonicalKey, ConversationState>> {
        self.conversations.get(key)
    }

    /// Evict conversations that have exceeded their idle timeout.
    ///
    /// Returns the number of evicted conversations.
    #[must_use]
    pub fn evict_idle(&self, now: Duration) -> usize {
        let mut evicted = 0;
        self.conversations.retain(|_, conv| {
            if conv.is_timed_out(now, &self.config) {
                evicted += 1;
                false
            } else {
                true
            }
        });
        evicted
    }

    /// Consume the table and return all conversations sorted by start time.
    #[must_use]
    pub fn into_conversations(self) -> Vec<ConversationState> {
        let mut conversations: Vec<ConversationState> =
            self.conversations.into_iter().map(|(_, v)| v).collect();
        conversations.sort_by_key(|c| c.start_time);
        conversations
    }

    /// Get a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &FlowConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::stack::{LayerStack, LayerStackEntry};
    use crate::{EthernetBuilder, Ipv4Builder, MacAddress, TcpBuilder, UdpBuilder};
    use std::net::Ipv4Addr;

    fn make_tcp_packet(
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

    fn make_udp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, sport: u16, dport: u16) -> Packet {
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
    fn test_ingest_creates_conversation() {
        let table = ConversationTable::with_default_config();
        let pkt = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            "S",
        );

        table
            .ingest_packet(&pkt, Duration::from_secs(1), 0)
            .unwrap();
        assert_eq!(table.conversation_count(), 1);
    }

    #[test]
    fn test_bidirectional_same_conversation() {
        let table = ConversationTable::with_default_config();

        // Forward packet
        let pkt_fwd = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            "S",
        );
        table
            .ingest_packet(&pkt_fwd, Duration::from_secs(1), 0)
            .unwrap();

        // Reverse packet
        let pkt_rev = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            12345,
            "SA",
        );
        table
            .ingest_packet(&pkt_rev, Duration::from_secs(2), 1)
            .unwrap();

        // Should be one conversation, not two
        assert_eq!(table.conversation_count(), 1);

        let conversations = table.into_conversations();
        assert_eq!(conversations[0].total_packets(), 2);
        assert_eq!(conversations[0].forward.packets, 1);
        assert_eq!(conversations[0].reverse.packets, 1);
    }

    #[test]
    fn test_different_flows_different_conversations() {
        let table = ConversationTable::with_default_config();

        let pkt1 = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            "S",
        );
        let pkt2 = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 3),
            12345,
            443,
            "S",
        );

        table
            .ingest_packet(&pkt1, Duration::from_secs(1), 0)
            .unwrap();
        table
            .ingest_packet(&pkt2, Duration::from_secs(2), 1)
            .unwrap();

        assert_eq!(table.conversation_count(), 2);
    }

    #[test]
    fn test_udp_conversation() {
        let table = ConversationTable::with_default_config();

        let pkt = make_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            53,
        );
        table
            .ingest_packet(&pkt, Duration::from_secs(1), 0)
            .unwrap();

        let conversations = table.into_conversations();
        assert_eq!(conversations.len(), 1);
        assert!(matches!(
            conversations[0].protocol_state,
            ProtocolState::Udp(_)
        ));
    }

    #[test]
    fn test_evict_idle() {
        let mut config = FlowConfig::default();
        config.udp_timeout = Duration::from_secs(10);
        let table = ConversationTable::new(config);

        let pkt = make_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            53,
        );
        table
            .ingest_packet(&pkt, Duration::from_secs(1), 0)
            .unwrap();
        assert_eq!(table.conversation_count(), 1);

        // Not yet timed out
        let evicted = table.evict_idle(Duration::from_secs(5));
        assert_eq!(evicted, 0);
        assert_eq!(table.conversation_count(), 1);

        // Now timed out
        let evicted = table.evict_idle(Duration::from_secs(20));
        assert_eq!(evicted, 1);
        assert_eq!(table.conversation_count(), 0);
    }

    #[test]
    fn test_into_conversations_sorted() {
        let table = ConversationTable::with_default_config();

        let pkt1 = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            80,
            "S",
        );
        let pkt2 = make_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 3),
            12345,
            443,
            "S",
        );

        // Insert second flow first (later timestamp)
        table
            .ingest_packet(&pkt2, Duration::from_secs(5), 1)
            .unwrap();
        table
            .ingest_packet(&pkt1, Duration::from_secs(1), 0)
            .unwrap();

        let conversations = table.into_conversations();
        assert!(conversations[0].start_time <= conversations[1].start_time);
    }
}
