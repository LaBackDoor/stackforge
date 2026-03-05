use std::time::Duration;

use super::config::FlowConfig;
use super::icmp_state::IcmpFlowState;
use super::key::{CanonicalKey, FlowDirection, TransportProtocol};
use super::tcp_state::TcpConversationState;
use super::udp_state::UdpFlowState;

/// Status of a tracked conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationStatus {
    /// Conversation is actively exchanging packets.
    Active,
    /// One direction has initiated close (TCP FIN sent).
    HalfClosed,
    /// Conversation has fully terminated.
    Closed,
    /// Conversation exceeded its idle timeout.
    TimedOut,
}

impl ConversationStatus {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::HalfClosed => "HalfClosed",
            Self::Closed => "Closed",
            Self::TimedOut => "TimedOut",
        }
    }
}

impl std::fmt::Display for ConversationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-direction traffic statistics.
#[derive(Debug, Clone)]
pub struct DirectionStats {
    /// Number of packets in this direction.
    pub packets: u64,
    /// Total bytes in this direction.
    pub bytes: u64,
    /// Timestamp of the first packet in this direction.
    pub first_seen: Duration,
    /// Timestamp of the most recent packet in this direction.
    pub last_seen: Duration,
    /// Maximum packet length in this direction (if tracking enabled).
    pub max_packet_len: Option<u64>,
}

impl DirectionStats {
    #[must_use]
    pub fn new(timestamp: Duration) -> Self {
        Self {
            packets: 0,
            bytes: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            max_packet_len: None,
        }
    }

    /// Record a new packet in this direction.
    pub fn record_packet(&mut self, byte_count: u64, timestamp: Duration, track_max_len: bool) {
        self.packets += 1;
        self.bytes += byte_count;
        self.last_seen = timestamp;
        if track_max_len {
            self.max_packet_len = Some(self.max_packet_len.unwrap_or(0).max(byte_count));
        }
    }
}

/// Protocol-specific state attached to a conversation.
#[derive(Debug)]
pub enum ProtocolState {
    /// TCP connection with full state machine and reassembly.
    Tcp(TcpConversationState),
    /// UDP pseudo-conversation with timeout tracking.
    Udp(UdpFlowState),
    /// ICMP conversation with echo request/reply tracking.
    Icmp(IcmpFlowState),
    /// ICMPv6 conversation with echo request/reply tracking.
    Icmpv6(IcmpFlowState),
    /// Z-Wave wireless conversation with home ID and node tracking.
    ZWave(ZWaveFlowState),
    /// Other protocols — no specific state tracking.
    Other,
}

/// Z-Wave conversation state tracking.
#[derive(Debug, Clone)]
pub struct ZWaveFlowState {
    /// Z-Wave network home ID.
    pub home_id: u32,
    /// Number of command messages (non-ACK frames) seen.
    pub command_count: u64,
    /// Number of ACK frames seen.
    pub ack_count: u64,
}

/// Complete state for a single bidirectional conversation.
///
/// Tracks the canonical key, timing, per-direction statistics, packet indices
/// (into the original capture), and protocol-specific state (TCP state machine
/// or UDP timeout tracking).
#[derive(Debug)]
pub struct ConversationState {
    /// Canonical bidirectional key identifying this conversation.
    pub key: CanonicalKey,
    /// Current conversation status.
    pub status: ConversationStatus,
    /// Timestamp of the first packet in the conversation.
    pub start_time: Duration,
    /// Timestamp of the most recent packet in the conversation.
    pub last_seen: Duration,
    /// Statistics for the forward direction (`addr_a` → `addr_b`).
    pub forward: DirectionStats,
    /// Statistics for the reverse direction (`addr_b` → `addr_a`).
    pub reverse: DirectionStats,
    /// Indices of packets belonging to this conversation (into original packet list).
    pub packet_indices: Vec<usize>,
    /// Protocol-specific state.
    pub protocol_state: ProtocolState,
    /// Maximum packet length across both directions (if tracking enabled).
    pub max_flow_len: Option<u64>,
}

impl ConversationState {
    /// Create a new conversation state from the first observed packet.
    #[must_use]
    pub fn new(key: CanonicalKey, timestamp: Duration) -> Self {
        let protocol_state = match key.protocol {
            TransportProtocol::Tcp => ProtocolState::Tcp(TcpConversationState::new()),
            TransportProtocol::Udp => ProtocolState::Udp(UdpFlowState::new()),
            TransportProtocol::Icmp => ProtocolState::Icmp(IcmpFlowState::new(0, 0)),
            TransportProtocol::Icmpv6 => ProtocolState::Icmpv6(IcmpFlowState::new(0, 0)),
            _ => ProtocolState::Other,
        };

        Self {
            key,
            status: ConversationStatus::Active,
            start_time: timestamp,
            last_seen: timestamp,
            forward: DirectionStats::new(timestamp),
            reverse: DirectionStats::new(timestamp),
            packet_indices: Vec::new(),
            protocol_state,
            max_flow_len: None,
        }
    }

    /// Create a new Z-Wave conversation state.
    ///
    /// Z-Wave conversations use a dummy canonical key since they are
    /// keyed by home ID and node pair rather than IP 5-tuple.
    #[must_use]
    pub fn new_zwave(zwave_key: super::key::ZWaveKey, timestamp: Duration) -> Self {
        use std::net::{IpAddr, Ipv4Addr};

        // Create a placeholder canonical key — the real key is the ZWaveKey
        // stored in the ProtocolState. We encode node IDs in the port fields
        // for display purposes.
        let (key, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            u16::from(zwave_key.node_a),
            u16::from(zwave_key.node_b),
            TransportProtocol::Other(0),
            None,
        );

        Self {
            key,
            status: ConversationStatus::Active,
            start_time: timestamp,
            last_seen: timestamp,
            forward: DirectionStats::new(timestamp),
            reverse: DirectionStats::new(timestamp),
            packet_indices: Vec::new(),
            protocol_state: ProtocolState::ZWave(ZWaveFlowState {
                home_id: zwave_key.home_id,
                command_count: 0,
                ack_count: 0,
            }),
            max_flow_len: None,
        }
    }

    /// Total packets across both directions.
    #[must_use]
    pub fn total_packets(&self) -> u64 {
        self.forward.packets + self.reverse.packets
    }

    /// Total bytes across both directions.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.forward.bytes + self.reverse.bytes
    }

    /// Duration of the conversation.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.last_seen.saturating_sub(self.start_time)
    }

    /// Record a packet in this conversation.
    pub fn record_packet(
        &mut self,
        direction: FlowDirection,
        byte_count: u64,
        timestamp: Duration,
        packet_index: usize,
        track_max_packet_len: bool,
        track_max_flow_len: bool,
        store_packet_indices: bool,
    ) {
        self.last_seen = timestamp;
        if store_packet_indices {
            self.packet_indices.push(packet_index);
        }

        match direction {
            FlowDirection::Forward => {
                self.forward
                    .record_packet(byte_count, timestamp, track_max_packet_len);
            },
            FlowDirection::Reverse => {
                self.reverse
                    .record_packet(byte_count, timestamp, track_max_packet_len);
            },
        }

        // Update max flow length if tracking is enabled
        if track_max_flow_len {
            self.max_flow_len = Some(self.max_flow_len.unwrap_or(0).max(byte_count));
        }
    }

    /// Update the conversation status based on protocol state.
    pub fn update_status(&mut self) {
        match &self.protocol_state {
            ProtocolState::Tcp(tcp) => {
                if tcp.conn_state.is_closed() {
                    self.status = ConversationStatus::Closed;
                } else if matches!(
                    tcp.conn_state,
                    super::tcp_state::TcpConnectionState::FinWait1
                        | super::tcp_state::TcpConnectionState::FinWait2
                        | super::tcp_state::TcpConnectionState::CloseWait
                        | super::tcp_state::TcpConnectionState::Closing
                        | super::tcp_state::TcpConnectionState::LastAck
                ) {
                    self.status = ConversationStatus::HalfClosed;
                }
            },
            ProtocolState::Udp(udp) => {
                self.status = udp.status;
            },
            ProtocolState::Icmp(icmp) => {
                self.status = icmp.status;
            },
            ProtocolState::Icmpv6(icmpv6) => {
                self.status = icmpv6.status;
            },
            ProtocolState::ZWave(_) => {},
            ProtocolState::Other => {},
        }
    }

    /// Check whether this conversation has exceeded its idle timeout.
    #[must_use]
    pub fn is_timed_out(&self, now: Duration, config: &FlowConfig) -> bool {
        let elapsed = now.saturating_sub(self.last_seen);
        match &self.protocol_state {
            ProtocolState::Tcp(tcp) => {
                if tcp.conn_state.is_closed() {
                    false // Already closed, no need to time out
                } else if tcp.conn_state.is_half_open() {
                    elapsed > config.tcp_half_open_timeout
                } else {
                    elapsed > config.tcp_established_timeout
                }
            },
            ProtocolState::Udp(_) => elapsed > config.udp_timeout,
            ProtocolState::Icmp(_) | ProtocolState::Icmpv6(_) => elapsed > config.udp_timeout,
            ProtocolState::ZWave(_) => elapsed > config.udp_timeout,
            ProtocolState::Other => elapsed > config.udp_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_key() -> CanonicalKey {
        let (key, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            12345,
            80,
            TransportProtocol::Tcp,
            None,
        );
        key
    }

    #[test]
    fn test_conversation_state_new() {
        let state = ConversationState::new(test_key(), Duration::from_secs(1));
        assert_eq!(state.status, ConversationStatus::Active);
        assert_eq!(state.total_packets(), 0);
        assert_eq!(state.total_bytes(), 0);
        assert!(matches!(state.protocol_state, ProtocolState::Tcp(_)));
    }

    #[test]
    fn test_record_packet() {
        let mut state = ConversationState::new(test_key(), Duration::from_secs(1));

        state.record_packet(
            FlowDirection::Forward,
            100,
            Duration::from_secs(1),
            0,
            false,
            false,
            true,
        );
        state.record_packet(
            FlowDirection::Reverse,
            200,
            Duration::from_secs(2),
            1,
            false,
            false,
            true,
        );
        state.record_packet(
            FlowDirection::Forward,
            50,
            Duration::from_secs(3),
            2,
            false,
            false,
            true,
        );

        assert_eq!(state.total_packets(), 3);
        assert_eq!(state.total_bytes(), 350);
        assert_eq!(state.forward.packets, 2);
        assert_eq!(state.reverse.packets, 1);
        assert_eq!(state.packet_indices, vec![0, 1, 2]);
        assert_eq!(state.duration(), Duration::from_secs(2));
    }

    #[test]
    fn test_udp_conversation() {
        let (key, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            12345,
            53,
            TransportProtocol::Udp,
            None,
        );
        let state = ConversationState::new(key, Duration::from_secs(0));
        assert!(matches!(state.protocol_state, ProtocolState::Udp(_)));
    }

    #[test]
    fn test_timeout_check() {
        let mut state = ConversationState::new(test_key(), Duration::from_secs(0));
        state.last_seen = Duration::from_secs(100);
        let config = FlowConfig::default();

        // Set to Established so it uses tcp_established_timeout (86400s)
        if let ProtocolState::Tcp(ref mut tcp) = state.protocol_state {
            tcp.conn_state = super::super::tcp_state::TcpConnectionState::Established;
        }

        // Not timed out at 100 + 86399 = 86499
        assert!(!state.is_timed_out(Duration::from_secs(86499), &config));

        // Timed out at 100 + 86401 = 86501
        assert!(state.is_timed_out(Duration::from_secs(86501), &config));
    }
}
