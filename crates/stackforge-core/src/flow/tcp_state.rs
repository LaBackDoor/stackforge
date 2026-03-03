use crate::TcpLayer;

use super::config::FlowConfig;
use super::error::FlowError;
use super::key::FlowDirection;
use super::tcp_reassembly::TcpReassembler;

/// TCP connection states per RFC 793.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnectionState {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl TcpConnectionState {
    /// Human-readable state name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynRcvd => "SYN_RCVD",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closed => "CLOSED",
        }
    }

    /// Whether this is a terminal/closed state.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait)
    }

    /// Whether this is a half-open state (not yet established).
    #[must_use]
    pub fn is_half_open(&self) -> bool {
        matches!(self, Self::Listen | Self::SynSent | Self::SynRcvd)
    }
}

impl std::fmt::Display for TcpConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Per-endpoint sequence tracking state.
#[derive(Debug, Clone)]
pub struct TcpEndpointState {
    /// Next expected sequence number from this endpoint.
    pub next_expected_seq: u32,
    /// Last acknowledged sequence number from this endpoint.
    pub last_ack: u32,
    /// Advertised receive window size.
    pub window_size: u16,
    /// Initial sequence number (set on SYN).
    pub initial_seq: Option<u32>,
}

impl TcpEndpointState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_expected_seq: 0,
            last_ack: 0,
            window_size: 0,
            initial_seq: None,
        }
    }
}

impl Default for TcpEndpointState {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete TCP conversation state including connection tracking,
/// per-endpoint sequence state, and stream reassembly.
#[derive(Debug)]
pub struct TcpConversationState {
    /// Current connection state (RFC 793 state machine).
    pub conn_state: TcpConnectionState,
    /// Sequence tracking for the forward direction (`addr_a` → `addr_b`).
    pub forward_endpoint: TcpEndpointState,
    /// Sequence tracking for the reverse direction (`addr_b` → `addr_a`).
    pub reverse_endpoint: TcpEndpointState,
    /// Stream reassembly for forward direction.
    pub reassembler_fwd: TcpReassembler,
    /// Stream reassembly for reverse direction.
    pub reassembler_rev: TcpReassembler,
}

impl TcpConversationState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            conn_state: TcpConnectionState::Listen,
            forward_endpoint: TcpEndpointState::new(),
            reverse_endpoint: TcpEndpointState::new(),
            reassembler_fwd: TcpReassembler::new(),
            reassembler_rev: TcpReassembler::new(),
        }
    }

    /// Process a TCP packet, updating connection state and reassembly buffers.
    ///
    /// `direction` indicates whether this packet is Forward (`addr_a` → `addr_b`)
    /// or Reverse (`addr_b` → `addr_a`) relative to the canonical key.
    /// `tcp` is the TCP layer view, `buf` is the full packet buffer.
    pub fn process_packet(
        &mut self,
        direction: FlowDirection,
        tcp: &TcpLayer,
        buf: &[u8],
        config: &FlowConfig,
    ) -> Result<(), FlowError> {
        let flags = tcp
            .flags(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let seq = tcp.seq(buf).map_err(|e| FlowError::PacketError(e.into()))?;
        let ack = tcp.ack(buf).map_err(|e| FlowError::PacketError(e.into()))?;
        let window = tcp
            .window(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;

        // Determine payload boundaries
        let data_offset = tcp
            .data_offset(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let header_bytes = (data_offset as usize) * 4;
        let tcp_start = tcp.index.start;
        // TCP payload starts after the TCP header. Since the TCP layer's
        // index.end marks the header boundary, the payload is everything
        // from header end to the end of the packet buffer.
        let payload_start = tcp_start + header_bytes;
        let payload = if payload_start < buf.len() {
            &buf[payload_start..buf.len()]
        } else {
            &[]
        };

        // Get mutable refs to endpoint and reassembler for this direction
        let (sender, _receiver, reassembler) = match direction {
            FlowDirection::Forward => (
                &mut self.forward_endpoint,
                &mut self.reverse_endpoint,
                &mut self.reassembler_fwd,
            ),
            FlowDirection::Reverse => (
                &mut self.reverse_endpoint,
                &mut self.forward_endpoint,
                &mut self.reassembler_rev,
            ),
        };

        // Update endpoint state
        sender.window_size = window;

        // State machine transitions
        if flags.rst {
            self.conn_state = TcpConnectionState::Closed;
            return Ok(());
        }

        match self.conn_state {
            TcpConnectionState::Listen => {
                if flags.syn && !flags.ack {
                    // SYN from initiator
                    sender.initial_seq = Some(seq);
                    sender.next_expected_seq = seq.wrapping_add(1); // SYN consumes 1 seq
                    self.conn_state = TcpConnectionState::SynSent;
                }
            },
            TcpConnectionState::SynSent => {
                if flags.syn && flags.ack {
                    // SYN-ACK from responder
                    sender.initial_seq = Some(seq);
                    sender.next_expected_seq = seq.wrapping_add(1);
                    sender.last_ack = ack;
                    self.conn_state = TcpConnectionState::SynRcvd;
                }
            },
            TcpConnectionState::SynRcvd => {
                if flags.ack && !flags.syn {
                    // Final ACK of 3-way handshake
                    sender.last_ack = ack;
                    self.conn_state = TcpConnectionState::Established;
                    // Initialize reassemblers with ISN+1 (after SYN)
                    if !self.reassembler_fwd.is_initialized()
                        && let Some(isn) = self.forward_endpoint.initial_seq
                    {
                        self.reassembler_fwd.initialize(isn.wrapping_add(1));
                    }
                    if !self.reassembler_rev.is_initialized()
                        && let Some(isn) = self.reverse_endpoint.initial_seq
                    {
                        self.reassembler_rev.initialize(isn.wrapping_add(1));
                    }
                }
            },
            TcpConnectionState::Established => {
                sender.last_ack = ack;

                // Process payload through reassembler
                if !payload.is_empty() {
                    // Ignore reassembly errors (buffer full, etc.) — they don't
                    // affect connection state tracking
                    let _ = reassembler.process_segment(seq, payload, config);
                }

                if flags.fin {
                    sender.next_expected_seq =
                        seq.wrapping_add(payload.len() as u32).wrapping_add(1); // FIN consumes 1 seq
                    match direction {
                        FlowDirection::Forward => {
                            self.conn_state = TcpConnectionState::FinWait1;
                        },
                        FlowDirection::Reverse => {
                            self.conn_state = TcpConnectionState::CloseWait;
                        },
                    }
                } else {
                    sender.next_expected_seq = seq.wrapping_add(payload.len() as u32);
                }
            },
            TcpConnectionState::FinWait1 => {
                if flags.fin && flags.ack {
                    // Simultaneous close
                    self.conn_state = TcpConnectionState::TimeWait;
                } else if flags.ack {
                    self.conn_state = TcpConnectionState::FinWait2;
                } else if flags.fin {
                    self.conn_state = TcpConnectionState::Closing;
                }
            },
            TcpConnectionState::FinWait2 => {
                if flags.fin {
                    self.conn_state = TcpConnectionState::TimeWait;
                }
            },
            TcpConnectionState::CloseWait => {
                if flags.fin {
                    self.conn_state = TcpConnectionState::LastAck;
                }
            },
            TcpConnectionState::Closing => {
                if flags.ack {
                    self.conn_state = TcpConnectionState::TimeWait;
                }
            },
            TcpConnectionState::LastAck => {
                if flags.ack {
                    self.conn_state = TcpConnectionState::Closed;
                }
            },
            TcpConnectionState::TimeWait | TcpConnectionState::Closed => {
                // Terminal states — no further transitions
            },
        }

        Ok(())
    }
}

impl Default for TcpConversationState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::stack::{LayerStack, LayerStackEntry};
    use crate::{EthernetBuilder, Ipv4Builder, TcpBuilder};

    fn make_tcp_packet(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack_num: u32,
        flags: &str,
        payload: &[u8],
    ) -> crate::Packet {
        let mut builder = TcpBuilder::new()
            .src_port(src_port)
            .dst_port(dst_port)
            .seq(seq)
            .ack_num(ack_num)
            .window(65535);

        for c in flags.chars() {
            builder = match c {
                'S' => builder.syn(),
                'A' => builder.ack(),
                'F' => builder.fin(),
                'R' => builder.rst(),
                'P' => builder.psh(),
                _ => builder,
            };
        }

        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(crate::MacAddress::BROADCAST)
                    .src(crate::MacAddress::new([0, 1, 2, 3, 4, 5])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new()
                    .src(std::net::Ipv4Addr::new(10, 0, 0, 1))
                    .dst(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            ))
            .push(LayerStackEntry::Tcp(builder));

        let stack = if !payload.is_empty() {
            stack.push(LayerStackEntry::Raw(payload.to_vec()))
        } else {
            stack
        };

        stack.build_packet()
    }

    fn get_tcp_and_buf(pkt: &crate::Packet) -> (TcpLayer, &[u8]) {
        let tcp = pkt.tcp().unwrap();
        let buf = pkt.as_bytes();
        (tcp, buf)
    }

    #[test]
    fn test_three_way_handshake() {
        let config = FlowConfig::default();
        let mut state = TcpConversationState::new();

        // SYN (client → server, forward)
        let pkt = make_tcp_packet(12345, 80, 1000, 0, "S", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Forward, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::SynSent);

        // SYN-ACK (server → client, reverse)
        let pkt = make_tcp_packet(80, 12345, 2000, 1001, "SA", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Reverse, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::SynRcvd);

        // ACK (client → server, forward)
        let pkt = make_tcp_packet(12345, 80, 1001, 2001, "A", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Forward, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::Established);
    }

    #[test]
    fn test_rst_closes_connection() {
        let config = FlowConfig::default();
        let mut state = TcpConversationState::new();
        state.conn_state = TcpConnectionState::Established;

        let pkt = make_tcp_packet(12345, 80, 1000, 0, "R", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Forward, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::Closed);
    }

    #[test]
    fn test_fin_handshake() {
        let config = FlowConfig::default();
        let mut state = TcpConversationState::new();
        state.conn_state = TcpConnectionState::Established;

        // FIN from forward direction
        let pkt = make_tcp_packet(12345, 80, 1000, 2000, "FA", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Forward, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::FinWait1);

        // ACK of FIN from reverse
        let pkt = make_tcp_packet(80, 12345, 2000, 1001, "A", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Reverse, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::FinWait2);

        // FIN from reverse
        let pkt = make_tcp_packet(80, 12345, 2000, 1001, "FA", &[]);
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Reverse, &tcp, buf, &config)
            .unwrap();
        assert_eq!(state.conn_state, TcpConnectionState::TimeWait);
    }

    #[test]
    fn test_data_transfer_and_reassembly() {
        let config = FlowConfig::default();
        let mut state = TcpConversationState::new();
        state.conn_state = TcpConnectionState::Established;

        // Initialize forward reassembler
        state.forward_endpoint.initial_seq = Some(999);
        state.reassembler_fwd.initialize(1000);

        // Data from forward direction
        let pkt = make_tcp_packet(12345, 80, 1000, 2000, "A", b"GET /");
        let (tcp, buf) = get_tcp_and_buf(&pkt);
        state
            .process_packet(FlowDirection::Forward, &tcp, buf, &config)
            .unwrap();

        assert_eq!(state.reassembler_fwd.reassembled_data(), b"GET /");
    }

    #[test]
    fn test_state_display() {
        assert_eq!(TcpConnectionState::Established.name(), "ESTABLISHED");
        assert_eq!(TcpConnectionState::SynSent.name(), "SYN_SENT");
        assert!(TcpConnectionState::Closed.is_closed());
        assert!(TcpConnectionState::TimeWait.is_closed());
        assert!(TcpConnectionState::SynSent.is_half_open());
        assert!(!TcpConnectionState::Established.is_half_open());
    }
}
