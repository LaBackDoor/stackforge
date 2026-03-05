use std::net::IpAddr;

use crate::Packet;
use crate::layer::LayerKind;
use crate::layer::ipv6::Ipv6Layer;

use super::error::FlowError;

/// Z-Wave conversation key based on home ID and node pair.
///
/// Uses canonical ordering: the smaller node ID is always `node_a`.
/// This ensures that both directions of a Z-Wave conversation hash
/// to the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZWaveKey {
    /// Z-Wave network home ID.
    pub home_id: u32,
    /// The smaller node ID.
    pub node_a: u8,
    /// The larger node ID.
    pub node_b: u8,
}

impl ZWaveKey {
    /// Create a new canonical Z-Wave key with deterministic node ordering.
    ///
    /// Returns the key and the direction of the original packet relative
    /// to the canonical ordering.
    #[must_use]
    pub fn new(home_id: u32, src_node: u8, dst_node: u8) -> (Self, FlowDirection) {
        if src_node <= dst_node {
            (
                Self {
                    home_id,
                    node_a: src_node,
                    node_b: dst_node,
                },
                FlowDirection::Forward,
            )
        } else {
            (
                Self {
                    home_id,
                    node_a: dst_node,
                    node_b: src_node,
                },
                FlowDirection::Reverse,
            )
        }
    }
}

impl std::fmt::Display for ZWaveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ZWave[{:#010X}] node {} <-> node {}",
            self.home_id, self.node_a, self.node_b
        )
    }
}

/// Extract a Z-Wave key and direction from a parsed packet.
///
/// Reads the Z-Wave layer for home ID, source, and destination node IDs.
pub fn extract_zwave_key(packet: &Packet) -> Result<(ZWaveKey, FlowDirection), FlowError> {
    if !packet.is_parsed() {
        return Err(FlowError::PacketNotParsed);
    }

    let buf = packet.as_bytes();

    let zwave = packet.zwave().ok_or(FlowError::NoTransportLayer)?;

    let home_id = zwave
        .home_id(buf)
        .map_err(|e| FlowError::PacketError(e.into()))?;
    let src = zwave
        .src(buf)
        .map_err(|e| FlowError::PacketError(e.into()))?;
    let dst = zwave
        .dst(buf)
        .map_err(|e| FlowError::PacketError(e.into()))?;

    Ok(ZWaveKey::new(home_id, src, dst))
}

/// Transport layer protocol identifier for flow keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl TransportProtocol {
    /// Create from IP protocol number.
    #[must_use]
    pub fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Other(_) => "Other",
        }
    }
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(n) => write!(f, "Other({n})"),
            _ => f.write_str(self.name()),
        }
    }
}

/// Direction of a packet relative to the conversation's canonical key.
///
/// Forward means the packet's source matches `addr_a` (the smaller address).
/// Reverse means the packet's source matches `addr_b` (the larger address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowDirection {
    Forward,
    Reverse,
}

/// Bidirectional canonical conversation key.
///
/// Uses Wireshark-style canonical ordering: the smaller IP address is always
/// `addr_a` with its corresponding port as `port_a`. This ensures that both
/// directions of a conversation hash to the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalKey {
    /// The smaller IP address (or first if equal, then by port).
    pub addr_a: IpAddr,
    /// The larger IP address.
    pub addr_b: IpAddr,
    /// Port corresponding to `addr_a`.
    pub port_a: u16,
    /// Port corresponding to `addr_b`.
    pub port_b: u16,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Optional VLAN ID for deinterlacing.
    pub vlan_id: Option<u16>,
}

/// Helper to get byte representation of an IP address for comparison.
fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

impl CanonicalKey {
    /// Create a new canonical key with deterministic ordering.
    ///
    /// Returns the key and the direction of the original packet relative
    /// to the canonical ordering.
    #[must_use]
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: TransportProtocol,
        vlan_id: Option<u16>,
    ) -> (Self, FlowDirection) {
        let src_bytes = ip_to_bytes(&src_ip);
        let dst_bytes = ip_to_bytes(&dst_ip);

        let (addr_a, port_a, addr_b, port_b, direction) = match src_bytes.cmp(&dst_bytes) {
            std::cmp::Ordering::Less => {
                (src_ip, src_port, dst_ip, dst_port, FlowDirection::Forward)
            },
            std::cmp::Ordering::Greater => {
                (dst_ip, dst_port, src_ip, src_port, FlowDirection::Reverse)
            },
            std::cmp::Ordering::Equal => {
                // IPs are equal, sort by port
                if src_port <= dst_port {
                    (src_ip, src_port, dst_ip, dst_port, FlowDirection::Forward)
                } else {
                    (dst_ip, dst_port, src_ip, src_port, FlowDirection::Reverse)
                }
            },
        };

        (
            Self {
                addr_a,
                addr_b,
                port_a,
                port_b,
                protocol,
                vlan_id,
            },
            direction,
        )
    }
}

impl std::fmt::Display for CanonicalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} <-> {}:{} [{}]",
            self.addr_a, self.port_a, self.addr_b, self.port_b, self.protocol
        )
    }
}

/// Extract a canonical key and direction from a parsed packet.
///
/// Reads the IP layer (IPv4 or IPv6) for addresses and protocol number,
/// and the transport layer (TCP or UDP) for ports. For ICMP and other
/// protocols without ports, ports are set to 0.
pub fn extract_key(packet: &Packet) -> Result<(CanonicalKey, FlowDirection), FlowError> {
    if !packet.is_parsed() {
        return Err(FlowError::PacketNotParsed);
    }

    let buf = packet.as_bytes();

    // Extract IP addresses and protocol
    let (src_ip, dst_ip, proto) = if let Some(ipv4) = packet.ipv4() {
        let src = ipv4
            .src(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let dst = ipv4
            .dst(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let protocol = ipv4
            .protocol(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        (IpAddr::V4(src), IpAddr::V4(dst), protocol)
    } else if let Some(idx) = packet.get_layer(LayerKind::Ipv6) {
        let ipv6 = Ipv6Layer { index: *idx };
        let src = ipv6
            .src(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let dst = ipv6
            .dst(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        let next_header = ipv6
            .next_header(buf)
            .map_err(|e| FlowError::PacketError(e.into()))?;
        (IpAddr::V6(src), IpAddr::V6(dst), next_header)
    } else {
        return Err(FlowError::NoIpLayer);
    };

    let transport = TransportProtocol::from_ip_protocol(proto);

    // Extract ports from transport layer
    let (src_port, dst_port) = match transport {
        TransportProtocol::Tcp => {
            let tcp = packet.tcp().ok_or(FlowError::NoTransportLayer)?;
            let sport = tcp
                .src_port(buf)
                .map_err(|e| FlowError::PacketError(e.into()))?;
            let dport = tcp
                .dst_port(buf)
                .map_err(|e| FlowError::PacketError(e.into()))?;
            (sport, dport)
        },
        TransportProtocol::Udp => {
            let udp = packet.udp().ok_or(FlowError::NoTransportLayer)?;
            let sport = udp
                .src_port(buf)
                .map_err(|e| FlowError::PacketError(e.into()))?;
            let dport = udp
                .dst_port(buf)
                .map_err(|e| FlowError::PacketError(e.into()))?;
            (sport, dport)
        },
        TransportProtocol::Icmp => {
            // For ICMP, use identifier (for echo/timestamp types) for both ports
            // (symmetric), or type+code as port substitute for other types.
            // Using identifier symmetrically ensures request and reply have
            // the same canonical key regardless of direction.
            if let Some(icmp_layer) = packet.get_layer(LayerKind::Icmp) {
                if buf.len() >= icmp_layer.start + 8 {
                    let icmp_type = buf[icmp_layer.start];
                    let is_echo = icmp_type == 0 || icmp_type == 8;
                    if is_echo {
                        let id = u16::from_be_bytes([
                            buf[icmp_layer.start + 4],
                            buf[icmp_layer.start + 5],
                        ]);
                        (id, id) // Use identifier symmetrically for both ports
                    } else {
                        let code = buf[icmp_layer.start + 1];
                        (icmp_type as u16, code as u16)
                    }
                } else {
                    (0u16, 0u16)
                }
            } else {
                (0u16, 0u16)
            }
        },
        TransportProtocol::Icmpv6 => {
            // For ICMPv6, use identifier (for echo/timestamp types) for both ports
            // (symmetric), or type+code as port substitute for other types.
            // Using identifier symmetrically ensures request and reply have
            // the same canonical key regardless of direction.
            if let Some(icmpv6_layer) = packet.get_layer(LayerKind::Icmpv6) {
                if buf.len() >= icmpv6_layer.start + 8 {
                    let icmpv6_type = buf[icmpv6_layer.start];
                    let is_echo = icmpv6_type == 128 || icmpv6_type == 129;
                    if is_echo {
                        let id = u16::from_be_bytes([
                            buf[icmpv6_layer.start + 4],
                            buf[icmpv6_layer.start + 5],
                        ]);
                        (id, id) // Use identifier symmetrically for both ports
                    } else {
                        let code = buf[icmpv6_layer.start + 1];
                        (icmpv6_type as u16, code as u16)
                    }
                } else {
                    (0u16, 0u16)
                }
            } else {
                (0u16, 0u16)
            }
        },
        // Other protocols have no ports
        _ => (0u16, 0u16),
    };

    // Check for VLAN tag
    let vlan_id = if packet.get_layer(LayerKind::Dot1Q).is_some() {
        // TODO: Extract actual VLAN ID from Dot1Q layer if needed
        None
    } else {
        None
    };

    Ok(CanonicalKey::new(
        src_ip, dst_ip, src_port, dst_port, transport, vlan_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_canonical_key_forward() {
        let (key, dir) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
            80,
            TransportProtocol::Tcp,
            None,
        );
        assert_eq!(dir, FlowDirection::Forward);
        assert_eq!(key.addr_a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(key.addr_b, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(key.port_a, 12345);
        assert_eq!(key.port_b, 80);
    }

    #[test]
    fn test_canonical_key_reverse() {
        let (key, dir) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            12345,
            TransportProtocol::Tcp,
            None,
        );
        assert_eq!(dir, FlowDirection::Reverse);
        assert_eq!(key.addr_a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(key.addr_b, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(key.port_a, 12345);
        assert_eq!(key.port_b, 80);
    }

    #[test]
    fn test_canonical_key_bidirectional_match() {
        let (key_fwd, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(81, 209, 179, 69)),
            50272,
            80,
            TransportProtocol::Tcp,
            None,
        );
        let (key_rev, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(81, 209, 179, 69)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            80,
            50272,
            TransportProtocol::Tcp,
            None,
        );
        assert_eq!(key_fwd, key_rev);
    }

    #[test]
    fn test_canonical_key_equal_ips_sort_by_port() {
        let (key, dir) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
            80,
            TransportProtocol::Tcp,
            None,
        );
        assert_eq!(dir, FlowDirection::Reverse);
        assert_eq!(key.port_a, 80);
        assert_eq!(key.port_b, 8080);
    }

    #[test]
    fn test_canonical_key_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        let (key_fwd, _) = CanonicalKey::new(src, dst, 1234, 80, TransportProtocol::Tcp, None);
        let (key_rev, _) = CanonicalKey::new(dst, src, 80, 1234, TransportProtocol::Tcp, None);
        assert_eq!(key_fwd, key_rev);
    }

    #[test]
    fn test_canonical_key_different_protocols() {
        let (key_tcp, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
            TransportProtocol::Tcp,
            None,
        );
        let (key_udp, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
            TransportProtocol::Udp,
            None,
        );
        assert_ne!(key_tcp, key_udp);
    }

    #[test]
    fn test_transport_protocol_from_ip() {
        assert_eq!(
            TransportProtocol::from_ip_protocol(6),
            TransportProtocol::Tcp
        );
        assert_eq!(
            TransportProtocol::from_ip_protocol(17),
            TransportProtocol::Udp
        );
        assert_eq!(
            TransportProtocol::from_ip_protocol(1),
            TransportProtocol::Icmp
        );
        assert_eq!(
            TransportProtocol::from_ip_protocol(58),
            TransportProtocol::Icmpv6
        );
        assert_eq!(
            TransportProtocol::from_ip_protocol(47),
            TransportProtocol::Other(47)
        );
    }

    #[test]
    fn test_canonical_key_display() {
        let (key, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
            TransportProtocol::Tcp,
            None,
        );
        let s = key.to_string();
        assert!(s.contains("10.0.0.1:1234"));
        assert!(s.contains("10.0.0.2:80"));
        assert!(s.contains("TCP"));
    }
}
