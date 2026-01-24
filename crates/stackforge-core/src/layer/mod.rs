//! Layer definitions and enum dispatch for protocol handling.
//!
//! This module implements the "Lazy Zero-Copy View" architecture where layers
//! are represented as lightweight views into a raw packet buffer.

pub mod arp;
pub mod bindings;
pub mod ethernet;
pub mod field;
pub mod ipv4;
pub mod neighbor;
pub mod tcp;

use std::ops::Range;

// Re-export layer types
pub use arp::{ArpBuilder, ArpLayer};
pub use bindings::{LAYER_BINDINGS, LayerBinding};
pub use ethernet::{Dot3Builder, Dot3Layer, EthernetBuilder, EthernetLayer};
pub use field::{BytesField, Field, FieldDesc, FieldError, FieldType, FieldValue, MacAddress};
pub use ipv4::{Ipv4Builder, Ipv4Flags, Ipv4Layer, Ipv4Options, Ipv4Route};
pub use neighbor::{NeighborCache, NeighborResolver};
pub use tcp::{
    TCP_FIELDS, TCP_MAX_HEADER_LEN, TCP_MIN_HEADER_LEN, TCP_SERVICES, TcpAoValue, TcpBuilder,
    TcpFlags, TcpLayer, TcpOption, TcpOptionKind, TcpOptions, TcpOptionsBuilder, TcpSackBlock,
    TcpTimestamp, service_name, service_port, tcp_checksum, tcp_checksum_ipv4, verify_tcp_checksum,
};

/// Identifies the type of network protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LayerKind {
    Ethernet = 0,
    Dot3 = 1,
    Arp = 2,
    Ipv4 = 3,
    Ipv6 = 4,
    Icmp = 5,
    Icmpv6 = 6,
    Tcp = 7,
    Udp = 8,
    Dns = 9,
    Dot1Q = 10,
    Dot1AD = 11,
    Dot1AH = 12,
    LLC = 13,
    SNAP = 14,
    Raw = 255,
}

impl LayerKind {
    #[inline]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Dot3 => "802.3",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::Dot1Q => "802.1Q",
            Self::Dot1AD => "802.1AD",
            Self::Dot1AH => "802.1AH",
            Self::LLC => "LLC",
            Self::SNAP => "SNAP",
            Self::Raw => "Raw",
        }
    }

    #[inline]
    pub const fn min_header_size(&self) -> usize {
        match self {
            Self::Ethernet | Self::Dot3 => ethernet::ETHERNET_HEADER_LEN,
            Self::Arp => arp::ARP_HEADER_LEN,
            Self::Ipv4 => ipv4::IPV4_MIN_HEADER_LEN,
            Self::Ipv6 => 40,
            Self::Icmp | Self::Icmpv6 => 8,
            Self::Tcp => tcp::TCP_MIN_HEADER_LEN,
            Self::Udp => 8,
            Self::Dns => 12,
            Self::Dot1Q => 4,
            Self::Dot1AD => 4,
            Self::Dot1AH => 6,
            Self::LLC => 3,
            Self::SNAP => 5,
            Self::Raw => 0,
        }
    }

    /// Check if this is a link layer protocol
    #[inline]
    pub const fn is_link_layer(&self) -> bool {
        matches!(
            self,
            Self::Ethernet | Self::Dot3 | Self::Dot1Q | Self::Dot1AD | Self::Dot1AH
        )
    }

    /// Check if this is a network layer protocol
    #[inline]
    pub const fn is_network_layer(&self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6 | Self::Arp)
    }

    /// Check if this is a transport layer protocol
    #[inline]
    pub const fn is_transport_layer(&self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::Icmp | Self::Icmpv6)
    }
}

impl std::fmt::Display for LayerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Index information for a layer within a packet buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerIndex {
    pub kind: LayerKind,
    pub start: usize,
    pub end: usize,
}

impl LayerIndex {
    #[inline]
    pub const fn new(kind: LayerKind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }

    #[inline]
    pub const fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Get the bytes for this layer from a buffer
    #[inline]
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end.min(buf.len())]
    }

    /// Get payload bytes (everything after this layer)
    #[inline]
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.end.min(buf.len())..]
    }
}

/// Trait for types that can act as a network protocol layer.
///
/// This trait defines the core interface for all protocol layers,
/// including methods for packet matching (hashret/answers) and
/// padding extraction
pub trait Layer {
    /// Get the kind of this layer
    fn kind(&self) -> LayerKind;

    /// Get a human-readable summary of this layer
    fn summary(&self, data: &[u8]) -> String;

    /// Get the header length for this layer
    fn header_len(&self, data: &[u8]) -> usize;

    /// Compute a hash for packet matching.
    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        vec![]
    }

    /// Check if this packet answers another packet.
    fn answers(&self, _data: &[u8], _other: &Self, _other_data: &[u8]) -> bool {
        false
    }

    /// Extract padding from the packet.
    fn extract_padding<'a>(&self, data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let header_len = self.header_len(data);
        (&data[header_len..], &[])
    }

    /// Get the list of field names for this layer
    fn field_names(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Enum dispatch for protocol layers.
#[derive(Debug, Clone)]
pub enum LayerEnum {
    Ethernet(EthernetLayer),
    Dot3(Dot3Layer),
    Arp(ArpLayer),
    Ipv4(Ipv4Layer),
    Ipv6(Ipv6Layer),
    Icmp(IcmpLayer),
    Icmpv6(Icmpv6Layer),
    Tcp(TcpLayer),
    Udp(UdpLayer),
    Dns(DnsLayer),
    Raw(RawLayer),
}

impl LayerEnum {
    #[inline]
    pub fn kind(&self) -> LayerKind {
        match self {
            Self::Ethernet(_) => LayerKind::Ethernet,
            Self::Dot3(_) => LayerKind::Dot3,
            Self::Arp(_) => LayerKind::Arp,
            Self::Ipv4(_) => LayerKind::Ipv4,
            Self::Ipv6(_) => LayerKind::Ipv6,
            Self::Icmp(_) => LayerKind::Icmp,
            Self::Icmpv6(_) => LayerKind::Icmpv6,
            Self::Tcp(_) => LayerKind::Tcp,
            Self::Udp(_) => LayerKind::Udp,
            Self::Dns(_) => LayerKind::Dns,
            Self::Raw(_) => LayerKind::Raw,
        }
    }

    #[inline]
    pub fn index(&self) -> &LayerIndex {
        match self {
            Self::Ethernet(l) => &l.index,
            Self::Dot3(l) => &l.index,
            Self::Arp(l) => &l.index,
            Self::Ipv4(l) => &l.index,
            Self::Ipv6(l) => &l.index,
            Self::Icmp(l) => &l.index,
            Self::Icmpv6(l) => &l.index,
            Self::Tcp(l) => &l.index,
            Self::Udp(l) => &l.index,
            Self::Dns(l) => &l.index,
            Self::Raw(l) => &l.index,
        }
    }

    pub fn summary(&self, buf: &[u8]) -> String {
        match self {
            Self::Ethernet(l) => l.summary(buf),
            Self::Dot3(l) => l.summary(buf),
            Self::Arp(l) => l.summary(buf),
            Self::Ipv4(l) => l.summary(buf),
            Self::Ipv6(l) => l.summary(buf),
            Self::Icmp(l) => l.summary(buf),
            Self::Icmpv6(l) => l.summary(buf),
            Self::Tcp(l) => l.summary(buf),
            Self::Udp(l) => l.summary(buf),
            Self::Dns(l) => l.summary(buf),
            Self::Raw(l) => l.summary(buf),
        }
    }

    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        match self {
            Self::Ethernet(l) => l.hashret(buf),
            Self::Arp(l) => l.hashret(buf),
            Self::Ipv4(l) => l.hashret(buf),
            Self::Tcp(l) => l.hashret(buf),
            _ => vec![],
        }
    }

    pub fn header_len(&self, buf: &[u8]) -> usize {
        match self {
            Self::Ethernet(l) => l.header_len(buf),
            Self::Dot3(_) => ethernet::ETHERNET_HEADER_LEN,
            Self::Arp(l) => l.header_len(buf),
            Self::Ipv4(l) => l.header_len(buf),
            Self::Ipv6(l) => l.header_len(buf),
            Self::Icmp(l) => l.header_len(buf),
            Self::Icmpv6(l) => l.header_len(buf),
            Self::Tcp(l) => l.header_len(buf),
            Self::Udp(l) => l.header_len(buf),
            Self::Dns(l) => l.header_len(buf),
            Self::Raw(l) => l.header_len(buf),
        }
    }
}

// Placeholder layer structs (to be fully implemented in later weeks)
#[derive(Debug, Clone)]
pub struct Ipv6Layer {
    pub index: LayerIndex,
}

impl Ipv6Layer {
    pub fn summary(&self, _buf: &[u8]) -> String {
        "IPv6".to_string()
    }
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        40
    }
}

#[derive(Debug, Clone)]
pub struct IcmpLayer {
    pub index: LayerIndex,
}

impl IcmpLayer {
    pub fn summary(&self, buf: &[u8]) -> String {
        let slice = self.index.slice(buf);
        if !slice.is_empty() {
            let icmp_type = slice[0];
            format!("ICMP type {}", icmp_type)
        } else {
            "ICMP".to_string()
        }
    }
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        8
    }
}

#[derive(Debug, Clone)]
pub struct Icmpv6Layer {
    pub index: LayerIndex,
}

impl Icmpv6Layer {
    pub fn summary(&self, _buf: &[u8]) -> String {
        "ICMPv6".to_string()
    }
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        8
    }
}

// TcpLayer is now imported from the tcp module

#[derive(Debug, Clone)]
pub struct UdpLayer {
    pub index: LayerIndex,
}

impl UdpLayer {
    pub fn summary(&self, buf: &[u8]) -> String {
        let slice = self.index.slice(buf);
        if slice.len() >= 4 {
            let src_port = u16::from_be_bytes([slice[0], slice[1]]);
            let dst_port = u16::from_be_bytes([slice[2], slice[3]]);
            format!("UDP {} > {}", src_port, dst_port)
        } else {
            "UDP".to_string()
        }
    }
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        8
    }
}

#[derive(Debug, Clone)]
pub struct DnsLayer {
    pub index: LayerIndex,
}

impl DnsLayer {
    pub fn summary(&self, _buf: &[u8]) -> String {
        "DNS".to_string()
    }
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        12
    }
}

#[derive(Debug, Clone)]
pub struct RawLayer {
    pub index: LayerIndex,
}

impl RawLayer {
    pub fn summary(&self, buf: &[u8]) -> String {
        format!("Raw ({} bytes)", self.index.slice(buf).len())
    }
    pub fn header_len(&self, buf: &[u8]) -> usize {
        self.index.slice(buf).len()
    }
}

/// EtherType constants
pub mod ethertype {
    use crate::LayerKind;

    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86DD;
    pub const VLAN: u16 = 0x8100;
    pub const DOT1AD: u16 = 0x88A8;
    pub const DOT1AH: u16 = 0x88E7;
    pub const MACSEC: u16 = 0x88E5;
    pub const LOOPBACK: u16 = 0x9000;

    pub fn name(t: u16) -> &'static str {
        match t {
            IPV4 => "IPv4",
            ARP => "ARP",
            IPV6 => "IPv6",
            VLAN => "802.1Q",
            DOT1AD => "802.1AD",
            DOT1AH => "802.1AH",
            MACSEC => "MACsec",
            LOOPBACK => "Loopback",
            _ => "Unknown",
        }
    }

    pub fn to_layer_kind(t: u16) -> Option<LayerKind> {
        match t {
            IPV4 => Some(LayerKind::Ipv4),
            ARP => Some(LayerKind::Arp),
            IPV6 => Some(LayerKind::Ipv6),
            VLAN => Some(LayerKind::Dot1Q),
            DOT1AD => Some(LayerKind::Dot1AD),
            DOT1AH => Some(LayerKind::Dot1AH),
            _ => None,
        }
    }

    pub fn from_layer_kind(kind: LayerKind) -> Option<u16> {
        match kind {
            LayerKind::Ipv4 => Some(IPV4),
            LayerKind::Arp => Some(ARP),
            LayerKind::Ipv6 => Some(IPV6),
            LayerKind::Dot1Q => Some(VLAN),
            LayerKind::Dot1AD => Some(DOT1AD),
            LayerKind::Dot1AH => Some(DOT1AH),
            _ => None,
        }
    }
}

/// IP protocol numbers
pub mod ip_protocol {
    pub use crate::layer::ipv4::protocol::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_kind() {
        assert_eq!(LayerKind::Ethernet.name(), "Ethernet");
        assert_eq!(LayerKind::Arp.min_header_size(), 28);
        assert!(LayerKind::Ethernet.is_link_layer());
        assert!(LayerKind::Ipv4.is_network_layer());
        assert!(LayerKind::Tcp.is_transport_layer());
    }

    #[test]
    fn test_layer_index() {
        let idx = LayerIndex::new(LayerKind::Ethernet, 0, 14);
        assert_eq!(idx.len(), 14);
        assert_eq!(idx.range(), 0..14);

        let buf = vec![0u8; 100];
        assert_eq!(idx.slice(&buf).len(), 14);
        assert_eq!(idx.payload(&buf).len(), 86);
    }

    #[test]
    fn test_ethertype_conversions() {
        assert_eq!(ethertype::to_layer_kind(0x0800), Some(LayerKind::Ipv4));
        assert_eq!(ethertype::from_layer_kind(LayerKind::Arp), Some(0x0806));
    }
}
