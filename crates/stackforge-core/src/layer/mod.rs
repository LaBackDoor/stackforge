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

    /// Returns a detailed field-by-field representation for show() output.
    /// Format: Vec<(field_name, field_value)>
    pub fn show_fields(&self, buf: &[u8]) -> Vec<(&'static str, String)> {
        match self {
            Self::Ethernet(l) => ethernet_show_fields(l, buf),
            Self::Dot3(l) => dot3_show_fields(l, buf),
            Self::Arp(l) => arp_show_fields(l, buf),
            Self::Ipv4(l) => ipv4_show_fields(l, buf),
            Self::Ipv6(l) => ipv6_show_fields(l, buf),
            Self::Icmp(l) => icmp_show_fields(l, buf),
            Self::Icmpv6(l) => icmpv6_show_fields(l, buf),
            Self::Tcp(l) => tcp_show_fields(l, buf),
            Self::Udp(l) => udp_show_fields(l, buf),
            Self::Dns(l) => dns_show_fields(l, buf),
            Self::Raw(l) => raw_show_fields(l, buf),
        }
    }

    /// Get a field value by name from this layer.
    /// Returns None if the field doesn't exist in this layer type.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match self {
            Self::Ethernet(l) => l.get_field(buf, name),
            Self::Dot3(l) => l.get_field(buf, name),
            Self::Arp(l) => l.get_field(buf, name),
            Self::Ipv4(l) => l.get_field(buf, name),
            Self::Tcp(l) => l.get_field(buf, name),
            // Placeholder layers don't have dynamic field access yet
            Self::Ipv6(_)
            | Self::Icmp(_)
            | Self::Icmpv6(_)
            | Self::Udp(_)
            | Self::Dns(_)
            | Self::Raw(_) => None,
        }
    }

    /// Set a field value by name in this layer.
    /// Returns None if the field doesn't exist in this layer type.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match self {
            Self::Ethernet(l) => l.set_field(buf, name, value),
            Self::Dot3(l) => l.set_field(buf, name, value),
            Self::Arp(l) => l.set_field(buf, name, value),
            Self::Ipv4(l) => l.set_field(buf, name, value),
            Self::Tcp(l) => l.set_field(buf, name, value),
            // Placeholder layers don't have dynamic field access yet
            Self::Ipv6(_)
            | Self::Icmp(_)
            | Self::Icmpv6(_)
            | Self::Udp(_)
            | Self::Dns(_)
            | Self::Raw(_) => None,
        }
    }

    /// Get the list of field names for this layer type.
    pub fn field_names(&self) -> &'static [&'static str] {
        match self {
            Self::Ethernet(_) => EthernetLayer::field_names(),
            Self::Dot3(_) => Dot3Layer::field_names(),
            Self::Arp(_) => ArpLayer::field_names(),
            Self::Ipv4(_) => Ipv4Layer::field_names(),
            Self::Tcp(_) => TcpLayer::field_names(),
            // Placeholder layers
            Self::Ipv6(_)
            | Self::Icmp(_)
            | Self::Icmpv6(_)
            | Self::Udp(_)
            | Self::Dns(_)
            | Self::Raw(_) => &[],
        }
    }
}

// ============================================================================
// Show Fields Implementations
// ============================================================================

fn ethernet_show_fields(l: &EthernetLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "dst",
        l.dst(buf)
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "src",
        l.src(buf)
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    let etype = l.ethertype(buf).unwrap_or(0);
    fields.push((
        "type",
        format!("{:#06x} ({})", etype, ethertype::name(etype)),
    ));
    fields
}

fn dot3_show_fields(l: &Dot3Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "dst",
        l.dst(buf)
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "src",
        l.src(buf)
            .map(|m| m.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "len",
        l.len_field(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields
}

fn arp_show_fields(l: &ArpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    let hwtype = l.hwtype(buf).unwrap_or(0);
    fields.push((
        "hwtype",
        format!("{:#06x} ({})", hwtype, arp::hardware_type::name(hwtype)),
    ));
    let ptype = l.ptype(buf).unwrap_or(0);
    fields.push(("ptype", format!("{:#06x}", ptype)));
    fields.push((
        "hwlen",
        l.hwlen(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "plen",
        l.plen(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    let op = l.op(buf).unwrap_or(0);
    fields.push(("op", format!("{} ({})", op, arp::opcode::name(op))));
    fields.push((
        "hwsrc",
        l.hwsrc_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "psrc",
        l.psrc_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "hwdst",
        l.hwdst_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "pdst",
        l.pdst_raw(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields
}

fn ipv4_show_fields(l: &Ipv4Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "version",
        l.version(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "ihl",
        l.ihl(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "tos",
        l.tos(buf)
            .map(|v| format!("{:#04x}", v))
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "len",
        l.total_len(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "id",
        l.id(buf)
            .map(|v| format!("{:#06x}", v))
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "flags",
        l.flags(buf)
            .map(|f| f.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "frag",
        l.frag_offset(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "ttl",
        l.ttl(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    let proto = l.protocol(buf).unwrap_or(0);
    fields.push(("proto", format!("{} ({})", proto, l.protocol_name(buf))));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map(|v| format!("{:#06x}", v))
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "src",
        l.src(buf)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "dst",
        l.dst(buf)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    // Options (if present)
    let opts_len = l.options_len(buf);
    if opts_len > 0 {
        fields.push(("options", format!("[{} bytes]", opts_len)));
    }
    fields
}

fn ipv6_show_fields(l: &Ipv6Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    let mut fields = Vec::new();
    if slice.len() >= 40 {
        let version = (slice[0] >> 4) & 0x0F;
        fields.push(("version", version.to_string()));
        let traffic_class = ((slice[0] & 0x0F) << 4) | ((slice[1] >> 4) & 0x0F);
        fields.push(("tc", format!("{:#04x}", traffic_class)));
        let flow_label =
            ((slice[1] as u32 & 0x0F) << 16) | ((slice[2] as u32) << 8) | (slice[3] as u32);
        fields.push(("fl", format!("{:#07x}", flow_label)));
        let payload_len = u16::from_be_bytes([slice[4], slice[5]]);
        fields.push(("plen", payload_len.to_string()));
        let nh = slice[6];
        fields.push(("nh", format!("{} ({})", nh, ipv4::protocol::to_name(nh))));
        let hlim = slice[7];
        fields.push(("hlim", hlim.to_string()));
        // src/dst addresses
        if slice.len() >= 40 {
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&slice[8..24]);
            dst_bytes.copy_from_slice(&slice[24..40]);
            let src = std::net::Ipv6Addr::from(src_bytes);
            let dst = std::net::Ipv6Addr::from(dst_bytes);
            fields.push(("src", src.to_string()));
            fields.push(("dst", dst.to_string()));
        }
    }
    fields
}

fn icmp_show_fields(l: &IcmpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    let mut fields = Vec::new();
    if !slice.is_empty() {
        let icmp_type = slice[0];
        let type_name = match icmp_type {
            0 => "echo-reply",
            3 => "dest-unreach",
            4 => "source-quench",
            5 => "redirect",
            8 => "echo-request",
            11 => "time-exceeded",
            12 => "parameter-problem",
            13 => "timestamp",
            14 => "timestamp-reply",
            _ => "unknown",
        };
        fields.push(("type", format!("{} ({})", icmp_type, type_name)));
    }
    if slice.len() > 1 {
        fields.push(("code", slice[1].to_string()));
    }
    if slice.len() >= 4 {
        let chksum = u16::from_be_bytes([slice[2], slice[3]]);
        fields.push(("chksum", format!("{:#06x}", chksum)));
    }
    if slice.len() >= 8 {
        let id = u16::from_be_bytes([slice[4], slice[5]]);
        let seq = u16::from_be_bytes([slice[6], slice[7]]);
        fields.push(("id", format!("{:#06x}", id)));
        fields.push(("seq", seq.to_string()));
    }
    fields
}

fn icmpv6_show_fields(l: &Icmpv6Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    let mut fields = Vec::new();
    if !slice.is_empty() {
        let icmp_type = slice[0];
        let type_name = match icmp_type {
            1 => "dest-unreach",
            2 => "pkt-too-big",
            3 => "time-exceeded",
            4 => "param-problem",
            128 => "echo-request",
            129 => "echo-reply",
            133 => "router-solicit",
            134 => "router-advert",
            135 => "neighbor-solicit",
            136 => "neighbor-advert",
            _ => "unknown",
        };
        fields.push(("type", format!("{} ({})", icmp_type, type_name)));
    }
    if slice.len() > 1 {
        fields.push(("code", slice[1].to_string()));
    }
    if slice.len() >= 4 {
        let chksum = u16::from_be_bytes([slice[2], slice[3]]);
        fields.push(("chksum", format!("{:#06x}", chksum)));
    }
    fields
}

fn tcp_show_fields(l: &TcpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "sport",
        l.src_port(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "dport",
        l.dst_port(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "seq",
        l.seq(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "ack",
        l.ack(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "dataofs",
        l.data_offset(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "reserved",
        l.reserved(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "flags",
        l.flags(buf)
            .map(|f| f.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "window",
        l.window(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map(|v| format!("{:#06x}", v))
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "urgptr",
        l.urgent_ptr(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".into()),
    ));
    // Options (if present)
    let opts_len = l.options_len(buf);
    if opts_len > 0 {
        fields.push(("options", format!("[{} bytes]", opts_len)));
    }
    fields
}

fn udp_show_fields(l: &UdpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    let mut fields = Vec::new();
    if slice.len() >= 2 {
        let sport = u16::from_be_bytes([slice[0], slice[1]]);
        fields.push(("sport", sport.to_string()));
    }
    if slice.len() >= 4 {
        let dport = u16::from_be_bytes([slice[2], slice[3]]);
        fields.push(("dport", dport.to_string()));
    }
    if slice.len() >= 6 {
        let len = u16::from_be_bytes([slice[4], slice[5]]);
        fields.push(("len", len.to_string()));
    }
    if slice.len() >= 8 {
        let chksum = u16::from_be_bytes([slice[6], slice[7]]);
        fields.push(("chksum", format!("{:#06x}", chksum)));
    }
    fields
}

fn dns_show_fields(l: &DnsLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    let mut fields = Vec::new();
    if slice.len() >= 12 {
        let id = u16::from_be_bytes([slice[0], slice[1]]);
        fields.push(("id", format!("{:#06x}", id)));
        let flags = u16::from_be_bytes([slice[2], slice[3]]);
        let qr = if (flags & 0x8000) != 0 {
            "response"
        } else {
            "query"
        };
        fields.push(("qr", qr.to_string()));
        let opcode = (flags >> 11) & 0x0F;
        fields.push(("opcode", opcode.to_string()));
        let qdcount = u16::from_be_bytes([slice[4], slice[5]]);
        fields.push(("qdcount", qdcount.to_string()));
        let ancount = u16::from_be_bytes([slice[6], slice[7]]);
        fields.push(("ancount", ancount.to_string()));
        let nscount = u16::from_be_bytes([slice[8], slice[9]]);
        fields.push(("nscount", nscount.to_string()));
        let arcount = u16::from_be_bytes([slice[10], slice[11]]);
        fields.push(("arcount", arcount.to_string()));
    }
    fields
}

fn raw_show_fields(l: &RawLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let slice = l.index.slice(buf);
    vec![("load", format!("[{} bytes]", slice.len()))]
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
