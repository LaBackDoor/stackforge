//! Layer definitions and enum dispatch for protocol handling.
//!
//! This module implements the "Lazy Zero-Copy View" architecture where layers
//! are represented as lightweight views into a raw packet buffer.

pub mod arp;
pub mod bindings;
pub mod dns;
pub mod dot11;
pub mod dot15d4;
pub mod ethernet;
pub mod field;
pub mod field_ext;
pub mod ftp;
pub mod generic;
pub mod http;
pub mod http2;
pub mod icmp;
pub mod icmpv6;
pub mod imap;
pub mod ipv4;
pub mod ipv6;
pub mod l2tp;
pub mod modbus;
pub mod mqtt;
pub mod mqttsn;
pub mod neighbor;
pub mod pop3;
pub mod quic;
pub mod raw;
pub mod smtp;
pub mod ssh;
pub mod stack;
pub mod tcp;
pub mod tftp;
pub mod tls;
pub mod udp;
pub mod zwave;

use std::ops::Range;

// Re-export layer types
pub use arp::{ArpBuilder, ArpLayer};
pub use bindings::{LAYER_BINDINGS, LayerBinding};
pub use ethernet::{Dot3Builder, Dot3Layer, EthernetBuilder, EthernetLayer};
pub use field::{BytesField, Field, FieldDesc, FieldError, FieldType, FieldValue, MacAddress};
pub use ftp::{
    FTP_CONTROL_PORT, FTP_DATA_PORT, FTP_FIELD_NAMES, FTP_MIN_HEADER_LEN, FtpBuilder, FtpLayer,
    is_ftp_payload,
};
pub use http::{HTTP_FIELD_NAMES, HttpLayer, HttpRequestBuilder, HttpResponseBuilder};
pub use http2::{HTTP2_FIELD_NAMES, Http2Builder, Http2FrameBuilder, Http2Layer};
pub use icmp::{ICMP_MIN_HEADER_LEN, IcmpBuilder, IcmpLayer, icmp_checksum, verify_icmp_checksum};
pub use icmpv6::{
    ICMPV6_MIN_HEADER_LEN, Icmpv6Builder, Icmpv6Layer, icmpv6_checksum, verify_icmpv6_checksum,
};
pub use imap::{
    IMAP_FIELD_NAMES, IMAP_MIN_HEADER_LEN, IMAP_PORT, ImapBuilder, ImapLayer, is_imap_payload,
};
pub use ipv4::{Ipv4Builder, Ipv4Flags, Ipv4Layer, Ipv4Options, Ipv4Route};
pub use ipv6::{IPV6_HEADER_LEN, Ipv6Builder, Ipv6Layer};
pub use l2tp::{L2TP_FIELD_NAMES, L2TP_MIN_HEADER_LEN, L2TP_PORT, L2tpBuilder, L2tpLayer};
pub use modbus::{
    MODBUS_FIELD_NAMES, MODBUS_MIN_HEADER_LEN, MODBUS_TCP_PORT, ModbusBuilder, ModbusLayer,
    is_modbus_tcp_payload,
};
pub use mqtt::{
    MQTT_FIELD_NAMES, MQTT_MIN_HEADER_LEN, MQTT_PORT, MqttBuilder, MqttLayer, is_mqtt_payload,
};
pub use mqttsn::{
    MQTTSN_FIELD_NAMES, MQTTSN_MIN_HEADER_LEN, MQTTSN_PORT, MqttSnBuilder, MqttSnLayer,
    is_mqttsn_payload,
};
pub use neighbor::{NeighborCache, NeighborResolver};
pub use pop3::{
    POP3_FIELD_NAMES, POP3_MIN_HEADER_LEN, POP3_PORT, Pop3Builder, Pop3Layer, is_pop3_payload,
};
pub use raw::{RAW_FIELDS, RawBuilder, RawLayer};
pub use smtp::{
    SMTP_FIELD_NAMES, SMTP_MIN_HEADER_LEN, SMTP_PORT, SmtpBuilder, SmtpLayer, is_smtp_payload,
};
pub use ssh::{SSH_BINARY_HEADER_LEN, SSH_PORT, SshBuilder, SshLayer};
pub use stack::{IntoLayerStackEntry, LayerStack, LayerStackEntry};
pub use tcp::{
    TCP_FIELDS, TCP_MAX_HEADER_LEN, TCP_MIN_HEADER_LEN, TCP_SERVICES, TcpAoValue, TcpBuilder,
    TcpFlags, TcpLayer, TcpOption, TcpOptionKind, TcpOptions, TcpOptionsBuilder, TcpSackBlock,
    TcpTimestamp, service_name, service_port, tcp_checksum, tcp_checksum_ipv4, verify_tcp_checksum,
};
pub use tftp::{TFTP_MIN_HEADER_LEN, TFTP_PORT, TftpBuilder, TftpLayer, is_tftp_payload};
pub use tls::{
    TLS_FIELDS, TLS_PORT, TLS_RECORD_HEADER_LEN, TlsAlertBuilder, TlsCcsBuilder, TlsContentType,
    TlsLayer, TlsRecordBuilder, TlsVersion,
};
pub use udp::{
    UDP_HEADER_LEN, UdpBuilder, UdpLayer, udp_checksum_ipv4, udp_checksum_ipv6,
    verify_udp_checksum_ipv4, verify_udp_checksum_ipv6,
};
pub use zwave::{
    ZWAVE_FIELD_NAMES, ZWAVE_HEADER_LEN, ZWAVE_MIN_HEADER_LEN, ZWaveBuilder, ZWaveLayer,
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
    Ssh = 15,
    Tls = 16,
    Dot15d4 = 17,
    Dot15d4Fcs = 18,
    Dot11 = 19,
    Http = 20,
    Quic = 21,
    Generic = 22,
    Http2 = 23,
    L2tp = 24,
    Mqtt = 25,
    MqttSn = 26,
    Modbus = 27,
    ZWave = 28,
    Ftp = 29,
    Tftp = 30,
    Smtp = 31,
    Pop3 = 32,
    Imap = 33,
    Raw = 255,
}

impl LayerKind {
    #[inline]
    #[must_use]
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
            Self::Ssh => "SSH",
            Self::Tls => "TLS",
            Self::Dot15d4 => "802.15.4",
            Self::Dot15d4Fcs => "802.15.4 FCS",
            Self::Dot11 => "802.11",
            Self::Http => "HTTP",
            Self::Quic => "QUIC",
            Self::Generic => "Generic",
            Self::Http2 => "HTTP/2",
            Self::L2tp => "L2TP",
            Self::Mqtt => "MQTT",
            Self::MqttSn => "MQTT-SN",
            Self::Modbus => "Modbus",
            Self::ZWave => "Z-Wave",
            Self::Ftp => "FTP",
            Self::Tftp => "TFTP",
            Self::Smtp => "SMTP",
            Self::Pop3 => "POP3",
            Self::Imap => "IMAP",
            Self::Raw => "Raw",
        }
    }

    #[inline]
    #[must_use]
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
            Self::Ssh => ssh::SSH_BINARY_HEADER_LEN,
            Self::Tls => tls::TLS_RECORD_HEADER_LEN,
            Self::Dot15d4 => 3,    // minimum: 2 bytes FCF + 1 byte seqnum
            Self::Dot15d4Fcs => 5, // minimum: 2 bytes FCF + 1 byte seqnum + 2 bytes FCS
            Self::Dot11 => dot11::DOT11_MIN_HEADER_LEN,
            Self::Http => 14, // minimum: "GET / HTTP/1.1\r\n\r\n" is ~18 bytes, but use 14 as min
            Self::Quic => quic::QUIC_MIN_HEADER_LEN,
            Self::Generic => 0,
            Self::Http2 => 9, // 9-byte frame header
            Self::L2tp => l2tp::L2TP_MIN_HEADER_LEN,
            Self::Mqtt => mqtt::MQTT_MIN_HEADER_LEN,
            Self::MqttSn => mqttsn::MQTTSN_MIN_HEADER_LEN,
            Self::Modbus => modbus::MODBUS_MIN_HEADER_LEN,
            Self::ZWave => zwave::ZWAVE_MIN_HEADER_LEN,
            Self::Ftp => ftp::FTP_MIN_HEADER_LEN,
            Self::Tftp => tftp::TFTP_MIN_HEADER_LEN,
            Self::Smtp => smtp::SMTP_MIN_HEADER_LEN,
            Self::Pop3 => pop3::POP3_MIN_HEADER_LEN,
            Self::Imap => imap::IMAP_MIN_HEADER_LEN,
            Self::Raw => 0,
        }
    }

    /// Check if this is a link layer protocol
    #[inline]
    #[must_use]
    pub const fn is_link_layer(&self) -> bool {
        matches!(
            self,
            Self::Ethernet | Self::Dot3 | Self::Dot1Q | Self::Dot1AD | Self::Dot1AH
        )
    }

    /// Check if this is a network layer protocol
    #[inline]
    #[must_use]
    pub const fn is_network_layer(&self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6 | Self::Arp)
    }

    /// Check if this is a transport layer protocol
    #[inline]
    #[must_use]
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
    #[must_use]
    pub const fn new(kind: LayerKind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }

    #[inline]
    #[must_use]
    pub const fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Get the bytes for this layer from a buffer
    #[inline]
    #[must_use]
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end.min(buf.len())]
    }

    /// Get mutable bytes for this layer from a buffer
    #[inline]
    pub fn slice_mut<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        let end = self.end.min(buf.len());
        &mut buf[self.start..end]
    }

    /// Get payload bytes (everything after this layer)
    #[inline]
    #[must_use]
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
    Ssh(SshLayer),
    Tls(TlsLayer),
    Dot15d4(dot15d4::Dot15d4Layer),
    Dot15d4Fcs(dot15d4::Dot15d4FcsLayer),
    Dot11(dot11::Dot11Layer),
    Http(http::HttpLayer),
    Http2(http2::Http2Layer),
    Quic(quic::QuicLayer),
    L2tp(l2tp::L2tpLayer),
    Mqtt(mqtt::MqttLayer),
    MqttSn(mqttsn::MqttSnLayer),
    Modbus(modbus::ModbusLayer),
    ZWave(zwave::ZWaveLayer),
    Ftp(ftp::FtpLayer),
    Tftp(tftp::TftpLayer),
    Smtp(smtp::SmtpLayer),
    Pop3(pop3::Pop3Layer),
    Imap(imap::ImapLayer),
    Raw(RawLayer),
}

impl LayerEnum {
    #[inline]
    #[must_use]
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
            Self::Ssh(_) => LayerKind::Ssh,
            Self::Tls(_) => LayerKind::Tls,
            Self::Dot15d4(_) => LayerKind::Dot15d4,
            Self::Dot15d4Fcs(_) => LayerKind::Dot15d4Fcs,
            Self::Dot11(_) => LayerKind::Dot11,
            Self::Http(_) => LayerKind::Http,
            Self::Http2(_) => LayerKind::Http2,
            Self::Quic(_) => LayerKind::Quic,
            Self::L2tp(_) => LayerKind::L2tp,
            Self::Mqtt(_) => LayerKind::Mqtt,
            Self::MqttSn(_) => LayerKind::MqttSn,
            Self::Modbus(_) => LayerKind::Modbus,
            Self::ZWave(_) => LayerKind::ZWave,
            Self::Ftp(_) => LayerKind::Ftp,
            Self::Tftp(_) => LayerKind::Tftp,
            Self::Smtp(_) => LayerKind::Smtp,
            Self::Pop3(_) => LayerKind::Pop3,
            Self::Imap(_) => LayerKind::Imap,
            Self::Raw(_) => LayerKind::Raw,
        }
    }

    #[inline]
    #[must_use]
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
            Self::Ssh(l) => &l.index,
            Self::Tls(l) => &l.index,
            Self::Dot15d4(l) => &l.index,
            Self::Dot15d4Fcs(l) => &l.index,
            Self::Dot11(l) => &l.index,
            Self::Http(l) => &l.index,
            Self::Http2(l) => &l.index,
            Self::Quic(l) => &l.index,
            Self::L2tp(l) => &l.index,
            Self::Mqtt(l) => &l.index,
            Self::MqttSn(l) => &l.index,
            Self::Modbus(l) => &l.index,
            Self::ZWave(l) => &l.index,
            Self::Ftp(l) => &l.index,
            Self::Tftp(l) => &l.index,
            Self::Smtp(l) => &l.index,
            Self::Pop3(l) => &l.index,
            Self::Imap(l) => &l.index,
            Self::Raw(l) => &l.index,
        }
    }

    #[must_use]
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
            Self::Ssh(l) => l.summary(buf),
            Self::Tls(l) => l.summary(buf),
            Self::Dot15d4(l) => l.summary(buf),
            Self::Dot15d4Fcs(l) => l.summary(buf),
            Self::Dot11(l) => l.summary(buf),
            Self::Http(l) => l.summary(buf),
            Self::Http2(l) => l.summary(buf),
            Self::Quic(l) => l.summary(buf),
            Self::L2tp(l) => l.summary(buf),
            Self::Mqtt(l) => l.summary(buf),
            Self::MqttSn(l) => l.summary(buf),
            Self::Modbus(l) => l.summary(buf),
            Self::ZWave(l) => l.summary(buf),
            Self::Ftp(l) => l.summary(buf),
            Self::Tftp(l) => l.summary(buf),
            Self::Smtp(l) => l.summary(buf),
            Self::Pop3(l) => l.summary(buf),
            Self::Imap(l) => l.summary(buf),
            Self::Raw(l) => l.summary(buf),
        }
    }

    #[must_use]
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        match self {
            Self::Ethernet(l) => l.hashret(buf),
            Self::Arp(l) => l.hashret(buf),
            Self::Ipv4(l) => l.hashret(buf),
            Self::Icmp(l) => l.hashret(buf),
            Self::Tcp(l) => l.hashret(buf),
            Self::Udp(l) => l.hashret(buf),
            Self::Dot15d4(l) => l.hashret(buf),
            Self::Dot15d4Fcs(l) => l.hashret(buf),
            Self::Dot11(l) => l.hashret(buf),
            _ => vec![],
        }
    }

    #[must_use]
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
            Self::Ssh(l) => l.header_len(buf),
            Self::Tls(l) => l.header_len(buf),
            Self::Dot15d4(l) => l.header_len(buf),
            Self::Dot15d4Fcs(l) => l.header_len(buf),
            Self::Dot11(l) => l.header_len(buf),
            Self::Http(l) => l.header_len(buf),
            Self::Http2(l) => l.header_len(buf),
            Self::Quic(l) => l.header_len(buf),
            Self::L2tp(l) => l.header_len(buf),
            Self::Mqtt(l) => l.header_len(buf),
            Self::MqttSn(l) => l.header_len(buf),
            Self::Modbus(l) => l.header_len(buf),
            Self::ZWave(l) => l.header_len(buf),
            Self::Ftp(l) => l.header_len(buf),
            Self::Tftp(l) => l.header_len(buf),
            Self::Smtp(l) => l.header_len(buf),
            Self::Pop3(l) => l.header_len(buf),
            Self::Imap(l) => l.header_len(buf),
            Self::Raw(l) => l.header_len(buf),
        }
    }

    /// Returns a detailed field-by-field representation for `show()` output.
    /// Format: Vec<(`field_name`, `field_value`)>
    #[must_use]
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
            Self::Ssh(l) => ssh_show_fields(l, buf),
            Self::Tls(l) => tls_show_fields(l, buf),
            Self::Dot15d4(l) => dot15d4_show_fields(l, buf),
            Self::Dot15d4Fcs(l) => dot15d4_fcs_show_fields(l, buf),
            Self::Dot11(l) => dot11_show_fields(l, buf),
            Self::Http(l) => http_show_fields(l, buf),
            Self::Http2(l) => http2_show_fields(l, buf),
            Self::Quic(l) => quic_show_fields(l, buf),
            Self::L2tp(l) => l2tp_show_fields(l, buf),
            Self::Mqtt(l) => mqtt_show_fields(l, buf),
            Self::MqttSn(l) => mqttsn_show_fields(l, buf),
            Self::Modbus(l) => modbus_show_fields(l, buf),
            Self::ZWave(l) => zwave_show_fields(l, buf),
            Self::Ftp(l) => ftp::ftp_show_fields(l, buf),
            Self::Tftp(l) => tftp::tftp_show_fields(l, buf),
            Self::Smtp(l) => smtp::smtp_show_fields(l, buf),
            Self::Pop3(l) => pop3::pop3_show_fields(l, buf),
            Self::Imap(l) => imap::imap_show_fields(l, buf),
            Self::Raw(l) => raw::raw_show_fields(l, buf),
        }
    }

    /// Get a field value by name from this layer.
    /// Returns None if the field doesn't exist in this layer type.
    #[must_use]
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match self {
            Self::Ethernet(l) => l.get_field(buf, name),
            Self::Dot3(l) => l.get_field(buf, name),
            Self::Arp(l) => l.get_field(buf, name),
            Self::Ipv4(l) => l.get_field(buf, name),
            Self::Icmp(l) => l.get_field(buf, name),
            Self::Tcp(l) => l.get_field(buf, name),
            Self::Udp(l) => l.get_field(buf, name),
            Self::Raw(l) => l.get_field(buf, name),
            Self::Ssh(l) => l.get_field(buf, name),
            Self::Tls(l) => l.get_field(buf, name),
            Self::Dns(l) => l.get_field(buf, name),
            Self::Dot15d4(l) => l.get_field(buf, name),
            Self::Dot15d4Fcs(l) => l.get_field(buf, name),
            Self::Dot11(l) => l.get_field(buf, name),
            Self::Http(l) => l.get_field(buf, name),
            Self::Http2(l) => l.get_field(buf, name),
            Self::Quic(l) => l.get_field(buf, name),
            Self::Ipv6(l) => l.get_field(buf, name),
            Self::Icmpv6(l) => l.get_field(buf, name),
            Self::L2tp(l) => l.get_field(buf, name),
            Self::Mqtt(l) => l.get_field(buf, name),
            Self::MqttSn(l) => l.get_field(buf, name),
            Self::Modbus(l) => l.get_field(buf, name),
            Self::ZWave(l) => l.get_field(buf, name),
            Self::Ftp(l) => l.get_field(buf, name),
            Self::Tftp(l) => l.get_field(buf, name),
            Self::Smtp(l) => l.get_field(buf, name),
            Self::Pop3(l) => l.get_field(buf, name),
            Self::Imap(l) => l.get_field(buf, name),
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
            Self::Icmp(l) => l.set_field(buf, name, value),
            Self::Tcp(l) => l.set_field(buf, name, value),
            Self::Udp(l) => l.set_field(buf, name, value),
            Self::Raw(l) => l.set_field(buf, name, value),
            Self::Ssh(l) => l.set_field(buf, name, value),
            Self::Tls(l) => l.set_field(buf, name, value),
            Self::Dns(l) => l.set_field(buf, name, value),
            Self::Dot15d4(l) => l.set_field(buf, name, value),
            Self::Dot15d4Fcs(l) => l.set_field(buf, name, value),
            Self::Dot11(l) => l.set_field(buf, name, value),
            Self::Http(_) => None, // HTTP fields are read-only (text protocol)
            Self::Http2(_) => None, // HTTP/2 fields are read-only via this interface
            Self::Quic(l) => l.set_field(buf, name, value),
            Self::Ipv6(l) => l.set_field(buf, name, value),
            Self::Icmpv6(l) => l.set_field(buf, name, value),
            Self::L2tp(l) => l.set_field(buf, name, value),
            Self::Mqtt(l) => l.set_field(buf, name, value),
            Self::MqttSn(l) => l.set_field(buf, name, value),
            Self::Modbus(l) => l.set_field(buf, name, value),
            Self::ZWave(l) => l.set_field(buf, name, value),
            Self::Ftp(_) => None,  // FTP fields are read-only (text protocol)
            Self::Tftp(_) => None, // TFTP fields are read-only via this interface
            Self::Smtp(_) => None, // SMTP fields are read-only (text protocol)
            Self::Pop3(_) => None, // POP3 fields are read-only (text protocol)
            Self::Imap(_) => None, // IMAP fields are read-only (text protocol)
        }
    }

    /// Get the list of field names for this layer type.
    #[must_use]
    pub fn field_names(&self) -> &'static [&'static str] {
        match self {
            Self::Ethernet(l) => l.field_names(),
            Self::Dot3(_) => Dot3Layer::field_names(),
            Self::Arp(l) => l.field_names(),
            Self::Ipv4(l) => l.field_names(),
            Self::Icmp(l) => l.field_names(),
            Self::Tcp(l) => l.field_names(),
            Self::Udp(l) => l.field_names(),
            Self::Raw(_) => RawLayer::field_names(),
            Self::Ssh(l) => l.field_names(),
            Self::Tls(l) => l.field_names(),
            Self::Dns(_) => DnsLayer::field_names(),
            Self::Dot15d4(_) => dot15d4::Dot15d4Layer::field_names(),
            Self::Dot15d4Fcs(_) => dot15d4::Dot15d4FcsLayer::field_names(),
            Self::Dot11(_) => dot11::Dot11Layer::field_names(),
            Self::Http(l) => l.field_names(),
            Self::Http2(_) => Http2Layer::field_names(),
            Self::Quic(_) => quic::QuicLayer::field_names(),
            Self::Ipv6(_) => Ipv6Layer::field_names(),
            Self::Icmpv6(_) => Icmpv6Layer::field_names(),
            Self::L2tp(_) => l2tp::L2tpLayer::field_names(),
            Self::Mqtt(_) => mqtt::MqttLayer::field_names(),
            Self::MqttSn(_) => mqttsn::MqttSnLayer::field_names(),
            Self::Modbus(_) => modbus::ModbusLayer::field_names(),
            Self::ZWave(_) => zwave::ZWaveLayer::field_names(),
            Self::Ftp(l) => l.field_names(),
            Self::Tftp(l) => l.field_names(),
            Self::Smtp(l) => l.field_names(),
            Self::Pop3(l) => l.field_names(),
            Self::Imap(l) => l.field_names(),
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
        l.dst(buf).map_or_else(|_| "?".into(), |m| m.to_string()),
    ));
    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |m| m.to_string()),
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
        l.dst(buf).map_or_else(|_| "?".into(), |m| m.to_string()),
    ));
    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |m| m.to_string()),
    ));
    fields.push((
        "len",
        l.len_field(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
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
    fields.push(("ptype", format!("{ptype:#06x}")));
    fields.push((
        "hwlen",
        l.hwlen(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "plen",
        l.plen(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let op = l.op(buf).unwrap_or(0);
    fields.push(("op", format!("{} ({})", op, arp::opcode::name(op))));
    fields.push((
        "hwsrc",
        l.hwsrc_raw(buf)
            .map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields.push((
        "psrc",
        l.psrc_raw(buf)
            .map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields.push((
        "hwdst",
        l.hwdst_raw(buf)
            .map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields.push((
        "pdst",
        l.pdst_raw(buf)
            .map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields
}

fn ipv4_show_fields(l: &Ipv4Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "version",
        l.version(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ihl",
        l.ihl(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "tos",
        l.tos(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields.push((
        "len",
        l.total_len(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "id",
        l.id(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    fields.push((
        "flags",
        l.flags(buf).map_or_else(|_| "?".into(), |f| f.to_string()),
    ));
    fields.push((
        "frag",
        l.frag_offset(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ttl",
        l.ttl(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let proto = l.protocol(buf).unwrap_or(0);
    fields.push(("proto", format!("{} ({})", proto, l.protocol_name(buf))));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |ip| ip.to_string()),
    ));
    fields.push((
        "dst",
        l.dst(buf).map_or_else(|_| "?".into(), |ip| ip.to_string()),
    ));
    // Options (if present)
    let opts_len = l.options_len(buf);
    if opts_len > 0 {
        fields.push(("options", format!("[{opts_len} bytes]")));
    }
    fields
}

fn ipv6_show_fields(l: &Ipv6Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "version",
        l.version(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "tc",
        l.traffic_class(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields.push((
        "fl",
        l.flow_label(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#07x}")),
    ));
    fields.push((
        "plen",
        l.payload_len(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let nh = l.next_header(buf).unwrap_or(0);
    fields.push(("nh", format!("{} ({})", nh, ipv4::protocol::to_name(nh))));
    fields.push((
        "hlim",
        l.hop_limit(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields.push((
        "dst",
        l.dst(buf).map_or_else(|_| "?".into(), |a| a.to_string()),
    ));
    fields
}

fn icmp_show_fields(l: &IcmpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();

    // Type field
    fields.push((
        "type",
        l.icmp_type(buf).map_or_else(
            |_| "?".into(),
            |t: u8| format!("{} ({})", t, icmp::type_name(t)),
        ),
    ));

    // Code field
    fields.push((
        "code",
        l.code(buf)
            .map_or_else(|_| "?".into(), |c: u8| c.to_string()),
    ));

    // Checksum field
    fields.push((
        "chksum",
        l.checksum(buf)
            .map_or_else(|_| "?".into(), |v: u16| format!("{v:#06x}")),
    ));

    // ID field (conditional)
    if let Ok(Some(id)) = l.id(buf) {
        fields.push(("id", format!("{id:#06x}")));
    }

    // Sequence field (conditional)
    if let Ok(Some(seq)) = l.seq(buf) {
        fields.push(("seq", seq.to_string()));
    }

    // Gateway field (for redirect)
    if let Ok(Some(gateway)) = l.gateway(buf) {
        fields.push(("gw", gateway.to_string()));
    }

    // Pointer field (for parameter problem)
    if let Ok(Some(ptr)) = l.ptr(buf) {
        fields.push(("ptr", ptr.to_string()));
    }

    // Next-hop MTU (for dest unreachable, fragmentation needed)
    if let Ok(Some(mtu)) = l.next_hop_mtu(buf) {
        fields.push(("mtu", mtu.to_string()));
    }

    // Timestamp fields (for timestamp request/reply)
    if let Ok(Some(ts_ori)) = l.ts_ori(buf) {
        fields.push(("ts_ori", ts_ori.to_string()));
    }
    if let Ok(Some(ts_rx)) = l.ts_rx(buf) {
        fields.push(("ts_rx", ts_rx.to_string()));
    }
    if let Ok(Some(ts_tx)) = l.ts_tx(buf) {
        fields.push(("ts_tx", ts_tx.to_string()));
    }

    // Address mask (for address mask request/reply)
    if let Ok(Some(addr_mask)) = l.addr_mask(buf) {
        fields.push(("addr_mask", addr_mask.to_string()));
    }

    fields
}

fn icmpv6_show_fields(l: &Icmpv6Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    let icmpv6_type = l.icmpv6_type(buf).unwrap_or(0);
    let type_name = icmpv6::types::name(icmpv6_type);
    fields.push(("type", format!("{icmpv6_type} ({type_name})")));
    fields.push((
        "code",
        l.code(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    if let Ok(Some(id)) = l.id(buf) {
        fields.push(("id", format!("{id:#06x}")));
    }
    if let Ok(Some(seq)) = l.seq(buf) {
        fields.push(("seq", seq.to_string()));
    }
    if let Ok(Some(target)) = l.target_addr(buf) {
        fields.push(("tgt", target.to_string()));
    }
    if let Ok(Some(mtu)) = l.mtu(buf) {
        fields.push(("mtu", mtu.to_string()));
    }
    fields
}

fn tcp_show_fields(l: &TcpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "sport",
        l.src_port(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "dport",
        l.dst_port(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "seq",
        l.seq(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ack",
        l.ack(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "dataofs",
        l.data_offset(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "reserved",
        l.reserved(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "flags",
        l.flags(buf).map_or_else(|_| "?".into(), |f| f.to_string()),
    ));
    fields.push((
        "window",
        l.window(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    fields.push((
        "urgptr",
        l.urgent_ptr(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    // Options (if present)
    let opts_len = l.options_len(buf);
    if opts_len > 0 {
        fields.push(("options", format!("[{opts_len} bytes]")));
    }
    fields
}

fn udp_show_fields(l: &UdpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "sport",
        l.src_port(buf)
            .map_or_else(|_| "?".into(), |v: u16| v.to_string()),
    ));
    fields.push((
        "dport",
        l.dst_port(buf)
            .map_or_else(|_| "?".into(), |v: u16| v.to_string()),
    ));
    fields.push((
        "len",
        l.length(buf)
            .map_or_else(|_| "?".into(), |v: u16| v.to_string()),
    ));
    fields.push((
        "chksum",
        l.checksum(buf)
            .map_or_else(|_| "?".into(), |v: u16| format!("{v:#06x}")),
    ));
    fields
}

fn dns_show_fields(l: &DnsLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "id",
        l.id(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    let qr = l.qr(buf).unwrap_or(false);
    fields.push(("qr", if qr { "response" } else { "query" }.to_string()));
    fields.push((
        "opcode",
        l.opcode(buf).map_or_else(
            |_| "?".into(),
            |v| format!("{} ({})", v, dns::types::opcode_name(v)),
        ),
    ));
    fields.push((
        "aa",
        l.aa(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "tc",
        l.tc(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "rd",
        l.rd(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ra",
        l.ra(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push(("z", l.z(buf).map_or_else(|_| "?".into(), |v| v.to_string())));
    fields.push((
        "ad",
        l.ad(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "cd",
        l.cd(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "rcode",
        l.rcode(buf).map_or_else(
            |_| "?".into(),
            |v| format!("{} ({})", v, dns::types::rcode_name(v)),
        ),
    ));
    fields.push((
        "qdcount",
        l.qdcount(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ancount",
        l.ancount(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "nscount",
        l.nscount(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "arcount",
        l.arcount(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    // Show questions if present
    if let Ok(questions) = l.questions(buf) {
        for (i, q) in questions.iter().enumerate() {
            fields.push(("qd", format!("[{}] {}", i, q.summary())));
        }
    }
    fields
}

fn ssh_show_fields(l: &SshLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.is_version_exchange(buf) {
        if let Some(vs) = l.version_string(buf) {
            fields.push(("version_string", vs.to_string()));
        }
    } else {
        fields.push((
            "packet_length",
            l.packet_length(buf)
                .map_or_else(|_| "?".into(), |v| v.to_string()),
        ));
        fields.push((
            "padding_length",
            l.padding_length(buf)
                .map_or_else(|_| "?".into(), |v| v.to_string()),
        ));
        match l.message_type(buf) {
            Ok(Some(t)) => {
                fields.push((
                    "message_type",
                    format!("{} ({})", t, ssh::msg_types::name(t)),
                ));
            },
            Ok(None) => {},
            Err(_) => {
                fields.push(("message_type", "?".into()));
            },
        }
    }
    fields
}

fn tls_show_fields(l: &TlsLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "type",
        l.content_type(buf).map_or_else(
            |_| "?".into(),
            |ct| format!("{} ({})", ct.as_u8(), ct.name()),
        ),
    ));
    fields.push((
        "version",
        l.version(buf)
            .map(|v| {
                let ver = TlsVersion(v);
                format!("{:#06x} ({})", v, ver.name())
            })
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "len",
        l.length(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let frag = l.fragment(buf);
    if !frag.is_empty() {
        if frag.len() <= 16 {
            fields.push(("fragment", format!("[{} bytes] {:02x?}", frag.len(), frag)));
        } else {
            fields.push(("fragment", format!("[{} bytes]", frag.len())));
        }
    }
    fields
}

fn dot11_show_fields(l: &dot11::Dot11Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "type",
        l.frame_type(buf).map_or_else(
            |_| "?".into(),
            |v| format!("{} ({})", v, dot11::types::frame_type::name(v)),
        ),
    ));
    fields.push((
        "subtype",
        l.subtype(buf)
            .map(|v| {
                let ft = l.frame_type(buf).unwrap_or(0);
                format!("{} ({})", v, dot11::types::subtype_name(ft, v))
            })
            .unwrap_or_else(|_| "?".into()),
    ));
    fields.push((
        "proto",
        l.protocol_version(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "FCfield",
        l.flags(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields.push((
        "ID",
        l.duration(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "addr1",
        l.addr1(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "addr2",
        l.addr2(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "addr3",
        l.addr3(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "SC",
        l.seq_ctrl_raw(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    if l.has_addr4(buf) {
        fields.push((
            "addr4",
            l.addr4(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
        ));
    }
    fields
}

fn dot15d4_show_fields(l: &dot15d4::Dot15d4Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    // Frame type with name
    let ft = l.fcf_frametype(buf).unwrap_or(0);
    fields.push((
        "fcf_frametype",
        format!("{} ({})", ft, dot15d4::types::frame_type_name(ft)),
    ));
    // FCF flags
    fields.push((
        "fcf_security",
        l.fcf_security(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "fcf_pending",
        l.fcf_pending(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "fcf_ackreq",
        l.fcf_ackreq(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "fcf_panidcompress",
        l.fcf_panidcompress(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    // Address modes with names
    let dam = l.fcf_destaddrmode(buf).unwrap_or(0);
    fields.push((
        "fcf_destaddrmode",
        format!("{} ({})", dam, dot15d4::types::addr_mode_name(dam)),
    ));
    fields.push((
        "fcf_framever",
        l.fcf_framever(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let sam = l.fcf_srcaddrmode(buf).unwrap_or(0);
    fields.push((
        "fcf_srcaddrmode",
        format!("{} ({})", sam, dot15d4::types::addr_mode_name(sam)),
    ));
    // Sequence number
    fields.push((
        "seqnum",
        l.seqnum(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    // Conditional addressing fields
    if let Ok(Some(panid)) = l.dest_panid(buf) {
        fields.push(("dest_panid", format!("{panid:#06x}")));
    }
    if let Ok(Some(addr)) = l.dest_addr_short(buf) {
        fields.push(("dest_addr", format!("{addr:#06x}")));
    }
    if let Ok(Some(addr)) = l.dest_addr_long(buf) {
        fields.push(("dest_addr", format!("{addr:#018x}")));
    }
    if let Ok(Some(panid)) = l.src_panid(buf) {
        fields.push(("src_panid", format!("{panid:#06x}")));
    }
    if let Ok(Some(addr)) = l.src_addr_short(buf) {
        fields.push(("src_addr", format!("{addr:#06x}")));
    }
    if let Ok(Some(addr)) = l.src_addr_long(buf) {
        fields.push(("src_addr", format!("{addr:#018x}")));
    }
    fields
}

fn dot15d4_fcs_show_fields(
    l: &dot15d4::Dot15d4FcsLayer,
    buf: &[u8],
) -> Vec<(&'static str, String)> {
    let inner = dot15d4::Dot15d4Layer::new(l.index.start, l.index.end.saturating_sub(2));
    let mut fields = dot15d4_show_fields(&inner, buf);
    // Show FCS with verification status
    let slice = l.index.slice(buf);
    if slice.len() >= 2 {
        let fcs_bytes = &slice[slice.len() - 2..];
        let fcs = u16::from_le_bytes([fcs_bytes[0], fcs_bytes[1]]);
        let verified = l.verify_fcs(buf).unwrap_or(false);
        let status = if verified { "ok" } else { "INVALID" };
        fields.push(("fcs", format!("{fcs:#06x} ({status})")));
    }
    fields
}

fn http_show_fields(l: &http::HttpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.is_request(buf) {
        fields.push(("method", l.method(buf).unwrap_or("?").to_string()));
        fields.push(("uri", l.uri(buf).unwrap_or("?").to_string()));
        fields.push(("version", l.http_version(buf).unwrap_or("?").to_string()));
    } else if l.is_response(buf) {
        fields.push(("version", l.http_version(buf).unwrap_or("?").to_string()));
        fields.push((
            "status_code",
            l.status_code(buf)
                .map_or_else(|| "?".into(), |c| c.to_string()),
        ));
        fields.push(("reason", l.reason(buf).unwrap_or("?").to_string()));
    }
    fields
}

fn http2_show_fields(l: &http2::Http2Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if l.has_preface {
        fields.push(("preface", "true".to_string()));
    }
    if let Some(frame) = l.first_frame(buf) {
        fields.push((
            "frame_type",
            format!("{} ({})", frame.frame_type.as_u8(), frame.frame_type.name()),
        ));
        fields.push(("flags", format!("{:#04x}", frame.flags)));
        fields.push(("stream_id", frame.stream_id.to_string()));
        fields.push(("length", frame.length.to_string()));
    }
    fields
}

fn quic_show_fields(l: &quic::QuicLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "header_form",
        if l.is_long_header(buf) {
            "long".to_string()
        } else {
            "short".to_string()
        },
    ));
    if let Some(pt) = l.packet_type(buf) {
        fields.push(("packet_type", pt.name().to_string()));
    }
    if let Some(ver) = l.version(buf) {
        fields.push(("version", format!("{ver:#010x}")));
    }
    fields
}

fn l2tp_show_fields(l: &l2tp::L2tpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "flags",
        l.flags_word(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    fields.push((
        "version",
        l.version(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "msg_type",
        l.msg_type(buf)
            .map(|v| {
                if v == 0 {
                    "data".to_string()
                } else {
                    "control".to_string()
                }
            })
            .unwrap_or_else(|_| "?".into()),
    ));
    if let Ok(Some(length)) = l.length(buf) {
        fields.push(("length", length.to_string()));
    }
    fields.push((
        "tunnel_id",
        l.tunnel_id(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "session_id",
        l.session_id(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    if let Ok(Some(ns)) = l.ns(buf) {
        fields.push(("ns", ns.to_string()));
    }
    if let Ok(Some(nr)) = l.nr(buf) {
        fields.push(("nr", nr.to_string()));
    }
    fields
}

fn mqtt_show_fields(l: &mqtt::MqttLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "msg_type",
        l.msg_type(buf).map_or_else(
            |_| "?".into(),
            |v| format!("{} ({})", v, mqtt::message_type_name(v)),
        ),
    ));
    fields.push((
        "dup",
        l.dup(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "qos",
        l.qos(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "retain",
        l.retain(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "remaining_length",
        l.remaining_length(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    if let Ok(mt) = l.msg_type(buf) {
        if mt == mqtt::PUBLISH {
            if let Ok(topic) = l.topic(buf) {
                fields.push(("topic", topic));
            }
        } else if mt == mqtt::CONNECT {
            if let Ok(name) = l.proto_name(buf) {
                fields.push(("proto_name", name));
            }
            if let Ok(level) = l.proto_level(buf) {
                fields.push(("proto_level", level.to_string()));
            }
            if let Ok(klive) = l.klive(buf) {
                fields.push(("klive", klive.to_string()));
            }
            if let Ok(cid) = l.client_id(buf) {
                fields.push(("client_id", cid));
            }
        } else if mt == mqtt::CONNACK
            && let Ok(rc) = l.retcode(buf)
        {
            fields.push(("retcode", rc.to_string()));
        }
    }
    fields
}

fn mqttsn_show_fields(l: &mqttsn::MqttSnLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "length",
        l.packet_length(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    let mt = l.msg_type(buf).unwrap_or(0xFF);
    fields.push((
        "type",
        format!("{} ({})", mt, mqttsn::message_type_name(mt)),
    ));
    if let Ok(v) = l.gw_id(buf) {
        fields.push(("gw_id", format!("{v:#04x}")));
    }
    if let Ok(v) = l.duration(buf) {
        fields.push(("duration", v.to_string()));
    }
    if let Ok(v) = l.return_code(buf) {
        fields.push(("return_code", v.to_string()));
    }
    if let Ok(v) = l.tid(buf) {
        fields.push(("tid", format!("{v:#06x}")));
    }
    if let Ok(v) = l.mid(buf) {
        fields.push(("mid", format!("{v:#06x}")));
    }
    fields
}

fn modbus_show_fields(l: &modbus::ModbusLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "trans_id",
        l.trans_id(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "proto_id",
        l.proto_id(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#06x}")),
    ));
    fields.push((
        "length",
        l.length(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "unit_id",
        l.unit_id(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    let fc = l.func_code(buf).unwrap_or(0);
    fields.push((
        "func_code",
        format!("{:#04x} ({})", fc, modbus::func_code_name(fc)),
    ));
    if l.is_error(buf) {
        fields.push((
            "except_code",
            l.except_code(buf).map_or_else(
                |_| "?".into(),
                |v| format!("{} ({})", v, modbus::except_code_name(v)),
            ),
        ));
    }
    fields
}

fn zwave_show_fields(l: &zwave::ZWaveLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    fields.push((
        "home_id",
        l.home_id(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#010x}")),
    ));
    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "dst",
        l.dst(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "routed",
        l.routed(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "ackreq",
        l.ackreq(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "lowpower",
        l.lowpower(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "speedmodified",
        l.speedmodified(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "headertype",
        l.headertype(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields.push((
        "beam_control",
        l.beam_control(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "seqn",
        l.seqn(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    fields.push((
        "length",
        l.length(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));
    if !l.is_ack(buf) {
        fields.push((
            "cmd_class",
            l.cmd_class(buf).map_or_else(
                |_| "?".into(),
                |v| format!("{:#04x} ({})", v, zwave::cmd_class_name(v)),
            ),
        ));
        if let Ok(cmd) = l.cmd(buf) {
            fields.push(("cmd", format!("{cmd:#04x}")));
        }
    }
    fields.push((
        "crc",
        l.crc(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields
}

pub use dns::DnsLayer;

/// `EtherType` constants
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

    #[must_use]
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

    #[must_use]
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

    #[must_use]
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
