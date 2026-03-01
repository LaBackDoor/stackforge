//! Layer stacking support for packet composition.
//!
//! This module provides the `LayerStack` type for composing packets using
//! the `/` operator syntax: `Ether() / IP() / TCP()`.
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::{
//!     EthernetBuilder, LayerStack, LayerStackEntry, LayerKind,
//!     ipv4::Ipv4Builder,
//!     tcp::TcpBuilder,
//! };
//! use stackforge_core::layer::field::MacAddress;
//! use std::net::Ipv4Addr;
//!
//! // Build a TCP SYN packet
//! let pkt = LayerStack::new()
//!     .push(LayerStackEntry::Ethernet(
//!         EthernetBuilder::new()
//!             .dst(MacAddress::BROADCAST)
//!             .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
//!     ))
//!     .push(LayerStackEntry::Ipv4(
//!         Ipv4Builder::new()
//!             .src(Ipv4Addr::new(192, 168, 1, 1))
//!             .dst(Ipv4Addr::new(192, 168, 1, 2))
//!             .ttl(64)
//!     ))
//!     .push(LayerStackEntry::Tcp(
//!         TcpBuilder::new()
//!             .src_port(12345)
//!             .dst_port(80)
//!             .syn()
//!     ))
//!     .build();
//! ```

use super::bindings::apply_binding;
use super::dns::builder::DnsBuilder;
use super::ethernet::{ETHERNET_HEADER_LEN, EthernetBuilder};
use super::icmp::builder::IcmpBuilder;
use super::ipv4::builder::Ipv4Builder;
use super::ssh::builder::SshBuilder;
use super::tcp::builder::TcpBuilder;
use super::tls::builder::TlsRecordBuilder;
use super::udp::builder::UdpBuilder;
use super::{ArpBuilder, LayerKind};
use crate::Packet;
use crate::layer::arp::ARP_HEADER_LEN;
use crate::layer::dns::DNS_HEADER_LEN;
use crate::layer::icmp::ICMP_MIN_HEADER_LEN;
use crate::layer::ipv4::IPV4_MIN_HEADER_LEN;
use crate::layer::tcp::TCP_MIN_HEADER_LEN;
use crate::layer::udp::UDP_HEADER_LEN;

/// An entry in a layer stack, representing a protocol layer builder.
#[derive(Debug, Clone)]
pub enum LayerStackEntry {
    /// Ethernet II layer
    Ethernet(EthernetBuilder),
    /// ARP layer
    Arp(ArpBuilder),
    /// IPv4 layer
    Ipv4(Ipv4Builder),
    /// TCP layer
    Tcp(TcpBuilder),
    /// UDP layer
    Udp(UdpBuilder),
    /// ICMP layer
    Icmp(IcmpBuilder),
    /// SSH layer
    Ssh(SshBuilder),
    /// TLS record layer
    Tls(TlsRecordBuilder),
    /// DNS layer
    Dns(DnsBuilder),
    /// Raw bytes payload
    Raw(Vec<u8>),
}

impl LayerStackEntry {
    /// Get the LayerKind for this entry.
    pub fn kind(&self) -> LayerKind {
        match self {
            Self::Ethernet(_) => LayerKind::Ethernet,
            Self::Arp(_) => LayerKind::Arp,
            Self::Ipv4(_) => LayerKind::Ipv4,
            Self::Tcp(_) => LayerKind::Tcp,
            Self::Udp(_) => LayerKind::Udp,
            Self::Icmp(_) => LayerKind::Icmp,
            Self::Ssh(_) => LayerKind::Ssh,
            Self::Tls(_) => LayerKind::Tls,
            Self::Dns(_) => LayerKind::Dns,
            Self::Raw(_) => LayerKind::Raw,
        }
    }

    /// Build this layer into bytes, without applying bindings.
    pub fn build_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ethernet(b) => b.build(),
            Self::Arp(b) => b.build(),
            Self::Ipv4(b) => b.build(),
            Self::Tcp(b) => b.build(),
            Self::Udp(b) => b.build(),
            Self::Icmp(b) => b.build(),
            Self::Ssh(b) => b.build(),
            Self::Tls(b) => b.build(),
            Self::Dns(b) => b.build(),
            Self::Raw(data) => data.clone(),
        }
    }

    /// Get the header size for this layer.
    pub fn header_size(&self) -> usize {
        match self {
            Self::Ethernet(_) => ETHERNET_HEADER_LEN,
            Self::Arp(_) => ARP_HEADER_LEN,
            Self::Ipv4(b) => b.header_size(),
            Self::Tcp(b) => b.header_size(),
            Self::Udp(b) => b.header_size(),
            Self::Icmp(b) => b.header_size(),
            Self::Ssh(b) => b.header_size(),
            Self::Tls(b) => b.record_size(),
            Self::Dns(b) => b.header_size(),
            Self::Raw(data) => data.len(),
        }
    }

    /// Get minimum header size for this layer type.
    pub fn min_header_size(&self) -> usize {
        match self {
            Self::Ethernet(_) => ETHERNET_HEADER_LEN,
            Self::Arp(_) => ARP_HEADER_LEN,
            Self::Ipv4(_) => IPV4_MIN_HEADER_LEN,
            Self::Tcp(_) => TCP_MIN_HEADER_LEN,
            Self::Udp(_) => UDP_HEADER_LEN,
            Self::Icmp(_) => ICMP_MIN_HEADER_LEN,
            Self::Ssh(b) => b.header_size(),
            Self::Tls(_) => 5, // TLS record header is 5 bytes
            Self::Dns(_) => DNS_HEADER_LEN,
            Self::Raw(data) => data.len(),
        }
    }
}

/// A stack of protocol layers that can be combined into a packet.
///
/// The stack maintains the order of layers and automatically applies
/// bindings when building the final packet.
#[derive(Debug, Clone, Default)]
pub struct LayerStack {
    layers: Vec<LayerStackEntry>,
}

impl LayerStack {
    /// Create a new empty layer stack.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Push a new layer onto the stack.
    ///
    /// Layers are stacked from bottom (first) to top (last).
    pub fn push(mut self, layer: LayerStackEntry) -> Self {
        self.layers.push(layer);
        self
    }

    /// Add a layer to the stack (mutable version).
    pub fn add(&mut self, layer: LayerStackEntry) {
        self.layers.push(layer);
    }

    /// Stack another LayerStack on top of this one.
    ///
    /// This is the implementation of the `/` operator.
    pub fn stack(mut self, other: LayerStack) -> Self {
        self.layers.extend(other.layers);
        self
    }

    /// Get the number of layers in the stack.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Check if the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Get the layers in the stack.
    pub fn layers(&self) -> &[LayerStackEntry] {
        &self.layers
    }

    /// Build the stacked layers into raw bytes.
    ///
    /// This method:
    /// 1. Builds each layer
    /// 2. Applies bindings (e.g., sets Ethernet type when IP is stacked on top)
    /// 3. Concatenates all layer bytes
    /// 4. Recalculates checksums and lengths where applicable
    pub fn build(&self) -> Vec<u8> {
        if self.layers.is_empty() {
            return Vec::new();
        }

        // First pass: build all layers to determine total size
        let mut layer_bytes: Vec<Vec<u8>> = self.layers.iter().map(|l| l.build_bytes()).collect();

        // Calculate total payload sizes for each layer
        let total_len: usize = layer_bytes.iter().map(|b| b.len()).sum();

        // Second pass: apply bindings and fix length/checksum fields
        for i in 0..self.layers.len().saturating_sub(1) {
            let lower_kind = self.layers[i].kind();
            let upper_kind = self.layers[i + 1].kind();

            // Apply binding: set the appropriate field in the lower layer
            if let Some((field_name, field_value)) = apply_binding(lower_kind, upper_kind) {
                apply_field_to_bytes(&mut layer_bytes[i], lower_kind, field_name, field_value);
            }
        }

        // Fix IP and TCP checksum/length if present
        self.fix_ip_fields(&mut layer_bytes, total_len);
        self.fix_tcp_fields(&mut layer_bytes);
        self.fix_udp_fields(&mut layer_bytes);
        self.fix_icmp_fields(&mut layer_bytes);

        // Concatenate all layers
        layer_bytes.into_iter().flatten().collect()
    }

    /// Build the stack into a Packet.
    pub fn build_packet(&self) -> Packet {
        let bytes = self.build();
        let mut pkt = Packet::from_bytes(bytes);
        let _ = pkt.parse();
        pkt
    }

    /// Fix IP total length and checksum fields.
    fn fix_ip_fields(&self, layer_bytes: &mut [Vec<u8>], _total_len: usize) {
        for (i, layer) in self.layers.iter().enumerate() {
            if let LayerStackEntry::Ipv4(_) = layer {
                // Calculate payload size (everything after IP header)
                let payload_size: usize = layer_bytes[i + 1..].iter().map(|b| b.len()).sum();
                let ip_header_len = layer_bytes[i].len();
                let ip_total_len = ip_header_len + payload_size;

                // Update total length field (bytes 2-3)
                if layer_bytes[i].len() >= 4 {
                    layer_bytes[i][2] = ((ip_total_len >> 8) & 0xFF) as u8;
                    layer_bytes[i][3] = (ip_total_len & 0xFF) as u8;

                    // Recalculate checksum
                    // First zero out the checksum field
                    layer_bytes[i][10] = 0;
                    layer_bytes[i][11] = 0;

                    // Calculate new checksum
                    let checksum = crate::layer::ipv4::checksum::ipv4_checksum(
                        &layer_bytes[i][..ip_header_len],
                    );
                    layer_bytes[i][10] = ((checksum >> 8) & 0xFF) as u8;
                    layer_bytes[i][11] = (checksum & 0xFF) as u8;
                }
            }
        }
    }

    /// Fix TCP checksum if present.
    fn fix_tcp_fields(&self, layer_bytes: &mut [Vec<u8>]) {
        // Find IP layer for pseudo-header
        let mut ip_layer_idx = None;
        let mut tcp_layer_idx = None;

        for (i, layer) in self.layers.iter().enumerate() {
            if let LayerStackEntry::Ipv4(_) = layer {
                ip_layer_idx = Some(i);
            }
            if let LayerStackEntry::Tcp(_) = layer {
                tcp_layer_idx = Some(i);
            }
        }

        if let (Some(ip_idx), Some(tcp_idx)) = (ip_layer_idx, tcp_layer_idx) {
            let ip_bytes = &layer_bytes[ip_idx];
            if ip_bytes.len() >= 20 {
                // Extract source and destination IPs
                let mut src_bytes = [0u8; 4];
                let mut dst_bytes = [0u8; 4];
                src_bytes.copy_from_slice(&ip_bytes[12..16]);
                dst_bytes.copy_from_slice(&ip_bytes[16..20]);
                let src_ip = std::net::Ipv4Addr::from(src_bytes);
                let dst_ip = std::net::Ipv4Addr::from(dst_bytes);

                // Zero out checksum field
                if layer_bytes[tcp_idx].len() >= 18 {
                    layer_bytes[tcp_idx][16] = 0;
                    layer_bytes[tcp_idx][17] = 0;
                }

                // Recalculate checksum with zeroed field
                let mut tcp_with_zero_checksum: Vec<u8> =
                    layer_bytes[tcp_idx..].iter().flatten().copied().collect();
                if tcp_with_zero_checksum.len() >= 18 {
                    tcp_with_zero_checksum[16] = 0;
                    tcp_with_zero_checksum[17] = 0;
                }

                let checksum = crate::layer::tcp::checksum::tcp_checksum_ipv4(
                    src_ip,
                    dst_ip,
                    &tcp_with_zero_checksum,
                );

                if layer_bytes[tcp_idx].len() >= 18 {
                    layer_bytes[tcp_idx][16] = ((checksum >> 8) & 0xFF) as u8;
                    layer_bytes[tcp_idx][17] = (checksum & 0xFF) as u8;
                }
            }
        }
    }

    /// Fix UDP checksum and length if present.
    fn fix_udp_fields(&self, layer_bytes: &mut [Vec<u8>]) {
        // Find IP layer for pseudo-header
        let mut ip_layer_idx = None;
        let mut udp_layer_idx = None;

        for (i, layer) in self.layers.iter().enumerate() {
            if let LayerStackEntry::Ipv4(_) = layer {
                ip_layer_idx = Some(i);
            }
            if let LayerStackEntry::Udp(_) = layer {
                udp_layer_idx = Some(i);
            }
        }

        // If UDP is present without IP, just fix the length field
        if let Some(udp_idx) = udp_layer_idx {
            if ip_layer_idx.is_none() {
                // Standalone UDP - only fix length field, leave checksum as 0
                let udp_len: usize = layer_bytes[udp_idx..].iter().map(|b| b.len()).sum();
                if layer_bytes[udp_idx].len() >= 6 {
                    layer_bytes[udp_idx][4] = ((udp_len >> 8) & 0xFF) as u8;
                    layer_bytes[udp_idx][5] = (udp_len & 0xFF) as u8;
                }
                return;
            }
        }

        if let (Some(ip_idx), Some(udp_idx)) = (ip_layer_idx, udp_layer_idx) {
            let ip_bytes = &layer_bytes[ip_idx];
            if ip_bytes.len() >= 20 {
                // Extract source and destination IPs
                let mut src_bytes = [0u8; 4];
                let mut dst_bytes = [0u8; 4];
                src_bytes.copy_from_slice(&ip_bytes[12..16]);
                dst_bytes.copy_from_slice(&ip_bytes[16..20]);
                let src_ip = std::net::Ipv4Addr::from(src_bytes);
                let dst_ip = std::net::Ipv4Addr::from(dst_bytes);

                // Calculate UDP length (header + payload)
                let udp_len: usize = layer_bytes[udp_idx..].iter().map(|b| b.len()).sum();

                // Update length field (bytes 4-5)
                if layer_bytes[udp_idx].len() >= 6 {
                    layer_bytes[udp_idx][4] = ((udp_len >> 8) & 0xFF) as u8;
                    layer_bytes[udp_idx][5] = (udp_len & 0xFF) as u8;
                }

                // Zero out checksum field (bytes 6-7)
                if layer_bytes[udp_idx].len() >= 8 {
                    layer_bytes[udp_idx][6] = 0;
                    layer_bytes[udp_idx][7] = 0;
                }

                // Collect UDP segment (header + payload)
                let udp_segment: Vec<u8> =
                    layer_bytes[udp_idx..].iter().flatten().copied().collect();

                // Calculate checksum
                let checksum =
                    crate::layer::udp::checksum::udp_checksum_ipv4(src_ip, dst_ip, &udp_segment);

                // Write checksum back
                if layer_bytes[udp_idx].len() >= 8 {
                    layer_bytes[udp_idx][6] = ((checksum >> 8) & 0xFF) as u8;
                    layer_bytes[udp_idx][7] = (checksum & 0xFF) as u8;
                }
            }
        }
    }

    /// Fix ICMP checksum if present.
    fn fix_icmp_fields(&self, layer_bytes: &mut [Vec<u8>]) {
        // Find ICMP layer
        let mut icmp_layer_idx = None;

        for (i, layer) in self.layers.iter().enumerate() {
            if let LayerStackEntry::Icmp(_) = layer {
                icmp_layer_idx = Some(i);
                break;
            }
        }

        if let Some(icmp_idx) = icmp_layer_idx {
            // Zero out checksum field (bytes 2-3)
            if layer_bytes[icmp_idx].len() >= 4 {
                layer_bytes[icmp_idx][2] = 0;
                layer_bytes[icmp_idx][3] = 0;
            }

            // Collect ICMP message (header + payload)
            let icmp_message: Vec<u8> = layer_bytes[icmp_idx..].iter().flatten().copied().collect();

            // Calculate checksum
            let checksum = crate::layer::icmp::checksum::icmp_checksum(&icmp_message);

            // Write checksum back
            if layer_bytes[icmp_idx].len() >= 4 {
                layer_bytes[icmp_idx][2] = ((checksum >> 8) & 0xFF) as u8;
                layer_bytes[icmp_idx][3] = (checksum & 0xFF) as u8;
            }
        }
    }
}

/// Apply a binding field value to layer bytes.
fn apply_field_to_bytes(bytes: &mut Vec<u8>, layer_kind: LayerKind, field_name: &str, value: u16) {
    match layer_kind {
        LayerKind::Ethernet => {
            // type field is at offset 12, 2 bytes
            if field_name == "type" && bytes.len() >= 14 {
                bytes[12] = ((value >> 8) & 0xFF) as u8;
                bytes[13] = (value & 0xFF) as u8;
            }
        }
        LayerKind::Ipv4 => {
            // proto field is at offset 9, 1 byte
            if field_name == "proto" && bytes.len() >= 10 {
                bytes[9] = (value & 0xFF) as u8;
            }
        }
        LayerKind::Ipv6 => {
            // nh (next header) field is at offset 6, 1 byte
            if field_name == "nh" && bytes.len() >= 7 {
                bytes[6] = (value & 0xFF) as u8;
            }
        }
        LayerKind::Dot1Q | LayerKind::Dot1AD => {
            // type field is at offset 2, 2 bytes (after TCI)
            if field_name == "type" && bytes.len() >= 4 {
                bytes[2] = ((value >> 8) & 0xFF) as u8;
                bytes[3] = (value & 0xFF) as u8;
            }
        }
        LayerKind::Tcp => {
            // dport field is at offset 2, 2 bytes
            if field_name == "dport" && bytes.len() >= 4 {
                bytes[2] = ((value >> 8) & 0xFF) as u8;
                bytes[3] = (value & 0xFF) as u8;
            }
        }
        LayerKind::Udp => {
            // dport field is at offset 2, 2 bytes
            if field_name == "dport" && bytes.len() >= 4 {
                bytes[2] = ((value >> 8) & 0xFF) as u8;
                bytes[3] = (value & 0xFF) as u8;
            }
        }
        _ => {}
    }
}

/// Trait for types that can be converted into a LayerStackEntry.
pub trait IntoLayerStackEntry {
    fn into_layer_stack_entry(self) -> LayerStackEntry;
}

impl IntoLayerStackEntry for EthernetBuilder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Ethernet(self)
    }
}

impl IntoLayerStackEntry for ArpBuilder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Arp(self)
    }
}

impl IntoLayerStackEntry for Ipv4Builder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Ipv4(self)
    }
}

impl IntoLayerStackEntry for TcpBuilder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Tcp(self)
    }
}

impl IntoLayerStackEntry for UdpBuilder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Udp(self)
    }
}

impl IntoLayerStackEntry for DnsBuilder {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Dns(self)
    }
}

impl IntoLayerStackEntry for Vec<u8> {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Raw(self)
    }
}

impl IntoLayerStackEntry for &[u8] {
    fn into_layer_stack_entry(self) -> LayerStackEntry {
        LayerStackEntry::Raw(self.to_vec())
    }
}

// Implement Div for stacking
impl std::ops::Div<LayerStack> for LayerStack {
    type Output = LayerStack;

    fn div(self, rhs: LayerStack) -> Self::Output {
        self.stack(rhs)
    }
}

impl std::ops::Div<LayerStackEntry> for LayerStack {
    type Output = LayerStack;

    fn div(self, rhs: LayerStackEntry) -> Self::Output {
        self.push(rhs)
    }
}

impl std::ops::Div<LayerStackEntry> for LayerStackEntry {
    type Output = LayerStack;

    fn div(self, rhs: LayerStackEntry) -> Self::Output {
        LayerStack::new().push(self).push(rhs)
    }
}

// Implement From for common builder types to create single-layer stacks
impl From<EthernetBuilder> for LayerStack {
    fn from(builder: EthernetBuilder) -> Self {
        LayerStack::new().push(LayerStackEntry::Ethernet(builder))
    }
}

impl From<ArpBuilder> for LayerStack {
    fn from(builder: ArpBuilder) -> Self {
        LayerStack::new().push(LayerStackEntry::Arp(builder))
    }
}

impl From<Ipv4Builder> for LayerStack {
    fn from(builder: Ipv4Builder) -> Self {
        LayerStack::new().push(LayerStackEntry::Ipv4(builder))
    }
}

impl From<TcpBuilder> for LayerStack {
    fn from(builder: TcpBuilder) -> Self {
        LayerStack::new().push(LayerStackEntry::Tcp(builder))
    }
}

impl From<UdpBuilder> for LayerStack {
    fn from(builder: UdpBuilder) -> Self {
        LayerStack::new().push(LayerStackEntry::Udp(builder))
    }
}

impl From<DnsBuilder> for LayerStack {
    fn from(builder: DnsBuilder) -> Self {
        LayerStack::new().push(LayerStackEntry::Dns(builder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::field::MacAddress;
    use crate::layer::{ethertype, ip_protocol};
    use std::net::Ipv4Addr;

    #[test]
    fn test_ethernet_ip_stack() {
        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new()
                    .src(Ipv4Addr::new(192, 168, 1, 1))
                    .dst(Ipv4Addr::new(192, 168, 1, 2))
                    .ttl(64),
            ));

        let bytes = stack.build();

        // Verify Ethernet type was set correctly
        let etype = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(etype, ethertype::IPV4);

        // Parse and verify
        let mut pkt = Packet::from_bytes(bytes);
        pkt.parse().unwrap();
        assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
        assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    }

    #[test]
    fn test_ethernet_ip_tcp_stack() {
        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new()
                    .src(Ipv4Addr::new(192, 168, 1, 1))
                    .dst(Ipv4Addr::new(192, 168, 1, 2))
                    .ttl(64),
            ))
            .push(LayerStackEntry::Tcp(
                TcpBuilder::new().src_port(12345).dst_port(80).syn(),
            ));

        let bytes = stack.build();

        // Verify Ethernet type was set correctly
        let etype = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(etype, ethertype::IPV4);

        // Verify IP protocol was set correctly
        let proto = bytes[14 + 9]; // Ethernet header + IP protocol offset
        assert_eq!(proto, ip_protocol::TCP);

        // Parse and verify
        let mut pkt = Packet::from_bytes(bytes);
        pkt.parse().unwrap();
        assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
        assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
        assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    }

    #[test]
    fn test_ethernet_arp_stack() {
        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ))
            .push(LayerStackEntry::Arp(
                ArpBuilder::new()
                    .op(1) // REQUEST
                    .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
                    .psrc(Ipv4Addr::new(192, 168, 1, 1))
                    .pdst(Ipv4Addr::new(192, 168, 1, 2)),
            ));

        let bytes = stack.build();

        // Verify Ethernet type was set correctly
        let etype = u16::from_be_bytes([bytes[12], bytes[13]]);
        assert_eq!(etype, ethertype::ARP);

        // Parse and verify
        let mut pkt = Packet::from_bytes(bytes);
        pkt.parse().unwrap();
        assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
        assert!(pkt.get_layer(LayerKind::Arp).is_some());
    }

    #[test]
    fn test_div_operator() {
        let eth = LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );
        let ip = LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 1))
                .dst(Ipv4Addr::new(192, 168, 1, 2))
                .ttl(64),
        );

        let stack = eth / ip;

        assert_eq!(stack.len(), 2);
        assert_eq!(stack.layers()[0].kind(), LayerKind::Ethernet);
        assert_eq!(stack.layers()[1].kind(), LayerKind::Ipv4);
    }

    #[test]
    fn test_raw_payload() {
        let payload = b"Hello, World!";
        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(
                EthernetBuilder::new()
                    .dst(MacAddress::BROADCAST)
                    .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new()
                    .src(Ipv4Addr::new(192, 168, 1, 1))
                    .dst(Ipv4Addr::new(192, 168, 1, 2))
                    .ttl(64),
            ))
            .push(LayerStackEntry::Raw(payload.to_vec()));

        let bytes = stack.build();

        // Verify payload is at the end
        let expected_offset = 14 + 20; // Ethernet + IP header
        assert_eq!(
            &bytes[expected_offset..expected_offset + payload.len()],
            payload
        );
    }

    #[test]
    fn test_ip_total_length_calculation() {
        let payload = vec![0u8; 100];
        let stack = LayerStack::new()
            .push(LayerStackEntry::Ethernet(EthernetBuilder::new()))
            .push(LayerStackEntry::Ipv4(
                Ipv4Builder::new()
                    .src(Ipv4Addr::new(10, 0, 0, 1))
                    .dst(Ipv4Addr::new(10, 0, 0, 2)),
            ))
            .push(LayerStackEntry::Raw(payload));

        let bytes = stack.build();

        // Check IP total length (should be 20 + 100 = 120)
        let ip_total_len = u16::from_be_bytes([bytes[14 + 2], bytes[14 + 3]]);
        assert_eq!(ip_total_len, 120);
    }
}
