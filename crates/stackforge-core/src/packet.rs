//! Zero-copy packet representation and manipulation.
//!
//! This module implements the core `Packet` struct using a "Lazy Zero-Copy View"
//! architecture. Packets are represented as:
//!
//! 1. A contiguous buffer of raw bytes (`Bytes`)
//! 2. A lightweight index of layer boundaries (`SmallVec<LayerIndex>`)
//!
//! Field access is lazy - values are read directly from the buffer only when
//! requested, avoiding the allocation overhead of eager parsing.

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::error::{PacketError, Result};
use crate::layer::{
    DnsLayer, IcmpLayer, Icmpv6Layer, Ipv6Layer, LayerEnum, LayerIndex, LayerKind, RawLayer,
    TcpLayer, UdpLayer,
    arp::ArpLayer,
    ethernet::{Dot3Layer, ETHERNET_HEADER_LEN, EthernetLayer},
    ethertype, ip_protocol,
    ipv4::Ipv4Layer,
};

/// Maximum number of layers to store inline before heap allocation.
const INLINE_LAYER_CAPACITY: usize = 4;

/// A network packet with zero-copy buffer storage.
///
/// # Architecture
///
/// The `Packet` struct implements a "Lazy Zero-Copy View" model:
///
/// - **Zero-Copy**: The `data` field uses `Bytes`, a reference-counted buffer.
/// - **Lazy**: Fields are not parsed until accessed.
/// - **Copy-on-Write**: Mutation triggers cloning only when buffer is shared.
#[derive(Debug, Clone)]
pub struct Packet {
    data: Bytes,
    layers: SmallVec<[LayerIndex; INLINE_LAYER_CAPACITY]>,
    is_dirty: bool,
}

impl Packet {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Creates an empty packet with no data.
    #[inline]
    pub fn empty() -> Self {
        Self {
            data: Bytes::new(),
            layers: SmallVec::new(),
            is_dirty: false,
        }
    }

    /// Creates a packet from raw bytes without parsing.
    #[inline]
    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        Self {
            data: data.into(),
            layers: SmallVec::new(),
            is_dirty: false,
        }
    }

    /// Creates a packet from a byte slice by copying the data.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(data),
            layers: SmallVec::new(),
            is_dirty: false,
        }
    }

    /// Creates a new packet with pre-allocated capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Bytes::from(BytesMut::with_capacity(capacity)),
            layers: SmallVec::new(),
            is_dirty: false,
        }
    }

    // ========================================================================
    // Basic Properties
    // ========================================================================

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }
    #[inline]
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
    #[inline]
    pub fn is_parsed(&self) -> bool {
        !self.layers.is_empty()
    }

    // ========================================================================
    // Raw Data Access
    // ========================================================================

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    #[inline]
    pub fn bytes(&self) -> Bytes {
        self.data.clone()
    }
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    // ========================================================================
    // Layer Access
    // ========================================================================

    #[inline]
    pub fn layers(&self) -> &[LayerIndex] {
        &self.layers
    }

    #[inline]
    pub fn get_layer(&self, kind: LayerKind) -> Option<&LayerIndex> {
        self.layers.iter().find(|l| l.kind == kind)
    }

    /// Returns the bytes for a specific layer.
    pub fn layer_bytes(&self, kind: LayerKind) -> Result<&[u8]> {
        self.get_layer(kind)
            .map(|idx| &self.data[idx.range()])
            .ok_or(PacketError::LayerNotFound(kind))
    }

    /// Returns the payload (data after all parsed headers).
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.layers
            .last()
            .map(|l| &self.data[l.end..])
            .unwrap_or(&self.data)
    }

    // ========================================================================
    // Typed Layer Access
    // ========================================================================

    /// Get the Ethernet layer view if present.
    pub fn ethernet(&self) -> Option<EthernetLayer> {
        self.get_layer(LayerKind::Ethernet)
            .map(|idx| EthernetLayer::new(idx.start, idx.end))
    }

    /// Get the IPv4 layer view if present.
    pub fn ipv4(&self) -> Option<Ipv4Layer> {
        self.get_layer(LayerKind::Ipv4)
            .map(|idx| Ipv4Layer::new(idx.start, idx.end))
    }

    /// Get the ARP layer view if present.
    pub fn arp(&self) -> Option<ArpLayer> {
        self.get_layer(LayerKind::Arp)
            .map(|idx| ArpLayer::new(idx.start, idx.end))
    }

    /// Get a LayerEnum for a given LayerIndex.
    pub fn layer_enum(&self, idx: &LayerIndex) -> LayerEnum {
        match idx.kind {
            LayerKind::Ethernet => LayerEnum::Ethernet(EthernetLayer::new(idx.start, idx.end)),
            LayerKind::Dot3 => LayerEnum::Dot3(Dot3Layer::new(idx.start, idx.end)),
            LayerKind::Arp => LayerEnum::Arp(ArpLayer::new(idx.start, idx.end)),
            LayerKind::Ipv4 => LayerEnum::Ipv4(Ipv4Layer::new(idx.start, idx.end)),
            LayerKind::Ipv6 => LayerEnum::Ipv6(Ipv6Layer { index: *idx }),
            LayerKind::Icmp => LayerEnum::Icmp(IcmpLayer { index: *idx }),
            LayerKind::Icmpv6 => LayerEnum::Icmpv6(Icmpv6Layer { index: *idx }),
            LayerKind::Tcp => LayerEnum::Tcp(TcpLayer::new(idx.start, idx.end)),
            LayerKind::Udp => LayerEnum::Udp(UdpLayer { index: *idx }),
            LayerKind::Dns => LayerEnum::Dns(DnsLayer { index: *idx }),
            LayerKind::Raw
            | LayerKind::Dot1Q
            | LayerKind::Dot1AD
            | LayerKind::Dot1AH
            | LayerKind::LLC
            | LayerKind::SNAP => LayerEnum::Raw(RawLayer { index: *idx }),
        }
    }

    /// Get all layers as LayerEnum objects.
    pub fn layer_enums(&self) -> Vec<LayerEnum> {
        self.layers.iter().map(|idx| self.layer_enum(idx)).collect()
    }

    // ========================================================================
    // Parsing (Index-Only)
    // ========================================================================

    /// Parses the packet to identify layer boundaries.
    pub fn parse(&mut self) -> Result<()> {
        self.layers.clear();

        if self.data.len() < ETHERNET_HEADER_LEN {
            return Ok(());
        }

        // Parse Ethernet header
        let eth_end = ETHERNET_HEADER_LEN;
        self.layers
            .push(LayerIndex::new(LayerKind::Ethernet, 0, eth_end));

        let etype = u16::from_be_bytes([self.data[12], self.data[13]]);

        match etype {
            ethertype::IPV4 => self.parse_ipv4(eth_end)?,
            ethertype::IPV6 => self.parse_ipv6(eth_end)?,
            ethertype::ARP => self.parse_arp(eth_end)?,
            _ => {
                if eth_end < self.data.len() {
                    self.layers
                        .push(LayerIndex::new(LayerKind::Raw, eth_end, self.data.len()));
                }
            }
        }

        Ok(())
    }

    fn parse_ipv4(&mut self, offset: usize) -> Result<()> {
        let min_size = 20;
        if offset + min_size > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + min_size,
                actual: self.data.len(),
            });
        }

        let ihl = (self.data[offset] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_len < min_size {
            return Err(PacketError::ParseError {
                offset,
                message: format!("invalid IHL: {}", ihl),
            });
        }

        let ip_end = offset + header_len;
        if ip_end > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: ip_end,
                actual: self.data.len(),
            });
        }

        self.layers
            .push(LayerIndex::new(LayerKind::Ipv4, offset, ip_end));

        let protocol = self.data[offset + 9];
        match protocol {
            ip_protocol::TCP => self.parse_tcp(ip_end)?,
            ip_protocol::UDP => self.parse_udp(ip_end)?,
            ip_protocol::ICMP => self.parse_icmp(ip_end)?,
            _ => {
                if ip_end < self.data.len() {
                    self.layers
                        .push(LayerIndex::new(LayerKind::Raw, ip_end, self.data.len()));
                }
            }
        }

        Ok(())
    }

    fn parse_ipv6(&mut self, offset: usize) -> Result<()> {
        let min_size = 40;
        if offset + min_size > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + min_size,
                actual: self.data.len(),
            });
        }

        let ip_end = offset + min_size;
        self.layers
            .push(LayerIndex::new(LayerKind::Ipv6, offset, ip_end));

        let next_header = self.data[offset + 6];
        match next_header {
            ip_protocol::TCP => self.parse_tcp(ip_end)?,
            ip_protocol::UDP => self.parse_udp(ip_end)?,
            ip_protocol::ICMPV6 => self.parse_icmpv6(ip_end)?,
            _ => {
                if ip_end < self.data.len() {
                    self.layers
                        .push(LayerIndex::new(LayerKind::Raw, ip_end, self.data.len()));
                }
            }
        }

        Ok(())
    }

    fn parse_arp(&mut self, offset: usize) -> Result<()> {
        // First check if we have enough bytes for hwlen/plen fields
        if offset + 5 > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + 5,
                actual: self.data.len(),
            });
        }

        let hwlen = self.data[offset + 4] as usize;
        let plen = self.data[offset + 5] as usize;
        let total_len = 8 + 2 * hwlen + 2 * plen;

        if offset + total_len > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + total_len,
                actual: self.data.len(),
            });
        }

        let arp_end = offset + total_len;
        self.layers
            .push(LayerIndex::new(LayerKind::Arp, offset, arp_end));

        if arp_end < self.data.len() {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, arp_end, self.data.len()));
        }

        Ok(())
    }

    fn parse_tcp(&mut self, offset: usize) -> Result<()> {
        let min_size = 20;
        if offset + min_size > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + min_size,
                actual: self.data.len(),
            });
        }

        let data_offset = ((self.data[offset + 12] >> 4) & 0x0F) as usize;
        let header_len = data_offset * 4;

        let tcp_end = (offset + header_len).min(self.data.len());
        self.layers
            .push(LayerIndex::new(LayerKind::Tcp, offset, tcp_end));

        if tcp_end < self.data.len() {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, tcp_end, self.data.len()));
        }

        Ok(())
    }

    fn parse_udp(&mut self, offset: usize) -> Result<()> {
        let min_size = 8;
        if offset + min_size > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + min_size,
                actual: self.data.len(),
            });
        }

        let udp_end = offset + min_size;
        self.layers
            .push(LayerIndex::new(LayerKind::Udp, offset, udp_end));

        // Check for DNS
        let dst_port = u16::from_be_bytes([self.data[offset + 2], self.data[offset + 3]]);
        let src_port = u16::from_be_bytes([self.data[offset], self.data[offset + 1]]);

        if (dst_port == 53 || src_port == 53) && udp_end + 12 <= self.data.len() {
            self.layers
                .push(LayerIndex::new(LayerKind::Dns, udp_end, self.data.len()));
        } else if udp_end < self.data.len() {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, udp_end, self.data.len()));
        }

        Ok(())
    }

    fn parse_icmp(&mut self, offset: usize) -> Result<()> {
        if offset + 8 > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + 8,
                actual: self.data.len(),
            });
        }
        self.layers
            .push(LayerIndex::new(LayerKind::Icmp, offset, self.data.len()));
        Ok(())
    }

    fn parse_icmpv6(&mut self, offset: usize) -> Result<()> {
        if offset + 8 > self.data.len() {
            return Err(PacketError::BufferTooShort {
                expected: offset + 8,
                actual: self.data.len(),
            });
        }
        self.layers
            .push(LayerIndex::new(LayerKind::Icmpv6, offset, self.data.len()));
        Ok(())
    }

    // ========================================================================
    // Mutation Support (Copy-on-Write)
    // ========================================================================

    /// Applies a mutation function to the packet data.
    pub fn with_data_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let bytes = std::mem::take(&mut self.data);
        let mut bytes_mut = bytes
            .try_into_mut()
            .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
        let result = f(&mut bytes_mut);
        self.data = bytes_mut.freeze();
        self.is_dirty = true;
        result
    }

    pub fn set_byte(&mut self, offset: usize, value: u8) {
        self.with_data_mut(|data| data[offset] = value);
    }

    pub fn set_bytes(&mut self, offset: usize, values: &[u8]) {
        self.with_data_mut(|data| data[offset..offset + values.len()].copy_from_slice(values));
    }

    #[inline]
    pub fn mark_dirty(&mut self) {
        self.is_dirty = true;
    }
    #[inline]
    pub fn mark_clean(&mut self) {
        self.is_dirty = false;
    }

    pub fn add_layer(&mut self, index: LayerIndex) {
        self.layers.push(index);
    }

    pub fn set_data(&mut self, data: BytesMut) {
        self.data = data.freeze();
        self.is_dirty = true;
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<u8>> for Packet {
    fn from(data: Vec<u8>) -> Self {
        Self::from_bytes(data)
    }
}

impl From<&[u8]> for Packet {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ARP_HEADER_LEN;
    use crate::layer::field::MacAddress;

    fn sample_arp_packet() -> Vec<u8> {
        vec![
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x06, // type: ARP
            // ARP header (28 bytes)
            0x00, 0x01, // hwtype: Ethernet
            0x08, 0x00, // ptype: IPv4
            0x06, 0x04, // hwlen, plen
            0x00, 0x01, // op: request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // hwsrc
            0xc0, 0xa8, 0x01, 0x01, // psrc: 192.168.1.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hwdst
            0xc0, 0xa8, 0x01, 0x02, // pdst: 192.168.1.2
        ]
    }

    #[test]
    fn test_packet_parse_arp() {
        let data = sample_arp_packet();
        let mut packet = Packet::from_bytes(data);
        packet.parse().unwrap();

        assert_eq!(packet.layer_count(), 2); // Ethernet + ARP

        let eth = packet.ethernet().unwrap();
        assert!(eth.is_broadcast(packet.as_bytes()));
        assert_eq!(eth.ethertype(packet.as_bytes()).unwrap(), ethertype::ARP);

        let arp = packet.arp().unwrap();
        assert!(arp.is_request(packet.as_bytes()));
    }

    #[test]
    fn test_packet_layer_access() {
        let data = sample_arp_packet();
        let mut packet = Packet::from_bytes(data);
        packet.parse().unwrap();

        let eth_bytes = packet.layer_bytes(LayerKind::Ethernet).unwrap();
        assert_eq!(eth_bytes.len(), ETHERNET_HEADER_LEN);

        let arp_bytes = packet.layer_bytes(LayerKind::Arp).unwrap();
        assert_eq!(arp_bytes.len(), ARP_HEADER_LEN);
    }

    #[test]
    fn test_packet_modify_through_layer() {
        let data = sample_arp_packet();
        let mut packet = Packet::from_bytes(data);
        packet.parse().unwrap();

        // Modify source MAC through ethernet layer
        let eth = packet.ethernet().unwrap();
        packet.with_data_mut(|buf| {
            eth.set_src(buf, MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
                .unwrap();
        });

        assert!(packet.is_dirty());
        let eth = packet.ethernet().unwrap();
        assert_eq!(
            eth.src(packet.as_bytes()).unwrap(),
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }
}
