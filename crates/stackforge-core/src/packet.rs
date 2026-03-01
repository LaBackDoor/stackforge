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
    SshLayer, TcpLayer, TlsLayer, UdpLayer,
    arp::ArpLayer,
    ethernet::{Dot3Layer, ETHERNET_HEADER_LEN, EthernetLayer},
    ethertype, icmp, ip_protocol,
    ipv4::Ipv4Layer,
    ssh::{SSH_PORT, is_ssh_payload},
    tls::is_tls_payload,
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

    /// Get the ICMP layer view if present.
    pub fn icmp(&self) -> Option<IcmpLayer> {
        self.get_layer(LayerKind::Icmp)
            .map(|idx| IcmpLayer { index: *idx })
    }

    /// Get the TCP layer view if present.
    pub fn tcp(&self) -> Option<TcpLayer> {
        self.get_layer(LayerKind::Tcp)
            .map(|idx| TcpLayer::new(idx.start, idx.end))
    }

    /// Get the UDP layer view if present.
    pub fn udp(&self) -> Option<UdpLayer> {
        self.get_layer(LayerKind::Udp)
            .map(|idx| UdpLayer { index: *idx })
    }

    /// Get the DNS layer view if present.
    pub fn dns(&self) -> Option<DnsLayer> {
        self.get_layer(LayerKind::Dns)
            .map(|idx| DnsLayer { index: *idx })
    }

    /// Get the TLS layer view if present.
    pub fn tls(&self) -> Option<TlsLayer> {
        self.get_layer(LayerKind::Tls)
            .map(|idx| TlsLayer { index: *idx })
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
            LayerKind::Ssh => LayerEnum::Ssh(SshLayer { index: *idx }),
            LayerKind::Tls => LayerEnum::Tls(TlsLayer { index: *idx }),
            LayerKind::Dot15d4 => {
                LayerEnum::Dot15d4(crate::layer::dot15d4::Dot15d4Layer::new(idx.start, idx.end))
            }
            LayerKind::Dot15d4Fcs => LayerEnum::Dot15d4Fcs(
                crate::layer::dot15d4::Dot15d4FcsLayer::new(idx.start, idx.end),
            ),
            LayerKind::Dot11 => {
                LayerEnum::Dot11(crate::layer::dot11::Dot11Layer::new(idx.start, idx.end))
            }
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
            // Check for SSH on port 22
            let src_port = u16::from_be_bytes([self.data[offset], self.data[offset + 1]]);
            let dst_port = u16::from_be_bytes([self.data[offset + 2], self.data[offset + 3]]);

            if (src_port == SSH_PORT || dst_port == SSH_PORT)
                && is_ssh_payload(&self.data[tcp_end..])
            {
                self.parse_ssh(tcp_end)?;
            } else if is_tls_payload(&self.data[tcp_end..]) {
                self.parse_tls(tcp_end)?;
            } else {
                self.layers
                    .push(LayerIndex::new(LayerKind::Raw, tcp_end, self.data.len()));
            }
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

        if (dst_port == 53 || src_port == 53 || dst_port == 5353 || src_port == 5353)
            && udp_end + 12 <= self.data.len()
        {
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

        // Add ICMP layer
        self.layers
            .push(LayerIndex::new(LayerKind::Icmp, offset, self.data.len()));

        // Check if this is an ICMP error message that contains an embedded packet
        // Error types: 3 (dest unreach), 4 (source quench), 5 (redirect), 11 (time exceeded), 12 (param problem)
        if offset < self.data.len() {
            let icmp_type = self.data[offset];
            if icmp::is_error_type(icmp_type) {
                // ICMP error messages have 8-byte header, then embedded IP packet
                let embedded_offset = offset + 8;
                if embedded_offset < self.data.len() {
                    // Try to parse the embedded IP packet
                    // Silently ignore errors since the embedded packet might be truncated
                    let _ = self.parse_ipv4(embedded_offset);
                }
            }
        }

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

    fn parse_ssh(&mut self, offset: usize) -> Result<()> {
        let remaining = &self.data[offset..];

        if remaining.len() >= 4 && &remaining[..4] == b"SSH-" {
            // SSH version exchange - spans until \r\n
            let end = remaining
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| offset + p + 2)
                .unwrap_or(self.data.len());
            self.layers
                .push(LayerIndex::new(LayerKind::Ssh, offset, end));
            if end < self.data.len() {
                self.layers
                    .push(LayerIndex::new(LayerKind::Raw, end, self.data.len()));
            }
        } else if remaining.len() >= 5 {
            // SSH binary packet
            let pkt_len =
                u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                    as usize;
            let end = (offset + 4 + pkt_len).min(self.data.len());
            self.layers
                .push(LayerIndex::new(LayerKind::Ssh, offset, end));
            if end < self.data.len() {
                self.layers
                    .push(LayerIndex::new(LayerKind::Raw, end, self.data.len()));
            }
        } else {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, offset, self.data.len()));
        }

        Ok(())
    }

    fn parse_tls(&mut self, offset: usize) -> Result<()> {
        use crate::layer::tls::TLS_RECORD_HEADER_LEN;

        let remaining = self.data.len() - offset;
        if remaining < TLS_RECORD_HEADER_LEN {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, offset, self.data.len()));
            return Ok(());
        }

        // Read the TLS record header
        let frag_len = u16::from_be_bytes([self.data[offset + 3], self.data[offset + 4]]) as usize;
        let record_end = (offset + TLS_RECORD_HEADER_LEN + frag_len).min(self.data.len());

        self.layers
            .push(LayerIndex::new(LayerKind::Tls, offset, record_end));

        // If there's more data after this record, treat as Raw
        // (could be additional TLS records, but we parse one for now)
        if record_end < self.data.len() {
            self.layers
                .push(LayerIndex::new(LayerKind::Raw, record_end, self.data.len()));
        }

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

    #[test]
    fn test_icmp_error_packet_parsing() {
        // ICMP Destination Unreachable with embedded UDP packet
        let data = vec![
            // Ethernet header (14 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x08, 0x00, // ethertype: IPv4
            // Outer IPv4 header (20 bytes) - ICMP error message from router
            0x45, 0x00, 0x00, 0x38, // ver/ihl, tos, total len = 56
            0x00, 0x01, 0x00, 0x00, // id, flags, frag offset
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP, checksum
            192, 168, 1, 1, // src: router
            192, 168, 1, 100, // dst: original sender
            // ICMP Destination Unreachable (8 bytes)
            0x03, // type = 3 (dest unreachable)
            0x03, // code = 3 (port unreachable)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // unused
            // Embedded original IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x1c, // ver/ihl, tos, total len = 28
            0xab, 0xcd, 0x00, 0x00, // id, flags, frag offset
            0x40, 0x11, 0x00, 0x00, // ttl=64, proto=UDP, checksum
            192, 168, 1, 100, // src: original sender
            8, 8, 8, 8, // dst: 8.8.8.8 (where packet was sent)
            // Embedded UDP header (first 8 bytes)
            0x04, 0xd2, // sport = 1234
            0x00, 0x35, // dport = 53 (DNS)
            0x00, 0x14, // length = 20
            0x00, 0x00, // checksum
        ];

        let mut packet = Packet::from_bytes(data);
        packet.parse().unwrap();

        // Should have: Ethernet, IP (outer), ICMP, IP (embedded), UDP (embedded)
        assert_eq!(packet.layer_count(), 5);

        // Verify outer IP layer
        assert!(packet.ethernet().is_some());
        assert!(packet.ipv4().is_some());
        assert!(packet.icmp().is_some());

        // Verify ICMP error type
        let icmp = packet.icmp().unwrap();
        let icmp_type = icmp.icmp_type(packet.as_bytes()).unwrap();
        assert_eq!(icmp_type, 3); // Destination unreachable

        // Verify embedded packet layers exist
        // The second IP layer is the embedded one
        let layers = packet.layers();
        let _embedded_ip_idx = layers
            .iter()
            .rposition(|idx| idx.kind == LayerKind::Ipv4)
            .unwrap();

        // Verify embedded UDP exists
        assert!(packet.udp().is_some());
    }

    #[test]
    fn test_icmp_time_exceeded_with_tcp() {
        // ICMP Time Exceeded with embedded TCP packet
        // Note: ICMP error messages typically only include first 8 bytes of transport header
        let data = vec![
            // Ethernet header
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
            // Outer IPv4 header
            0x45, 0x00, 0x00, 0x4c, // total len = 76 (longer to include full embedded packet)
            0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 0, 1, // src: router
            192, 168, 1, 100, // dst: original sender
            // ICMP Time Exceeded
            0x0b, // type = 11 (time exceeded)
            0x00, // code = 0 (TTL exceeded)
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // unused
            // Embedded original IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // total len = 40 (20 IP + 20 TCP)
            0x12, 0x34, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00, // ttl=1, proto=TCP
            192, 168, 1, 100, // src
            93, 184, 216, 34, // dst
            // Embedded TCP header (full 20 bytes for proper parsing)
            0x04, 0xd2, // sport = 1234
            0x00, 0x50, // dport = 80 (HTTP)
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x20, 0x00, // data offset=5, flags=SYN, window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ];

        let mut packet = Packet::from_bytes(data);
        packet.parse().unwrap();

        // Should have: Ethernet, IP (outer), ICMP, IP (embedded), TCP (embedded)
        assert_eq!(packet.layer_count(), 5);

        // Verify layers exist
        assert!(packet.icmp().is_some());
        assert!(packet.tcp().is_some());

        // Verify ICMP type
        let icmp = packet.icmp().unwrap();
        assert_eq!(icmp.icmp_type(packet.as_bytes()).unwrap(), 11);
    }

    #[test]
    fn test_icmp_with_extensions() {
        // ICMP Time Exceeded with RFC 4884 extensions (Interface Information)
        let data = vec![
            // Ethernet header
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // ethertype = IPv4
            // IPv4 header (outer)
            0x45, 0x00, 0x00, 0xa0, // version, ihl, tos, total_length (160 bytes)
            0x00, 0x01, 0x00, 0x00, // id, flags, fragment offset
            0x40, 0x01, 0x00, 0x00, // ttl=64, proto=ICMP, checksum
            0xc0, 0xa8, 0x01, 0x01, // src = 192.168.1.1
            0xc0, 0xa8, 0x01, 0x64, // dst = 192.168.1.100
            // ICMP header
            0x0b, // type = Time Exceeded
            0x00, // code = TTL exceeded
            0x00, 0x00, // checksum (will be wrong, but OK for parsing test)
            0x00, 0x00, 0x00, 0x00, // unused
            // Embedded IP packet (padded to 128 bytes per RFC 4884)
            0x45, 0x00, 0x00, 0x3c, // Embedded IPv4 header
            0x12, 0x34, 0x40, 0x00, // id, flags
            0x01, 0x11, 0x00, 0x00, // ttl=1, proto=UDP, checksum
            0xc0, 0xa8, 0x01, 0x64, // src = 192.168.1.100
            0x08, 0x08, 0x08, 0x08, // dst = 8.8.8.8
            // Embedded UDP header (first 8 bytes)
            0x04, 0xd2, 0x00, 0x35, // sport=1234, dport=53 (DNS)
            0x00, 0x28, 0x00, 0x00, // length, checksum
            // Padding to reach 128 bytes total (from start of embedded IP)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // ICMP Extension Header (4 bytes)
            0x20, 0x00, // version=2, reserved=0
            0x00, 0x00, // checksum (simplified, would need proper calculation)
            // ICMP Extension Object - Interface Information (classnum=2)
            0x00, 0x10, // length = 16 bytes
            0x02, // classnum = Interface Information
            0x19, // flags: has_ifindex=1, has_ipaddr=1, has_mtu=1
            0x00, 0x00, 0x00, 0x02, // ifindex = 2
            0x00, 0x01, 0x00, 0x00, // AFI = IPv4 (1), reserved
            0xc0, 0xa8, 0x01, 0x01, // IP = 192.168.1.1
        ];

        let mut packet = Packet::from_bytes(data.clone());
        packet.parse().unwrap();

        // Verify ICMP layer exists
        assert!(packet.icmp().is_some());
        let icmp = packet.icmp().unwrap();

        // Verify ICMP type
        assert_eq!(
            icmp.icmp_type(packet.as_bytes()).unwrap(),
            crate::layer::icmp::types::types::TIME_EXCEEDED
        );

        // Test extension detection
        use crate::layer::icmp;
        let icmp_offset = packet.layers()[1].end; // After outer IP
        let icmp_payload = &data[icmp_offset + 8..]; // After ICMP header

        assert!(icmp::has_extensions(
            crate::layer::icmp::types::types::TIME_EXCEEDED,
            icmp_payload.len()
        ));

        // Parse extension header
        let ext_offset = icmp_offset + 8 + 128; // ICMP header + padded payload
        if let Some((version, _checksum)) = icmp::parse_extension_header(&data, ext_offset) {
            assert_eq!(version, 2);

            // Parse extension object
            let obj_offset = ext_offset + 4;
            if let Some((len, classnum, _classtype, data_offset)) =
                icmp::parse_extension_object(&data, obj_offset)
            {
                assert_eq!(len, 16);
                assert_eq!(
                    classnum,
                    icmp::extensions::class_nums::INTERFACE_INFORMATION
                );

                // Parse Interface Information
                let data_len = (len as usize) - 4; // Object length minus header
                if let Some(info) = icmp::parse_interface_information(&data, data_offset, data_len)
                {
                    assert!(info.flags.has_ifindex);
                    assert!(info.flags.has_ipaddr);
                    assert_eq!(info.ifindex, Some(2));
                    if let Some(icmp::IpAddr::V4(ip)) = info.ip_addr {
                        assert_eq!(ip.to_string(), "192.168.1.1");
                    } else {
                        panic!("Expected IPv4 address");
                    }
                }
            }
        }
    }
}
