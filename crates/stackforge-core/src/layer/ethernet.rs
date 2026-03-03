//! Ethernet II frame layer implementation.
//!
//! This module provides complete Ethernet II frame handling including
//! dispatch hooks for 802.3 detection and Scapy-compatible methods.

use crate::layer::field::{Field, FieldDesc, FieldError, FieldType, FieldValue, MacAddress};
use crate::layer::{Layer, LayerIndex, LayerKind, ethertype};

/// Ethernet header length in bytes.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Maximum value for 802.3 length field (values > 1500 are `EtherTypes`)
pub const DOT3_MAX_LENGTH: u16 = 1500;

/// Field offsets within Ethernet header.
pub mod offsets {
    pub const DST: usize = 0;
    pub const SRC: usize = 6;
    pub const TYPE: usize = 12;
}

/// Field descriptors for dynamic access (Ethernet II).
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::new("dst", offsets::DST, 6, FieldType::Mac),
    FieldDesc::new("src", offsets::SRC, 6, FieldType::Mac),
    FieldDesc::new("type", offsets::TYPE, 2, FieldType::U16),
];

/// Field descriptors for dynamic access (802.3/Dot3).
pub static DOT3_FIELDS: &[FieldDesc] = &[
    FieldDesc::new("dst", offsets::DST, 6, FieldType::Mac),
    FieldDesc::new("src", offsets::SRC, 6, FieldType::Mac),
    FieldDesc::new("len", offsets::TYPE, 2, FieldType::U16),
];

/// Frame type discrimination result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetFrameType {
    /// Ethernet II (`EtherType` > 1500)
    EthernetII,
    /// IEEE 802.3 (length field <= 1500)
    Dot3,
}

/// Dispatch hook to determine frame type (Ethernet II vs 802.3)
#[inline]
#[must_use]
pub fn dispatch_hook(buf: &[u8], offset: usize) -> EthernetFrameType {
    if buf.len() < offset + ETHERNET_HEADER_LEN {
        return EthernetFrameType::EthernetII;
    }

    let type_or_len = u16::from_be_bytes([buf[offset + 12], buf[offset + 13]]);

    if type_or_len <= DOT3_MAX_LENGTH {
        EthernetFrameType::Dot3
    } else {
        EthernetFrameType::EthernetII
    }
}

/// Check if a frame at offset is 802.3 (not Ethernet II)
#[inline]
#[must_use]
pub fn is_dot3(buf: &[u8], offset: usize) -> bool {
    dispatch_hook(buf, offset) == EthernetFrameType::Dot3
}

/// Check if a frame at offset is Ethernet II
#[inline]
#[must_use]
pub fn is_ethernet_ii(buf: &[u8], offset: usize) -> bool {
    dispatch_hook(buf, offset) == EthernetFrameType::EthernetII
}

/// A view into an Ethernet II frame.
#[derive(Debug, Clone)]
pub struct EthernetLayer {
    pub index: LayerIndex,
}

impl EthernetLayer {
    #[inline]
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Ethernet, start, end),
        }
    }

    #[inline]
    #[must_use]
    pub const fn at_start() -> Self {
        Self::new(0, ETHERNET_HEADER_LEN)
    }

    #[inline]
    #[must_use]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + ETHERNET_HEADER_LEN)
    }

    #[inline]
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + ETHERNET_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: ETHERNET_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// Dispatch hook: returns appropriate layer type based on type/length field
    #[must_use]
    pub fn dispatch(buf: &[u8], offset: usize) -> EthernetFrameType {
        dispatch_hook(buf, offset)
    }

    // ========== Field Readers ==========
    #[inline]
    pub fn dst(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::DST)
    }

    #[inline]
    pub fn src(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::SRC)
    }

    #[inline]
    pub fn ethertype(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::TYPE)
    }

    // ========== Field Writers ==========
    #[inline]
    pub fn set_dst(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::DST)
    }

    #[inline]
    pub fn set_src(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::SRC)
    }

    #[inline]
    pub fn set_ethertype(&self, buf: &mut [u8], etype: u16) -> Result<(), FieldError> {
        etype.write(buf, self.index.start + offsets::TYPE)
    }

    // ========== Dynamic Field Access ==========
    #[must_use]
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        FIELDS
            .iter()
            .find(|f| f.name == name)
            .map(|desc| FieldValue::read(buf, &desc.with_offset(self.index.start)))
    }

    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        FIELDS
            .iter()
            .find(|f| f.name == name)
            .map(|desc| value.write(buf, &desc.with_offset(self.index.start)))
    }

    pub fn set_field_value<V: Into<FieldValue>>(
        &self,
        buf: &mut [u8],
        name: &str,
        value: V,
    ) -> Option<Result<(), FieldError>> {
        self.set_field(buf, name, value.into())
    }

    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &["dst", "src", "type"]
    }

    /// Compute hash for packet matching.
    /// Returns type field + payload hash for matching request/response pairs.
    #[must_use]
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let etype = self.ethertype(buf).unwrap_or(0);
        etype.to_be_bytes().to_vec()
        // In full implementation, would append: + self.payload_layer().hashret()
    }

    /// Check if this packet answers another.
    /// For Ethernet, this delegates to payload matching.
    #[must_use]
    pub fn answers(&self, buf: &[u8], other: &EthernetLayer, other_buf: &[u8]) -> bool {
        // Types must match
        if self.ethertype(buf) != other.ethertype(other_buf) {
            return false;
        }
        // In full implementation, would delegate to payload:
        // self.payload_layer().answers(other.payload_layer())
        true
    }

    /// Extract padding (Ethernet II has no padding concept at this layer)
    #[must_use]
    pub fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let payload_start = self.index.end.min(buf.len());
        (&buf[payload_start..], &[])
    }

    // ========== Utility Methods ==========
    #[inline]
    #[must_use]
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.index.end..]
    }

    #[inline]
    #[must_use]
    pub fn payload_copy(&self, buf: &[u8]) -> Vec<u8> {
        buf[self.index.end..].to_vec()
    }

    #[must_use]
    pub fn next_layer(&self, buf: &[u8]) -> Option<LayerKind> {
        self.ethertype(buf).ok().and_then(|t| match t {
            ethertype::IPV4 => Some(LayerKind::Ipv4),
            ethertype::IPV6 => Some(LayerKind::Ipv6),
            ethertype::ARP => Some(LayerKind::Arp),
            ethertype::VLAN => Some(LayerKind::Raw), // Would be Dot1Q
            _ => None,
        })
    }

    #[inline]
    #[must_use]
    pub fn is_broadcast(&self, buf: &[u8]) -> bool {
        self.dst(buf).map(|m| m.is_broadcast()).unwrap_or(false)
    }

    #[inline]
    #[must_use]
    pub fn is_multicast(&self, buf: &[u8]) -> bool {
        self.dst(buf).map(|m| m.is_multicast()).unwrap_or(false)
    }

    #[inline]
    #[must_use]
    pub fn is_unicast(&self, buf: &[u8]) -> bool {
        self.dst(buf).map(|m| m.is_unicast()).unwrap_or(false)
    }

    #[inline]
    #[must_use]
    pub fn header_bytes<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.index.start..self.index.end.min(buf.len())]
    }

    #[inline]
    #[must_use]
    pub fn header_copy(&self, buf: &[u8]) -> Vec<u8> {
        self.header_bytes(buf).to_vec()
    }

    /// Get `EtherType` name
    pub fn ethertype_name(&self, buf: &[u8]) -> &'static str {
        self.ethertype(buf)
            .map(ethertype::name)
            .unwrap_or("Unknown")
    }

    /// Routing for Ethernet layer
    #[must_use]
    pub fn route(&self, _buf: &[u8]) -> Option<String> {
        // Would delegate to payload for actual routing
        // For now, return None - caller must use payload's route()
        None
    }
}

impl Layer for EthernetLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Ethernet
    }

    fn summary(&self, buf: &[u8]) -> String {
        let dst = self.dst(buf).map_or_else(|_| "?".into(), |m| m.to_string());
        let src = self.src(buf).map_or_else(|_| "?".into(), |m| m.to_string());
        let etype = self.ethertype(buf).unwrap_or(0);
        format!("{} > {} ({})", src, dst, ethertype::name(etype))
    }

    fn header_len(&self, _buf: &[u8]) -> usize {
        ETHERNET_HEADER_LEN
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        self.answers(buf, other, other_buf)
    }

    fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        self.extract_padding(buf)
    }
}

// ============================================================================
// IEEE 802.3 Layer
// ============================================================================

/// IEEE 802.3 frame (uses length field instead of `EtherType`)
#[derive(Debug, Clone)]
pub struct Dot3Layer {
    pub index: LayerIndex,
}

impl Dot3Layer {
    #[inline]
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Raw, start, end),
        } // Using Raw for now
    }

    #[inline]
    #[must_use]
    pub const fn at_start() -> Self {
        Self::new(0, ETHERNET_HEADER_LEN)
    }

    #[inline]
    #[must_use]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + ETHERNET_HEADER_LEN)
    }

    #[inline]
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + ETHERNET_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: ETHERNET_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    // ========== Field Readers ==========
    #[inline]
    pub fn dst(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::DST)
    }

    #[inline]
    pub fn src(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::SRC)
    }

    /// Length field (not `EtherType`!)
    #[inline]
    pub fn len_field(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::TYPE)
    }

    // ========== Field Writers ==========
    #[inline]
    pub fn set_dst(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::DST)
    }

    #[inline]
    pub fn set_src(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::SRC)
    }

    #[inline]
    pub fn set_len(&self, buf: &mut [u8], len: u16) -> Result<(), FieldError> {
        len.write(buf, self.index.start + offsets::TYPE)
    }

    /// Extract padding based on length field
    #[must_use]
    pub fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let len = self.len_field(buf).unwrap_or(0) as usize;
        let payload_start = self.index.end;
        let payload_end = (payload_start + len).min(buf.len());

        (&buf[payload_start..payload_end], &buf[payload_end..])
    }

    /// Hash for packet matching
    #[must_use]
    pub fn hashret(&self, _buf: &[u8]) -> Vec<u8> {
        // 802.3 hashret delegates to payload
        vec![]
    }

    /// Check if this answers another packet
    #[must_use]
    pub fn answers(&self, _buf: &[u8], _other: &Dot3Layer, _other_buf: &[u8]) -> bool {
        // Delegates to payload
        true
    }

    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let dst = self.dst(buf).map_or_else(|_| "?".into(), |m| m.to_string());
        let src = self.src(buf).map_or_else(|_| "?".into(), |m| m.to_string());
        format!("802.3 {src} > {dst}")
    }

    // ========== Dynamic Field Access ==========
    #[must_use]
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        DOT3_FIELDS
            .iter()
            .find(|f| f.name == name)
            .map(|desc| FieldValue::read(buf, &desc.with_offset(self.index.start)))
    }

    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        DOT3_FIELDS
            .iter()
            .find(|f| f.name == name)
            .map(|desc| value.write(buf, &desc.with_offset(self.index.start)))
    }

    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &["dst", "src", "len"]
    }
}

// ============================================================================
// EthernetBuilder
// ============================================================================

#[derive(Debug, Clone)]
pub struct EthernetBuilder {
    dst: MacAddress,
    src: MacAddress,
    ethertype: u16,
}

impl Default for EthernetBuilder {
    fn default() -> Self {
        Self {
            dst: MacAddress::BROADCAST,
            src: MacAddress::ZERO,
            ethertype: 0x9000, // Loopback (Scapy default)
        }
    }
}

impl EthernetBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn dst(mut self, mac: MacAddress) -> Self {
        self.dst = mac;
        self
    }
    #[must_use]
    pub fn src(mut self, mac: MacAddress) -> Self {
        self.src = mac;
        self
    }
    #[must_use]
    pub fn ethertype(mut self, etype: u16) -> Self {
        self.ethertype = etype;
        self
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    pub fn build_into(&self, buf: &mut [u8]) -> Result<(), FieldError> {
        let layer = EthernetLayer::at_start();
        layer.set_dst(buf, self.dst)?;
        layer.set_src(buf, self.src)?;
        layer.set_ethertype(buf, self.ethertype)?;
        Ok(())
    }

    #[must_use]
    pub fn build_with_payload(&self, payload_kind: LayerKind) -> Vec<u8> {
        let etype = match payload_kind {
            LayerKind::Ipv4 => ethertype::IPV4,
            LayerKind::Ipv6 => ethertype::IPV6,
            LayerKind::Arp => ethertype::ARP,
            _ => self.ethertype,
        };

        let mut buf = vec![0u8; ETHERNET_HEADER_LEN];
        let layer = EthernetLayer::at_start();
        layer.set_dst(&mut buf, self.dst).unwrap();
        layer.set_src(&mut buf, self.src).unwrap();
        layer.set_ethertype(&mut buf, etype).unwrap();
        buf
    }
}

// ============================================================================
// Dot3Builder
// ============================================================================

#[derive(Debug, Clone)]
pub struct Dot3Builder {
    dst: MacAddress,
    src: MacAddress,
    len: Option<u16>, // Auto-calculated if None
}

impl Default for Dot3Builder {
    fn default() -> Self {
        Self {
            dst: MacAddress::BROADCAST,
            src: MacAddress::ZERO,
            len: None,
        }
    }
}

impl Dot3Builder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn dst(mut self, mac: MacAddress) -> Self {
        self.dst = mac;
        self
    }
    #[must_use]
    pub fn src(mut self, mac: MacAddress) -> Self {
        self.src = mac;
        self
    }
    #[must_use]
    pub fn len(mut self, len: u16) -> Self {
        self.len = Some(len);
        self
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    pub fn build_into(&self, buf: &mut [u8]) -> Result<(), FieldError> {
        let layer = Dot3Layer::at_start();
        layer.set_dst(buf, self.dst)?;
        layer.set_src(buf, self.src)?;
        layer.set_len(buf, self.len.unwrap_or(0))?;
        Ok(())
    }

    /// Build with auto-calculated length based on payload
    #[must_use]
    pub fn build_with_payload(&self, payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN];
        let layer = Dot3Layer::at_start();
        layer.set_dst(&mut buf, self.dst).unwrap();
        layer.set_src(&mut buf, self.src).unwrap();
        layer
            .set_len(&mut buf, self.len.unwrap_or(payload_len as u16))
            .unwrap();
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ethernet_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ]
    }

    fn sample_dot3_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00,
            0x04, // Length = 4 (< 1500)
            0xde, 0xad, 0xbe, 0xef,
        ]
    }

    #[test]
    fn test_dispatch_hook() {
        let eth2 = sample_ethernet_frame();
        let dot3 = sample_dot3_frame();

        assert_eq!(dispatch_hook(&eth2, 0), EthernetFrameType::EthernetII);
        assert_eq!(dispatch_hook(&dot3, 0), EthernetFrameType::Dot3);

        assert!(!is_dot3(&eth2, 0));
        assert!(is_dot3(&dot3, 0));
    }

    #[test]
    fn test_ethernet_hashret() {
        let buf = sample_ethernet_frame();
        let eth = EthernetLayer::at_start();
        let hash = eth.hashret(&buf);

        assert_eq!(hash, vec![0x08, 0x00]); // IPv4 EtherType
    }

    #[test]
    fn test_ethernet_answers() {
        let buf1 = sample_ethernet_frame();
        let buf2 = sample_ethernet_frame();
        let eth1 = EthernetLayer::at_start();
        let eth2 = EthernetLayer::at_start();

        assert!(eth1.answers(&buf1, &eth2, &buf2));
    }

    #[test]
    fn test_dot3_layer() {
        let buf = sample_dot3_frame();
        let dot3 = Dot3Layer::at_start();

        assert_eq!(dot3.len_field(&buf).unwrap(), 4);

        let (payload, padding) = dot3.extract_padding(&buf);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(padding.is_empty());
    }

    #[test]
    fn test_dot3_with_padding() {
        let mut buf = sample_dot3_frame();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Add padding

        let dot3 = Dot3Layer::at_start();
        let (payload, padding) = dot3.extract_padding(&buf);

        assert_eq!(payload.len(), 4);
        assert_eq!(padding.len(), 4);
    }

    #[test]
    fn test_dot3_builder() {
        let frame = Dot3Builder::new()
            .dst(MacAddress::BROADCAST)
            .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
            .len(100)
            .build();

        let dot3 = Dot3Layer::at_start();
        assert_eq!(dot3.len_field(&frame).unwrap(), 100);
    }

    #[test]
    fn test_ethertype_name() {
        let buf = sample_ethernet_frame();
        let eth = EthernetLayer::at_start();

        assert_eq!(eth.ethertype_name(&buf), "IPv4");
    }
}
