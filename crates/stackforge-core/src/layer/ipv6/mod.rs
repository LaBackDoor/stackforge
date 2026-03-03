//! IPv6 layer implementation.
//!
//! This module provides types and functions for working with IPv6 packets,
//! including parsing, field access, and next-header resolution.

pub mod builder;
pub mod ext_headers;

pub use builder::Ipv6Builder;
pub use ext_headers::{ExtHeader, ExtHeaderKind, parse_ext_headers};

use crate::layer::field::{Field, FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};
use std::net::Ipv6Addr;

/// IPv6 fixed header length (40 bytes).
pub const IPV6_HEADER_LEN: usize = 40;

/// Field offsets within the IPv6 header.
pub mod offsets {
    /// Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits) - bytes 0-3
    pub const VERSION_TC_FL: usize = 0;
    /// Payload length (16 bits)
    pub const PAYLOAD_LEN: usize = 4;
    /// Next Header (8 bits)
    pub const NEXT_HEADER: usize = 6;
    /// Hop Limit (8 bits)
    pub const HOP_LIMIT: usize = 7;
    /// Source address (128 bits = 16 bytes)
    pub const SRC: usize = 8;
    /// Destination address (128 bits = 16 bytes)
    pub const DST: usize = 24;
}

/// A view into an IPv6 packet header.
///
/// Uses the "Lazy Zero-Copy View" pattern: holds only layer boundaries
/// and reads fields directly from the buffer on demand.
#[derive(Debug, Clone)]
pub struct Ipv6Layer {
    pub index: LayerIndex,
}

impl Ipv6Layer {
    /// Create a new IPv6 layer view with specified bounds.
    #[inline]
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Ipv6, start, end),
        }
    }

    /// Create a layer at offset 0 with IPv6 header length.
    #[inline]
    #[must_use]
    pub const fn at_start() -> Self {
        Self::new(0, IPV6_HEADER_LEN)
    }

    /// Create a layer at the specified offset.
    #[inline]
    #[must_use]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + IPV6_HEADER_LEN)
    }

    // ========== Field Readers ==========

    /// Read the IP version (should be 6).
    #[inline]
    pub fn version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::VERSION_TC_FL,
                need: 1,
                have: 0,
            });
        }
        Ok((slice[0] >> 4) & 0x0F)
    }

    /// Read the Traffic Class field (8 bits).
    #[inline]
    pub fn traffic_class(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::VERSION_TC_FL,
                need: 2,
                have: slice.len(),
            });
        }
        Ok(((slice[0] & 0x0F) << 4) | ((slice[1] >> 4) & 0x0F))
    }

    /// Read the Flow Label field (20 bits).
    #[inline]
    pub fn flow_label(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::VERSION_TC_FL,
                need: 4,
                have: slice.len(),
            });
        }
        let fl =
            ((u32::from(slice[1]) & 0x0F) << 16) | (u32::from(slice[2]) << 8) | u32::from(slice[3]);
        Ok(fl)
    }

    /// Read the Payload Length field (16 bits).
    #[inline]
    pub fn payload_len(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::PAYLOAD_LEN + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::PAYLOAD_LEN,
                need: 2,
                have: slice.len().saturating_sub(offsets::PAYLOAD_LEN),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::PAYLOAD_LEN],
            slice[offsets::PAYLOAD_LEN + 1],
        ]))
    }

    /// Read the Next Header field (8 bits).
    #[inline]
    pub fn next_header(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() <= offsets::NEXT_HEADER {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::NEXT_HEADER,
                need: 1,
                have: slice.len().saturating_sub(offsets::NEXT_HEADER),
            });
        }
        Ok(slice[offsets::NEXT_HEADER])
    }

    /// Read the Hop Limit field (8 bits).
    #[inline]
    pub fn hop_limit(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() <= offsets::HOP_LIMIT {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::HOP_LIMIT,
                need: 1,
                have: slice.len().saturating_sub(offsets::HOP_LIMIT),
            });
        }
        Ok(slice[offsets::HOP_LIMIT])
    }

    /// Read the Source IPv6 address.
    #[inline]
    pub fn src(&self, buf: &[u8]) -> Result<Ipv6Addr, FieldError> {
        Ipv6Addr::read(buf, self.index.start + offsets::SRC)
    }

    /// Read the Destination IPv6 address.
    #[inline]
    pub fn dst(&self, buf: &[u8]) -> Result<Ipv6Addr, FieldError> {
        Ipv6Addr::read(buf, self.index.start + offsets::DST)
    }

    // ========== Field Writers ==========

    /// Set the version field (high 4 bits of byte 0).
    #[inline]
    pub fn set_version(&self, buf: &mut [u8], version: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::VERSION_TC_FL;
        if buf.len() <= offset {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset] = (buf[offset] & 0x0F) | ((version & 0x0F) << 4);
        Ok(())
    }

    /// Set the Traffic Class field.
    #[inline]
    pub fn set_traffic_class(&self, buf: &mut [u8], tc: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::VERSION_TC_FL;
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        // High nibble of TC goes into low nibble of byte 0
        buf[offset] = (buf[offset] & 0xF0) | ((tc >> 4) & 0x0F);
        // Low nibble of TC goes into high nibble of byte 1
        buf[offset + 1] = (buf[offset + 1] & 0x0F) | ((tc & 0x0F) << 4);
        Ok(())
    }

    /// Set the Flow Label field (20 bits).
    #[inline]
    pub fn set_flow_label(&self, buf: &mut [u8], fl: u32) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::VERSION_TC_FL;
        if buf.len() < offset + 4 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 4,
                have: buf.len().saturating_sub(offset),
            });
        }
        // Byte 1: keep high nibble (TC low nibble), set low nibble (FL bits 19-16)
        buf[offset + 1] = (buf[offset + 1] & 0xF0) | (((fl >> 16) & 0x0F) as u8);
        // Bytes 2-3: FL bits 15-0
        buf[offset + 2] = ((fl >> 8) & 0xFF) as u8;
        buf[offset + 3] = (fl & 0xFF) as u8;
        Ok(())
    }

    /// Set the Payload Length field.
    #[inline]
    pub fn set_payload_len(&self, buf: &mut [u8], len: u16) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::PAYLOAD_LEN;
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + 2].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }

    /// Set the Next Header field.
    #[inline]
    pub fn set_next_header(&self, buf: &mut [u8], nh: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::NEXT_HEADER;
        if buf.len() <= offset {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset] = nh;
        Ok(())
    }

    /// Set the Hop Limit field.
    #[inline]
    pub fn set_hop_limit(&self, buf: &mut [u8], hlim: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::HOP_LIMIT;
        if buf.len() <= offset {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset] = hlim;
        Ok(())
    }

    /// Set the source IPv6 address.
    #[inline]
    pub fn set_src(&self, buf: &mut [u8], src: Ipv6Addr) -> Result<(), FieldError> {
        src.write(buf, self.index.start + offsets::SRC)
    }

    /// Set the destination IPv6 address.
    #[inline]
    pub fn set_dst(&self, buf: &mut [u8], dst: Ipv6Addr) -> Result<(), FieldError> {
        dst.write(buf, self.index.start + offsets::DST)
    }

    // ========== Dynamic Field Access ==========

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "version" => Some(self.version(buf).map(FieldValue::U8)),
            "tc" | "traffic_class" => Some(self.traffic_class(buf).map(FieldValue::U8)),
            "fl" | "flow_label" => Some(self.flow_label(buf).map(FieldValue::U32)),
            "plen" | "payload_len" => Some(self.payload_len(buf).map(FieldValue::U16)),
            "nh" | "next_header" => Some(self.next_header(buf).map(FieldValue::U8)),
            "hlim" | "hop_limit" => Some(self.hop_limit(buf).map(FieldValue::U8)),
            "src" => Some(self.src(buf).map(FieldValue::Ipv6)),
            "dst" => Some(self.dst(buf).map(FieldValue::Ipv6)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match (name, value) {
            ("version", FieldValue::U8(v)) => Some(self.set_version(buf, v)),
            ("tc" | "traffic_class", FieldValue::U8(v)) => Some(self.set_traffic_class(buf, v)),
            ("fl" | "flow_label", FieldValue::U32(v)) => Some(self.set_flow_label(buf, v)),
            ("plen" | "payload_len", FieldValue::U16(v)) => Some(self.set_payload_len(buf, v)),
            ("nh" | "next_header", FieldValue::U8(v)) => Some(self.set_next_header(buf, v)),
            ("hlim" | "hop_limit", FieldValue::U8(v)) => Some(self.set_hop_limit(buf, v)),
            ("src", FieldValue::Ipv6(v)) => Some(self.set_src(buf, v)),
            ("dst", FieldValue::Ipv6(v)) => Some(self.set_dst(buf, v)),
            _ => None,
        }
    }

    /// Get the list of field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &["version", "tc", "fl", "plen", "nh", "hlim", "src", "dst"]
    }

    // ========== Utility Methods ==========

    /// Generate a human-readable summary string.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let src = self
            .src(buf)
            .map_or_else(|_| "?".to_string(), |a| a.to_string());
        let dst = self
            .dst(buf)
            .map_or_else(|_| "?".to_string(), |a| a.to_string());
        format!("IPv6 {src} > {dst}")
    }

    /// Get the header length (always 40 for IPv6 base header).
    #[must_use]
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        IPV6_HEADER_LEN
    }

    /// Determine the next layer kind based on next header value.
    #[must_use]
    pub fn next_layer(&self, buf: &[u8]) -> Option<LayerKind> {
        use crate::layer::ipv4::protocol;
        self.next_header(buf).ok().and_then(|nh| match nh {
            protocol::TCP => Some(LayerKind::Tcp),
            protocol::UDP => Some(LayerKind::Udp),
            protocol::ICMPV6 => Some(LayerKind::Icmpv6),
            _ => None,
        })
    }

    /// Compute hash for packet matching (like Scapy's hashret).
    #[must_use]
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let src = self.src(buf).map(|ip| ip.octets()).unwrap_or([0; 16]);
        let dst = self.dst(buf).map(|ip| ip.octets()).unwrap_or([0; 16]);
        let nh = self.next_header(buf).unwrap_or(0);

        let mut result = Vec::with_capacity(17);
        for i in 0..16 {
            result.push(src[i] ^ dst[i]);
        }
        result.push(nh);
        result
    }

    /// Check if this packet answers another (for `sr()` matching).
    #[must_use]
    pub fn answers(&self, buf: &[u8], other: &Ipv6Layer, other_buf: &[u8]) -> bool {
        let self_src = self.src(buf).ok();
        let self_dst = self.dst(buf).ok();
        let other_src = other.src(other_buf).ok();
        let other_dst = other.dst(other_buf).ok();

        // Response src should match request dst
        if self_src != other_dst {
            return false;
        }
        // Response dst should match request src
        if self_dst != other_src {
            return false;
        }
        true
    }
}

impl Layer for Ipv6Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Ipv6
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    fn hashret(&self, data: &[u8]) -> Vec<u8> {
        self.hashret(data)
    }

    fn answers(&self, data: &[u8], other: &Self, other_data: &[u8]) -> bool {
        self.answers(data, other, other_data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        Self::field_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv6_buf(src: Ipv6Addr, dst: Ipv6Addr, nh: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 40];
        // Version = 6, TC = 0, FL = 0
        buf[0] = 0x60;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        // Payload length = 0
        buf[4] = 0;
        buf[5] = 0;
        // Next header
        buf[6] = nh;
        // Hop limit
        buf[7] = 64;
        // Source address
        buf[8..24].copy_from_slice(&src.octets());
        // Destination address
        buf[24..40].copy_from_slice(&dst.octets());
        buf
    }

    #[test]
    fn test_ipv6_version() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let buf = make_ipv6_buf(src, dst, 58);
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.version(&buf).unwrap(), 6);
    }

    #[test]
    fn test_ipv6_addresses() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let buf = make_ipv6_buf(src, dst, 58);
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.src(&buf).unwrap(), src);
        assert_eq!(layer.dst(&buf).unwrap(), dst);
    }

    #[test]
    fn test_ipv6_next_header() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let buf = make_ipv6_buf(src, dst, 58); // ICMPv6
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.next_header(&buf).unwrap(), 58);
    }

    #[test]
    fn test_ipv6_hop_limit() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let buf = make_ipv6_buf(src, dst, 6);
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.hop_limit(&buf).unwrap(), 64);
    }

    #[test]
    fn test_ipv6_traffic_class() {
        let mut buf = vec![0u8; 40];
        // Version=6, TC=0xAB, FL=0
        buf[0] = 0x60 | ((0xABu8 >> 4) & 0x0F); // 0x6A
        buf[1] = ((0xABu8 & 0x0F) << 4) | 0x00; // 0xB0
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.traffic_class(&buf).unwrap(), 0xAB);
    }

    #[test]
    fn test_ipv6_flow_label() {
        let mut buf = vec![0u8; 40];
        // Version=6, TC=0, FL=0x12345
        buf[0] = 0x60;
        buf[1] = 0x01; // FL bits 19-16 = 1
        buf[2] = 0x23; // FL bits 15-8
        buf[3] = 0x45; // FL bits 7-0
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.flow_label(&buf).unwrap(), 0x12345);
    }

    #[test]
    fn test_ipv6_summary() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let buf = make_ipv6_buf(src, dst, 58);
        let layer = Ipv6Layer::at_start();
        let summary = layer.summary(&buf);
        assert!(summary.contains("IPv6"));
        assert!(summary.contains("2001:db8::1"));
        assert!(summary.contains("2001:db8::2"));
    }

    #[test]
    fn test_ipv6_get_field() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let buf = make_ipv6_buf(src, dst, 17); // UDP
        let layer = Ipv6Layer::at_start();

        if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "version") {
            assert_eq!(v, 6);
        } else {
            panic!("expected version = 6");
        }

        if let Some(Ok(FieldValue::U8(v))) = layer.get_field(&buf, "nh") {
            assert_eq!(v, 17); // UDP
        } else {
            panic!("expected nh = 17");
        }
    }

    #[test]
    fn test_ipv6_set_field() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let mut buf = make_ipv6_buf(src, dst, 6);
        let layer = Ipv6Layer::at_start();

        // Change hop limit
        layer
            .set_field(&mut buf, "hlim", FieldValue::U8(128))
            .unwrap()
            .unwrap();
        assert_eq!(layer.hop_limit(&buf).unwrap(), 128);
    }

    #[test]
    fn test_ipv6_set_addresses() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let mut buf = make_ipv6_buf(src, dst, 6);
        let layer = Ipv6Layer::at_start();

        let new_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        layer.set_src(&mut buf, new_src).unwrap();
        assert_eq!(layer.src(&buf).unwrap(), new_src);
    }

    #[test]
    fn test_ipv6_payload_len() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let mut buf = make_ipv6_buf(src, dst, 58);
        buf[4] = 0x00;
        buf[5] = 0x28; // 40 bytes
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.payload_len(&buf).unwrap(), 40);
    }

    #[test]
    fn test_ipv6_header_len() {
        let buf = vec![0u8; 40];
        let layer = Ipv6Layer::at_start();
        assert_eq!(layer.header_len(&buf), IPV6_HEADER_LEN);
        assert_eq!(IPV6_HEADER_LEN, 40);
    }
}
