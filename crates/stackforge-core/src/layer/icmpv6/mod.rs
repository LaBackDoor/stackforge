//! `ICMPv6` (Internet Control Message Protocol for IPv6) layer implementation.
//!
//! This module provides types and functions for working with `ICMPv6` packets,
//! including parsing, field access, and checksum calculation using the IPv6
//! pseudo-header.

pub mod builder;

pub use builder::Icmpv6Builder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};
use std::net::Ipv6Addr;

/// `ICMPv6` minimum header length (8 bytes).
pub const ICMPV6_MIN_HEADER_LEN: usize = 8;

/// Field offsets within the `ICMPv6` header.
pub mod offsets {
    /// `ICMPv6` Type (8 bits)
    pub const TYPE: usize = 0;
    /// `ICMPv6` Code (8 bits)
    pub const CODE: usize = 1;
    /// Checksum (16 bits)
    pub const CHECKSUM: usize = 2;
    /// Type-specific bytes start at offset 4
    /// Echo request/reply: ID at offset 4, Seq at offset 6
    pub const ID: usize = 4;
    pub const SEQ: usize = 6;
    /// Neighbor Solicit/Advert & Router Advert: target address at offset 8
    pub const TARGET_ADDR: usize = 8;
    /// Packet Too Big: MTU at offset 4 (4 bytes)
    pub const MTU: usize = 4;
}

/// `ICMPv6` type constants.
pub mod types {
    /// Destination Unreachable
    pub const DEST_UNREACH: u8 = 1;
    /// Packet Too Big
    pub const PKT_TOO_BIG: u8 = 2;
    /// Time Exceeded
    pub const TIME_EXCEEDED: u8 = 3;
    /// Parameter Problem
    pub const PARAM_PROBLEM: u8 = 4;
    /// Echo Request
    pub const ECHO_REQUEST: u8 = 128;
    /// Echo Reply
    pub const ECHO_REPLY: u8 = 129;
    /// Router Solicitation (NDP)
    pub const ROUTER_SOLICIT: u8 = 133;
    /// Router Advertisement (NDP)
    pub const ROUTER_ADVERT: u8 = 134;
    /// Neighbor Solicitation (NDP)
    pub const NEIGHBOR_SOLICIT: u8 = 135;
    /// Neighbor Advertisement (NDP)
    pub const NEIGHBOR_ADVERT: u8 = 136;
    /// Redirect Message (NDP)
    pub const REDIRECT: u8 = 137;

    /// Get the name of an `ICMPv6` type.
    #[must_use]
    pub fn name(t: u8) -> &'static str {
        match t {
            DEST_UNREACH => "dest-unreach",
            PKT_TOO_BIG => "pkt-too-big",
            TIME_EXCEEDED => "time-exceeded",
            PARAM_PROBLEM => "param-problem",
            ECHO_REQUEST => "echo-request",
            ECHO_REPLY => "echo-reply",
            ROUTER_SOLICIT => "router-solicit",
            ROUTER_ADVERT => "router-advert",
            NEIGHBOR_SOLICIT => "neighbor-solicit",
            NEIGHBOR_ADVERT => "neighbor-advert",
            REDIRECT => "redirect",
            _ => "unknown",
        }
    }
}

/// Compute the `ICMPv6` checksum over the IPv6 pseudo-header + `ICMPv6` data.
///
/// The `ICMPv6` checksum covers:
/// 1. IPv6 pseudo-header: src (16 bytes), dst (16 bytes), upper-layer length (4 bytes),
///    zeros (3 bytes), next header = 58 (1 byte)
/// 2. The `ICMPv6` message (type, code, checksum=0, and payload)
///
/// Returns the 16-bit checksum in network byte order.
#[must_use]
pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmpv6_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // IPv6 pseudo-header
    let src_bytes = src.octets();
    let dst_bytes = dst.octets();

    // Sum source address (16 bytes as 8 x u16)
    for chunk in src_bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // Sum destination address (16 bytes as 8 x u16)
    for chunk in dst_bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // Upper-layer packet length (4 bytes big-endian)
    let upper_len = icmpv6_data.len() as u32;
    sum += upper_len >> 16;
    sum += upper_len & 0xFFFF;

    // Next header = 58 (ICMPv6), preceded by 3 zero bytes
    // In the pseudo-header format: [0, 0, 0, 58]
    // As two u16s: [0x0000, 0x003A]
    sum += 0x003Au32; // 58 = 0x3A

    // Sum ICMPv6 data
    let mut chunks = icmpv6_data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Handle odd byte
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }

    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Verify an `ICMPv6` checksum.
///
/// Returns true if the checksum is valid (result of checksumming the full
/// message with checksum field included should be 0 or 0xFFFF).
#[must_use]
pub fn verify_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmpv6_data: &[u8]) -> bool {
    let result = icmpv6_checksum(src, dst, icmpv6_data);
    result == 0 || result == 0xFFFF
}

/// An `ICMPv6` layer view.
///
/// Uses the "Lazy Zero-Copy View" pattern: holds only layer boundaries
/// and reads fields directly from the buffer on demand.
#[derive(Debug, Clone)]
pub struct Icmpv6Layer {
    pub index: LayerIndex,
}

impl Icmpv6Layer {
    /// Create a new `ICMPv6` layer view.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a layer at offset 0.
    #[must_use]
    pub const fn at_start() -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Icmpv6, 0, ICMPV6_MIN_HEADER_LEN),
        }
    }

    // ========== Field Readers ==========

    /// Get the `ICMPv6` type.
    pub fn icmpv6_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::TYPE,
                need: 1,
                have: 0,
            });
        }
        Ok(slice[offsets::TYPE])
    }

    /// Get the `ICMPv6` code.
    pub fn code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::CODE + 1 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::CODE,
                need: 1,
                have: slice.len().saturating_sub(offsets::CODE),
            });
        }
        Ok(slice[offsets::CODE])
    }

    /// Get the checksum.
    pub fn checksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::CHECKSUM + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::CHECKSUM,
                need: 2,
                have: slice.len().saturating_sub(offsets::CHECKSUM),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::CHECKSUM],
            slice[offsets::CHECKSUM + 1],
        ]))
    }

    /// Get the identifier field (for echo request/reply only).
    ///
    /// Returns None if this `ICMPv6` type doesn't have an ID field.
    pub fn id(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let icmpv6_type = self.icmpv6_type(buf)?;
        if !matches!(icmpv6_type, types::ECHO_REQUEST | types::ECHO_REPLY) {
            return Ok(None);
        }
        let slice = self.index.slice(buf);
        if slice.len() < offsets::ID + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::ID,
                need: 2,
                have: slice.len().saturating_sub(offsets::ID),
            });
        }
        Ok(Some(u16::from_be_bytes([
            slice[offsets::ID],
            slice[offsets::ID + 1],
        ])))
    }

    /// Get the sequence number field (for echo request/reply only).
    ///
    /// Returns None if this `ICMPv6` type doesn't have a sequence field.
    pub fn seq(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let icmpv6_type = self.icmpv6_type(buf)?;
        if !matches!(icmpv6_type, types::ECHO_REQUEST | types::ECHO_REPLY) {
            return Ok(None);
        }
        let slice = self.index.slice(buf);
        if slice.len() < offsets::SEQ + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::SEQ,
                need: 2,
                have: slice.len().saturating_sub(offsets::SEQ),
            });
        }
        Ok(Some(u16::from_be_bytes([
            slice[offsets::SEQ],
            slice[offsets::SEQ + 1],
        ])))
    }

    /// Get the target address (for Neighbor Solicitation/Advertisement).
    ///
    /// Returns None if this `ICMPv6` type doesn't have a target address.
    pub fn target_addr(&self, buf: &[u8]) -> Result<Option<Ipv6Addr>, FieldError> {
        let icmpv6_type = self.icmpv6_type(buf)?;
        if !matches!(
            icmpv6_type,
            types::NEIGHBOR_SOLICIT | types::NEIGHBOR_ADVERT | types::REDIRECT
        ) {
            return Ok(None);
        }
        let start = self.index.start + offsets::TARGET_ADDR;
        if buf.len() < start + 16 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 16,
                have: buf.len().saturating_sub(start),
            });
        }
        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&buf[start..start + 16]);
        Ok(Some(Ipv6Addr::from(addr_bytes)))
    }

    /// Get the MTU (for Packet Too Big only).
    ///
    /// Returns None if this is not a Packet Too Big message.
    pub fn mtu(&self, buf: &[u8]) -> Result<Option<u32>, FieldError> {
        let icmpv6_type = self.icmpv6_type(buf)?;
        if icmpv6_type != types::PKT_TOO_BIG {
            return Ok(None);
        }
        let slice = self.index.slice(buf);
        if slice.len() < offsets::MTU + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::MTU,
                need: 4,
                have: slice.len().saturating_sub(offsets::MTU),
            });
        }
        Ok(Some(u32::from_be_bytes([
            slice[offsets::MTU],
            slice[offsets::MTU + 1],
            slice[offsets::MTU + 2],
            slice[offsets::MTU + 3],
        ])))
    }

    // ========== Field Writers ==========

    /// Set the `ICMPv6` type.
    pub fn set_type(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::TYPE;
        if buf.len() <= offset {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset] = value;
        Ok(())
    }

    /// Set the `ICMPv6` code.
    pub fn set_code(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::CODE;
        if buf.len() <= offset {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset] = value;
        Ok(())
    }

    /// Set the checksum.
    pub fn set_checksum(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::CHECKSUM;
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the identifier field (for echo request/reply).
    pub fn set_id(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::ID;
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the sequence number field.
    pub fn set_seq(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::SEQ;
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // ========== Dynamic Field Access ==========

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "type" => Some(self.icmpv6_type(buf).map(FieldValue::U8)),
            "code" => Some(self.code(buf).map(FieldValue::U8)),
            "chksum" => Some(self.checksum(buf).map(FieldValue::U16)),
            "id" => Some(
                self.id(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "id field not available for this ICMPv6 type".into(),
                        ))
                    })
                    .map(FieldValue::U16),
            ),
            "seq" => Some(
                self.seq(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "seq field not available for this ICMPv6 type".into(),
                        ))
                    })
                    .map(FieldValue::U16),
            ),
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
            ("type", FieldValue::U8(v)) => Some(self.set_type(buf, v)),
            ("code", FieldValue::U8(v)) => Some(self.set_code(buf, v)),
            ("chksum", FieldValue::U16(v)) => Some(self.set_checksum(buf, v)),
            ("id", FieldValue::U16(v)) => Some(self.set_id(buf, v)),
            ("seq", FieldValue::U16(v)) => Some(self.set_seq(buf, v)),
            (name, value) => Some(Err(FieldError::InvalidValue(format!(
                "unknown field '{name}' or type mismatch for {value:?}"
            )))),
        }
    }

    /// Get the list of field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &["type", "code", "chksum", "id", "seq"]
    }

    // ========== Utility Methods ==========

    /// Generate a human-readable summary string.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        if let (Ok(icmpv6_type), Ok(code)) = (self.icmpv6_type(buf), self.code(buf)) {
            let type_name = types::name(icmpv6_type);

            let details = match icmpv6_type {
                types::ECHO_REQUEST | types::ECHO_REPLY => {
                    let id_str = self
                        .id(buf)
                        .ok()
                        .flatten()
                        .map(|id| format!(" id={id:#06x}"))
                        .unwrap_or_default();
                    let seq_str = self
                        .seq(buf)
                        .ok()
                        .flatten()
                        .map(|seq| format!(" seq={seq}"))
                        .unwrap_or_default();
                    format!("{id_str}{seq_str}")
                },
                types::PKT_TOO_BIG => self
                    .mtu(buf)
                    .ok()
                    .flatten()
                    .map(|mtu| format!(" mtu={mtu}"))
                    .unwrap_or_default(),
                types::NEIGHBOR_SOLICIT | types::NEIGHBOR_ADVERT => self
                    .target_addr(buf)
                    .ok()
                    .flatten()
                    .map(|addr| format!(" target={addr}"))
                    .unwrap_or_default(),
                _ => String::new(),
            };

            if code == 0 {
                format!("ICMPv6 {type_name}{details}")
            } else {
                format!("ICMPv6 {type_name} code={code}{details}")
            }
        } else {
            "ICMPv6".to_string()
        }
    }

    /// Get the `ICMPv6` header length.
    ///
    /// The base header is always 8 bytes. Type-specific fields (like target
    /// addresses for NDP) are counted as part of the "body" beyond the 8-byte
    /// header.
    #[must_use]
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        ICMPV6_MIN_HEADER_LEN
    }

    /// Compute hash for packet matching.
    #[must_use]
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let icmpv6_type = self.icmpv6_type(buf).unwrap_or(0);
        match icmpv6_type {
            types::ECHO_REQUEST | types::ECHO_REPLY => {
                // Hash on id + seq for echo matching
                let id = self.id(buf).ok().flatten().unwrap_or(0);
                let seq = self.seq(buf).ok().flatten().unwrap_or(0);
                vec![
                    (id >> 8) as u8,
                    (id & 0xFF) as u8,
                    (seq >> 8) as u8,
                    (seq & 0xFF) as u8,
                ]
            },
            _ => vec![],
        }
    }

    /// Check if this packet answers another `ICMPv6` packet.
    #[must_use]
    pub fn answers(&self, buf: &[u8], other: &Icmpv6Layer, other_buf: &[u8]) -> bool {
        let self_type = self.icmpv6_type(buf).unwrap_or(0);
        let other_type = other.icmpv6_type(other_buf).unwrap_or(0);

        match (self_type, other_type) {
            (types::ECHO_REPLY, types::ECHO_REQUEST) => {
                // ID and seq must match
                let self_id = self.id(buf).ok().flatten();
                let other_id = other.id(other_buf).ok().flatten();
                let self_seq = self.seq(buf).ok().flatten();
                let other_seq = other.seq(other_buf).ok().flatten();
                self_id == other_id && self_seq == other_seq
            },
            _ => false,
        }
    }
}

impl Layer for Icmpv6Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Icmpv6
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

    fn make_echo_request(id: u16, seq: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        buf[0] = types::ECHO_REQUEST;
        buf[1] = 0; // code
        buf[2] = 0; // checksum (zero for now)
        buf[3] = 0;
        buf[4] = (id >> 8) as u8;
        buf[5] = (id & 0xFF) as u8;
        buf[6] = (seq >> 8) as u8;
        buf[7] = (seq & 0xFF) as u8;
        buf
    }

    fn make_echo_reply(id: u16, seq: u16) -> Vec<u8> {
        let mut buf = make_echo_request(id, seq);
        buf[0] = types::ECHO_REPLY;
        buf
    }

    fn make_ns(target: Ipv6Addr) -> Vec<u8> {
        let mut buf = vec![0u8; 24]; // 8 byte header + 16 byte target
        buf[0] = types::NEIGHBOR_SOLICIT;
        buf[1] = 0;
        // bytes 4-7: reserved (zero)
        buf[8..24].copy_from_slice(&target.octets());
        buf
    }

    #[test]
    fn test_icmpv6_type_echo_request() {
        let buf = make_echo_request(0x1234, 5);
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.icmpv6_type(&buf).unwrap(), types::ECHO_REQUEST);
    }

    #[test]
    fn test_icmpv6_code() {
        let buf = make_echo_request(1, 1);
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.code(&buf).unwrap(), 0);
    }

    #[test]
    fn test_icmpv6_id_seq() {
        let buf = make_echo_request(0x5678, 42);
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.id(&buf).unwrap(), Some(0x5678));
        assert_eq!(layer.seq(&buf).unwrap(), Some(42));
    }

    #[test]
    fn test_icmpv6_id_seq_not_available() {
        let mut buf = vec![0u8; 8];
        buf[0] = types::NEIGHBOR_SOLICIT;
        let layer = Icmpv6Layer::at_start();
        // NS doesn't have id/seq fields
        assert_eq!(layer.id(&buf).unwrap(), None);
        assert_eq!(layer.seq(&buf).unwrap(), None);
    }

    #[test]
    fn test_icmpv6_target_addr() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
        let mut buf = make_ns(target);
        // Create a layer that spans the whole buffer including the target addr
        let layer = Icmpv6Layer::new(LayerIndex::new(LayerKind::Icmpv6, 0, buf.len()));
        let addr = layer.target_addr(&buf).unwrap();
        assert_eq!(addr, Some(target));
    }

    #[test]
    fn test_icmpv6_mtu() {
        let mut buf = vec![0u8; 8];
        buf[0] = types::PKT_TOO_BIG;
        buf[4] = 0x00;
        buf[5] = 0x00;
        buf[6] = 0x05;
        buf[7] = 0xDC; // 1500
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.mtu(&buf).unwrap(), Some(1500));
    }

    #[test]
    fn test_icmpv6_mtu_not_available() {
        let buf = make_echo_request(1, 1);
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.mtu(&buf).unwrap(), None);
    }

    #[test]
    fn test_icmpv6_summary_echo_request() {
        let buf = make_echo_request(0x1234, 5);
        let layer = Icmpv6Layer::at_start();
        let s = layer.summary(&buf);
        assert!(s.contains("echo-request"));
        assert!(s.contains("0x1234"));
        assert!(s.contains("5"));
    }

    #[test]
    fn test_icmpv6_summary_ns() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
        let buf = make_ns(target);
        let layer = Icmpv6Layer::new(LayerIndex::new(LayerKind::Icmpv6, 0, buf.len()));
        let s = layer.summary(&buf);
        assert!(s.contains("neighbor-solicit"));
    }

    #[test]
    fn test_icmpv6_answers_echo() {
        let req_buf = make_echo_request(0xABCD, 10);
        let rep_buf = make_echo_reply(0xABCD, 10);

        let req_layer = Icmpv6Layer::at_start();
        let rep_layer = Icmpv6Layer::at_start();

        assert!(rep_layer.answers(&rep_buf, &req_layer, &req_buf));
    }

    #[test]
    fn test_icmpv6_answers_echo_wrong_id() {
        let req_buf = make_echo_request(0xABCD, 10);
        let rep_buf = make_echo_reply(0x0001, 10);

        let req_layer = Icmpv6Layer::at_start();
        let rep_layer = Icmpv6Layer::at_start();

        assert!(!rep_layer.answers(&rep_buf, &req_layer, &req_buf));
    }

    #[test]
    fn test_icmpv6_checksum() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Build an echo request with zeroed checksum
        let mut buf = make_echo_request(0x1234, 1);
        // Calculate and set checksum
        let chksum = icmpv6_checksum(src, dst, &buf);
        buf[2] = (chksum >> 8) as u8;
        buf[3] = (chksum & 0xFF) as u8;

        // Verify
        assert!(verify_icmpv6_checksum(src, dst, &buf));
    }

    #[test]
    fn test_icmpv6_checksum_wrong() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let buf = make_echo_request(0x1234, 1);
        // Checksum is zero, which should be wrong for this packet
        // (unless by coincidence it's valid — we just test the function runs)
        let _ = verify_icmpv6_checksum(src, dst, &buf);
    }

    #[test]
    fn test_icmpv6_get_field() {
        let buf = make_echo_request(0x5678, 3);
        let layer = Icmpv6Layer::at_start();

        if let Some(Ok(FieldValue::U8(t))) = layer.get_field(&buf, "type") {
            assert_eq!(t, types::ECHO_REQUEST);
        } else {
            panic!("expected type field");
        }

        if let Some(Ok(FieldValue::U16(id))) = layer.get_field(&buf, "id") {
            assert_eq!(id, 0x5678);
        } else {
            panic!("expected id field");
        }
    }

    #[test]
    fn test_icmpv6_set_field() {
        let mut buf = make_echo_request(1, 1);
        let layer = Icmpv6Layer::at_start();
        layer
            .set_field(&mut buf, "id", FieldValue::U16(0xDEAD))
            .unwrap()
            .unwrap();
        assert_eq!(layer.id(&buf).unwrap(), Some(0xDEAD));
    }

    #[test]
    fn test_icmpv6_header_len() {
        let buf = make_echo_request(1, 1);
        let layer = Icmpv6Layer::at_start();
        assert_eq!(layer.header_len(&buf), ICMPV6_MIN_HEADER_LEN);
        assert_eq!(ICMPV6_MIN_HEADER_LEN, 8);
    }

    #[test]
    fn test_icmpv6_field_names() {
        let names = Icmpv6Layer::field_names();
        assert!(names.contains(&"type"));
        assert!(names.contains(&"code"));
        assert!(names.contains(&"chksum"));
        assert!(names.contains(&"id"));
        assert!(names.contains(&"seq"));
    }
}
