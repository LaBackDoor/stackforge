//! QUIC protocol layer implementation (RFC 9000).
//!
//! This module implements the "Lazy Zero-Copy View" architecture for QUIC:
//! the [`QuicLayer`] holds a [`LayerIndex`] and reads fields directly from
//! the underlying packet buffer on demand.
//!
//! # Sub-modules
//!
//! - [`varint`]  — QUIC variable-length integer encoding/decoding.
//! - [`frames`]  — QUIC frame types and best-effort frame parser.
//! - [`headers`] — QUIC long-header and short-header structures.
//! - [`builder`] — [`QuicBuilder`] for constructing QUIC packets.

pub mod builder;
pub mod frames;
pub mod headers;
pub mod varint;

pub use builder::{QuicBuilder, QuicInitialBuilder};
pub use frames::{FrameType, QuicFrame, parse_frames};
pub use headers::{QuicLongHeader, QuicPacketType, QuicShortHeader, packet_type};
pub use varint::{decode as varint_decode, encode as varint_encode};

use crate::layer::field::{FieldDesc, FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum size of a QUIC header (just the first byte).
pub const QUIC_MIN_HEADER_LEN: usize = 1;

/// Static field descriptors for the QUIC layer.
///
/// Fields common to all QUIC packet types plus long-header specific fields.
/// Variable-length fields (conn IDs, length, `packet_number`) use placeholder
/// offsets because their actual positions must be computed dynamically in
/// `get_field()`.
pub static QUIC_FIELDS: &[FieldDesc] = &[
    FieldDesc::new("header_form", 0, 1, FieldType::U8),
    FieldDesc::new("fixed_bit", 0, 1, FieldType::U8),
    FieldDesc::new("packet_type", 0, 1, FieldType::U8),
    FieldDesc::new("long_packet_type", 0, 1, FieldType::U8),
    FieldDesc::new("packet_number_len", 0, 1, FieldType::U8),
    FieldDesc::new("version", 1, 4, FieldType::U32),
    // Variable-length fields (offsets are placeholders; actual access is dynamic)
    FieldDesc::new("dst_conn_id_len", 5, 1, FieldType::U8),
    FieldDesc::new("src_conn_id_len", 5, 1, FieldType::U8),
    FieldDesc::new("dst_conn_id", 6, 0, FieldType::Bytes),
    FieldDesc::new("src_conn_id", 6, 0, FieldType::Bytes),
    FieldDesc::new("length", 6, 8, FieldType::U64),
    FieldDesc::new("packet_number", 6, 4, FieldType::U32),
];

/// QUIC protocol layer — a lightweight view into a raw packet buffer.
///
/// Follows the same "Lazy Zero-Copy View" pattern as all other layers in
/// stackforge-core: no field values are copied at parse time; they are read
/// directly from the buffer when accessed.
#[derive(Debug, Clone)]
pub struct QuicLayer {
    pub index: LayerIndex,
}

impl QuicLayer {
    /// Create a new `QuicLayer` covering `buf[start..end]`.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Quic, start, end),
        }
    }

    /// Create a `QuicLayer` from an existing `LayerIndex`.
    #[must_use]
    pub fn from_index(index: LayerIndex) -> Self {
        Self { index }
    }

    // -------------------------------------------------------------------------
    // Field readers
    // -------------------------------------------------------------------------

    /// Returns `true` if bit 7 of the first byte is set (long header).
    #[must_use]
    pub fn is_long_header(&self, buf: &[u8]) -> bool {
        let slice = self.index.slice(buf);
        !slice.is_empty() && slice[0] & 0x80 != 0
    }

    /// Returns the logical packet type, or `None` if the buffer is too short.
    #[must_use]
    pub fn packet_type(&self, buf: &[u8]) -> Option<QuicPacketType> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return None;
        }
        let first = slice[0];
        let version = if slice.len() >= 5 {
            u32::from_be_bytes([slice[1], slice[2], slice[3], slice[4]])
        } else {
            0
        };
        Some(headers::packet_type(first, version))
    }

    /// Returns the QUIC version (bytes 1-4) for long-header packets, or `None`
    /// if this is a short-header packet or the buffer is too short.
    #[must_use]
    pub fn version(&self, buf: &[u8]) -> Option<u32> {
        if !self.is_long_header(buf) {
            return None;
        }
        let slice = self.index.slice(buf);
        if slice.len() < 5 {
            return None;
        }
        Some(u32::from_be_bytes([slice[1], slice[2], slice[3], slice[4]]))
    }

    /// Returns a human-readable summary string.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        match self.packet_type(buf) {
            Some(pt) => format!("QUIC {}", pt.name()),
            None => "QUIC".to_string(),
        }
    }

    /// Returns the header length in bytes.
    ///
    /// For long headers this parses the connection-ID lengths to compute the
    /// actual header size.  For short headers (where the connection-ID length
    /// is negotiated out-of-band) we return 1 as a safe minimum.
    #[must_use]
    pub fn header_len(&self, buf: &[u8]) -> usize {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return QUIC_MIN_HEADER_LEN;
        }

        if self.is_long_header(buf) {
            match QuicLongHeader::parse(slice) {
                Some(hdr) => hdr.header_len,
                None => QUIC_MIN_HEADER_LEN,
            }
        } else {
            // Short header: 1-byte first byte, variable connection ID (unknown here).
            QUIC_MIN_HEADER_LEN
        }
    }

    /// Returns the static field names exposed by this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &[
            "header_form",
            "fixed_bit",
            "packet_type",
            "long_packet_type",
            "packet_number_len",
            "version",
            "dst_conn_id_len",
            "src_conn_id_len",
            "dst_conn_id",
            "src_conn_id",
            "length",
            "packet_number",
        ]
    }

    /// Read a field value by name from the underlying buffer.
    #[must_use]
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        let slice = self.index.slice(buf);
        match name {
            "header_form" => {
                if slice.is_empty() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 1,
                        have: 0,
                    }));
                }
                let v = (slice[0] >> 7) & 0x01;
                Some(Ok(FieldValue::U8(v)))
            },
            "fixed_bit" => {
                if slice.is_empty() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 1,
                        have: 0,
                    }));
                }
                let v = (slice[0] >> 6) & 0x01;
                Some(Ok(FieldValue::U8(v)))
            },
            "packet_type" => {
                if slice.is_empty() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 1,
                        have: 0,
                    }));
                }
                // For long headers: bits 5-4.  For short headers: 0 (no type field).
                let v = if slice[0] & 0x80 != 0 {
                    (slice[0] & 0x30) >> 4
                } else {
                    0
                };
                Some(Ok(FieldValue::U8(v)))
            },
            "version" => {
                if slice.len() < 5 {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start + 1,
                        need: 4,
                        have: slice.len().saturating_sub(1),
                    }));
                }
                let v = u32::from_be_bytes([slice[1], slice[2], slice[3], slice[4]]);
                Some(Ok(FieldValue::U32(v)))
            },
            "long_packet_type" => {
                if slice.is_empty() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 1,
                        have: 0,
                    }));
                }
                // bits 5-4 of byte 0 (only meaningful for long-header packets)
                let v = (slice[0] & 0x30) >> 4;
                Some(Ok(FieldValue::U8(v)))
            },
            "packet_number_len" => {
                if slice.is_empty() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 1,
                        have: 0,
                    }));
                }
                // bits 1-0 of byte 0: encoded packet number length minus 1
                let v = slice[0] & 0x03;
                Some(Ok(FieldValue::U8(v)))
            },
            "dst_conn_id_len" => {
                if slice.len() < 6 {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start + 5,
                        need: 1,
                        have: slice.len().saturating_sub(5),
                    }));
                }
                if slice[0] & 0x80 == 0 {
                    // Short header — no explicit DCIL byte
                    return Some(Ok(FieldValue::U8(0)));
                }
                Some(Ok(FieldValue::U8(slice[5])))
            },
            "src_conn_id_len" => {
                if slice[0] & 0x80 == 0 {
                    // Short header — no SCID
                    return Some(Ok(FieldValue::U8(0)));
                }
                match QuicLongHeader::parse(slice) {
                    Some(hdr) => Some(Ok(FieldValue::U8(hdr.src_conn_id.len() as u8))),
                    None => Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 7,
                        have: slice.len(),
                    })),
                }
            },
            "dst_conn_id" => {
                if slice[0] & 0x80 == 0 {
                    // Short header — DCID not explicitly encoded
                    return Some(Ok(FieldValue::Bytes(vec![])));
                }
                match QuicLongHeader::parse(slice) {
                    Some(hdr) => Some(Ok(FieldValue::Bytes(hdr.dst_conn_id))),
                    None => Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 7,
                        have: slice.len(),
                    })),
                }
            },
            "src_conn_id" => {
                if slice[0] & 0x80 == 0 {
                    // Short header — no SCID
                    return Some(Ok(FieldValue::Bytes(vec![])));
                }
                match QuicLongHeader::parse(slice) {
                    Some(hdr) => Some(Ok(FieldValue::Bytes(hdr.src_conn_id))),
                    None => Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start,
                        need: 7,
                        have: slice.len(),
                    })),
                }
            },
            "length" | "packet_number" => {
                if slice[0] & 0x80 == 0 {
                    // Short header — no length/packet_number fields in long-header sense
                    return None;
                }
                let hdr = match QuicLongHeader::parse(slice) {
                    Some(h) => h,
                    None => {
                        return Some(Err(FieldError::BufferTooShort {
                            offset: self.index.start,
                            need: 7,
                            have: slice.len(),
                        }));
                    },
                };
                let mut pos = hdr.header_len; // after SCID

                // For Initial packets only: skip token_length varint + token bytes.
                if hdr.packet_type == headers::QuicPacketType::Initial {
                    match varint::decode(&slice[pos..]) {
                        Some((token_len, token_varint_bytes)) => {
                            pos += token_varint_bytes + token_len as usize;
                        },
                        None => {
                            return Some(Err(FieldError::BufferTooShort {
                                offset: self.index.start + pos,
                                need: 1,
                                have: slice.len().saturating_sub(pos),
                            }));
                        },
                    }
                }

                // Length varint
                let (length_val, length_varint_bytes) = match varint::decode(&slice[pos..]) {
                    Some(v) => v,
                    None => {
                        return Some(Err(FieldError::BufferTooShort {
                            offset: self.index.start + pos,
                            need: 1,
                            have: slice.len().saturating_sub(pos),
                        }));
                    },
                };

                if name == "length" {
                    return Some(Ok(FieldValue::U64(length_val)));
                }

                // packet_number: comes after the length varint
                pos += length_varint_bytes;
                let pn_len = (slice[0] & 0x03) as usize + 1;
                if pos + pn_len > slice.len() {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: self.index.start + pos,
                        need: pn_len,
                        have: slice.len().saturating_sub(pos),
                    }));
                }
                let pn_bytes = &slice[pos..pos + pn_len];
                let pn: u32 = match pn_len {
                    1 => u32::from(pn_bytes[0]),
                    2 => u32::from(u16::from_be_bytes([pn_bytes[0], pn_bytes[1]])),
                    3 => {
                        (u32::from(pn_bytes[0]) << 16)
                            | (u32::from(pn_bytes[1]) << 8)
                            | u32::from(pn_bytes[2])
                    },
                    4 => u32::from_be_bytes([pn_bytes[0], pn_bytes[1], pn_bytes[2], pn_bytes[3]]),
                    _ => unreachable!(),
                };
                Some(Ok(FieldValue::U32(pn)))
            },
            _ => None,
        }
    }

    /// Write a field value by name into the underlying (mutable) buffer.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        let start = self.index.start;
        match name {
            "header_form" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    other => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "header_form: expected U8, got {other:?}"
                        ))));
                    },
                };
                if buf.len() <= start {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start,
                        need: 1,
                        have: 0,
                    }));
                }
                if v != 0 {
                    buf[start] |= 0x80;
                } else {
                    buf[start] &= !0x80;
                }
                Some(Ok(()))
            },
            "fixed_bit" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    other => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "fixed_bit: expected U8, got {other:?}"
                        ))));
                    },
                };
                if buf.len() <= start {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start,
                        need: 1,
                        have: 0,
                    }));
                }
                if v != 0 {
                    buf[start] |= 0x40;
                } else {
                    buf[start] &= !0x40;
                }
                Some(Ok(()))
            },
            "packet_type" => {
                let v = match value {
                    FieldValue::U8(v) => v,
                    other => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "packet_type: expected U8, got {other:?}"
                        ))));
                    },
                };
                if buf.len() <= start {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start,
                        need: 1,
                        have: 0,
                    }));
                }
                // Only meaningful for long headers (bits 5-4).
                buf[start] = (buf[start] & !0x30) | ((v & 0x03) << 4);
                Some(Ok(()))
            },
            "version" => {
                let v = match value {
                    FieldValue::U32(v) => v,
                    other => {
                        return Some(Err(FieldError::InvalidValue(format!(
                            "version: expected U32, got {other:?}"
                        ))));
                    },
                };
                if buf.len() < start + 5 {
                    return Some(Err(FieldError::BufferTooShort {
                        offset: start + 1,
                        need: 4,
                        have: buf.len().saturating_sub(start + 1),
                    }));
                }
                buf[start + 1..start + 5].copy_from_slice(&v.to_be_bytes());
                Some(Ok(()))
            },
            _ => None,
        }
    }
}

impl Layer for QuicLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Quic
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        QuicLayer::field_names()
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into bytes (panics on invalid input).
    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn make_initial_buf() -> Vec<u8> {
        QuicBuilder::initial()
            .version(1)
            .dst_conn_id(vec![0x01, 0x02])
            .src_conn_id(vec![])
            .payload(vec![])
            .build()
    }

    #[test]
    fn test_quic_layer_new() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        assert!(layer.is_long_header(&buf));
        assert_eq!(layer.packet_type(&buf), Some(QuicPacketType::Initial));
        assert_eq!(layer.version(&buf), Some(1));
    }

    #[test]
    fn test_summary_initial() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let s = layer.summary(&buf);
        assert!(s.contains("Initial"), "summary: {}", s);
    }

    #[test]
    fn test_get_field_header_form() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "header_form").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(1));
    }

    #[test]
    fn test_get_field_fixed_bit() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "fixed_bit").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(1));
    }

    #[test]
    fn test_get_field_packet_type() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_type").unwrap().unwrap();
        // Initial = 0x00
        assert_eq!(val, FieldValue::U8(0));
    }

    #[test]
    fn test_get_field_version() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "version").unwrap().unwrap();
        assert_eq!(val, FieldValue::U32(1));
    }

    #[test]
    fn test_get_field_unknown() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        assert!(layer.get_field(&buf, "nonexistent").is_none());
    }

    #[test]
    fn test_set_field_version() {
        let mut buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        layer
            .set_field(&mut buf, "version", FieldValue::U32(2))
            .unwrap()
            .unwrap();
        assert_eq!(layer.version(&buf), Some(2));
    }

    #[test]
    fn test_one_rtt_is_short_header() {
        let buf = QuicBuilder::one_rtt().payload(vec![0x01]).build();
        let layer = QuicLayer::new(0, buf.len());
        assert!(!layer.is_long_header(&buf));
        assert_eq!(layer.packet_type(&buf), Some(QuicPacketType::OneRtt));
        assert_eq!(layer.version(&buf), None);
    }

    #[test]
    fn test_layer_kind() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        assert_eq!(layer.kind(), LayerKind::Quic);
    }

    #[test]
    fn test_header_len_long() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        // Long header with 2-byte DCID, 0-byte SCID, token varint, length varint
        // header_len should be at minimum 6 (first+ver+DCIL+DCID+SCIL+SCID)
        let h = layer.header_len(&buf);
        assert!(h >= 6, "header_len={}", h);
    }

    // -------------------------------------------------------------------------
    // New field tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_get_field_long_packet_type_initial() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "long_packet_type").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(0)); // 0 = Initial
    }

    #[test]
    fn test_get_field_long_packet_type_handshake() {
        let buf = QuicBuilder::handshake().dst_conn_id(vec![0x01]).build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "long_packet_type").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(2)); // 2 = Handshake
    }

    #[test]
    fn test_get_field_packet_number_len_zero() {
        // Default packet_number=0 => pn_len=1, encoded as (pn_len-1)=0
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number_len").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(0));
    }

    #[test]
    fn test_get_field_packet_number_len_one() {
        // packet_number=0xFFFF => pn_len=2, encoded as 1
        let buf = QuicBuilder::initial().packet_number(0xFFFF).build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number_len").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(1));
    }

    #[test]
    fn test_get_field_dst_conn_id_len() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "dst_conn_id_len").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(2)); // 2-byte DCID
    }

    #[test]
    fn test_get_field_src_conn_id_len_zero() {
        let buf = make_initial_buf();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "src_conn_id_len").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(0)); // 0-byte SCID
    }

    #[test]
    fn test_get_field_src_conn_id_len_nonzero() {
        let buf = QuicBuilder::initial()
            .dst_conn_id(vec![0xAA])
            .src_conn_id(vec![0xBB, 0xCC])
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "src_conn_id_len").unwrap().unwrap();
        assert_eq!(val, FieldValue::U8(2));
    }

    #[test]
    fn test_get_field_dst_conn_id() {
        let dcid = vec![0x01, 0x02];
        let buf = QuicBuilder::initial().dst_conn_id(dcid.clone()).build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "dst_conn_id").unwrap().unwrap();
        assert_eq!(val, FieldValue::Bytes(dcid));
    }

    #[test]
    fn test_get_field_src_conn_id() {
        let scid = vec![0xAA, 0xBB];
        let buf = QuicBuilder::initial().src_conn_id(scid.clone()).build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "src_conn_id").unwrap().unwrap();
        assert_eq!(val, FieldValue::Bytes(scid));
    }

    #[test]
    fn test_get_field_length_initial() {
        // No payload, packet_number=0 (1 byte) => length = 1
        let buf = QuicBuilder::initial()
            .dst_conn_id(vec![0x01])
            .payload(vec![])
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "length").unwrap().unwrap();
        assert_eq!(val, FieldValue::U64(1)); // 1 byte pn + 0 payload
    }

    #[test]
    fn test_get_field_packet_number_initial_zero() {
        let buf = QuicBuilder::initial()
            .dst_conn_id(vec![0x01])
            .packet_number(0)
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number").unwrap().unwrap();
        assert_eq!(val, FieldValue::U32(0));
    }

    #[test]
    fn test_get_field_packet_number_initial_255() {
        let buf = QuicBuilder::initial()
            .dst_conn_id(vec![0x01])
            .packet_number(0xFF)
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number").unwrap().unwrap();
        assert_eq!(val, FieldValue::U32(0xFF));
    }

    #[test]
    fn test_get_field_packet_number_initial_65535() {
        let buf = QuicBuilder::initial()
            .dst_conn_id(vec![0x01])
            .packet_number(0xFFFF)
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number").unwrap().unwrap();
        assert_eq!(val, FieldValue::U32(0xFFFF));
    }

    #[test]
    fn test_get_field_packet_number_handshake() {
        let buf = QuicBuilder::handshake()
            .dst_conn_id(vec![0x01])
            .packet_number(1)
            .build();
        let layer = QuicLayer::new(0, buf.len());
        let val = layer.get_field(&buf, "packet_number").unwrap().unwrap();
        assert_eq!(val, FieldValue::U32(1));
    }

    #[test]
    fn test_uts_client_initial_fields() {
        // From tests/uts/quic.uts — Client Initial Packet
        let data = from_hex(
            "c00000000108000102030405060705635f636964004103001c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099",
        );
        let layer = QuicLayer::new(0, data.len());

        let dcid = layer.get_field(&data, "dst_conn_id").unwrap().unwrap();
        assert_eq!(
            dcid,
            FieldValue::Bytes(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        );

        let scid = layer.get_field(&data, "src_conn_id").unwrap().unwrap();
        assert_eq!(scid, FieldValue::Bytes(b"c_cid".to_vec()));

        let lpt = layer.get_field(&data, "long_packet_type").unwrap().unwrap();
        assert_eq!(lpt, FieldValue::U8(0)); // Initial

        let version = layer.get_field(&data, "version").unwrap().unwrap();
        assert_eq!(version, FieldValue::U32(1));

        let length = layer.get_field(&data, "length").unwrap().unwrap();
        assert_eq!(length, FieldValue::U64(259));

        let pn = layer.get_field(&data, "packet_number").unwrap().unwrap();
        assert_eq!(pn, FieldValue::U32(0));
    }

    #[test]
    fn test_uts_server_handshake_fields() {
        // From tests/uts/quic.uts — Server Handshake Packet
        let data = from_hex(
            "e00000000105635f63696405735f63696440cf014420f919681c3f0f102a30f5e647a3399abf54bc8e80453134996ba33099056242f3b8e662bbfce42f3ef2b6ba87159147489f8479e849284e983fd905320a62fc7d67e9587797096ca60101d0b2685d8747811178133ad9172b7ff8ea83fd81a814bae27b953a97d57ebff4b4710dba8df82a6b49d7d7fa3d8179cbdb8683d4bfa832645401e5a56a76535f71c6fb3e616c241bb1f43bc147c296f591402997ed49aa0c55e31721d03e14114af2dc458ae03944de5126fe08d66a6ef3ba2ed1025f98fea6d6024998184687dc06",
        );
        let layer = QuicLayer::new(0, data.len());

        let lpt = layer.get_field(&data, "long_packet_type").unwrap().unwrap();
        assert_eq!(lpt, FieldValue::U8(2)); // Handshake

        let dcid = layer.get_field(&data, "dst_conn_id").unwrap().unwrap();
        assert_eq!(dcid, FieldValue::Bytes(b"c_cid".to_vec()));

        let scid = layer.get_field(&data, "src_conn_id").unwrap().unwrap();
        assert_eq!(scid, FieldValue::Bytes(b"s_cid".to_vec()));

        let pn = layer.get_field(&data, "packet_number").unwrap().unwrap();
        assert_eq!(pn, FieldValue::U32(1));
    }

    #[test]
    fn test_uts_build_packet_fields() {
        // From tests/uts/quic.uts — QUIC_Initial(DstConnID=..., SrcConnID=..., PacketNumber=0xFF)
        let data: &[u8] = b"\xc0\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR\x03\xf7\x10Q\x00\x00\xff";
        let layer = QuicLayer::new(0, data.len());

        let dcil = layer.get_field(data, "dst_conn_id_len").unwrap().unwrap();
        assert_eq!(dcil, FieldValue::U8(15));

        let scil = layer.get_field(data, "src_conn_id_len").unwrap().unwrap();
        assert_eq!(scil, FieldValue::U8(3));

        let pnl = layer.get_field(data, "packet_number_len").unwrap().unwrap();
        assert_eq!(pnl, FieldValue::U8(0)); // 0 means 1 byte

        let pn = layer.get_field(data, "packet_number").unwrap().unwrap();
        assert_eq!(pn, FieldValue::U32(0xFF));
    }
}
