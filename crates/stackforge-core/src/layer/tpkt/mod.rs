//! TPKT (RFC 1006) layer implementation.
//!
//! TPKT provides a simple 4-byte transport header for carrying ISO transport
//! services over TCP. It is commonly used as the transport for COTP and S7
//! communication in industrial control systems (Siemens S7 PLC protocol stack).
//!
//! ## Header Format
//!
//! ```text
//! Byte 0: Version (always 3)
//! Byte 1: Reserved (always 0)
//! Bytes 2-3: Length (u16 BE, total packet length including this header)
//! ```

pub mod builder;

pub use builder::TpktBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// TPKT header length in bytes (always 4).
pub const TPKT_HEADER_LEN: usize = 4;

/// Minimum TPKT header length in bytes.
pub const TPKT_MIN_HEADER_LEN: usize = 4;

/// Standard TCP port for TPKT (ISO-TSAP / S7comm).
pub const TPKT_PORT: u16 = 102;

/// Field names exported for Python/generic access.
pub static TPKT_FIELD_NAMES: &[&str] = &["version", "reserved", "length"];

/// Check if a TCP payload looks like a TPKT packet.
///
/// TPKT packets start with version=3, reserved=0, and are at least 4 bytes.
#[inline]
#[must_use]
pub fn is_tpkt_payload(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] == 0x03 && buf[1] == 0x00
}

/// TPKT layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct TpktLayer {
    pub index: LayerIndex,
}

impl TpktLayer {
    /// Create a new TPKT layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a TPKT layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start() -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Tpkt, 0, TPKT_HEADER_LEN),
        }
    }

    /// Return a reference to a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Field accessors
    // ========================================================================

    /// Get the version field (byte 0, should always be 3).
    pub fn version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok(s[0])
    }

    /// Get the reserved field (byte 1, should always be 0).
    pub fn reserved(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 1,
                need: 1,
                have: s.len().saturating_sub(1),
            });
        }
        Ok(s[1])
    }

    /// Get the length field (bytes 2-3, total packet length including header).
    pub fn length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 2,
                have: s.len().saturating_sub(2),
            });
        }
        Ok(u16::from_be_bytes([s[2], s[3]]))
    }

    // ========================================================================
    // Field writers
    // ========================================================================

    /// Set the version field.
    pub fn set_version(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the reserved field.
    pub fn set_reserved(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 1;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the length field.
    pub fn set_length(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // ========================================================================
    // Payload
    // ========================================================================

    /// Get the payload bytes (everything after the 4-byte header).
    #[must_use]
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let start = (self.index.start + TPKT_HEADER_LEN).min(buf.len());
        let end = self
            .length(buf)
            .map(|l| (self.index.start + l as usize).min(buf.len()))
            .unwrap_or(buf.len());
        &buf[start..end]
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this TPKT layer.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let ver = self
            .version(buf)
            .map_or_else(|_| "?".to_string(), |v| v.to_string());
        let len = self
            .length(buf)
            .map_or_else(|_| "?".to_string(), |v| v.to_string());
        format!("TPKT version={ver} length={len}")
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        TPKT_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "version" => Some(self.version(buf).map(FieldValue::U8)),
            "reserved" => Some(self.reserved(buf).map(FieldValue::U8)),
            "length" => Some(self.length(buf).map(FieldValue::U16)),
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
        match name {
            "version" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_version(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "version: expected U8, got {value:?}"
                    ))))
                }
            },
            "reserved" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_reserved(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "reserved: expected U8, got {value:?}"
                    ))))
                }
            },
            "length" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "length: expected U16, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for TpktLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Tpkt
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, _data: &[u8]) -> usize {
        TPKT_HEADER_LEN
    }

    fn field_names(&self) -> &'static [&'static str] {
        TPKT_FIELD_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tpkt() -> Vec<u8> {
        // Version=3, Reserved=0, Length=7 (4 header + 3 payload)
        vec![0x03, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC]
    }

    #[test]
    fn test_is_tpkt_payload() {
        assert!(is_tpkt_payload(&[0x03, 0x00, 0x00, 0x04]));
        assert!(!is_tpkt_payload(&[0x03, 0x01, 0x00, 0x04])); // reserved != 0
        assert!(!is_tpkt_payload(&[0x02, 0x00, 0x00, 0x04])); // version != 3
        assert!(!is_tpkt_payload(&[0x03, 0x00, 0x00])); // too short
    }

    #[test]
    fn test_tpkt_fields() {
        let buf = sample_tpkt();
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        assert_eq!(tpkt.version(&buf).unwrap(), 3);
        assert_eq!(tpkt.reserved(&buf).unwrap(), 0);
        assert_eq!(tpkt.length(&buf).unwrap(), 7);
    }

    #[test]
    fn test_tpkt_payload() {
        let buf = sample_tpkt();
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        let payload = tpkt.payload(&buf);
        assert_eq!(payload, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_tpkt_set_fields() {
        let mut buf = vec![0x03, 0x00, 0x00, 0x04];
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        tpkt.set_version(&mut buf, 4).unwrap();
        tpkt.set_reserved(&mut buf, 1).unwrap();
        tpkt.set_length(&mut buf, 100).unwrap();

        assert_eq!(tpkt.version(&buf).unwrap(), 4);
        assert_eq!(tpkt.reserved(&buf).unwrap(), 1);
        assert_eq!(tpkt.length(&buf).unwrap(), 100);
    }

    #[test]
    fn test_tpkt_get_field() {
        let buf = sample_tpkt();
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        assert_eq!(
            tpkt.get_field(&buf, "version").unwrap().unwrap(),
            FieldValue::U8(3)
        );
        assert_eq!(
            tpkt.get_field(&buf, "reserved").unwrap().unwrap(),
            FieldValue::U8(0)
        );
        assert_eq!(
            tpkt.get_field(&buf, "length").unwrap().unwrap(),
            FieldValue::U16(7)
        );
        assert!(tpkt.get_field(&buf, "nonexistent").is_none());
    }

    #[test]
    fn test_tpkt_summary() {
        let buf = sample_tpkt();
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        let s = tpkt.summary(&buf);
        assert!(s.contains("version=3"));
        assert!(s.contains("length=7"));
    }

    #[test]
    fn test_tpkt_header_len() {
        let buf = sample_tpkt();
        let idx = LayerIndex::new(LayerKind::Tpkt, 0, 4);
        let tpkt = TpktLayer::new(idx);

        assert_eq!(Layer::header_len(&tpkt, &buf), 4);
    }
}
