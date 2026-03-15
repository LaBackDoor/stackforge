//! COTP (ISO 8073) layer implementation.
//!
//! Connection-Oriented Transport Protocol, used as an intermediate layer
//! between TPKT and S7 Communication in Siemens S7 PLC protocol stacks.
//!
//! ## Header Format
//!
//! The header has a variable length depending on the PDU type:
//!
//! ```text
//! Byte 0: Length Indicator (LI) - header length excluding the LI byte itself
//! Byte 1: PDU type (high nibble = type code, low nibble = credit/class)
//! ```
//!
//! ### DT (Data Transfer) - 3 bytes total
//! ```text
//! Byte 0: LI = 0x02
//! Byte 1: PDU type = 0xF0
//! Byte 2: TPDU-NR (upper 7 bits) + EOT (bit 7, 1 = last fragment)
//! ```
//!
//! ### CR/CC (Connection Request/Confirm) - 7+ bytes
//! ```text
//! Byte 0: LI
//! Byte 1: PDU type (0xE0 for CR, 0xD0 for CC)
//! Bytes 2-3: Destination Reference (u16 BE)
//! Bytes 4-5: Source Reference (u16 BE)
//! Byte 6: Class + Option
//! Bytes 7+: Optional parameters
//! ```

pub mod builder;

pub use builder::CotpBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum COTP header length: LI byte + PDU type byte.
pub const COTP_MIN_HEADER_LEN: usize = 2;

/// PDU type constants (full byte values, high nibble is the type code).
pub mod pdu_type {
    /// Connection Request
    pub const CR: u8 = 0xE0;
    /// Connection Confirm
    pub const CC: u8 = 0xD0;
    /// Disconnect Request
    pub const DR: u8 = 0x80;
    /// Disconnect Confirm
    pub const DC: u8 = 0xC0;
    /// Data Transfer
    pub const DT: u8 = 0xF0;
    /// Expedited Data
    pub const ED: u8 = 0x10;
    /// Data Acknowledge
    pub const AK: u8 = 0x60;
    /// Expedited Data Acknowledge
    pub const EA: u8 = 0x20;
    /// Reject
    pub const RJ: u8 = 0x50;
    /// Error
    pub const ER: u8 = 0x70;

    /// Get a human-readable name for a PDU type byte.
    #[must_use]
    pub fn name(pdu: u8) -> &'static str {
        match pdu & 0xF0 {
            0xE0 => "CR (Connection Request)",
            0xD0 => "CC (Connection Confirm)",
            0x80 => "DR (Disconnect Request)",
            0xC0 => "DC (Disconnect Confirm)",
            0xF0 => "DT (Data Transfer)",
            0x10 => "ED (Expedited Data)",
            0x60 => "AK (Data Acknowledge)",
            0x20 => "EA (Expedited Data Ack)",
            0x50 => "RJ (Reject)",
            0x70 => "ER (Error)",
            _ => "Unknown",
        }
    }
}

/// Field names exported for Python/generic access.
pub static COTP_FIELD_NAMES: &[&str] = &[
    "length",
    "pdu_type",
    "dst_ref",
    "src_ref",
    "class_option",
    "tpdu_nr",
    "eot",
];

/// Convenience function: get human-readable name for a PDU type byte.
#[inline]
#[must_use]
pub fn pdu_type_name(pdu: u8) -> &'static str {
    pdu_type::name(pdu)
}

/// Check if a buffer could be a COTP payload.
///
/// In practice, COTP is always called from TPKT context, so this is a
/// minimal sanity check.
#[inline]
#[must_use]
pub fn is_cotp_payload(buf: &[u8]) -> bool {
    buf.len() >= 2
}

/// COTP layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct CotpLayer {
    pub index: LayerIndex,
}

impl CotpLayer {
    /// Create a new COTP layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create a COTP layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start() -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Cotp, 0, COTP_MIN_HEADER_LEN),
        }
    }

    /// Return a reference to a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Field accessors
    // ========================================================================

    /// Get the Length Indicator (LI) byte -- the header length excluding the
    /// LI byte itself.
    pub fn length(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    /// Get the PDU type byte (full byte; use high nibble for type code).
    pub fn pdu_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    /// Get a human-readable name for the PDU type.
    pub fn pdu_type_name(&self, buf: &[u8]) -> &'static str {
        self.pdu_type(buf).map(pdu_type::name).unwrap_or("Unknown")
    }

    /// Get the Destination Reference (bytes 2-3, for CR/CC/DR/DC).
    pub fn dst_ref(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the Source Reference (bytes 4-5, for CR/CC/DR/DC).
    pub fn src_ref(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 4,
                need: 2,
                have: s.len().saturating_sub(4),
            });
        }
        Ok(u16::from_be_bytes([s[4], s[5]]))
    }

    /// Get the Class + Option byte (byte 6, for CR/CC).
    pub fn class_option(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 7 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 6,
                need: 1,
                have: s.len().saturating_sub(6),
            });
        }
        Ok(s[6])
    }

    /// Get the TPDU number (upper 7 bits of byte 2, for DT).
    pub fn tpdu_nr(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 1,
                have: s.len().saturating_sub(2),
            });
        }
        Ok(s[2] & 0x7F)
    }

    /// Get the EOT flag (bit 7 of byte 2, for DT; true = last fragment).
    pub fn eot(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 1,
                have: s.len().saturating_sub(2),
            });
        }
        Ok((s[2] & 0x80) != 0)
    }

    /// Check if this is a Data Transfer PDU.
    pub fn is_dt(&self, buf: &[u8]) -> bool {
        self.pdu_type(buf)
            .map(|t| t & 0xF0 == 0xF0)
            .unwrap_or(false)
    }

    /// Check if this is a Connection Request PDU.
    pub fn is_cr(&self, buf: &[u8]) -> bool {
        self.pdu_type(buf)
            .map(|t| t & 0xF0 == 0xE0)
            .unwrap_or(false)
    }

    /// Check if this is a Connection Confirm PDU.
    pub fn is_cc(&self, buf: &[u8]) -> bool {
        self.pdu_type(buf)
            .map(|t| t & 0xF0 == 0xD0)
            .unwrap_or(false)
    }

    /// Check if this is a Disconnect Request PDU.
    pub fn is_dr(&self, buf: &[u8]) -> bool {
        self.pdu_type(buf)
            .map(|t| t & 0xF0 == 0x80)
            .unwrap_or(false)
    }

    /// Check if this is a Disconnect Confirm PDU.
    pub fn is_dc(&self, buf: &[u8]) -> bool {
        self.pdu_type(buf)
            .map(|t| t & 0xF0 == 0xC0)
            .unwrap_or(false)
    }

    // ========================================================================
    // Field writers
    // ========================================================================

    /// Set the Length Indicator byte.
    pub fn set_length(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
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

    /// Set the PDU type byte.
    pub fn set_pdu_type(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
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

    /// Set the Destination Reference (bytes 2-3).
    pub fn set_dst_ref(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
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

    /// Set the Source Reference (bytes 4-5).
    pub fn set_src_ref(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 4;
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

    /// Set the Class+Option byte (byte 6).
    pub fn set_class_option(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 6;
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

    // ========================================================================
    // Header length computation
    // ========================================================================

    /// Compute the actual header length from the LI field.
    ///
    /// The LI byte gives the header length excluding itself, so
    /// total header = LI + 1.
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        self.length(buf)
            .map(|li| (li as usize) + 1)
            .unwrap_or(COTP_MIN_HEADER_LEN)
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this COTP layer.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let pdu_name = self.pdu_type_name(buf);
        if self.is_dt(buf) {
            let eot = self
                .eot(buf)
                .map(|e| if e { "1" } else { "0" })
                .unwrap_or("?");
            let nr = self
                .tpdu_nr(buf)
                .map_or_else(|_| "?".to_string(), |v| v.to_string());
            format!("COTP {pdu_name} tpdu_nr={nr} eot={eot}")
        } else if self.is_cr(buf) || self.is_cc(buf) {
            let dref = self
                .dst_ref(buf)
                .map_or_else(|_| "?".to_string(), |v| format!("{v:#06x}"));
            let sref = self
                .src_ref(buf)
                .map_or_else(|_| "?".to_string(), |v| format!("{v:#06x}"));
            format!("COTP {pdu_name} dst_ref={dref} src_ref={sref}")
        } else {
            format!("COTP {pdu_name}")
        }
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        COTP_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "length" => Some(self.length(buf).map(FieldValue::U8)),
            "pdu_type" => Some(self.pdu_type(buf).map(FieldValue::U8)),
            "dst_ref" => {
                if self.is_dt(buf) {
                    None
                } else {
                    Some(self.dst_ref(buf).map(FieldValue::U16))
                }
            },
            "src_ref" => {
                if self.is_dt(buf) {
                    None
                } else {
                    Some(self.src_ref(buf).map(FieldValue::U16))
                }
            },
            "class_option" => {
                if self.is_cr(buf) || self.is_cc(buf) {
                    Some(self.class_option(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "tpdu_nr" => {
                if self.is_dt(buf) {
                    Some(self.tpdu_nr(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "eot" => {
                if self.is_dt(buf) {
                    Some(self.eot(buf).map(|e| FieldValue::U8(u8::from(e))))
                } else {
                    None
                }
            },
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
            "length" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "length: expected U8, got {value:?}"
                    ))))
                }
            },
            "pdu_type" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_pdu_type(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "pdu_type: expected U8, got {value:?}"
                    ))))
                }
            },
            "dst_ref" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_dst_ref(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "dst_ref: expected U16, got {value:?}"
                    ))))
                }
            },
            "src_ref" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_src_ref(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "src_ref: expected U16, got {value:?}"
                    ))))
                }
            },
            "class_option" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_class_option(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "class_option: expected U8, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for CotpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Cotp
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        COTP_FIELD_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DT PDU: LI=2, PDU=0xF0, TPDU-NR=0 + EOT=1 -> byte2 = 0x80
    fn dt_packet() -> Vec<u8> {
        vec![0x02, 0xF0, 0x80]
    }

    /// CR PDU: LI=6, PDU=0xE0, dst_ref=0x0000, src_ref=0x000C, class=0x00
    fn cr_packet() -> Vec<u8> {
        vec![0x06, 0xE0, 0x00, 0x00, 0x00, 0x0C, 0x00]
    }

    /// CC PDU: LI=6, PDU=0xD0, dst_ref=0x000C, src_ref=0x0001, class=0x00
    fn cc_packet() -> Vec<u8> {
        vec![0x06, 0xD0, 0x00, 0x0C, 0x00, 0x01, 0x00]
    }

    #[test]
    fn test_dt_fields() {
        let buf = dt_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(cotp.length(&buf).unwrap(), 2);
        assert_eq!(cotp.pdu_type(&buf).unwrap(), 0xF0);
        assert!(cotp.is_dt(&buf));
        assert!(!cotp.is_cr(&buf));
        assert!(!cotp.is_cc(&buf));
        assert_eq!(cotp.tpdu_nr(&buf).unwrap(), 0);
        assert!(cotp.eot(&buf).unwrap());
    }

    #[test]
    fn test_cr_fields() {
        let buf = cr_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(cotp.length(&buf).unwrap(), 6);
        assert_eq!(cotp.pdu_type(&buf).unwrap(), 0xE0);
        assert!(cotp.is_cr(&buf));
        assert!(!cotp.is_dt(&buf));
        assert_eq!(cotp.dst_ref(&buf).unwrap(), 0x0000);
        assert_eq!(cotp.src_ref(&buf).unwrap(), 0x000C);
        assert_eq!(cotp.class_option(&buf).unwrap(), 0x00);
    }

    #[test]
    fn test_cc_fields() {
        let buf = cc_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert!(cotp.is_cc(&buf));
        assert_eq!(cotp.dst_ref(&buf).unwrap(), 0x000C);
        assert_eq!(cotp.src_ref(&buf).unwrap(), 0x0001);
    }

    #[test]
    fn test_dt_header_len() {
        let buf = dt_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        // LI=2, so header = 2 + 1 = 3 bytes
        assert_eq!(cotp.compute_header_len(&buf), 3);
    }

    #[test]
    fn test_cr_header_len() {
        let buf = cr_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        // LI=6, so header = 6 + 1 = 7 bytes
        assert_eq!(cotp.compute_header_len(&buf), 7);
    }

    #[test]
    fn test_pdu_type_name() {
        let buf = dt_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(cotp.pdu_type_name(&buf), "DT (Data Transfer)");
    }

    #[test]
    fn test_dt_summary() {
        let buf = dt_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        let s = cotp.summary(&buf);
        assert!(s.contains("DT"));
        assert!(s.contains("eot=1"));
    }

    #[test]
    fn test_cr_summary() {
        let buf = cr_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        let s = cotp.summary(&buf);
        assert!(s.contains("CR"));
        assert!(s.contains("dst_ref="));
        assert!(s.contains("src_ref="));
    }

    #[test]
    fn test_get_field_dt() {
        let buf = dt_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(
            cotp.get_field(&buf, "length").unwrap().unwrap(),
            FieldValue::U8(2)
        );
        assert_eq!(
            cotp.get_field(&buf, "pdu_type").unwrap().unwrap(),
            FieldValue::U8(0xF0)
        );
        assert_eq!(
            cotp.get_field(&buf, "tpdu_nr").unwrap().unwrap(),
            FieldValue::U8(0)
        );
        assert_eq!(
            cotp.get_field(&buf, "eot").unwrap().unwrap(),
            FieldValue::U8(1)
        );
        // dst_ref not available for DT
        assert!(cotp.get_field(&buf, "dst_ref").is_none());
    }

    #[test]
    fn test_get_field_cr() {
        let buf = cr_packet();
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(
            cotp.get_field(&buf, "dst_ref").unwrap().unwrap(),
            FieldValue::U16(0x0000)
        );
        assert_eq!(
            cotp.get_field(&buf, "src_ref").unwrap().unwrap(),
            FieldValue::U16(0x000C)
        );
        assert_eq!(
            cotp.get_field(&buf, "class_option").unwrap().unwrap(),
            FieldValue::U8(0x00)
        );
        // tpdu_nr not available for CR
        assert!(cotp.get_field(&buf, "tpdu_nr").is_none());
    }

    #[test]
    fn test_is_cotp_payload() {
        assert!(is_cotp_payload(&[0x02, 0xF0]));
        assert!(!is_cotp_payload(&[0x02])); // too short
    }

    #[test]
    fn test_dt_eot_false() {
        // DT with EOT=0: byte2 = 0x00 (tpdu_nr=0, eot=0)
        let buf = vec![0x02, 0xF0, 0x00];
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert!(!cotp.eot(&buf).unwrap());
        assert_eq!(cotp.tpdu_nr(&buf).unwrap(), 0);
    }

    #[test]
    fn test_dt_tpdu_nr_nonzero() {
        // DT with tpdu_nr=5, EOT=1: byte2 = 0x80 | 5 = 0x85
        let buf = vec![0x02, 0xF0, 0x85];
        let idx = LayerIndex::new(LayerKind::Cotp, 0, buf.len());
        let cotp = CotpLayer::new(idx);

        assert_eq!(cotp.tpdu_nr(&buf).unwrap(), 5);
        assert!(cotp.eot(&buf).unwrap());
    }
}
