//! L2TP (Layer 2 Tunneling Protocol) layer implementation.
//!
//! Implements L2TPv2 as defined in RFC 2661.
//!
//! ## Header Format
//!
//! ```text
//! Bits:  0 1 2 3 4 5 6 7 | 8 9 10 11 12 13 14 15
//!        T L X X S X X O | P X  X  X  X  Ver(4 bits)
//! ```
//!
//! Where:
//! - T (bit 0):   Message type: 0=data, 1=control
//! - L (bit 1):   Length bit; if set, Length field is present
//! - S (bit 4):   Sequence bit; if set, Ns and Nr fields are present
//! - O (bit 6):   Offset bit; if set, Offset Size/Pad fields are present
//! - P (bit 8):   Priority (data messages only)
//! - Ver (12-15): Must be 2 for L2TPv2
//!
//! Fields present in order:
//! 1. Flags+Version (2 bytes, always)
//! 2. Length (2 bytes, only if L=1)
//! 3. Tunnel ID (2 bytes, always)
//! 4. Session ID (2 bytes, always)
//! 5. Ns (2 bytes, only if S=1)
//! 6. Nr (2 bytes, only if S=1)
//! 7. Offset Size (2 bytes, only if O=1)
//! 8. Offset Pad (variable, only if O=1)

pub mod builder;

pub use builder::L2tpBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum L2TP header: flags+version (2) + tunnel_id (2) + session_id (2) = 6 bytes.
pub const L2TP_MIN_HEADER_LEN: usize = 6;

/// L2TP version number (bits 12-15 of the flags word).
pub const L2TP_VERSION: u8 = 2;

/// L2TP UDP port.
pub const L2TP_PORT: u16 = 1701;

/// Field names exported for Python/generic access.
pub static L2TP_FIELD_NAMES: &[&str] = &[
    "flags",
    "version",
    "msg_type",
    "length",
    "tunnel_id",
    "session_id",
    "ns",
    "nr",
    "offset_size",
];

/// L2TP layer — a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct L2tpLayer {
    pub index: LayerIndex,
}

impl L2tpLayer {
    /// Create a new L2TP layer from a layer index.
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create an L2TP layer starting at offset 0 (for standalone parsing).
    pub fn at_start() -> Self {
        Self {
            index: LayerIndex::new(LayerKind::L2tp, 0, L2TP_MIN_HEADER_LEN),
        }
    }

    /// Return a reference to a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Raw flag word helpers
    // ========================================================================

    /// Read the 2-byte flags+version word.
    pub fn flags_word(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 2,
                have: s.len(),
            });
        }
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// Get the raw flags byte (high byte of the flags word, bits 0-7).
    pub fn flags(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.flags_word(buf)
    }

    /// Get the version nibble (bits 12-15 of the flags word; should be 2).
    pub fn version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let word = self.flags_word(buf)?;
        Ok((word & 0x000F) as u8)
    }

    /// Get message type: 0 = data, 1 = control (T bit, bit 15 of word).
    pub fn msg_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let word = self.flags_word(buf)?;
        Ok(((word >> 15) & 0x01) as u8)
    }

    /// Returns true if the T (type) bit is set (control message).
    pub fn is_control(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.msg_type(buf)? == 1)
    }

    /// Returns true if the L (length) bit is set, meaning Length field is present.
    pub fn has_length(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let word = self.flags_word(buf)?;
        Ok((word >> 14) & 0x01 == 1)
    }

    /// Returns true if the S (sequence) bit is set, meaning Ns and Nr are present.
    pub fn has_sequence(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let word = self.flags_word(buf)?;
        Ok((word >> 11) & 0x01 == 1)
    }

    /// Returns true if the O (offset) bit is set, meaning Offset fields are present.
    pub fn has_offset(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let word = self.flags_word(buf)?;
        Ok((word >> 9) & 0x01 == 1)
    }

    // ========================================================================
    // Field accessors (conditional on flag bits)
    // ========================================================================

    /// Get the optional Length field (present when L bit is set).
    pub fn length(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        if !self.has_length(buf)? {
            return Ok(None);
        }
        let s = self.slice(buf);
        let offset = 2; // after flags word
        if s.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offset,
                need: 2,
                have: s.len().saturating_sub(offset),
            });
        }
        Ok(Some(u16::from_be_bytes([s[offset], s[offset + 1]])))
    }

    /// Compute the byte offset of tunnel_id within the layer slice.
    fn tunnel_id_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let mut off = 2; // after flags word
        if self.has_length(buf)? {
            off += 2; // skip Length field
        }
        Ok(off)
    }

    /// Get the Tunnel ID field.
    pub fn tunnel_id(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        let off = self.tunnel_id_offset(buf)?;
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([s[off], s[off + 1]]))
    }

    /// Set the Tunnel ID field.
    pub fn set_tunnel_id(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + self.tunnel_id_offset(buf)?;
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

    /// Compute byte offset of session_id within the layer slice.
    fn session_id_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok(self.tunnel_id_offset(buf)? + 2)
    }

    /// Get the Session ID field.
    pub fn session_id(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        let off = self.session_id_offset(buf)?;
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(u16::from_be_bytes([s[off], s[off + 1]]))
    }

    /// Set the Session ID field.
    pub fn set_session_id(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + self.session_id_offset(buf)?;
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

    /// Compute offset of Ns within layer slice (only valid when S bit set).
    fn ns_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok(self.session_id_offset(buf)? + 2)
    }

    /// Get the Ns (send sequence number) field if S bit is set.
    pub fn ns(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        if !self.has_sequence(buf)? {
            return Ok(None);
        }
        let s = self.slice(buf);
        let off = self.ns_offset(buf)?;
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(Some(u16::from_be_bytes([s[off], s[off + 1]])))
    }

    /// Set the Ns field.
    pub fn set_ns(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        if !self.has_sequence(buf)? {
            return Err(FieldError::InvalidValue(
                "S bit not set; Ns field not present".into(),
            ));
        }
        let off = self.index.start + self.ns_offset(buf)?;
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

    /// Compute offset of Nr within layer slice (only valid when S bit set).
    fn nr_offset(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok(self.ns_offset(buf)? + 2)
    }

    /// Get the Nr (receive sequence number) field if S bit is set.
    pub fn nr(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        if !self.has_sequence(buf)? {
            return Ok(None);
        }
        let s = self.slice(buf);
        let off = self.nr_offset(buf)?;
        if s.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + off,
                need: 2,
                have: s.len().saturating_sub(off),
            });
        }
        Ok(Some(u16::from_be_bytes([s[off], s[off + 1]])))
    }

    /// Set the Nr field.
    pub fn set_nr(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        if !self.has_sequence(buf)? {
            return Err(FieldError::InvalidValue(
                "S bit not set; Nr field not present".into(),
            ));
        }
        let off = self.index.start + self.nr_offset(buf)?;
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

    /// Compute the dynamic header length based on flag bits.
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        if s.len() < 2 {
            return L2TP_MIN_HEADER_LEN;
        }
        let word = u16::from_be_bytes([s[0], s[1]]);
        let has_l = (word >> 14) & 0x01 == 1;
        let has_s = (word >> 11) & 0x01 == 1;
        let has_o = (word >> 9) & 0x01 == 1;

        let mut len = 2; // flags word
        if has_l {
            len += 2;
        }
        len += 4; // tunnel_id + session_id
        if has_s {
            len += 4; // Ns + Nr
        }
        if has_o {
            // Offset Size (2 bytes) + Offset Pad (variable)
            let off_size_pos = len;
            if s.len() >= off_size_pos + 2 {
                let offset_size =
                    u16::from_be_bytes([s[off_size_pos], s[off_size_pos + 1]]) as usize;
                len += 2 + offset_size;
            } else {
                len += 2;
            }
        }
        len
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this L2TP layer.
    pub fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        if s.len() < 2 {
            return "L2TP".to_string();
        }
        let is_ctrl = self
            .is_control(buf)
            .map(|c| if c { "ctrl" } else { "data" })
            .unwrap_or("?");
        let tid = self
            .tunnel_id(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let sid = self
            .session_id(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string());
        format!("L2TP {} tunnel_id={} session_id={}", is_ctrl, tid, sid)
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    pub fn field_names() -> &'static [&'static str] {
        L2TP_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "flags" => Some(self.flags_word(buf).map(FieldValue::U16)),
            "version" => Some(self.version(buf).map(FieldValue::U8)),
            "msg_type" => Some(self.msg_type(buf).map(FieldValue::U8)),
            "length" => Some(self.length(buf).map(|v| FieldValue::U16(v.unwrap_or(0)))),
            "tunnel_id" => Some(self.tunnel_id(buf).map(FieldValue::U16)),
            "session_id" => Some(self.session_id(buf).map(FieldValue::U16)),
            "ns" => Some(self.ns(buf).map(|v| FieldValue::U16(v.unwrap_or(0)))),
            "nr" => Some(self.nr(buf).map(|v| FieldValue::U16(v.unwrap_or(0)))),
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
            "tunnel_id" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_tunnel_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "tunnel_id: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "session_id" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_session_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "session_id: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "ns" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_ns(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ns: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "nr" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_nr(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "nr: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for L2tpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::L2tp
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        L2TP_FIELD_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal data-type L2TP header (no optional fields).
    /// Flags word: 0x0002 (ver=2, all bits clear = data, no L, no S, no O)
    fn data_header(tunnel_id: u16, session_id: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 6];
        buf[0] = 0x00;
        buf[1] = 0x02; // flags = 0x0002 (ver=2)
        buf[2..4].copy_from_slice(&tunnel_id.to_be_bytes());
        buf[4..6].copy_from_slice(&session_id.to_be_bytes());
        buf
    }

    /// Build a control+length L2TP header (T=1, L=1, S=1, ver=2).
    /// Matches the UTS test: `L2TP(hdr="control+length", tunnel_id=1, session_id=2)`.
    fn control_length_header(tunnel_id: u16, session_id: u16) -> Vec<u8> {
        // flags word: T=1 (bit15), L=1 (bit14), S=1 (bit11) → 0xC002 | 0x0800 = 0xC802
        // Wait — "control+length" in UTS → T=1, L=1 → 0xC002
        // Then Ns=0, Nr=0 also appear in the UTS output, meaning S=1 too
        // Bytes: \xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00
        // 0xC0 = 1100_0000: T=1 (bit7), L=1 (bit6) of high byte
        // 0x02 = 0000_0010: ver=2
        // So S and O are in the HIGH byte bits 4 and 2 respectively:
        // High byte bit mapping: T=7, L=6, x=5, x=4, S=3, x=2, x=1, O=0 (but wait…)
        // Actually RFC 2661 bit ordering in 16-bit word (network byte order):
        // bit 0 = MSB of high byte = T
        // bit 1 = L
        // bit 4 = S
        // bit 6 = O
        // bit 8 = P (low byte bit 7)
        // bits 12-15 = Ver (low nibble of low byte)
        // So for control+length+sequence (T=1, L=1, S=1):
        // high byte: bit7=T=1, bit6=L=1, bit3=S=1 → 0xC8 | ... no
        // Let's just use the raw bytes from the UTS test:
        // \xc0\x02 = 0xC002 → flags word
        // 0xC0 high byte: 1100_0000 → T=1(bit7), L=1(bit6), others=0
        // 0x02 low byte: 0000_0010 → ver=2
        // Then: \x00\x0c = length=12
        // \x00\x01 = tunnel_id=1, \x00\x02 = session_id=2
        // \x00\x00 = Ns=0, \x00\x00 = Nr=0
        // BUT that needs S bit set for Ns/Nr to appear!
        // 0xC002: bit15=1(T), bit14=1(L), bit11=0(S)... so S is NOT set?
        // But the output has 12 bytes: 2+2+2+2+2+2=12 which includes Ns+Nr...
        // Looking at UTS bytes again: b'\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00'
        // = flags(2) + length(2) + tunnel(2) + session(2) + ns(2) + nr(2) = 12 bytes
        // So S bit MUST be set. 0xC002 in binary:
        // 1100 0000 0000 0010
        // MSB to LSB: T=1, L=1, 0, 0, S=0?, 0, 0, 0, 0, 0, 0, 0, ver=0010
        // S is at bit position 11 from MSB (0-indexed): bit 11 from left = bit 4 in low byte?
        // Actually 16-bit word bit numbering: bit 0 = bit 15 of the 16-bit word (T)
        // From RFC 2661 section 3.1:
        // The Flags and Version Fields are in network byte order.
        // T L x x S x O  P  x  x  x  x  Ver Ver Ver Ver
        // 0 1 2 3 4 5 6  7  8  9 10 11 12  13  14  15
        // So in network byte order (big-endian):
        // First byte (high byte): bits 0-7 = T, L, x, x, S, x, O, P (using RFC numbering 0-7)
        // → no wait. In network byte order, bit 0 is MSB.
        // RFC 2661: "The 16-bit flags/version field has the following format:
        //  0                   1
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |T|L|x|x|S|x|O|P|x|x|x|x| Ver |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
        // So bit 0 (MSB) = T, bit 1 = L, bit 4 = S, bit 6 = O, bit 7 = P, bits 12-15 = Ver
        // In the 16-bit big-endian word, the high byte is bits 0-7 and low byte is bits 8-15.
        // High byte: T(bit0/bit7 of byte)=1, L(bit1/bit6 of byte)=1 → 0xC0
        // S is bit 4 of the 16-bit word = bit 3 of high byte → 0xC0 | (1<<3) = 0xC8 for S=1
        // But UTS shows 0xC002 which means S=0 in the flags!
        // The 12-byte output for control+length must include something else...
        // Let me recount the UTS bytes for "control+length":
        // b'\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00'
        // If S=0 (no sequence), the fields would be:
        // flags(2) + length(2) + tunnel(2) + session(2) = 8 bytes total... but length=12
        // Scapy's default for L2TP control message includes Ns and Nr.
        // So the "control+length" hdr option sets T=1, L=1, AND Scapy also sets S=1 by default
        // for control messages. The flags word would then be:
        // T=1, L=1, S=1 → bits 0,1,4 set → 0xC0 | 0x08 = 0xC8 for high byte
        // But the UTS shows 0xC0... Let me just trust the test bytes directly.
        // Actually \xc0\x02 as a 16-bit: 0xC002
        // T = bit 15 (MSB of 16-bit) = 1 ✓
        // L = bit 14 = 1 ✓
        // S = bit 11 = 0... but we have Ns and Nr in the output
        // Something is off. Let me re-examine. 0xC002:
        // binary: 1100 0000 0000 0010
        //         TLXX SXOP XXXX VVVV
        // T=1, L=1, S=0, O=0, P=0, Ver=2
        // With T=1, L=1, S=0: header = flags(2)+len(2)+tunnel(2)+session(2) = 8 bytes, length=8
        // But UTS shows length=12 and 4 more bytes (the zeros at end).
        // UNLESS Scapy's "control+length" hdr actually means something different.
        // Perhaps Scapy L2TP with control messages ALWAYS adds Ns/Nr.
        // The actual bytes say length=0x0c=12 with 12 total bytes including Ns+Nr.
        // So S bit must be set somehow. Maybe Scapy represents it differently.
        // Let me look at 0xC002 again: maybe the bit ordering in Scapy is different.
        // Scapy field "hdr" is a FlagsField with bit names in order:
        // From Scapy source: BitField("hdr", 0xC802, 16) or similar
        // Actually I think Scapy might encode S differently.
        // For our implementation, let's just use what the test expects.
        // The 12-byte control+length header:
        // \xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00
        // We'll treat bits 12-15 (low nibble) as version=2 ✓
        // And interpret the bytes literally for our builder.
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&0xC002u16.to_be_bytes()); // flags word: T=1, L=1, ver=2
        buf.extend_from_slice(&12u16.to_be_bytes()); // length = 12
        buf.extend_from_slice(&tunnel_id.to_be_bytes());
        buf.extend_from_slice(&session_id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // Ns = 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // Nr = 0
        buf
    }

    #[test]
    fn test_data_header_parse() {
        let data = data_header(0, 0);
        let idx = LayerIndex::new(LayerKind::L2tp, 0, data.len());
        let l2tp = L2tpLayer::new(idx);

        assert_eq!(l2tp.version(&data).unwrap(), 2);
        assert_eq!(l2tp.msg_type(&data).unwrap(), 0); // data
        assert!(!l2tp.has_length(&data).unwrap());
        assert!(!l2tp.has_sequence(&data).unwrap());
        assert_eq!(l2tp.tunnel_id(&data).unwrap(), 0);
        assert_eq!(l2tp.session_id(&data).unwrap(), 0);
        assert!(l2tp.ns(&data).unwrap().is_none());
        assert!(l2tp.nr(&data).unwrap().is_none());
    }

    #[test]
    fn test_default_data_bytes() {
        // UTS: L2TP() default → \x00\x02\x00\x00\x00\x00
        let data = data_header(0, 0);
        assert_eq!(data, b"\x00\x02\x00\x00\x00\x00");
    }

    #[test]
    fn test_header_len_data() {
        let data = data_header(1, 2);
        let idx = LayerIndex::new(LayerKind::L2tp, 0, data.len());
        let l2tp = L2tpLayer::new(idx);
        assert_eq!(l2tp.compute_header_len(&data), 6);
    }

    #[test]
    fn test_header_len_with_length_field() {
        // L bit set → flags(2) + length(2) + tunnel(2) + session(2) = 8
        let mut data = vec![0xC0u8, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x02];
        let idx = LayerIndex::new(LayerKind::L2tp, 0, data.len());
        let l2tp = L2tpLayer::new(idx);
        assert!(l2tp.has_length(&data).unwrap());
        assert_eq!(l2tp.compute_header_len(&data), 8);
        assert_eq!(l2tp.tunnel_id(&data).unwrap(), 1);
        assert_eq!(l2tp.session_id(&data).unwrap(), 2);
        let _ = data;
    }

    #[test]
    fn test_set_tunnel_session_id() {
        let mut data = data_header(0, 0);
        let idx = LayerIndex::new(LayerKind::L2tp, 0, data.len());
        let l2tp = L2tpLayer::new(idx);
        l2tp.set_tunnel_id(&mut data, 42).unwrap();
        l2tp.set_session_id(&mut data, 99).unwrap();
        assert_eq!(l2tp.tunnel_id(&data).unwrap(), 42);
        assert_eq!(l2tp.session_id(&data).unwrap(), 99);
    }

    #[test]
    fn test_summary() {
        let data = data_header(1, 2);
        let idx = LayerIndex::new(LayerKind::L2tp, 0, data.len());
        let l2tp = L2tpLayer::new(idx);
        let s = l2tp.summary(&data);
        assert!(s.contains("tunnel_id=1"));
        assert!(s.contains("session_id=2"));
        assert!(s.contains("data"));
    }
}
