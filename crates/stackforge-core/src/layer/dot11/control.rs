//! IEEE 802.11 control frame subtypes.
//!
//! Control frames are used for assisting delivery of data and management frames.
//! Most control frames have minimal or no body beyond the 802.11 header addresses.

use crate::layer::field::FieldError;

// ============================================================================
// Dot11Ack
// ============================================================================

/// 802.11 ACK frame.
///
/// The ACK frame has no body beyond the 802.11 header (FC + Duration + Addr1).
#[derive(Debug, Clone)]
pub struct Dot11Ack {
    pub offset: usize,
}

impl Dot11Ack {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Header length (no additional fields beyond the main Dot11 header).
    pub fn header_len(&self) -> usize {
        0
    }
}

// ============================================================================
// Dot11RTS
// ============================================================================

/// 802.11 RTS (Request To Send) frame.
///
/// The RTS frame has no body beyond the 802.11 header (FC + Duration + Addr1 + Addr2).
#[derive(Debug, Clone)]
pub struct Dot11RTS {
    pub offset: usize,
}

impl Dot11RTS {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Header length (no additional fields).
    pub fn header_len(&self) -> usize {
        0
    }
}

// ============================================================================
// Dot11CTS
// ============================================================================

/// 802.11 CTS (Clear To Send) frame.
///
/// The CTS frame has no body beyond the 802.11 header (FC + Duration + Addr1).
#[derive(Debug, Clone)]
pub struct Dot11CTS {
    pub offset: usize,
}

impl Dot11CTS {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Header length (no additional fields).
    pub fn header_len(&self) -> usize {
        0
    }
}

// ============================================================================
// Dot11BlockAckReq (BAR)
// ============================================================================

/// 802.11 Block Ack Request (BAR) frame body.
///
/// After the 802.11 header (Addr1 + Addr2), contains:
/// - BAR Control (2 bytes, little-endian)
/// - Starting Sequence Control (2 bytes, little-endian)
#[derive(Debug, Clone)]
pub struct Dot11BlockAckReq {
    pub offset: usize,
}

pub const BAR_FIXED_LEN: usize = 4;

impl Dot11BlockAckReq {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// BAR Control field (little-endian u16).
    ///
    /// Bits 0: BAR Ack Policy
    /// Bits 1-3: BAR Type
    /// Bits 4-11: Reserved
    /// Bits 12-15: TID_INFO
    pub fn bar_control(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// BAR Ack Policy (bit 0 of BAR Control).
    pub fn ack_policy(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.bar_control(buf)? & 0x0001 != 0)
    }

    /// BAR Type (bits 1-3 of BAR Control).
    pub fn bar_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(((self.bar_control(buf)? >> 1) & 0x07) as u8)
    }

    /// TID Info (bits 12-15 of BAR Control).
    pub fn tid_info(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(((self.bar_control(buf)? >> 12) & 0x0F) as u8)
    }

    /// Starting Sequence Control (little-endian u16).
    pub fn start_seq_ctrl(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Starting sequence number (upper 12 bits of starting sequence control).
    pub fn start_seq_num(&self, buf: &[u8]) -> Result<u16, FieldError> {
        Ok(self.start_seq_ctrl(buf)? >> 4)
    }

    /// Fragment number (lower 4 bits of starting sequence control).
    pub fn fragment_num(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok((self.start_seq_ctrl(buf)? & 0x0F) as u8)
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        BAR_FIXED_LEN
    }

    /// Build BAR body.
    pub fn build(bar_control: u16, start_seq_ctrl: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(BAR_FIXED_LEN);
        out.extend_from_slice(&bar_control.to_le_bytes());
        out.extend_from_slice(&start_seq_ctrl.to_le_bytes());
        out
    }
}

// ============================================================================
// Dot11BlockAck (BA)
// ============================================================================

/// 802.11 Block Ack (BA) frame body.
///
/// After the 802.11 header (Addr1 + Addr2), contains:
/// - BA Control (2 bytes, little-endian)
/// - Starting Sequence Control (2 bytes, little-endian)
/// - Block Ack Bitmap (variable, typically 128 bytes for basic BA)
#[derive(Debug, Clone)]
pub struct Dot11BlockAck {
    pub offset: usize,
    pub len: usize,
}

pub const BA_MIN_FIXED_LEN: usize = 4;
pub const BA_BASIC_BITMAP_LEN: usize = 128;

impl Dot11BlockAck {
    pub fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    /// BA Control field (little-endian u16).
    pub fn ba_control(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// BA Ack Policy (bit 0).
    pub fn ack_policy(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.ba_control(buf)? & 0x0001 != 0)
    }

    /// BA Type (bits 1-3).
    pub fn ba_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(((self.ba_control(buf)? >> 1) & 0x07) as u8)
    }

    /// TID Info (bits 12-15).
    pub fn tid_info(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(((self.ba_control(buf)? >> 12) & 0x0F) as u8)
    }

    /// Starting Sequence Control (little-endian u16).
    pub fn start_seq_ctrl(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.offset + 2;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Starting sequence number.
    pub fn start_seq_num(&self, buf: &[u8]) -> Result<u16, FieldError> {
        Ok(self.start_seq_ctrl(buf)? >> 4)
    }

    /// Block Ack Bitmap (variable length, starts at offset+4).
    pub fn bitmap<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let off = self.offset + 4;
        let end = self.offset + self.len;
        if buf.len() < end {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: self.len - 4,
                have: buf.len().saturating_sub(off),
            });
        }
        Ok(&buf[off..end])
    }

    /// Header length (entire BA body including bitmap).
    pub fn header_len(&self) -> usize {
        self.len
    }

    /// Build a basic BA body with 128-byte bitmap.
    pub fn build_basic(ba_control: u16, start_seq_ctrl: u16, bitmap: &[u8; 128]) -> Vec<u8> {
        let mut out = Vec::with_capacity(BA_MIN_FIXED_LEN + BA_BASIC_BITMAP_LEN);
        out.extend_from_slice(&ba_control.to_le_bytes());
        out.extend_from_slice(&start_seq_ctrl.to_le_bytes());
        out.extend_from_slice(bitmap);
        out
    }
}

// ============================================================================
// Dot11PSPoll
// ============================================================================

/// 802.11 PS-Poll frame body.
///
/// The PS-Poll uses the Duration/ID field as AID.
/// No additional body beyond the 802.11 header.
#[derive(Debug, Clone)]
pub struct Dot11PSPoll {
    pub offset: usize,
}

impl Dot11PSPoll {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Header length (no additional fields).
    pub fn header_len(&self) -> usize {
        0
    }
}

// ============================================================================
// Dot11CFEnd
// ============================================================================

/// 802.11 CF-End frame body.
///
/// No additional body beyond the 802.11 header.
#[derive(Debug, Clone)]
pub struct Dot11CFEnd {
    pub offset: usize,
}

impl Dot11CFEnd {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Header length (no additional fields).
    pub fn header_len(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack() {
        let ack = Dot11Ack::new(0);
        assert_eq!(ack.header_len(), 0);
    }

    #[test]
    fn test_rts() {
        let rts = Dot11RTS::new(0);
        assert_eq!(rts.header_len(), 0);
    }

    #[test]
    fn test_cts() {
        let cts = Dot11CTS::new(0);
        assert_eq!(cts.header_len(), 0);
    }

    #[test]
    fn test_bar_parse() {
        let mut buf = vec![0u8; 4];
        // BAR Control: ack_policy=1, type=0, TID=5 => bit0=1, bits 12-15=5
        // = 0x5001
        buf[0..2].copy_from_slice(&0x5001u16.to_le_bytes());
        // Starting Sequence Control: seq=100 => 100 << 4 = 0x0640
        buf[2..4].copy_from_slice(&0x0640u16.to_le_bytes());

        let bar = Dot11BlockAckReq::new(0);
        assert_eq!(bar.bar_control(&buf).unwrap(), 0x5001);
        assert!(bar.ack_policy(&buf).unwrap());
        assert_eq!(bar.bar_type(&buf).unwrap(), 0);
        assert_eq!(bar.tid_info(&buf).unwrap(), 5);
        assert_eq!(bar.start_seq_num(&buf).unwrap(), 100);
        assert_eq!(bar.fragment_num(&buf).unwrap(), 0);
    }

    #[test]
    fn test_bar_build_roundtrip() {
        let data = Dot11BlockAckReq::build(0x5001, 0x0640);
        assert_eq!(data.len(), BAR_FIXED_LEN);

        let bar = Dot11BlockAckReq::new(0);
        assert_eq!(bar.bar_control(&data).unwrap(), 0x5001);
        assert_eq!(bar.start_seq_ctrl(&data).unwrap(), 0x0640);
    }

    #[test]
    fn test_ba_parse() {
        let mut buf = vec![0u8; 4 + 128];
        // BA Control: ack_policy=1, TID=3
        buf[0..2].copy_from_slice(&0x3001u16.to_le_bytes());
        // Starting Sequence Control: seq=50 => 50 << 4 = 0x0320
        buf[2..4].copy_from_slice(&0x0320u16.to_le_bytes());
        // First byte of bitmap set
        buf[4] = 0xFF;

        let ba = Dot11BlockAck::new(0, buf.len());
        assert_eq!(ba.ba_control(&buf).unwrap(), 0x3001);
        assert!(ba.ack_policy(&buf).unwrap());
        assert_eq!(ba.tid_info(&buf).unwrap(), 3);
        assert_eq!(ba.start_seq_num(&buf).unwrap(), 50);

        let bitmap = ba.bitmap(&buf).unwrap();
        assert_eq!(bitmap.len(), 128);
        assert_eq!(bitmap[0], 0xFF);
    }

    #[test]
    fn test_ba_build_roundtrip() {
        let mut bitmap = [0u8; 128];
        bitmap[0] = 0x01;
        bitmap[127] = 0x80;

        let data = Dot11BlockAck::build_basic(0x3001, 0x0320, &bitmap);
        assert_eq!(data.len(), BA_MIN_FIXED_LEN + BA_BASIC_BITMAP_LEN);

        let ba = Dot11BlockAck::new(0, data.len());
        assert_eq!(ba.ba_control(&data).unwrap(), 0x3001);
        let parsed_bitmap = ba.bitmap(&data).unwrap();
        assert_eq!(parsed_bitmap[0], 0x01);
        assert_eq!(parsed_bitmap[127], 0x80);
    }

    #[test]
    fn test_pspoll() {
        let pspoll = Dot11PSPoll::new(0);
        assert_eq!(pspoll.header_len(), 0);
    }

    #[test]
    fn test_cfend() {
        let cfend = Dot11CFEnd::new(0);
        assert_eq!(cfend.header_len(), 0);
    }
}
