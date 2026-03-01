//! IEEE 802.11 data frame subtypes and QoS handling.
//!
//! Data frames carry the actual payload data in 802.11 networks.
//! QoS data frames include a 2-byte QoS Control field after the
//! 802.11 header (and before the payload/security headers).

use crate::layer::field::FieldError;

/// QoS Control field length.
pub const QOS_CTRL_LEN: usize = 2;

/// LLC/SNAP header length.
pub const LLC_SNAP_LEN: usize = 8;

/// LLC/SNAP header: AA:AA:03:00:00:00 followed by 2-byte EtherType.
pub const LLC_SNAP_PREFIX: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];

// ============================================================================
// Dot11QoS
// ============================================================================

/// 802.11 QoS Control field (2 bytes).
///
/// Layout (Scapy bit ordering for byte 0):
/// ```text
/// Byte 0: [A-MSDU Present(1) | Ack Policy(2) | EOSP(1) | TID(4)]
/// Byte 1: TXOP Limit / Queue Size
/// ```
///
/// Present in QoS Data frames (subtype >= 8).
#[derive(Debug, Clone)]
pub struct Dot11QoS {
    pub offset: usize,
}

impl Dot11QoS {
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate buffer length.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + QOS_CTRL_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: QOS_CTRL_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// Raw QoS Control field (2 bytes, little-endian).
    pub fn raw(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// TID (Traffic Identifier, lower 4 bits of byte 0).
    pub fn tid(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.offset;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off] & 0x0F)
    }

    /// EOSP (End Of Service Period, bit 4 of byte 0).
    pub fn eosp(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let off = self.offset;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off] & 0x10 != 0)
    }

    /// Ack Policy (bits 5-6 of byte 0).
    pub fn ack_policy(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.offset;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok((buf[off] >> 5) & 0x03)
    }

    /// A-MSDU Present flag (bit 7 of byte 0).
    pub fn a_msdu_present(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let off = self.offset;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off] & 0x80 != 0)
    }

    /// TXOP Limit or Queue Size (byte 1).
    pub fn txop(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.offset + 1;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len(),
            });
        }
        Ok(buf[off])
    }

    /// Header length.
    pub fn header_len(&self) -> usize {
        QOS_CTRL_LEN
    }

    /// Build QoS Control field bytes.
    pub fn build(tid: u8, eosp: bool, ack_policy: u8, a_msdu: bool, txop: u8) -> Vec<u8> {
        let byte0 = (tid & 0x0F)
            | (if eosp { 0x10 } else { 0 })
            | ((ack_policy & 0x03) << 5)
            | (if a_msdu { 0x80 } else { 0 });
        vec![byte0, txop]
    }
}

// ============================================================================
// LLC/SNAP detection
// ============================================================================

/// Check if the data at the given offset starts with an LLC/SNAP header.
pub fn is_llc_snap(buf: &[u8], offset: usize) -> bool {
    if buf.len() < offset + LLC_SNAP_LEN {
        return false;
    }
    buf[offset..offset + 6] == LLC_SNAP_PREFIX
}

/// Extract the EtherType from an LLC/SNAP header at the given offset.
pub fn llc_snap_ethertype(buf: &[u8], offset: usize) -> Result<u16, FieldError> {
    if buf.len() < offset + LLC_SNAP_LEN {
        return Err(FieldError::BufferTooShort {
            offset: offset + 6,
            need: 2,
            have: buf.len().saturating_sub(offset + 6),
        });
    }
    Ok(u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]))
}

// ============================================================================
// A-MSDU subframe
// ============================================================================

/// A single A-MSDU subframe.
///
/// Layout:
/// - DA (6 bytes)
/// - SA (6 bytes)
/// - Length (2 bytes, big-endian)
/// - MSDU (variable)
/// - Padding (0-3 bytes to align to 4-byte boundary)
#[derive(Debug, Clone)]
pub struct AMsduSubframe {
    /// Destination address.
    pub da: [u8; 6],
    /// Source address.
    pub sa: [u8; 6],
    /// MSDU data.
    pub data: Vec<u8>,
}

/// A-MSDU subframe header length: DA(6) + SA(6) + Length(2) = 14.
pub const AMSDU_SUBFRAME_HEADER_LEN: usize = 14;

impl AMsduSubframe {
    /// Parse A-MSDU subframes from the given buffer.
    pub fn parse_all(buf: &[u8], offset: usize) -> Result<Vec<AMsduSubframe>, FieldError> {
        let mut subframes = Vec::new();
        let mut pos = offset;

        while pos + AMSDU_SUBFRAME_HEADER_LEN <= buf.len() {
            let mut da = [0u8; 6];
            let mut sa = [0u8; 6];
            da.copy_from_slice(&buf[pos..pos + 6]);
            sa.copy_from_slice(&buf[pos + 6..pos + 12]);
            let length = u16::from_be_bytes([buf[pos + 12], buf[pos + 13]]) as usize;

            let data_start = pos + AMSDU_SUBFRAME_HEADER_LEN;
            let data_end = data_start + length;
            if data_end > buf.len() {
                break;
            }

            subframes.push(AMsduSubframe {
                da,
                sa,
                data: buf[data_start..data_end].to_vec(),
            });

            // Align to 4-byte boundary
            pos = data_end;
            let padding = (4 - (pos % 4)) % 4;
            pos += padding;
        }

        Ok(subframes)
    }

    /// Build an A-MSDU subframe.
    pub fn build(&self) -> Vec<u8> {
        let length = self.data.len() as u16;
        let mut out = Vec::with_capacity(AMSDU_SUBFRAME_HEADER_LEN + self.data.len() + 3);
        out.extend_from_slice(&self.da);
        out.extend_from_slice(&self.sa);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        // Add padding to 4-byte boundary
        let padding = (4 - (out.len() % 4)) % 4;
        out.extend(std::iter::repeat(0u8).take(padding));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_parse() {
        let buf = vec![0x03, 0x00];
        let qos = Dot11QoS::new(0);

        assert_eq!(qos.tid(&buf).unwrap(), 3);
        assert!(!qos.eosp(&buf).unwrap());
        assert_eq!(qos.ack_policy(&buf).unwrap(), 0);
        assert!(!qos.a_msdu_present(&buf).unwrap());
        assert_eq!(qos.txop(&buf).unwrap(), 0);
    }

    #[test]
    fn test_qos_with_eosp_and_amsdu() {
        // TID=5, EOSP=1, AckPolicy=2, A-MSDU=1
        // byte0: TID=5(0x05) | EOSP(0x10) | AckPolicy=2(0x40) | A-MSDU(0x80) = 0xD5
        let buf = vec![0xD5, 0x10];
        let qos = Dot11QoS::new(0);

        assert_eq!(qos.tid(&buf).unwrap(), 5);
        assert!(qos.eosp(&buf).unwrap());
        assert_eq!(qos.ack_policy(&buf).unwrap(), 2);
        assert!(qos.a_msdu_present(&buf).unwrap());
        assert_eq!(qos.txop(&buf).unwrap(), 0x10);
    }

    #[test]
    fn test_qos_build_roundtrip() {
        let data = Dot11QoS::build(5, true, 2, true, 0x10);
        assert_eq!(data.len(), QOS_CTRL_LEN);

        let qos = Dot11QoS::new(0);
        assert_eq!(qos.tid(&data).unwrap(), 5);
        assert!(qos.eosp(&data).unwrap());
        assert_eq!(qos.ack_policy(&data).unwrap(), 2);
        assert!(qos.a_msdu_present(&data).unwrap());
        assert_eq!(qos.txop(&data).unwrap(), 0x10);
    }

    #[test]
    fn test_llc_snap_detection() {
        let mut buf = vec![0u8; 8];
        buf[0..6].copy_from_slice(&LLC_SNAP_PREFIX);
        buf[6] = 0x08;
        buf[7] = 0x00;

        assert!(is_llc_snap(&buf, 0));
        assert_eq!(llc_snap_ethertype(&buf, 0).unwrap(), 0x0800);
    }

    #[test]
    fn test_llc_snap_not_present() {
        let buf = vec![0x00; 8];
        assert!(!is_llc_snap(&buf, 0));
    }

    #[test]
    fn test_amsdu_parse() {
        let subframe1 = AMsduSubframe {
            da: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            sa: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
            data: vec![0xAA, 0xBB, 0xCC],
        };
        let built = subframe1.build();
        assert_eq!(built.len(), 20);

        let parsed = AMsduSubframe::parse_all(&built, 0).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].da, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(parsed[0].sa, [0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        assert_eq!(parsed[0].data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_amsdu_multiple_subframes() {
        let sf1 = AMsduSubframe {
            da: [0x01; 6],
            sa: [0x02; 6],
            data: vec![0x10, 0x20],
        };
        let sf2 = AMsduSubframe {
            da: [0x03; 6],
            sa: [0x04; 6],
            data: vec![0x30, 0x40, 0x50, 0x60],
        };

        let mut buf = sf1.build();
        buf.extend(sf2.build());

        let parsed = AMsduSubframe::parse_all(&buf, 0).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].data, vec![0x10, 0x20]);
        assert_eq!(parsed[1].data, vec![0x30, 0x40, 0x50, 0x60]);
    }

    #[test]
    fn test_qos_header_len() {
        let qos = Dot11QoS::new(0);
        assert_eq!(qos.header_len(), 2);
    }

    #[test]
    fn test_qos_raw() {
        let buf = vec![0xD5, 0x10];
        let qos = Dot11QoS::new(0);
        assert_eq!(qos.raw(&buf).unwrap(), 0x10D5);
    }
}
