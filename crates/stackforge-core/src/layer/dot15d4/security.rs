//! IEEE 802.15.4 Auxiliary Security Header parsing and building.
//!
//! The Auxiliary Security Header is present when the Security Enabled bit
//! is set in the Frame Control Field. It consists of:
//! - Security Control (1 byte)
//! - Frame Counter (4 bytes, LE)
//! - Key Identifier (variable length, based on Key Identifier Mode)

use crate::layer::field::{FieldError, read_u32_le, read_u64_le};

use super::types;

/// Security Control field bit layout (1 byte):
/// Bits 0-2: Security Level (3 bits)
/// Bits 3-4: Key Identifier Mode (2 bits)
/// Bits 5-7: Reserved (3 bits)

/// Parsed representation of an Auxiliary Security Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxSecurityHeader {
    /// Security level (3 bits).
    pub security_level: u8,
    /// Key identifier mode (2 bits).
    pub key_id_mode: u8,
    /// Reserved bits (3 bits).
    pub reserved: u8,
    /// Frame counter (4 bytes).
    pub frame_counter: u32,
    /// Key source (0, 4, or 8 bytes depending on key_id_mode).
    pub key_source: u64,
    /// Key index (1 byte, present if key_id_mode != 0).
    pub key_index: Option<u8>,
}

impl AuxSecurityHeader {
    /// Total byte length of this security header.
    pub fn len(&self) -> usize {
        // 1 (security control) + 4 (frame counter) + key_id_len
        1 + 4 + types::key_id_len(self.key_id_mode)
    }

    /// Compute the byte length of the security header given the security
    /// control byte (first byte of the header).
    pub fn compute_len(security_control: u8) -> usize {
        let key_id_mode = (security_control >> 3) & 0x03;
        1 + 4 + types::key_id_len(key_id_mode)
    }

    /// Parse an Auxiliary Security Header from the buffer at the given offset.
    /// Returns the parsed header and the number of bytes consumed.
    pub fn parse(buf: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        // Need at least 5 bytes (1 security control + 4 frame counter)
        if buf.len() < offset + 5 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 5,
                have: buf.len().saturating_sub(offset),
            });
        }

        let sc = buf[offset];
        let security_level = sc & 0x07;
        let key_id_mode = (sc >> 3) & 0x03;
        let reserved = (sc >> 5) & 0x07;

        let frame_counter = read_u32_le(buf, offset + 1)?;

        let ki_len = types::key_id_len(key_id_mode);
        let total_len = 1 + 4 + ki_len;

        if buf.len() < offset + total_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: total_len,
                have: buf.len().saturating_sub(offset),
            });
        }

        let mut key_source: u64 = 0;
        let key_index: Option<u8>;

        match key_id_mode {
            0 => {
                // Implicit: no key identifier
                key_index = None;
            }
            1 => {
                // Key Index only (1 byte)
                key_index = Some(buf[offset + 5]);
            }
            2 => {
                // 4-byte Key Source + 1-byte Key Index
                key_source = read_u32_le(buf, offset + 5)? as u64;
                key_index = Some(buf[offset + 9]);
            }
            3 => {
                // 8-byte Key Source + 1-byte Key Index
                key_source = read_u64_le(buf, offset + 5)?;
                key_index = Some(buf[offset + 13]);
            }
            _ => {
                key_index = None;
            }
        }

        Ok((
            Self {
                security_level,
                key_id_mode,
                reserved,
                frame_counter,
                key_source,
                key_index,
            },
            total_len,
        ))
    }

    /// Build the security header bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());

        // Security Control byte
        let sc = (self.security_level & 0x07)
            | ((self.key_id_mode & 0x03) << 3)
            | ((self.reserved & 0x07) << 5);
        out.push(sc);

        // Frame Counter (4 bytes, LE)
        out.extend_from_slice(&self.frame_counter.to_le_bytes());

        // Key Identifier
        match self.key_id_mode {
            0 => {
                // No key identifier
            }
            1 => {
                // Key Index only
                out.push(self.key_index.unwrap_or(0xFF));
            }
            2 => {
                // 4-byte Key Source (LE) + Key Index
                out.extend_from_slice(&(self.key_source as u32).to_le_bytes());
                out.push(self.key_index.unwrap_or(0xFF));
            }
            3 => {
                // 8-byte Key Source (LE) + Key Index
                out.extend_from_slice(&self.key_source.to_le_bytes());
                out.push(self.key_index.unwrap_or(0xFF));
            }
            _ => {}
        }

        out
    }

    /// Write the security header into a buffer at the given offset.
    /// Returns the number of bytes written.
    pub fn write_into(&self, buf: &mut [u8], offset: usize) -> Result<usize, FieldError> {
        let bytes = self.build();
        if buf.len() < offset + bytes.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: bytes.len(),
                have: buf.len().saturating_sub(offset),
            });
        }
        buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

impl Default for AuxSecurityHeader {
    fn default() -> Self {
        Self {
            security_level: 0,
            key_id_mode: 0,
            reserved: 0,
            frame_counter: 0,
            key_source: 0,
            key_index: None,
        }
    }
}

/// Read the security level from a Security Control byte.
#[inline]
pub fn read_security_level(sc: u8) -> u8 {
    sc & 0x07
}

/// Read the key identifier mode from a Security Control byte.
#[inline]
pub fn read_key_id_mode(sc: u8) -> u8 {
    (sc >> 3) & 0x03
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_implicit_key() {
        // Security Control: level=0 (None), key_id_mode=0 (Implicit), reserved=0
        // Frame Counter: 0x00000000
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00];
        let (hdr, consumed) = AuxSecurityHeader::parse(&buf, 0).unwrap();
        assert_eq!(hdr.security_level, 0);
        assert_eq!(hdr.key_id_mode, 0);
        assert_eq!(hdr.reserved, 0);
        assert_eq!(hdr.frame_counter, 0);
        assert_eq!(hdr.key_index, None);
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_key_index_mode() {
        // Security Control: level=1 (MIC-32), key_id_mode=1, reserved=0
        // SC = 0b00_01_001 = 0x09
        // Frame Counter: 0x12345678 (LE)
        // Key Index: 0x42
        let buf = [0x09, 0x78, 0x56, 0x34, 0x12, 0x42];
        let (hdr, consumed) = AuxSecurityHeader::parse(&buf, 0).unwrap();
        assert_eq!(hdr.security_level, 1);
        assert_eq!(hdr.key_id_mode, 1);
        assert_eq!(hdr.frame_counter, 0x12345678);
        assert_eq!(hdr.key_index, Some(0x42));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_parse_key_source_4() {
        // Security Control: level=5 (ENC-MIC-32), key_id_mode=2, reserved=0
        // SC = 0b00_10_101 = 0x15
        // Frame Counter: 0x00000001 (LE)
        // Key Source (4 bytes LE): 0xAABBCCDD
        // Key Index: 0x01
        let buf = [0x15, 0x01, 0x00, 0x00, 0x00, 0xDD, 0xCC, 0xBB, 0xAA, 0x01];
        let (hdr, consumed) = AuxSecurityHeader::parse(&buf, 0).unwrap();
        assert_eq!(hdr.security_level, 5);
        assert_eq!(hdr.key_id_mode, 2);
        assert_eq!(hdr.frame_counter, 1);
        assert_eq!(hdr.key_source, 0xAABBCCDD);
        assert_eq!(hdr.key_index, Some(0x01));
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_parse_key_source_8() {
        // Security Control: level=7 (ENC-MIC-128), key_id_mode=3, reserved=0
        // SC = 0b00_11_111 = 0x1F
        // Frame Counter: 0x00000002 (LE)
        // Key Source (8 bytes LE): 0x0102030405060708
        // Key Index: 0xFF
        let buf = [
            0x1F, 0x02, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xFF,
        ];
        let (hdr, consumed) = AuxSecurityHeader::parse(&buf, 0).unwrap();
        assert_eq!(hdr.security_level, 7);
        assert_eq!(hdr.key_id_mode, 3);
        assert_eq!(hdr.frame_counter, 2);
        assert_eq!(hdr.key_source, 0x0102030405060708);
        assert_eq!(hdr.key_index, Some(0xFF));
        assert_eq!(consumed, 14);
    }

    #[test]
    fn test_build_roundtrip_implicit() {
        let hdr = AuxSecurityHeader {
            security_level: 0,
            key_id_mode: 0,
            reserved: 0,
            frame_counter: 0,
            key_source: 0,
            key_index: None,
        };
        let bytes = hdr.build();
        assert_eq!(bytes.len(), 5);
        let (parsed, consumed) = AuxSecurityHeader::parse(&bytes, 0).unwrap();
        assert_eq!(consumed, 5);
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_build_roundtrip_key_index() {
        let hdr = AuxSecurityHeader {
            security_level: 1,
            key_id_mode: 1,
            reserved: 0,
            frame_counter: 0x12345678,
            key_source: 0,
            key_index: Some(0x42),
        };
        let bytes = hdr.build();
        assert_eq!(bytes.len(), 6);
        let (parsed, _) = AuxSecurityHeader::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_build_roundtrip_key_source_4() {
        let hdr = AuxSecurityHeader {
            security_level: 5,
            key_id_mode: 2,
            reserved: 0,
            frame_counter: 1,
            key_source: 0xAABBCCDD,
            key_index: Some(0x01),
        };
        let bytes = hdr.build();
        assert_eq!(bytes.len(), 10);
        let (parsed, _) = AuxSecurityHeader::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_build_roundtrip_key_source_8() {
        let hdr = AuxSecurityHeader {
            security_level: 7,
            key_id_mode: 3,
            reserved: 0,
            frame_counter: 2,
            key_source: 0x0102030405060708,
            key_index: Some(0xFF),
        };
        let bytes = hdr.build();
        assert_eq!(bytes.len(), 14);
        let (parsed, _) = AuxSecurityHeader::parse(&bytes, 0).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_parse_with_offset() {
        // Prepend some garbage bytes
        let mut buf = vec![0xAA, 0xBB, 0xCC];
        let hdr = AuxSecurityHeader {
            security_level: 4,
            key_id_mode: 1,
            reserved: 0,
            frame_counter: 100,
            key_source: 0,
            key_index: Some(0x05),
        };
        buf.extend_from_slice(&hdr.build());
        let (parsed, consumed) = AuxSecurityHeader::parse(&buf, 3).unwrap();
        assert_eq!(parsed, hdr);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_parse_buffer_too_short() {
        let buf = [0x00, 0x00]; // Too short for even minimal header
        let result = AuxSecurityHeader::parse(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_len() {
        assert_eq!(AuxSecurityHeader::compute_len(0x00), 5); // mode 0
        assert_eq!(AuxSecurityHeader::compute_len(0x08), 6); // mode 1
        assert_eq!(AuxSecurityHeader::compute_len(0x10), 10); // mode 2
        assert_eq!(AuxSecurityHeader::compute_len(0x18), 14); // mode 3
    }

    #[test]
    fn test_write_into() {
        let hdr = AuxSecurityHeader {
            security_level: 1,
            key_id_mode: 1,
            reserved: 0,
            frame_counter: 42,
            key_source: 0,
            key_index: Some(0x10),
        };
        let mut buf = vec![0u8; 20];
        let written = hdr.write_into(&mut buf, 2).unwrap();
        assert_eq!(written, 6);
        let (parsed, _) = AuxSecurityHeader::parse(&buf, 2).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_read_security_level() {
        assert_eq!(read_security_level(0x00), 0);
        assert_eq!(read_security_level(0x07), 7);
        assert_eq!(read_security_level(0xFF), 7);
    }

    #[test]
    fn test_read_key_id_mode() {
        assert_eq!(read_key_id_mode(0x00), 0);
        assert_eq!(read_key_id_mode(0x08), 1);
        assert_eq!(read_key_id_mode(0x10), 2);
        assert_eq!(read_key_id_mode(0x18), 3);
    }
}
