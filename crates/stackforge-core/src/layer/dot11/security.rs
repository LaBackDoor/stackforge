//! IEEE 802.11 security wrappers (WEP, TKIP, CCMP).
//!
//! These wrappers handle the encryption header and trailer fields
//! that appear in protected 802.11 data frames. They do NOT perform
//! actual encryption/decryption — they provide parsing and building
//! of the security header/trailer structures.

use crate::layer::field::FieldError;

// ============================================================================
// WEP Header/Trailer constants
// ============================================================================

/// WEP header length: IV(3) + KeyID(1) = 4 bytes.
pub const WEP_HEADER_LEN: usize = 4;

/// WEP trailer length: ICV(4) = 4 bytes.
pub const WEP_TRAILER_LEN: usize = 4;

// ============================================================================
// Dot11WEP
// ============================================================================

/// WEP (Wired Equivalent Privacy) encryption wrapper.
///
/// Format:
/// ```text
/// [IV (3 bytes)] [KeyID/Pad (1 byte)] [Encrypted Data ...] [ICV (4 bytes)]
/// ```
///
/// The `KeyID` byte layout:
/// - Bits 0-5: Pad (reserved, should be 0)
/// - Bits 6-7: Key ID (0-3)
#[derive(Debug, Clone)]
pub struct Dot11WEP {
    pub offset: usize,
}

impl Dot11WEP {
    #[must_use]
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate buffer length for WEP header.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + WEP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: WEP_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// Initialization Vector (3 bytes).
    pub fn iv(&self, buf: &[u8]) -> Result<[u8; 3], FieldError> {
        if buf.len() < self.offset + WEP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: WEP_HEADER_LEN,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok([buf[self.offset], buf[self.offset + 1], buf[self.offset + 2]])
    }

    /// Full IV as a u32 (24-bit value, big-endian).
    pub fn iv_u32(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let iv = self.iv(buf)?;
        Ok((u32::from(iv[0]) << 16) | (u32::from(iv[1]) << 8) | u32::from(iv[2]))
    }

    /// Key ID (bits 6-7 of byte 3).
    pub fn key_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() < self.offset + WEP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: WEP_HEADER_LEN,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok((buf[self.offset + 3] >> 6) & 0x03)
    }

    /// Raw KeyID/Pad byte.
    pub fn key_id_byte(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() < self.offset + WEP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: WEP_HEADER_LEN,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok(buf[self.offset + 3])
    }

    /// ICV (Integrity Check Value) — 4 bytes at the end of the encrypted data.
    /// `frame_end` is the offset of the end of the entire frame (after ICV).
    pub fn icv(&self, buf: &[u8], frame_end: usize) -> Result<u32, FieldError> {
        if frame_end < WEP_TRAILER_LEN || buf.len() < frame_end {
            return Err(FieldError::BufferTooShort {
                offset: frame_end.saturating_sub(WEP_TRAILER_LEN),
                need: WEP_TRAILER_LEN,
                have: 0,
            });
        }
        let off = frame_end - WEP_TRAILER_LEN;
        Ok(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    }

    /// Encrypted data (between header and ICV).
    pub fn encrypted_data<'a>(
        &self,
        buf: &'a [u8],
        frame_end: usize,
    ) -> Result<&'a [u8], FieldError> {
        let start = self.offset + WEP_HEADER_LEN;
        let end = frame_end.saturating_sub(WEP_TRAILER_LEN);
        if start > end || buf.len() < frame_end {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 0,
                have: 0,
            });
        }
        Ok(&buf[start..end])
    }

    /// Header length (always 4 bytes).
    #[must_use]
    pub fn header_len(&self) -> usize {
        WEP_HEADER_LEN
    }

    /// Trailer length (always 4 bytes).
    #[must_use]
    pub fn trailer_len(&self) -> usize {
        WEP_TRAILER_LEN
    }

    /// Build a WEP header.
    #[must_use]
    pub fn build_header(iv: [u8; 3], key_id: u8) -> Vec<u8> {
        vec![iv[0], iv[1], iv[2], (key_id & 0x03) << 6]
    }

    /// Build a WEP ICV trailer.
    #[must_use]
    pub fn build_icv(icv: u32) -> Vec<u8> {
        icv.to_le_bytes().to_vec()
    }
}

// ============================================================================
// TKIP Header/Trailer constants
// ============================================================================

/// TKIP header length without Extended IV: 4 bytes.
pub const TKIP_HEADER_SHORT: usize = 4;

/// TKIP header length with Extended IV: 8 bytes.
pub const TKIP_HEADER_LONG: usize = 8;

/// TKIP trailer length: MIC(8) + ICV(4) = 12 bytes.
/// Note: The ICV is part of the encrypted payload, and the 8-byte MIC
/// is also encrypted. The trailer for raw wire format is 4 bytes (ICV only).
pub const TKIP_ICV_LEN: usize = 4;

// ============================================================================
// Dot11TKIP
// ============================================================================

/// TKIP (Temporal Key Integrity Protocol) encryption wrapper.
///
/// Format:
/// ```text
/// [TSC1(1)] [WEPSeed(1)] [TSC0(1)] [KeyID/ExtIV(1)] [TSC2(1) TSC3(1) TSC4(1) TSC5(1)] [Encrypted Data...] [ICV(4)]
/// ```
///
/// The KeyID/ExtIV byte:
/// - Bits 0-4: Reserved
/// - Bit 5: `ExtIV` flag (always 1 for TKIP)
/// - Bits 6-7: Key ID
///
/// TSC (TKIP Sequence Counter) is a 48-bit value constructed from TSC0..TSC5.
#[derive(Debug, Clone)]
pub struct Dot11TKIP {
    pub offset: usize,
}

impl Dot11TKIP {
    #[must_use]
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate buffer length for TKIP header.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + TKIP_HEADER_SHORT {
            return Err(FieldError::BufferTooShort {
                offset,
                need: TKIP_HEADER_SHORT,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// TSC1 (byte 0 of TKIP header).
    pub fn tsc1(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset])
    }

    /// WEP Seed (byte 1 of TKIP header).
    pub fn wep_seed(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset + 1 {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 1,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset + 1])
    }

    /// TSC0 (byte 2 of TKIP header).
    pub fn tsc0(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 2,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset + 2])
    }

    /// Check if Extended IV flag is set (bit 5 of byte 3).
    pub fn ext_iv(&self, buf: &[u8]) -> Result<bool, FieldError> {
        if buf.len() < self.offset + TKIP_HEADER_SHORT {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: TKIP_HEADER_SHORT,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok(buf[self.offset + 3] & 0x20 != 0)
    }

    /// Key ID (bits 6-7 of byte 3).
    pub fn key_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() < self.offset + TKIP_HEADER_SHORT {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: TKIP_HEADER_SHORT,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok((buf[self.offset + 3] >> 6) & 0x03)
    }

    /// TSC2-TSC5 (bytes 4-7, only present if `ExtIV` is set).
    pub fn tsc_high(&self, buf: &[u8]) -> Result<[u8; 4], FieldError> {
        if buf.len() < self.offset + TKIP_HEADER_LONG {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 4,
                need: 4,
                have: buf.len().saturating_sub(self.offset + 4),
            });
        }
        Ok([
            buf[self.offset + 4],
            buf[self.offset + 5],
            buf[self.offset + 6],
            buf[self.offset + 7],
        ])
    }

    /// Full 48-bit TSC (TKIP Sequence Counter).
    /// TSC = TSC0 | (TSC1 << 8) | (TSC2 << 16) | (TSC3 << 24) | (TSC4 << 32) | (TSC5 << 40)
    pub fn tsc(&self, buf: &[u8]) -> Result<u64, FieldError> {
        let tsc0 = u64::from(self.tsc0(buf)?);
        let tsc1 = u64::from(self.tsc1(buf)?);
        let high = self.tsc_high(buf)?;
        let tsc2 = u64::from(high[0]);
        let tsc3 = u64::from(high[1]);
        let tsc4 = u64::from(high[2]);
        let tsc5 = u64::from(high[3]);
        Ok(tsc0 | (tsc1 << 8) | (tsc2 << 16) | (tsc3 << 24) | (tsc4 << 32) | (tsc5 << 40))
    }

    /// Header length: 4 bytes (no `ExtIV`) or 8 bytes (with `ExtIV`).
    #[must_use]
    pub fn header_len(&self, buf: &[u8]) -> usize {
        if self.ext_iv(buf).unwrap_or(false) {
            TKIP_HEADER_LONG
        } else {
            TKIP_HEADER_SHORT
        }
    }

    /// Trailer length (ICV = 4 bytes).
    #[must_use]
    pub fn trailer_len(&self) -> usize {
        TKIP_ICV_LEN
    }

    /// Build a TKIP header with Extended IV.
    #[must_use]
    pub fn build_header(tsc: u64, key_id: u8) -> Vec<u8> {
        let tsc0 = (tsc & 0xFF) as u8;
        let tsc1 = ((tsc >> 8) & 0xFF) as u8;
        let tsc2 = ((tsc >> 16) & 0xFF) as u8;
        let tsc3 = ((tsc >> 24) & 0xFF) as u8;
        let tsc4 = ((tsc >> 32) & 0xFF) as u8;
        let tsc5 = ((tsc >> 40) & 0xFF) as u8;
        // WEP Seed = (TSC1 | 0x20) & 0x7F (per 802.11i)
        let wep_seed = (tsc1 | 0x20) & 0x7F;
        let key_id_byte = ((key_id & 0x03) << 6) | 0x20; // ExtIV=1
        vec![tsc1, wep_seed, tsc0, key_id_byte, tsc2, tsc3, tsc4, tsc5]
    }
}

// ============================================================================
// CCMP Header/Trailer constants
// ============================================================================

/// CCMP header length: 8 bytes always.
pub const CCMP_HEADER_LEN: usize = 8;

/// CCMP trailer length: MIC(8) = 8 bytes.
pub const CCMP_MIC_LEN: usize = 8;

// ============================================================================
// Dot11CCMP
// ============================================================================

/// CCMP (Counter Mode CBC-MAC Protocol / AES-CCM) encryption wrapper.
///
/// Format:
/// ```text
/// [PN0(1)] [PN1(1)] [Rsvd(1)] [KeyID/ExtIV(1)] [PN2(1)] [PN3(1)] [PN4(1)] [PN5(1)]
/// [Encrypted Data ...]
/// [MIC (8 bytes)]
/// ```
///
/// The KeyID/ExtIV byte:
/// - Bits 0-4: Reserved
/// - Bit 5: `ExtIV` flag (always 1 for CCMP)
/// - Bits 6-7: Key ID
///
/// PN (Packet Number) is a 48-bit value constructed from PN0..PN5.
#[derive(Debug, Clone)]
pub struct Dot11CCMP {
    pub offset: usize,
}

impl Dot11CCMP {
    #[must_use]
    pub fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Validate buffer length for CCMP header.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + CCMP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: CCMP_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    /// PN0 (byte 0 of CCMP header).
    pub fn pn0(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset])
    }

    /// PN1 (byte 1 of CCMP header).
    pub fn pn1(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset + 1 {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 1,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset + 1])
    }

    /// Reserved byte (byte 2, should be 0).
    pub fn reserved(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() <= self.offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 2,
                need: 1,
                have: 0,
            });
        }
        Ok(buf[self.offset + 2])
    }

    /// Key ID (bits 6-7 of byte 3).
    pub fn key_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        if buf.len() < self.offset + CCMP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: CCMP_HEADER_LEN,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok((buf[self.offset + 3] >> 6) & 0x03)
    }

    /// `ExtIV` flag (bit 5 of byte 3, always 1 for CCMP).
    pub fn ext_iv(&self, buf: &[u8]) -> Result<bool, FieldError> {
        if buf.len() < self.offset + CCMP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset,
                need: CCMP_HEADER_LEN,
                have: buf.len().saturating_sub(self.offset),
            });
        }
        Ok(buf[self.offset + 3] & 0x20 != 0)
    }

    /// PN2-PN5 (bytes 4-7).
    pub fn pn_high(&self, buf: &[u8]) -> Result<[u8; 4], FieldError> {
        if buf.len() < self.offset + CCMP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.offset + 4,
                need: 4,
                have: buf.len().saturating_sub(self.offset + 4),
            });
        }
        Ok([
            buf[self.offset + 4],
            buf[self.offset + 5],
            buf[self.offset + 6],
            buf[self.offset + 7],
        ])
    }

    /// Full 48-bit Packet Number (PN).
    /// PN = PN0 | (PN1 << 8) | (PN2 << 16) | (PN3 << 24) | (PN4 << 32) | (PN5 << 40)
    pub fn pn(&self, buf: &[u8]) -> Result<u64, FieldError> {
        let pn0 = u64::from(self.pn0(buf)?);
        let pn1 = u64::from(self.pn1(buf)?);
        let high = self.pn_high(buf)?;
        let pn2 = u64::from(high[0]);
        let pn3 = u64::from(high[1]);
        let pn4 = u64::from(high[2]);
        let pn5 = u64::from(high[3]);
        Ok(pn0 | (pn1 << 8) | (pn2 << 16) | (pn3 << 24) | (pn4 << 32) | (pn5 << 40))
    }

    /// MIC (Message Integrity Code) — 8 bytes at the end of the encrypted data.
    pub fn mic(&self, buf: &[u8], frame_end: usize) -> Result<[u8; 8], FieldError> {
        if frame_end < CCMP_MIC_LEN || buf.len() < frame_end {
            return Err(FieldError::BufferTooShort {
                offset: frame_end.saturating_sub(CCMP_MIC_LEN),
                need: CCMP_MIC_LEN,
                have: 0,
            });
        }
        let off = frame_end - CCMP_MIC_LEN;
        let mut mic = [0u8; 8];
        mic.copy_from_slice(&buf[off..frame_end]);
        Ok(mic)
    }

    /// Header length (always 8 bytes for CCMP).
    #[must_use]
    pub fn header_len(&self) -> usize {
        CCMP_HEADER_LEN
    }

    /// Trailer length (MIC = 8 bytes).
    #[must_use]
    pub fn trailer_len(&self) -> usize {
        CCMP_MIC_LEN
    }

    /// Build a CCMP header.
    #[must_use]
    pub fn build_header(pn: u64, key_id: u8) -> Vec<u8> {
        let pn0 = (pn & 0xFF) as u8;
        let pn1 = ((pn >> 8) & 0xFF) as u8;
        let pn2 = ((pn >> 16) & 0xFF) as u8;
        let pn3 = ((pn >> 24) & 0xFF) as u8;
        let pn4 = ((pn >> 32) & 0xFF) as u8;
        let pn5 = ((pn >> 40) & 0xFF) as u8;
        let key_id_byte = ((key_id & 0x03) << 6) | 0x20; // ExtIV=1
        vec![pn0, pn1, 0x00, key_id_byte, pn2, pn3, pn4, pn5]
    }

    /// Build a CCMP MIC trailer (placeholder — actual MIC requires key material).
    #[must_use]
    pub fn build_mic(mic: [u8; 8]) -> Vec<u8> {
        mic.to_vec()
    }
}

// ============================================================================
// Helper: Detect security type from protected frame
// ============================================================================

/// Security protocol type detected from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    /// WEP (no `ExtIV` flag).
    WEP,
    /// TKIP (`ExtIV` flag set, WEP seed pattern).
    TKIP,
    /// CCMP (`ExtIV` flag set, reserved byte is 0).
    CCMP,
}

/// Detect the security type from the encryption header at the given offset.
///
/// This uses heuristics based on the `ExtIV` flag and the reserved byte:
/// - No `ExtIV` flag (bit 5 of byte 3 is 0) => WEP
/// - `ExtIV` flag set and byte 2 is 0 (reserved) => CCMP
/// - `ExtIV` flag set and byte 2 is non-zero => TKIP (WEP seed)
///
/// Note: This is a heuristic and may not always be correct. The actual
/// security type should be determined from the RSN/WPA IE in the beacon.
#[must_use]
pub fn detect_security_type(buf: &[u8], offset: usize) -> Option<SecurityType> {
    if buf.len() < offset + 4 {
        return None;
    }
    let ext_iv = buf[offset + 3] & 0x20 != 0;
    if !ext_iv {
        return Some(SecurityType::WEP);
    }
    // ExtIV is set — TKIP or CCMP
    // CCMP has a reserved byte (byte 2) = 0
    if buf[offset + 2] == 0 {
        Some(SecurityType::CCMP)
    } else {
        Some(SecurityType::TKIP)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wep_parse() {
        // IV: 0x01, 0x02, 0x03; KeyID: 1 (bits 6-7 = 01 => 0x40)
        let mut buf = vec![0x01, 0x02, 0x03, 0x40];
        // Add some encrypted data and ICV
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // encrypted
        buf.extend_from_slice(&0x12345678u32.to_le_bytes()); // ICV

        let wep = Dot11WEP::new(0);
        assert_eq!(wep.iv(&buf).unwrap(), [0x01, 0x02, 0x03]);
        assert_eq!(wep.key_id(&buf).unwrap(), 1);
        assert_eq!(wep.header_len(), 4);
        assert_eq!(wep.trailer_len(), 4);
        assert_eq!(wep.icv(&buf, buf.len()).unwrap(), 0x12345678);

        let encrypted = wep.encrypted_data(&buf, buf.len()).unwrap();
        assert_eq!(encrypted, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_wep_build() {
        let header = Dot11WEP::build_header([0x11, 0x22, 0x33], 2);
        assert_eq!(header, vec![0x11, 0x22, 0x33, 0x80]); // key_id=2 => bits 6-7 = 10 => 0x80

        let wep = Dot11WEP::new(0);
        assert_eq!(wep.iv(&header).unwrap(), [0x11, 0x22, 0x33]);
        assert_eq!(wep.key_id(&header).unwrap(), 2);

        let icv = Dot11WEP::build_icv(0xDEADBEEF);
        assert_eq!(icv, 0xDEADBEEFu32.to_le_bytes().to_vec());
    }

    #[test]
    fn test_wep_iv_u32() {
        let buf = vec![0x01, 0x02, 0x03, 0x00];
        let wep = Dot11WEP::new(0);
        assert_eq!(wep.iv_u32(&buf).unwrap(), 0x010203);
    }

    #[test]
    fn test_tkip_parse() {
        // TKIP header with ExtIV: TSC1=0x00, WEPSeed=0x20, TSC0=0x01, KeyID/ExtIV=0x20
        // TSC2-5: 0x02, 0x03, 0x04, 0x05
        let buf = vec![
            0x00, 0x20, 0x01, 0x20, // first 4 bytes
            0x02, 0x03, 0x04, 0x05, // TSC2-5
        ];

        let tkip = Dot11TKIP::new(0);
        assert!(tkip.ext_iv(&buf).unwrap());
        assert_eq!(tkip.key_id(&buf).unwrap(), 0);
        assert_eq!(tkip.tsc0(&buf).unwrap(), 0x01);
        assert_eq!(tkip.tsc1(&buf).unwrap(), 0x00);
        assert_eq!(tkip.wep_seed(&buf).unwrap(), 0x20);
        assert_eq!(tkip.tsc_high(&buf).unwrap(), [0x02, 0x03, 0x04, 0x05]);
        assert_eq!(tkip.header_len(&buf), 8);
        assert_eq!(tkip.trailer_len(), 4);

        // TSC = 0x01 | (0x00 << 8) | (0x02 << 16) | (0x03 << 24) | (0x04 << 32) | (0x05 << 40)
        let tsc = tkip.tsc(&buf).unwrap();
        assert_eq!(tsc & 0xFF, 0x01);
        assert_eq!((tsc >> 8) & 0xFF, 0x00);
        assert_eq!((tsc >> 16) & 0xFF, 0x02);
        assert_eq!((tsc >> 24) & 0xFF, 0x03);
        assert_eq!((tsc >> 32) & 0xFF, 0x04);
        assert_eq!((tsc >> 40) & 0xFF, 0x05);
    }

    #[test]
    fn test_tkip_build_roundtrip() {
        let tsc: u64 = 0x050403020001; // TSC0=01, TSC1=00, TSC2=02, TSC3=03, TSC4=04, TSC5=05
        let header = Dot11TKIP::build_header(tsc, 1);
        assert_eq!(header.len(), 8);

        let tkip = Dot11TKIP::new(0);
        assert!(tkip.ext_iv(&header).unwrap());
        assert_eq!(tkip.key_id(&header).unwrap(), 1);
        assert_eq!(tkip.tsc(&header).unwrap(), tsc);
    }

    #[test]
    fn test_ccmp_parse() {
        // CCMP header: PN0=0x01, PN1=0x02, Rsvd=0x00, KeyID/ExtIV=0x20
        // PN2-5: 0x03, 0x04, 0x05, 0x06
        let buf = vec![
            0x01, 0x02, 0x00, 0x20, // first 4 bytes
            0x03, 0x04, 0x05, 0x06, // PN2-5
        ];

        let ccmp = Dot11CCMP::new(0);
        assert_eq!(ccmp.pn0(&buf).unwrap(), 0x01);
        assert_eq!(ccmp.pn1(&buf).unwrap(), 0x02);
        assert_eq!(ccmp.reserved(&buf).unwrap(), 0x00);
        assert!(ccmp.ext_iv(&buf).unwrap());
        assert_eq!(ccmp.key_id(&buf).unwrap(), 0);
        assert_eq!(ccmp.pn_high(&buf).unwrap(), [0x03, 0x04, 0x05, 0x06]);
        assert_eq!(ccmp.header_len(), 8);
        assert_eq!(ccmp.trailer_len(), 8);

        let pn = ccmp.pn(&buf).unwrap();
        assert_eq!(pn & 0xFF, 0x01);
        assert_eq!((pn >> 8) & 0xFF, 0x02);
        assert_eq!((pn >> 16) & 0xFF, 0x03);
        assert_eq!((pn >> 24) & 0xFF, 0x04);
        assert_eq!((pn >> 32) & 0xFF, 0x05);
        assert_eq!((pn >> 40) & 0xFF, 0x06);
    }

    #[test]
    fn test_ccmp_build_roundtrip() {
        let pn: u64 = 0x060504030201;
        let header = Dot11CCMP::build_header(pn, 2);
        assert_eq!(header.len(), 8);

        let ccmp = Dot11CCMP::new(0);
        assert!(ccmp.ext_iv(&header).unwrap());
        assert_eq!(ccmp.key_id(&header).unwrap(), 2);
        assert_eq!(ccmp.pn(&header).unwrap(), pn);
    }

    #[test]
    fn test_ccmp_mic() {
        let mut buf = vec![0u8; 8]; // CCMP header
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // encrypted data
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // MIC

        let ccmp = Dot11CCMP::new(0);
        let mic = ccmp.mic(&buf, buf.len()).unwrap();
        assert_eq!(mic, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_detect_security_type() {
        // WEP: no ExtIV flag
        let wep_buf = vec![0x01, 0x02, 0x03, 0x00];
        assert_eq!(detect_security_type(&wep_buf, 0), Some(SecurityType::WEP));

        // CCMP: ExtIV set, reserved byte = 0
        let ccmp_buf = vec![0x01, 0x02, 0x00, 0x20];
        assert_eq!(detect_security_type(&ccmp_buf, 0), Some(SecurityType::CCMP));

        // TKIP: ExtIV set, byte 2 (WEP seed) non-zero
        let tkip_buf = vec![0x01, 0x20, 0x03, 0x20];
        assert_eq!(detect_security_type(&tkip_buf, 0), Some(SecurityType::TKIP));

        // Too short
        assert_eq!(detect_security_type(&[0x01, 0x02], 0), None);
    }

    #[test]
    fn test_wep_validate() {
        assert!(Dot11WEP::validate(&[0u8; 4], 0).is_ok());
        assert!(Dot11WEP::validate(&[0u8; 3], 0).is_err());
    }

    #[test]
    fn test_tkip_validate() {
        assert!(Dot11TKIP::validate(&[0u8; 4], 0).is_ok());
        assert!(Dot11TKIP::validate(&[0u8; 3], 0).is_err());
    }

    #[test]
    fn test_ccmp_validate() {
        assert!(Dot11CCMP::validate(&[0u8; 8], 0).is_ok());
        assert!(Dot11CCMP::validate(&[0u8; 7], 0).is_err());
    }
}
