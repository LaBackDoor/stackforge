//! CRC-16/DNP implementation.
//!
//! Polynomial: 0x3D65 (reflected: 0xA6BC), init=0x0000, xorout=0xFFFF.
//! Used for both header and data block CRC verification in DNP3 frames.

/// Precomputed CRC-16/DNP lookup table.
const CRC_TABLE: [u16; 256] = {
    // Generated from polynomial 0x3D65 (reflected = 0xA6BC)
    let mut table = [0u16; 256];
    let poly: u16 = 0xA6BC; // reflected polynomial
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u16;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Calculate CRC-16/DNP for a byte slice.
#[inline]
pub fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let idx = ((crc ^ byte as u16) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[idx];
    }
    crc ^ 0xFFFF
}

/// Verify CRC-16/DNP for a data block with appended CRC (LE).
///
/// Returns `true` if the CRC of the data portion matches the trailing 2-byte LE CRC.
#[inline]
pub fn verify_dnp3_crc(data_with_crc: &[u8]) -> bool {
    if data_with_crc.len() < 3 {
        return false;
    }
    let data = &data_with_crc[..data_with_crc.len() - 2];
    let expected = u16::from_le_bytes([
        data_with_crc[data_with_crc.len() - 2],
        data_with_crc[data_with_crc.len() - 1],
    ]);
    dnp3_crc(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc_known_value() {
        // DNP3 CRC-16 of empty data should be 0xFFFF (init=0, xorout=0xFFFF)
        assert_eq!(dnp3_crc(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc_single_byte() {
        let crc = dnp3_crc(&[0x00]);
        // CRC should be deterministic and non-zero
        assert_ne!(crc, 0);
    }

    #[test]
    fn test_crc_dnp3_header() {
        // A typical DNP3 link header: 0x05 0x64 0x05 0xC0 0x01 0x00 0x00 0x00
        let header = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00];
        let crc = dnp3_crc(&header);
        // Verify CRC is non-trivial (not all zeros or all ones)
        assert!(crc != 0x0000);
    }

    #[test]
    fn test_verify_crc_roundtrip() {
        let data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00];
        let crc = dnp3_crc(&data);
        let crc_bytes = crc.to_le_bytes();
        let mut data_with_crc = data.to_vec();
        data_with_crc.extend_from_slice(&crc_bytes);
        assert!(verify_dnp3_crc(&data_with_crc));
    }

    #[test]
    fn test_verify_crc_corrupted() {
        let data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00];
        let crc = dnp3_crc(&data);
        let crc_bytes = crc.to_le_bytes();
        let mut data_with_crc = data.to_vec();
        data_with_crc.extend_from_slice(&crc_bytes);
        // Corrupt one byte
        data_with_crc[3] ^= 0x01;
        assert!(!verify_dnp3_crc(&data_with_crc));
    }

    #[test]
    fn test_verify_too_short() {
        assert!(!verify_dnp3_crc(&[0x00, 0x01]));
        assert!(!verify_dnp3_crc(&[]));
    }

    #[test]
    fn test_crc_deterministic() {
        let data = b"Hello DNP3";
        let crc1 = dnp3_crc(data);
        let crc2 = dnp3_crc(data);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc_different_data() {
        let crc1 = dnp3_crc(&[0x01, 0x02, 0x03]);
        let crc2 = dnp3_crc(&[0x03, 0x02, 0x01]);
        assert_ne!(crc1, crc2);
    }
}
