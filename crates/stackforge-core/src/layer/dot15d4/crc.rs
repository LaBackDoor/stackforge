//! CRC-16 CCITT Kermit implementation for IEEE 802.15.4 FCS.
//!
//! The 802.15.4 standard uses CRC-16 CCITT with the Kermit polynomial (0x8408),
//! which is the bit-reversed form of the standard CCITT polynomial (0x1021).
//! Initial value is 0x0000, and the result is stored in little-endian byte order.

/// Compute CRC-16 CCITT Kermit checksum over the given data.
///
/// Algorithm from the Kermit Protocol Manual (June 1986).
/// Polynomial: 0x8408 (bit-reversed 0x1021)
/// Initial value: 0x0000
///
/// Returns the CRC as a u16 in native byte order.
pub fn crc_ccitt_kermit(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        let c = byte as u16;
        // Process low-order 4 bits
        let q = (crc ^ c) & 0x0F;
        crc = (crc >> 4) ^ (q * 4225);
        // Process high-order 4 bits
        let q = (crc ^ (c >> 4)) & 0x0F;
        crc = (crc >> 4) ^ (q * 4225);
    }
    crc
}

/// Compute the FCS bytes (2 bytes, little-endian) for the given data.
pub fn compute_fcs(data: &[u8]) -> [u8; 2] {
    crc_ccitt_kermit(data).to_le_bytes()
}

/// Verify the FCS of a frame.
///
/// `data` is the frame data (without FCS), and `expected_fcs` is the
/// 2-byte FCS value read from the frame (already in native u16 order).
pub fn verify_fcs(data: &[u8], expected_fcs: u16) -> bool {
    crc_ccitt_kermit(data) == expected_fcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc_empty() {
        assert_eq!(crc_ccitt_kermit(&[]), 0x0000);
    }

    #[test]
    fn test_crc_known_value() {
        // Known test vector: "123456789" should produce 0x2189 for Kermit CRC
        let data = b"123456789";
        assert_eq!(crc_ccitt_kermit(data), 0x2189);
    }

    #[test]
    fn test_compute_fcs_le_bytes() {
        let data = b"123456789";
        let fcs = compute_fcs(data);
        // 0x2189 in little-endian is [0x89, 0x21]
        assert_eq!(fcs, [0x89, 0x21]);
    }

    #[test]
    fn test_verify_fcs() {
        let data = b"123456789";
        assert!(verify_fcs(data, 0x2189));
        assert!(!verify_fcs(data, 0x0000));
    }

    #[test]
    fn test_crc_single_byte() {
        // Single byte 0x00
        let crc = crc_ccitt_kermit(&[0x00]);
        assert_eq!(crc, 0x0000);
    }

    #[test]
    fn test_crc_802154_beacon_frame() {
        // A minimal 802.15.4 beacon frame (FCF + seqnum = 3 bytes)
        // FCF: 0x0000 (beacon, no addressing), seqnum: 0x01
        let data = [0x00, 0x00, 0x01];
        let crc = crc_ccitt_kermit(&data);
        let fcs_bytes = compute_fcs(&data);
        // Verify round-trip
        assert!(verify_fcs(&data, crc));
        assert_eq!(fcs_bytes, crc.to_le_bytes());
    }

    #[test]
    fn test_crc_deterministic() {
        let data = [0x41, 0x88, 0x05, 0xFF, 0xFF, 0x34, 0x12];
        let crc1 = crc_ccitt_kermit(&data);
        let crc2 = crc_ccitt_kermit(&data);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_verify_fcs_wrong_data() {
        let data1 = [0x01, 0x02, 0x03];
        let crc = crc_ccitt_kermit(&data1);
        let data2 = [0x01, 0x02, 0x04]; // different
        assert!(!verify_fcs(&data2, crc));
    }
}
