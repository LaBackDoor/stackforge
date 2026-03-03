//! ICMP checksum calculation and verification.
//!
//! ICMP uses the Internet checksum (RFC 1071) over the entire ICMP message
//! (header + data), without a pseudo-header like TCP/UDP.

use crate::utils::internet_checksum;

/// Calculate ICMP checksum.
///
/// # Arguments
/// * `icmp_data` - Complete ICMP packet (header + payload)
///
/// # Returns
/// The calculated checksum.
///
/// # Note
/// Unlike TCP/UDP, ICMP does not use a pseudo-header. The checksum is
/// calculated over the entire ICMP message only.
#[must_use]
pub fn icmp_checksum(icmp_data: &[u8]) -> u16 {
    internet_checksum(icmp_data)
}

/// Verify ICMP checksum.
///
/// # Arguments
/// * `icmp_data` - Complete ICMP packet (header + payload) with checksum field
///
/// # Returns
/// `true` if the checksum is valid, `false` otherwise.
///
/// # Note
/// A valid checksum should result in 0 or 0xFFFF when the checksum is
/// computed over the entire message including the checksum field.
#[must_use]
pub fn verify_icmp_checksum(icmp_data: &[u8]) -> bool {
    if icmp_data.len() < 8 {
        return false;
    }

    let checksum = icmp_checksum(icmp_data);
    checksum == 0 || checksum == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum() {
        // ICMP echo request: type=8, code=0, checksum=0, id=1, seq=1
        let mut icmp_data = vec![
            0x08, // type = 8 (echo request)
            0x00, // code = 0
            0x00, 0x00, // checksum = 0 (to be calculated)
            0x00, 0x01, // id = 1
            0x00, 0x01, // seq = 1
        ];

        let checksum = icmp_checksum(&icmp_data);
        assert_ne!(checksum, 0);

        // Set the checksum
        icmp_data[2] = (checksum >> 8) as u8;
        icmp_data[3] = (checksum & 0xFF) as u8;

        // Verify the checksum
        assert!(verify_icmp_checksum(&icmp_data));
    }

    #[test]
    fn test_icmp_checksum_with_payload() {
        // ICMP echo request with payload
        let mut icmp_data = vec![
            0x08, // type = 8
            0x00, // code = 0
            0x00, 0x00, // checksum = 0
            0x12, 0x34, // id
            0x00, 0x01, // seq
            // Payload
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        ];

        let checksum = icmp_checksum(&icmp_data);
        icmp_data[2] = (checksum >> 8) as u8;
        icmp_data[3] = (checksum & 0xFF) as u8;

        assert!(verify_icmp_checksum(&icmp_data));
    }

    #[test]
    fn test_verify_icmp_checksum_invalid() {
        // ICMP with wrong checksum
        let icmp_data = vec![
            0x08, 0x00, // type, code
            0xFF, 0xFF, // wrong checksum
            0x00, 0x01, // id
            0x00, 0x01, // seq
        ];

        assert!(!verify_icmp_checksum(&icmp_data));
    }

    #[test]
    fn test_verify_icmp_checksum_too_short() {
        let icmp_data = vec![0x08, 0x00, 0x00]; // Too short
        assert!(!verify_icmp_checksum(&icmp_data));
    }
}
