//! UDP checksum calculation and verification.
//!
//! UDP uses the same pseudo-header as TCP for checksum calculation.
//! For IPv4, the checksum is optional (can be 0), but for IPv6 it's mandatory.
//! Per RFC 768, if the computed checksum is 0, it should be set to 0xFFFF.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::utils::{finalize_checksum, partial_checksum};

/// UDP protocol number.
const UDP_PROTOCOL: u8 = 17;

/// Calculate UDP checksum with IPv4 pseudo-header.
///
/// # Arguments
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `udp_data` - Complete UDP packet (header + payload)
///
/// # Returns
/// The calculated checksum. Per RFC 768, if result is 0, returns 0xFFFF.
pub fn udp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Add IPv4 pseudo-header
    // Source IP (4 bytes)
    for chunk in src_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Destination IP (4 bytes)
    for chunk in dst_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Zero + Protocol (2 bytes): 0x00 (zero) + 0x11 (UDP) = 0x0011 as u16
    sum += UDP_PROTOCOL as u32;

    // UDP Length (2 bytes)
    sum += udp_data.len() as u32;

    // Add UDP data
    sum = partial_checksum(udp_data, sum);

    let checksum = finalize_checksum(sum);

    // RFC 768: If computed checksum is 0, use 0xFFFF
    if checksum == 0 { 0xFFFF } else { checksum }
}

/// Calculate UDP checksum with IPv6 pseudo-header.
///
/// # Arguments
/// * `src_ip` - Source IPv6 address
/// * `dst_ip` - Destination IPv6 address
/// * `udp_data` - Complete UDP packet (header + payload)
///
/// # Returns
/// The calculated checksum. Per RFC 2460, if result is 0, returns 0xFFFF.
pub fn udp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, udp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Add IPv6 pseudo-header
    // Source IP (16 bytes)
    for chunk in src_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Destination IP (16 bytes)
    for chunk in dst_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // UDP Length (4 bytes, big-endian)
    let udp_len = udp_data.len() as u32;
    sum += (udp_len >> 16) as u32;
    sum += (udp_len & 0xFFFF) as u32;

    // Three zero bytes + Next Header (4 bytes total)
    sum += UDP_PROTOCOL as u32;

    // Add UDP data
    sum = partial_checksum(udp_data, sum);

    let checksum = finalize_checksum(sum);

    // RFC 2460: If computed checksum is 0, use 0xFFFF
    if checksum == 0 { 0xFFFF } else { checksum }
}

/// Verify UDP checksum with IPv4 pseudo-header.
pub fn verify_udp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_data: &[u8]) -> bool {
    if udp_data.len() < 8 {
        return false;
    }

    // Check if checksum is 0 (optional for IPv4)
    let stored_checksum = u16::from_be_bytes([udp_data[6], udp_data[7]]);
    if stored_checksum == 0 {
        return true; // No checksum provided, considered valid
    }

    let calculated = udp_checksum_ipv4(src_ip, dst_ip, udp_data);

    // The checksum should be 0xFFFF when calculated over data with valid checksum
    calculated == 0xFFFF || calculated == stored_checksum
}

/// Verify UDP checksum with IPv6 pseudo-header.
pub fn verify_udp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, udp_data: &[u8]) -> bool {
    if udp_data.len() < 8 {
        return false;
    }

    let stored_checksum = u16::from_be_bytes([udp_data[6], udp_data[7]]);

    // For IPv6, checksum is mandatory (cannot be 0)
    if stored_checksum == 0 {
        return false;
    }

    let calculated = udp_checksum_ipv6(src_ip, dst_ip, udp_data);

    // The checksum should be 0xFFFF when calculated over data with valid checksum
    calculated == 0xFFFF || calculated == stored_checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_checksum_ipv4() {
        // Create a simple UDP packet
        let mut udp_data = vec![
            0x04, 0xd2, // sport = 1234
            0x00, 0x35, // dport = 53
            0x00, 0x0c, // length = 12
            0x00, 0x00, // checksum = 0 (to be calculated)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let checksum = udp_checksum_ipv4(src_ip, dst_ip, &udp_data);

        // Set the checksum in the packet
        udp_data[6] = (checksum >> 8) as u8;
        udp_data[7] = (checksum & 0xFF) as u8;

        // Verify the checksum
        assert!(verify_udp_checksum_ipv4(src_ip, dst_ip, &udp_data));
    }

    #[test]
    fn test_udp_checksum_ipv4_zero() {
        // Test that computed checksum of 0 becomes 0xFFFF
        // This is a contrived example; in practice, getting a 0 checksum is rare
        let udp_data = vec![
            0x00, 0x00, // sport
            0x00, 0x00, // dport
            0x00, 0x08, // length = 8 (header only)
            0x00, 0x00, // checksum placeholder
        ];

        let src_ip: Ipv4Addr = "0.0.0.0".parse().unwrap();
        let dst_ip: Ipv4Addr = "0.0.0.0".parse().unwrap();

        let checksum = udp_checksum_ipv4(src_ip, dst_ip, &udp_data);

        // The checksum should be 0xFFFF if raw calculation was 0
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_udp_checksum_ipv6() {
        let mut udp_data = vec![
            0x04, 0xd2, // sport = 1234
            0x00, 0x35, // dport = 53
            0x00, 0x0c, // length = 12
            0x00, 0x00, // checksum = 0 (to be calculated)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let checksum = udp_checksum_ipv6(src_ip, dst_ip, &udp_data);

        // Checksum should not be 0 for IPv6
        assert_ne!(checksum, 0);

        // Set the checksum in the packet
        udp_data[6] = (checksum >> 8) as u8;
        udp_data[7] = (checksum & 0xFF) as u8;

        // Verify the checksum
        assert!(verify_udp_checksum_ipv6(src_ip, dst_ip, &udp_data));
    }

    #[test]
    fn test_verify_udp_checksum_ipv4_optional() {
        // IPv4 UDP checksum is optional; 0 means no checksum
        let udp_data = vec![
            0x04, 0xd2, // sport = 1234
            0x00, 0x35, // dport = 53
            0x00, 0x08, // length = 8
            0x00, 0x00, // checksum = 0 (no checksum)
        ];

        let src_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Should be valid even with 0 checksum
        assert!(verify_udp_checksum_ipv4(src_ip, dst_ip, &udp_data));
    }

    #[test]
    fn test_verify_udp_checksum_ipv6_mandatory() {
        // IPv6 UDP checksum is mandatory; 0 is invalid
        let udp_data = vec![
            0x04, 0xd2, // sport = 1234
            0x00, 0x35, // dport = 53
            0x00, 0x08, // length = 8
            0x00, 0x00, // checksum = 0 (invalid for IPv6)
        ];

        let src_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst_ip: Ipv6Addr = "2001:db8::2".parse().unwrap();

        // Should be invalid with 0 checksum
        assert!(!verify_udp_checksum_ipv6(src_ip, dst_ip, &udp_data));
    }
}
