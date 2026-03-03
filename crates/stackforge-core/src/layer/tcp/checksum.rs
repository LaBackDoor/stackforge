//! TCP checksum calculation.
//!
//! TCP uses the Internet checksum (RFC 1071) computed over a pseudo-header
//! followed by the TCP header and payload.
//!
//! # IPv4 Pseudo-header
//!
//! ```text
//! +--------+--------+--------+--------+
//! |           Source Address          |
//! +--------+--------+--------+--------+
//! |         Destination Address       |
//! +--------+--------+--------+--------+
//! |  zero  |  PTCL  |    TCP Length   |
//! +--------+--------+--------+--------+
//! ```
//!
//! # IPv6 Pseudo-header
//!
//! ```text
//! +--------+--------+--------+--------+
//! |                                   |
//! +                                   +
//! |           Source Address          |
//! +                                   +
//! |                                   |
//! +                                   +
//! |                                   |
//! +--------+--------+--------+--------+
//! |                                   |
//! +                                   +
//! |         Destination Address       |
//! +                                   +
//! |                                   |
//! +                                   +
//! |                                   |
//! +--------+--------+--------+--------+
//! |         Upper-Layer Packet Length |
//! +--------+--------+--------+--------+
//! |           zero          |Next Hdr|
//! +--------+--------+--------+--------+
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::layer::ipv4::checksum::{pseudo_header_checksum, transport_checksum};
use crate::utils::{finalize_checksum, partial_checksum};

/// TCP protocol number for pseudo-header.
pub const TCP_PROTOCOL: u8 = 6;

/// Compute TCP checksum with IPv4 pseudo-header.
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// The computed checksum value.
#[must_use]
pub fn tcp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    transport_checksum(&src_ip.octets(), &dst_ip.octets(), TCP_PROTOCOL, tcp_data)
}

/// Compute TCP checksum with IPv6 pseudo-header.
///
/// # Arguments
///
/// * `src_ip` - Source IPv6 address
/// * `dst_ip` - Destination IPv6 address
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// The computed checksum value.
#[must_use]
pub fn tcp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_data: &[u8]) -> u16 {
    let tcp_len = tcp_data.len() as u32;

    // IPv6 pseudo-header checksum
    let mut sum: u32 = 0;

    // Source address (16 bytes)
    let src_octets = src_ip.octets();
    for chunk in src_octets.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // Destination address (16 bytes)
    let dst_octets = dst_ip.octets();
    for chunk in dst_octets.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // Upper-layer packet length (4 bytes)
    sum += (tcp_len >> 16) & 0xFFFF;
    sum += tcp_len & 0xFFFF;

    // Zero + Next Header (4 bytes, but only last byte is non-zero)
    sum += u32::from(TCP_PROTOCOL);

    // Add TCP data
    sum = partial_checksum(tcp_data, sum);

    // Finalize
    finalize_checksum(sum)
}

/// Compute TCP checksum (generic version).
///
/// Automatically handles IPv4 or IPv6 based on address type.
/// Uses raw byte slices for maximum flexibility.
///
/// # Arguments
///
/// * `src_ip` - Source IP address bytes (4 for IPv4, 16 for IPv6)
/// * `dst_ip` - Destination IP address bytes
/// * `tcp_data` - Complete TCP segment (header + payload)
///
/// # Returns
///
/// The computed checksum value, or None if address lengths are invalid.
#[must_use]
pub fn tcp_checksum(src_ip: &[u8], dst_ip: &[u8], tcp_data: &[u8]) -> Option<u16> {
    match (src_ip.len(), dst_ip.len()) {
        (4, 4) => {
            let src: [u8; 4] = src_ip.try_into().ok()?;
            let dst: [u8; 4] = dst_ip.try_into().ok()?;
            Some(transport_checksum(&src, &dst, TCP_PROTOCOL, tcp_data))
        },
        (16, 16) => {
            let src: [u8; 16] = src_ip.try_into().ok()?;
            let dst: [u8; 16] = dst_ip.try_into().ok()?;
            Some(tcp_checksum_ipv6(
                Ipv6Addr::from(src),
                Ipv6Addr::from(dst),
                tcp_data,
            ))
        },
        _ => None,
    }
}

/// Verify TCP checksum with IPv4 pseudo-header.
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_data` - Complete TCP segment (header + payload) with checksum
///
/// # Returns
///
/// `true` if the checksum is valid.
#[must_use]
pub fn verify_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> bool {
    if tcp_data.len() < 20 {
        return false;
    }

    let checksum = tcp_checksum_ipv4(src_ip, dst_ip, tcp_data);
    checksum == 0 || checksum == 0xFFFF
}

/// Verify TCP checksum with IPv6 pseudo-header.
#[must_use]
pub fn verify_tcp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_data: &[u8]) -> bool {
    if tcp_data.len() < 20 {
        return false;
    }

    let checksum = tcp_checksum_ipv6(src_ip, dst_ip, tcp_data);
    checksum == 0 || checksum == 0xFFFF
}

/// Build the IPv4 pseudo-header bytes for TCP.
///
/// # Arguments
///
/// * `src_ip` - Source IPv4 address
/// * `dst_ip` - Destination IPv4 address
/// * `tcp_len` - Length of TCP segment (header + payload)
///
/// # Returns
///
/// 12-byte pseudo-header.
#[must_use]
pub fn ipv4_pseudo_header(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_len: u16) -> [u8; 12] {
    let mut header = [0u8; 12];

    // Source IP (4 bytes)
    header[0..4].copy_from_slice(&src_ip.octets());

    // Destination IP (4 bytes)
    header[4..8].copy_from_slice(&dst_ip.octets());

    // Zero (1 byte)
    header[8] = 0;

    // Protocol (1 byte)
    header[9] = TCP_PROTOCOL;

    // TCP Length (2 bytes)
    header[10..12].copy_from_slice(&tcp_len.to_be_bytes());

    header
}

/// Build the IPv6 pseudo-header bytes for TCP.
///
/// # Arguments
///
/// * `src_ip` - Source IPv6 address
/// * `dst_ip` - Destination IPv6 address
/// * `tcp_len` - Length of TCP segment (header + payload)
///
/// # Returns
///
/// 40-byte pseudo-header.
#[must_use]
pub fn ipv6_pseudo_header(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_len: u32) -> [u8; 40] {
    let mut header = [0u8; 40];

    // Source IP (16 bytes)
    header[0..16].copy_from_slice(&src_ip.octets());

    // Destination IP (16 bytes)
    header[16..32].copy_from_slice(&dst_ip.octets());

    // Upper-Layer Packet Length (4 bytes)
    header[32..36].copy_from_slice(&tcp_len.to_be_bytes());

    // Zero (3 bytes) + Next Header (1 byte)
    header[36] = 0;
    header[37] = 0;
    header[38] = 0;
    header[39] = TCP_PROTOCOL;

    header
}

/// Compute checksum for partial data (for segmented computation).
///
/// Useful when computing checksum across multiple buffers.
#[must_use]
pub fn tcp_partial_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_len: u16) -> u32 {
    pseudo_header_checksum(src_ip, dst_ip, TCP_PROTOCOL, tcp_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_checksum_ipv4() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        // Minimal TCP header with zeroed checksum
        let tcp_header = [
            0x00, 0x50, // Source port: 80
            0x1F, 0x90, // Dest port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, // Data offset + flags (SYN)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum (zeroed)
            0x00, 0x00, // Urgent pointer
        ];

        let checksum = tcp_checksum_ipv4(src_ip, dst_ip, &tcp_header);
        assert_ne!(checksum, 0);

        // Insert checksum and verify
        let mut tcp_with_checksum = tcp_header;
        tcp_with_checksum[16] = (checksum >> 8) as u8;
        tcp_with_checksum[17] = (checksum & 0xFF) as u8;

        assert!(verify_tcp_checksum(src_ip, dst_ip, &tcp_with_checksum));
    }

    #[test]
    fn test_tcp_checksum_ipv6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Minimal TCP header with zeroed checksum
        let tcp_header = [
            0x00, 0x50, // Source port: 80
            0x1F, 0x90, // Dest port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, // Data offset + flags (SYN)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum (zeroed)
            0x00, 0x00, // Urgent pointer
        ];

        let checksum = tcp_checksum_ipv6(src_ip, dst_ip, &tcp_header);
        assert_ne!(checksum, 0);

        // Insert checksum and verify
        let mut tcp_with_checksum = tcp_header;
        tcp_with_checksum[16] = (checksum >> 8) as u8;
        tcp_with_checksum[17] = (checksum & 0xFF) as u8;

        assert!(verify_tcp_checksum_ipv6(src_ip, dst_ip, &tcp_with_checksum));
    }

    #[test]
    fn test_tcp_checksum_generic() {
        let src_ipv4 = [192, 168, 1, 1];
        let dst_ipv4 = [192, 168, 1, 2];

        let tcp_header = [
            0x00, 0x50, // Source port: 80
            0x1F, 0x90, // Dest port: 8080
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, // Data offset + flags (SYN)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum (zeroed)
            0x00, 0x00, // Urgent pointer
        ];

        let checksum = tcp_checksum(&src_ipv4, &dst_ipv4, &tcp_header);
        assert!(checksum.is_some());

        let checksum_direct = tcp_checksum_ipv4(
            Ipv4Addr::from(src_ipv4),
            Ipv4Addr::from(dst_ipv4),
            &tcp_header,
        );
        assert_eq!(checksum.unwrap(), checksum_direct);
    }

    #[test]
    fn test_pseudo_header() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let tcp_len = 20u16;

        let header = ipv4_pseudo_header(src_ip, dst_ip, tcp_len);

        assert_eq!(&header[0..4], &[192, 168, 1, 1]);
        assert_eq!(&header[4..8], &[192, 168, 1, 2]);
        assert_eq!(header[8], 0);
        assert_eq!(header[9], TCP_PROTOCOL);
        assert_eq!(&header[10..12], &[0, 20]);
    }

    #[test]
    fn test_invalid_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        // TCP header with bad checksum
        let tcp_header = [
            0x00, 0x50, 0x1F, 0x90, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0xFF, 0xFF, 0xFF, 0xFF, // Bad checksum
            0x00, 0x00,
        ];

        assert!(!verify_tcp_checksum(src_ip, dst_ip, &tcp_header));
    }

    #[test]
    fn test_checksum_with_payload() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

        // TCP header + "Hello" payload
        let mut tcp_segment = vec![
            0x00, 0x50, // Source port: 80
            0x00, 0x51, // Dest port: 81
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x01, // Ack number
            0x50, 0x18, // Data offset + flags (PSH+ACK)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum (zeroed)
            0x00, 0x00, // Urgent pointer
        ];
        tcp_segment.extend_from_slice(b"Hello");

        let checksum = tcp_checksum_ipv4(src_ip, dst_ip, &tcp_segment);
        tcp_segment[16] = (checksum >> 8) as u8;
        tcp_segment[17] = (checksum & 0xFF) as u8;

        assert!(verify_tcp_checksum(src_ip, dst_ip, &tcp_segment));
    }
}
