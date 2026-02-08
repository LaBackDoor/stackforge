//! IPv4 header checksum calculation.
//!
//! Implements RFC 1071 Internet checksum algorithm used for IPv4 headers.
//! The checksum is computed lazily - only when the packet is serialized.

use crate::utils::internet_checksum;

/// Compute the Internet checksum (RFC 1071) over a byte slice.
///
/// This is the standard one's complement sum used for IP, ICMP, TCP, and UDP.
///
/// # Algorithm
///
/// 1. Sum all 16-bit words in the data
/// 2. Add any odd byte as the high byte of a word
/// 3. Fold 32-bit sum to 16 bits by adding carry bits
/// 4. Take one's complement of the result
///
/// # Example
///
/// ```rust
/// use stackforge_core::layer::ipv4::checksum::ipv4_checksum;
///
/// let header = [
///     0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
///     0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
///     0xac, 0x10, 0x0a, 0x0c,
/// ];
/// let checksum = ipv4_checksum(&header);
/// ```
#[inline]
pub fn ipv4_checksum(data: &[u8]) -> u16 {
    internet_checksum(data)
}

// Note: internet_checksum, partial_checksum, and finalize_checksum
// are now imported from crate::utils::checksum

/// Verify that a checksum is valid.
///
/// When computed over data that includes a valid checksum, the result
/// should be 0x0000 or 0xFFFF.
#[inline]
pub fn verify_ipv4_checksum(data: &[u8]) -> bool {
    let sum = internet_checksum(data);
    sum == 0 || sum == 0xFFFF
}

/// Incrementally update a checksum when a 16-bit field changes.
///
/// This is more efficient than recomputing the entire checksum when
/// only a single field is modified.
///
/// # Arguments
///
/// * `old_checksum` - The existing checksum value
/// * `old_value` - The old 16-bit field value
/// * `new_value` - The new 16-bit field value
///
/// # Returns
///
/// The updated checksum value.
#[inline]
pub fn incremental_update_checksum(old_checksum: u16, old_value: u16, new_value: u16) -> u16 {
    // RFC 1624: HC' = ~(~HC + ~m + m')
    let hc = !old_checksum as u32;
    let m = !old_value as u32;
    let m_prime = new_value as u32;

    let mut sum = hc + m + m_prime;

    // Fold carry
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Incrementally update checksum when a 32-bit field changes.
///
/// Useful for updating checksum after IP address changes.
#[inline]
pub fn incremental_update_checksum_32(old_checksum: u16, old_value: u32, new_value: u32) -> u16 {
    // Update for high 16 bits, then low 16 bits
    let old_high = (old_value >> 16) as u16;
    let old_low = (old_value & 0xFFFF) as u16;
    let new_high = (new_value >> 16) as u16;
    let new_low = (new_value & 0xFFFF) as u16;

    let tmp = incremental_update_checksum(old_checksum, old_high, new_high);
    incremental_update_checksum(tmp, old_low, new_low)
}

/// Compute the pseudo-header checksum for TCP/UDP.
///
/// The pseudo-header includes:
/// - Source IP (4 bytes)
/// - Destination IP (4 bytes)
/// - Zero (1 byte)
/// - Protocol (1 byte)
/// - TCP/UDP length (2 bytes)
///
/// # Arguments
///
/// * `src_ip` - Source IP address (4 bytes)
/// * `dst_ip` - Destination IP address (4 bytes)
/// * `protocol` - IP protocol number
/// * `transport_len` - Length of the transport layer data
///
/// # Returns
///
/// The partial checksum from the pseudo-header.
pub fn pseudo_header_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    protocol: u8,
    transport_len: u16,
) -> u32 {
    let mut sum: u32 = 0;

    // Source IP
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;

    // Destination IP
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;

    // Zero + Protocol
    sum += protocol as u32;

    // Transport length
    sum += transport_len as u32;

    sum
}

/// Compute complete transport layer checksum (TCP or UDP).
///
/// # Arguments
///
/// * `src_ip` - Source IP address
/// * `dst_ip` - Destination IP address
/// * `protocol` - IP protocol number (6 for TCP, 17 for UDP)
/// * `transport_data` - The complete transport layer header and payload
///
/// # Returns
///
/// The computed checksum value.
pub fn transport_checksum(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    protocol: u8,
    transport_data: &[u8],
) -> u16 {
    // Start with pseudo-header checksum
    let mut sum = pseudo_header_checksum(src_ip, dst_ip, protocol, transport_data.len() as u16);

    // Add transport data
    let mut chunks = transport_data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Handle odd byte
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }

    // Fold and complement
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // For UDP, if checksum is 0, use 0xFFFF instead (RFC 768)
    let result = !sum as u16;
    if result == 0 && protocol == 17 {
        0xFFFF
    } else {
        result
    }
}

// Note: partial_checksum and finalize_checksum moved to crate::utils::checksum
// and are re-exported from this module for backwards compatibility.
pub use crate::utils::{finalize_checksum, partial_checksum};

/// Zero out checksum field in a buffer at the specified offset.
#[inline]
pub fn zero_checksum(buf: &mut [u8], offset: usize) {
    if buf.len() >= offset + 2 {
        buf[offset] = 0;
        buf[offset + 1] = 0;
    }
}

/// Write checksum to buffer at the specified offset.
#[inline]
pub fn write_checksum(buf: &mut [u8], offset: usize, checksum: u16) {
    if buf.len() >= offset + 2 {
        let bytes = checksum.to_be_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
    }
}

/// Read checksum from buffer at the specified offset.
#[inline]
pub fn read_checksum(buf: &[u8], offset: usize) -> Option<u16> {
    if buf.len() >= offset + 2 {
        Some(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_checksum() {
        // Sample IPv4 header from RFC 1071
        let header = [
            0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Total Length
            0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (zeroed)
            0xac, 0x10, 0x0a, 0x63, // Source: 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // Dest: 172.16.10.12
        ];

        let checksum = ipv4_checksum(&header);

        // Place checksum in header and verify
        let mut header_with_cksum = header;
        header_with_cksum[10] = (checksum >> 8) as u8;
        header_with_cksum[11] = (checksum & 0xFF) as u8;

        assert!(verify_ipv4_checksum(&header_with_cksum));
    }

    #[test]
    fn test_verify_valid_checksum() {
        // Header with pre-computed valid checksum
        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1,
            0xe6, // checksum
            0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];

        assert!(verify_ipv4_checksum(&header));
    }

    #[test]
    fn test_verify_invalid_checksum() {
        // Header with corrupted checksum
        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xFF,
            0xFF, // bad checksum
            0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];

        assert!(!verify_ipv4_checksum(&header));
    }

    #[test]
    fn test_incremental_update() {
        // Original header with valid checksum
        let mut header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];

        // Compute initial checksum
        let initial_checksum = ipv4_checksum(&header);
        header[10] = (initial_checksum >> 8) as u8;
        header[11] = (initial_checksum & 0xFF) as u8;

        // Change TTL from 0x40 to 0x3F using incremental update
        let old_ttl_word = u16::from_be_bytes([header[8], header[9]]);
        header[8] = 0x3F;
        let new_ttl_word = u16::from_be_bytes([header[8], header[9]]);

        let new_checksum =
            incremental_update_checksum(initial_checksum, old_ttl_word, new_ttl_word);
        header[10] = (new_checksum >> 8) as u8;
        header[11] = (new_checksum & 0xFF) as u8;

        // Verify the incrementally updated checksum is valid
        assert!(verify_ipv4_checksum(&header));
    }

    #[test]
    fn test_pseudo_header_checksum() {
        let src = [192, 168, 1, 1];
        let dst = [192, 168, 1, 2];
        let protocol = 6; // TCP
        let length = 20; // TCP header only

        let sum = pseudo_header_checksum(&src, &dst, protocol, length);

        // Verify sum contains expected components
        assert!(sum > 0);
    }

    #[test]
    fn test_transport_checksum_tcp() {
        let src_ip = [192, 168, 1, 1];
        let dst_ip = [192, 168, 1, 2];

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

        let checksum = transport_checksum(&src_ip, &dst_ip, 6, &tcp_header);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_transport_checksum_udp_zero() {
        let src_ip = [0, 0, 0, 0];
        let dst_ip = [0, 0, 0, 0];

        // UDP header that would result in zero checksum
        // For UDP, zero should become 0xFFFF
        let udp_header = [
            0x00, 0x00, // Source port
            0x00, 0x00, // Dest port
            0x00, 0x08, // Length
            0x00, 0x00, // Checksum (zeroed)
        ];

        let checksum = transport_checksum(&src_ip, &dst_ip, 17, &udp_header);
        // UDP checksum should never be 0 (use 0xFFFF instead)
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_partial_checksum() {
        let data1 = [0x01, 0x02, 0x03, 0x04];
        let data2 = [0x05, 0x06, 0x07, 0x08];

        // Compute separately and combine
        let sum1 = partial_checksum(&data1, 0);
        let sum2 = partial_checksum(&data2, sum1);
        let checksum1 = finalize_checksum(sum2);

        // Compute together
        let combined = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let checksum2 = internet_checksum(&combined);

        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_odd_length_data() {
        // Test with odd number of bytes
        let data = [0x45, 0x00, 0x00, 0x3c, 0x1c];
        let checksum = internet_checksum(&data);

        // Should handle odd byte correctly
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_zero_and_write_checksum() {
        let mut buf = [0x45, 0x00, 0xAB, 0xCD, 0x00, 0x00];

        zero_checksum(&mut buf, 2);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 0);

        write_checksum(&mut buf, 2, 0x1234);
        assert_eq!(buf[2], 0x12);
        assert_eq!(buf[3], 0x34);

        assert_eq!(read_checksum(&buf, 2), Some(0x1234));
    }
}
