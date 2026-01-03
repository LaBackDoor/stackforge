//! Utility functions for packet manipulation.
//!
//! This module provides helper functions like hexdump, checksum calculation,
//! and other common operations used in network programming.

#[cfg(feature = "rand")]
use rand::Rng;
use std::fmt::Write;

/// Generate a hexdump of bytes in the style of `xxd` or Scapy's hexdump.
///
/// # Example
/// ```
/// use stackforge_core::utils::hexdump;
/// let data = b"Hello, World!";
/// println!("{}", hexdump(data));
/// ```
pub fn hexdump(data: &[u8]) -> String {
    let mut output = String::new();
    let mut offset = 0;

    for chunk in data.chunks(16) {
        // Offset
        write!(output, "{:08x}  ", offset).unwrap();

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' ');
            }
            write!(output, "{:02x} ", byte).unwrap();
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            for i in chunk.len()..16 {
                if i == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
        }

        // ASCII representation
        output.push(' ');
        output.push('|');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('|');
        output.push('\n');

        offset += 16;
    }

    output
}

/// Generate a compact hex string representation.
pub fn hexstr(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(output, "{:02x}", byte).unwrap();
    }
    output
}

/// Generate hex string with separator.
pub fn hexstr_sep(data: &[u8], sep: &str) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(sep)
}

/// Parse a hex string into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().replace(" ", "").replace(":", "").replace("-", "");

    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i, e))
        })
        .collect()
}

/// Calculate the Internet checksum (RFC 1071).
///
/// This is used for IP, ICMP, TCP, and UDP checksums.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Process 16-bit words
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Handle odd byte
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate checksum with pseudo-header (for TCP/UDP).
pub fn transport_checksum(src_ip: &[u8], dst_ip: &[u8], protocol: u8, data: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + data.len());

    // Source IP
    pseudo_header.extend_from_slice(src_ip);
    // Destination IP
    pseudo_header.extend_from_slice(dst_ip);
    // Zero
    pseudo_header.push(0);
    // Protocol
    pseudo_header.push(protocol);
    // Length (big-endian)
    let len = data.len() as u16;
    pseudo_header.extend_from_slice(&len.to_be_bytes());
    // Data
    pseudo_header.extend_from_slice(data);

    internet_checksum(&pseudo_header)
}

/// Verify a checksum is valid (should be 0 or 0xFFFF when calculated over data with checksum).
pub fn verify_checksum(data: &[u8]) -> bool {
    let sum = internet_checksum(data);
    sum == 0 || sum == 0xFFFF
}

/// Convert bytes to a pretty-printed representation (like Scapy's show()).
pub fn pretty_bytes(data: &[u8], indent: usize) -> String {
    let indent_str = " ".repeat(indent);
    let mut output = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        if i > 0 {
            output.push('\n');
        }
        output.push_str(&indent_str);

        for byte in chunk {
            write!(output, "{:02x} ", byte).unwrap();
        }
    }

    output
}

/// Compare two byte slices and return the first differing index.
pub fn find_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let min_len = a.len().min(b.len());

    for i in 0..min_len {
        if a[i] != b[i] {
            return Some(i);
        }
    }

    if a.len() != b.len() {
        Some(min_len)
    } else {
        None
    }
}

/// Generate a diff between two byte slices.
pub fn byte_diff(a: &[u8], b: &[u8]) -> String {
    let mut output = String::new();
    let max_len = a.len().max(b.len());

    writeln!(output, "Comparing {} bytes vs {} bytes", a.len(), b.len()).unwrap();

    for i in 0..max_len {
        let byte_a = a.get(i).copied();
        let byte_b = b.get(i).copied();

        if byte_a != byte_b {
            let a_str = byte_a
                .map(|b| format!("{:02x}", b))
                .unwrap_or_else(|| "--".to_string());
            let b_str = byte_b
                .map(|b| format!("{:02x}", b))
                .unwrap_or_else(|| "--".to_string());
            writeln!(output, "  offset {:04x}: {} != {}", i, a_str, b_str).unwrap();
        }
    }

    output
}

/// Pad data to a minimum length with zeros.
pub fn pad_to(data: &[u8], min_len: usize) -> Vec<u8> {
    if data.len() >= min_len {
        data.to_vec()
    } else {
        let mut padded = data.to_vec();
        padded.resize(min_len, 0);
        padded
    }
}

/// Pad data to align to a boundary.
pub fn align_to(data: &[u8], alignment: usize) -> Vec<u8> {
    let padded_len = (data.len() + alignment - 1) / alignment * alignment;
    pad_to(data, padded_len)
}

/// Calculate the minimum Ethernet frame size (including padding).
pub fn ethernet_min_frame(data: &[u8]) -> Vec<u8> {
    // Minimum Ethernet frame is 64 bytes (including 4-byte FCS)
    // Without FCS, it's 60 bytes
    pad_to(data, 60)
}

/// Extract bits from a byte.
#[inline]
pub fn extract_bits(byte: u8, start: u8, len: u8) -> u8 {
    (byte >> (8 - start - len)) & ((1 << len) - 1)
}

/// Set bits in a byte.
#[inline]
pub fn set_bits(byte: &mut u8, start: u8, len: u8, value: u8) {
    let mask = ((1u8 << len) - 1) << (8 - start - len);
    *byte = (*byte & !mask) | ((value << (8 - start - len)) & mask);
}

/// Convert a u16 to big-endian bytes.
#[inline]
pub const fn u16_to_be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// Convert a u32 to big-endian bytes.
#[inline]
pub const fn u32_to_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Convert big-endian bytes to u16.
#[inline]
pub const fn be_to_u16(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

/// Convert big-endian bytes to u32.
#[inline]
pub const fn be_to_u32(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

/// Generate random bytes.
#[cfg(feature = "rand")]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random()).collect()
}

/// Generate a random MAC address.
#[cfg(feature = "rand")]
pub fn random_mac() -> crate::MacAddress {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes);
    // Set locally administered bit, clear multicast bit
    bytes[0] = (bytes[0] | 0x02) & 0xFE;
    crate::MacAddress::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump() {
        let data = b"Hello, World!";
        let dump = hexdump(data);
        assert!(dump.contains("48 65 6c 6c")); // "Hell"
        assert!(dump.contains("|Hello, World!|"));
    }

    #[test]
    fn test_hexstr() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hexstr(&data), "deadbeef");
        assert_eq!(hexstr_sep(&data, ":"), "de:ad:be:ef");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            parse_hex("de:ad:be:ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            parse_hex("de ad be ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(parse_hex("dea").is_err()); // Odd length
    }

    #[test]
    fn test_internet_checksum() {
        // Test with known values from RFC 1071
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let checksum = internet_checksum(&data);
        // The result should fold correctly
        assert_ne!(checksum, 0); // Non-zero for this data
    }

    #[test]
    fn test_checksum_verify() {
        // Create data with valid checksum
        let mut data = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        data.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]); // checksum = 0 initially
        data.extend_from_slice(&[0xac, 0x10, 0x0a, 0x63]); // src IP
        data.extend_from_slice(&[0xac, 0x10, 0x0a, 0x0c]); // dst IP

        let checksum = internet_checksum(&data);
        // Set the checksum
        data[10] = (checksum >> 8) as u8;
        data[11] = checksum as u8;

        // Now verification should pass
        assert!(verify_checksum(&data));
    }

    #[test]
    fn test_pad_to() {
        let data = [1, 2, 3];
        let padded = pad_to(&data, 6);
        assert_eq!(padded, vec![1, 2, 3, 0, 0, 0]);

        // No padding needed
        let padded = pad_to(&data, 2);
        assert_eq!(padded, vec![1, 2, 3]);
    }

    #[test]
    fn test_align_to() {
        let data = [1, 2, 3, 4, 5];
        let aligned = align_to(&data, 4);
        assert_eq!(aligned.len(), 8);
        assert_eq!(&aligned[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_extract_bits() {
        let byte = 0b1010_0110;
        assert_eq!(extract_bits(byte, 0, 4), 0b1010);
        assert_eq!(extract_bits(byte, 4, 4), 0b0110);
        assert_eq!(extract_bits(byte, 2, 4), 0b1001);
    }

    #[test]
    fn test_set_bits() {
        let mut byte = 0b0000_0000;
        set_bits(&mut byte, 0, 4, 0b1010);
        assert_eq!(byte, 0b1010_0000);

        set_bits(&mut byte, 4, 4, 0b0110);
        assert_eq!(byte, 0b1010_0110);
    }

    #[test]
    fn test_find_diff() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 9, 4, 5];
        assert_eq!(find_diff(&a, &b), Some(2));

        let c = [1, 2, 3, 4, 5];
        assert_eq!(find_diff(&a, &c), None);

        let d = [1, 2, 3];
        assert_eq!(find_diff(&a, &d), Some(3));
    }

    #[test]
    fn test_ethernet_min_frame() {
        let data = vec![0u8; 20];
        let frame = ethernet_min_frame(&data);
        assert_eq!(frame.len(), 60);
    }
}
