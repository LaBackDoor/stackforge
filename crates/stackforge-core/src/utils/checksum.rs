//! Checksum calculation and verification utilities.
//!
//! Provides generic RFC 1071 Internet checksum implementation that can be used
//! by all protocol layers (IP, ICMP, TCP, UDP, etc.).

/// Calculate the Internet checksum (RFC 1071).
///
/// This is used for IP, ICMP, TCP, and UDP checksums.
///
/// # Algorithm
///
/// 1. Sum all 16-bit words in the data
/// 2. Add any odd byte as the high byte of a word
/// 3. Fold 32-bit sum to 16 bits by adding carry bits
/// 4. Take one's complement of the result
pub fn internet_checksum(data: &[u8]) -> u16 {
    let sum = partial_checksum(data, 0);
    finalize_checksum(sum)
}

/// Compute partial checksum (before folding and complement).
///
/// Useful for computing checksum across multiple data segments or when
/// combining pseudo-header with data.
///
/// # Arguments
///
/// * `data` - The data to checksum
/// * `initial` - Initial checksum value (use 0 for starting fresh)
///
/// # Returns
///
/// The 32-bit partial sum (not yet folded or complemented).
#[inline]
pub fn partial_checksum(data: &[u8], initial: u32) -> u32 {
    let mut sum = initial;

    // Process 16-bit words
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    // Handle odd byte (pad with zero on the right)
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }

    sum
}

/// Finalize a partial checksum.
///
/// Folds the 32-bit sum to 16 bits by adding carry bits, then takes
/// one's complement.
///
/// # Arguments
///
/// * `sum` - The 32-bit partial sum from `partial_checksum()`
///
/// # Returns
///
/// The final 16-bit checksum value.
#[inline]
pub fn finalize_checksum(sum: u32) -> u16 {
    let mut s = sum;
    // Fold 32-bit sum to 16 bits (add carry)
    while (s >> 16) != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    // One's complement
    !s as u16
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
