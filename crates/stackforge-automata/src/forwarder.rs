use stackforge_core::layer::field::MacAddress;

/// Rewrite the destination MAC in an Ethernet frame and return the modified bytes.
///
/// The first 6 bytes of an Ethernet frame are the destination MAC.
/// This function copies the packet data and overwrites those bytes.
#[must_use]
pub fn rewrite_dst_mac(frame: &[u8], new_dst: MacAddress) -> Vec<u8> {
    if frame.len() < 14 {
        return frame.to_vec();
    }
    let mut out = frame.to_vec();
    out[0..6].copy_from_slice(&new_dst.0);
    out
}

/// Rewrite the source MAC in an Ethernet frame and return the modified bytes.
#[must_use]
pub fn rewrite_src_mac(frame: &[u8], new_src: MacAddress) -> Vec<u8> {
    if frame.len() < 14 {
        return frame.to_vec();
    }
    let mut out = frame.to_vec();
    out[6..12].copy_from_slice(&new_src.0);
    out
}

/// Rewrite both source and destination MACs.
#[must_use]
pub fn rewrite_macs(frame: &[u8], new_dst: MacAddress, new_src: MacAddress) -> Vec<u8> {
    if frame.len() < 14 {
        return frame.to_vec();
    }
    let mut out = frame.to_vec();
    out[0..6].copy_from_slice(&new_dst.0);
    out[6..12].copy_from_slice(&new_src.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_dst_mac() {
        let frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // ethertype
            0xde, 0xad, // payload
        ];
        let new_dst = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let result = rewrite_dst_mac(&frame, new_dst);
        assert_eq!(&result[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(&result[6..12], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_rewrite_macs() {
        let frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00,
        ];
        let dst = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let src = MacAddress::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let result = rewrite_macs(&frame, dst, src);
        assert_eq!(&result[0..6], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(&result[6..12], &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
    }
}
