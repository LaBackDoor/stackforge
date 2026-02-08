//! Bitwise operations and byte order conversions.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
