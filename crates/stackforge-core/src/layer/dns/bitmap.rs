//! NSEC/NSEC3 type bitmap encoding and decoding (RFC 4034 Section 4.1.2).

use crate::layer::field::FieldError;

/// Convert NSEC/NSEC3 type bitmap wire format to a list of RR type numbers.
///
/// The bitmap format consists of windows:
///   - Window block number (1 byte): high 8 bits of type number
///   - Bitmap length (1 byte): number of bitmap bytes (1-32)
///   - Bitmap (variable): each bit represents a type in that window
pub fn bitmap_to_rr_list(data: &[u8]) -> Result<Vec<u16>, FieldError> {
    let mut types = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(FieldError::InvalidValue(
                "truncated NSEC bitmap window".to_string(),
            ));
        }

        let window = u16::from(data[pos]);
        let bitmap_len = data[pos + 1] as usize;
        pos += 2;

        if bitmap_len == 0 || bitmap_len > 32 {
            return Err(FieldError::InvalidValue(format!(
                "invalid NSEC bitmap length: {bitmap_len}"
            )));
        }

        if pos + bitmap_len > data.len() {
            return Err(FieldError::InvalidValue(
                "truncated NSEC bitmap data".to_string(),
            ));
        }

        for i in 0..bitmap_len {
            let byte = data[pos + i];
            for bit in 0..8u16 {
                if (byte >> (7 - bit)) & 1 != 0 {
                    let rr_type = window * 256 + (i as u16) * 8 + bit;
                    types.push(rr_type);
                }
            }
        }

        pos += bitmap_len;
    }

    Ok(types)
}

/// Convert a list of RR type numbers to NSEC/NSEC3 type bitmap wire format.
#[must_use]
pub fn rr_list_to_bitmap(types: &[u16]) -> Vec<u8> {
    if types.is_empty() {
        return Vec::new();
    }

    // Group types by window (high byte)
    let mut windows: std::collections::BTreeMap<u8, Vec<u16>> = std::collections::BTreeMap::new();
    for &t in types {
        let window = (t >> 8) as u8;
        let offset = t & 0xFF;
        windows.entry(window).or_default().push(offset);
    }

    let mut out = Vec::new();

    for (&window, offsets) in &windows {
        // Find the maximum byte needed in this window
        let max_offset = *offsets.iter().max().unwrap();
        let bitmap_len = (max_offset / 8 + 1) as usize;

        // Build the bitmap
        let mut bitmap = vec![0u8; bitmap_len];
        for &offset in offsets {
            let byte_idx = (offset / 8) as usize;
            let bit_idx = 7 - (offset % 8);
            bitmap[byte_idx] |= 1 << bit_idx;
        }

        out.push(window);
        out.push(bitmap_len as u8);
        out.extend_from_slice(&bitmap);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_roundtrip_simple() {
        let types = vec![1, 2, 5, 6, 15, 16, 28]; // A, NS, CNAME, SOA, MX, TXT, AAAA
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_single_type() {
        let types = vec![1]; // Just A
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_type_zero() {
        let types = vec![0];
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_high_types() {
        // Types in higher windows (256, 512, etc.)
        let types = vec![256, 512, 4096, 36864];
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_type_65535() {
        let types = vec![65535];
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_mixed_windows() {
        let mut types = vec![1, 2, 28, 46, 47, 48, 256, 257];
        let bitmap = rr_list_to_bitmap(&types);
        let decoded = bitmap_to_rr_list(&bitmap).unwrap();
        types.sort();
        assert_eq!(decoded, types);
    }

    #[test]
    fn test_bitmap_empty() {
        let bitmap = rr_list_to_bitmap(&[]);
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_bitmap_decode_truncated() {
        let data = vec![0]; // Only window byte, no length
        assert!(bitmap_to_rr_list(&data).is_err());
    }

    #[test]
    fn test_bitmap_decode_invalid_length() {
        let data = vec![0, 33]; // Length > 32
        assert!(bitmap_to_rr_list(&data).is_err());
    }

    #[test]
    fn test_bitmap_decode_zero_length() {
        let data = vec![0, 0]; // Length == 0
        assert!(bitmap_to_rr_list(&data).is_err());
    }
}
