//! QUIC variable-length integer encoding (RFC 9000 Section 16).
//!
//! The high 2 bits of the first byte encode the length:
//! - `00` = 1 byte  (6-bit value, max 63)
//! - `01` = 2 bytes (14-bit value, max 16383)
//! - `10` = 4 bytes (30-bit value, max 1073741823)
//! - `11` = 8 bytes (62-bit value, max 4611686018427387903)

/// Maximum value that fits in a QUIC variable-length integer (62 bits).
pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Decode a QUIC variable-length integer from a buffer.
///
/// Returns `Some((value, bytes_consumed))` on success, or `None` if the buffer
/// is too short or the prefix is invalid.
#[must_use]
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let prefix = (buf[0] & 0xC0) >> 6;
    match prefix {
        0 => {
            // 1-byte encoding: 6-bit value
            Some((u64::from(buf[0] & 0x3F), 1))
        },
        1 => {
            // 2-byte encoding: 14-bit value
            if buf.len() < 2 {
                return None;
            }
            let value = u64::from(u16::from_be_bytes([buf[0] & 0x3F, buf[1]]));
            Some((value, 2))
        },
        2 => {
            // 4-byte encoding: 30-bit value
            if buf.len() < 4 {
                return None;
            }
            let value = u64::from(u32::from_be_bytes([buf[0] & 0x3F, buf[1], buf[2], buf[3]]));
            Some((value, 4))
        },
        3 => {
            // 8-byte encoding: 62-bit value
            if buf.len() < 8 {
                return None;
            }
            let value = u64::from_be_bytes([
                buf[0] & 0x3F,
                buf[1],
                buf[2],
                buf[3],
                buf[4],
                buf[5],
                buf[6],
                buf[7],
            ]);
            Some((value, 8))
        },
        _ => unreachable!("prefix is always 0..=3"),
    }
}

/// Encode a QUIC variable-length integer into bytes.
///
/// # Panics
///
/// Panics if `value` exceeds `VARINT_MAX` (4611686018427387903).
#[must_use]
pub fn encode(value: u64) -> Vec<u8> {
    assert!(
        value <= VARINT_MAX,
        "QUIC varint value {value} exceeds maximum {VARINT_MAX}"
    );
    if value < 64 {
        // 1-byte encoding
        vec![value as u8]
    } else if value < 16_384 {
        // 2-byte encoding: set top 2 bits to 0b01
        let encoded = (value as u16) | 0x4000;
        encoded.to_be_bytes().to_vec()
    } else if value < 1_073_741_824 {
        // 4-byte encoding: set top 2 bits to 0b10
        let encoded = (value as u32) | 0x8000_0000;
        encoded.to_be_bytes().to_vec()
    } else {
        // 8-byte encoding: set top 2 bits to 0b11
        let encoded = value | 0xC000_0000_0000_0000;
        encoded.to_be_bytes().to_vec()
    }
}

/// Get the byte length that would be needed to encode `value`.
///
/// Returns 1, 2, 4, or 8.
///
/// # Panics
///
/// Panics if `value` exceeds `VARINT_MAX`.
#[must_use]
pub fn encoded_len(value: u64) -> usize {
    assert!(
        value <= VARINT_MAX,
        "QUIC varint value {value} exceeds maximum {VARINT_MAX}"
    );
    if value < 64 {
        1
    } else if value < 16_384 {
        2
    } else if value < 1_073_741_824 {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_1byte() {
        let buf = [0x25u8]; // 0b00100101 = 37
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 37);
        assert_eq!(len, 1);
    }

    #[test]
    fn test_decode_2bytes() {
        // 0x4001 => prefix=01, value=0x0001=1 (but high bits cleared)
        // Actually: 0x40 | 0x01 = 0x4001 encodes value=1
        let buf = [0x40u8, 0x01u8];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 1);
        assert_eq!(len, 2);
    }

    #[test]
    fn test_decode_4bytes() {
        // Encode 494878333 in 4-byte form: 0x80000000 | 494878333 = 0x9D7F3B3D
        let encoded = (494_878_333u32 | 0x8000_0000u32).to_be_bytes();
        let (val, len) = decode(&encoded).unwrap();
        assert_eq!(val, 494_878_333);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_decode_8bytes() {
        let v: u64 = 151_288_809_941_952_652;
        let encoded = (v | 0xC000_0000_0000_0000).to_be_bytes();
        let (val, len) = decode(&encoded).unwrap();
        assert_eq!(val, v);
        assert_eq!(len, 8);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        for &v in &[
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            VARINT_MAX,
        ] {
            let encoded = encode(v);
            let (decoded, _) = decode(&encoded).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_encoded_len() {
        assert_eq!(encoded_len(0), 1);
        assert_eq!(encoded_len(63), 1);
        assert_eq!(encoded_len(64), 2);
        assert_eq!(encoded_len(16383), 2);
        assert_eq!(encoded_len(16384), 4);
        assert_eq!(encoded_len(1_073_741_823), 4);
        assert_eq!(encoded_len(1_073_741_824), 8);
        assert_eq!(encoded_len(VARINT_MAX), 8);
    }

    #[test]
    fn test_decode_empty() {
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        // 2-byte prefix but only 1 byte
        assert!(decode(&[0x40]).is_none());
        // 4-byte prefix but only 2 bytes
        assert!(decode(&[0x80, 0x01]).is_none());
        // 8-byte prefix but only 4 bytes
        assert!(decode(&[0xC0, 0x01, 0x02, 0x03]).is_none());
    }
}
