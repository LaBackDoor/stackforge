//! Modbus CRC-16 and LRC checksum functions.
//!
//! - **CRC-16/MODBUS**: Used by Modbus RTU frames. Polynomial 0xA001 (reflected),
//!   init 0xFFFF, no final XOR.
//! - **LRC**: Longitudinal Redundancy Check used by Modbus ASCII frames.
//!   Two's complement of the sum of all bytes (mod 256).

/// Compute the Modbus CRC-16 checksum.
///
/// Uses the reflected polynomial 0xA001, initial value 0xFFFF.
/// The result is in little-endian byte order when appended to an RTU frame
/// (low byte first, high byte second).
pub fn modbus_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Verify the CRC-16 of a complete Modbus RTU frame (data + 2-byte CRC).
///
/// The last two bytes of `frame` are the CRC in little-endian order.
/// Returns true if the CRC is correct.
pub fn verify_crc16(frame: &[u8]) -> bool {
    if frame.len() < 3 {
        return false;
    }
    let data = &frame[..frame.len() - 2];
    let expected = u16::from_le_bytes([frame[frame.len() - 2], frame[frame.len() - 1]]);
    modbus_crc16(data) == expected
}

/// Compute the Modbus LRC (Longitudinal Redundancy Check).
///
/// LRC is the two's complement of the 8-bit sum of all bytes.
/// Used in Modbus ASCII mode: the LRC byte is transmitted as two ASCII hex chars.
pub fn modbus_lrc(data: &[u8]) -> u8 {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum.wrapping_neg()
}

/// Verify the LRC of a data slice where the last byte is the LRC.
///
/// Returns true if the LRC is correct (sum of all bytes including LRC == 0).
pub fn verify_lrc(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_check_value() {
        // Standard CRC-16/MODBUS check value: "123456789" -> 0x4B37
        assert_eq!(modbus_crc16(b"123456789"), 0x4B37);
    }

    #[test]
    fn test_crc16_known_vector() {
        // Slave=0x01, FC=0x03, Addr=0x0000, Qty=0x000A
        // Verify round-trip consistency
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let crc = modbus_crc16(&data);
        let mut frame = data.to_vec();
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);
        assert!(verify_crc16(&frame));
    }

    #[test]
    fn test_crc16_empty() {
        assert_eq!(modbus_crc16(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_single_byte() {
        // CRC of [0x00]: init=0xFFFF, XOR with 0x00 -> process 8 bits
        let crc = modbus_crc16(&[0x00]);
        // Self-consistency: verify round-trip
        let mut frame = vec![0x00u8];
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);
        assert!(verify_crc16(&frame));
    }

    #[test]
    fn test_verify_crc16_valid() {
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let crc = modbus_crc16(&data);
        let mut frame = data.to_vec();
        frame.push((crc & 0xFF) as u8); // low byte
        frame.push((crc >> 8) as u8); // high byte
        assert!(verify_crc16(&frame));
    }

    #[test]
    fn test_verify_crc16_corrupted() {
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let crc = modbus_crc16(&data);
        let mut frame = data.to_vec();
        frame.push((crc & 0xFF) as u8);
        frame.push(((crc >> 8) as u8) ^ 0xFF); // corrupt high byte
        assert!(!verify_crc16(&frame));
    }

    #[test]
    fn test_verify_crc16_too_short() {
        assert!(!verify_crc16(&[0x01, 0x02]));
        assert!(!verify_crc16(&[]));
    }

    #[test]
    fn test_lrc_known_vector() {
        // Slave=0x01, FC=0x03, Addr=0x0000, Qty=0x000A
        // Sum = 0x01 + 0x03 + 0x00 + 0x00 + 0x00 + 0x0A = 0x0E
        // LRC = -(0x0E) mod 256 = 0xF2
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(modbus_lrc(&data), 0xF2);
    }

    #[test]
    fn test_lrc_empty() {
        assert_eq!(modbus_lrc(&[]), 0x00);
    }

    #[test]
    fn test_lrc_self_check() {
        // sum of data + LRC should be 0
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let lrc = modbus_lrc(&data);
        let mut with_lrc = data.to_vec();
        with_lrc.push(lrc);
        assert!(verify_lrc(&with_lrc));
    }

    #[test]
    fn test_verify_lrc_valid() {
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xF2];
        assert!(verify_lrc(&data));
    }

    #[test]
    fn test_verify_lrc_invalid() {
        let data = [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xFF];
        assert!(!verify_lrc(&data));
    }

    #[test]
    fn test_verify_lrc_empty() {
        assert!(!verify_lrc(&[]));
    }
}
