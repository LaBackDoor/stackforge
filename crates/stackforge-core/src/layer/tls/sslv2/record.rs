//! `SSLv2` record format parsing.
//!
//! `SSLv2` has two record header formats:
//! - 2-byte header (MSB set): length = (byte0 & 0x7F) << 8 | byte1, no padding
//! - 3-byte header (MSB clear): length = (byte0 & 0x3F) << 8 | byte1, padding = byte2

/// Parsed `SSLv2` record.
#[derive(Debug, Clone)]
pub struct Sslv2Record {
    /// Header length (2 or 3 bytes).
    pub header_len: usize,
    /// Record data length.
    pub length: usize,
    /// Padding length (0 for 2-byte header).
    pub padding: u8,
    /// Record data (includes message type byte).
    pub data: Vec<u8>,
}

/// Parse an `SSLv2` record from raw bytes.
///
/// Returns the record and number of bytes consumed.
#[must_use]
pub fn parse_sslv2_record(data: &[u8]) -> Option<(Sslv2Record, usize)> {
    if data.len() < 2 {
        return None;
    }

    let (header_len, length, padding) = if (data[0] & 0x80) != 0 {
        // 2-byte header
        let length = ((data[0] as usize & 0x7F) << 8) | data[1] as usize;
        (2, length, 0u8)
    } else {
        // 3-byte header
        if data.len() < 3 {
            return None;
        }
        let length = ((data[0] as usize & 0x3F) << 8) | data[1] as usize;
        let padding = data[2];
        (3, length, padding)
    };

    let total = header_len + length;
    let record_data = if total <= data.len() {
        data[header_len..total].to_vec()
    } else {
        data[header_len..].to_vec()
    };

    Some((
        Sslv2Record {
            header_len,
            length,
            padding,
            data: record_data,
        },
        total.min(data.len()),
    ))
}

impl Sslv2Record {
    /// Build `SSLv2` record with 2-byte header.
    #[must_use]
    pub fn build(data: &[u8]) -> Vec<u8> {
        let length = data.len();
        let mut buf = Vec::with_capacity(2 + length);
        buf.push(0x80 | ((length >> 8) as u8 & 0x7F));
        buf.push((length & 0xFF) as u8);
        buf.extend_from_slice(data);
        buf
    }

    /// Get the message type byte (first byte of data).
    #[must_use]
    pub fn msg_type(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_2byte_header() {
        // MSB set, length = 0x2E (46)
        let data = vec![0x80, 0x2E, 0x01, 0x00, 0x02];
        let (record, consumed) = parse_sslv2_record(&data).unwrap();
        assert_eq!(record.header_len, 2);
        assert_eq!(record.length, 46);
        assert_eq!(record.padding, 0);
        // Only got 3 bytes of data (truncated)
        assert_eq!(record.data.len(), 3);
        assert_eq!(consumed, 5); // min(48, 5)
    }

    #[test]
    fn test_parse_3byte_header() {
        // MSB clear, 3-byte header
        let data = vec![0x00, 0x05, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let (record, consumed) = parse_sslv2_record(&data).unwrap();
        assert_eq!(record.header_len, 3);
        assert_eq!(record.length, 5);
        assert_eq!(record.padding, 1);
        assert_eq!(record.data.len(), 5);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_build_record() {
        let data = vec![0x01, 0x00, 0x02];
        let built = Sslv2Record::build(&data);
        assert_eq!(built[0] & 0x80, 0x80); // MSB set
        assert_eq!(built.len(), 5); // 2 header + 3 data
    }

    #[test]
    fn test_msg_type() {
        let data = vec![0x80, 0x03, 0x01, 0xAA, 0xBB];
        let (record, _) = parse_sslv2_record(&data).unwrap();
        assert_eq!(record.msg_type(), Some(0x01)); // ClientHello
    }
}
