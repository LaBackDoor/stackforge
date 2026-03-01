//! UDP (User Datagram Protocol) layer implementation.
//!
//! This module provides types and functions for working with UDP packets,
//! including parsing, field access, and checksum calculation.

pub mod builder;
pub mod checksum;

// Re-export builder
pub use builder::UdpBuilder;

// Re-export checksum functions
pub use checksum::{
    udp_checksum_ipv4, udp_checksum_ipv6, verify_udp_checksum_ipv4, verify_udp_checksum_ipv6,
};

use crate::layer::field::{FieldDesc, FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// UDP header length (8 bytes fixed).
pub const UDP_HEADER_LEN: usize = 8;

/// Field offsets within the UDP header.
pub mod offsets {
    pub const SRC_PORT: usize = 0;
    pub const DST_PORT: usize = 2;
    pub const LENGTH: usize = 4;
    pub const CHECKSUM: usize = 6;
}

/// UDP field descriptors for dynamic access.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::new("sport", offsets::SRC_PORT, 2, FieldType::U16),
    FieldDesc::new("dport", offsets::DST_PORT, 2, FieldType::U16),
    FieldDesc::new("len", offsets::LENGTH, 2, FieldType::U16),
    FieldDesc::new("chksum", offsets::CHECKSUM, 2, FieldType::U16),
];

/// UDP layer representation.
///
/// UDP is a simple, connectionless transport protocol defined in RFC 768.
/// The header is 8 bytes:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Length             |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             Data                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct UdpLayer {
    pub index: LayerIndex,
}

impl UdpLayer {
    /// Create a new UDP layer from a layer index.
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Get the source port.
    pub fn src_port(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::SRC_PORT + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::SRC_PORT,
                need: 2,
                have: slice.len().saturating_sub(offsets::SRC_PORT),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::SRC_PORT],
            slice[offsets::SRC_PORT + 1],
        ]))
    }

    /// Get the destination port.
    pub fn dst_port(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::DST_PORT + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::DST_PORT,
                need: 2,
                have: slice.len().saturating_sub(offsets::DST_PORT),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::DST_PORT],
            slice[offsets::DST_PORT + 1],
        ]))
    }

    /// Get the length field (header + data length in bytes).
    pub fn length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::LENGTH + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::LENGTH,
                need: 2,
                have: slice.len().saturating_sub(offsets::LENGTH),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::LENGTH],
            slice[offsets::LENGTH + 1],
        ]))
    }

    /// Get the checksum.
    pub fn checksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::CHECKSUM + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::CHECKSUM,
                need: 2,
                have: slice.len().saturating_sub(offsets::CHECKSUM),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::CHECKSUM],
            slice[offsets::CHECKSUM + 1],
        ]))
    }

    /// Set the source port.
    pub fn set_src_port(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::SRC_PORT;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the destination port.
    pub fn set_dst_port(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::DST_PORT;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the length field.
    pub fn set_length(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::LENGTH;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the checksum.
    pub fn set_checksum(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::CHECKSUM;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Generate a summary string for display.
    pub fn summary(&self, buf: &[u8]) -> String {
        let slice = self.index.slice(buf);
        if slice.len() >= 4 {
            let src_port = u16::from_be_bytes([slice[0], slice[1]]);
            let dst_port = u16::from_be_bytes([slice[2], slice[3]]);
            format!("UDP {} > {}", src_port, dst_port)
        } else {
            "UDP".to_string()
        }
    }

    /// Get the UDP header length (always 8 bytes).
    pub fn header_len(&self, _buf: &[u8]) -> usize {
        UDP_HEADER_LEN
    }

    /// Get field names for this layer.
    pub fn field_names(&self) -> &'static [&'static str] {
        &["sport", "dport", "len", "chksum"]
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "sport" => Some(self.src_port(buf).map(FieldValue::U16)),
            "dport" => Some(self.dst_port(buf).map(FieldValue::U16)),
            "len" => Some(self.length(buf).map(FieldValue::U16)),
            "chksum" => Some(self.checksum(buf).map(FieldValue::U16)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "sport" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_src_port(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "sport: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "dport" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_dst_port(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "dport: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "len" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "len: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "chksum" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_checksum(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "chksum: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for UdpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Udp
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    fn hashret(&self, _data: &[u8]) -> Vec<u8> {
        // UDP is stateless, return empty hash
        vec![]
    }

    fn answers(&self, data: &[u8], other: &Self, other_data: &[u8]) -> bool {
        // UDP answers if destination port matches other's source port
        if let (Ok(self_dport), Ok(other_sport)) = (self.dst_port(data), other.src_port(other_data))
        {
            self_dport == other_sport
        } else {
            false
        }
    }

    fn extract_padding<'a>(&self, data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        // UDP length field includes header + payload
        if let Ok(udp_len) = self.length(data) {
            let udp_len = udp_len as usize;
            let start = self.index.start;
            let available = data.len().saturating_sub(start);

            if udp_len >= UDP_HEADER_LEN && udp_len <= available {
                let end = start + udp_len;
                return (&data[start..end], &data[end..]);
            }
        }
        // If length field is invalid, assume no padding
        let payload = self.index.payload(data);
        (
            &data[self.index.start..self.index.start + self.index.len() + payload.len()],
            &[],
        )
    }

    fn field_names(&self) -> &'static [&'static str] {
        self.field_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_parse() {
        // UDP packet: sport=12345, dport=53, len=20, checksum=0x1234
        let data = [
            0x30, 0x39, // sport = 12345
            0x00, 0x35, // dport = 53 (DNS)
            0x00, 0x14, // len = 20
            0x12, 0x34, // checksum
            // 12 bytes of payload
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];

        let index = LayerIndex::new(LayerKind::Udp, 0, 8);
        let udp = UdpLayer::new(index);

        assert_eq!(udp.src_port(&data).unwrap(), 12345);
        assert_eq!(udp.dst_port(&data).unwrap(), 53);
        assert_eq!(udp.length(&data).unwrap(), 20);
        assert_eq!(udp.checksum(&data).unwrap(), 0x1234);
    }

    #[test]
    fn test_udp_summary() {
        let data = [
            0x04, 0xd2, // sport = 1234
            0x00, 0x50, // dport = 80 (HTTP)
            0x00, 0x08, // len = 8 (header only)
            0x00, 0x00, // checksum
        ];

        let index = LayerIndex::new(LayerKind::Udp, 0, 8);
        let udp = UdpLayer::new(index);

        let summary = udp.summary(&data);
        assert_eq!(summary, "UDP 1234 > 80");
    }

    #[test]
    fn test_udp_set_fields() {
        let mut data = vec![0u8; 8];
        let index = LayerIndex::new(LayerKind::Udp, 0, 8);
        let udp = UdpLayer::new(index);

        udp.set_src_port(&mut data, 5000).unwrap();
        udp.set_dst_port(&mut data, 6000).unwrap();
        udp.set_length(&mut data, 100).unwrap();
        udp.set_checksum(&mut data, 0xABCD).unwrap();

        assert_eq!(udp.src_port(&data).unwrap(), 5000);
        assert_eq!(udp.dst_port(&data).unwrap(), 6000);
        assert_eq!(udp.length(&data).unwrap(), 100);
        assert_eq!(udp.checksum(&data).unwrap(), 0xABCD);
    }

    #[test]
    fn test_udp_extract_padding() {
        // UDP packet with padding
        let data = [
            0x30, 0x39, // sport
            0x00, 0x35, // dport
            0x00, 0x0c, // len = 12 (8 header + 4 payload)
            0x00, 0x00, // checksum
            0x01, 0x02, 0x03, 0x04, // 4 bytes payload
            0xff, 0xff, 0xff, 0xff, // 4 bytes padding
        ];

        let index = LayerIndex::new(LayerKind::Udp, 0, 8);
        let udp = UdpLayer::new(index);

        let (udp_data, padding) = udp.extract_padding(&data);
        assert_eq!(udp_data.len(), 12); // 8 header + 4 payload
        assert_eq!(padding.len(), 4); // 4 bytes padding
    }
}
