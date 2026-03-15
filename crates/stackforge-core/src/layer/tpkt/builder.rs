//! TPKT packet builder.
//!
//! Provides a fluent API for constructing TPKT (RFC 1006) packets.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::tpkt::builder::TpktBuilder;
//!
//! // Default TPKT header (no payload): version=3, reserved=0, length=4
//! let pkt = TpktBuilder::new().build();
//! assert_eq!(pkt, b"\x03\x00\x00\x04");
//!
//! // TPKT with payload
//! let pkt = TpktBuilder::new().payload(vec![0x02, 0xF0, 0x80]).build();
//! assert_eq!(pkt.len(), 7);
//! assert_eq!(&pkt[0..4], b"\x03\x00\x00\x07");
//! ```

/// Builder for TPKT packets.
///
/// The length field is auto-calculated as 4 (header) + payload length.
#[derive(Debug, Clone)]
pub struct TpktBuilder {
    /// TPKT version (default: 3).
    version: u8,
    /// Reserved byte (default: 0).
    reserved: u8,
    /// Payload bytes (after the 4-byte header).
    payload: Vec<u8>,
}

impl Default for TpktBuilder {
    fn default() -> Self {
        Self {
            version: 3,
            reserved: 0,
            payload: Vec::new(),
        }
    }
}

impl TpktBuilder {
    /// Create a new TPKT builder with default values (version=3, reserved=0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the version field.
    #[must_use]
    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set the reserved field.
    #[must_use]
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved = reserved;
        self
    }

    /// Set the payload bytes.
    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Compute the total packet length (header + payload).
    #[must_use]
    pub fn packet_size(&self) -> usize {
        4 + self.payload.len()
    }

    /// Serialize the TPKT packet into bytes.
    ///
    /// The length field is auto-calculated as 4 + payload.len().
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let total = self.packet_size();
        let mut buf = Vec::with_capacity(total);

        // Byte 0: version
        buf.push(self.version);
        // Byte 1: reserved
        buf.push(self.reserved);
        // Bytes 2-3: length (total including header)
        let length = total as u16;
        buf.extend_from_slice(&length.to_be_bytes());
        // Payload
        buf.extend_from_slice(&self.payload);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tpkt() {
        let pkt = TpktBuilder::new().build();
        assert_eq!(pkt, b"\x03\x00\x00\x04");
    }

    #[test]
    fn test_tpkt_with_payload() {
        // COTP DT (3 bytes): LI=2, PDU=0xF0, EOT=0x80
        let pkt = TpktBuilder::new().payload(vec![0x02, 0xF0, 0x80]).build();
        assert_eq!(pkt.len(), 7);
        assert_eq!(pkt[0], 0x03); // version
        assert_eq!(pkt[1], 0x00); // reserved
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 7); // length = 4 + 3
        assert_eq!(&pkt[4..], &[0x02, 0xF0, 0x80]);
    }

    #[test]
    fn test_tpkt_custom_version() {
        let pkt = TpktBuilder::new().version(4).build();
        assert_eq!(pkt[0], 4);
    }

    #[test]
    fn test_tpkt_packet_size() {
        let b = TpktBuilder::new();
        assert_eq!(b.packet_size(), 4);

        let b = TpktBuilder::new().payload(vec![0; 10]);
        assert_eq!(b.packet_size(), 14);
    }
}
