//! QUIC packet builder (RFC 9000 Sections 17.2 and 17.3).
//!
//! Provides [`QuicBuilder`] for constructing QUIC packets in byte form.
//! All encryption / key scheduling is deliberately out of scope here: the
//! builder emits the plaintext wire bytes only.

use super::headers::QuicPacketType;
use super::varint;

/// Builder for QUIC packets.
///
/// Supports Initial, Handshake (long header) and 1-RTT (short header) packet
/// construction.
///
/// # Example
///
/// ```rust
/// use stackforge_core::layer::quic::builder::QuicBuilder;
///
/// let bytes = QuicBuilder::initial()
///     .dst_conn_id(vec![0x01, 0x02, 0x03, 0x04])
///     .src_conn_id(vec![0xAA, 0xBB])
///     .payload(vec![0xDE, 0xAD, 0xBE, 0xEF])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct QuicBuilder {
    /// Whether this packet uses a long header (false = short/1-RTT).
    is_long_header: bool,
    /// Logical packet type.
    packet_type: QuicPacketType,
    /// QUIC version (big-endian u32).  Default = 1 (QUIC v1, RFC 9000).
    version: u32,
    /// Destination Connection ID.
    dst_conn_id: Vec<u8>,
    /// Source Connection ID (long header only).
    src_conn_id: Vec<u8>,
    /// Token (Initial packets only, RFC 9000 Section 17.2.2).
    token: Vec<u8>,
    /// Decrypted payload bytes (frames).
    payload: Vec<u8>,
    /// Packet number (used verbatim; no truncation is applied).
    packet_number: u32,
}

impl Default for QuicBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicBuilder {
    /// Create a bare builder.  Most callers should use [`initial`], [`handshake`],
    /// or [`one_rtt`] instead.
    pub fn new() -> Self {
        Self {
            is_long_header: true,
            packet_type: QuicPacketType::Initial,
            version: 1,
            dst_conn_id: Vec::new(),
            src_conn_id: Vec::new(),
            token: Vec::new(),
            payload: Vec::new(),
            packet_number: 0,
        }
    }

    /// Create a builder pre-configured for a QUIC Initial packet (RFC 9000 Section 17.2.2).
    pub fn initial() -> Self {
        Self {
            is_long_header: true,
            packet_type: QuicPacketType::Initial,
            version: 1,
            ..Self::new()
        }
    }

    /// Create a builder pre-configured for a QUIC Handshake packet (RFC 9000 Section 17.2.4).
    pub fn handshake() -> Self {
        Self {
            is_long_header: true,
            packet_type: QuicPacketType::Handshake,
            version: 1,
            ..Self::new()
        }
    }

    /// Create a builder pre-configured for a QUIC 1-RTT (short header) packet
    /// (RFC 9000 Section 17.3).
    pub fn one_rtt() -> Self {
        Self {
            is_long_header: false,
            packet_type: QuicPacketType::OneRtt,
            version: 1,
            ..Self::new()
        }
    }

    /// Set the destination connection ID.
    pub fn dst_conn_id(mut self, id: Vec<u8>) -> Self {
        self.dst_conn_id = id;
        self
    }

    /// Set the source connection ID (ignored for short-header packets).
    pub fn src_conn_id(mut self, id: Vec<u8>) -> Self {
        self.src_conn_id = id;
        self
    }

    /// Set the QUIC version.
    pub fn version(mut self, v: u32) -> Self {
        self.version = v;
        self
    }

    /// Set the token (Initial packets only).
    pub fn token(mut self, t: Vec<u8>) -> Self {
        self.token = t;
        self
    }

    /// Set the (plaintext) payload bytes.
    pub fn payload(mut self, p: Vec<u8>) -> Self {
        self.payload = p;
        self
    }

    /// Set the packet number.
    pub fn packet_number(mut self, n: u32) -> Self {
        self.packet_number = n;
        self
    }

    /// Build the QUIC packet into a raw byte buffer.
    ///
    /// The packet number is encoded in the minimum number of bytes needed
    /// (1 through 4) according to RFC 9000 Section 17.1.
    pub fn build(&self) -> Vec<u8> {
        if self.is_long_header {
            self.build_long()
        } else {
            self.build_short()
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Packet-number byte length (1..=4) for the current `packet_number`.
    fn pn_len(&self) -> usize {
        if self.packet_number < 0x100 {
            1
        } else if self.packet_number < 0x1_0000 {
            2
        } else if self.packet_number < 0x100_0000 {
            3
        } else {
            4
        }
    }

    /// Encode the packet number into bytes (big-endian, minimal width).
    fn encode_pn(&self) -> Vec<u8> {
        let n = self.pn_len();
        let pn = self.packet_number;
        match n {
            1 => vec![pn as u8],
            2 => (pn as u16).to_be_bytes().to_vec(),
            3 => {
                let b = pn.to_be_bytes();
                vec![b[1], b[2], b[3]]
            },
            _ => pn.to_be_bytes().to_vec(),
        }
    }

    /// Long-header packet type bits (bits 5-4 of byte 0).
    fn long_type_bits(&self) -> u8 {
        match self.packet_type {
            QuicPacketType::Initial => 0x00,
            QuicPacketType::ZeroRtt => 0x01,
            QuicPacketType::Handshake => 0x02,
            QuicPacketType::Retry => 0x03,
            // Short header / VersionNeg don't use this path.
            _ => 0x00,
        }
    }

    /// Build a long-header packet (Initial or Handshake).
    fn build_long(&self) -> Vec<u8> {
        let pn_len = self.pn_len();
        let pn_bytes = self.encode_pn();

        // Length field = len(packet_number) + len(payload)
        let length_val = (pn_len + self.payload.len()) as u64;
        let length_varint = varint::encode(length_val);

        // --- Byte 0 ---
        // Header Form (1) = 1
        // Fixed Bit (1)   = 1
        // Long Packet Type (2)
        // Reserved (2)    = 0
        // Packet Number Length (2) = pn_len - 1
        let first_byte: u8 = 0x80                        // Header Form = Long
            | 0x40                      // Fixed Bit
            | (self.long_type_bits() << 4)
            | ((pn_len as u8) - 1); // Packet Number Length (0-based)

        let mut out = Vec::new();

        // Byte 0
        out.push(first_byte);

        // Bytes 1-4: Version
        out.extend_from_slice(&self.version.to_be_bytes());

        // DCIL + DCID
        out.push(self.dst_conn_id.len() as u8);
        out.extend_from_slice(&self.dst_conn_id);

        // SCIL + SCID
        out.push(self.src_conn_id.len() as u8);
        out.extend_from_slice(&self.src_conn_id);

        // Token (Initial only)
        if self.packet_type == QuicPacketType::Initial {
            out.extend_from_slice(&varint::encode(self.token.len() as u64));
            out.extend_from_slice(&self.token);
        }

        // Length (varint)
        out.extend_from_slice(&length_varint);

        // Packet Number
        out.extend_from_slice(&pn_bytes);

        // Payload
        out.extend_from_slice(&self.payload);

        out
    }

    /// Build a short-header (1-RTT) packet.
    fn build_short(&self) -> Vec<u8> {
        let pn_len = self.pn_len();
        let pn_bytes = self.encode_pn();

        // Byte 0:
        // Header Form (1) = 0
        // Fixed Bit (1)   = 1
        // Spin Bit (1)    = 0
        // Reserved (2)    = 0
        // Key Phase (1)   = 0
        // Packet Number Length (2) = pn_len - 1
        let first_byte: u8 = 0x40 | ((pn_len as u8) - 1);

        let mut out = Vec::new();
        out.push(first_byte);

        // Destination Connection ID (0 bytes for simplicity when not set)
        out.extend_from_slice(&self.dst_conn_id);

        // Packet Number
        out.extend_from_slice(&pn_bytes);

        // Payload
        out.extend_from_slice(&self.payload);

        out
    }
}

/// Type alias for building QUIC Initial packets — same as `QuicBuilder::initial()`.
pub type QuicInitialBuilder = QuicBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::quic::headers::{QuicLongHeader, QuicShortHeader};

    #[test]
    fn test_build_initial_basic() {
        let bytes = QuicBuilder::initial()
            .dst_conn_id(vec![0x01, 0x02, 0x03, 0x04])
            .src_conn_id(vec![])
            .payload(vec![0xAA, 0xBB])
            .build();

        // Must start with long-header first byte
        assert_eq!(bytes[0] & 0x80, 0x80, "Header Form must be 1 (long)");
        assert_eq!(bytes[0] & 0x40, 0x40, "Fixed Bit must be 1");
        // Long packet type bits 5-4 = 00 => Initial
        assert_eq!((bytes[0] & 0x30) >> 4, 0x00);

        // Version = 1
        assert_eq!(&bytes[1..5], &[0x00, 0x00, 0x00, 0x01]);

        // DCIL = 4
        assert_eq!(bytes[5], 4);
        assert_eq!(&bytes[6..10], &[0x01, 0x02, 0x03, 0x04]);

        // SCIL = 0
        assert_eq!(bytes[10], 0);
    }

    #[test]
    fn test_build_initial_parse_back() {
        let bytes = QuicBuilder::initial()
            .dst_conn_id(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .src_conn_id(vec![0x11, 0x22])
            .build();

        let hdr = QuicLongHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.packet_type, QuicPacketType::Initial);
        assert_eq!(hdr.dst_conn_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(hdr.src_conn_id, vec![0x11, 0x22]);
        assert_eq!(hdr.version, 1);
    }

    #[test]
    fn test_build_handshake() {
        let bytes = QuicBuilder::handshake()
            .dst_conn_id(vec![0x01])
            .payload(vec![0x06, 0x00, 0x01, 0xFF]) // pretend CRYPTO frame
            .build();

        assert_eq!(bytes[0] & 0x80, 0x80, "long header");
        assert_eq!((bytes[0] & 0x30) >> 4, 0x02, "Handshake type bits");

        let hdr = QuicLongHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.packet_type, QuicPacketType::Handshake);
    }

    #[test]
    fn test_build_one_rtt() {
        let bytes = QuicBuilder::one_rtt()
            .payload(vec![0x01]) // PING
            .build();

        // Short header: bit 7 = 0
        assert_eq!(bytes[0] & 0x80, 0x00, "short header");
        assert_eq!(bytes[0] & 0x40, 0x40, "Fixed Bit must be 1");

        let hdr = QuicShortHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.header_len, 1);
    }

    #[test]
    fn test_build_with_token() {
        let bytes = QuicBuilder::initial()
            .token(vec![0xCA, 0xFE])
            .payload(vec![])
            .build();

        // Token len varint should be present after SCID
        // Minimal: [byte0][ver:4][DCIL=0][SCIL=0][TokenLen=2(varint)][CA][FE][Length][PN]
        // Token length byte at offset 6 (after byte0 + ver4 + DCIL=0 + SCIL=0 = 7 bytes)
        // Actually: byte0=1, ver=4, DCIL_byte=1, DCID=0, SCIL_byte=1, SCID=0 => pos=7
        // Then TokenLen varint (2 => encodes as 0x02) at pos=7
        assert!(bytes.len() >= 12);
    }

    #[test]
    fn test_packet_number_encoding() {
        // Small packet number => 1 byte
        let bytes = QuicBuilder::initial().packet_number(0).build();
        assert_eq!(bytes[0] & 0x03, 0, "pn_len-1 = 0 for 1-byte PN");

        // Large packet number => 4 bytes
        let bytes = QuicBuilder::initial().packet_number(0x1234_5678).build();
        assert_eq!(bytes[0] & 0x03, 3, "pn_len-1 = 3 for 4-byte PN");
    }
}
