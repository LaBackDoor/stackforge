//! QUIC packet header structures (RFC 9000 Section 17).
//!
//! QUIC supports two header forms:
//!
//! * **Long Header** (bit 7 = 1): used for Initial, 0-RTT, Handshake, Retry, and Version
//!   Negotiation packets.
//! * **Short Header** (bit 7 = 0): used for 1-RTT (data) packets after the handshake.
//!
//! Long Header format (RFC 9000 Section 17.2):
//! ```text
//!  Byte 0:  | Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific (4) |
//!  Bytes 1-4: Version (big-endian u32)
//!  Byte 5:  Destination Connection ID Length
//!  N bytes: Destination Connection ID
//!  Byte:    Source Connection ID Length
//!  M bytes: Source Connection ID
//!  (type-specific fields follow)
//! ```
//!
//! Version Negotiation packets have bit 6 = 0 (Fixed Bit cleared).
//! All other long-header packets have bit 6 = 1.

/// QUIC packet type, derived from the first byte (and version field for Version Negotiation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketType {
    /// Long header, type 0x00 — Initial packet (RFC 9000 Section 17.2.2).
    Initial,
    /// Long header, type 0x01 — 0-RTT packet (RFC 9000 Section 17.2.3).
    ZeroRtt,
    /// Long header, type 0x02 — Handshake packet (RFC 9000 Section 17.2.4).
    Handshake,
    /// Long header, type 0x03 — Retry packet (RFC 9000 Section 17.2.5).
    Retry,
    /// Short header — 1-RTT data packet (RFC 9000 Section 17.3).
    OneRtt,
    /// Long header with Fixed Bit = 0 — Version Negotiation (RFC 9000 Section 17.2.1).
    VersionNeg,
}

impl QuicPacketType {
    /// Human-readable name for this packet type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Initial => "Initial",
            Self::ZeroRtt => "0-RTT",
            Self::Handshake => "Handshake",
            Self::Retry => "Retry",
            Self::OneRtt => "1-RTT",
            Self::VersionNeg => "Version Negotiation",
        }
    }
}

/// Determine the QUIC packet type from the first byte.
///
/// `version` should be the 4-byte version field (bytes 1-4 of a long-header
/// packet).  For short-header detection the caller can pass 0.
///
/// Returns `None` if the buffer has fewer than 1 byte.
pub fn packet_type(first_byte: u8, _version: u32) -> QuicPacketType {
    let is_long = first_byte & 0x80 != 0;
    if !is_long {
        return QuicPacketType::OneRtt;
    }

    // Long header
    let fixed_bit = first_byte & 0x40 != 0;
    if !fixed_bit {
        // Version Negotiation packet has Fixed Bit cleared.
        return QuicPacketType::VersionNeg;
    }

    let long_type = (first_byte & 0x30) >> 4;
    match long_type {
        0 => QuicPacketType::Initial,
        1 => QuicPacketType::ZeroRtt,
        2 => QuicPacketType::Handshake,
        3 => QuicPacketType::Retry,
        _ => unreachable!("long_type is always 0..=3"),
    }
}

/// Parsed QUIC Long Header.
#[derive(Debug, Clone)]
pub struct QuicLongHeader {
    /// The packet type.
    pub packet_type: QuicPacketType,
    /// QUIC version (big-endian u32 from bytes 1-4).
    pub version: u32,
    /// Destination Connection ID bytes.
    pub dst_conn_id: Vec<u8>,
    /// Source Connection ID bytes.
    pub src_conn_id: Vec<u8>,
    /// Total byte length of the long header (up to and including `src_conn_id`).
    /// Type-specific fields (token, length, packet number) are NOT included.
    pub header_len: usize,
}

impl QuicLongHeader {
    /// Minimum bytes required for a valid long header (before connection IDs).
    ///
    /// 1 (first byte) + 4 (version) + 1 (DCIL) = 6 bytes minimum.
    const MIN_LEN: usize = 6;

    /// Parse a QUIC Long Header from `buf`.
    ///
    /// Returns `None` if:
    /// - the buffer is too short,
    /// - bit 7 of the first byte is 0 (short header), or
    /// - the connection ID lengths extend beyond the buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::MIN_LEN {
            return None;
        }

        let first_byte = buf[0];
        if first_byte & 0x80 == 0 {
            // Short header, not a long header.
            return None;
        }

        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let pkt_type = packet_type(first_byte, version);

        // Byte 5: Destination Connection ID length
        let dcil = buf[5] as usize;
        let mut pos = 6;

        if pos + dcil > buf.len() {
            return None;
        }
        let dst_conn_id = buf[pos..pos + dcil].to_vec();
        pos += dcil;

        // Next byte: Source Connection ID length
        if pos >= buf.len() {
            return None;
        }
        let scil = buf[pos] as usize;
        pos += 1;

        if pos + scil > buf.len() {
            return None;
        }
        let src_conn_id = buf[pos..pos + scil].to_vec();
        pos += scil;

        Some(Self {
            packet_type: pkt_type,
            version,
            dst_conn_id,
            src_conn_id,
            header_len: pos,
        })
    }
}

/// Parsed QUIC Short Header (1-RTT).
///
/// In practice the destination connection ID length is negotiated during the
/// handshake and is not encoded in the short header.  For pcap-level parsing
/// where this length is unknown, we default to a 0-byte connection ID.
#[derive(Debug, Clone)]
pub struct QuicShortHeader {
    /// Destination Connection ID bytes (may be empty if length is unknown).
    pub dst_conn_id: Vec<u8>,
    /// Total byte length consumed by the short header (first byte + connection ID).
    pub header_len: usize,
}

impl QuicShortHeader {
    /// Parse a QUIC Short Header from `buf`.
    ///
    /// `conn_id_len` is the negotiated destination connection ID length.  When
    /// parsing captured packets without prior handshake context, pass `0`.
    ///
    /// Returns `None` if the buffer is too short or bit 7 of the first byte is
    /// set (long header).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        Self::parse_with_conn_id_len(buf, 0)
    }

    /// Parse a QUIC Short Header, specifying the known connection ID length.
    pub fn parse_with_conn_id_len(buf: &[u8], conn_id_len: usize) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }

        let first_byte = buf[0];
        if first_byte & 0x80 != 0 {
            // Long header, not a short header.
            return None;
        }

        let header_len = 1 + conn_id_len;
        if buf.len() < header_len {
            return None;
        }

        let dst_conn_id = buf[1..1 + conn_id_len].to_vec();

        Some(Self {
            dst_conn_id,
            header_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_short_header() {
        // bit 7 = 0 => short header (1-RTT)
        assert_eq!(packet_type(0x40, 0), QuicPacketType::OneRtt);
        assert_eq!(packet_type(0x00, 0), QuicPacketType::OneRtt);
    }

    #[test]
    fn test_packet_type_version_neg() {
        // bit 7 = 1, bit 6 = 0 => Version Negotiation
        assert_eq!(packet_type(0x80, 0), QuicPacketType::VersionNeg);
    }

    #[test]
    fn test_packet_type_initial() {
        // bit 7 = 1, bit 6 = 1, bits 5-4 = 00 => Initial
        assert_eq!(packet_type(0xC0, 1), QuicPacketType::Initial);
    }

    #[test]
    fn test_packet_type_handshake() {
        // bit 7 = 1, bit 6 = 1, bits 5-4 = 10 => Handshake
        assert_eq!(packet_type(0xE0, 1), QuicPacketType::Handshake);
    }

    #[test]
    fn test_packet_type_retry() {
        // bit 7 = 1, bit 6 = 1, bits 5-4 = 11 => Retry
        assert_eq!(packet_type(0xF0, 1), QuicPacketType::Retry);
    }

    #[test]
    fn test_long_header_parse_initial() {
        // Initial packet: 0xC0 | pkt_num_len=0 => 0xC0
        // Version = 1 (0x00000001)
        // DCID len = 8, SCID len = 0
        let mut buf = vec![
            0xC0u8, // first byte: long, fixed, Initial
            0x00, 0x00, 0x00, 0x01, // version = 1
            0x08, // DCIL = 8
        ];
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // DCID
        buf.push(0x00); // SCIL = 0

        let hdr = QuicLongHeader::parse(&buf).unwrap();
        assert_eq!(hdr.packet_type, QuicPacketType::Initial);
        assert_eq!(hdr.version, 1);
        assert_eq!(hdr.dst_conn_id, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(hdr.src_conn_id, vec![]);
        assert_eq!(hdr.header_len, 6 + 8 + 1); // first+version+dcil + dcid + scil
    }

    #[test]
    fn test_long_header_parse_too_short() {
        let buf = [0xC0u8, 0x00, 0x00]; // way too short
        assert!(QuicLongHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_long_header_parse_short_header_rejected() {
        // bit 7 = 0 => short header, should return None for long header parser
        let buf = [0x40u8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert!(QuicLongHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_short_header_parse() {
        let buf = [0x40u8, 0xAA, 0xBB]; // short header, no conn id
        let hdr = QuicShortHeader::parse(&buf).unwrap();
        assert_eq!(hdr.dst_conn_id, vec![]);
        assert_eq!(hdr.header_len, 1);
    }

    #[test]
    fn test_short_header_parse_with_conn_id() {
        let buf = [0x40u8, 0x01, 0x02, 0x03, 0x04]; // short header + 4-byte conn id
        let hdr = QuicShortHeader::parse_with_conn_id_len(&buf, 4).unwrap();
        assert_eq!(hdr.dst_conn_id, vec![1, 2, 3, 4]);
        assert_eq!(hdr.header_len, 5);
    }

    #[test]
    fn test_short_header_parse_long_rejected() {
        // bit 7 = 1 => long header, should return None for short header parser
        let buf = [0xC0u8, 0x01, 0x02];
        assert!(QuicShortHeader::parse(&buf).is_none());
    }

    #[test]
    fn test_packet_type_names() {
        assert_eq!(QuicPacketType::Initial.name(), "Initial");
        assert_eq!(QuicPacketType::ZeroRtt.name(), "0-RTT");
        assert_eq!(QuicPacketType::Handshake.name(), "Handshake");
        assert_eq!(QuicPacketType::Retry.name(), "Retry");
        assert_eq!(QuicPacketType::OneRtt.name(), "1-RTT");
        assert_eq!(QuicPacketType::VersionNeg.name(), "Version Negotiation");
    }
}
