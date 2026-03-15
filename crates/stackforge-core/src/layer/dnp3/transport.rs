//! DNP3 Transport layer fragment handling.
//!
//! The transport layer sits between the link layer and the application layer.
//! It provides segmentation and reassembly of application-layer messages.
//!
//! ## Transport Header Format (1 byte)
//!
//! ```text
//! Bit 7: FIN (final fragment)
//! Bit 6: FIR (first fragment)
//! Bits 5-0: SEQ (sequence number, 0-63)
//! ```

/// A DNP3 transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeader {
    /// Final fragment flag.
    pub fin: bool,
    /// First fragment flag.
    pub fir: bool,
    /// Sequence number (0-63).
    pub seq: u8,
}

impl TransportHeader {
    /// Parse a transport header from a single byte.
    #[inline]
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        Self {
            fin: byte & 0x80 != 0,
            fir: byte & 0x40 != 0,
            seq: byte & 0x3F,
        }
    }

    /// Build the transport header into a single byte.
    #[inline]
    #[must_use]
    pub fn build(&self) -> u8 {
        let mut b = self.seq & 0x3F;
        if self.fir {
            b |= 0x40;
        }
        if self.fin {
            b |= 0x80;
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fir_fin() {
        let h = TransportHeader::parse(0xC0);
        assert!(h.fin);
        assert!(h.fir);
        assert_eq!(h.seq, 0);
    }

    #[test]
    fn test_parse_seq_only() {
        let h = TransportHeader::parse(0x1F);
        assert!(!h.fin);
        assert!(!h.fir);
        assert_eq!(h.seq, 31);
    }

    #[test]
    fn test_parse_all_bits() {
        let h = TransportHeader::parse(0xFF);
        assert!(h.fin);
        assert!(h.fir);
        assert_eq!(h.seq, 63);
    }

    #[test]
    fn test_build_roundtrip() {
        for byte in 0..=255u8 {
            let h = TransportHeader::parse(byte);
            assert_eq!(h.build(), byte);
        }
    }

    #[test]
    fn test_build_specific() {
        let h = TransportHeader {
            fin: true,
            fir: true,
            seq: 5,
        };
        assert_eq!(h.build(), 0xC5);
    }

    #[test]
    fn test_fir_only() {
        let h = TransportHeader::parse(0x40);
        assert!(!h.fin);
        assert!(h.fir);
        assert_eq!(h.seq, 0);
    }

    #[test]
    fn test_fin_only() {
        let h = TransportHeader::parse(0x80);
        assert!(h.fin);
        assert!(!h.fir);
        assert_eq!(h.seq, 0);
    }
}
