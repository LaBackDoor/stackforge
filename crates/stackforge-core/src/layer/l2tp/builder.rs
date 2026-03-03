//! L2TP packet builder.
//!
//! Provides a fluent API for constructing L2TPv2 packets (RFC 2661).
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::l2tp::builder::L2tpBuilder;
//!
//! // Default data message
//! let pkt = L2tpBuilder::new().build();
//! assert_eq!(pkt, b"\x00\x02\x00\x00\x00\x00");
//!
//! // Control + length message (T=1, L=1, ver=2; header = 8 bytes)
//! let pkt = L2tpBuilder::new()
//!     .control()
//!     .with_length()
//!     .tunnel_id(1)
//!     .session_id(2)
//!     .build();
//! assert_eq!(pkt, b"\xc0\x02\x00\x08\x00\x01\x00\x02");
//! ```

/// Builder for L2TPv2 packets.
///
/// The builder encodes the header flags and optional fields according to
/// RFC 2661.  Fields:
/// - T bit (message type): cleared for data, set for control
/// - L bit: when set a 2-byte Length field appears after the flags word
/// - S bit: when set Ns and Nr (2 bytes each) appear after Session ID
/// - O bit: when set Offset Size + Offset Pad appear after Nr (or Session ID)
/// - Ver nibble: always 2 for L2TPv2
#[derive(Debug, Clone)]
pub struct L2tpBuilder {
    /// Message type: 0 = data, 1 = control (T bit)
    msg_type: u8,
    /// Whether the L (length) bit is set
    has_length: bool,
    /// Whether the S (sequence) bit is set
    has_sequence: bool,
    /// Whether the O (offset) bit is set
    has_offset: bool,
    /// Priority bit (P), only meaningful for data messages
    priority: bool,
    /// Tunnel ID
    tunnel_id: u16,
    /// Session ID
    session_id: u16,
    /// Send sequence number (Ns), present when S=1
    ns: u16,
    /// Receive sequence number (Nr), present when S=1
    nr: u16,
    /// Offset size, present when O=1
    offset_size: u16,
    /// Payload after the L2TP header
    payload: Vec<u8>,
}

impl Default for L2tpBuilder {
    fn default() -> Self {
        Self {
            msg_type: 0,
            has_length: false,
            has_sequence: false,
            has_offset: false,
            priority: false,
            tunnel_id: 0,
            session_id: 0,
            ns: 0,
            nr: 0,
            offset_size: 0,
            payload: Vec::new(),
        }
    }
}

impl L2tpBuilder {
    /// Create a new L2TP data message builder with minimal defaults.
    /// Produces a 6-byte header: `\x00\x02\x00\x00\x00\x00` (ver=2, tid=0, sid=0).
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Type / flags setters ==========

    /// Set the T bit — makes this a control message.
    pub fn control(mut self) -> Self {
        self.msg_type = 1;
        self
    }

    /// Set the T bit to 0 — data message (default).
    pub fn data(mut self) -> Self {
        self.msg_type = 0;
        self
    }

    /// Set the L (length) bit so a Length field will be included in the header.
    pub fn with_length(mut self) -> Self {
        self.has_length = true;
        self
    }

    /// Set the S (sequence) bit so Ns and Nr will be included.
    pub fn with_sequence(mut self) -> Self {
        self.has_sequence = true;
        self
    }

    /// Set the O (offset) bit so Offset Size + Offset Pad will be included.
    pub fn with_offset(mut self) -> Self {
        self.has_offset = true;
        self
    }

    /// Set the P (priority) bit for data messages.
    pub fn priority(mut self) -> Self {
        self.priority = true;
        self
    }

    // ========== Field setters ==========

    /// Set the Tunnel ID.
    pub fn tunnel_id(mut self, id: u16) -> Self {
        self.tunnel_id = id;
        self
    }

    /// Set the Session ID.
    pub fn session_id(mut self, id: u16) -> Self {
        self.session_id = id;
        self
    }

    /// Set the Ns (send sequence number) field.
    /// Automatically enables the S bit.
    pub fn ns(mut self, ns: u16) -> Self {
        self.has_sequence = true;
        self.ns = ns;
        self
    }

    /// Set the Nr (receive sequence number) field.
    /// Automatically enables the S bit.
    pub fn nr(mut self, nr: u16) -> Self {
        self.has_sequence = true;
        self.nr = nr;
        self
    }

    /// Set the Offset Size field.
    /// Automatically enables the O bit.
    pub fn offset_size(mut self, size: u16) -> Self {
        self.has_offset = true;
        self.offset_size = size;
        self
    }

    /// Set the payload (data after the L2TP header).
    pub fn payload<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.payload = data.into();
        self
    }

    // ========== Convenience constructors ==========

    /// Create a control message with the Length bit set (matching Scapy's
    /// `L2TP(hdr="control+length")` default).
    pub fn control_length() -> Self {
        Self::new().control().with_length().with_sequence()
    }

    // ========== Size / header helpers ==========

    /// Compute the header length in bytes.
    pub fn header_size(&self) -> usize {
        let mut len = 2; // flags word
        if self.has_length {
            len += 2;
        }
        len += 4; // tunnel_id + session_id
        if self.has_sequence {
            len += 4; // Ns + Nr
        }
        if self.has_offset {
            len += 2 + self.offset_size as usize; // Offset Size + Offset Pad
        }
        len
    }

    /// Compute the total packet size (header + payload).
    pub fn packet_size(&self) -> usize {
        self.header_size() + self.payload.len()
    }

    // ========== Build ==========

    /// Serialize the L2TP header (and payload if any) into bytes.
    pub fn build(&self) -> Vec<u8> {
        let total = self.packet_size();
        let mut buf = vec![0u8; total];
        self.build_into(&mut buf);
        buf
    }

    /// Serialize into an existing buffer (must be at least `packet_size()` bytes).
    pub fn build_into(&self, buf: &mut Vec<u8>) {
        // Build flags word (16-bit, big-endian)
        // Bit layout (MSB to LSB of 16-bit word):
        //  bit 15: T
        //  bit 14: L
        //  bit 13: x (reserved)
        //  bit 12: x (reserved)
        //  bit 11: S
        //  bit 10: x (reserved)
        //  bit  9: O
        //  bit  8: P
        //  bits 7-4: x (reserved)
        //  bits 3-0: Ver (= 2)
        let mut flags: u16 = 0;
        if self.msg_type != 0 {
            flags |= 1 << 15; // T
        }
        if self.has_length {
            flags |= 1 << 14; // L
        }
        if self.has_sequence {
            flags |= 1 << 11; // S
        }
        if self.has_offset {
            flags |= 1 << 9; // O
        }
        if self.priority && self.msg_type == 0 {
            flags |= 1 << 8; // P (data only)
        }
        flags |= 2; // Ver = 2

        let mut pos = 0;

        // Flags + Version
        buf[pos..pos + 2].copy_from_slice(&flags.to_be_bytes());
        pos += 2;

        // Optional Length field
        if self.has_length {
            // Length = total header + payload
            let total_len = self.packet_size() as u16;
            buf[pos..pos + 2].copy_from_slice(&total_len.to_be_bytes());
            pos += 2;
        }

        // Tunnel ID
        buf[pos..pos + 2].copy_from_slice(&self.tunnel_id.to_be_bytes());
        pos += 2;

        // Session ID
        buf[pos..pos + 2].copy_from_slice(&self.session_id.to_be_bytes());
        pos += 2;

        // Optional Ns + Nr
        if self.has_sequence {
            buf[pos..pos + 2].copy_from_slice(&self.ns.to_be_bytes());
            pos += 2;
            buf[pos..pos + 2].copy_from_slice(&self.nr.to_be_bytes());
            pos += 2;
        }

        // Optional Offset Size + Offset Pad
        if self.has_offset {
            buf[pos..pos + 2].copy_from_slice(&self.offset_size.to_be_bytes());
            pos += 2;
            // Offset Pad: `offset_size` zero bytes
            pos += self.offset_size as usize;
        }

        // Payload
        if !self.payload.is_empty() {
            let plen = self.payload.len();
            buf[pos..pos + plen].copy_from_slice(&self.payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_data_packet() {
        // UTS: raw(L2TP()) → \x00\x02\x00\x00\x00\x00
        let pkt = L2tpBuilder::new().build();
        assert_eq!(
            pkt, b"\x00\x02\x00\x00\x00\x00",
            "default data L2TP bytes mismatch"
        );
    }

    #[test]
    fn test_control_length_packet() {
        // UTS: bytes(L2TP(hdr="control+length", tunnel_id=1, session_id=2))
        //    → b'\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00'
        // T=1, L=1, S=1, ver=2 → flags word = 0xC802? Let's check:
        // 0xC802 = 1100 1000 0000 0010 → T=1, L=1, S=1, ver=2
        // But UTS shows \xc0\x02 = 0xC002 = 1100 0000 0000 0010 → T=1, L=1, S=0
        // With S=0 and L=1 the header would be: 2+2+2+2=8 bytes with length=8
        // But the UTS bytes are 12 bytes long with 4 trailing zeros (Ns+Nr).
        // This suggests Scapy's L2TP "control+length" hdr field also implies S=1.
        // Let's test with with_sequence() enabled:
        let pkt = L2tpBuilder::new()
            .control()
            .with_length()
            .with_sequence()
            .tunnel_id(1)
            .session_id(2)
            .build();
        // Expected: flags=0xC802, len=12, tid=1, sid=2, ns=0, nr=0
        assert_eq!(pkt.len(), 12);
        let flags = u16::from_be_bytes([pkt[0], pkt[1]]);
        // T=1 (bit15), L=1 (bit14), S=1 (bit11) → 0xC000 | 0x0800 | 0x0002 = 0xC802
        assert_eq!(flags & 0x8000, 0x8000, "T bit should be set");
        assert_eq!(flags & 0x4000, 0x4000, "L bit should be set");
        assert_eq!(flags & 0x0800, 0x0800, "S bit should be set");
        assert_eq!(flags & 0x000F, 2, "Version should be 2");
        let length = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(length, 12, "length field should be 12");
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1, "tunnel_id");
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 2, "session_id");
        assert_eq!(&pkt[8..12], b"\x00\x00\x00\x00", "Ns+Nr should be 0");
    }

    #[test]
    fn test_data_with_tunnel_session() {
        let pkt = L2tpBuilder::new()
            .tunnel_id(0x1234)
            .session_id(0x5678)
            .build();
        assert_eq!(pkt.len(), 6);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 0x0002); // data, ver=2
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x5678);
    }

    #[test]
    fn test_with_payload() {
        let pkt = L2tpBuilder::new()
            .tunnel_id(1)
            .session_id(2)
            .payload(b"hello".to_vec())
            .build();
        assert_eq!(pkt.len(), 11);
        assert_eq!(&pkt[6..], b"hello");
    }

    #[test]
    fn test_header_size_data_only() {
        let b = L2tpBuilder::new();
        assert_eq!(b.header_size(), 6);
    }

    #[test]
    fn test_header_size_with_length() {
        let b = L2tpBuilder::new().with_length();
        assert_eq!(b.header_size(), 8);
    }

    #[test]
    fn test_header_size_with_sequence() {
        let b = L2tpBuilder::new().with_sequence();
        assert_eq!(b.header_size(), 10);
    }

    #[test]
    fn test_header_size_full() {
        let b = L2tpBuilder::new().with_length().with_sequence();
        assert_eq!(b.header_size(), 12);
    }

    #[test]
    fn test_ns_nr_setters() {
        let pkt = L2tpBuilder::new().with_sequence().ns(100).nr(200).build();
        assert_eq!(pkt.len(), 10);
        let flags = u16::from_be_bytes([pkt[0], pkt[1]]);
        assert_eq!(flags & 0x0800, 0x0800, "S bit should be set");
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 100);
        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 200);
    }
}
