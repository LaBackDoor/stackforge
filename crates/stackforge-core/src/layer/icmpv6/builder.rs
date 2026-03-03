//! `ICMPv6` packet builder.
//!
//! Provides a fluent API for constructing `ICMPv6` packets with type-specific
//! fields and automatic checksum calculation using the IPv6 pseudo-header.
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::icmpv6::Icmpv6Builder;
//! use std::net::Ipv6Addr;
//!
//! // Build an echo request
//! let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
//! let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
//! let packet = Icmpv6Builder::echo_request(0x1234, 1)
//!     .set_src_ip(src)
//!     .set_dst_ip(dst)
//!     .build();
//! ```

use std::net::Ipv6Addr;

use super::{ICMPV6_MIN_HEADER_LEN, icmpv6_checksum, offsets, types};

/// Builder for `ICMPv6` packets.
#[derive(Debug, Clone)]
pub struct Icmpv6Builder {
    /// `ICMPv6` Type
    icmpv6_type: u8,
    /// `ICMPv6` Code
    code: u8,
    /// Optional manual checksum override
    checksum: Option<u16>,
    /// Identifier (for echo request/reply)
    id: Option<u16>,
    /// Sequence number (for echo request/reply)
    seq: Option<u16>,
    /// Target IPv6 address (for NS/NA/Redirect)
    target: Option<Ipv6Addr>,
    /// MTU (for Packet Too Big)
    mtu: Option<u32>,
    /// 4-byte type-specific field (bytes 4-7 of header)
    type_specific: [u8; 4],
    /// Payload data (appended after the 8-byte base header)
    payload: Vec<u8>,
    /// If true, compute checksum automatically when src/dst are set
    auto_checksum: bool,
    /// Source IPv6 address (for checksum calculation)
    src_ip: Option<Ipv6Addr>,
    /// Destination IPv6 address (for checksum calculation)
    dst_ip: Option<Ipv6Addr>,
}

impl Default for Icmpv6Builder {
    fn default() -> Self {
        Self {
            icmpv6_type: types::ECHO_REQUEST,
            code: 0,
            checksum: None,
            id: None,
            seq: None,
            target: None,
            mtu: None,
            type_specific: [0; 4],
            payload: Vec::new(),
            auto_checksum: true,
            src_ip: None,
            dst_ip: None,
        }
    }
}

impl Icmpv6Builder {
    /// Create a new `ICMPv6` builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Factory Methods ==========

    /// Create an Echo Request (ping6) packet.
    ///
    /// # Arguments
    /// * `id` - Identifier
    /// * `seq` - Sequence number
    #[must_use]
    pub fn echo_request(id: u16, seq: u16) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::ECHO_REQUEST;
        b.code = 0;
        b.id = Some(id);
        b.seq = Some(seq);
        b.type_specific[0] = (id >> 8) as u8;
        b.type_specific[1] = (id & 0xFF) as u8;
        b.type_specific[2] = (seq >> 8) as u8;
        b.type_specific[3] = (seq & 0xFF) as u8;
        b
    }

    /// Create an Echo Reply (pong6) packet.
    ///
    /// # Arguments
    /// * `id` - Identifier (should match the request)
    /// * `seq` - Sequence number (should match the request)
    #[must_use]
    pub fn echo_reply(id: u16, seq: u16) -> Self {
        let mut b = Self::echo_request(id, seq);
        b.icmpv6_type = types::ECHO_REPLY;
        b
    }

    /// Create a Neighbor Solicitation (NDP) packet.
    ///
    /// # Arguments
    /// * `target` - The IPv6 address being queried
    #[must_use]
    pub fn neighbor_solicitation(target: Ipv6Addr) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::NEIGHBOR_SOLICIT;
        b.code = 0;
        b.target = Some(target);
        // Bytes 4-7 are Reserved (zero)
        b
    }

    /// Create a Neighbor Advertisement (NDP) packet.
    ///
    /// # Arguments
    /// * `target` - The IPv6 address being advertised
    #[must_use]
    pub fn neighbor_advertisement(target: Ipv6Addr) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::NEIGHBOR_ADVERT;
        b.code = 0;
        b.target = Some(target);
        // Bytes 4-7: R|S|O flags (bit 31=Router, bit 30=Solicited, bit 29=Override)
        // Default to Solicited + Override flags set (typical response)
        b.type_specific[0] = 0x60; // S=1, O=1
        b
    }

    /// Create a Router Solicitation (NDP) packet.
    #[must_use]
    pub fn router_solicitation() -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::ROUTER_SOLICIT;
        b.code = 0;
        // Bytes 4-7: Reserved (zero)
        b
    }

    /// Create a Router Advertisement (NDP) packet.
    #[must_use]
    pub fn router_advertisement() -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::ROUTER_ADVERT;
        b.code = 0;
        // Bytes 4-7: Cur Hop Limit, M/O flags, Router Lifetime
        // (left at zero defaults; caller can customize via payload)
        b
    }

    /// Create a Destination Unreachable packet.
    ///
    /// # Arguments
    /// * `code` - Reason code (0=No route, 1=Admin prohibited, 3=Port unreachable, etc.)
    /// * `payload` - The offending packet bytes (or truncation thereof)
    #[must_use]
    pub fn dest_unreachable(code: u8, payload: Vec<u8>) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::DEST_UNREACH;
        b.code = code;
        b.payload = payload;
        // Bytes 4-7: Unused (zero)
        b
    }

    /// Create a Time Exceeded packet.
    ///
    /// # Arguments
    /// * `code` - 0=Hop limit exceeded, 1=Fragment reassembly time exceeded
    /// * `payload` - The offending packet bytes (or truncation thereof)
    #[must_use]
    pub fn time_exceeded(code: u8, payload: Vec<u8>) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::TIME_EXCEEDED;
        b.code = code;
        b.payload = payload;
        // Bytes 4-7: Unused (zero)
        b
    }

    /// Create a Packet Too Big packet.
    ///
    /// # Arguments
    /// * `mtu` - Maximum Transmission Unit of the next-hop link
    /// * `payload` - The offending packet bytes (or truncation thereof)
    #[must_use]
    pub fn pkt_too_big(mtu: u32, payload: Vec<u8>) -> Self {
        let mut b = Self::new();
        b.icmpv6_type = types::PKT_TOO_BIG;
        b.code = 0;
        b.mtu = Some(mtu);
        b.type_specific = [
            (mtu >> 24) as u8,
            ((mtu >> 16) & 0xFF) as u8,
            ((mtu >> 8) & 0xFF) as u8,
            (mtu & 0xFF) as u8,
        ];
        b.payload = payload;
        b
    }

    // ========== Field Setters ==========

    /// Set the `ICMPv6` type manually.
    #[must_use]
    pub fn icmpv6_type(mut self, t: u8) -> Self {
        self.icmpv6_type = t;
        self
    }

    /// Set the `ICMPv6` code.
    #[must_use]
    pub fn code(mut self, c: u8) -> Self {
        self.code = c;
        self
    }

    /// Set the checksum manually (disables auto-checksum).
    #[must_use]
    pub fn checksum(mut self, csum: u16) -> Self {
        self.checksum = Some(csum);
        self.auto_checksum = false;
        self
    }

    /// Alias for checksum (Scapy compatibility).
    #[must_use]
    pub fn chksum(self, csum: u16) -> Self {
        self.checksum(csum)
    }

    /// Set the payload bytes.
    pub fn payload<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.payload = data.into();
        self
    }

    /// Enable automatic checksum calculation (default: true).
    #[must_use]
    pub fn enable_auto_checksum(mut self) -> Self {
        self.auto_checksum = true;
        self.checksum = None;
        self
    }

    /// Disable automatic checksum calculation.
    #[must_use]
    pub fn disable_auto_checksum(mut self) -> Self {
        self.auto_checksum = false;
        self
    }

    /// Set the source IP address (used for checksum calculation).
    #[must_use]
    pub fn set_src_ip(mut self, src: Ipv6Addr) -> Self {
        self.src_ip = Some(src);
        self
    }

    /// Set the destination IP address (used for checksum calculation).
    #[must_use]
    pub fn set_dst_ip(mut self, dst: Ipv6Addr) -> Self {
        self.dst_ip = Some(dst);
        self
    }

    // ========== Size Calculation ==========

    /// Get the total packet size.
    #[must_use]
    pub fn packet_size(&self) -> usize {
        let base = ICMPV6_MIN_HEADER_LEN;
        let extra = match self.icmpv6_type {
            types::NEIGHBOR_SOLICIT | types::NEIGHBOR_ADVERT => 16, // target address
            _ => 0,
        };
        base + extra + self.payload.len()
    }

    /// Get the header size (base 8 bytes + any type-specific fixed fields).
    #[must_use]
    pub fn header_size(&self) -> usize {
        ICMPV6_MIN_HEADER_LEN
    }

    // ========== Build Methods ==========

    /// Build the `ICMPv6` packet into a byte vector.
    ///
    /// # Byte layout:
    /// - Byte 0: type
    /// - Byte 1: code
    /// - Bytes 2-3: checksum (computed or manual or zero)
    /// - Bytes 4-7: type-specific data
    /// - Bytes 8+: type-specific body (target addr for NS/NA) + payload
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let total = self.packet_size();
        let mut buf = vec![0u8; total];

        // Type
        buf[offsets::TYPE] = self.icmpv6_type;

        // Code
        buf[offsets::CODE] = self.code;

        // Checksum: set to zero initially
        buf[offsets::CHECKSUM] = 0;
        buf[offsets::CHECKSUM + 1] = 0;

        // Type-specific bytes 4-7
        buf[4..8].copy_from_slice(&self.type_specific);

        let mut offset = 8;

        // Type-specific body
        match self.icmpv6_type {
            types::NEIGHBOR_SOLICIT | types::NEIGHBOR_ADVERT | types::REDIRECT => {
                if let Some(target) = self.target
                    && offset + 16 <= buf.len()
                {
                    buf[offset..offset + 16].copy_from_slice(&target.octets());
                    offset += 16;
                }
            },
            _ => {},
        }

        // Payload
        if !self.payload.is_empty() && offset + self.payload.len() <= buf.len() {
            buf[offset..offset + self.payload.len()].copy_from_slice(&self.payload);
        }

        // Calculate checksum if auto_checksum is enabled and src/dst are available
        if self.auto_checksum {
            if let (Some(src), Some(dst)) = (self.src_ip, self.dst_ip) {
                let csum = icmpv6_checksum(src, dst, &buf);
                buf[offsets::CHECKSUM] = (csum >> 8) as u8;
                buf[offsets::CHECKSUM + 1] = (csum & 0xFF) as u8;
            }
            // If no src/dst, leave checksum as zero
        } else if let Some(csum) = self.checksum {
            buf[offsets::CHECKSUM] = (csum >> 8) as u8;
            buf[offsets::CHECKSUM + 1] = (csum & 0xFF) as u8;
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request_builder() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let bytes = Icmpv6Builder::echo_request(0x1234, 5)
            .set_src_ip(src)
            .set_dst_ip(dst)
            .payload(b"ping".as_ref())
            .build();

        assert_eq!(bytes[0], types::ECHO_REQUEST);
        assert_eq!(bytes[1], 0); // code
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 0x1234); // id
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 5); // seq
        assert_eq!(&bytes[8..], b"ping");

        // Checksum should be non-zero
        let chksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_ne!(chksum, 0);
    }

    #[test]
    fn test_echo_reply_builder() {
        let bytes = Icmpv6Builder::echo_reply(0x5678, 10).build();

        assert_eq!(bytes[0], types::ECHO_REPLY);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 0x5678);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 10);
    }

    #[test]
    fn test_neighbor_solicitation_builder() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
        let bytes = Icmpv6Builder::neighbor_solicitation(target).build();

        assert_eq!(bytes[0], types::NEIGHBOR_SOLICIT);
        assert_eq!(bytes.len(), 24); // 8 base + 16 target addr

        let mut addr_bytes = [0u8; 16];
        addr_bytes.copy_from_slice(&bytes[8..24]);
        assert_eq!(Ipv6Addr::from(addr_bytes), target);
    }

    #[test]
    fn test_neighbor_advertisement_builder() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
        let bytes = Icmpv6Builder::neighbor_advertisement(target).build();

        assert_eq!(bytes[0], types::NEIGHBOR_ADVERT);
        assert_eq!(bytes.len(), 24); // 8 base + 16 target addr
        // S and O flags should be set
        assert_eq!(bytes[4] & 0x60, 0x60);
    }

    #[test]
    fn test_router_solicitation_builder() {
        let bytes = Icmpv6Builder::router_solicitation().build();
        assert_eq!(bytes[0], types::ROUTER_SOLICIT);
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_pkt_too_big_builder() {
        let payload = vec![0xAAu8; 20];
        let bytes = Icmpv6Builder::pkt_too_big(1500, payload.clone()).build();

        assert_eq!(bytes[0], types::PKT_TOO_BIG);
        assert_eq!(bytes[1], 0); // code must be 0
        let mtu = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(mtu, 1500);
        assert_eq!(&bytes[8..], payload.as_slice());
    }

    #[test]
    fn test_dest_unreachable_builder() {
        let payload = vec![0u8; 10];
        let bytes = Icmpv6Builder::dest_unreachable(3, payload.clone()).build();

        assert_eq!(bytes[0], types::DEST_UNREACH);
        assert_eq!(bytes[1], 3); // Port unreachable
        assert_eq!(&bytes[8..], payload.as_slice());
    }

    #[test]
    fn test_time_exceeded_builder() {
        let bytes = Icmpv6Builder::time_exceeded(0, vec![]).build();
        assert_eq!(bytes[0], types::TIME_EXCEEDED);
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_manual_checksum() {
        let bytes = Icmpv6Builder::echo_request(1, 1).checksum(0xABCD).build();

        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xABCD);
    }

    #[test]
    fn test_checksum_verification() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let bytes = Icmpv6Builder::echo_request(0x1234, 1)
            .set_src_ip(src)
            .set_dst_ip(dst)
            .build();

        // Verify the checksum
        assert!(super::super::verify_icmpv6_checksum(src, dst, &bytes));
    }

    #[test]
    fn test_no_checksum_without_src_dst() {
        let bytes = Icmpv6Builder::echo_request(1, 1).build();
        // Without src/dst, checksum should be zero
        let chksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(chksum, 0);
    }

    #[test]
    fn test_packet_size() {
        let builder = Icmpv6Builder::echo_request(1, 1).payload(vec![0u8; 10]);
        assert_eq!(builder.packet_size(), 18); // 8 + 10

        let ns_builder = Icmpv6Builder::neighbor_solicitation(Ipv6Addr::LOCALHOST);
        assert_eq!(ns_builder.packet_size(), 24); // 8 + 16
    }
}
