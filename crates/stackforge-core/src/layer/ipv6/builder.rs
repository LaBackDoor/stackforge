//! IPv6 packet builder.
//!
//! Provides a fluent API for constructing IPv6 packet headers.
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::ipv6::Ipv6Builder;
//! use std::net::Ipv6Addr;
//!
//! let bytes = Ipv6Builder::new()
//!     .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
//!     .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
//!     .hop_limit(64)
//!     .next_header(58) // ICMPv6
//!     .build();
//!
//! assert_eq!(bytes.len(), 40); // IPv6 header only (no payload)
//! ```

use std::net::Ipv6Addr;

use super::IPV6_HEADER_LEN;

/// Builder for IPv6 packet headers.
#[derive(Debug, Clone)]
pub struct Ipv6Builder {
    /// Traffic Class (8 bits, DSCP+ECN)
    traffic_class: u8,
    /// Flow Label (20 bits)
    flow_label: u32,
    /// Next Header protocol number
    next_header: u8,
    /// Hop Limit (analogous to TTL in IPv4)
    hop_limit: u8,
    /// Source IPv6 address
    src: Ipv6Addr,
    /// Destination IPv6 address
    dst: Ipv6Addr,
    /// Payload bytes (appended after the 40-byte header)
    payload: Vec<u8>,
    /// If true, automatically compute `payload_len` from `payload.len()`
    auto_length: bool,
    /// Manual override for payload length (ignored if `auto_length=true`)
    payload_len_override: Option<u16>,
}

impl Default for Ipv6Builder {
    fn default() -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            next_header: 59, // No next header
            hop_limit: 64,
            src: Ipv6Addr::UNSPECIFIED,
            dst: Ipv6Addr::UNSPECIFIED,
            payload: Vec::new(),
            auto_length: true,
            payload_len_override: None,
        }
    }
}

impl Ipv6Builder {
    /// Create a new IPv6 builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Field Setters ==========

    /// Set the source IPv6 address.
    #[must_use]
    pub fn src(mut self, src: Ipv6Addr) -> Self {
        self.src = src;
        self
    }

    /// Set the destination IPv6 address.
    #[must_use]
    pub fn dst(mut self, dst: Ipv6Addr) -> Self {
        self.dst = dst;
        self
    }

    /// Set the Hop Limit (equivalent to TTL in IPv4).
    #[must_use]
    pub fn hop_limit(mut self, hlim: u8) -> Self {
        self.hop_limit = hlim;
        self
    }

    /// Set the Traffic Class field.
    #[must_use]
    pub fn traffic_class(mut self, tc: u8) -> Self {
        self.traffic_class = tc;
        self
    }

    /// Set the Flow Label (20 bits; upper 12 bits are ignored).
    #[must_use]
    pub fn flow_label(mut self, fl: u32) -> Self {
        self.flow_label = fl & 0x000F_FFFF;
        self
    }

    /// Set the Next Header field.
    #[must_use]
    pub fn next_header(mut self, nh: u8) -> Self {
        self.next_header = nh;
        self
    }

    /// Set the payload bytes (appended after the 40-byte header).
    pub fn payload<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.payload = data.into();
        self
    }

    /// Configure automatic payload length calculation (default: true).
    #[must_use]
    pub fn auto_length(mut self, auto: bool) -> Self {
        self.auto_length = auto;
        self
    }

    /// Manually override the payload length field.
    ///
    /// Only used when `auto_length` is false.
    #[must_use]
    pub fn payload_len(mut self, len: u16) -> Self {
        self.payload_len_override = Some(len);
        self.auto_length = false;
        self
    }

    // ========== Size Calculation ==========

    /// Get the header size (always 40 bytes for IPv6).
    #[must_use]
    pub fn header_size(&self) -> usize {
        IPV6_HEADER_LEN
    }

    /// Get the total packet size (header + payload).
    #[must_use]
    pub fn packet_size(&self) -> usize {
        IPV6_HEADER_LEN + self.payload.len()
    }

    // ========== Build Methods ==========

    /// Build the IPv6 header + payload into a byte vector.
    ///
    /// # Byte layout:
    /// - Byte 0: version (6) in high 4 bits | TC high nibble in low 4 bits
    /// - Byte 1: TC low nibble in high 4 bits | FL bits 19-16 in low 4 bits
    /// - Bytes 2-3: FL bits 15-0 (big-endian)
    /// - Bytes 4-5: `payload_len` (big-endian)
    /// - Byte 6: `next_header`
    /// - Byte 7: `hop_limit`
    /// - Bytes 8-23: source address (16 bytes)
    /// - Bytes 24-39: destination address (16 bytes)
    /// - Bytes 40+: payload
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let total = self.packet_size();
        let mut buf = vec![0u8; total];

        // Byte 0: version (6) high nibble | TC high nibble low nibble
        buf[0] = 0x60 | ((self.traffic_class >> 4) & 0x0F);

        // Byte 1: TC low nibble high nibble | FL bits 19-16 low nibble
        buf[1] = ((self.traffic_class & 0x0F) << 4) | (((self.flow_label >> 16) & 0x0F) as u8);

        // Bytes 2-3: FL bits 15-0
        buf[2] = ((self.flow_label >> 8) & 0xFF) as u8;
        buf[3] = (self.flow_label & 0xFF) as u8;

        // Bytes 4-5: payload length
        let plen: u16 = if self.auto_length {
            self.payload.len() as u16
        } else {
            self.payload_len_override
                .unwrap_or(self.payload.len() as u16)
        };
        buf[4] = (plen >> 8) as u8;
        buf[5] = (plen & 0xFF) as u8;

        // Byte 6: next header
        buf[6] = self.next_header;

        // Byte 7: hop limit
        buf[7] = self.hop_limit;

        // Bytes 8-23: source address
        buf[8..24].copy_from_slice(&self.src.octets());

        // Bytes 24-39: destination address
        buf[24..40].copy_from_slice(&self.dst.octets());

        // Bytes 40+: payload
        if !self.payload.is_empty() {
            buf[40..40 + self.payload.len()].copy_from_slice(&self.payload);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_builder_basic() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let bytes = Ipv6Builder::new()
            .src(src)
            .dst(dst)
            .hop_limit(64)
            .next_header(58)
            .build();

        assert_eq!(bytes.len(), 40);
        // Version = 6
        assert_eq!((bytes[0] >> 4) & 0x0F, 6);
        // Next header = 58 (ICMPv6)
        assert_eq!(bytes[6], 58);
        // Hop limit = 64
        assert_eq!(bytes[7], 64);
        // Source address
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&bytes[8..24]);
        assert_eq!(Ipv6Addr::from(src_bytes), src);
        // Destination address
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&bytes[24..40]);
        assert_eq!(Ipv6Addr::from(dst_bytes), dst);
    }

    #[test]
    fn test_ipv6_builder_with_payload() {
        let payload = b"hello world";
        let bytes = Ipv6Builder::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::LOCALHOST)
            .next_header(59)
            .payload(payload.as_ref())
            .build();

        assert_eq!(bytes.len(), 40 + payload.len());
        // Payload length in header
        let plen = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(plen as usize, payload.len());
        // Payload bytes at offset 40
        assert_eq!(&bytes[40..], payload.as_ref());
    }

    #[test]
    fn test_ipv6_traffic_class() {
        let bytes = Ipv6Builder::new().traffic_class(0xAB).build();

        // Byte 0: 0x60 | (0xAB >> 4 = 0x0A) = 0x6A
        assert_eq!(bytes[0], 0x6A);
        // Byte 1: (0xAB & 0x0F = 0x0B) << 4 = 0xB0
        assert_eq!(bytes[1] & 0xF0, 0xB0);
        // Reconstruct TC
        let tc = ((bytes[0] & 0x0F) << 4) | ((bytes[1] >> 4) & 0x0F);
        assert_eq!(tc, 0xAB);
    }

    #[test]
    fn test_ipv6_flow_label() {
        let bytes = Ipv6Builder::new().flow_label(0x12345).build();

        // FL bits 19-16 in byte 1 low nibble
        assert_eq!(bytes[1] & 0x0F, 0x01);
        // FL bits 15-8 in byte 2
        assert_eq!(bytes[2], 0x23);
        // FL bits 7-0 in byte 3
        assert_eq!(bytes[3], 0x45);
        // Reconstruct FL
        let fl = ((bytes[1] as u32 & 0x0F) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32);
        assert_eq!(fl, 0x12345);
    }

    #[test]
    fn test_ipv6_manual_payload_len() {
        let bytes = Ipv6Builder::new()
            .payload(vec![0u8; 20])
            .payload_len(100) // Override with manual value
            .build();

        let plen = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(plen, 100);
    }

    #[test]
    fn test_ipv6_header_size() {
        let builder = Ipv6Builder::new();
        assert_eq!(builder.header_size(), 40);
    }
}
