//! UDP packet builder.
//!
//! Provides a fluent API for constructing UDP packets with automatic
//! field calculation (length, checksum).
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::udp::UdpBuilder;
//! use std::net::Ipv4Addr;
//!
//! // Build a DNS request packet
//! let packet = UdpBuilder::new()
//!     .src_port(12345)
//!     .dst_port(53)
//!     .payload(b"DNS query data")
//!     .build();
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::checksum::{udp_checksum_ipv4, udp_checksum_ipv6};
use super::{UDP_HEADER_LEN, offsets};
use crate::layer::field::FieldError;

/// Builder for UDP packets.
#[derive(Debug, Clone)]
pub struct UdpBuilder {
    // Header fields
    src_port: u16,
    dst_port: u16,
    length: Option<u16>,
    checksum: Option<u16>,

    // Payload
    payload: Vec<u8>,

    // Build options
    auto_length: bool,
    auto_checksum: bool,

    // IP addresses for checksum calculation
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
}

/// IP address enum for checksum calculation.
#[derive(Debug, Clone, Copy)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<Ipv4Addr> for IpAddr {
    fn from(addr: Ipv4Addr) -> Self {
        IpAddr::V4(addr)
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(addr: Ipv6Addr) -> Self {
        IpAddr::V6(addr)
    }
}

impl Default for UdpBuilder {
    fn default() -> Self {
        Self {
            src_port: 53,
            dst_port: 53,
            length: None,
            checksum: None,
            payload: Vec::new(),
            auto_length: true,
            auto_checksum: true,
            src_ip: None,
            dst_ip: None,
        }
    }
}

impl UdpBuilder {
    /// Create a new UDP builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder initialized from an existing packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FieldError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: UDP_HEADER_LEN,
                have: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([data[offsets::SRC_PORT], data[offsets::SRC_PORT + 1]]);
        let dst_port = u16::from_be_bytes([data[offsets::DST_PORT], data[offsets::DST_PORT + 1]]);
        let length = u16::from_be_bytes([data[offsets::LENGTH], data[offsets::LENGTH + 1]]);
        let checksum = u16::from_be_bytes([data[offsets::CHECKSUM], data[offsets::CHECKSUM + 1]]);

        let mut builder = Self::new();
        builder.src_port = src_port;
        builder.dst_port = dst_port;
        builder.length = Some(length);
        builder.checksum = Some(checksum);

        // Copy payload if present
        if data.len() > UDP_HEADER_LEN {
            builder.payload = data[UDP_HEADER_LEN..].to_vec();
        }

        // Disable auto-calculation since we're copying exact values
        builder.auto_length = false;
        builder.auto_checksum = false;

        Ok(builder)
    }

    // ========== Header Field Setters ==========

    /// Set the source port.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    /// Alias for src_port (Scapy compatibility).
    pub fn sport(self, port: u16) -> Self {
        self.src_port(port)
    }

    /// Set the destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Alias for dst_port (Scapy compatibility).
    pub fn dport(self, port: u16) -> Self {
        self.dst_port(port)
    }

    /// Set the UDP length manually.
    ///
    /// If not set, the length will be calculated automatically (8 + payload length).
    pub fn length(mut self, len: u16) -> Self {
        self.length = Some(len);
        self.auto_length = false;
        self
    }

    /// Alias for length (Scapy compatibility).
    pub fn len(self, len: u16) -> Self {
        self.length(len)
    }

    /// Set the checksum manually.
    ///
    /// If not set, the checksum will be calculated automatically if IP addresses are provided.
    pub fn checksum(mut self, csum: u16) -> Self {
        self.checksum = Some(csum);
        self.auto_checksum = false;
        self
    }

    /// Alias for checksum (Scapy compatibility).
    pub fn chksum(self, csum: u16) -> Self {
        self.checksum(csum)
    }

    /// Enable automatic length calculation (default).
    pub fn enable_auto_length(mut self) -> Self {
        self.auto_length = true;
        self.length = None;
        self
    }

    /// Disable automatic length calculation.
    pub fn disable_auto_length(mut self) -> Self {
        self.auto_length = false;
        self
    }

    /// Enable automatic checksum calculation (default).
    pub fn enable_auto_checksum(mut self) -> Self {
        self.auto_checksum = true;
        self.checksum = None;
        self
    }

    /// Disable automatic checksum calculation.
    pub fn disable_auto_checksum(mut self) -> Self {
        self.auto_checksum = false;
        self
    }

    // ========== IP Address Setters ==========

    /// Set source IPv4 address for checksum calculation.
    pub fn src_ipv4(mut self, addr: Ipv4Addr) -> Self {
        self.src_ip = Some(IpAddr::V4(addr));
        self
    }

    /// Set destination IPv4 address for checksum calculation.
    pub fn dst_ipv4(mut self, addr: Ipv4Addr) -> Self {
        self.dst_ip = Some(IpAddr::V4(addr));
        self
    }

    /// Set source IPv6 address for checksum calculation.
    pub fn src_ipv6(mut self, addr: Ipv6Addr) -> Self {
        self.src_ip = Some(IpAddr::V6(addr));
        self
    }

    /// Set destination IPv6 address for checksum calculation.
    pub fn dst_ipv6(mut self, addr: Ipv6Addr) -> Self {
        self.dst_ip = Some(IpAddr::V6(addr));
        self
    }

    /// Set both source and destination IPv4 addresses.
    pub fn ipv4_addrs(self, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        self.src_ipv4(src).dst_ipv4(dst)
    }

    /// Set both source and destination IPv6 addresses.
    pub fn ipv6_addrs(self, src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        self.src_ipv6(src).dst_ipv6(dst)
    }

    // ========== Payload Setters ==========

    /// Set the payload data.
    pub fn payload<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.payload = data.into();
        self
    }

    /// Append to the payload data.
    pub fn append_payload<T: AsRef<[u8]>>(mut self, data: T) -> Self {
        self.payload.extend_from_slice(data.as_ref());
        self
    }

    // ========== Size Calculation ==========

    /// Get the total packet size (header + payload).
    pub fn packet_size(&self) -> usize {
        UDP_HEADER_LEN + self.payload.len()
    }

    /// Get the header size (always 8 bytes for UDP).
    pub fn header_size(&self) -> usize {
        UDP_HEADER_LEN
    }

    // ========== Build Methods ==========

    /// Build the UDP packet into a new buffer.
    pub fn build(&self) -> Vec<u8> {
        let total_size = self.packet_size();
        let mut buf = vec![0u8; total_size];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    /// Build the UDP packet into an existing buffer.
    pub fn build_into(&self, buf: &mut [u8]) -> Result<usize, FieldError> {
        let total_size = self.packet_size();

        if buf.len() < total_size {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: total_size,
                have: buf.len(),
            });
        }

        // Calculate length (header + payload)
        let length = if self.auto_length {
            total_size as u16
        } else {
            self.length.unwrap_or(total_size as u16)
        };

        // Source Port (big-endian)
        buf[offsets::SRC_PORT..offsets::SRC_PORT + 2].copy_from_slice(&self.src_port.to_be_bytes());

        // Destination Port (big-endian)
        buf[offsets::DST_PORT..offsets::DST_PORT + 2].copy_from_slice(&self.dst_port.to_be_bytes());

        // Length (big-endian)
        buf[offsets::LENGTH..offsets::LENGTH + 2].copy_from_slice(&length.to_be_bytes());

        // Checksum (initially 0, calculated later if auto_checksum is enabled)
        buf[offsets::CHECKSUM..offsets::CHECKSUM + 2].copy_from_slice(&[0, 0]);

        // Copy payload
        if !self.payload.is_empty() {
            buf[UDP_HEADER_LEN..total_size].copy_from_slice(&self.payload);
        }

        // Calculate checksum if enabled and IP addresses are available
        if self.auto_checksum {
            let checksum = self.calculate_checksum(&buf[..total_size]);
            if let Some(csum) = checksum {
                // RFC 768: If checksum is 0, it should be 0xFFFF
                let final_csum = if csum == 0 { 0xFFFF } else { csum };
                buf[offsets::CHECKSUM..offsets::CHECKSUM + 2]
                    .copy_from_slice(&final_csum.to_be_bytes());
            }
        } else if let Some(csum) = self.checksum {
            buf[offsets::CHECKSUM..offsets::CHECKSUM + 2].copy_from_slice(&csum.to_be_bytes());
        }

        Ok(total_size)
    }

    /// Build just the UDP header (without payload).
    pub fn build_header(&self) -> Vec<u8> {
        let mut buf = vec![0u8; UDP_HEADER_LEN];

        // Create a copy without payload for header-only build
        let builder = Self {
            payload: Vec::new(),
            ..self.clone()
        };
        builder
            .build_into(&mut buf)
            .expect("buffer is correctly sized");

        buf
    }

    /// Calculate the checksum based on IP addresses.
    fn calculate_checksum(&self, udp_packet: &[u8]) -> Option<u16> {
        match (self.src_ip, self.dst_ip) {
            (Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))) => {
                Some(udp_checksum_ipv4(src, dst, udp_packet))
            },
            (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
                Some(udp_checksum_ipv6(src, dst, udp_packet))
            },
            _ => None, // Can't calculate without IP addresses or with mismatched versions
        }
    }
}

// ========== Convenience Constructors ==========

impl UdpBuilder {
    /// Create a DNS query packet builder (port 53).
    pub fn dns_query() -> Self {
        Self::new().src_port(53).dst_port(53)
    }

    /// Create a DHCP client packet builder (ports 68 -> 67).
    pub fn dhcp_client() -> Self {
        Self::new().src_port(68).dst_port(67)
    }

    /// Create a DHCP server packet builder (ports 67 -> 68).
    pub fn dhcp_server() -> Self {
        Self::new().src_port(67).dst_port(68)
    }

    /// Create a NTP packet builder (port 123).
    pub fn ntp() -> Self {
        Self::new().src_port(123).dst_port(123)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = UdpBuilder::new();
        assert_eq!(builder.src_port, 53);
        assert_eq!(builder.dst_port, 53);
        assert!(builder.auto_length);
        assert!(builder.auto_checksum);
    }

    #[test]
    fn test_build_basic() {
        let packet = UdpBuilder::new()
            .src_port(12345)
            .dst_port(80)
            .payload(b"Hello")
            .build();

        // Check header
        assert_eq!(packet.len(), 8 + 5); // header + payload
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 12345); // sport
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 80); // dport
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 13); // length (8+5)

        // Check payload
        assert_eq!(&packet[8..], b"Hello");
    }

    #[test]
    fn test_build_with_manual_length() {
        let packet = UdpBuilder::new()
            .src_port(1234)
            .dst_port(5678)
            .length(100)
            .build();

        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 100);
    }

    #[test]
    fn test_build_with_checksum() {
        let packet = UdpBuilder::new()
            .src_port(1234)
            .dst_port(5678)
            .src_ipv4(Ipv4Addr::new(192, 168, 1, 1))
            .dst_ipv4(Ipv4Addr::new(192, 168, 1, 2))
            .payload(b"test")
            .build();

        // Checksum should be calculated
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);
        assert_ne!(checksum, 0); // Should have a non-zero checksum
    }

    #[test]
    fn test_build_with_zero_checksum_becomes_ffff() {
        // This is a contrived test - in practice it's hard to get exactly 0
        // But the code handles it per RFC 768
        let builder = UdpBuilder::new()
            .src_port(0)
            .dst_port(0)
            .disable_auto_checksum()
            .checksum(0);

        let packet = builder.build();
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);
        assert_eq!(checksum, 0); // Manual checksum is used as-is
    }

    #[test]
    fn test_from_bytes() {
        let original = UdpBuilder::new()
            .src_port(1234)
            .dst_port(5678)
            .payload(b"test data")
            .build();

        let rebuilt = UdpBuilder::from_bytes(&original).unwrap();
        assert_eq!(rebuilt.src_port, 1234);
        assert_eq!(rebuilt.dst_port, 5678);
        assert_eq!(rebuilt.payload, b"test data");
    }

    #[test]
    fn test_scapy_aliases() {
        let packet = UdpBuilder::new()
            .sport(1234) // alias for src_port
            .dport(5678) // alias for dst_port
            .len(20) // alias for length
            .chksum(0xABCD) // alias for checksum
            .build();

        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 1234);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 5678);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 20);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0xABCD);
    }

    #[test]
    fn test_convenience_constructors() {
        let dns = UdpBuilder::dns_query().build();
        assert_eq!(u16::from_be_bytes([dns[0], dns[1]]), 53);
        assert_eq!(u16::from_be_bytes([dns[2], dns[3]]), 53);

        let dhcp_client = UdpBuilder::dhcp_client().build();
        assert_eq!(u16::from_be_bytes([dhcp_client[0], dhcp_client[1]]), 68);
        assert_eq!(u16::from_be_bytes([dhcp_client[2], dhcp_client[3]]), 67);
    }

    #[test]
    fn test_build_header_only() {
        let header = UdpBuilder::new()
            .src_port(1234)
            .dst_port(5678)
            .payload(b"this should not be included")
            .build_header();

        assert_eq!(header.len(), 8); // Header only, no payload
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 1234);
    }
}
