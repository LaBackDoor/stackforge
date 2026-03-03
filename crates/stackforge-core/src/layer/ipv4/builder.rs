//! IPv4 packet builder.
//!
//! Provides a fluent API for constructing IPv4 packets with automatic
//! field calculation (checksum, length, IHL).

use std::net::Ipv4Addr;

use super::checksum::ipv4_checksum;
use super::header::{IPV4_MIN_HEADER_LEN, Ipv4Flags, Ipv4Layer, offsets};
use super::options::{Ipv4Option, Ipv4Options, Ipv4OptionsBuilder};
use super::protocol;
use crate::layer::field::FieldError;

/// Builder for IPv4 packets.
///
/// # Example
///
/// ```rust
/// use stackforge_core::layer::ipv4::{Ipv4Builder, protocol};
/// use std::net::Ipv4Addr;
///
/// let packet = Ipv4Builder::new()
///     .src(Ipv4Addr::new(192, 168, 1, 1))
///     .dst(Ipv4Addr::new(192, 168, 1, 2))
///     .ttl(64)
///     .protocol(protocol::TCP)
///     .dont_fragment()
///     .build();
///
/// assert_eq!(packet.len(), 20); // Minimum header, no payload
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Builder {
    // Header fields
    version: u8,
    ihl: Option<u8>,
    tos: u8,
    total_len: Option<u16>,
    id: u16,
    flags: Ipv4Flags,
    frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: Option<u16>,
    src: Ipv4Addr,
    dst: Ipv4Addr,

    // Options
    options: Ipv4Options,

    // Payload
    payload: Vec<u8>,

    // Build options
    auto_checksum: bool,
    auto_length: bool,
    auto_ihl: bool,
}

impl Default for Ipv4Builder {
    fn default() -> Self {
        Self {
            version: 4,
            ihl: None,
            tos: 0,
            total_len: None,
            id: 1,
            flags: Ipv4Flags::NONE,
            frag_offset: 0,
            ttl: 64,
            protocol: 0,
            checksum: None,
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::LOCALHOST,
            options: Ipv4Options::new(),
            payload: Vec::new(),
            auto_checksum: true,
            auto_length: true,
            auto_ihl: true,
        }
    }
}

impl Ipv4Builder {
    /// Create a new IPv4 builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder initialized from an existing packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FieldError> {
        let layer = Ipv4Layer::at_offset_dynamic(data, 0)?;

        let mut builder = Self::new();
        builder.version = layer.version(data)?;
        builder.ihl = Some(layer.ihl(data)?);
        builder.tos = layer.tos(data)?;
        builder.total_len = Some(layer.total_len(data)?);
        builder.id = layer.id(data)?;
        builder.flags = layer.flags(data)?;
        builder.frag_offset = layer.frag_offset(data)?;
        builder.ttl = layer.ttl(data)?;
        builder.protocol = layer.protocol(data)?;
        builder.checksum = Some(layer.checksum(data)?);
        builder.src = layer.src(data)?;
        builder.dst = layer.dst(data)?;

        // Parse options if present
        if layer.options_len(data) > 0 {
            builder.options = layer.options(data)?;
        }

        // Copy payload
        let header_len = layer.calculate_header_len(data);
        let total_len = layer.total_len(data)? as usize;
        if total_len > header_len && data.len() >= total_len {
            builder.payload = data[header_len..total_len].to_vec();
        }

        // Disable auto-calculation since we're copying exact values
        builder.auto_checksum = false;
        builder.auto_length = false;
        builder.auto_ihl = false;

        Ok(builder)
    }

    // ========== Header Field Setters ==========

    /// Set the IP version (should normally be 4).
    #[must_use]
    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set the Internet Header Length (in 32-bit words).
    /// If not set, will be calculated automatically.
    #[must_use]
    pub fn ihl(mut self, ihl: u8) -> Self {
        self.ihl = Some(ihl);
        self.auto_ihl = false;
        self
    }

    /// Set the Type of Service field.
    #[must_use]
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = tos;
        self
    }

    /// Set the DSCP (Differentiated Services Code Point).
    #[must_use]
    pub fn dscp(mut self, dscp: u8) -> Self {
        self.tos = (self.tos & 0x03) | ((dscp & 0x3F) << 2);
        self
    }

    /// Set the ECN (Explicit Congestion Notification).
    #[must_use]
    pub fn ecn(mut self, ecn: u8) -> Self {
        self.tos = (self.tos & 0xFC) | (ecn & 0x03);
        self
    }

    /// Set the total length field.
    /// If not set, will be calculated automatically.
    #[must_use]
    pub fn total_len(mut self, len: u16) -> Self {
        self.total_len = Some(len);
        self.auto_length = false;
        self
    }

    /// Alias for `total_len` (Scapy compatibility).
    #[must_use]
    pub fn len(self, len: u16) -> Self {
        self.total_len(len)
    }

    /// Set the identification field.
    #[must_use]
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Set the flags field.
    #[must_use]
    pub fn flags(mut self, flags: Ipv4Flags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the Don't Fragment flag.
    #[must_use]
    pub fn dont_fragment(mut self) -> Self {
        self.flags.df = true;
        self
    }

    /// Clear the Don't Fragment flag.
    #[must_use]
    pub fn allow_fragment(mut self) -> Self {
        self.flags.df = false;
        self
    }

    /// Set the More Fragments flag.
    #[must_use]
    pub fn more_fragments(mut self) -> Self {
        self.flags.mf = true;
        self
    }

    /// Set the reserved/evil bit.
    #[must_use]
    pub fn evil(mut self) -> Self {
        self.flags.reserved = true;
        self
    }

    /// Set the fragment offset (in 8-byte units).
    #[must_use]
    pub fn frag_offset(mut self, offset: u16) -> Self {
        self.frag_offset = offset & 0x1FFF;
        self
    }

    /// Set the fragment offset in bytes (will be divided by 8).
    #[must_use]
    pub fn frag_offset_bytes(mut self, offset: u32) -> Self {
        self.frag_offset = ((offset / 8) & 0x1FFF) as u16;
        self
    }

    /// Set the TTL (Time to Live).
    #[must_use]
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the protocol number.
    #[must_use]
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    /// Alias for protocol (Scapy compatibility).
    #[must_use]
    pub fn proto(self, protocol: u8) -> Self {
        self.protocol(protocol)
    }

    /// Set the checksum manually.
    /// If not set, will be calculated automatically.
    #[must_use]
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self.auto_checksum = false;
        self
    }

    /// Alias for checksum (Scapy compatibility).
    #[must_use]
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the source IP address.
    #[must_use]
    pub fn src(mut self, src: Ipv4Addr) -> Self {
        self.src = src;
        self
    }

    /// Set the destination IP address.
    #[must_use]
    pub fn dst(mut self, dst: Ipv4Addr) -> Self {
        self.dst = dst;
        self
    }

    // ========== Options ==========

    /// Set the options.
    #[must_use]
    pub fn options(mut self, options: Ipv4Options) -> Self {
        self.options = options;
        self
    }

    /// Add a single option.
    #[must_use]
    pub fn option(mut self, option: Ipv4Option) -> Self {
        self.options.push(option);
        self
    }

    /// Add options using a builder function.
    pub fn with_options<F>(mut self, f: F) -> Self
    where
        F: FnOnce(Ipv4OptionsBuilder) -> Ipv4OptionsBuilder,
    {
        self.options = f(Ipv4OptionsBuilder::new()).build();
        self
    }

    /// Add a Record Route option.
    #[must_use]
    pub fn record_route(mut self, slots: usize) -> Self {
        self.options.push(Ipv4Option::RecordRoute {
            pointer: 4,
            route: vec![Ipv4Addr::UNSPECIFIED; slots],
        });
        self
    }

    /// Add a Loose Source Route option.
    #[must_use]
    pub fn lsrr(mut self, route: Vec<Ipv4Addr>) -> Self {
        self.options.push(Ipv4Option::Lsrr { pointer: 4, route });
        self
    }

    /// Add a Strict Source Route option.
    #[must_use]
    pub fn ssrr(mut self, route: Vec<Ipv4Addr>) -> Self {
        self.options.push(Ipv4Option::Ssrr { pointer: 4, route });
        self
    }

    /// Add a Router Alert option.
    #[must_use]
    pub fn router_alert(mut self, value: u16) -> Self {
        self.options.push(Ipv4Option::RouterAlert { value });
        self
    }

    // ========== Payload ==========

    /// Set the payload data.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Append data to the payload.
    #[must_use]
    pub fn append_payload(mut self, data: &[u8]) -> Self {
        self.payload.extend_from_slice(data);
        self
    }

    // ========== Build Options ==========

    /// Enable or disable automatic checksum calculation.
    #[must_use]
    pub fn auto_checksum(mut self, enabled: bool) -> Self {
        self.auto_checksum = enabled;
        self
    }

    /// Enable or disable automatic length calculation.
    #[must_use]
    pub fn auto_length(mut self, enabled: bool) -> Self {
        self.auto_length = enabled;
        self
    }

    /// Enable or disable automatic IHL calculation.
    #[must_use]
    pub fn auto_ihl(mut self, enabled: bool) -> Self {
        self.auto_ihl = enabled;
        self
    }

    // ========== Build Methods ==========

    /// Calculate the header size (including options).
    #[must_use]
    pub fn header_size(&self) -> usize {
        if let Some(ihl) = self.ihl {
            (ihl as usize) * 4
        } else {
            let opts_len = self.options.padded_len();
            IPV4_MIN_HEADER_LEN + opts_len
        }
    }

    /// Calculate the total packet size.
    #[must_use]
    pub fn packet_size(&self) -> usize {
        self.header_size() + self.payload.len()
    }

    /// Build the IPv4 packet.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let _header_size = self.header_size();
        let total_size = self.packet_size();

        let mut buf = vec![0u8; total_size];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    /// Build the IPv4 packet into an existing buffer.
    pub fn build_into(&self, buf: &mut [u8]) -> Result<usize, FieldError> {
        let header_size = self.header_size();
        let total_size = self.packet_size();

        if buf.len() < total_size {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: total_size,
                have: buf.len(),
            });
        }

        // Calculate IHL
        let ihl = if self.auto_ihl {
            (header_size / 4) as u8
        } else {
            self.ihl.unwrap_or(5)
        };

        // Calculate total length
        let total_len = if self.auto_length {
            total_size as u16
        } else {
            self.total_len.unwrap_or(total_size as u16)
        };

        // Version + IHL
        buf[offsets::VERSION_IHL] = ((self.version & 0x0F) << 4) | (ihl & 0x0F);

        // TOS
        buf[offsets::TOS] = self.tos;

        // Total Length
        buf[offsets::TOTAL_LEN] = (total_len >> 8) as u8;
        buf[offsets::TOTAL_LEN + 1] = (total_len & 0xFF) as u8;

        // ID
        buf[offsets::ID] = (self.id >> 8) as u8;
        buf[offsets::ID + 1] = (self.id & 0xFF) as u8;

        // Flags + Fragment Offset
        let flags_frag = u16::from(self.flags.to_byte()) << 8 | self.frag_offset;
        buf[offsets::FLAGS_FRAG] = (flags_frag >> 8) as u8;
        buf[offsets::FLAGS_FRAG + 1] = (flags_frag & 0xFF) as u8;

        // TTL
        buf[offsets::TTL] = self.ttl;

        // Protocol
        buf[offsets::PROTOCOL] = self.protocol;

        // Checksum (initially 0)
        buf[offsets::CHECKSUM] = 0;
        buf[offsets::CHECKSUM + 1] = 0;

        // Source IP
        let src_octets = self.src.octets();
        buf[offsets::SRC..offsets::SRC + 4].copy_from_slice(&src_octets);

        // Destination IP
        let dst_octets = self.dst.octets();
        buf[offsets::DST..offsets::DST + 4].copy_from_slice(&dst_octets);

        // Options
        if !self.options.is_empty() {
            let opts_bytes = self.options.to_bytes();
            let opts_end = offsets::OPTIONS + opts_bytes.len();
            if opts_end <= header_size {
                buf[offsets::OPTIONS..opts_end].copy_from_slice(&opts_bytes);
            }
        }

        // Payload
        if !self.payload.is_empty() {
            buf[header_size..header_size + self.payload.len()].copy_from_slice(&self.payload);
        }

        // Checksum (computed last)
        let checksum = if self.auto_checksum {
            ipv4_checksum(&buf[..header_size])
        } else {
            self.checksum.unwrap_or(0)
        };
        buf[offsets::CHECKSUM] = (checksum >> 8) as u8;
        buf[offsets::CHECKSUM + 1] = (checksum & 0xFF) as u8;

        Ok(total_size)
    }

    /// Build only the header (no payload).
    #[must_use]
    pub fn build_header(&self) -> Vec<u8> {
        let header_size = self.header_size();
        let mut buf = vec![0u8; header_size];

        // Temporarily clear payload for header-only build
        let payload = std::mem::take(&mut self.payload.clone());
        let builder = Self {
            payload: Vec::new(),
            ..self.clone()
        };
        builder
            .build_into(&mut buf)
            .expect("buffer is correctly sized");

        // Don't actually need to restore since we cloned
        drop(payload);

        buf
    }
}

// ========== Convenience Constructors ==========

impl Ipv4Builder {
    /// Create an ICMP packet builder.
    #[must_use]
    pub fn icmp() -> Self {
        Self::new().protocol(protocol::ICMP)
    }

    /// Create a TCP packet builder.
    #[must_use]
    pub fn tcp() -> Self {
        Self::new().protocol(protocol::TCP)
    }

    /// Create a UDP packet builder.
    #[must_use]
    pub fn udp() -> Self {
        Self::new().protocol(protocol::UDP)
    }

    /// Create an IP-in-IP tunnel packet builder.
    #[must_use]
    pub fn ipip() -> Self {
        Self::new().protocol(protocol::IPV4)
    }

    /// Create a GRE tunnel packet builder.
    #[must_use]
    pub fn gre() -> Self {
        Self::new().protocol(protocol::GRE)
    }

    /// Create a packet destined for a specific address.
    #[must_use]
    pub fn to(dst: Ipv4Addr) -> Self {
        Self::new().dst(dst)
    }

    /// Create a packet from a specific source.
    #[must_use]
    pub fn from(src: Ipv4Addr) -> Self {
        Self::new().src(src)
    }
}

// ========== Random Values ==========

#[cfg(feature = "rand")]
impl Ipv4Builder {
    /// Set a random ID.
    #[must_use]
    pub fn random_id(mut self) -> Self {
        use rand::Rng;
        self.id = rand::rng().random();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_build() {
        let pkt = Ipv4Builder::new()
            .src(Ipv4Addr::new(192, 168, 1, 1))
            .dst(Ipv4Addr::new(192, 168, 1, 2))
            .ttl(64)
            .protocol(protocol::TCP)
            .build();

        assert_eq!(pkt.len(), 20);

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.version(&pkt).unwrap(), 4);
        assert_eq!(layer.ihl(&pkt).unwrap(), 5);
        assert_eq!(layer.ttl(&pkt).unwrap(), 64);
        assert_eq!(layer.protocol(&pkt).unwrap(), protocol::TCP);
        assert_eq!(layer.src(&pkt).unwrap(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(layer.dst(&pkt).unwrap(), Ipv4Addr::new(192, 168, 1, 2));

        // Verify checksum
        assert!(layer.verify_checksum(&pkt).unwrap());
    }

    #[test]
    fn test_with_payload() {
        let payload = vec![1, 2, 3, 4, 5];
        let pkt = Ipv4Builder::new()
            .src(Ipv4Addr::new(10, 0, 0, 1))
            .dst(Ipv4Addr::new(10, 0, 0, 2))
            .protocol(protocol::UDP)
            .payload(payload.clone())
            .build();

        assert_eq!(pkt.len(), 25); // 20 + 5

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.total_len(&pkt).unwrap(), 25);
        assert_eq!(layer.payload(&pkt).unwrap(), &payload[..]);
    }

    #[test]
    fn test_with_options() {
        let pkt = Ipv4Builder::new()
            .src(Ipv4Addr::new(10, 0, 0, 1))
            .dst(Ipv4Addr::new(10, 0, 0, 2))
            .router_alert(0)
            .build();

        // Router Alert is 4 bytes, header should be 24 bytes
        assert_eq!(pkt.len(), 24);

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.ihl(&pkt).unwrap(), 6); // 24/4 = 6
        assert!(layer.verify_checksum(&pkt).unwrap());
    }

    #[test]
    fn test_flags() {
        let pkt = Ipv4Builder::new()
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            .dont_fragment()
            .build();

        let layer = Ipv4Layer::at_offset(0);
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.df);
        assert!(!flags.mf);
    }

    #[test]
    fn test_fragment() {
        let pkt = Ipv4Builder::new()
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            .more_fragments()
            .frag_offset(100)
            .build();

        let layer = Ipv4Layer::at_offset(0);
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.mf);
        assert_eq!(layer.frag_offset(&pkt).unwrap(), 100);
    }

    #[test]
    fn test_dscp_ecn() {
        let pkt = Ipv4Builder::new()
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            .dscp(46) // EF
            .ecn(2) // ECT(0)
            .build();

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.dscp(&pkt).unwrap(), 46);
        assert_eq!(layer.ecn(&pkt).unwrap(), 2);
    }

    #[test]
    fn test_from_bytes() {
        let original = Ipv4Builder::new()
            .src(Ipv4Addr::new(192, 168, 1, 100))
            .dst(Ipv4Addr::new(192, 168, 1, 200))
            .ttl(128)
            .id(0xABCD)
            .protocol(protocol::ICMP)
            .payload(vec![8, 0, 0, 0, 0, 1, 0, 1]) // ICMP echo
            .build();

        let rebuilt = Ipv4Builder::from_bytes(&original)
            .unwrap()
            .auto_checksum(true)
            .build();

        // Should be identical
        assert_eq!(original.len(), rebuilt.len());

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.src(&original).unwrap(), layer.src(&rebuilt).unwrap());
        assert_eq!(layer.dst(&original).unwrap(), layer.dst(&rebuilt).unwrap());
        assert_eq!(layer.ttl(&original).unwrap(), layer.ttl(&rebuilt).unwrap());
        assert_eq!(layer.id(&original).unwrap(), layer.id(&rebuilt).unwrap());
    }

    #[test]
    fn test_convenience_constructors() {
        let icmp = Ipv4Builder::icmp().build();
        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.protocol(&icmp).unwrap(), protocol::ICMP);

        let tcp = Ipv4Builder::tcp().build();
        assert_eq!(layer.protocol(&tcp).unwrap(), protocol::TCP);

        let udp = Ipv4Builder::udp().build();
        assert_eq!(layer.protocol(&udp).unwrap(), protocol::UDP);
    }

    #[test]
    fn test_manual_fields() {
        let pkt = Ipv4Builder::new()
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            .total_len(100)
            .checksum(0x1234)
            .ihl(5)
            .build();

        let layer = Ipv4Layer::at_offset(0);
        assert_eq!(layer.total_len(&pkt).unwrap(), 100);
        assert_eq!(layer.checksum(&pkt).unwrap(), 0x1234);
        assert_eq!(layer.ihl(&pkt).unwrap(), 5);
    }

    #[test]
    fn test_source_route_option() {
        let route = vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
        ];

        let pkt = Ipv4Builder::new()
            .dst(Ipv4Addr::new(10, 0, 0, 4))
            .lsrr(route.clone())
            .build();

        let layer = Ipv4Layer::at_offset(0);
        let options = layer.options(&pkt).unwrap();

        // Check that options are parsed correctly.
        // We might get extra options (padding/NOP), so we just look for LSRR
        let lsrr_option = options
            .options
            .iter()
            .find(|opt| matches!(opt, Ipv4Option::Lsrr { .. }));

        assert!(lsrr_option.is_some(), "Expected LSRR option");

        if let Some(Ipv4Option::Lsrr {
            route: parsed_route,
            ..
        }) = lsrr_option
        {
            assert_eq!(parsed_route, &route);
        }
    }
}
