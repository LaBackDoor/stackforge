//! TCP packet builder.
//!
//! Provides a fluent API for constructing TCP packets with automatic
//! field calculation (checksum, data offset).
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::tcp::{TcpBuilder, TcpFlags};
//! use std::net::Ipv4Addr;
//!
//! // Build a SYN packet
//! let packet = TcpBuilder::new()
//!     .src_port(12345)
//!     .dst_port(80)
//!     .seq(1000)
//!     .syn()
//!     .window(65535)
//!     .mss(1460)
//!     .wscale(7)
//!     .sack_ok()
//!     .build();
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::checksum::{tcp_checksum_ipv4, tcp_checksum_ipv6};
use super::flags::TcpFlags;
use super::header::{TCP_MIN_HEADER_LEN, TcpLayer, offsets};
use super::options::{TcpAoValue, TcpOption, TcpOptions, TcpOptionsBuilder, TcpSackBlock};
use crate::layer::field::FieldError;

/// Builder for TCP packets.
#[derive(Debug, Clone)]
pub struct TcpBuilder {
    // Header fields
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: Option<u8>,
    reserved: u8,
    flags: TcpFlags,
    window: u16,
    checksum: Option<u16>,
    urgent_ptr: u16,

    // Options
    options: TcpOptions,

    // Payload
    payload: Vec<u8>,

    // Build options
    auto_checksum: bool,
    auto_data_offset: bool,

    // IP addresses for checksum calculation
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,

    // Tracks whether flags were explicitly set by the user.
    // When true, the default SYN flag has already been cleared.
    flags_explicitly_set: bool,
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

impl Default for TcpBuilder {
    fn default() -> Self {
        Self {
            src_port: 20,
            dst_port: 80,
            seq: 0,
            ack: 0,
            data_offset: None,
            reserved: 0,
            flags: TcpFlags::from_u16(0x02), // SYN
            window: 8192,
            checksum: None,
            urgent_ptr: 0,
            options: TcpOptions::new(),
            payload: Vec::new(),
            auto_checksum: true,
            auto_data_offset: true,
            src_ip: None,
            dst_ip: None,
            flags_explicitly_set: false,
        }
    }
}

impl TcpBuilder {
    /// Create a new TCP builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder initialized from an existing packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self, FieldError> {
        let layer = TcpLayer::at_offset_dynamic(data, 0)?;

        let mut builder = Self::new();
        builder.src_port = layer.src_port(data)?;
        builder.dst_port = layer.dst_port(data)?;
        builder.seq = layer.seq(data)?;
        builder.ack = layer.ack(data)?;
        builder.data_offset = Some(layer.data_offset(data)?);
        builder.reserved = layer.reserved(data)?;
        builder.flags = layer.flags(data)?;
        builder.window = layer.window(data)?;
        builder.checksum = Some(layer.checksum(data)?);
        builder.urgent_ptr = layer.urgent_ptr(data)?;

        // Parse options if present
        if layer.options_len(data) > 0 {
            builder.options = layer.options(data)?;
        }

        // Copy payload
        let header_len = layer.calculate_header_len(data);
        if data.len() > header_len {
            builder.payload = data[header_len..].to_vec();
        }

        // Disable auto-calculation since we're copying exact values
        builder.auto_checksum = false;
        builder.auto_data_offset = false;

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

    /// Set the sequence number.
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    /// Set the acknowledgment number.
    pub fn ack_num(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    /// Set the data offset (in 32-bit words).
    pub fn data_offset(mut self, offset: u8) -> Self {
        self.data_offset = Some(offset);
        self.auto_data_offset = false;
        self
    }

    /// Alias for data_offset (Scapy compatibility).
    pub fn dataofs(self, offset: u8) -> Self {
        self.data_offset(offset)
    }

    /// Set the reserved bits.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved = reserved & 0x07;
        self
    }

    /// Set the flags.
    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self.flags_explicitly_set = true;
        self
    }

    /// Set flags from a string like "S", "SA", "FA", etc.
    pub fn flags_str(mut self, s: &str) -> Self {
        self.flags = TcpFlags::from_str(s);
        self.flags_explicitly_set = true;
        self
    }

    /// Clear default flags on first explicit flag call.
    /// The default has SYN set (matching Scapy's TCP() default), but when
    /// the user explicitly sets flags via individual methods, the default
    /// should be cleared first so e.g. `.fin()` produces only FIN, not SYN|FIN.
    fn clear_defaults_if_needed(&mut self) {
        if !self.flags_explicitly_set {
            self.flags = TcpFlags::from_u16(0);
            self.flags_explicitly_set = true;
        }
    }

    /// Set the SYN flag.
    pub fn syn(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.syn = true;
        self
    }

    /// Set the ACK flag.
    pub fn ack(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.ack = true;
        self
    }

    /// Set the FIN flag.
    pub fn fin(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.fin = true;
        self
    }

    /// Set the RST flag.
    pub fn rst(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.rst = true;
        self
    }

    /// Set the PSH flag.
    pub fn psh(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.psh = true;
        self
    }

    /// Set the URG flag.
    pub fn urg(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.urg = true;
        self
    }

    /// Set the ECE flag.
    pub fn ece(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.ece = true;
        self
    }

    /// Set the CWR flag.
    pub fn cwr(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.cwr = true;
        self
    }

    /// Set the NS flag.
    pub fn ns(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.ns = true;
        self
    }

    /// Set SYN+ACK flags.
    pub fn syn_ack(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.syn = true;
        self.flags.ack = true;
        self
    }

    /// Set FIN+ACK flags.
    pub fn fin_ack(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.fin = true;
        self.flags.ack = true;
        self
    }

    /// Set PSH+ACK flags.
    pub fn psh_ack(mut self) -> Self {
        self.clear_defaults_if_needed();
        self.flags.psh = true;
        self.flags.ack = true;
        self
    }

    /// Set the window size.
    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// Set the checksum manually.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self.auto_checksum = false;
        self
    }

    /// Alias for checksum (Scapy compatibility).
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the urgent pointer.
    pub fn urgent_ptr(mut self, urgptr: u16) -> Self {
        self.urgent_ptr = urgptr;
        self
    }

    /// Alias for urgent_ptr (Scapy compatibility).
    pub fn urgptr(self, urgptr: u16) -> Self {
        self.urgent_ptr(urgptr)
    }

    // ========== IP Address Setters (for checksum) ==========

    /// Set the source IP address (for checksum calculation).
    pub fn src_ip<T: Into<IpAddr>>(mut self, ip: T) -> Self {
        self.src_ip = Some(ip.into());
        self
    }

    /// Set the destination IP address (for checksum calculation).
    pub fn dst_ip<T: Into<IpAddr>>(mut self, ip: T) -> Self {
        self.dst_ip = Some(ip.into());
        self
    }

    /// Set both source and destination IPv4 addresses.
    pub fn ipv4_addrs(mut self, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        self.src_ip = Some(IpAddr::V4(src));
        self.dst_ip = Some(IpAddr::V4(dst));
        self
    }

    /// Set both source and destination IPv6 addresses.
    pub fn ipv6_addrs(mut self, src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        self.src_ip = Some(IpAddr::V6(src));
        self.dst_ip = Some(IpAddr::V6(dst));
        self
    }

    // ========== Options ==========

    /// Set the options.
    pub fn options(mut self, options: TcpOptions) -> Self {
        self.options = options;
        self
    }

    /// Add a single option.
    pub fn option(mut self, option: TcpOption) -> Self {
        self.options.push(option);
        self
    }

    /// Add options using a builder function.
    pub fn with_options<F>(mut self, f: F) -> Self
    where
        F: FnOnce(TcpOptionsBuilder) -> TcpOptionsBuilder,
    {
        self.options = f(TcpOptionsBuilder::new()).build();
        self
    }

    /// Add an MSS (Maximum Segment Size) option.
    pub fn mss(mut self, mss: u16) -> Self {
        self.options.push(TcpOption::Mss(mss));
        self
    }

    /// Add a Window Scale option.
    pub fn wscale(mut self, scale: u8) -> Self {
        self.options.push(TcpOption::WScale(scale));
        self
    }

    /// Add SACK Permitted option.
    pub fn sack_ok(mut self) -> Self {
        self.options.push(TcpOption::SackOk);
        self
    }

    /// Add a SACK option with blocks.
    pub fn sack(mut self, blocks: Vec<TcpSackBlock>) -> Self {
        self.options.push(TcpOption::Sack(blocks));
        self
    }

    /// Add a Timestamp option.
    pub fn timestamp(mut self, ts_val: u32, ts_ecr: u32) -> Self {
        self.options.push(TcpOption::timestamp(ts_val, ts_ecr));
        self
    }

    /// Add a NOP (padding) option.
    pub fn nop(mut self) -> Self {
        self.options.push(TcpOption::Nop);
        self
    }

    /// Add an EOL (End of Options) option.
    pub fn eol(mut self) -> Self {
        self.options.push(TcpOption::Eol);
        self
    }

    /// Add a TFO (TCP Fast Open) option.
    pub fn tfo(mut self, cookie: Option<Vec<u8>>) -> Self {
        self.options.push(TcpOption::Tfo { cookie });
        self
    }

    /// Add an MD5 signature option.
    pub fn md5(mut self, signature: [u8; 16]) -> Self {
        self.options.push(TcpOption::Md5(signature));
        self
    }

    /// Add an Authentication Option (TCP-AO).
    pub fn ao(mut self, key_id: u8, rnext_key_id: u8, mac: Vec<u8>) -> Self {
        self.options
            .push(TcpOption::Ao(TcpAoValue::new(key_id, rnext_key_id, mac)));
        self
    }

    // ========== Payload ==========

    /// Set the payload data.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Append data to the payload.
    pub fn append_payload(mut self, data: &[u8]) -> Self {
        self.payload.extend_from_slice(data);
        self
    }

    // ========== Build Options ==========

    /// Enable or disable automatic checksum calculation.
    pub fn auto_checksum(mut self, enabled: bool) -> Self {
        self.auto_checksum = enabled;
        self
    }

    /// Enable or disable automatic data offset calculation.
    pub fn auto_data_offset(mut self, enabled: bool) -> Self {
        self.auto_data_offset = enabled;
        self
    }

    // ========== Build Methods ==========

    /// Calculate the header size (including options, with padding).
    pub fn header_size(&self) -> usize {
        if let Some(doff) = self.data_offset {
            (doff as usize) * 4
        } else {
            let opts_len = self.options.padded_len();
            TCP_MIN_HEADER_LEN + opts_len
        }
    }

    /// Calculate the total packet size.
    pub fn packet_size(&self) -> usize {
        self.header_size() + self.payload.len()
    }

    /// Build the TCP packet.
    pub fn build(&self) -> Vec<u8> {
        let total_size = self.packet_size();
        let mut buf = vec![0u8; total_size];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    /// Build the TCP packet into an existing buffer.
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

        // Calculate data offset
        let data_offset = if self.auto_data_offset {
            (header_size / 4) as u8
        } else {
            self.data_offset.unwrap_or(5)
        };

        // Source Port
        buf[offsets::SRC_PORT] = (self.src_port >> 8) as u8;
        buf[offsets::SRC_PORT + 1] = (self.src_port & 0xFF) as u8;

        // Destination Port
        buf[offsets::DST_PORT] = (self.dst_port >> 8) as u8;
        buf[offsets::DST_PORT + 1] = (self.dst_port & 0xFF) as u8;

        // Sequence Number
        buf[offsets::SEQ..offsets::SEQ + 4].copy_from_slice(&self.seq.to_be_bytes());

        // Acknowledgment Number
        buf[offsets::ACK..offsets::ACK + 4].copy_from_slice(&self.ack.to_be_bytes());

        // Data Offset + Reserved + NS flag
        buf[offsets::DATA_OFFSET] =
            ((data_offset & 0x0F) << 4) | ((self.reserved & 0x07) << 1) | self.flags.ns_bit();

        // Flags (without NS)
        buf[offsets::FLAGS] = self.flags.to_byte();

        // Window
        buf[offsets::WINDOW] = (self.window >> 8) as u8;
        buf[offsets::WINDOW + 1] = (self.window & 0xFF) as u8;

        // Checksum (initially 0)
        buf[offsets::CHECKSUM] = 0;
        buf[offsets::CHECKSUM + 1] = 0;

        // Urgent Pointer
        buf[offsets::URG_PTR] = (self.urgent_ptr >> 8) as u8;
        buf[offsets::URG_PTR + 1] = (self.urgent_ptr & 0xFF) as u8;

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

        // Checksum (computed last if we have IP addresses)
        let checksum = if self.auto_checksum {
            match (self.src_ip, self.dst_ip) {
                (Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))) => {
                    tcp_checksum_ipv4(src, dst, &buf[..total_size])
                }
                (Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))) => {
                    tcp_checksum_ipv6(src, dst, &buf[..total_size])
                }
                _ => 0, // Can't compute checksum without IP addresses
            }
        } else {
            self.checksum.unwrap_or(0)
        };
        buf[offsets::CHECKSUM] = (checksum >> 8) as u8;
        buf[offsets::CHECKSUM + 1] = (checksum & 0xFF) as u8;

        Ok(total_size)
    }

    /// Build only the header (no payload).
    pub fn build_header(&self) -> Vec<u8> {
        let header_size = self.header_size();
        let mut buf = vec![0u8; header_size];

        // Create a copy without payload
        let builder = Self {
            payload: Vec::new(),
            ..self.clone()
        };
        builder
            .build_into(&mut buf)
            .expect("buffer is correctly sized");

        buf
    }
}

// ========== Convenience Constructors ==========

impl TcpBuilder {
    /// Create a SYN packet builder.
    pub fn syn_packet() -> Self {
        Self::new().syn().ack_num(0)
    }

    /// Create a SYN-ACK packet builder.
    pub fn syn_ack_packet() -> Self {
        Self::new().syn_ack()
    }

    /// Create an ACK packet builder.
    pub fn ack_packet() -> Self {
        Self::new().flags(TcpFlags::A)
    }

    /// Create a FIN-ACK packet builder.
    pub fn fin_ack_packet() -> Self {
        Self::new().fin_ack()
    }

    /// Create a RST packet builder.
    pub fn rst_packet() -> Self {
        Self::new().flags(TcpFlags::R)
    }

    /// Create a RST-ACK packet builder.
    pub fn rst_ack_packet() -> Self {
        Self::new().flags(TcpFlags::RA)
    }

    /// Create a PSH-ACK packet builder (for data).
    pub fn data_packet() -> Self {
        Self::new().psh_ack()
    }
}

// ========== Random Values ==========

#[cfg(feature = "rand")]
impl TcpBuilder {
    /// Set a random sequence number.
    pub fn random_seq(mut self) -> Self {
        use rand::Rng;
        self.seq = rand::rng().random();
        self
    }

    /// Set a random source port (dynamic range: 49152-65535).
    pub fn random_sport(mut self) -> Self {
        use rand::Rng;
        self.src_port = rand::rng().random_range(49152..=65535);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_build() {
        let pkt = TcpBuilder::new()
            .src_port(12345)
            .dst_port(80)
            .seq(1000)
            .syn()
            .window(65535)
            .build();

        assert_eq!(pkt.len(), 20); // Minimum header, no options

        let layer = TcpLayer::at_offset(0);
        assert_eq!(layer.src_port(&pkt).unwrap(), 12345);
        assert_eq!(layer.dst_port(&pkt).unwrap(), 80);
        assert_eq!(layer.seq(&pkt).unwrap(), 1000);
        assert_eq!(layer.window(&pkt).unwrap(), 65535);

        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);
    }

    #[test]
    fn test_with_options() {
        let pkt = TcpBuilder::new()
            .src_port(12345)
            .dst_port(80)
            .syn()
            .mss(1460)
            .wscale(7)
            .sack_ok()
            .nop()
            .build();

        let layer = TcpLayer::at_offset(0);
        let opts = layer.options(&pkt).unwrap();

        assert_eq!(opts.mss(), Some(1460));
        assert_eq!(opts.wscale(), Some(7));
        assert!(opts.sack_permitted());
    }

    #[test]
    fn test_with_payload() {
        let payload = b"Hello, TCP!";
        let pkt = TcpBuilder::new()
            .src_port(12345)
            .dst_port(80)
            .psh_ack()
            .payload(payload.to_vec())
            .build();

        assert_eq!(pkt.len(), 20 + payload.len());

        let layer = TcpLayer::at_offset(0);
        let pkt_payload = layer.payload(&pkt);
        assert_eq!(pkt_payload, payload);
    }

    #[test]
    fn test_with_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        let pkt = TcpBuilder::new()
            .src_port(12345)
            .dst_port(80)
            .syn()
            .ipv4_addrs(src_ip, dst_ip)
            .build();

        let layer = TcpLayer::at_offset(0);
        let checksum = layer.checksum(&pkt).unwrap();
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_flags() {
        let pkt = TcpBuilder::new().syn_ack().build();

        let layer = TcpLayer::at_offset(0);
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.syn);
        assert!(flags.ack);

        let pkt = TcpBuilder::new().fin_ack().build();
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.fin);
        assert!(flags.ack);
    }

    #[test]
    fn test_from_bytes() {
        let original = TcpBuilder::new()
            .src_port(12345)
            .dst_port(443)
            .seq(0xDEADBEEF)
            .ack_num(0xCAFEBABE)
            .syn_ack()
            .window(32768)
            .mss(1460)
            .build();

        let rebuilt = TcpBuilder::from_bytes(&original)
            .unwrap()
            .auto_checksum(false)
            .build();

        assert_eq!(original.len(), rebuilt.len());

        let layer = TcpLayer::at_offset(0);
        assert_eq!(
            layer.src_port(&original).unwrap(),
            layer.src_port(&rebuilt).unwrap()
        );
        assert_eq!(
            layer.dst_port(&original).unwrap(),
            layer.dst_port(&rebuilt).unwrap()
        );
        assert_eq!(layer.seq(&original).unwrap(), layer.seq(&rebuilt).unwrap());
        assert_eq!(layer.ack(&original).unwrap(), layer.ack(&rebuilt).unwrap());
    }

    #[test]
    fn test_convenience_constructors() {
        let syn = TcpBuilder::syn_packet().build();
        let layer = TcpLayer::at_offset(0);
        let flags = layer.flags(&syn).unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);

        let syn_ack = TcpBuilder::syn_ack_packet().build();
        let flags = layer.flags(&syn_ack).unwrap();
        assert!(flags.syn);
        assert!(flags.ack);

        let rst = TcpBuilder::rst_packet().build();
        let flags = layer.flags(&rst).unwrap();
        assert!(flags.rst);
    }

    #[test]
    fn test_timestamp_option() {
        let pkt = TcpBuilder::new()
            .syn()
            .mss(1460)
            .timestamp(12345, 0)
            .build();

        let layer = TcpLayer::at_offset(0);
        let opts = layer.options(&pkt).unwrap();

        let ts = opts.timestamp().unwrap();
        assert_eq!(ts.ts_val, 12345);
        assert_eq!(ts.ts_ecr, 0);
    }

    #[test]
    fn test_tfo_option() {
        let cookie = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pkt = TcpBuilder::new().syn().tfo(Some(cookie.clone())).build();

        let layer = TcpLayer::at_offset(0);
        let opts = layer.options(&pkt).unwrap();

        assert_eq!(opts.tfo_cookie(), Some(cookie.as_slice()));
    }

    #[test]
    fn test_flags_str() {
        let pkt = TcpBuilder::new().flags_str("SA").build();

        let layer = TcpLayer::at_offset(0);
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.syn);
        assert!(flags.ack);

        let pkt = TcpBuilder::new().flags_str("FA").build();
        let flags = layer.flags(&pkt).unwrap();
        assert!(flags.fin);
        assert!(flags.ack);
    }
}
