//! ICMP packet builder.
//!
//! Provides a fluent API for constructing ICMP packets with type-specific fields
//! and automatic checksum calculation.
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::icmp::IcmpBuilder;
//!
//! // Build an echo request
//! let packet = IcmpBuilder::echo_request(0x1234, 1)
//!     .payload(b"ping data")
//!     .build();
//!
//! // Build a destination unreachable message
//! let packet = IcmpBuilder::dest_unreach(3) // Port unreachable
//!     .build();
//! ```

use std::net::Ipv4Addr;

use super::checksum::icmp_checksum;
use super::types::types;
use super::{ICMP_MIN_HEADER_LEN, offsets};
use crate::layer::field::FieldError;

/// Builder for ICMP packets.
///
/// Due to ICMP's type-specific fields, this builder provides factory methods
/// for common ICMP message types rather than a generic constructor.
#[derive(Debug, Clone)]
pub struct IcmpBuilder {
    // Base fields (all ICMP messages)
    icmp_type: u8,
    code: u8,
    checksum: Option<u16>,

    // Type-specific data (4 bytes after checksum)
    // Layout depends on ICMP type:
    // - Echo: [id: u16, seq: u16]
    // - Redirect: [gateway: 4 bytes IP]
    // - Dest Unreach (code 4): [unused: u16, mtu: u16]
    // - Param Problem: [ptr: u8, unused: 3 bytes]
    // - Timestamp: handled separately (has additional fields)
    type_specific: [u8; 4],

    // Additional data for timestamp messages (12 bytes)
    // ts_ori, ts_rx, ts_tx (3 x u32)
    timestamp_data: Option<[u8; 12]>,

    // Payload data
    payload: Vec<u8>,

    // Build options
    auto_checksum: bool,
}

impl Default for IcmpBuilder {
    fn default() -> Self {
        Self {
            icmp_type: types::ECHO_REQUEST,
            code: 0,
            checksum: None,
            type_specific: [0; 4],
            timestamp_data: None,
            payload: Vec::new(),
            auto_checksum: true,
        }
    }
}

impl IcmpBuilder {
    /// Create a new ICMP builder with default values (echo request).
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Factory Methods for Common Types ==========

    /// Create an echo request (ping) packet.
    ///
    /// # Arguments
    /// * `id` - Identifier
    /// * `seq` - Sequence number
    pub fn echo_request(id: u16, seq: u16) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::ECHO_REQUEST;
        builder.code = 0;
        builder.set_id_seq(id, seq);
        builder
    }

    /// Create an echo reply (pong) packet.
    ///
    /// # Arguments
    /// * `id` - Identifier (should match request)
    /// * `seq` - Sequence number (should match request)
    pub fn echo_reply(id: u16, seq: u16) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::ECHO_REPLY;
        builder.code = 0;
        builder.set_id_seq(id, seq);
        builder
    }

    /// Create a destination unreachable message.
    ///
    /// # Arguments
    /// * `code` - Specific unreachable code (0-15)
    ///   - 0: Network unreachable
    ///   - 1: Host unreachable
    ///   - 2: Protocol unreachable
    ///   - 3: Port unreachable
    ///   - 4: Fragmentation needed (use `dest_unreach_need_frag` for this)
    pub fn dest_unreach(code: u8) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::DEST_UNREACH;
        builder.code = code;
        builder.type_specific = [0; 4]; // Unused for most codes
        builder
    }

    /// Create a destination unreachable - fragmentation needed message.
    ///
    /// # Arguments
    /// * `mtu` - Next-hop MTU value
    pub fn dest_unreach_need_frag(mtu: u16) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::DEST_UNREACH;
        builder.code = 4; // Fragmentation needed
        builder.type_specific[0] = 0; // Unused byte
        builder.type_specific[1] = 0; // Unused byte
        builder.type_specific[2..4].copy_from_slice(&mtu.to_be_bytes());
        builder
    }

    /// Create a redirect message.
    ///
    /// # Arguments
    /// * `code` - Redirect code (0-3)
    ///   - 0: Redirect for network
    ///   - 1: Redirect for host
    ///   - 2: Redirect for TOS and network
    ///   - 3: Redirect for TOS and host
    /// * `gateway` - Gateway IP address to redirect to
    pub fn redirect(code: u8, gateway: Ipv4Addr) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::REDIRECT;
        builder.code = code;
        builder.type_specific.copy_from_slice(&gateway.octets());
        builder
    }

    /// Create a time exceeded message.
    ///
    /// # Arguments
    /// * `code` - Time exceeded code
    ///   - 0: TTL exceeded in transit
    ///   - 1: Fragment reassembly time exceeded
    pub fn time_exceeded(code: u8) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::TIME_EXCEEDED;
        builder.code = code;
        builder.type_specific = [0; 4]; // Unused
        builder
    }

    /// Create a parameter problem message.
    ///
    /// # Arguments
    /// * `ptr` - Pointer to the problematic byte in the original packet
    pub fn param_problem(ptr: u8) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::PARAM_PROBLEM;
        builder.code = 0;
        builder.type_specific[0] = ptr;
        builder.type_specific[1] = 0; // Unused
        builder.type_specific[2] = 0; // Length
        builder.type_specific[3] = 0; // Unused
        builder
    }

    /// Create a source quench message (deprecated).
    pub fn source_quench() -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::SOURCE_QUENCH;
        builder.code = 0;
        builder.type_specific = [0; 4]; // Unused
        builder
    }

    /// Create a timestamp request message.
    ///
    /// # Arguments
    /// * `id` - Identifier
    /// * `seq` - Sequence number
    /// * `ts_ori` - Originate timestamp (milliseconds since midnight UT)
    /// * `ts_rx` - Receive timestamp (0 for request)
    /// * `ts_tx` - Transmit timestamp (0 for request)
    pub fn timestamp_request(id: u16, seq: u16, ts_ori: u32, ts_rx: u32, ts_tx: u32) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::TIMESTAMP;
        builder.code = 0;
        builder.set_id_seq(id, seq);

        let mut ts_data = [0u8; 12];
        ts_data[0..4].copy_from_slice(&ts_ori.to_be_bytes());
        ts_data[4..8].copy_from_slice(&ts_rx.to_be_bytes());
        ts_data[8..12].copy_from_slice(&ts_tx.to_be_bytes());
        builder.timestamp_data = Some(ts_data);

        builder
    }

    /// Create a timestamp reply message.
    ///
    /// # Arguments
    /// * `id` - Identifier (should match request)
    /// * `seq` - Sequence number (should match request)
    /// * `ts_ori` - Originate timestamp from request
    /// * `ts_rx` - Receive timestamp (when request was received)
    /// * `ts_tx` - Transmit timestamp (when reply is sent)
    pub fn timestamp_reply(id: u16, seq: u16, ts_ori: u32, ts_rx: u32, ts_tx: u32) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::TIMESTAMP_REPLY;
        builder.code = 0;
        builder.set_id_seq(id, seq);

        let mut ts_data = [0u8; 12];
        ts_data[0..4].copy_from_slice(&ts_ori.to_be_bytes());
        ts_data[4..8].copy_from_slice(&ts_rx.to_be_bytes());
        ts_data[8..12].copy_from_slice(&ts_tx.to_be_bytes());
        builder.timestamp_data = Some(ts_data);

        builder
    }

    /// Create an address mask request message.
    ///
    /// # Arguments
    /// * `id` - Identifier
    /// * `seq` - Sequence number
    pub fn address_mask_request(id: u16, seq: u16) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::ADDRESS_MASK_REQUEST;
        builder.code = 0;
        builder.set_id_seq(id, seq);
        builder
    }

    /// Create an address mask reply message.
    ///
    /// # Arguments
    /// * `id` - Identifier (should match request)
    /// * `seq` - Sequence number (should match request)
    /// * `mask` - Address mask
    pub fn address_mask_reply(id: u16, seq: u16, mask: Ipv4Addr) -> Self {
        let mut builder = Self::new();
        builder.icmp_type = types::ADDRESS_MASK_REPLY;
        builder.code = 0;
        builder.set_id_seq(id, seq);
        // For address mask, the mask goes in the payload area
        builder.payload = mask.octets().to_vec();
        builder
    }

    // ========== Helper Methods ==========

    /// Set ID and sequence number (for echo, timestamp, etc.)
    fn set_id_seq(&mut self, id: u16, seq: u16) {
        self.type_specific[0..2].copy_from_slice(&id.to_be_bytes());
        self.type_specific[2..4].copy_from_slice(&seq.to_be_bytes());
    }

    // ========== Field Setters ==========

    /// Set the ICMP type manually (use factory methods instead when possible).
    pub fn icmp_type(mut self, t: u8) -> Self {
        self.icmp_type = t;
        self
    }

    /// Set the ICMP code manually.
    pub fn code(mut self, c: u8) -> Self {
        self.code = c;
        self
    }

    /// Set the checksum manually.
    ///
    /// If not set, the checksum will be calculated automatically.
    pub fn checksum(mut self, csum: u16) -> Self {
        self.checksum = Some(csum);
        self.auto_checksum = false;
        self
    }

    /// Alias for checksum (Scapy compatibility).
    pub fn chksum(self, csum: u16) -> Self {
        self.checksum(csum)
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

    /// Get the total packet size (header + optional timestamp + payload).
    pub fn packet_size(&self) -> usize {
        let mut size = ICMP_MIN_HEADER_LEN; // Base 8 bytes

        // Timestamp messages have 12 additional bytes
        if self.timestamp_data.is_some() {
            size += 12;
        }

        size + self.payload.len()
    }

    /// Get the header size (8 bytes for most, 20 for timestamp).
    pub fn header_size(&self) -> usize {
        if self.timestamp_data.is_some() {
            20 // 8 base + 12 timestamp data
        } else {
            ICMP_MIN_HEADER_LEN
        }
    }

    // ========== Build Methods ==========

    /// Build the ICMP packet into a new buffer.
    pub fn build(&self) -> Vec<u8> {
        let total_size = self.packet_size();
        let mut buf = vec![0u8; total_size];
        self.build_into(&mut buf)
            .expect("buffer is correctly sized");
        buf
    }

    /// Build the ICMP packet into an existing buffer.
    pub fn build_into(&self, buf: &mut [u8]) -> Result<usize, FieldError> {
        let total_size = self.packet_size();

        if buf.len() < total_size {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: total_size,
                have: buf.len(),
            });
        }

        // Type
        buf[offsets::TYPE] = self.icmp_type;

        // Code
        buf[offsets::CODE] = self.code;

        // Checksum (initially 0, calculated later if auto_checksum is enabled)
        buf[offsets::CHECKSUM..offsets::CHECKSUM + 2].copy_from_slice(&[0, 0]);

        // Type-specific data (4 bytes)
        buf[4..8].copy_from_slice(&self.type_specific);

        let mut offset = 8;

        // Timestamp data if present (12 bytes)
        if let Some(ts_data) = &self.timestamp_data {
            buf[offset..offset + 12].copy_from_slice(ts_data);
            offset += 12;
        }

        // Payload
        if !self.payload.is_empty() {
            buf[offset..offset + self.payload.len()].copy_from_slice(&self.payload);
        }

        // Calculate checksum if enabled
        if self.auto_checksum {
            let csum = icmp_checksum(&buf[..total_size]);
            buf[offsets::CHECKSUM..offsets::CHECKSUM + 2].copy_from_slice(&csum.to_be_bytes());
        } else if let Some(csum) = self.checksum {
            buf[offsets::CHECKSUM..offsets::CHECKSUM + 2].copy_from_slice(&csum.to_be_bytes());
        }

        Ok(total_size)
    }

    /// Build just the ICMP header (without payload).
    pub fn build_header(&self) -> Vec<u8> {
        let header_size = self.header_size();
        let mut buf = vec![0u8; header_size];

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request() {
        let packet = IcmpBuilder::echo_request(0x1234, 5)
            .payload(b"Hello")
            .build();

        assert_eq!(packet[0], types::ECHO_REQUEST); // type
        assert_eq!(packet[1], 0); // code
        // bytes 2-3 are checksum
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x1234); // id
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 5); // seq
        assert_eq!(&packet[8..], b"Hello"); // payload
    }

    #[test]
    fn test_echo_reply() {
        let packet = IcmpBuilder::echo_reply(0x5678, 10).build();

        assert_eq!(packet[0], types::ECHO_REPLY);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x5678);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 10);
    }

    #[test]
    fn test_dest_unreach() {
        let packet = IcmpBuilder::dest_unreach(3).build(); // Port unreachable

        assert_eq!(packet[0], types::DEST_UNREACH);
        assert_eq!(packet[1], 3); // code
    }

    #[test]
    fn test_dest_unreach_need_frag() {
        let packet = IcmpBuilder::dest_unreach_need_frag(1500).build();

        assert_eq!(packet[0], types::DEST_UNREACH);
        assert_eq!(packet[1], 4); // fragmentation needed
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1500); // MTU
    }

    #[test]
    fn test_redirect() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let packet = IcmpBuilder::redirect(1, gateway).build();

        assert_eq!(packet[0], types::REDIRECT);
        assert_eq!(packet[1], 1); // code: redirect host
        assert_eq!(&packet[4..8], &[192, 168, 1, 1]); // gateway IP
    }

    #[test]
    fn test_time_exceeded() {
        let packet = IcmpBuilder::time_exceeded(0).build(); // TTL exceeded

        assert_eq!(packet[0], types::TIME_EXCEEDED);
        assert_eq!(packet[1], 0);
    }

    #[test]
    fn test_param_problem() {
        let packet = IcmpBuilder::param_problem(20).build();

        assert_eq!(packet[0], types::PARAM_PROBLEM);
        assert_eq!(packet[4], 20); // pointer
    }

    #[test]
    fn test_timestamp_request() {
        let packet = IcmpBuilder::timestamp_request(0x1234, 1, 1000, 0, 0).build();

        assert_eq!(packet[0], types::TIMESTAMP);
        assert_eq!(packet.len(), 20); // 8 base + 12 timestamp data
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x1234); // id
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1); // seq
        assert_eq!(
            u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
            1000
        ); // ts_ori
    }

    #[test]
    fn test_checksum_calculation() {
        let packet = IcmpBuilder::echo_request(1, 1).payload(b"test").build();

        // Checksum should be non-zero
        let checksum = u16::from_be_bytes([packet[2], packet[3]]);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_manual_checksum() {
        let packet = IcmpBuilder::echo_request(1, 1).checksum(0xABCD).build();

        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 0xABCD);
    }

    #[test]
    fn test_build_header_only() {
        let header = IcmpBuilder::echo_request(1, 1)
            .payload(b"this should not be included")
            .build_header();

        assert_eq!(header.len(), 8); // Header only
    }

    #[test]
    fn test_timestamp_header_size() {
        let header = IcmpBuilder::timestamp_request(1, 1, 1000, 2000, 3000).build_header();

        assert_eq!(header.len(), 20); // 8 + 12 for timestamps
    }
}
