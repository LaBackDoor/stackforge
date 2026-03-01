//! IEEE 802.15.4 packet builders with fluent API.
//!
//! Provides `Dot15d4Builder` for constructing 802.15.4 MAC frames
//! and `Dot15d4FcsBuilder` which wraps and appends FCS.

use super::crc;
use super::types;
use super::{FCS_LEN, build_fcf, compute_header_len};

/// Address specification for the builder.
#[derive(Debug, Clone)]
pub enum Dot15d4Addr {
    /// No address.
    None,
    /// Short (16-bit) address.
    Short(u16),
    /// Long (64-bit) address.
    Long(u64),
}

impl Dot15d4Addr {
    /// Get the address mode for this address.
    fn mode(&self) -> u8 {
        match self {
            Self::None => types::addr_mode::NONE,
            Self::Short(_) => types::addr_mode::SHORT,
            Self::Long(_) => types::addr_mode::LONG,
        }
    }
}

/// Builder for constructing IEEE 802.15.4 MAC frames.
#[derive(Debug, Clone)]
pub struct Dot15d4Builder {
    /// Frame type (3 bits).
    pub frame_type: u8,
    /// Security enabled flag.
    pub security: bool,
    /// Frame pending flag.
    pub pending: bool,
    /// ACK request flag.
    pub ackreq: bool,
    /// PAN ID compression flag.
    pub panid_compress: bool,
    /// Frame version (2 bits).
    pub frame_ver: u8,
    /// Sequence number.
    pub seqnum: u8,
    /// Destination PAN ID.
    pub dest_panid: Option<u16>,
    /// Destination address.
    pub dest_addr: Dot15d4Addr,
    /// Source PAN ID.
    pub src_panid: Option<u16>,
    /// Source address.
    pub src_addr: Dot15d4Addr,
}

impl Dot15d4Builder {
    /// Create a new builder with default values (Data frame, short addressing).
    pub fn new() -> Self {
        Self {
            frame_type: types::frame_type::DATA,
            security: false,
            pending: false,
            ackreq: false,
            panid_compress: false,
            frame_ver: 0,
            seqnum: 1,
            dest_panid: Some(0xFFFF),
            dest_addr: Dot15d4Addr::Short(0xFFFF),
            src_panid: None,
            src_addr: Dot15d4Addr::None,
        }
    }

    /// Create a builder for a beacon frame.
    pub fn beacon() -> Self {
        Self {
            frame_type: types::frame_type::BEACON,
            security: false,
            pending: false,
            ackreq: false,
            panid_compress: false,
            frame_ver: 0,
            seqnum: 0,
            dest_panid: None,
            dest_addr: Dot15d4Addr::None,
            src_panid: None,
            src_addr: Dot15d4Addr::None,
        }
    }

    /// Create a builder for a data frame.
    pub fn data() -> Self {
        Self::new()
    }

    /// Create a builder for an ACK frame.
    pub fn ack() -> Self {
        Self {
            frame_type: types::frame_type::ACK,
            security: false,
            pending: false,
            ackreq: false,
            panid_compress: false,
            frame_ver: 0,
            seqnum: 0,
            dest_panid: None,
            dest_addr: Dot15d4Addr::None,
            src_panid: None,
            src_addr: Dot15d4Addr::None,
        }
    }

    /// Create a builder for a command frame.
    pub fn command() -> Self {
        Self {
            frame_type: types::frame_type::MAC_CMD,
            security: false,
            pending: false,
            ackreq: false,
            panid_compress: false,
            frame_ver: 0,
            seqnum: 0,
            dest_panid: Some(0xFFFF),
            dest_addr: Dot15d4Addr::Short(0x0000),
            src_panid: None,
            src_addr: Dot15d4Addr::None,
        }
    }

    // Fluent setters

    /// Set the frame type.
    pub fn frame_type(mut self, ft: u8) -> Self {
        self.frame_type = ft;
        self
    }

    /// Set the security enabled flag.
    pub fn security(mut self, val: bool) -> Self {
        self.security = val;
        self
    }

    /// Set the frame pending flag.
    pub fn pending(mut self, val: bool) -> Self {
        self.pending = val;
        self
    }

    /// Set the ACK request flag.
    pub fn ackreq(mut self, val: bool) -> Self {
        self.ackreq = val;
        self
    }

    /// Set the PAN ID compression flag.
    pub fn panid_compress(mut self, val: bool) -> Self {
        self.panid_compress = val;
        self
    }

    /// Set the frame version.
    pub fn frame_ver(mut self, ver: u8) -> Self {
        self.frame_ver = ver;
        self
    }

    /// Set the sequence number.
    pub fn seqnum(mut self, seq: u8) -> Self {
        self.seqnum = seq;
        self
    }

    /// Set the destination PAN ID.
    pub fn dest_panid(mut self, panid: u16) -> Self {
        self.dest_panid = Some(panid);
        self
    }

    /// Set the destination short address.
    pub fn dest_addr_short(mut self, addr: u16) -> Self {
        self.dest_addr = Dot15d4Addr::Short(addr);
        if self.dest_panid.is_none() {
            self.dest_panid = Some(0xFFFF);
        }
        self
    }

    /// Set the destination long address.
    pub fn dest_addr_long(mut self, addr: u64) -> Self {
        self.dest_addr = Dot15d4Addr::Long(addr);
        if self.dest_panid.is_none() {
            self.dest_panid = Some(0xFFFF);
        }
        self
    }

    /// Clear the destination address (set to None).
    pub fn no_dest_addr(mut self) -> Self {
        self.dest_addr = Dot15d4Addr::None;
        self.dest_panid = None;
        self
    }

    /// Set the source PAN ID.
    pub fn src_panid(mut self, panid: u16) -> Self {
        self.src_panid = Some(panid);
        self
    }

    /// Set the source short address.
    pub fn src_addr_short(mut self, addr: u16) -> Self {
        self.src_addr = Dot15d4Addr::Short(addr);
        self
    }

    /// Set the source long address.
    pub fn src_addr_long(mut self, addr: u64) -> Self {
        self.src_addr = Dot15d4Addr::Long(addr);
        self
    }

    /// Clear the source address (set to None).
    pub fn no_src_addr(mut self) -> Self {
        self.src_addr = Dot15d4Addr::None;
        self.src_panid = None;
        self
    }

    /// Compute the destination address mode.
    fn dest_addr_mode(&self) -> u8 {
        self.dest_addr.mode()
    }

    /// Compute the source address mode.
    fn src_addr_mode(&self) -> u8 {
        self.src_addr.mode()
    }

    /// Build the 802.15.4 MAC frame bytes (without FCS).
    pub fn build(&self) -> Vec<u8> {
        let dest_mode = self.dest_addr_mode();
        let src_mode = self.src_addr_mode();

        let fcf = build_fcf(
            self.frame_type,
            self.security,
            self.pending,
            self.ackreq,
            self.panid_compress,
            dest_mode,
            self.frame_ver,
            src_mode,
        );

        let header_len = compute_header_len(fcf);
        let mut out = Vec::with_capacity(header_len);

        // Frame Control Field (2 bytes, LE)
        out.extend_from_slice(&fcf.to_le_bytes());

        // Sequence Number (1 byte)
        out.push(self.seqnum);

        // Destination PAN ID + Address
        if dest_mode != types::addr_mode::NONE {
            let panid = self.dest_panid.unwrap_or(0xFFFF);
            out.extend_from_slice(&panid.to_le_bytes());

            match &self.dest_addr {
                Dot15d4Addr::Short(addr) => {
                    out.extend_from_slice(&addr.to_le_bytes());
                }
                Dot15d4Addr::Long(addr) => {
                    out.extend_from_slice(&addr.to_le_bytes());
                }
                Dot15d4Addr::None => {} // Should not happen if dest_mode != NONE
            }
        }

        // Source PAN ID + Address
        if src_mode != types::addr_mode::NONE {
            if !self.panid_compress {
                let panid = self.src_panid.unwrap_or(0x0000);
                out.extend_from_slice(&panid.to_le_bytes());
            }

            match &self.src_addr {
                Dot15d4Addr::Short(addr) => {
                    out.extend_from_slice(&addr.to_le_bytes());
                }
                Dot15d4Addr::Long(addr) => {
                    out.extend_from_slice(&addr.to_le_bytes());
                }
                Dot15d4Addr::None => {} // Should not happen if src_mode != NONE
            }
        }

        out
    }

    /// Get the expected header size for the current configuration.
    pub fn header_size(&self) -> usize {
        let fcf = build_fcf(
            self.frame_type,
            self.security,
            self.pending,
            self.ackreq,
            self.panid_compress,
            self.dest_addr_mode(),
            self.frame_ver,
            self.src_addr_mode(),
        );
        compute_header_len(fcf)
    }
}

impl Default for Dot15d4Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for IEEE 802.15.4 frames with FCS.
///
/// Wraps `Dot15d4Builder` and appends a CRC-16 CCITT Kermit FCS.
#[derive(Debug, Clone)]
pub struct Dot15d4FcsBuilder {
    /// Inner builder for the frame content.
    pub inner: Dot15d4Builder,
}

impl Dot15d4FcsBuilder {
    /// Create a new FCS builder with default values.
    pub fn new() -> Self {
        Self {
            inner: Dot15d4Builder::new(),
        }
    }

    /// Create from an existing Dot15d4Builder.
    pub fn from_builder(builder: Dot15d4Builder) -> Self {
        Self { inner: builder }
    }

    /// Create a builder for a beacon frame with FCS.
    pub fn beacon() -> Self {
        Self {
            inner: Dot15d4Builder::beacon(),
        }
    }

    /// Create a builder for a data frame with FCS.
    pub fn data() -> Self {
        Self {
            inner: Dot15d4Builder::data(),
        }
    }

    /// Create a builder for an ACK frame with FCS.
    pub fn ack() -> Self {
        Self {
            inner: Dot15d4Builder::ack(),
        }
    }

    /// Create a builder for a command frame with FCS.
    pub fn command() -> Self {
        Self {
            inner: Dot15d4Builder::command(),
        }
    }

    // Fluent setters that delegate to inner builder

    pub fn frame_type(mut self, ft: u8) -> Self {
        self.inner = self.inner.frame_type(ft);
        self
    }

    pub fn security(mut self, val: bool) -> Self {
        self.inner = self.inner.security(val);
        self
    }

    pub fn pending(mut self, val: bool) -> Self {
        self.inner = self.inner.pending(val);
        self
    }

    pub fn ackreq(mut self, val: bool) -> Self {
        self.inner = self.inner.ackreq(val);
        self
    }

    pub fn panid_compress(mut self, val: bool) -> Self {
        self.inner = self.inner.panid_compress(val);
        self
    }

    pub fn frame_ver(mut self, ver: u8) -> Self {
        self.inner = self.inner.frame_ver(ver);
        self
    }

    pub fn seqnum(mut self, seq: u8) -> Self {
        self.inner = self.inner.seqnum(seq);
        self
    }

    pub fn dest_panid(mut self, panid: u16) -> Self {
        self.inner = self.inner.dest_panid(panid);
        self
    }

    pub fn dest_addr_short(mut self, addr: u16) -> Self {
        self.inner = self.inner.dest_addr_short(addr);
        self
    }

    pub fn dest_addr_long(mut self, addr: u64) -> Self {
        self.inner = self.inner.dest_addr_long(addr);
        self
    }

    pub fn no_dest_addr(mut self) -> Self {
        self.inner = self.inner.no_dest_addr();
        self
    }

    pub fn src_panid(mut self, panid: u16) -> Self {
        self.inner = self.inner.src_panid(panid);
        self
    }

    pub fn src_addr_short(mut self, addr: u16) -> Self {
        self.inner = self.inner.src_addr_short(addr);
        self
    }

    pub fn src_addr_long(mut self, addr: u64) -> Self {
        self.inner = self.inner.src_addr_long(addr);
        self
    }

    pub fn no_src_addr(mut self) -> Self {
        self.inner = self.inner.no_src_addr();
        self
    }

    /// Build the 802.15.4 MAC frame bytes with FCS appended.
    pub fn build(&self) -> Vec<u8> {
        let mut frame = self.inner.build();
        let fcs = crc::compute_fcs(&frame);
        frame.extend_from_slice(&fcs);
        frame
    }

    /// Get the expected total size (header + FCS).
    pub fn total_size(&self) -> usize {
        self.inner.header_size() + FCS_LEN
    }
}

impl Default for Dot15d4FcsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::dot15d4::{Dot15d4FcsLayer, Dot15d4Layer};

    #[test]
    fn test_builder_default() {
        let b = Dot15d4Builder::new();
        assert_eq!(b.frame_type, types::frame_type::DATA);
        assert!(!b.security);
        assert!(!b.ackreq);
        assert_eq!(b.seqnum, 1);
    }

    #[test]
    fn test_builder_beacon() {
        let b = Dot15d4Builder::beacon();
        assert_eq!(b.frame_type, types::frame_type::BEACON);
    }

    #[test]
    fn test_builder_ack() {
        let b = Dot15d4Builder::ack();
        assert_eq!(b.frame_type, types::frame_type::ACK);
        let frame = b.build();
        assert_eq!(frame.len(), 3); // FCF + seqnum
    }

    #[test]
    fn test_builder_fluent_api() {
        let b = Dot15d4Builder::new()
            .frame_type(types::frame_type::DATA)
            .ackreq(true)
            .panid_compress(true)
            .seqnum(42)
            .dest_panid(0x1234)
            .dest_addr_short(0xFFFF)
            .src_addr_short(0x0001);

        assert_eq!(b.frame_type, types::frame_type::DATA);
        assert!(b.ackreq);
        assert!(b.panid_compress);
        assert_eq!(b.seqnum, 42);
    }

    #[test]
    fn test_build_data_frame_short() {
        let frame = Dot15d4Builder::new()
            .frame_type(types::frame_type::DATA)
            .ackreq(true)
            .panid_compress(true)
            .seqnum(5)
            .dest_panid(0x1234)
            .dest_addr_short(0xFFFF)
            .src_addr_short(0x0001)
            .build();

        // Parse it back
        let layer = Dot15d4Layer::new(0, frame.len());
        assert_eq!(layer.fcf_frametype(&frame).unwrap(), 1);
        assert!(layer.fcf_ackreq(&frame).unwrap());
        assert!(layer.fcf_panidcompress(&frame).unwrap());
        assert_eq!(layer.fcf_destaddrmode(&frame).unwrap(), 2);
        assert_eq!(layer.fcf_srcaddrmode(&frame).unwrap(), 2);
        assert_eq!(layer.seqnum(&frame).unwrap(), 5);
        assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));
        assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0xFFFF));
        assert_eq!(layer.src_panid(&frame).unwrap(), None); // compressed
        assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x0001));

        // Header length should be 9
        assert_eq!(frame.len(), 9);
    }

    #[test]
    fn test_build_data_frame_long() {
        let frame = Dot15d4Builder::new()
            .frame_type(types::frame_type::DATA)
            .seqnum(10)
            .dest_panid(0x1234)
            .dest_addr_long(0x0102030405060708)
            .src_panid(0xABCD)
            .src_addr_long(0x1112131415161718)
            .build();

        let layer = Dot15d4Layer::new(0, frame.len());
        assert_eq!(layer.fcf_destaddrmode(&frame).unwrap(), 3);
        assert_eq!(layer.fcf_srcaddrmode(&frame).unwrap(), 3);
        assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));
        assert_eq!(
            layer.dest_addr_long(&frame).unwrap(),
            Some(0x0102030405060708)
        );
        assert_eq!(layer.src_panid(&frame).unwrap(), Some(0xABCD));
        assert_eq!(
            layer.src_addr_long(&frame).unwrap(),
            Some(0x1112131415161718)
        );

        // Header: 3 + 2 + 8 + 2 + 8 = 23
        assert_eq!(frame.len(), 23);
    }

    #[test]
    fn test_build_ack_frame() {
        let frame = Dot15d4Builder::ack().seqnum(42).build();

        let layer = Dot15d4Layer::new(0, frame.len());
        assert_eq!(layer.fcf_frametype(&frame).unwrap(), 2);
        assert_eq!(layer.fcf_destaddrmode(&frame).unwrap(), 0);
        assert_eq!(layer.fcf_srcaddrmode(&frame).unwrap(), 0);
        assert_eq!(layer.seqnum(&frame).unwrap(), 42);
        assert_eq!(frame.len(), 3);
    }

    #[test]
    fn test_fcs_builder() {
        let frame = Dot15d4FcsBuilder::new()
            .frame_type(types::frame_type::DATA)
            .ackreq(true)
            .panid_compress(true)
            .seqnum(5)
            .dest_panid(0x1234)
            .dest_addr_short(0xFFFF)
            .src_addr_short(0x0001)
            .build();

        // Should be header + 2 bytes FCS
        assert_eq!(frame.len(), 11); // 9 header + 2 FCS

        // Verify FCS
        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert!(layer.verify_fcs(&frame).unwrap());

        // Verify inner fields
        assert_eq!(layer.fcf_frametype(&frame).unwrap(), 1);
        assert_eq!(layer.seqnum(&frame).unwrap(), 5);
    }

    #[test]
    fn test_fcs_builder_from_inner() {
        let inner = Dot15d4Builder::ack().seqnum(99);
        let fcs_builder = Dot15d4FcsBuilder::from_builder(inner);
        let frame = fcs_builder.build();

        assert_eq!(frame.len(), 5); // 3 header + 2 FCS

        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert!(layer.verify_fcs(&frame).unwrap());
        assert_eq!(layer.seqnum(&frame).unwrap(), 99);
    }

    #[test]
    fn test_header_size() {
        let b = Dot15d4Builder::ack();
        assert_eq!(b.header_size(), 3);

        let b = Dot15d4Builder::new()
            .dest_addr_short(0xFFFF)
            .panid_compress(true)
            .src_addr_short(0x0001);
        assert_eq!(b.header_size(), 9);

        let b = Dot15d4Builder::new()
            .dest_addr_long(0x0102030405060708)
            .src_addr_long(0x1112131415161718);
        assert_eq!(b.header_size(), 23);
    }

    #[test]
    fn test_fcs_total_size() {
        let b = Dot15d4FcsBuilder::ack();
        assert_eq!(b.total_size(), 5);
    }

    #[test]
    fn test_builder_no_dest_addr() {
        let b = Dot15d4Builder::new().no_dest_addr().no_src_addr();
        let frame = b.build();
        assert_eq!(frame.len(), 3);
    }

    #[test]
    fn test_build_parse_roundtrip_short() {
        let original = Dot15d4Builder::new()
            .frame_type(types::frame_type::DATA)
            .ackreq(true)
            .panid_compress(true)
            .seqnum(77)
            .dest_panid(0xBEEF)
            .dest_addr_short(0x1234)
            .src_addr_short(0x5678);

        let frame = original.build();
        let layer = Dot15d4Layer::new(0, frame.len());

        assert_eq!(
            layer.fcf_frametype(&frame).unwrap(),
            types::frame_type::DATA
        );
        assert!(layer.fcf_ackreq(&frame).unwrap());
        assert!(layer.fcf_panidcompress(&frame).unwrap());
        assert_eq!(layer.seqnum(&frame).unwrap(), 77);
        assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0xBEEF));
        assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0x1234));
        assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x5678));
    }

    #[test]
    fn test_fcs_builder_beacon() {
        let frame = Dot15d4FcsBuilder::beacon().seqnum(0).build();
        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert_eq!(
            layer.fcf_frametype(&frame).unwrap(),
            types::frame_type::BEACON
        );
        assert!(layer.verify_fcs(&frame).unwrap());
    }

    #[test]
    fn test_fcs_builder_command() {
        let frame = Dot15d4FcsBuilder::command()
            .seqnum(10)
            .dest_panid(0x1234)
            .dest_addr_short(0x0001)
            .build();
        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert_eq!(
            layer.fcf_frametype(&frame).unwrap(),
            types::frame_type::MAC_CMD
        );
        assert!(layer.verify_fcs(&frame).unwrap());
    }
}
