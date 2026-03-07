//! IPv4 header layer implementation.
//!
//! Provides zero-copy access to IPv4 header fields.

use std::net::Ipv4Addr;

use crate::layer::field::{Field, FieldDesc, FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

use super::checksum::ipv4_checksum;
use super::options::{Ipv4Options, parse_options};
use super::protocol;
use super::routing::Ipv4Route;

/// Minimum IPv4 header length (no options).
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Maximum IPv4 header length (with maximum options).
pub const IPV4_MAX_HEADER_LEN: usize = 60;

/// Maximum total length of an IPv4 packet.
pub const IPV4_MAX_PACKET_LEN: usize = 65535;

/// Field offsets within the IPv4 header.
pub mod offsets {
    /// Version (4 bits) + IHL (4 bits)
    pub const VERSION_IHL: usize = 0;
    /// DSCP (6 bits) + ECN (2 bits) - also known as TOS
    pub const TOS: usize = 1;
    /// Total length (16 bits)
    pub const TOTAL_LEN: usize = 2;
    /// Identification (16 bits)
    pub const ID: usize = 4;
    /// Flags (3 bits) + Fragment offset (13 bits)
    pub const FLAGS_FRAG: usize = 6;
    /// Time to live (8 bits)
    pub const TTL: usize = 8;
    /// Protocol (8 bits)
    pub const PROTOCOL: usize = 9;
    /// Header checksum (16 bits)
    pub const CHECKSUM: usize = 10;
    /// Source address (32 bits)
    pub const SRC: usize = 12;
    /// Destination address (32 bits)
    pub const DST: usize = 16;
    /// Options start (if IHL > 5)
    pub const OPTIONS: usize = 20;
}

/// Field descriptors for dynamic access.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::new("version", offsets::VERSION_IHL, 1, FieldType::U8),
    FieldDesc::new("ihl", offsets::VERSION_IHL, 1, FieldType::U8),
    FieldDesc::new("tos", offsets::TOS, 1, FieldType::U8),
    FieldDesc::new("dscp", offsets::TOS, 1, FieldType::U8),
    FieldDesc::new("ecn", offsets::TOS, 1, FieldType::U8),
    FieldDesc::new("len", offsets::TOTAL_LEN, 2, FieldType::U16),
    FieldDesc::new("id", offsets::ID, 2, FieldType::U16),
    FieldDesc::new("flags", offsets::FLAGS_FRAG, 1, FieldType::U8),
    FieldDesc::new("frag", offsets::FLAGS_FRAG, 2, FieldType::U16),
    FieldDesc::new("ttl", offsets::TTL, 1, FieldType::U8),
    FieldDesc::new("proto", offsets::PROTOCOL, 1, FieldType::U8),
    FieldDesc::new("chksum", offsets::CHECKSUM, 2, FieldType::U16),
    FieldDesc::new("src", offsets::SRC, 4, FieldType::Ipv4),
    FieldDesc::new("dst", offsets::DST, 4, FieldType::Ipv4),
];

/// IPv4 flags in the flags/fragment offset field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv4Flags {
    /// Reserved/Evil bit (should be 0)
    pub reserved: bool,
    /// Don't Fragment
    pub df: bool,
    /// More Fragments
    pub mf: bool,
}

impl Ipv4Flags {
    pub const NONE: Self = Self {
        reserved: false,
        df: false,
        mf: false,
    };

    pub const DF: Self = Self {
        reserved: false,
        df: true,
        mf: false,
    };

    pub const MF: Self = Self {
        reserved: false,
        df: false,
        mf: true,
    };

    /// Create flags from a raw byte value (upper 3 bits).
    #[inline]
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        Self {
            reserved: (byte & 0x80) != 0,
            df: (byte & 0x40) != 0,
            mf: (byte & 0x20) != 0,
        }
    }

    /// Convert to a raw byte value (upper 3 bits).
    #[inline]
    #[must_use]
    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.reserved {
            b |= 0x80;
        }
        if self.df {
            b |= 0x40;
        }
        if self.mf {
            b |= 0x20;
        }
        b
    }

    /// Check if this is a fragment (MF set or offset > 0).
    #[inline]
    #[must_use]
    pub fn is_fragment(self, offset: u16) -> bool {
        self.mf || offset > 0
    }
}

impl std::fmt::Display for Ipv4Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.reserved {
            parts.push("evil");
        }
        if self.df {
            parts.push("DF");
        }
        if self.mf {
            parts.push("MF");
        }
        if parts.is_empty() {
            write!(f, "-")
        } else {
            write!(f, "{}", parts.join("+"))
        }
    }
}

/// A view into an IPv4 packet header.
#[derive(Debug, Clone)]
pub struct Ipv4Layer {
    pub index: LayerIndex,
}

impl Ipv4Layer {
    /// Create a new IPv4 layer view with specified bounds.
    #[inline]
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Ipv4, start, end),
        }
    }

    /// Create a layer at offset 0 with minimum header length.
    #[inline]
    #[must_use]
    pub const fn at_start() -> Self {
        Self::new(0, IPV4_MIN_HEADER_LEN)
    }

    /// Create a layer at the specified offset with minimum header length.
    #[inline]
    #[must_use]
    pub const fn at_offset(offset: usize) -> Self {
        Self::new(offset, offset + IPV4_MIN_HEADER_LEN)
    }

    /// Create a layer at offset, calculating actual header length from IHL.
    pub fn at_offset_dynamic(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 1 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len().saturating_sub(offset),
            });
        }

        let ihl = (buf[offset] & 0x0F) as usize;
        let header_len = ihl * 4;

        if header_len < IPV4_MIN_HEADER_LEN {
            return Err(FieldError::InvalidValue(format!(
                "IHL {ihl} is less than minimum (5)"
            )));
        }

        if buf.len() < offset + header_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: header_len,
                have: buf.len().saturating_sub(offset),
            });
        }

        Ok(Self::new(offset, offset + header_len))
    }

    /// Validate that the buffer contains a valid IPv4 header at the offset.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + IPV4_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: IPV4_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }

        let version = (buf[offset] >> 4) & 0x0F;
        if version != 4 {
            return Err(FieldError::InvalidValue(format!(
                "not IPv4: version = {version}"
            )));
        }

        let ihl = (buf[offset] & 0x0F) as usize;
        if ihl < 5 {
            return Err(FieldError::InvalidValue(format!(
                "IHL {ihl} is less than minimum (5)"
            )));
        }

        let header_len = ihl * 4;
        if buf.len() < offset + header_len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: header_len,
                have: buf.len().saturating_sub(offset),
            });
        }

        Ok(())
    }

    /// Calculate the actual header length from the buffer.
    #[must_use]
    pub fn calculate_header_len(&self, buf: &[u8]) -> usize {
        self.ihl(buf).map(|ihl| (ihl as usize) * 4).unwrap_or(20)
    }

    /// Get the options length (header length - 20).
    #[must_use]
    pub fn options_len(&self, buf: &[u8]) -> usize {
        self.calculate_header_len(buf)
            .saturating_sub(IPV4_MIN_HEADER_LEN)
    }

    // ========== Field Readers ==========

    /// Read the version field (should be 4).
    #[inline]
    pub fn version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::VERSION_IHL)?;
        Ok((b >> 4) & 0x0F)
    }

    /// Read the Internet Header Length (in 32-bit words).
    #[inline]
    pub fn ihl(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::VERSION_IHL)?;
        Ok(b & 0x0F)
    }

    /// Read the header length in bytes.
    #[inline]
    pub fn header_len_bytes(&self, buf: &[u8]) -> Result<usize, FieldError> {
        Ok((self.ihl(buf)? as usize) * 4)
    }

    /// Read the Type of Service (TOS) field.
    #[inline]
    pub fn tos(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::TOS)
    }

    /// Read the DSCP (Differentiated Services Code Point).
    #[inline]
    pub fn dscp(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok((self.tos(buf)? >> 2) & 0x3F)
    }

    /// Read the ECN (Explicit Congestion Notification).
    #[inline]
    pub fn ecn(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.tos(buf)? & 0x03)
    }

    /// Read the total length field.
    #[inline]
    pub fn total_len(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::TOTAL_LEN)
    }

    /// Read the identification field.
    #[inline]
    pub fn id(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::ID)
    }

    /// Read the flags as a structured type.
    #[inline]
    pub fn flags(&self, buf: &[u8]) -> Result<Ipv4Flags, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::FLAGS_FRAG)?;
        Ok(Ipv4Flags::from_byte(b))
    }

    /// Read the raw flags byte (upper 3 bits of flags/frag field).
    #[inline]
    pub fn flags_raw(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let b = u8::read(buf, self.index.start + offsets::FLAGS_FRAG)?;
        Ok((b >> 5) & 0x07)
    }

    /// Read the fragment offset (in 8-byte units).
    #[inline]
    pub fn frag_offset(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let val = u16::read(buf, self.index.start + offsets::FLAGS_FRAG)?;
        Ok(val & 0x1FFF)
    }

    /// Read the fragment offset in bytes.
    #[inline]
    pub fn frag_offset_bytes(&self, buf: &[u8]) -> Result<u32, FieldError> {
        Ok(u32::from(self.frag_offset(buf)?) * 8)
    }

    /// Read the Time to Live field.
    #[inline]
    pub fn ttl(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::TTL)
    }

    /// Read the protocol field.
    #[inline]
    pub fn protocol(&self, buf: &[u8]) -> Result<u8, FieldError> {
        u8::read(buf, self.index.start + offsets::PROTOCOL)
    }

    /// Read the header checksum.
    #[inline]
    pub fn checksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        u16::read(buf, self.index.start + offsets::CHECKSUM)
    }

    /// Read the source IP address.
    #[inline]
    pub fn src(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        Ipv4Addr::read(buf, self.index.start + offsets::SRC)
    }

    /// Read the destination IP address.
    #[inline]
    pub fn dst(&self, buf: &[u8]) -> Result<Ipv4Addr, FieldError> {
        Ipv4Addr::read(buf, self.index.start + offsets::DST)
    }

    /// Read the options bytes (if any).
    pub fn options_bytes<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let header_len = self.calculate_header_len(buf);
        let opts_start = self.index.start + IPV4_MIN_HEADER_LEN;
        let opts_end = self.index.start + header_len;

        if buf.len() < opts_end {
            return Err(FieldError::BufferTooShort {
                offset: opts_start,
                need: header_len - IPV4_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(opts_start),
            });
        }

        Ok(&buf[opts_start..opts_end])
    }

    /// Parse and return the options.
    pub fn options(&self, buf: &[u8]) -> Result<Ipv4Options, FieldError> {
        let opts_bytes = self.options_bytes(buf)?;
        parse_options(opts_bytes)
    }

    // ========== Field Writers ==========

    /// Set the version field.
    #[inline]
    pub fn set_version(&self, buf: &mut [u8], version: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::VERSION_IHL;
        let current = u8::read(buf, offset)?;
        let new_val = (current & 0x0F) | ((version & 0x0F) << 4);
        new_val.write(buf, offset)
    }

    /// Set the IHL field.
    #[inline]
    pub fn set_ihl(&self, buf: &mut [u8], ihl: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::VERSION_IHL;
        let current = u8::read(buf, offset)?;
        let new_val = (current & 0xF0) | (ihl & 0x0F);
        new_val.write(buf, offset)
    }

    /// Set the TOS field.
    #[inline]
    pub fn set_tos(&self, buf: &mut [u8], tos: u8) -> Result<(), FieldError> {
        tos.write(buf, self.index.start + offsets::TOS)
    }

    /// Set the DSCP field.
    #[inline]
    pub fn set_dscp(&self, buf: &mut [u8], dscp: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::TOS;
        let current = u8::read(buf, offset)?;
        let new_val = (current & 0x03) | ((dscp & 0x3F) << 2);
        new_val.write(buf, offset)
    }

    /// Set the ECN field.
    #[inline]
    pub fn set_ecn(&self, buf: &mut [u8], ecn: u8) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::TOS;
        let current = u8::read(buf, offset)?;
        let new_val = (current & 0xFC) | (ecn & 0x03);
        new_val.write(buf, offset)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&self, buf: &mut [u8], len: u16) -> Result<(), FieldError> {
        len.write(buf, self.index.start + offsets::TOTAL_LEN)
    }

    /// Set the identification field.
    #[inline]
    pub fn set_id(&self, buf: &mut [u8], id: u16) -> Result<(), FieldError> {
        id.write(buf, self.index.start + offsets::ID)
    }

    /// Set the flags field.
    #[inline]
    pub fn set_flags(&self, buf: &mut [u8], flags: Ipv4Flags) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::FLAGS_FRAG;
        let current = u8::read(buf, offset)?;
        let new_val = (current & 0x1F) | flags.to_byte();
        new_val.write(buf, offset)
    }

    /// Set the fragment offset (in 8-byte units).
    #[inline]
    pub fn set_frag_offset(&self, buf: &mut [u8], offset_val: u16) -> Result<(), FieldError> {
        let offset = self.index.start + offsets::FLAGS_FRAG;
        let current = u16::read(buf, offset)?;
        let new_val = (current & 0xE000) | (offset_val & 0x1FFF);
        new_val.write(buf, offset)
    }

    /// Set the TTL field.
    #[inline]
    pub fn set_ttl(&self, buf: &mut [u8], ttl: u8) -> Result<(), FieldError> {
        ttl.write(buf, self.index.start + offsets::TTL)
    }

    /// Set the protocol field.
    #[inline]
    pub fn set_protocol(&self, buf: &mut [u8], proto: u8) -> Result<(), FieldError> {
        proto.write(buf, self.index.start + offsets::PROTOCOL)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&self, buf: &mut [u8], checksum: u16) -> Result<(), FieldError> {
        checksum.write(buf, self.index.start + offsets::CHECKSUM)
    }

    /// Set the source IP address.
    #[inline]
    pub fn set_src(&self, buf: &mut [u8], src: Ipv4Addr) -> Result<(), FieldError> {
        src.write(buf, self.index.start + offsets::SRC)
    }

    /// Set the destination IP address.
    #[inline]
    pub fn set_dst(&self, buf: &mut [u8], dst: Ipv4Addr) -> Result<(), FieldError> {
        dst.write(buf, self.index.start + offsets::DST)
    }

    /// Compute and set the header checksum.
    pub fn compute_checksum(&self, buf: &mut [u8]) -> Result<u16, FieldError> {
        // Zero out existing checksum first
        self.set_checksum(buf, 0)?;

        // Calculate header length
        let header_len = self.calculate_header_len(buf);
        let header_end = self.index.start + header_len;

        if buf.len() < header_end {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: header_len,
                have: buf.len().saturating_sub(self.index.start),
            });
        }

        // Compute checksum over header bytes
        let checksum = ipv4_checksum(&buf[self.index.start..header_end]);

        // Write checksum
        self.set_checksum(buf, checksum)?;

        Ok(checksum)
    }

    /// Verify the header checksum.
    pub fn verify_checksum(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let header_len = self.calculate_header_len(buf);
        let header_end = self.index.start + header_len;

        if buf.len() < header_end {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: header_len,
                have: buf.len().saturating_sub(self.index.start),
            });
        }

        let checksum = ipv4_checksum(&buf[self.index.start..header_end]);
        Ok(checksum == 0 || checksum == 0xFFFF)
    }

    // ========== Dynamic Field Access ==========

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "version" => Some(self.version(buf).map(FieldValue::U8)),
            "ihl" => Some(self.ihl(buf).map(FieldValue::U8)),
            "tos" => Some(self.tos(buf).map(FieldValue::U8)),
            "dscp" => Some(self.dscp(buf).map(FieldValue::U8)),
            "ecn" => Some(self.ecn(buf).map(FieldValue::U8)),
            "len" | "total_len" => Some(self.total_len(buf).map(FieldValue::U16)),
            "id" => Some(self.id(buf).map(FieldValue::U16)),
            "flags" => Some(self.flags_raw(buf).map(FieldValue::U8)),
            "frag" | "frag_offset" => Some(self.frag_offset(buf).map(FieldValue::U16)),
            "ttl" => Some(self.ttl(buf).map(FieldValue::U8)),
            "proto" | "protocol" => Some(self.protocol(buf).map(FieldValue::U8)),
            "chksum" | "checksum" => Some(self.checksum(buf).map(FieldValue::U16)),
            "src" => Some(self.src(buf).map(FieldValue::Ipv4)),
            "dst" => Some(self.dst(buf).map(FieldValue::Ipv4)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match (name, value) {
            ("version", FieldValue::U8(v)) => Some(self.set_version(buf, v)),
            ("ihl", FieldValue::U8(v)) => Some(self.set_ihl(buf, v)),
            ("tos", FieldValue::U8(v)) => Some(self.set_tos(buf, v)),
            ("dscp", FieldValue::U8(v)) => Some(self.set_dscp(buf, v)),
            ("ecn", FieldValue::U8(v)) => Some(self.set_ecn(buf, v)),
            ("len" | "total_len", FieldValue::U16(v)) => Some(self.set_total_len(buf, v)),
            ("id", FieldValue::U16(v)) => Some(self.set_id(buf, v)),
            ("frag" | "frag_offset", FieldValue::U16(v)) => Some(self.set_frag_offset(buf, v)),
            ("ttl", FieldValue::U8(v)) => Some(self.set_ttl(buf, v)),
            ("proto" | "protocol", FieldValue::U8(v)) => Some(self.set_protocol(buf, v)),
            ("chksum" | "checksum", FieldValue::U16(v)) => Some(self.set_checksum(buf, v)),
            ("src", FieldValue::Ipv4(v)) => Some(self.set_src(buf, v)),
            ("dst", FieldValue::Ipv4(v)) => Some(self.set_dst(buf, v)),
            _ => None,
        }
    }

    /// Get list of field names.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        &[
            "version", "ihl", "tos", "dscp", "ecn", "len", "id", "flags", "frag", "ttl", "proto",
            "chksum", "src", "dst",
        ]
    }

    // ========== Utility Methods ==========

    /// Check if this is a fragment.
    #[must_use]
    pub fn is_fragment(&self, buf: &[u8]) -> bool {
        let flags = self.flags(buf).unwrap_or(Ipv4Flags::NONE);
        let offset = self.frag_offset(buf).unwrap_or(0);
        flags.is_fragment(offset)
    }

    /// Check if this is the first fragment.
    #[must_use]
    pub fn is_first_fragment(&self, buf: &[u8]) -> bool {
        let flags = self.flags(buf).unwrap_or(Ipv4Flags::NONE);
        let offset = self.frag_offset(buf).unwrap_or(0);
        flags.mf && offset == 0
    }

    /// Check if this is the last fragment.
    #[must_use]
    pub fn is_last_fragment(&self, buf: &[u8]) -> bool {
        let flags = self.flags(buf).unwrap_or(Ipv4Flags::NONE);
        let offset = self.frag_offset(buf).unwrap_or(0);
        !flags.mf && offset > 0
    }

    /// Check if the Don't Fragment flag is set.
    #[must_use]
    pub fn is_dont_fragment(&self, buf: &[u8]) -> bool {
        self.flags(buf).map(|f| f.df).unwrap_or(false)
    }

    /// Get the payload length (`total_len` - `header_len`).
    pub fn payload_len(&self, buf: &[u8]) -> Result<usize, FieldError> {
        let total = self.total_len(buf)? as usize;
        let header = self.calculate_header_len(buf);
        Ok(total.saturating_sub(header))
    }

    /// Get a slice of the payload data.
    pub fn payload<'a>(&self, buf: &'a [u8]) -> Result<&'a [u8], FieldError> {
        let header_len = self.calculate_header_len(buf);
        let total_len = self.total_len(buf)? as usize;
        let payload_start = self.index.start + header_len;
        let payload_end = (self.index.start + total_len).min(buf.len());

        if payload_start > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: payload_start,
                need: 0,
                have: buf.len().saturating_sub(payload_start),
            });
        }

        Ok(&buf[payload_start..payload_end])
    }

    /// Get the header bytes.
    #[inline]
    #[must_use]
    pub fn header_bytes<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let header_len = self.calculate_header_len(buf);
        let end = (self.index.start + header_len).min(buf.len());
        &buf[self.index.start..end]
    }

    /// Copy the header bytes.
    #[inline]
    #[must_use]
    pub fn header_copy(&self, buf: &[u8]) -> Vec<u8> {
        self.header_bytes(buf).to_vec()
    }

    /// Get the protocol name.
    pub fn protocol_name(&self, buf: &[u8]) -> &'static str {
        self.protocol(buf)
            .map(protocol::to_name)
            .unwrap_or("Unknown")
    }

    /// Determine the next layer kind based on protocol.
    #[must_use]
    pub fn next_layer(&self, buf: &[u8]) -> Option<LayerKind> {
        self.protocol(buf).ok().and_then(|proto| match proto {
            protocol::TCP => Some(LayerKind::Tcp),
            protocol::UDP => Some(LayerKind::Udp),
            protocol::ICMP => Some(LayerKind::Icmp),
            protocol::IPV4 => Some(LayerKind::Ipv4),
            protocol::IPV6 => Some(LayerKind::Ipv6),
            _ => None,
        })
    }

    /// Compute hash for packet matching (like Scapy's hashret).
    #[must_use]
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let proto = self.protocol(buf).unwrap_or(0);

        // For ICMP error messages, delegate to inner packet
        if proto == protocol::ICMP {
            // Check if it's an ICMP error (type 3, 4, 5, 11, 12)
            let header_len = self.calculate_header_len(buf);
            let icmp_start = self.index.start + header_len;
            if buf.len() > icmp_start {
                let icmp_type = buf[icmp_start];
                if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
                    // Return hash of the embedded packet
                    // For now, just use src/dst XOR + proto
                }
            }
        }

        // For IP-in-IP tunnels, delegate to inner packet
        if matches!(proto, protocol::IPV4 | protocol::IPV6) {
            // Could recurse here
        }

        // Standard hash: XOR of src and dst + protocol
        let src = self.src(buf).map(|ip| ip.octets()).unwrap_or([0; 4]);
        let dst = self.dst(buf).map(|ip| ip.octets()).unwrap_or([0; 4]);

        let mut result = Vec::with_capacity(5);
        for i in 0..4 {
            result.push(src[i] ^ dst[i]);
        }
        result.push(proto);
        result
    }

    /// Check if this packet answers another (for `sr()` matching).
    #[must_use]
    pub fn answers(&self, buf: &[u8], other: &Ipv4Layer, other_buf: &[u8]) -> bool {
        // Protocol must match
        let self_proto = self.protocol(buf).unwrap_or(0);
        let other_proto = other.protocol(other_buf).unwrap_or(0);

        // Handle ICMP errors
        if self_proto == protocol::ICMP {
            let header_len = self.calculate_header_len(buf);
            let icmp_start = self.index.start + header_len;
            if buf.len() > icmp_start {
                let icmp_type = buf[icmp_start];
                if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
                    // ICMP error - check embedded packet
                    // The embedded packet should match the original
                    return true; // Simplified - real impl would check embedded
                }
            }
        }

        // Handle IP-in-IP tunnels
        if matches!(other_proto, protocol::IPV4 | protocol::IPV6) {
            // Delegate to inner packet
        }

        if self_proto != other_proto {
            return false;
        }

        // Check addresses
        let self_src = self.src(buf).ok();
        let self_dst = self.dst(buf).ok();
        let other_src = other.src(other_buf).ok();
        let other_dst = other.dst(other_buf).ok();

        // Response src should match request dst
        if self_src != other_dst {
            return false;
        }

        // Response dst should match request src
        if self_dst != other_src {
            return false;
        }

        true
    }

    /// Extract padding from the packet.
    /// Returns (payload, padding) tuple.
    #[must_use]
    pub fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let header_len = self.calculate_header_len(buf);
        let total_len = self.total_len(buf).unwrap_or(0) as usize;

        let payload_start = self.index.start + header_len;
        let payload_end = (self.index.start + total_len).min(buf.len());

        if payload_start >= buf.len() {
            return (&[], &buf[buf.len()..]);
        }

        let payload = &buf[payload_start..payload_end];
        let padding = &buf[payload_end..];

        (payload, padding)
    }

    /// Get routing information for this packet.
    #[must_use]
    pub fn route(&self, buf: &[u8]) -> Ipv4Route {
        use crate::layer::ipv4::routing::get_route;
        let dst = self.dst(buf).unwrap_or(Ipv4Addr::UNSPECIFIED);
        get_route(dst)
    }

    /// Estimate the original TTL.
    #[must_use]
    pub fn original_ttl(&self, buf: &[u8]) -> u8 {
        let current = self.ttl(buf).unwrap_or(0);
        super::ttl::estimate_original(current)
    }

    /// Estimate the number of hops.
    #[must_use]
    pub fn hops(&self, buf: &[u8]) -> u8 {
        let current = self.ttl(buf).unwrap_or(0);
        super::ttl::estimate_hops(current)
    }
}

impl Layer for Ipv4Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Ipv4
    }

    fn summary(&self, buf: &[u8]) -> String {
        let src = self
            .src(buf)
            .map_or_else(|_| "?".into(), |ip| ip.to_string());
        let dst = self
            .dst(buf)
            .map_or_else(|_| "?".into(), |ip| ip.to_string());
        let proto = self.protocol_name(buf);
        let ttl = self.ttl(buf).unwrap_or(0);

        let mut s = format!("IP {src} > {dst} {proto} ttl={ttl}");

        // Add fragment info if fragmented
        if self.is_fragment(buf) {
            let flags = self.flags(buf).unwrap_or(Ipv4Flags::NONE);
            let offset = self.frag_offset(buf).unwrap_or(0);
            s.push_str(&format!(
                " frag:{}+{}",
                offset,
                if flags.mf { "MF" } else { "" }
            ));
        }

        s
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.calculate_header_len(buf)
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        self.answers(buf, other, other_buf)
    }

    fn extract_padding<'a>(&self, buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        self.extract_padding(buf)
    }

    fn field_names(&self) -> &'static [&'static str] {
        Ipv4Layer::field_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4_header() -> Vec<u8> {
        vec![
            0x45, // Version=4, IHL=5
            0x00, // TOS=0
            0x00, 0x3c, // Total length = 60
            0x1c, 0x46, // ID = 0x1c46
            0x40, 0x00, // Flags=DF, Frag offset=0
            0x40, // TTL=64
            0x06, // Protocol=TCP
            0x00, 0x00, // Checksum (to be computed)
            0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02, // Dst: 192.168.1.2
        ]
    }

    #[test]
    fn test_field_readers() {
        let buf = sample_ipv4_header();
        let layer = Ipv4Layer::at_offset(0);

        assert_eq!(layer.version(&buf).unwrap(), 4);
        assert_eq!(layer.ihl(&buf).unwrap(), 5);
        assert_eq!(layer.tos(&buf).unwrap(), 0);
        assert_eq!(layer.total_len(&buf).unwrap(), 60);
        assert_eq!(layer.id(&buf).unwrap(), 0x1c46);
        assert!(layer.flags(&buf).unwrap().df);
        assert_eq!(layer.frag_offset(&buf).unwrap(), 0);
        assert_eq!(layer.ttl(&buf).unwrap(), 64);
        assert_eq!(layer.protocol(&buf).unwrap(), protocol::TCP);
        assert_eq!(layer.src(&buf).unwrap(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(layer.dst(&buf).unwrap(), Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn test_field_writers() {
        let mut buf = sample_ipv4_header();
        let layer = Ipv4Layer::at_offset(0);

        layer.set_ttl(&mut buf, 128).unwrap();
        assert_eq!(layer.ttl(&buf).unwrap(), 128);

        layer.set_src(&mut buf, Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        assert_eq!(layer.src(&buf).unwrap(), Ipv4Addr::new(10, 0, 0, 1));

        layer.set_flags(&mut buf, Ipv4Flags::MF).unwrap();
        assert!(layer.flags(&buf).unwrap().mf);
        assert!(!layer.flags(&buf).unwrap().df);
    }

    #[test]
    fn test_checksum() {
        let mut buf = sample_ipv4_header();
        let layer = Ipv4Layer::at_offset(0);

        // Compute checksum
        let checksum = layer.compute_checksum(&mut buf).unwrap();
        assert_ne!(checksum, 0);

        // Verify it
        assert!(layer.verify_checksum(&buf).unwrap());

        // Corrupt and verify fails
        buf[0] ^= 0x01;
        assert!(!layer.verify_checksum(&buf).unwrap());
    }

    #[test]
    fn test_flags() {
        let flags = Ipv4Flags::from_byte(0x40); // DF
        assert!(flags.df);
        assert!(!flags.mf);
        assert!(!flags.reserved);
        assert_eq!(flags.to_byte(), 0x40);

        let flags = Ipv4Flags::from_byte(0x20); // MF
        assert!(!flags.df);
        assert!(flags.mf);
        assert!(!flags.reserved);

        let flags = Ipv4Flags::from_byte(0xE0); // All set
        assert!(flags.df);
        assert!(flags.mf);
        assert!(flags.reserved);
    }

    #[test]
    fn test_is_fragment() {
        let mut buf = sample_ipv4_header();
        let layer = Ipv4Layer::at_offset(0);

        // DF set, not a fragment
        assert!(!layer.is_fragment(&buf));

        // Set MF
        layer.set_flags(&mut buf, Ipv4Flags::MF).unwrap();
        assert!(layer.is_fragment(&buf));

        // Clear MF, set offset
        layer.set_flags(&mut buf, Ipv4Flags::NONE).unwrap();
        layer.set_frag_offset(&mut buf, 100).unwrap();
        assert!(layer.is_fragment(&buf));
    }

    #[test]
    fn test_dynamic_field_access() {
        let buf = sample_ipv4_header();
        let layer = Ipv4Layer::at_offset(0);

        let ttl = layer.get_field(&buf, "ttl").unwrap().unwrap();
        assert_eq!(ttl.as_u8(), Some(64));

        let src = layer.get_field(&buf, "src").unwrap().unwrap();
        assert_eq!(src.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_validate() {
        let buf = sample_ipv4_header();
        assert!(Ipv4Layer::validate(&buf, 0).is_ok());

        // Too short
        let short = vec![0x45, 0x00];
        assert!(Ipv4Layer::validate(&short, 0).is_err());

        // Wrong version
        let mut wrong_version = sample_ipv4_header();
        wrong_version[0] = 0x65; // Version 6
        assert!(Ipv4Layer::validate(&wrong_version, 0).is_err());

        // Invalid IHL
        let mut bad_ihl = sample_ipv4_header();
        bad_ihl[0] = 0x43; // IHL=3 (< minimum 5)
        assert!(Ipv4Layer::validate(&bad_ihl, 0).is_err());
    }

    #[test]
    fn test_extract_padding() {
        let mut buf = sample_ipv4_header();
        // Set total_len to 30 (header=20 + payload=10)
        buf[2] = 0x00;
        buf[3] = 0x1e; // 30

        // Add some payload and padding
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // 10 bytes payload
        buf.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes padding

        let layer = Ipv4Layer::at_offset(0);
        let (payload, padding) = layer.extract_padding(&buf);

        assert_eq!(payload.len(), 10);
        assert_eq!(padding.len(), 4);
    }
}
