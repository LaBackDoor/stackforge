//! Field trait and implementations for zero-copy field access.
//!
//! This module provides the abstraction for reading and writing protocol
//! fields directly from/to raw packet buffers at specific offsets.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Errors that can occur during field operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FieldError {
    #[error("buffer too short: need {need} bytes at offset {offset}, have {have}")]
    BufferTooShort {
        offset: usize,
        need: usize,
        have: usize,
    },

    #[error("invalid MAC address format: {0}")]
    InvalidMac(String),

    #[error("invalid IP address format: {0}")]
    InvalidIp(String),

    #[error("field type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },

    #[error("field not found: {0}")]
    FieldNotFound(String),

    #[error("invalid field value: {0}")]
    InvalidValue(String),
}

/// A 6-byte MAC address with display and parsing support.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const ZERO: Self = Self([0x00; 6]);
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// Common multicast prefix for IPv4 (01:00:5e)
    pub const IPV4_MULTICAST_PREFIX: [u8; 3] = [0x01, 0x00, 0x5e];
    /// Common multicast prefix for IPv6 (33:33)
    pub const IPV6_MULTICAST_PREFIX: [u8; 2] = [0x33, 0x33];

    #[inline]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    #[inline]
    pub const fn to_bytes(self) -> [u8; 6] {
        self.0
    }

    #[inline]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    #[inline]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    #[inline]
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0x00; 6]
    }

    /// Check if this is an IPv4 multicast MAC (01:00:5e:xx:xx:xx)
    #[inline]
    pub fn is_ipv4_multicast(&self) -> bool {
        self.0[0] == 0x01 && self.0[1] == 0x00 && self.0[2] == 0x5e
    }

    /// Check if this is an IPv6 multicast MAC (33:33:xx:xx:xx:xx)
    #[inline]
    pub fn is_ipv6_multicast(&self) -> bool {
        self.0[0] == 0x33 && self.0[1] == 0x33
    }

    /// Create multicast MAC for IPv4 multicast address
    pub fn from_ipv4_multicast(ip: Ipv4Addr) -> Self {
        let octets = ip.octets();
        Self([0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3]])
    }

    /// Create multicast MAC for IPv6 multicast address
    pub fn from_ipv6_multicast(ip: Ipv6Addr) -> Self {
        let octets = ip.octets();
        Self([0x33, 0x33, octets[12], octets[13], octets[14], octets[15]])
    }

    /// Parse MAC from string (e.g., "00:11:22:33:44:55" or "00-11-22-33-44-55")
    pub fn parse(s: &str) -> Result<Self, FieldError> {
        let s = s.trim();
        let parts: Vec<&str> = if s.contains(':') {
            s.split(':').collect()
        } else if s.contains('-') {
            s.split('-').collect()
        } else if s.len() == 12 {
            // Handle bare hex string like "001122334455"
            return Self::parse_bare_hex(s);
        } else {
            return Err(FieldError::InvalidMac(s.to_string()));
        };

        if parts.len() != 6 {
            return Err(FieldError::InvalidMac(s.to_string()));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] =
                u8::from_str_radix(part, 16).map_err(|_| FieldError::InvalidMac(s.to_string()))?;
        }
        Ok(Self(bytes))
    }

    fn parse_bare_hex(s: &str) -> Result<Self, FieldError> {
        if s.len() != 12 {
            return Err(FieldError::InvalidMac(s.to_string()));
        }
        let mut bytes = [0u8; 6];
        for i in 0..6 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| FieldError::InvalidMac(s.to_string()))?;
        }
        Ok(Self(bytes))
    }

    #[inline]
    pub fn read_from(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        <Self as Field>::read(buf, offset)
    }

    #[inline]
    pub fn write_to(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        <Self as Field>::write(self, buf, offset)
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(mac: MacAddress) -> Self {
        mac.0
    }
}

impl std::str::FromStr for MacAddress {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Trait for reading/writing protocol fields from raw buffers.
pub trait Field: Sized {
    /// The size of this field in bytes (None for variable-length fields).
    const SIZE: Option<usize>;

    /// Read the field value from the buffer at the given offset.
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError>;

    /// Write the field value to the buffer at the given offset.
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError>;
}

// ============================================================================
// Field implementations for primitive types
// ============================================================================

impl Field for u8 {
    const SIZE: Option<usize> = Some(1);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        buf.get(offset)
            .copied()
            .ok_or_else(|| FieldError::BufferTooShort {
                offset,
                need: 1,
                have: buf.len(),
            })
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        let len = buf.len();
        *buf.get_mut(offset).ok_or(FieldError::BufferTooShort {
            offset,
            need: 1,
            have: len,
        })? = *self;
        Ok(())
    }
}

impl Field for u16 {
    const SIZE: Option<usize> = Some(2);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 2 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 2,
                have: buf.len(),
            });
        }
        let bytes = self.to_be_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
        Ok(())
    }
}

impl Field for u32 {
    const SIZE: Option<usize> = Some(4);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 4 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 4,
                have: buf.len(),
            });
        }
        Ok(u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 4 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 4,
                have: buf.len(),
            });
        }
        buf[offset..offset + 4].copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl Field for u64 {
    const SIZE: Option<usize> = Some(8);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 8 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 8,
                have: buf.len(),
            });
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[offset..offset + 8]);
        Ok(u64::from_be_bytes(bytes))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 8 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 8,
                have: buf.len(),
            });
        }
        buf[offset..offset + 8].copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl Field for MacAddress {
    const SIZE: Option<usize> = Some(6);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 6 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 6,
                have: buf.len(),
            });
        }
        Ok(Self([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
        ]))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 6 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 6,
                have: buf.len(),
            });
        }
        buf[offset..offset + 6].copy_from_slice(&self.0);
        Ok(())
    }
}

impl Field for Ipv4Addr {
    const SIZE: Option<usize> = Some(4);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 4 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 4,
                have: buf.len(),
            });
        }
        Ok(Ipv4Addr::new(
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 4 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 4,
                have: buf.len(),
            });
        }
        buf[offset..offset + 4].copy_from_slice(&self.octets());
        Ok(())
    }
}

impl Field for Ipv6Addr {
    const SIZE: Option<usize> = Some(16);

    #[inline]
    fn read(buf: &[u8], offset: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + 16 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 16,
                have: buf.len(),
            });
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&buf[offset..offset + 16]);
        Ok(Ipv6Addr::from(arr))
    }

    #[inline]
    fn write(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + 16 {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 16,
                have: buf.len(),
            });
        }
        buf[offset..offset + 16].copy_from_slice(&self.octets());
        Ok(())
    }
}

// ============================================================================
// Variable-length bytes field
// ============================================================================

/// A variable-length byte field
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct BytesField(pub Vec<u8>);

impl BytesField {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    pub fn from_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn read_with_len(buf: &[u8], offset: usize, len: usize) -> Result<Self, FieldError> {
        if buf.len() < offset + len {
            return Err(FieldError::BufferTooShort {
                offset,
                need: len,
                have: buf.len(),
            });
        }
        Ok(Self(buf[offset..offset + len].to_vec()))
    }

    pub fn write_to(&self, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + self.0.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: self.0.len(),
                have: buf.len(),
            });
        }
        buf[offset..offset + self.0.len()].copy_from_slice(&self.0);
        Ok(())
    }
}

impl From<Vec<u8>> for BytesField {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for BytesField {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

// ============================================================================
// Field descriptor for dynamic field definitions
// ============================================================================

/// Describes a field's position and type within a protocol header.
#[derive(Debug, Clone, Copy)]
pub struct FieldDesc {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
    pub field_type: FieldType,
}

/// Supported field types for dynamic access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    LEU16,
    LEU32,
    LEU64,
    U24,
    LEU24,
    Bool,
    Mac,
    Ipv4,
    Ipv6,
    Bytes,
    Str,
    DnsName,
}

impl FieldType {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::LEU16 => "le_u16",
            Self::LEU32 => "le_u32",
            Self::LEU64 => "le_u64",
            Self::U24 => "u24",
            Self::LEU24 => "le_u24",
            Self::Bool => "bool",
            Self::Mac => "MAC",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Bytes => "Bytes",
            Self::Str => "Str",
            Self::DnsName => "DnsName",
        }
    }

    pub const fn size(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 | Self::Bool => Some(1),
            Self::U16 | Self::I16 | Self::LEU16 => Some(2),
            Self::U24 | Self::LEU24 => Some(3),
            Self::U32 | Self::I32 | Self::LEU32 => Some(4),
            Self::U64 | Self::I64 | Self::LEU64 => Some(8),
            Self::Mac => Some(6),
            Self::Ipv4 => Some(4),
            Self::Ipv6 => Some(16),
            Self::Bytes | Self::Str | Self::DnsName => None,
        }
    }
}

impl FieldDesc {
    pub const fn new(
        name: &'static str,
        offset: usize,
        size: usize,
        field_type: FieldType,
    ) -> Self {
        Self {
            name,
            offset,
            size,
            field_type,
        }
    }

    #[inline]
    pub const fn with_offset(&self, base: usize) -> Self {
        Self {
            name: self.name,
            offset: base + self.offset,
            size: self.size,
            field_type: self.field_type,
        }
    }
}

/// A dynamically-typed field value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Bool(bool),
    Mac(MacAddress),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Bytes(Vec<u8>),
    Str(String),
    List(Vec<FieldValue>),
}

impl FieldValue {
    /// Read a field value from buffer using the field descriptor.
    pub fn read(buf: &[u8], desc: &FieldDesc) -> Result<Self, FieldError> {
        match desc.field_type {
            FieldType::U8 => Ok(Self::U8(u8::read(buf, desc.offset)?)),
            FieldType::U16 => Ok(Self::U16(u16::read(buf, desc.offset)?)),
            FieldType::U32 => Ok(Self::U32(u32::read(buf, desc.offset)?)),
            FieldType::U64 => Ok(Self::U64(u64::read(buf, desc.offset)?)),
            FieldType::I8 => Ok(Self::I8(read_i8(buf, desc.offset)?)),
            FieldType::I16 => Ok(Self::I16(read_i16_be(buf, desc.offset)?)),
            FieldType::I32 => Ok(Self::I32(read_i32_be(buf, desc.offset)?)),
            FieldType::I64 => Ok(Self::I64(read_i64_be(buf, desc.offset)?)),
            FieldType::LEU16 => Ok(Self::U16(read_u16_le(buf, desc.offset)?)),
            FieldType::LEU32 => Ok(Self::U32(read_u32_le(buf, desc.offset)?)),
            FieldType::LEU64 => Ok(Self::U64(read_u64_le(buf, desc.offset)?)),
            FieldType::U24 => Ok(Self::U32(read_u24_be(buf, desc.offset)?)),
            FieldType::LEU24 => Ok(Self::U32(read_u24_le(buf, desc.offset)?)),
            FieldType::Bool => Ok(Self::Bool(u8::read(buf, desc.offset)? != 0)),
            FieldType::Mac => Ok(Self::Mac(MacAddress::read(buf, desc.offset)?)),
            FieldType::Ipv4 => Ok(Self::Ipv4(Ipv4Addr::read(buf, desc.offset)?)),
            FieldType::Ipv6 => Ok(Self::Ipv6(Ipv6Addr::read(buf, desc.offset)?)),
            FieldType::Bytes => {
                let field = BytesField::read_with_len(buf, desc.offset, desc.size)?;
                Ok(Self::Bytes(field.0))
            },
            FieldType::Str => {
                let field = BytesField::read_with_len(buf, desc.offset, desc.size)?;
                Ok(Self::Str(String::from_utf8_lossy(&field.0).into_owned()))
            },
            FieldType::DnsName => {
                // DnsName requires special handling with the full packet buffer
                // Return raw bytes; callers should use dns::name module directly
                let field = BytesField::read_with_len(buf, desc.offset, desc.size)?;
                Ok(Self::Bytes(field.0))
            },
        }
    }

    /// Read a bytes field with explicit length
    pub fn read_bytes(buf: &[u8], offset: usize, len: usize) -> Result<Self, FieldError> {
        let field = BytesField::read_with_len(buf, offset, len)?;
        Ok(Self::Bytes(field.0))
    }

    /// Write a field value to buffer using the field descriptor.
    pub fn write(&self, buf: &mut [u8], desc: &FieldDesc) -> Result<(), FieldError> {
        match (self, desc.field_type) {
            (Self::U8(v), FieldType::U8) => v.write(buf, desc.offset),
            (Self::U16(v), FieldType::U16) => v.write(buf, desc.offset),
            (Self::U32(v), FieldType::U32) => v.write(buf, desc.offset),
            (Self::U64(v), FieldType::U64) => v.write(buf, desc.offset),
            (Self::I8(v), FieldType::I8) => write_i8(*v, buf, desc.offset),
            (Self::I16(v), FieldType::I16) => write_i16_be(*v, buf, desc.offset),
            (Self::I32(v), FieldType::I32) => write_i32_be(*v, buf, desc.offset),
            (Self::I64(v), FieldType::I64) => write_i64_be(*v, buf, desc.offset),
            (Self::U16(v), FieldType::LEU16) => write_u16_le(*v, buf, desc.offset),
            (Self::U32(v), FieldType::LEU32) => write_u32_le(*v, buf, desc.offset),
            (Self::U64(v), FieldType::LEU64) => write_u64_le(*v, buf, desc.offset),
            (Self::U32(v), FieldType::U24) => write_u24_be(*v, buf, desc.offset),
            (Self::U32(v), FieldType::LEU24) => write_u24_le(*v, buf, desc.offset),
            (Self::Bool(v), FieldType::Bool) => {
                (if *v { 1u8 } else { 0u8 }).write(buf, desc.offset)
            },
            (Self::Mac(v), FieldType::Mac) => v.write(buf, desc.offset),
            (Self::Ipv4(v), FieldType::Ipv4) => v.write(buf, desc.offset),
            (Self::Ipv6(v), FieldType::Ipv6) => v.write(buf, desc.offset),
            (Self::Bytes(v), FieldType::Bytes) => BytesField(v.clone()).write_to(buf, desc.offset),
            (Self::Str(v), FieldType::Str) => {
                BytesField(v.as_bytes().to_vec()).write_to(buf, desc.offset)
            },
            _ => Err(FieldError::TypeMismatch {
                expected: desc.field_type.name(),
                got: self.type_name(),
            }),
        }
    }

    /// Write bytes to buffer at offset
    pub fn write_bytes(bytes: &[u8], buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
        BytesField::from_slice(bytes).write_to(buf, offset)
    }

    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::U8(_) => "u8",
            Self::U16(_) => "u16",
            Self::U32(_) => "u32",
            Self::U64(_) => "u64",
            Self::I8(_) => "i8",
            Self::I16(_) => "i16",
            Self::I32(_) => "i32",
            Self::I64(_) => "i64",
            Self::Bool(_) => "bool",
            Self::Mac(_) => "MAC",
            Self::Ipv4(_) => "IPv4",
            Self::Ipv6(_) => "IPv6",
            Self::Bytes(_) => "Bytes",
            Self::Str(_) => "Str",
            Self::List(_) => "List",
        }
    }

    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::U8(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Self::U16(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_mac(&self) -> Option<MacAddress> {
        match self {
            Self::Mac(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Ipv6(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_i8(&self) -> Option<i8> {
        match self {
            Self::I8(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i16(&self) -> Option<i16> {
        match self {
            Self::I16(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[FieldValue]> {
        match self {
            Self::List(v) => Some(v),
            _ => None,
        }
    }

    /// Convert to bytes representation
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::U8(v) => vec![*v],
            Self::U16(v) => v.to_be_bytes().to_vec(),
            Self::U32(v) => v.to_be_bytes().to_vec(),
            Self::U64(v) => v.to_be_bytes().to_vec(),
            Self::I8(v) => v.to_be_bytes().to_vec(),
            Self::I16(v) => v.to_be_bytes().to_vec(),
            Self::I32(v) => v.to_be_bytes().to_vec(),
            Self::I64(v) => v.to_be_bytes().to_vec(),
            Self::Bool(v) => vec![if *v { 1 } else { 0 }],
            Self::Mac(v) => v.0.to_vec(),
            Self::Ipv4(v) => v.octets().to_vec(),
            Self::Ipv6(v) => v.octets().to_vec(),
            Self::Bytes(v) => v.clone(),
            Self::Str(v) => v.as_bytes().to_vec(),
            Self::List(v) => v.iter().flat_map(|f| f.to_bytes()).collect(),
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{}", v),
            Self::U16(v) => write!(f, "{:#06x}", v),
            Self::U32(v) => write!(f, "{:#010x}", v),
            Self::U64(v) => write!(f, "{:#018x}", v),
            Self::I8(v) => write!(f, "{}", v),
            Self::I16(v) => write!(f, "{}", v),
            Self::I32(v) => write!(f, "{}", v),
            Self::I64(v) => write!(f, "{}", v),
            Self::Bool(v) => write!(f, "{}", v),
            Self::Mac(v) => write!(f, "{}", v),
            Self::Ipv4(v) => write!(f, "{}", v),
            Self::Ipv6(v) => write!(f, "{}", v),
            Self::Bytes(v) => {
                write!(f, "0x")?;
                for b in v {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            },
            Self::Str(v) => write!(f, "{}", v),
            Self::List(v) => {
                write!(f, "[")?;
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            },
        }
    }
}

// Conversion traits
impl From<u8> for FieldValue {
    fn from(v: u8) -> Self {
        Self::U8(v)
    }
}
impl From<u16> for FieldValue {
    fn from(v: u16) -> Self {
        Self::U16(v)
    }
}
impl From<u32> for FieldValue {
    fn from(v: u32) -> Self {
        Self::U32(v)
    }
}
impl From<u64> for FieldValue {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}
impl From<MacAddress> for FieldValue {
    fn from(v: MacAddress) -> Self {
        Self::Mac(v)
    }
}
impl From<Ipv4Addr> for FieldValue {
    fn from(v: Ipv4Addr) -> Self {
        Self::Ipv4(v)
    }
}
impl From<Ipv6Addr> for FieldValue {
    fn from(v: Ipv6Addr) -> Self {
        Self::Ipv6(v)
    }
}
impl From<Vec<u8>> for FieldValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<&[u8]> for FieldValue {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}
impl From<i8> for FieldValue {
    fn from(v: i8) -> Self {
        Self::I8(v)
    }
}
impl From<i16> for FieldValue {
    fn from(v: i16) -> Self {
        Self::I16(v)
    }
}
impl From<i32> for FieldValue {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}
impl From<i64> for FieldValue {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}
impl From<bool> for FieldValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<String> for FieldValue {
    fn from(v: String) -> Self {
        Self::Str(v)
    }
}
impl From<&str> for FieldValue {
    fn from(v: &str) -> Self {
        Self::Str(v.to_string())
    }
}

// ============================================================================
// Little-endian and signed integer helpers
// ============================================================================

#[inline]
pub fn read_i8(buf: &[u8], offset: usize) -> Result<i8, FieldError> {
    Ok(u8::read(buf, offset)? as i8)
}

#[inline]
pub fn write_i8(v: i8, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    (v as u8).write(buf, offset)
}

#[inline]
pub fn read_i16_be(buf: &[u8], offset: usize) -> Result<i16, FieldError> {
    if buf.len() < offset + 2 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 2,
            have: buf.len(),
        });
    }
    Ok(i16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

#[inline]
pub fn write_i16_be(v: i16, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 2 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 2,
            have: buf.len(),
        });
    }
    buf[offset..offset + 2].copy_from_slice(&v.to_be_bytes());
    Ok(())
}

#[inline]
pub fn read_i32_be(buf: &[u8], offset: usize) -> Result<i32, FieldError> {
    if buf.len() < offset + 4 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 4,
            have: buf.len(),
        });
    }
    Ok(i32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

#[inline]
pub fn write_i32_be(v: i32, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 4 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 4,
            have: buf.len(),
        });
    }
    buf[offset..offset + 4].copy_from_slice(&v.to_be_bytes());
    Ok(())
}

#[inline]
pub fn read_i64_be(buf: &[u8], offset: usize) -> Result<i64, FieldError> {
    if buf.len() < offset + 8 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 8,
            have: buf.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    Ok(i64::from_be_bytes(bytes))
}

#[inline]
pub fn write_i64_be(v: i64, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 8 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 8,
            have: buf.len(),
        });
    }
    buf[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
    Ok(())
}

#[inline]
pub fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, FieldError> {
    if buf.len() < offset + 2 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 2,
            have: buf.len(),
        });
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

#[inline]
pub fn write_u16_le(v: u16, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 2 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 2,
            have: buf.len(),
        });
    }
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[inline]
pub fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, FieldError> {
    if buf.len() < offset + 4 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 4,
            have: buf.len(),
        });
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

#[inline]
pub fn write_u32_le(v: u32, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 4 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 4,
            have: buf.len(),
        });
    }
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[inline]
pub fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, FieldError> {
    if buf.len() < offset + 8 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 8,
            have: buf.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    Ok(u64::from_le_bytes(bytes))
}

#[inline]
pub fn write_u64_le(v: u64, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 8 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 8,
            have: buf.len(),
        });
    }
    buf[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
    Ok(())
}

#[inline]
pub fn read_u24_be(buf: &[u8], offset: usize) -> Result<u32, FieldError> {
    if buf.len() < offset + 3 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 3,
            have: buf.len(),
        });
    }
    Ok(((buf[offset] as u32) << 16) | ((buf[offset + 1] as u32) << 8) | (buf[offset + 2] as u32))
}

#[inline]
pub fn write_u24_be(v: u32, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 3 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 3,
            have: buf.len(),
        });
    }
    buf[offset] = ((v >> 16) & 0xFF) as u8;
    buf[offset + 1] = ((v >> 8) & 0xFF) as u8;
    buf[offset + 2] = (v & 0xFF) as u8;
    Ok(())
}

#[inline]
pub fn read_u24_le(buf: &[u8], offset: usize) -> Result<u32, FieldError> {
    if buf.len() < offset + 3 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 3,
            have: buf.len(),
        });
    }
    Ok((buf[offset] as u32) | ((buf[offset + 1] as u32) << 8) | ((buf[offset + 2] as u32) << 16))
}

#[inline]
pub fn write_u24_le(v: u32, buf: &mut [u8], offset: usize) -> Result<(), FieldError> {
    if buf.len() < offset + 3 {
        return Err(FieldError::BufferTooShort {
            offset,
            need: 3,
            have: buf.len(),
        });
    }
    buf[offset] = (v & 0xFF) as u8;
    buf[offset + 1] = ((v >> 8) & 0xFF) as u8;
    buf[offset + 2] = ((v >> 16) & 0xFF) as u8;
    Ok(())
}

// ============================================================================
// Bit field reader/writer for arbitrary bit-width fields
// ============================================================================

/// Read arbitrary number of bits from a byte buffer at a bit offset.
/// `bit_offset` is the starting bit position (0 = MSB of first byte).
/// `num_bits` is 1..=64.
/// Returns the value right-aligned in a u64.
#[inline]
pub fn read_bits_be(buf: &[u8], bit_offset: usize, num_bits: usize) -> Result<u64, FieldError> {
    if num_bits == 0 || num_bits > 64 {
        return Err(FieldError::InvalidValue(format!(
            "num_bits must be 1..=64, got {}",
            num_bits
        )));
    }
    let end_bit = bit_offset + num_bits;
    let end_byte = (end_bit + 7) / 8;
    if end_byte > buf.len() {
        return Err(FieldError::BufferTooShort {
            offset: bit_offset / 8,
            need: end_byte,
            have: buf.len(),
        });
    }

    let mut result: u64 = 0;
    for i in 0..num_bits {
        let bit_pos = bit_offset + i;
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8); // MSB first
        if (buf[byte_idx] >> bit_idx) & 1 != 0 {
            result |= 1u64 << (num_bits - 1 - i);
        }
    }
    Ok(result)
}

/// Write arbitrary number of bits to a byte buffer at a bit offset.
/// `bit_offset` is the starting bit position (0 = MSB of first byte).
/// `num_bits` is 1..=64.
/// `value` is right-aligned.
#[inline]
pub fn write_bits_be(
    buf: &mut [u8],
    bit_offset: usize,
    num_bits: usize,
    value: u64,
) -> Result<(), FieldError> {
    if num_bits == 0 || num_bits > 64 {
        return Err(FieldError::InvalidValue(format!(
            "num_bits must be 1..=64, got {}",
            num_bits
        )));
    }
    let end_bit = bit_offset + num_bits;
    let end_byte = (end_bit + 7) / 8;
    if end_byte > buf.len() {
        return Err(FieldError::BufferTooShort {
            offset: bit_offset / 8,
            need: end_byte,
            have: buf.len(),
        });
    }

    for i in 0..num_bits {
        let bit_pos = bit_offset + i;
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8); // MSB first
        let bit_val = (value >> (num_bits - 1 - i)) & 1;
        if bit_val != 0 {
            buf[byte_idx] |= 1 << bit_idx;
        } else {
            buf[byte_idx] &= !(1 << bit_idx);
        }
    }
    Ok(())
}

/// Read bits in little-endian bit order (LSB of first byte = bit 0).
#[inline]
pub fn read_bits_le(buf: &[u8], bit_offset: usize, num_bits: usize) -> Result<u64, FieldError> {
    if num_bits == 0 || num_bits > 64 {
        return Err(FieldError::InvalidValue(format!(
            "num_bits must be 1..=64, got {}",
            num_bits
        )));
    }
    let end_bit = bit_offset + num_bits;
    let end_byte = (end_bit + 7) / 8;
    if end_byte > buf.len() {
        return Err(FieldError::BufferTooShort {
            offset: bit_offset / 8,
            need: end_byte,
            have: buf.len(),
        });
    }

    let mut result: u64 = 0;
    for i in 0..num_bits {
        let bit_pos = bit_offset + i;
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8; // LSB first
        if (buf[byte_idx] >> bit_idx) & 1 != 0 {
            result |= 1u64 << i;
        }
    }
    Ok(result)
}

/// Write bits in little-endian bit order (LSB of first byte = bit 0).
#[inline]
pub fn write_bits_le(
    buf: &mut [u8],
    bit_offset: usize,
    num_bits: usize,
    value: u64,
) -> Result<(), FieldError> {
    if num_bits == 0 || num_bits > 64 {
        return Err(FieldError::InvalidValue(format!(
            "num_bits must be 1..=64, got {}",
            num_bits
        )));
    }
    let end_bit = bit_offset + num_bits;
    let end_byte = (end_bit + 7) / 8;
    if end_byte > buf.len() {
        return Err(FieldError::BufferTooShort {
            offset: bit_offset / 8,
            need: end_byte,
            have: buf.len(),
        });
    }

    for i in 0..num_bits {
        let bit_pos = bit_offset + i;
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8; // LSB first
        let bit_val = (value >> i) & 1;
        if bit_val != 0 {
            buf[byte_idx] |= 1 << bit_idx;
        } else {
            buf[byte_idx] &= !(1 << bit_idx);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_field() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut buf = [0u8; 20];
        ip.write(&mut buf, 2).unwrap();
        let read_ip = Ipv6Addr::read(&buf, 2).unwrap();
        assert_eq!(ip, read_ip);
    }

    #[test]
    fn test_bytes_field() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0u8; 10];
        BytesField(data.clone()).write_to(&mut buf, 2).unwrap();
        let read = BytesField::read_with_len(&buf, 2, 4).unwrap();
        assert_eq!(read.0, data);
    }

    #[test]
    fn test_field_value_ipv6() {
        let ip = Ipv6Addr::LOCALHOST;
        let val = FieldValue::from(ip);
        assert_eq!(val.as_ipv6(), Some(ip));
        assert_eq!(val.type_name(), "IPv6");
    }

    #[test]
    fn test_mac_multicast() {
        let mcast = MacAddress::from_ipv4_multicast(Ipv4Addr::new(224, 0, 0, 1));
        assert!(mcast.is_ipv4_multicast());
        assert!(mcast.is_multicast());
    }

    #[test]
    fn test_u64_field() {
        let mut buf = [0u8; 10];
        let val: u64 = 0x0102030405060708;
        val.write(&mut buf, 1).unwrap();
        assert_eq!(u64::read(&buf, 1).unwrap(), val);
    }

    #[test]
    fn test_i8_read_write() {
        let mut buf = [0u8; 4];
        write_i8(-42, &mut buf, 1).unwrap();
        assert_eq!(read_i8(&buf, 1).unwrap(), -42);
        write_i8(127, &mut buf, 0).unwrap();
        assert_eq!(read_i8(&buf, 0).unwrap(), 127);
    }

    #[test]
    fn test_i16_read_write() {
        let mut buf = [0u8; 4];
        write_i16_be(-1234, &mut buf, 1).unwrap();
        assert_eq!(read_i16_be(&buf, 1).unwrap(), -1234);
    }

    #[test]
    fn test_i32_read_write() {
        let mut buf = [0u8; 8];
        write_i32_be(-100_000, &mut buf, 2).unwrap();
        assert_eq!(read_i32_be(&buf, 2).unwrap(), -100_000);
    }

    #[test]
    fn test_i64_read_write() {
        let mut buf = [0u8; 10];
        write_i64_be(-1_000_000_000_000, &mut buf, 1).unwrap();
        assert_eq!(read_i64_be(&buf, 1).unwrap(), -1_000_000_000_000);
    }

    #[test]
    fn test_u16_le_read_write() {
        let mut buf = [0u8; 4];
        write_u16_le(0x0102, &mut buf, 1).unwrap();
        assert_eq!(buf[1], 0x02); // LE: low byte first
        assert_eq!(buf[2], 0x01);
        assert_eq!(read_u16_le(&buf, 1).unwrap(), 0x0102);
    }

    #[test]
    fn test_u32_le_read_write() {
        let mut buf = [0u8; 6];
        write_u32_le(0x01020304, &mut buf, 1).unwrap();
        assert_eq!(read_u32_le(&buf, 1).unwrap(), 0x01020304);
    }

    #[test]
    fn test_u64_le_read_write() {
        let mut buf = [0u8; 10];
        write_u64_le(0x0102030405060708, &mut buf, 1).unwrap();
        assert_eq!(read_u64_le(&buf, 1).unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_u24_be_read_write() {
        let mut buf = [0u8; 5];
        write_u24_be(0x123456, &mut buf, 1).unwrap();
        assert_eq!(buf[1], 0x12);
        assert_eq!(buf[2], 0x34);
        assert_eq!(buf[3], 0x56);
        assert_eq!(read_u24_be(&buf, 1).unwrap(), 0x123456);
    }

    #[test]
    fn test_u24_le_read_write() {
        let mut buf = [0u8; 5];
        write_u24_le(0x123456, &mut buf, 1).unwrap();
        assert_eq!(buf[1], 0x56); // LE: low byte first
        assert_eq!(buf[2], 0x34);
        assert_eq!(buf[3], 0x12);
        assert_eq!(read_u24_le(&buf, 1).unwrap(), 0x123456);
    }

    #[test]
    fn test_read_bits_be() {
        // byte 0xA5 = 1010_0101
        let buf = [0xA5u8];
        assert_eq!(read_bits_be(&buf, 0, 1).unwrap(), 1); // bit 7 = 1
        assert_eq!(read_bits_be(&buf, 1, 1).unwrap(), 0); // bit 6 = 0
        assert_eq!(read_bits_be(&buf, 0, 4).unwrap(), 0b1010); // top nibble
        assert_eq!(read_bits_be(&buf, 4, 4).unwrap(), 0b0101); // bottom nibble
        assert_eq!(read_bits_be(&buf, 0, 8).unwrap(), 0xA5); // full byte
    }

    #[test]
    fn test_write_bits_be() {
        let mut buf = [0u8; 2];
        write_bits_be(&mut buf, 0, 4, 0b1010).unwrap();
        write_bits_be(&mut buf, 4, 4, 0b0101).unwrap();
        assert_eq!(buf[0], 0xA5);
    }

    #[test]
    fn test_bits_be_cross_byte() {
        let buf = [0b1100_0011, 0b1010_0101];
        // Read 4 bits spanning bytes: bits 6,7 of byte 0 + bits 0,1 of byte 1
        assert_eq!(read_bits_be(&buf, 6, 4).unwrap(), 0b1110);
    }

    #[test]
    fn test_read_bits_le() {
        // For LE bit ordering, bit 0 is LSB of first byte
        let buf = [0xA5u8]; // 1010_0101
        assert_eq!(read_bits_le(&buf, 0, 1).unwrap(), 1); // bit 0 (LSB) = 1
        assert_eq!(read_bits_le(&buf, 1, 1).unwrap(), 0); // bit 1 = 0
        assert_eq!(read_bits_le(&buf, 0, 4).unwrap(), 0b0101); // low nibble
        assert_eq!(read_bits_le(&buf, 4, 4).unwrap(), 0b1010); // high nibble
    }

    #[test]
    fn test_write_bits_le() {
        let mut buf = [0u8; 2];
        // Write 3 bits at bit offset 0 (LE): value 5 = 0b101
        write_bits_le(&mut buf, 0, 3, 0b101).unwrap();
        assert_eq!(buf[0] & 0x07, 0b101);
    }

    #[test]
    fn test_field_value_new_types() {
        assert_eq!(FieldValue::from(-42i8).as_i8(), Some(-42));
        assert_eq!(FieldValue::from(-1000i16).as_i16(), Some(-1000));
        assert_eq!(FieldValue::from(-100_000i32).as_i32(), Some(-100_000));
        assert_eq!(FieldValue::from(-1i64).as_i64(), Some(-1));
        assert_eq!(FieldValue::from(true).as_bool(), Some(true));
        assert_eq!(FieldValue::from(false).as_bool(), Some(false));
        assert_eq!(FieldValue::from("hello").as_str(), Some("hello"));
    }

    #[test]
    fn test_field_value_list() {
        let list = FieldValue::List(vec![
            FieldValue::U16(1),
            FieldValue::U16(2),
            FieldValue::U16(3),
        ]);
        assert_eq!(list.as_list().unwrap().len(), 3);
        assert_eq!(list.to_string(), "[0x0001, 0x0002, 0x0003]");
    }

    #[test]
    fn test_buffer_too_short_errors() {
        let buf = [0u8; 2];
        assert!(read_u24_be(&buf, 0).is_err());
        assert!(read_u32_le(&buf, 0).is_err());
        assert!(read_i32_be(&buf, 0).is_err());
        assert!(read_bits_be(&buf, 0, 24).is_err());
    }
}
