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
    Mac,
    Ipv4,
    Ipv6,
    Bytes,
}

impl FieldType {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::Mac => "MAC",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Bytes => "Bytes",
        }
    }

    pub const fn size(&self) -> Option<usize> {
        match self {
            Self::U8 => Some(1),
            Self::U16 => Some(2),
            Self::U32 => Some(4),
            Self::U64 => Some(8),
            Self::Mac => Some(6),
            Self::Ipv4 => Some(4),
            Self::Ipv6 => Some(16),
            Self::Bytes => None,
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
    Mac(MacAddress),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Bytes(Vec<u8>),
}

impl FieldValue {
    /// Read a field value from buffer using the field descriptor.
    pub fn read(buf: &[u8], desc: &FieldDesc) -> Result<Self, FieldError> {
        match desc.field_type {
            FieldType::U8 => Ok(Self::U8(u8::read(buf, desc.offset)?)),
            FieldType::U16 => Ok(Self::U16(u16::read(buf, desc.offset)?)),
            FieldType::U32 => Ok(Self::U32(u32::read(buf, desc.offset)?)),
            FieldType::U64 => Ok(Self::U64(u64::read(buf, desc.offset)?)),
            FieldType::Mac => Ok(Self::Mac(MacAddress::read(buf, desc.offset)?)),
            FieldType::Ipv4 => Ok(Self::Ipv4(Ipv4Addr::read(buf, desc.offset)?)),
            FieldType::Ipv6 => Ok(Self::Ipv6(Ipv6Addr::read(buf, desc.offset)?)),
            FieldType::Bytes => {
                let field = BytesField::read_with_len(buf, desc.offset, desc.size)?;
                Ok(Self::Bytes(field.0))
            }
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
            (Self::Mac(v), FieldType::Mac) => v.write(buf, desc.offset),
            (Self::Ipv4(v), FieldType::Ipv4) => v.write(buf, desc.offset),
            (Self::Ipv6(v), FieldType::Ipv6) => v.write(buf, desc.offset),
            (Self::Bytes(v), FieldType::Bytes) => BytesField(v.clone()).write_to(buf, desc.offset),
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
            Self::Mac(_) => "MAC",
            Self::Ipv4(_) => "IPv4",
            Self::Ipv6(_) => "IPv6",
            Self::Bytes(_) => "Bytes",
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

    /// Convert to bytes representation
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::U8(v) => vec![*v],
            Self::U16(v) => v.to_be_bytes().to_vec(),
            Self::U32(v) => v.to_be_bytes().to_vec(),
            Self::U64(v) => v.to_be_bytes().to_vec(),
            Self::Mac(v) => v.0.to_vec(),
            Self::Ipv4(v) => v.octets().to_vec(),
            Self::Ipv6(v) => v.octets().to_vec(),
            Self::Bytes(v) => v.clone(),
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
            Self::Mac(v) => write!(f, "{}", v),
            Self::Ipv4(v) => write!(f, "{}", v),
            Self::Ipv6(v) => write!(f, "{}", v),
            Self::Bytes(v) => {
                write!(f, "0x")?;
                for b in v {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
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
}
