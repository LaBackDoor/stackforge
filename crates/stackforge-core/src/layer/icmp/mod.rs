//! ICMP (Internet Control Message Protocol) layer implementation.
//!
//! This module provides types and functions for working with ICMP packets,
//! including parsing, field access, and checksum calculation.

pub mod builder;
pub mod checksum;
pub mod error;
pub mod extensions;
pub mod types;

// Re-export builder
pub use builder::IcmpBuilder;

// Re-export checksum functions
pub use checksum::{icmp_checksum, verify_icmp_checksum};
pub use error::{ERROR_MIN_PAYLOAD, ERROR_TYPES, error_payload_offset, is_error_type};
pub use extensions::{
    InterfaceInformation, IpAddr, class_name as extension_class_name, has_extensions,
    parse_extension_header, parse_extension_object, parse_interface_information,
};
pub use types::{ICMP_ANSWERS, code_name, type_name};

use crate::layer::field::{FieldDesc, FieldError, FieldType, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};
use std::net::Ipv4Addr;

/// ICMP minimum header length (8 bytes).
pub const ICMP_MIN_HEADER_LEN: usize = 8;

/// Field offsets within the ICMP header.
pub mod offsets {
    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: usize = 2;

    // Conditional fields based on type

    // Echo request/reply (types 0, 8) and other ID/Seq types
    pub const ID: usize = 4;
    pub const SEQ: usize = 6;

    // Redirect (type 5)
    pub const GATEWAY: usize = 4;

    // Destination unreachable (type 3)
    pub const UNUSED_DU: usize = 4;
    pub const LENGTH_DU: usize = 5;
    pub const NEXT_HOP_MTU: usize = 6;

    // Time exceeded (type 11)
    pub const UNUSED_TE: usize = 4;
    pub const LENGTH_TE: usize = 6;

    // Parameter problem (type 12)
    pub const PTR: usize = 4;
    pub const UNUSED_PP: usize = 5;
    pub const LENGTH_PP: usize = 6;

    // Timestamp request/reply (types 13, 14)
    pub const TS_ORI: usize = 8;
    pub const TS_RX: usize = 12;
    pub const TS_TX: usize = 16;

    // Address mask request/reply (types 17, 18)
    pub const ADDR_MASK: usize = 4;
}

/// ICMP field descriptors for dynamic access.
pub static FIELDS: &[FieldDesc] = &[
    FieldDesc::new("type", offsets::TYPE, 1, FieldType::U8),
    FieldDesc::new("code", offsets::CODE, 1, FieldType::U8),
    FieldDesc::new("chksum", offsets::CHECKSUM, 2, FieldType::U16),
    // Conditional fields - available based on ICMP type
    FieldDesc::new("id", offsets::ID, 2, FieldType::U16),
    FieldDesc::new("seq", offsets::SEQ, 2, FieldType::U16),
];

/// ICMP layer representation.
///
/// ICMP is the control protocol for IP, defined in RFC 792.
/// The header format varies based on message type:
///
/// ```text
/// Base header (all types):
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    (Type-specific data)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Echo/Echo Reply (type 0, 8):
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Identifier           |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Redirect (type 5):
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Gateway IP Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct IcmpLayer {
    pub index: LayerIndex,
}

impl IcmpLayer {
    /// Create a new ICMP layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Get the ICMP type.
    pub fn icmp_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::TYPE,
                need: 1,
                have: 0,
            });
        }
        Ok(slice[offsets::TYPE])
    }

    /// Get the ICMP code.
    pub fn code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::CODE + 1 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::CODE,
                need: 1,
                have: slice.len().saturating_sub(offsets::CODE),
            });
        }
        Ok(slice[offsets::CODE])
    }

    /// Get the checksum.
    pub fn checksum(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < offsets::CHECKSUM + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::CHECKSUM,
                need: 2,
                have: slice.len().saturating_sub(offsets::CHECKSUM),
            });
        }
        Ok(u16::from_be_bytes([
            slice[offsets::CHECKSUM],
            slice[offsets::CHECKSUM + 1],
        ]))
    }

    /// Get the identifier (for echo, timestamp).
    ///
    /// Returns None if this ICMP type doesn't have an ID field.
    pub fn id(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        // ID field only exists for certain types
        if !matches!(
            icmp_type,
            types::types::ECHO_REQUEST
                | types::types::ECHO_REPLY
                | types::types::TIMESTAMP
                | types::types::TIMESTAMP_REPLY
                | types::types::INFO_REQUEST
                | types::types::INFO_REPLY
                | types::types::ADDRESS_MASK_REQUEST
                | types::types::ADDRESS_MASK_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::ID + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::ID,
                need: 2,
                have: slice.len().saturating_sub(offsets::ID),
            });
        }
        Ok(Some(u16::from_be_bytes([
            slice[offsets::ID],
            slice[offsets::ID + 1],
        ])))
    }

    /// Get the sequence number (for echo, timestamp).
    ///
    /// Returns None if this ICMP type doesn't have a sequence field.
    pub fn seq(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        // Sequence field only exists for certain types
        if !matches!(
            icmp_type,
            types::types::ECHO_REQUEST
                | types::types::ECHO_REPLY
                | types::types::TIMESTAMP
                | types::types::TIMESTAMP_REPLY
                | types::types::INFO_REQUEST
                | types::types::INFO_REPLY
                | types::types::ADDRESS_MASK_REQUEST
                | types::types::ADDRESS_MASK_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::SEQ + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::SEQ,
                need: 2,
                have: slice.len().saturating_sub(offsets::SEQ),
            });
        }
        Ok(Some(u16::from_be_bytes([
            slice[offsets::SEQ],
            slice[offsets::SEQ + 1],
        ])))
    }

    /// Get the gateway address (for redirect messages).
    ///
    /// Returns None if this is not a redirect message.
    pub fn gateway(&self, buf: &[u8]) -> Result<Option<Ipv4Addr>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if icmp_type != types::types::REDIRECT {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::GATEWAY + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::GATEWAY,
                need: 4,
                have: slice.len().saturating_sub(offsets::GATEWAY),
            });
        }

        Ok(Some(Ipv4Addr::new(
            slice[offsets::GATEWAY],
            slice[offsets::GATEWAY + 1],
            slice[offsets::GATEWAY + 2],
            slice[offsets::GATEWAY + 3],
        )))
    }

    /// Get the next-hop MTU (for destination unreachable, fragmentation needed).
    ///
    /// Returns None if this is not a dest unreachable with code 4 (fragmentation needed).
    pub fn next_hop_mtu(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;
        let code = self.code(buf)?;

        // Only valid for dest unreachable type 3, code 4 (fragmentation needed)
        if icmp_type != types::types::DEST_UNREACH || code != 4 {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::NEXT_HOP_MTU + 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::NEXT_HOP_MTU,
                need: 2,
                have: slice.len().saturating_sub(offsets::NEXT_HOP_MTU),
            });
        }

        Ok(Some(u16::from_be_bytes([
            slice[offsets::NEXT_HOP_MTU],
            slice[offsets::NEXT_HOP_MTU + 1],
        ])))
    }

    /// Get the pointer field (for parameter problem).
    ///
    /// Returns None if this is not a parameter problem message.
    pub fn ptr(&self, buf: &[u8]) -> Result<Option<u8>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if icmp_type != types::types::PARAM_PROBLEM {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::PTR + 1 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::PTR,
                need: 1,
                have: slice.len().saturating_sub(offsets::PTR),
            });
        }

        Ok(Some(slice[offsets::PTR]))
    }

    /// Get the originate timestamp (for timestamp request/reply).
    ///
    /// Returns None if this is not a timestamp message.
    /// Timestamp is in milliseconds since midnight UT.
    pub fn ts_ori(&self, buf: &[u8]) -> Result<Option<u32>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if !matches!(
            icmp_type,
            types::types::TIMESTAMP | types::types::TIMESTAMP_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::TS_ORI + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::TS_ORI,
                need: 4,
                have: slice.len().saturating_sub(offsets::TS_ORI),
            });
        }

        Ok(Some(u32::from_be_bytes([
            slice[offsets::TS_ORI],
            slice[offsets::TS_ORI + 1],
            slice[offsets::TS_ORI + 2],
            slice[offsets::TS_ORI + 3],
        ])))
    }

    /// Get the receive timestamp (for timestamp request/reply).
    ///
    /// Returns None if this is not a timestamp message.
    /// Timestamp is in milliseconds since midnight UT.
    pub fn ts_rx(&self, buf: &[u8]) -> Result<Option<u32>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if !matches!(
            icmp_type,
            types::types::TIMESTAMP | types::types::TIMESTAMP_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::TS_RX + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::TS_RX,
                need: 4,
                have: slice.len().saturating_sub(offsets::TS_RX),
            });
        }

        Ok(Some(u32::from_be_bytes([
            slice[offsets::TS_RX],
            slice[offsets::TS_RX + 1],
            slice[offsets::TS_RX + 2],
            slice[offsets::TS_RX + 3],
        ])))
    }

    /// Get the transmit timestamp (for timestamp request/reply).
    ///
    /// Returns None if this is not a timestamp message.
    /// Timestamp is in milliseconds since midnight UT.
    pub fn ts_tx(&self, buf: &[u8]) -> Result<Option<u32>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if !matches!(
            icmp_type,
            types::types::TIMESTAMP | types::types::TIMESTAMP_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::TS_TX + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::TS_TX,
                need: 4,
                have: slice.len().saturating_sub(offsets::TS_TX),
            });
        }

        Ok(Some(u32::from_be_bytes([
            slice[offsets::TS_TX],
            slice[offsets::TS_TX + 1],
            slice[offsets::TS_TX + 2],
            slice[offsets::TS_TX + 3],
        ])))
    }

    /// Get the address mask (for address mask request/reply).
    ///
    /// Returns None if this is not an address mask message.
    pub fn addr_mask(&self, buf: &[u8]) -> Result<Option<Ipv4Addr>, FieldError> {
        let icmp_type = self.icmp_type(buf)?;

        if !matches!(
            icmp_type,
            types::types::ADDRESS_MASK_REQUEST | types::types::ADDRESS_MASK_REPLY
        ) {
            return Ok(None);
        }

        let slice = self.index.slice(buf);
        if slice.len() < offsets::ADDR_MASK + 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + offsets::ADDR_MASK,
                need: 4,
                have: slice.len().saturating_sub(offsets::ADDR_MASK),
            });
        }

        Ok(Some(Ipv4Addr::new(
            slice[offsets::ADDR_MASK],
            slice[offsets::ADDR_MASK + 1],
            slice[offsets::ADDR_MASK + 2],
            slice[offsets::ADDR_MASK + 3],
        )))
    }

    /// Set the ICMP type.
    pub fn set_type(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let start = self.index.start + offsets::TYPE;
        if buf.len() < start + 1 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 1,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start] = value;
        Ok(())
    }

    /// Set the ICMP code.
    pub fn set_code(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let start = self.index.start + offsets::CODE;
        if buf.len() < start + 1 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 1,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start] = value;
        Ok(())
    }

    /// Set the checksum.
    pub fn set_checksum(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::CHECKSUM;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the identifier (for echo, timestamp).
    pub fn set_id(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::ID;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the sequence number (for echo, timestamp).
    pub fn set_seq(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::SEQ;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the gateway address (for redirect).
    pub fn set_gateway(&self, buf: &mut [u8], value: Ipv4Addr) -> Result<(), FieldError> {
        let start = self.index.start + offsets::GATEWAY;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 4,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 4].copy_from_slice(&value.octets());
        Ok(())
    }

    /// Set the next-hop MTU (for destination unreachable, fragmentation needed).
    pub fn set_next_hop_mtu(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start + offsets::NEXT_HOP_MTU;
        if buf.len() < start + 2 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 2,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the pointer field (for parameter problem).
    pub fn set_ptr(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let start = self.index.start + offsets::PTR;
        if buf.len() < start + 1 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 1,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start] = value;
        Ok(())
    }

    /// Set the originate timestamp (for timestamp request/reply).
    pub fn set_ts_ori(&self, buf: &mut [u8], value: u32) -> Result<(), FieldError> {
        let start = self.index.start + offsets::TS_ORI;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 4,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the receive timestamp (for timestamp request/reply).
    pub fn set_ts_rx(&self, buf: &mut [u8], value: u32) -> Result<(), FieldError> {
        let start = self.index.start + offsets::TS_RX;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 4,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the transmit timestamp (for timestamp request/reply).
    pub fn set_ts_tx(&self, buf: &mut [u8], value: u32) -> Result<(), FieldError> {
        let start = self.index.start + offsets::TS_TX;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 4,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the address mask (for address mask request/reply).
    pub fn set_addr_mask(&self, buf: &mut [u8], value: Ipv4Addr) -> Result<(), FieldError> {
        let start = self.index.start + offsets::ADDR_MASK;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start,
                need: 4,
                have: buf.len().saturating_sub(start),
            });
        }
        buf[start..start + 4].copy_from_slice(&value.octets());
        Ok(())
    }

    /// Generate a summary string for display.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        if let (Ok(icmp_type), Ok(code)) = (self.icmp_type(buf), self.code(buf)) {
            let type_str = type_name(icmp_type);
            let code_str = code_name(icmp_type, code);

            // Add type-specific details
            let details = match icmp_type {
                types::types::REDIRECT => {
                    if let Ok(Some(gw)) = self.gateway(buf) {
                        format!(" gw={gw}")
                    } else {
                        String::new()
                    }
                },
                types::types::DEST_UNREACH if code == 4 => {
                    // Fragmentation needed
                    if let Ok(Some(mtu)) = self.next_hop_mtu(buf) {
                        format!(" mtu={mtu}")
                    } else {
                        String::new()
                    }
                },
                types::types::PARAM_PROBLEM => {
                    if let Ok(Some(ptr)) = self.ptr(buf) {
                        format!(" ptr={ptr}")
                    } else {
                        String::new()
                    }
                },
                types::types::ECHO_REQUEST | types::types::ECHO_REPLY => {
                    let id_str = self
                        .id(buf)
                        .ok()
                        .flatten()
                        .map(|id| format!(" id={id}"))
                        .unwrap_or_default();
                    let seq_str = self
                        .seq(buf)
                        .ok()
                        .flatten()
                        .map(|seq| format!(" seq={seq}"))
                        .unwrap_or_default();
                    format!("{id_str}{seq_str}")
                },
                _ => String::new(),
            };

            format!("ICMP {type_str} {code_str}{details}")
        } else {
            "ICMP".to_string()
        }
    }

    /// Get the ICMP header length (variable based on type).
    #[must_use]
    pub fn header_len(&self, buf: &[u8]) -> usize {
        // Most ICMP types have 8-byte header
        // Timestamp has 20-byte header (8 base + 12 for timestamps)
        if let Ok(icmp_type) = self.icmp_type(buf) {
            match icmp_type {
                types::types::TIMESTAMP | types::types::TIMESTAMP_REPLY => 20,
                _ => ICMP_MIN_HEADER_LEN,
            }
        } else {
            ICMP_MIN_HEADER_LEN
        }
    }

    /// Get field names for this layer.
    #[must_use]
    pub fn field_names(&self) -> &'static [&'static str] {
        &[
            "type",
            "code",
            "chksum",
            "id",
            "seq",
            "gw",
            "ptr",
            "mtu",
            "ts_ori",
            "ts_rx",
            "ts_tx",
            "addr_mask",
        ]
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "type" => Some(self.icmp_type(buf).map(FieldValue::U8)),
            "code" => Some(self.code(buf).map(FieldValue::U8)),
            "chksum" => Some(self.checksum(buf).map(FieldValue::U16)),
            "id" => Some(
                self.id(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "id field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U16),
            ),
            "seq" => Some(
                self.seq(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "seq field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U16),
            ),
            "gw" => Some(
                self.gateway(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "gw field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::Ipv4),
            ),
            "ptr" => Some(
                self.ptr(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "ptr field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U8),
            ),
            "mtu" => Some(
                self.next_hop_mtu(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "mtu field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U16),
            ),
            "ts_ori" => Some(
                self.ts_ori(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "ts_ori field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U32),
            ),
            "ts_rx" => Some(
                self.ts_rx(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "ts_rx field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U32),
            ),
            "ts_tx" => Some(
                self.ts_tx(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "ts_tx field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::U32),
            ),
            "addr_mask" => Some(
                self.addr_mask(buf)
                    .and_then(|opt| {
                        opt.ok_or(FieldError::InvalidValue(
                            "addr_mask field not available for this ICMP type".into(),
                        ))
                    })
                    .map(FieldValue::Ipv4),
            ),
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
        match name {
            "type" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_type(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "type: expected U8, got {value:?}"
                    ))))
                }
            },
            "code" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_code(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "code: expected U8, got {value:?}"
                    ))))
                }
            },
            "chksum" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_checksum(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "chksum: expected U16, got {value:?}"
                    ))))
                }
            },
            "id" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "id: expected U16, got {value:?}"
                    ))))
                }
            },
            "seq" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_seq(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "seq: expected U16, got {value:?}"
                    ))))
                }
            },
            "gw" => {
                if let FieldValue::Ipv4(v) = value {
                    Some(self.set_gateway(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "gw: expected Ipv4, got {value:?}"
                    ))))
                }
            },
            "ptr" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_ptr(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ptr: expected U8, got {value:?}"
                    ))))
                }
            },
            "mtu" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_next_hop_mtu(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "mtu: expected U16, got {value:?}"
                    ))))
                }
            },
            "ts_ori" => {
                if let FieldValue::U32(v) = value {
                    Some(self.set_ts_ori(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ts_ori: expected U32, got {value:?}"
                    ))))
                }
            },
            "ts_rx" => {
                if let FieldValue::U32(v) = value {
                    Some(self.set_ts_rx(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ts_rx: expected U32, got {value:?}"
                    ))))
                }
            },
            "ts_tx" => {
                if let FieldValue::U32(v) = value {
                    Some(self.set_ts_tx(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "ts_tx: expected U32, got {value:?}"
                    ))))
                }
            },
            "addr_mask" => {
                if let FieldValue::Ipv4(v) = value {
                    Some(self.set_addr_mask(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "addr_mask: expected Ipv4, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for IcmpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Icmp
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.header_len(data)
    }

    fn hashret(&self, data: &[u8]) -> Vec<u8> {
        // For echo request/reply, return id+seq as hash
        if let (Ok(Some(id)), Ok(Some(seq))) = (self.id(data), self.seq(data)) {
            let mut hash = Vec::with_capacity(4);
            hash.extend_from_slice(&id.to_be_bytes());
            hash.extend_from_slice(&seq.to_be_bytes());
            hash
        } else {
            // For other types, return empty (no session concept)
            vec![]
        }
    }

    fn answers(&self, data: &[u8], other: &Self, other_data: &[u8]) -> bool {
        // Check if this ICMP message answers another
        if let (Ok(self_type), Ok(other_type)) = (self.icmp_type(data), other.icmp_type(other_data))
        {
            // Check type pairs
            for &(req_type, reply_type) in ICMP_ANSWERS {
                if self_type == reply_type && other_type == req_type {
                    // For echo and similar, also check id+seq match
                    if let (
                        Ok(Some(self_id)),
                        Ok(Some(other_id)),
                        Ok(Some(self_seq)),
                        Ok(Some(other_seq)),
                    ) = (
                        self.id(data),
                        other.id(other_data),
                        self.seq(data),
                        other.seq(other_data),
                    ) {
                        return self_id == other_id && self_seq == other_seq;
                    }
                    return true;
                }
            }
        }
        false
    }

    fn extract_padding<'a>(&self, data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        // ICMP doesn't have a length field, so we can't determine padding
        // Return the entire ICMP message as data, no padding
        let header_len = self.header_len(data);
        let start = self.index.start;
        let end = data.len();

        if start + header_len <= end {
            (&data[start..end], &[])
        } else {
            (&data[start..end], &[])
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        self.field_names()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_parse() {
        // ICMP echo request: type=8, code=0, checksum=0x1234, id=0x5678, seq=0x0001
        let data = [
            0x08, // type = 8 (echo request)
            0x00, // code = 0
            0x12, 0x34, // checksum
            0x56, 0x78, // id = 0x5678
            0x00, 0x01, // seq = 1
            // Payload
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 8);
        assert_eq!(icmp.code(&data).unwrap(), 0);
        assert_eq!(icmp.checksum(&data).unwrap(), 0x1234);
        assert_eq!(icmp.id(&data).unwrap(), Some(0x5678));
        assert_eq!(icmp.seq(&data).unwrap(), Some(1));
    }

    #[test]
    fn test_icmp_summary() {
        let data = [
            0x08, // type = 8 (echo request)
            0x00, // code = 0
            0x00, 0x00, // checksum
            0x00, 0x01, // id
            0x00, 0x01, // seq
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        let summary = icmp.summary(&data);
        assert!(summary.contains("echo-request"));
    }

    #[test]
    fn test_icmp_set_fields() {
        let mut data = vec![0u8; 8];
        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        icmp.set_type(&mut data, types::types::ECHO_REPLY).unwrap();
        icmp.set_code(&mut data, 0).unwrap();
        icmp.set_checksum(&mut data, 0xABCD).unwrap();
        icmp.set_id(&mut data, 0x1234).unwrap();
        icmp.set_seq(&mut data, 42).unwrap();

        assert_eq!(icmp.icmp_type(&data).unwrap(), types::types::ECHO_REPLY);
        assert_eq!(icmp.code(&data).unwrap(), 0);
        assert_eq!(icmp.checksum(&data).unwrap(), 0xABCD);
        assert_eq!(icmp.id(&data).unwrap(), Some(0x1234));
        assert_eq!(icmp.seq(&data).unwrap(), Some(42));
    }

    #[test]
    fn test_icmp_answers() {
        // Echo request
        let request_data = [
            0x08, 0x00, // type=8, code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // id=0x1234
            0x00, 0x05, // seq=5
        ];

        // Echo reply
        let reply_data = [
            0x00, 0x00, // type=0, code=0
            0x00, 0x00, // checksum
            0x12, 0x34, // id=0x1234 (same)
            0x00, 0x05, // seq=5 (same)
        ];

        let request_index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let reply_index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);

        let request = IcmpLayer::new(request_index);
        let reply = IcmpLayer::new(reply_index);

        assert!(reply.answers(&reply_data, &request, &request_data));
        assert!(!request.answers(&request_data, &reply, &reply_data));
    }

    #[test]
    fn test_icmp_dest_unreach_no_id() {
        // Destination unreachable has no id/seq fields
        let data = [
            0x03, // type = 3 (dest unreachable)
            0x03, // code = 3 (port unreachable)
            0x00, 0x00, // checksum
            0x00, // unused
            0x00, // length
            0x00, 0x00, // unused/next-hop MTU
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 3);
        assert_eq!(icmp.code(&data).unwrap(), 3);
        assert_eq!(icmp.id(&data).unwrap(), None);
        assert_eq!(icmp.seq(&data).unwrap(), None);
    }

    #[test]
    fn test_icmp_redirect_gateway() {
        // Redirect message with gateway
        let data = [
            0x05, // type = 5 (redirect)
            0x01, // code = 1 (redirect host)
            0x00, 0x00, // checksum
            192, 168, 1, 1, // gateway = 192.168.1.1
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 5);
        assert_eq!(
            icmp.gateway(&data).unwrap(),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_icmp_dest_unreach_mtu() {
        // Destination unreachable, fragmentation needed (code 4)
        let mut data = vec![
            0x03, // type = 3 (dest unreachable)
            0x04, // code = 4 (fragmentation needed)
            0x00, 0x00, // checksum
            0x00, // unused
            0x00, // length
            0x05, 0xdc, // next-hop MTU = 1500
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 3);
        assert_eq!(icmp.code(&data).unwrap(), 4);
        assert_eq!(icmp.next_hop_mtu(&data).unwrap(), Some(1500));

        // Test setter
        icmp.set_next_hop_mtu(&mut data, 1400).unwrap();
        assert_eq!(icmp.next_hop_mtu(&data).unwrap(), Some(1400));
    }

    #[test]
    fn test_icmp_param_problem_ptr() {
        // Parameter problem with pointer
        let mut data = vec![
            0x0c, // type = 12 (parameter problem)
            0x00, // code = 0
            0x00, 0x00, // checksum
            0x14, // ptr = 20 (byte offset of problem)
            0x00, // unused
            0x00, 0x00, // length/unused
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 12);
        assert_eq!(icmp.ptr(&data).unwrap(), Some(20));

        // Test setter
        icmp.set_ptr(&mut data, 30).unwrap();
        assert_eq!(icmp.ptr(&data).unwrap(), Some(30));
    }

    #[test]
    fn test_icmp_timestamp_fields() {
        // Timestamp request with all timestamp fields
        let mut data = vec![
            0x0d, // type = 13 (timestamp request)
            0x00, // code = 0
            0x00, 0x00, // checksum
            0x12, 0x34, // id
            0x00, 0x01, // seq
            // Originate timestamp (32 bits)
            0x00, 0x00, 0x10, 0x00, // ts_ori = 4096
            // Receive timestamp (32 bits)
            0x00, 0x00, 0x20, 0x00, // ts_rx = 8192
            // Transmit timestamp (32 bits)
            0x00, 0x00, 0x30, 0x00, // ts_tx = 12288
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, 20); // Timestamp header is 20 bytes
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 13);
        assert_eq!(icmp.code(&data).unwrap(), 0);
        assert_eq!(icmp.id(&data).unwrap(), Some(0x1234));
        assert_eq!(icmp.seq(&data).unwrap(), Some(1));
        assert_eq!(icmp.ts_ori(&data).unwrap(), Some(4096));
        assert_eq!(icmp.ts_rx(&data).unwrap(), Some(8192));
        assert_eq!(icmp.ts_tx(&data).unwrap(), Some(12288));

        // Test setters
        icmp.set_ts_ori(&mut data, 5000).unwrap();
        icmp.set_ts_rx(&mut data, 6000).unwrap();
        icmp.set_ts_tx(&mut data, 7000).unwrap();

        assert_eq!(icmp.ts_ori(&data).unwrap(), Some(5000));
        assert_eq!(icmp.ts_rx(&data).unwrap(), Some(6000));
        assert_eq!(icmp.ts_tx(&data).unwrap(), Some(7000));
    }

    #[test]
    fn test_icmp_timestamp_header_len() {
        // Timestamp messages have 20-byte header
        let data = vec![
            0x0d, // type = 13 (timestamp request)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.header_len(&data), 20);
    }

    #[test]
    fn test_icmp_address_mask() {
        // Address mask request
        let mut data = vec![
            0x11, // type = 17 (address mask request)
            0x00, // code = 0
            0x00, 0x00, // checksum
            255, 255, 255, 0, // addr_mask = 255.255.255.0
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.icmp_type(&data).unwrap(), 17);
        assert_eq!(
            icmp.addr_mask(&data).unwrap(),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );

        // Test setter
        icmp.set_addr_mask(&mut data, Ipv4Addr::new(255, 255, 0, 0))
            .unwrap();
        assert_eq!(
            icmp.addr_mask(&data).unwrap(),
            Some(Ipv4Addr::new(255, 255, 0, 0))
        );
    }

    #[test]
    fn test_icmp_conditional_fields_none() {
        // Echo request should not have gateway, ptr, mtu, or addr_mask
        let data = vec![
            0x08, // type = 8 (echo request)
            0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01,
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        assert_eq!(icmp.gateway(&data).unwrap(), None);
        assert_eq!(icmp.ptr(&data).unwrap(), None);
        assert_eq!(icmp.next_hop_mtu(&data).unwrap(), None);
        assert_eq!(icmp.addr_mask(&data).unwrap(), None);
        assert_eq!(icmp.ts_ori(&data).unwrap(), None);
        assert_eq!(icmp.ts_rx(&data).unwrap(), None);
        assert_eq!(icmp.ts_tx(&data).unwrap(), None);
    }

    #[test]
    fn test_icmp_summary_with_details() {
        // Test that summary includes type-specific details

        // Echo with id and seq
        let echo_data = vec![
            0x08, 0x00, 0x00, 0x00, 0x12, 0x34, // id = 0x1234
            0x00, 0x05, // seq = 5
        ];
        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);
        let summary = icmp.summary(&echo_data);
        assert!(summary.contains("id="));
        assert!(summary.contains("seq="));

        // Redirect with gateway
        let redirect_data = vec![
            0x05, 0x01, 0x00, 0x00, 192, 168, 1, 1, // gateway
        ];
        let icmp = IcmpLayer::new(index);
        let summary = icmp.summary(&redirect_data);
        assert!(summary.contains("gw="));

        // Parameter problem with ptr
        let pp_data = vec![
            0x0c, 0x00, 0x00, 0x00, 0x14, // ptr = 20
            0x00, 0x00, 0x00,
        ];
        let icmp = IcmpLayer::new(index);
        let summary = icmp.summary(&pp_data);
        assert!(summary.contains("ptr="));

        // Dest unreachable with MTU
        let du_data = vec![
            0x03, 0x04, 0x00, 0x00, // type=3, code=4 (frag needed)
            0x00, 0x00, 0x05, 0xdc, // mtu = 1500
        ];
        let icmp = IcmpLayer::new(index);
        let summary = icmp.summary(&du_data);
        assert!(summary.contains("mtu="));
    }

    #[test]
    fn test_icmp_set_gateway() {
        // Test setting gateway for redirect
        let mut data = vec![
            0x05, 0x01, 0x00, 0x00, 0, 0, 0, 0, // gateway (to be set)
        ];

        let index = LayerIndex::new(LayerKind::Icmp, 0, ICMP_MIN_HEADER_LEN);
        let icmp = IcmpLayer::new(index);

        icmp.set_gateway(&mut data, Ipv4Addr::new(10, 0, 0, 1))
            .unwrap();
        assert_eq!(
            icmp.gateway(&data).unwrap(),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_icmp_error_type_detection() {
        // Test that error type detection works
        assert!(error::is_error_type(types::types::DEST_UNREACH));
        assert!(error::is_error_type(types::types::TIME_EXCEEDED));
        assert!(error::is_error_type(types::types::PARAM_PROBLEM));
        assert!(error::is_error_type(types::types::SOURCE_QUENCH));
        assert!(error::is_error_type(types::types::REDIRECT));

        assert!(!error::is_error_type(types::types::ECHO_REQUEST));
        assert!(!error::is_error_type(types::types::ECHO_REPLY));
    }

    #[test]
    fn test_icmp_error_payload_offset() {
        // Error types should have payload at offset 8
        assert_eq!(
            error::error_payload_offset(types::types::DEST_UNREACH),
            Some(8)
        );
        assert_eq!(
            error::error_payload_offset(types::types::TIME_EXCEEDED),
            Some(8)
        );

        // Non-error types should return None
        assert_eq!(
            error::error_payload_offset(types::types::ECHO_REQUEST),
            None
        );
    }
}
