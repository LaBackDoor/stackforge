//! IEEE 802.11 (WiFi / Dot11) protocol layer implementation.
//!
//! Provides full 802.11 frame parsing, building, and field access including:
//! - Frame Control field parsing (type, subtype, flags)
//! - Variable address fields (1-4 MAC addresses depending on frame type)
//! - Sequence control field
//! - FCS variant (Dot11FCS)
//! - RadioTap header support
//! - Management, control, and data frame subtypes
//! - Information elements (IEs)
//! - Security wrappers (WEP, TKIP, CCMP)

pub mod builder;
pub mod control;
pub mod data;
pub mod ie;
pub mod management;
pub mod radiotap;
pub mod security;
pub mod types;

pub use builder::Dot11Builder;
pub use control::{
    Dot11Ack, Dot11BlockAck, Dot11BlockAckReq, Dot11CFEnd, Dot11CTS, Dot11PSPoll, Dot11RTS,
};
pub use data::Dot11QoS;
pub use ie::{Dot11Elt, Dot11EltRSN, Dot11EltRates};
pub use management::{
    Dot11Action, Dot11AssocReq, Dot11AssocResp, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11Disas,
    Dot11ProbeReq, Dot11ProbeResp, Dot11ReassocReq, Dot11ReassocResp,
};
pub use radiotap::{RadioTapBuilder, RadioTapLayer};
pub use security::{Dot11CCMP, Dot11TKIP, Dot11WEP};

use crate::layer::field::{Field, FieldError, FieldValue, MacAddress};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum 802.11 header length: FC(2) + Duration(2) + Addr1(6) = 10 bytes.
/// Most frames have at least 24 bytes (3 addresses + seq ctrl).
pub const DOT11_MIN_HEADER_LEN: usize = 10;

/// Standard management/data header length: FC(2) + Dur(2) + Addr1(6) + Addr2(6) + Addr3(6) + SC(2) = 24.
pub const DOT11_MGMT_HEADER_LEN: usize = 24;

/// WDS (4 address) header length: 24 + Addr4(6) = 30.
pub const DOT11_WDS_HEADER_LEN: usize = 30;

/// FCS field length.
pub const DOT11_FCS_LEN: usize = 4;

/// Field offsets within the 802.11 header.
/// NOTE: Frame Control is little-endian.
pub mod offsets {
    /// Frame Control (2 bytes, little-endian).
    pub const FRAME_CONTROL: usize = 0;
    /// Duration/ID (2 bytes, little-endian).
    pub const DURATION: usize = 2;
    /// Address 1 (6 bytes) - always present.
    pub const ADDR1: usize = 4;
    /// Address 2 (6 bytes) - present in most frames.
    pub const ADDR2: usize = 10;
    /// Address 3 (6 bytes) - present in management and data frames.
    pub const ADDR3: usize = 16;
    /// Sequence Control (2 bytes, little-endian).
    pub const SEQ_CTRL: usize = 22;
    /// Address 4 (6 bytes) - only in WDS (to_DS=1 AND from_DS=1).
    pub const ADDR4: usize = 24;
}

/// IEEE 802.11 layer - a zero-copy view into the packet buffer.
///
/// Provides lazy field access for all 802.11 header fields.
/// The Frame Control field is always little-endian.
///
/// Frame Control layout (2 bytes, little-endian):
/// ```text
/// Byte 0: [subtype(4) | type(2) | protocol_version(2)]
/// Byte 1: [order | protected | more_data | pwr_mgt | retry | more_frag | from_ds | to_ds]
/// ```
#[derive(Debug, Clone)]
pub struct Dot11Layer {
    pub index: LayerIndex,
}

impl Dot11Layer {
    /// Create a new Dot11Layer from start/end offsets.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dot11, start, end),
        }
    }

    /// Validate that the buffer contains enough data for this layer.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + DOT11_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: DOT11_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    // ========================================================================
    // Frame Control field accessors
    // ========================================================================

    /// Read the raw Frame Control field (2 bytes, little-endian).
    #[inline]
    pub fn frame_control_raw(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.index.start + offsets::FRAME_CONTROL;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Protocol version (2 bits from FC byte 0, bits 0-1).
    #[inline]
    pub fn protocol_version(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let fc = self.frame_control_raw(buf)?;
        Ok((fc & 0x0003) as u8)
    }

    /// Frame type (2 bits from FC byte 0, bits 2-3).
    #[inline]
    pub fn frame_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let fc = self.frame_control_raw(buf)?;
        Ok(((fc >> 2) & 0x0003) as u8)
    }

    /// Frame subtype (4 bits from FC byte 0, bits 4-7).
    #[inline]
    pub fn subtype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let fc = self.frame_control_raw(buf)?;
        Ok(((fc >> 4) & 0x000F) as u8)
    }

    /// Flags byte (FC byte 1, bits 8-15 of the FC word).
    #[inline]
    pub fn flags(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let fc = self.frame_control_raw(buf)?;
        Ok((fc >> 8) as u8)
    }

    /// To DS flag (bit 0 of flags byte).
    #[inline]
    pub fn to_ds(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::TO_DS != 0)
    }

    /// From DS flag (bit 1 of flags byte).
    #[inline]
    pub fn from_ds(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::FROM_DS != 0)
    }

    /// More Fragments flag (bit 2 of flags byte).
    #[inline]
    pub fn more_frag(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::MORE_FRAG != 0)
    }

    /// Retry flag (bit 3 of flags byte).
    #[inline]
    pub fn retry(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::RETRY != 0)
    }

    /// Power Management flag (bit 4 of flags byte).
    #[inline]
    pub fn pwr_mgt(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::PWR_MGT != 0)
    }

    /// More Data flag (bit 5 of flags byte).
    #[inline]
    pub fn more_data(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::MORE_DATA != 0)
    }

    /// Protected Frame flag (bit 6 of flags byte).
    #[inline]
    pub fn protected(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::PROTECTED != 0)
    }

    /// HTC/Order flag (bit 7 of flags byte).
    #[inline]
    pub fn htc_order(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.flags(buf)? & types::fc_flags::HTC_ORDER != 0)
    }

    // ========================================================================
    // Duration/ID field
    // ========================================================================

    /// Duration/ID field (2 bytes, little-endian).
    #[inline]
    pub fn duration(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.index.start + offsets::DURATION;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    // ========================================================================
    // Address fields
    // ========================================================================

    /// Address 1 (always present, 6 bytes at offset 4).
    #[inline]
    pub fn addr1(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::ADDR1)
    }

    /// Address 2 (present in most frames except some control frames).
    #[inline]
    pub fn addr2(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::ADDR2)
    }

    /// Address 3 (present in management and data frames).
    #[inline]
    pub fn addr3(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::ADDR3)
    }

    /// Address 4 (only present in WDS frames: to_DS=1 AND from_DS=1).
    #[inline]
    pub fn addr4(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        MacAddress::read(buf, self.index.start + offsets::ADDR4)
    }

    /// Check if this frame has a 4th address field (WDS mode).
    #[inline]
    pub fn has_addr4(&self, buf: &[u8]) -> bool {
        if let Ok(ft) = self.frame_type(buf) {
            if ft == types::frame_type::DATA {
                if let Ok(flags) = self.flags(buf) {
                    return (flags & 0x03) == 0x03; // to_DS=1 AND from_DS=1
                }
            }
        }
        false
    }

    /// Check if this is a control frame (which may have fewer addresses).
    #[inline]
    pub fn is_control(&self, buf: &[u8]) -> bool {
        matches!(self.frame_type(buf), Ok(types::frame_type::CONTROL))
    }

    // ========================================================================
    // Sequence Control field
    // ========================================================================

    /// Raw Sequence Control field (2 bytes, little-endian).
    #[inline]
    pub fn seq_ctrl_raw(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let off = self.index.start + offsets::SEQ_CTRL;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
    }

    /// Fragment number (lower 4 bits of Sequence Control).
    #[inline]
    pub fn fragment_num(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok((self.seq_ctrl_raw(buf)? & 0x000F) as u8)
    }

    /// Sequence number (upper 12 bits of Sequence Control).
    #[inline]
    pub fn sequence_num(&self, buf: &[u8]) -> Result<u16, FieldError> {
        Ok(self.seq_ctrl_raw(buf)? >> 4)
    }

    // ========================================================================
    // Header length calculation
    // ========================================================================

    /// Calculate the actual header length based on frame type and flags.
    pub fn compute_header_len(&self, buf: &[u8]) -> usize {
        let ft = self.frame_type(buf).unwrap_or(0);
        let st = self.subtype(buf).unwrap_or(0);

        match ft {
            types::frame_type::MANAGEMENT => DOT11_MGMT_HEADER_LEN,
            types::frame_type::CONTROL => {
                match st {
                    types::ctrl_subtype::ACK | types::ctrl_subtype::CTS => {
                        // FC(2) + Duration(2) + Addr1(6) = 10
                        10
                    }
                    _ => {
                        // FC(2) + Duration(2) + Addr1(6) + Addr2(6) = 16
                        16
                    }
                }
            }
            types::frame_type::DATA => {
                if self.has_addr4(buf) {
                    DOT11_WDS_HEADER_LEN
                } else {
                    DOT11_MGMT_HEADER_LEN
                }
            }
            types::frame_type::EXTENSION => 10,
            _ => DOT11_MIN_HEADER_LEN,
        }
    }

    // ========================================================================
    // Field writers
    // ========================================================================

    /// Write the Frame Control field (little-endian).
    pub fn set_frame_control(&self, buf: &mut [u8], fc: u16) -> Result<(), FieldError> {
        let off = self.index.start + offsets::FRAME_CONTROL;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        let bytes = fc.to_le_bytes();
        buf[off] = bytes[0];
        buf[off + 1] = bytes[1];
        Ok(())
    }

    /// Write the Duration/ID field (little-endian).
    pub fn set_duration(&self, buf: &mut [u8], dur: u16) -> Result<(), FieldError> {
        let off = self.index.start + offsets::DURATION;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        let bytes = dur.to_le_bytes();
        buf[off] = bytes[0];
        buf[off + 1] = bytes[1];
        Ok(())
    }

    /// Write Address 1.
    pub fn set_addr1(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::ADDR1)
    }

    /// Write Address 2.
    pub fn set_addr2(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::ADDR2)
    }

    /// Write Address 3.
    pub fn set_addr3(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::ADDR3)
    }

    /// Write Address 4.
    pub fn set_addr4(&self, buf: &mut [u8], mac: MacAddress) -> Result<(), FieldError> {
        mac.write(buf, self.index.start + offsets::ADDR4)
    }

    /// Write the Sequence Control field (little-endian).
    pub fn set_seq_ctrl(&self, buf: &mut [u8], sc: u16) -> Result<(), FieldError> {
        let off = self.index.start + offsets::SEQ_CTRL;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len(),
            });
        }
        let bytes = sc.to_le_bytes();
        buf[off] = bytes[0];
        buf[off + 1] = bytes[1];
        Ok(())
    }

    // ========================================================================
    // Dynamic field access
    // ========================================================================

    /// Field names for dynamic access.
    pub fn field_names() -> &'static [&'static str] {
        &[
            "type", "subtype", "proto", "FCfield", "ID", "addr1", "addr2", "addr3", "SC", "addr4",
        ]
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "type" => Some(self.frame_type(buf).map(FieldValue::U8)),
            "subtype" => Some(self.subtype(buf).map(FieldValue::U8)),
            "proto" => Some(self.protocol_version(buf).map(FieldValue::U8)),
            "FCfield" => Some(self.flags(buf).map(FieldValue::U8)),
            "ID" => Some(self.duration(buf).map(FieldValue::U16)),
            "addr1" => Some(self.addr1(buf).map(FieldValue::Mac)),
            "addr2" => Some(self.addr2(buf).map(FieldValue::Mac)),
            "addr3" => Some(self.addr3(buf).map(FieldValue::Mac)),
            "SC" => Some(self.seq_ctrl_raw(buf).map(FieldValue::U16)),
            "addr4" => {
                if self.has_addr4(buf) {
                    Some(self.addr4(buf).map(FieldValue::Mac))
                } else {
                    None
                }
            }
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
            "ID" => match value {
                FieldValue::U16(v) => Some(self.set_duration(buf, v)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "u16",
                    got: "other",
                })),
            },
            "addr1" => match value {
                FieldValue::Mac(m) => Some(self.set_addr1(buf, m)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "mac",
                    got: "other",
                })),
            },
            "addr2" => match value {
                FieldValue::Mac(m) => Some(self.set_addr2(buf, m)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "mac",
                    got: "other",
                })),
            },
            "addr3" => match value {
                FieldValue::Mac(m) => Some(self.set_addr3(buf, m)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "mac",
                    got: "other",
                })),
            },
            "addr4" => match value {
                FieldValue::Mac(m) => Some(self.set_addr4(buf, m)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "mac",
                    got: "other",
                })),
            },
            "SC" => match value {
                FieldValue::U16(v) => Some(self.set_seq_ctrl(buf, v)),
                _ => Some(Err(FieldError::TypeMismatch {
                    expected: "u16",
                    got: "other",
                })),
            },
            _ => None,
        }
    }

    /// Compute hash for packet matching.
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        let mut hash = Vec::new();
        if let Ok(addr1) = self.addr1(buf) {
            hash.extend_from_slice(addr1.as_bytes());
        }
        if let Ok(addr2) = self.addr2(buf) {
            hash.extend_from_slice(addr2.as_bytes());
        }
        hash
    }

    /// Check if this packet answers another 802.11 packet.
    pub fn answers(&self, buf: &[u8], other: &Dot11Layer, other_buf: &[u8]) -> bool {
        let self_type = self.frame_type(buf).unwrap_or(255);
        let other_type = other.frame_type(other_buf).unwrap_or(255);

        if self_type != other_type {
            return false;
        }

        match self_type {
            types::frame_type::MANAGEMENT => {
                let self_addr1 = self.addr1(buf).unwrap_or(MacAddress::ZERO);
                let other_addr2 = other.addr2(other_buf).unwrap_or(MacAddress::ZERO);
                if self_addr1 != other_addr2 {
                    return false;
                }
                let self_sub = self.subtype(buf).unwrap_or(255);
                let other_sub = other.subtype(other_buf).unwrap_or(255);
                matches!((other_sub, self_sub), (0, 1) | (2, 3) | (4, 5) | (11, 11))
            }
            types::frame_type::CONTROL => false,
            types::frame_type::DATA => true,
            _ => false,
        }
    }
}

impl Layer for Dot11Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dot11
    }

    fn summary(&self, buf: &[u8]) -> String {
        let ft = self.frame_type(buf).unwrap_or(0);
        let st = self.subtype(buf).unwrap_or(0);
        let type_name = types::frame_type::name(ft);
        let subtype_name = types::subtype_name(ft, st);
        let addr2_str = self
            .addr2(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let addr1_str = self
            .addr1(buf)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());
        format!(
            "802.11 {} {} {} > {}",
            type_name, subtype_name, addr2_str, addr1_str
        )
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.compute_header_len(buf)
    }

    fn hashret(&self, data: &[u8]) -> Vec<u8> {
        self.hashret(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        Dot11Layer::field_names()
    }
}

/// IEEE 802.11 FCS layer - same as Dot11Layer but includes a 4-byte FCS trailer.
#[derive(Debug, Clone)]
pub struct Dot11FcsLayer {
    pub index: LayerIndex,
}

impl Dot11FcsLayer {
    /// Create a new Dot11FcsLayer from start/end offsets.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dot11, start, end),
        }
    }

    /// Get the inner Dot11Layer view (excluding FCS).
    pub fn dot11(&self) -> Dot11Layer {
        Dot11Layer::new(
            self.index.start,
            self.index.end.saturating_sub(DOT11_FCS_LEN),
        )
    }

    /// Read the FCS field (4 bytes at end of frame, little-endian).
    pub fn fcs(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let off = self.index.end.saturating_sub(DOT11_FCS_LEN);
        if buf.len() < off + 4 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 4,
                have: buf.len(),
            });
        }
        Ok(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    }

    /// Compute the CRC32 FCS for the frame data (excluding the FCS itself).
    pub fn compute_fcs(data: &[u8]) -> u32 {
        crc32_ieee(data)
    }

    /// Verify that the FCS matches the frame data.
    pub fn verify_fcs(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let fcs_val = self.fcs(buf)?;
        let data_end = self.index.end.saturating_sub(DOT11_FCS_LEN);
        let data = &buf[self.index.start..data_end];
        let computed = Self::compute_fcs(data);
        Ok(fcs_val == computed)
    }

    /// Delegate field access to the inner Dot11Layer.
    pub fn frame_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.dot11().frame_type(buf)
    }

    pub fn subtype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.dot11().subtype(buf)
    }

    pub fn flags(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.dot11().flags(buf)
    }

    pub fn addr1(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        self.dot11().addr1(buf)
    }

    pub fn addr2(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        self.dot11().addr2(buf)
    }

    pub fn addr3(&self, buf: &[u8]) -> Result<MacAddress, FieldError> {
        self.dot11().addr3(buf)
    }

    pub fn duration(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.dot11().duration(buf)
    }
}

impl Layer for Dot11FcsLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dot11
    }

    fn summary(&self, buf: &[u8]) -> String {
        let inner = self.dot11();
        let base = inner.summary(buf);
        let fcs_str = self
            .fcs(buf)
            .map(|f| format!(" [FCS={:#010x}]", f))
            .unwrap_or_default();
        format!("{}{}", base, fcs_str)
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.dot11().compute_header_len(buf)
    }

    fn field_names(&self) -> &'static [&'static str] {
        Dot11Layer::field_names()
    }
}

/// Build a Frame Control u16 value from components.
///
/// Frame Control layout (little-endian u16):
/// Bits 0-1:  Protocol Version
/// Bits 2-3:  Type
/// Bits 4-7:  Subtype
/// Bits 8-15: Flags
pub fn build_frame_control(proto: u8, frame_type: u8, subtype: u8, flags: u8) -> u16 {
    let byte0 = (proto & 0x03) | ((frame_type & 0x03) << 2) | ((subtype & 0x0F) << 4);
    u16::from_le_bytes([byte0, flags])
}

/// Compute IEEE CRC32 (used for FCS).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal beacon frame for testing.
    fn make_beacon_frame() -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        // Frame Control: type=0 (mgmt), subtype=8 (beacon)
        // byte0: proto=0, type=0, subtype=8 => 0x80
        // byte1: flags=0
        buf[0] = 0x80;
        buf[1] = 0x00;
        // Duration
        buf[2] = 0x00;
        buf[3] = 0x00;
        // Addr1 (DA) = ff:ff:ff:ff:ff:ff (broadcast)
        buf[4..10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Addr2 (SA) = 00:11:22:33:44:55
        buf[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Addr3 (BSSID) = 00:11:22:33:44:55
        buf[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Sequence Control
        buf[22] = 0x10;
        buf[23] = 0x00;
        buf
    }

    /// Build an ACK frame (control, subtype=13).
    fn make_ack_frame() -> Vec<u8> {
        let mut buf = vec![0u8; 10];
        // FC: type=1 (control), subtype=13 (ACK)
        // byte0: proto=0, type=1, subtype=13 => (13 << 4) | (1 << 2) = 0xD4
        buf[0] = 0xD4;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        buf[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        buf
    }

    /// Build a data frame with to_DS=1, from_DS=1 (WDS).
    fn make_wds_data_frame() -> Vec<u8> {
        let mut buf = vec![0u8; 30];
        // FC: type=2 (data), subtype=0
        // byte0: (0 << 4) | (2 << 2) = 0x08
        buf[0] = 0x08;
        // byte1: flags to_DS=1, from_DS=1 => 0x03
        buf[1] = 0x03;
        buf[2] = 0x00;
        buf[3] = 0x00;
        buf[4..10].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        buf[10..16].copy_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        buf[16..22].copy_from_slice(&[0x21, 0x22, 0x23, 0x24, 0x25, 0x26]);
        buf[22] = 0x00;
        buf[23] = 0x00;
        buf[24..30].copy_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        buf
    }

    #[test]
    fn test_parse_beacon_frame_control() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());

        assert_eq!(layer.protocol_version(&buf).unwrap(), 0);
        assert_eq!(layer.frame_type(&buf).unwrap(), 0);
        assert_eq!(layer.subtype(&buf).unwrap(), 8);
        assert_eq!(layer.flags(&buf).unwrap(), 0);
    }

    #[test]
    fn test_parse_beacon_addresses() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());

        assert!(layer.addr1(&buf).unwrap().is_broadcast());
        assert_eq!(
            layer.addr2(&buf).unwrap(),
            MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            layer.addr3(&buf).unwrap(),
            MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn test_parse_beacon_seq_ctrl() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());

        assert_eq!(layer.seq_ctrl_raw(&buf).unwrap(), 0x0010);
        assert_eq!(layer.fragment_num(&buf).unwrap(), 0);
        assert_eq!(layer.sequence_num(&buf).unwrap(), 1);
    }

    #[test]
    fn test_beacon_header_len() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());
        assert_eq!(layer.compute_header_len(&buf), 24);
    }

    #[test]
    fn test_parse_ack_frame() {
        let buf = make_ack_frame();
        let layer = Dot11Layer::new(0, buf.len());

        assert_eq!(layer.frame_type(&buf).unwrap(), 1);
        assert_eq!(layer.subtype(&buf).unwrap(), 13);
        assert_eq!(layer.compute_header_len(&buf), 10);
        assert_eq!(
            layer.addr1(&buf).unwrap(),
            MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
    }

    #[test]
    fn test_parse_wds_frame() {
        let buf = make_wds_data_frame();
        let layer = Dot11Layer::new(0, buf.len());

        assert_eq!(layer.frame_type(&buf).unwrap(), 2);
        assert!(layer.to_ds(&buf).unwrap());
        assert!(layer.from_ds(&buf).unwrap());
        assert!(layer.has_addr4(&buf));
        assert_eq!(layer.compute_header_len(&buf), 30);
        assert_eq!(
            layer.addr4(&buf).unwrap(),
            MacAddress::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
        );
    }

    #[test]
    fn test_build_frame_control() {
        let fc = build_frame_control(0, 0, 8, 0);
        assert_eq!(fc.to_le_bytes(), [0x80, 0x00]);

        let fc = build_frame_control(0, 1, 13, 0);
        assert_eq!(fc.to_le_bytes(), [0xD4, 0x00]);

        let fc = build_frame_control(0, 2, 0, 0x01);
        assert_eq!(fc.to_le_bytes(), [0x08, 0x01]);
    }

    #[test]
    fn test_flags_parsing() {
        let mut buf = make_beacon_frame();
        buf[1] = types::fc_flags::RETRY | types::fc_flags::PROTECTED;
        let layer = Dot11Layer::new(0, buf.len());

        assert!(layer.retry(&buf).unwrap());
        assert!(layer.protected(&buf).unwrap());
        assert!(!layer.to_ds(&buf).unwrap());
        assert!(!layer.from_ds(&buf).unwrap());
    }

    #[test]
    fn test_summary() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());
        let summary = layer.summary(&buf);
        assert!(summary.contains("Management"));
        assert!(summary.contains("Beacon"));
    }

    #[test]
    fn test_field_access() {
        let buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());

        let ft = layer.get_field(&buf, "type").unwrap().unwrap();
        assert_eq!(ft, FieldValue::U8(0));

        let st = layer.get_field(&buf, "subtype").unwrap().unwrap();
        assert_eq!(st, FieldValue::U8(8));

        let a1 = layer.get_field(&buf, "addr1").unwrap().unwrap();
        assert_eq!(a1, FieldValue::Mac(MacAddress::BROADCAST));
    }

    #[test]
    fn test_set_duration() {
        let mut buf = make_beacon_frame();
        let layer = Dot11Layer::new(0, buf.len());

        layer.set_duration(&mut buf, 0x1234).unwrap();
        assert_eq!(layer.duration(&buf).unwrap(), 0x1234);
    }

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        assert_eq!(crc32_ieee(data), 0xCBF43926);
    }

    #[test]
    fn test_fcs_layer() {
        let mut buf = make_beacon_frame();
        let fcs = crc32_ieee(&buf);
        buf.extend_from_slice(&fcs.to_le_bytes());

        let fcs_layer = Dot11FcsLayer::new(0, buf.len());
        assert_eq!(fcs_layer.fcs(&buf).unwrap(), fcs);
        assert!(fcs_layer.verify_fcs(&buf).unwrap());

        assert_eq!(fcs_layer.frame_type(&buf).unwrap(), 0);
        assert_eq!(fcs_layer.subtype(&buf).unwrap(), 8);
    }

    #[test]
    fn test_roundtrip_build_parse() {
        let fc = build_frame_control(0, 0, 8, 0);
        let mut buf = vec![0u8; 24];
        buf[0..2].copy_from_slice(&fc.to_le_bytes());
        buf[2..4].copy_from_slice(&0u16.to_le_bytes());
        buf[4..10].copy_from_slice(&[0xff; 6]);
        buf[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        buf[22..24].copy_from_slice(&0x0020u16.to_le_bytes());

        let layer = Dot11Layer::new(0, buf.len());
        assert_eq!(layer.frame_type(&buf).unwrap(), 0);
        assert_eq!(layer.subtype(&buf).unwrap(), 8);
        assert_eq!(layer.sequence_num(&buf).unwrap(), 2);
        assert_eq!(layer.fragment_num(&buf).unwrap(), 0);
    }

    #[test]
    fn test_answers_management() {
        let mut req = vec![0u8; 24];
        req[0] = 0x00; // type=0, subtype=0
        req[4..10].copy_from_slice(&[0xBB; 6]);
        req[10..16].copy_from_slice(&[0xAA; 6]);

        let mut resp = vec![0u8; 24];
        resp[0] = 0x10; // type=0, subtype=1
        resp[4..10].copy_from_slice(&[0xAA; 6]);
        resp[10..16].copy_from_slice(&[0xBB; 6]);

        let req_layer = Dot11Layer::new(0, req.len());
        let resp_layer = Dot11Layer::new(0, resp.len());

        assert!(resp_layer.answers(&resp, &req_layer, &req));
        assert!(!req_layer.answers(&req, &resp_layer, &resp));
    }
}
