//! IEEE 802.15.4 (Zigbee / Dot15d4) protocol layer implementation.
//!
//! Provides full 802.15.4 MAC frame parsing, building, and field access with:
//! - Frame Control Field (FCF) with all flag/mode fields
//! - Variable-length addressing (short and long addresses)
//! - PAN ID compression support
//! - Auxiliary Security Header (optional)
//! - Beacon frames with superframe spec, GTS, and pending addresses
//! - MAC command frames with all command payloads
//! - FCS (CRC-16 CCITT Kermit) computation and verification
//!
//! All fields are little-endian as per the IEEE 802.15.4 standard.

pub mod beacon;
pub mod builder;
pub mod command;
pub mod crc;
pub mod security;
pub mod types;

pub use builder::{Dot15d4Builder, Dot15d4FcsBuilder};

use crate::layer::field::{
    FieldError, FieldValue, read_u16_le, read_u64_le, write_u16_le, write_u64_le,
};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum header length: 2 bytes FCF + 1 byte sequence number.
pub const DOT15D4_MIN_HEADER_LEN: usize = 3;

/// FCS length in bytes (CRC-16).
pub const FCS_LEN: usize = 2;

/// Field names for dynamic access.
pub const DOT15D4_FIELDS: &[&str] = &[
    "fcf_frametype",
    "fcf_security",
    "fcf_pending",
    "fcf_ackreq",
    "fcf_panidcompress",
    "fcf_destaddrmode",
    "fcf_framever",
    "fcf_srcaddrmode",
    "seqnum",
    "dest_panid",
    "dest_addr_short",
    "dest_addr_long",
    "src_panid",
    "src_addr_short",
    "src_addr_long",
];

/// FCS layer field names (includes all base fields plus fcs).
pub const DOT15D4_FCS_FIELDS: &[&str] = &[
    "fcf_frametype",
    "fcf_security",
    "fcf_pending",
    "fcf_ackreq",
    "fcf_panidcompress",
    "fcf_destaddrmode",
    "fcf_framever",
    "fcf_srcaddrmode",
    "seqnum",
    "dest_panid",
    "dest_addr_short",
    "dest_addr_long",
    "src_panid",
    "src_addr_short",
    "src_addr_long",
    "fcs",
];

// ============================================================================
// Frame Control Field helpers
// ============================================================================

/// Read the 16-bit Frame Control Field (little-endian) from the buffer.
#[inline]
fn read_fcf(buf: &[u8], offset: usize) -> Result<u16, FieldError> {
    read_u16_le(buf, offset)
}

/// Write the 16-bit Frame Control Field (little-endian) into the buffer.
#[inline]
fn write_fcf(buf: &mut [u8], offset: usize, fcf: u16) -> Result<(), FieldError> {
    write_u16_le(fcf, buf, offset)
}

/// Extract frame type from FCF (bits 0-2).
#[inline]
pub fn fcf_frame_type(fcf: u16) -> u8 {
    (fcf & 0x0007) as u8
}

/// Extract security enabled flag from FCF (bit 3).
#[inline]
pub fn fcf_security(fcf: u16) -> bool {
    (fcf & 0x0008) != 0
}

/// Extract frame pending flag from FCF (bit 4).
#[inline]
pub fn fcf_pending(fcf: u16) -> bool {
    (fcf & 0x0010) != 0
}

/// Extract ACK request flag from FCF (bit 5).
#[inline]
pub fn fcf_ackreq(fcf: u16) -> bool {
    (fcf & 0x0020) != 0
}

/// Extract PAN ID compression flag from FCF (bit 6).
#[inline]
pub fn fcf_panid_compress(fcf: u16) -> bool {
    (fcf & 0x0040) != 0
}

/// Extract destination address mode from FCF (bits 10-11).
#[inline]
pub fn fcf_dest_addr_mode(fcf: u16) -> u8 {
    ((fcf >> 10) & 0x03) as u8
}

/// Extract frame version from FCF (bits 12-13).
#[inline]
pub fn fcf_frame_ver(fcf: u16) -> u8 {
    ((fcf >> 12) & 0x03) as u8
}

/// Extract source address mode from FCF (bits 14-15).
#[inline]
pub fn fcf_src_addr_mode(fcf: u16) -> u8 {
    ((fcf >> 14) & 0x03) as u8
}

/// Build a Frame Control Field value from individual fields.
pub fn build_fcf(
    frame_type: u8,
    security: bool,
    pending: bool,
    ackreq: bool,
    panid_compress: bool,
    dest_addr_mode: u8,
    frame_ver: u8,
    src_addr_mode: u8,
) -> u16 {
    let mut fcf: u16 = 0;
    fcf |= (frame_type as u16) & 0x07;
    if security {
        fcf |= 0x0008;
    }
    if pending {
        fcf |= 0x0010;
    }
    if ackreq {
        fcf |= 0x0020;
    }
    if panid_compress {
        fcf |= 0x0040;
    }
    // bits 7-9 reserved (0)
    fcf |= ((dest_addr_mode as u16) & 0x03) << 10;
    fcf |= ((frame_ver as u16) & 0x03) << 12;
    fcf |= ((src_addr_mode as u16) & 0x03) << 14;
    fcf
}

/// Compute the variable header length based on FCF fields.
///
/// The header consists of:
/// - 2 bytes FCF
/// - 1 byte sequence number
/// - Dest PAN ID (2 bytes if dest_addr_mode != 0)
/// - Dest Address (2 or 8 bytes based on dest_addr_mode)
/// - Src PAN ID (2 bytes if src_addr_mode != 0 AND NOT panid_compress)
/// - Src Address (2 or 8 bytes based on src_addr_mode)
pub fn compute_header_len(fcf: u16) -> usize {
    let mut len = DOT15D4_MIN_HEADER_LEN; // FCF (2) + seqnum (1)
    let dest_mode = fcf_dest_addr_mode(fcf);
    let src_mode = fcf_src_addr_mode(fcf);
    let panid_compress = fcf_panid_compress(fcf);

    // Destination PAN ID + Address
    if dest_mode != types::addr_mode::NONE {
        len += 2; // PAN ID
        len += types::addr_mode_len(dest_mode);
    }

    // Source PAN ID + Address
    if src_mode != types::addr_mode::NONE {
        if !panid_compress {
            len += 2; // PAN ID (not compressed)
        }
        len += types::addr_mode_len(src_mode);
    }

    len
}

/// Compute the offset where addressing fields begin (after FCF + seqnum).
#[inline]
fn addr_start(start: usize) -> usize {
    start + DOT15D4_MIN_HEADER_LEN
}

// ============================================================================
// Dot15d4Layer -- zero-copy view into an 802.15.4 MAC frame
// ============================================================================

/// IEEE 802.15.4 MAC frame layer (without FCS).
///
/// This is a zero-copy view into the packet buffer. The header length
/// is variable depending on the address modes specified in the FCF.
#[derive(Debug, Clone)]
pub struct Dot15d4Layer {
    pub index: LayerIndex,
}

impl Dot15d4Layer {
    /// Create a new Dot15d4Layer from start/end offsets.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dot15d4, start, end),
        }
    }

    /// Validate that the buffer has enough bytes for at least the minimum header.
    pub fn validate(buf: &[u8], offset: usize) -> Result<(), FieldError> {
        if buf.len() < offset + DOT15D4_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset,
                need: DOT15D4_MIN_HEADER_LEN,
                have: buf.len().saturating_sub(offset),
            });
        }
        Ok(())
    }

    // ========================================================================
    // Frame Control Field accessors
    // ========================================================================

    /// Read the raw 16-bit Frame Control Field.
    #[inline]
    pub fn fcf_raw(&self, buf: &[u8]) -> Result<u16, FieldError> {
        read_fcf(buf, self.index.start)
    }

    /// Frame type (3 bits): 0=Beacon, 1=Data, 2=Ack, 3=Command.
    pub fn fcf_frametype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.fcf_raw(buf).map(fcf_frame_type)
    }

    /// Security Enabled flag.
    pub fn fcf_security(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.fcf_raw(buf).map(fcf_security)
    }

    /// Frame Pending flag.
    pub fn fcf_pending(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.fcf_raw(buf).map(fcf_pending)
    }

    /// ACK Request flag.
    pub fn fcf_ackreq(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.fcf_raw(buf).map(fcf_ackreq)
    }

    /// PAN ID Compression flag (intra-PAN).
    pub fn fcf_panidcompress(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.fcf_raw(buf).map(fcf_panid_compress)
    }

    /// Destination Address Mode (2 bits): 0=None, 2=Short, 3=Long.
    pub fn fcf_destaddrmode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.fcf_raw(buf).map(fcf_dest_addr_mode)
    }

    /// Frame Version (2 bits).
    pub fn fcf_framever(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.fcf_raw(buf).map(fcf_frame_ver)
    }

    /// Source Address Mode (2 bits): 0=None, 2=Short, 3=Long.
    pub fn fcf_srcaddrmode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.fcf_raw(buf).map(fcf_src_addr_mode)
    }

    // ========================================================================
    // Sequence Number
    // ========================================================================

    /// Sequence number (1 byte).
    pub fn seqnum(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.index.start + 2;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        Ok(buf[off])
    }

    /// Set sequence number.
    pub fn set_seqnum(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let off = self.index.start + 2;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = val;
        Ok(())
    }

    // ========================================================================
    // Addressing field offsets (computed from FCF)
    // ========================================================================

    /// Compute the offset of the destination PAN ID field.
    /// Returns None if dest_addr_mode == 0.
    fn dest_panid_offset(&self, buf: &[u8]) -> Result<Option<usize>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        let dest_mode = fcf_dest_addr_mode(fcf);
        if dest_mode == types::addr_mode::NONE {
            return Ok(None);
        }
        Ok(Some(addr_start(self.index.start)))
    }

    /// Compute the offset of the destination address field.
    /// Returns None if dest_addr_mode == 0.
    fn dest_addr_offset(&self, buf: &[u8]) -> Result<Option<usize>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        let dest_mode = fcf_dest_addr_mode(fcf);
        if dest_mode == types::addr_mode::NONE {
            return Ok(None);
        }
        // After dest PAN ID (2 bytes)
        Ok(Some(addr_start(self.index.start) + 2))
    }

    /// Compute the offset of the source PAN ID field.
    /// Returns None if src_addr_mode == 0 or PAN ID compressed.
    fn src_panid_offset(&self, buf: &[u8]) -> Result<Option<usize>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        let dest_mode = fcf_dest_addr_mode(fcf);
        let src_mode = fcf_src_addr_mode(fcf);
        let panid_compress = fcf_panid_compress(fcf);

        if src_mode == types::addr_mode::NONE || panid_compress {
            return Ok(None);
        }

        let mut off = addr_start(self.index.start);
        if dest_mode != types::addr_mode::NONE {
            off += 2 + types::addr_mode_len(dest_mode); // PAN ID + address
        }
        Ok(Some(off))
    }

    /// Compute the offset of the source address field.
    /// Returns None if src_addr_mode == 0.
    fn src_addr_offset(&self, buf: &[u8]) -> Result<Option<usize>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        let dest_mode = fcf_dest_addr_mode(fcf);
        let src_mode = fcf_src_addr_mode(fcf);
        let panid_compress = fcf_panid_compress(fcf);

        if src_mode == types::addr_mode::NONE {
            return Ok(None);
        }

        let mut off = addr_start(self.index.start);
        // Skip dest PAN ID + dest addr
        if dest_mode != types::addr_mode::NONE {
            off += 2 + types::addr_mode_len(dest_mode);
        }
        // Skip src PAN ID if present
        if !panid_compress {
            off += 2;
        }
        Ok(Some(off))
    }

    // ========================================================================
    // Addressing field readers
    // ========================================================================

    /// Destination PAN ID (2 bytes, LE).
    /// Returns None if dest_addr_mode == 0.
    pub fn dest_panid(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        match self.dest_panid_offset(buf)? {
            Some(off) => read_u16_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    /// Destination short address (2 bytes, LE).
    /// Returns None if dest_addr_mode != SHORT.
    pub fn dest_addr_short(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_dest_addr_mode(fcf) != types::addr_mode::SHORT {
            return Ok(None);
        }
        match self.dest_addr_offset(buf)? {
            Some(off) => read_u16_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    /// Destination long address (8 bytes, LE).
    /// Returns None if dest_addr_mode != LONG.
    pub fn dest_addr_long(&self, buf: &[u8]) -> Result<Option<u64>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_dest_addr_mode(fcf) != types::addr_mode::LONG {
            return Ok(None);
        }
        match self.dest_addr_offset(buf)? {
            Some(off) => read_u64_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    /// Source PAN ID (2 bytes, LE).
    /// Returns None if src_addr_mode == 0 or PAN ID compressed.
    pub fn src_panid(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        match self.src_panid_offset(buf)? {
            Some(off) => read_u16_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    /// Source short address (2 bytes, LE).
    /// Returns None if src_addr_mode != SHORT.
    pub fn src_addr_short(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_src_addr_mode(fcf) != types::addr_mode::SHORT {
            return Ok(None);
        }
        match self.src_addr_offset(buf)? {
            Some(off) => read_u16_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    /// Source long address (8 bytes, LE).
    /// Returns None if src_addr_mode != LONG.
    pub fn src_addr_long(&self, buf: &[u8]) -> Result<Option<u64>, FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_src_addr_mode(fcf) != types::addr_mode::LONG {
            return Ok(None);
        }
        match self.src_addr_offset(buf)? {
            Some(off) => read_u64_le(buf, off).map(Some),
            None => Ok(None),
        }
    }

    // ========================================================================
    // FCF field writers
    // ========================================================================

    /// Set the frame type in the FCF.
    pub fn set_fcf_frametype(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        fcf = (fcf & !0x0007) | ((val as u16) & 0x07);
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the security enabled flag in the FCF.
    pub fn set_fcf_security(&self, buf: &mut [u8], val: bool) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        if val {
            fcf |= 0x0008;
        } else {
            fcf &= !0x0008;
        }
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the frame pending flag in the FCF.
    pub fn set_fcf_pending(&self, buf: &mut [u8], val: bool) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        if val {
            fcf |= 0x0010;
        } else {
            fcf &= !0x0010;
        }
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the ACK request flag in the FCF.
    pub fn set_fcf_ackreq(&self, buf: &mut [u8], val: bool) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        if val {
            fcf |= 0x0020;
        } else {
            fcf &= !0x0020;
        }
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the PAN ID compression flag in the FCF.
    pub fn set_fcf_panidcompress(&self, buf: &mut [u8], val: bool) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        if val {
            fcf |= 0x0040;
        } else {
            fcf &= !0x0040;
        }
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the destination address mode in the FCF.
    pub fn set_fcf_destaddrmode(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        fcf = (fcf & !0x0C00) | (((val as u16) & 0x03) << 10);
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the frame version in the FCF.
    pub fn set_fcf_framever(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        fcf = (fcf & !0x3000) | (((val as u16) & 0x03) << 12);
        write_fcf(buf, self.index.start, fcf)
    }

    /// Set the source address mode in the FCF.
    pub fn set_fcf_srcaddrmode(&self, buf: &mut [u8], val: u8) -> Result<(), FieldError> {
        let mut fcf = self.fcf_raw(buf)?;
        fcf = (fcf & !0xC000) | (((val as u16) & 0x03) << 14);
        write_fcf(buf, self.index.start, fcf)
    }

    // ========================================================================
    // Addressing field writers
    // ========================================================================

    /// Set the destination PAN ID.
    pub fn set_dest_panid(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        match self.dest_panid_offset(buf)? {
            Some(off) => write_u16_le(val, buf, off),
            None => Err(FieldError::InvalidValue(
                "dest_addr_mode is None, cannot set dest_panid".into(),
            )),
        }
    }

    /// Set the destination short address.
    pub fn set_dest_addr_short(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_dest_addr_mode(fcf) != types::addr_mode::SHORT {
            return Err(FieldError::InvalidValue(
                "dest_addr_mode is not SHORT".into(),
            ));
        }
        match self.dest_addr_offset(buf)? {
            Some(off) => write_u16_le(val, buf, off),
            None => Err(FieldError::InvalidValue("no dest address offset".into())),
        }
    }

    /// Set the destination long address.
    pub fn set_dest_addr_long(&self, buf: &mut [u8], val: u64) -> Result<(), FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_dest_addr_mode(fcf) != types::addr_mode::LONG {
            return Err(FieldError::InvalidValue(
                "dest_addr_mode is not LONG".into(),
            ));
        }
        match self.dest_addr_offset(buf)? {
            Some(off) => write_u64_le(val, buf, off),
            None => Err(FieldError::InvalidValue("no dest address offset".into())),
        }
    }

    /// Set the source PAN ID.
    pub fn set_src_panid(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        match self.src_panid_offset(buf)? {
            Some(off) => write_u16_le(val, buf, off),
            None => Err(FieldError::InvalidValue(
                "src PAN ID not present (compressed or src_addr_mode is None)".into(),
            )),
        }
    }

    /// Set the source short address.
    pub fn set_src_addr_short(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_src_addr_mode(fcf) != types::addr_mode::SHORT {
            return Err(FieldError::InvalidValue(
                "src_addr_mode is not SHORT".into(),
            ));
        }
        match self.src_addr_offset(buf)? {
            Some(off) => write_u16_le(val, buf, off),
            None => Err(FieldError::InvalidValue("no src address offset".into())),
        }
    }

    /// Set the source long address.
    pub fn set_src_addr_long(&self, buf: &mut [u8], val: u64) -> Result<(), FieldError> {
        let fcf = self.fcf_raw(buf)?;
        if fcf_src_addr_mode(fcf) != types::addr_mode::LONG {
            return Err(FieldError::InvalidValue("src_addr_mode is not LONG".into()));
        }
        match self.src_addr_offset(buf)? {
            Some(off) => write_u64_le(val, buf, off),
            None => Err(FieldError::InvalidValue("no src address offset".into())),
        }
    }

    // ========================================================================
    // Dynamic field access
    // ========================================================================

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "fcf_frametype" => Some(self.fcf_frametype(buf).map(FieldValue::U8)),
            "fcf_security" => Some(self.fcf_security(buf).map(FieldValue::Bool)),
            "fcf_pending" => Some(self.fcf_pending(buf).map(FieldValue::Bool)),
            "fcf_ackreq" => Some(self.fcf_ackreq(buf).map(FieldValue::Bool)),
            "fcf_panidcompress" => Some(self.fcf_panidcompress(buf).map(FieldValue::Bool)),
            "fcf_destaddrmode" => Some(self.fcf_destaddrmode(buf).map(FieldValue::U8)),
            "fcf_framever" => Some(self.fcf_framever(buf).map(FieldValue::U8)),
            "fcf_srcaddrmode" => Some(self.fcf_srcaddrmode(buf).map(FieldValue::U8)),
            "seqnum" => Some(self.seqnum(buf).map(FieldValue::U8)),
            "dest_panid" => Some(
                self.dest_panid(buf)
                    .map(|opt| opt.map(FieldValue::U16).unwrap_or(FieldValue::U16(0))),
            ),
            "dest_addr_short" => Some(
                self.dest_addr_short(buf)
                    .map(|opt| opt.map(FieldValue::U16).unwrap_or(FieldValue::U16(0))),
            ),
            "dest_addr_long" => Some(
                self.dest_addr_long(buf)
                    .map(|opt| opt.map(FieldValue::U64).unwrap_or(FieldValue::U64(0))),
            ),
            "src_panid" => Some(
                self.src_panid(buf)
                    .map(|opt| opt.map(FieldValue::U16).unwrap_or(FieldValue::U16(0))),
            ),
            "src_addr_short" => Some(
                self.src_addr_short(buf)
                    .map(|opt| opt.map(FieldValue::U16).unwrap_or(FieldValue::U16(0))),
            ),
            "src_addr_long" => Some(
                self.src_addr_long(buf)
                    .map(|opt| opt.map(FieldValue::U64).unwrap_or(FieldValue::U64(0))),
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
            "fcf_frametype" => Some(match value.as_u8() {
                Some(v) => self.set_fcf_frametype(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u8 for fcf_frametype".into(),
                )),
            }),
            "fcf_security" => Some(match value.as_bool() {
                Some(v) => self.set_fcf_security(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected bool for fcf_security".into(),
                )),
            }),
            "fcf_pending" => Some(match value.as_bool() {
                Some(v) => self.set_fcf_pending(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected bool for fcf_pending".into(),
                )),
            }),
            "fcf_ackreq" => Some(match value.as_bool() {
                Some(v) => self.set_fcf_ackreq(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected bool for fcf_ackreq".into(),
                )),
            }),
            "fcf_panidcompress" => Some(match value.as_bool() {
                Some(v) => self.set_fcf_panidcompress(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected bool for fcf_panidcompress".into(),
                )),
            }),
            "fcf_destaddrmode" => Some(match value.as_u8() {
                Some(v) => self.set_fcf_destaddrmode(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u8 for fcf_destaddrmode".into(),
                )),
            }),
            "fcf_framever" => Some(match value.as_u8() {
                Some(v) => self.set_fcf_framever(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u8 for fcf_framever".into(),
                )),
            }),
            "fcf_srcaddrmode" => Some(match value.as_u8() {
                Some(v) => self.set_fcf_srcaddrmode(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u8 for fcf_srcaddrmode".into(),
                )),
            }),
            "seqnum" => Some(match value.as_u8() {
                Some(v) => self.set_seqnum(buf, v),
                None => Err(FieldError::InvalidValue("expected u8 for seqnum".into())),
            }),
            "dest_panid" => Some(match value.as_u16() {
                Some(v) => self.set_dest_panid(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u16 for dest_panid".into(),
                )),
            }),
            "dest_addr_short" => Some(match value.as_u16() {
                Some(v) => self.set_dest_addr_short(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u16 for dest_addr_short".into(),
                )),
            }),
            "dest_addr_long" => Some(match value.as_u64() {
                Some(v) => self.set_dest_addr_long(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u64 for dest_addr_long".into(),
                )),
            }),
            "src_panid" => Some(match value.as_u16() {
                Some(v) => self.set_src_panid(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u16 for src_panid".into(),
                )),
            }),
            "src_addr_short" => Some(match value.as_u16() {
                Some(v) => self.set_src_addr_short(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u16 for src_addr_short".into(),
                )),
            }),
            "src_addr_long" => Some(match value.as_u64() {
                Some(v) => self.set_src_addr_long(buf, v),
                None => Err(FieldError::InvalidValue(
                    "expected u64 for src_addr_long".into(),
                )),
            }),
            _ => None,
        }
    }

    /// Get the list of field names.
    pub fn field_names() -> &'static [&'static str] {
        DOT15D4_FIELDS
    }

    /// Determine the next layer kind based on frame type.
    pub fn next_layer(&self, buf: &[u8]) -> Option<LayerKind> {
        self.fcf_frametype(buf).ok().and_then(|ft| match ft {
            types::frame_type::BEACON => None,
            types::frame_type::DATA => Some(LayerKind::Raw),
            types::frame_type::ACK => None,
            types::frame_type::MAC_CMD => None,
            _ => Some(LayerKind::Raw),
        })
    }

    /// Format a long address as a colon-separated hex string.
    pub fn format_long_addr(addr: u64) -> String {
        let bytes = addr.to_be_bytes();
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
        )
    }

    /// Compute hash for packet matching (based on sequence number).
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.seqnum(buf).map(|s| vec![s]).unwrap_or_default()
    }
}

impl Layer for Dot15d4Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dot15d4
    }

    fn summary(&self, buf: &[u8]) -> String {
        let ft = self.fcf_frametype(buf).unwrap_or(0);
        let ackreq = self.fcf_ackreq(buf).unwrap_or(false);
        let dest_mode = self.fcf_destaddrmode(buf).unwrap_or(0);
        let src_mode = self.fcf_srcaddrmode(buf).unwrap_or(0);
        let seq = self.seqnum(buf).unwrap_or(0);

        format!(
            "802.15.4 {} ackreq({}) ( {} -> {} ) Seq#{}",
            types::frame_type_name(ft),
            ackreq,
            types::addr_mode_name(dest_mode),
            types::addr_mode_name(src_mode),
            seq,
        )
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        match self.fcf_raw(buf) {
            Ok(fcf) => {
                let computed = compute_header_len(fcf);
                let available = self.index.len();
                computed.min(available)
            },
            Err(_) => DOT15D4_MIN_HEADER_LEN.min(self.index.len()),
        }
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        // An ACK frame answers a frame if:
        // 1. This is an ACK (frametype == 2)
        // 2. Sequence numbers match
        // 3. The other frame requested an ACK
        if let (Ok(ft), Ok(seq), Ok(other_seq), Ok(other_ackreq)) = (
            self.fcf_frametype(buf),
            self.seqnum(buf),
            other.seqnum(other_buf),
            other.fcf_ackreq(other_buf),
        ) {
            if ft == types::frame_type::ACK && seq == other_seq && other_ackreq {
                return true;
            }
        }
        false
    }

    fn field_names(&self) -> &'static [&'static str] {
        DOT15D4_FIELDS
    }
}

// ============================================================================
// Dot15d4FcsLayer -- 802.15.4 frame with FCS
// ============================================================================

/// IEEE 802.15.4 MAC frame with FCS (2-byte CRC at the end).
///
/// This is a drop-in replacement for `Dot15d4Layer` that expects a
/// 2-byte FCS/checksum at the end of the frame, and produces one
/// when building.
#[derive(Debug, Clone)]
pub struct Dot15d4FcsLayer {
    pub index: LayerIndex,
}

impl Dot15d4FcsLayer {
    /// Create a new Dot15d4FcsLayer from start/end offsets.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dot15d4Fcs, start, end),
        }
    }

    /// Create the inner Dot15d4Layer view (excluding FCS bytes).
    fn inner(&self) -> Dot15d4Layer {
        Dot15d4Layer::new(self.index.start, self.index.end.saturating_sub(FCS_LEN))
    }

    /// Read the FCS value (2 bytes, LE) from the end of the frame.
    pub fn fcs(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < FCS_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.index.end.saturating_sub(FCS_LEN),
                need: FCS_LEN,
                have: slice.len(),
            });
        }
        let fcs_offset = slice.len() - FCS_LEN;
        Ok(u16::from_le_bytes([
            slice[fcs_offset],
            slice[fcs_offset + 1],
        ]))
    }

    /// Verify the FCS of this frame.
    pub fn verify_fcs(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let slice = self.index.slice(buf);
        if slice.len() < FCS_LEN + DOT15D4_MIN_HEADER_LEN {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: DOT15D4_MIN_HEADER_LEN + FCS_LEN,
                have: slice.len(),
            });
        }
        let data = &slice[..slice.len() - FCS_LEN];
        let expected = self.fcs(buf)?;
        Ok(crc::verify_fcs(data, expected))
    }

    // Delegate all FCF/addressing accessors to the inner layer.

    pub fn fcf_raw(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.inner().fcf_raw(buf)
    }

    pub fn fcf_frametype(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.inner().fcf_frametype(buf)
    }

    pub fn fcf_security(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.inner().fcf_security(buf)
    }

    pub fn fcf_pending(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.inner().fcf_pending(buf)
    }

    pub fn fcf_ackreq(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.inner().fcf_ackreq(buf)
    }

    pub fn fcf_panidcompress(&self, buf: &[u8]) -> Result<bool, FieldError> {
        self.inner().fcf_panidcompress(buf)
    }

    pub fn fcf_destaddrmode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.inner().fcf_destaddrmode(buf)
    }

    pub fn fcf_framever(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.inner().fcf_framever(buf)
    }

    pub fn fcf_srcaddrmode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.inner().fcf_srcaddrmode(buf)
    }

    pub fn seqnum(&self, buf: &[u8]) -> Result<u8, FieldError> {
        self.inner().seqnum(buf)
    }

    pub fn dest_panid(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        self.inner().dest_panid(buf)
    }

    pub fn dest_addr_short(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        self.inner().dest_addr_short(buf)
    }

    pub fn dest_addr_long(&self, buf: &[u8]) -> Result<Option<u64>, FieldError> {
        self.inner().dest_addr_long(buf)
    }

    pub fn src_panid(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        self.inner().src_panid(buf)
    }

    pub fn src_addr_short(&self, buf: &[u8]) -> Result<Option<u16>, FieldError> {
        self.inner().src_addr_short(buf)
    }

    pub fn src_addr_long(&self, buf: &[u8]) -> Result<Option<u64>, FieldError> {
        self.inner().src_addr_long(buf)
    }

    /// Get a field value by name (includes "fcs").
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        if name == "fcs" {
            return Some(self.fcs(buf).map(FieldValue::U16));
        }
        self.inner().get_field(buf, name)
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        // FCS is computed, not set directly
        if name == "fcs" {
            return Some(Err(FieldError::InvalidValue(
                "FCS is computed automatically, cannot set directly".into(),
            )));
        }
        self.inner().set_field(buf, name, value)
    }

    /// Get the list of field names.
    pub fn field_names() -> &'static [&'static str] {
        DOT15D4_FCS_FIELDS
    }

    /// Compute hash for packet matching.
    pub fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.inner().hashret(buf)
    }
}

impl Layer for Dot15d4FcsLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dot15d4Fcs
    }

    fn summary(&self, buf: &[u8]) -> String {
        let inner_summary = self.inner().summary(buf);
        let fcs_str = self
            .fcs(buf)
            .map(|f| format!(" FCS={:#06x}", f))
            .unwrap_or_default();
        format!("{}{}", inner_summary, fcs_str)
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        // Include FCS in the header length
        let inner_len = self.inner().header_len(buf);
        let total = inner_len + FCS_LEN;
        total.min(self.index.len())
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.hashret(buf)
    }

    fn answers(&self, buf: &[u8], other: &Self, other_buf: &[u8]) -> bool {
        self.inner().answers(buf, &other.inner(), other_buf)
    }

    fn field_names(&self) -> &'static [&'static str] {
        DOT15D4_FCS_FIELDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal data frame with short addressing:
    /// FCF: frame_type=1 (Data), dest_addr_mode=2 (Short), src_addr_mode=2 (Short),
    ///      panid_compress=1 (no src PAN ID)
    /// Seq: 0x05
    /// Dest PAN ID: 0x1234
    /// Dest Addr: 0xFFFF
    /// Src Addr: 0x0001
    fn sample_data_frame_short() -> Vec<u8> {
        // FCF: frame_type=1, security=0, pending=0, ackreq=1, panid_compress=1
        //      dest_addr_mode=2, frame_ver=0, src_addr_mode=2
        // Bits: src_addr_mode(2)=10, frame_ver=00, dest_addr_mode(2)=10, reserved=000,
        //       panid_compress=1, ackreq=1, pending=0, security=0, frame_type=001
        // Byte 0 (bits 0-7): 0_1_1_0_0_001 = 0x61
        // Byte 1 (bits 8-15): 10_00_10_00 = 0x88
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x61, 0x88]); // FCF (LE)
        buf.push(0x05); // Sequence number
        buf.extend_from_slice(&[0x34, 0x12]); // Dest PAN ID (LE)
        buf.extend_from_slice(&[0xFF, 0xFF]); // Dest Addr Short (LE)
        buf.extend_from_slice(&[0x01, 0x00]); // Src Addr Short (LE)
        buf
    }

    /// Build a data frame with long addressing and no PAN ID compression.
    fn sample_data_frame_long() -> Vec<u8> {
        // FCF: frame_type=1, dest_addr_mode=3 (Long), src_addr_mode=3 (Long),
        //      panid_compress=0
        // Byte 0 (bits 0-7): 0_0_0_0_0_001 = 0x01
        // Byte 1 (bits 8-15): 11_00_11_00 = 0xCC
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0xCC]); // FCF
        buf.push(0x0A); // Seqnum
        buf.extend_from_slice(&[0x34, 0x12]); // Dest PAN ID
        buf.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // Dest Addr Long
        buf.extend_from_slice(&[0xCD, 0xAB]); // Src PAN ID
        buf.extend_from_slice(&[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]); // Src Addr Long
        buf
    }

    /// Build a minimal ACK frame (no addressing).
    fn sample_ack_frame() -> Vec<u8> {
        // FCF: frame_type=2, all addr modes = 0
        // Byte 0: 0_0_0_0_0_010 = 0x02
        // Byte 1: 00_00_00_00 = 0x00
        vec![0x02, 0x00, 0x05] // FCF + seqnum
    }

    #[test]
    fn test_fcf_helpers() {
        let fcf = build_fcf(1, false, false, true, true, 2, 0, 2);
        assert_eq!(fcf_frame_type(fcf), 1);
        assert!(!fcf_security(fcf));
        assert!(!fcf_pending(fcf));
        assert!(fcf_ackreq(fcf));
        assert!(fcf_panid_compress(fcf));
        assert_eq!(fcf_dest_addr_mode(fcf), 2);
        assert_eq!(fcf_frame_ver(fcf), 0);
        assert_eq!(fcf_src_addr_mode(fcf), 2);
    }

    #[test]
    fn test_build_fcf_roundtrip() {
        for ft in 0..=5u8 {
            for dam in 0..=3u8 {
                for sam in 0..=3u8 {
                    let fcf = build_fcf(ft, true, false, true, false, dam, 1, sam);
                    assert_eq!(fcf_frame_type(fcf), ft);
                    assert!(fcf_security(fcf));
                    assert!(!fcf_pending(fcf));
                    assert!(fcf_ackreq(fcf));
                    assert!(!fcf_panid_compress(fcf));
                    assert_eq!(fcf_dest_addr_mode(fcf), dam);
                    assert_eq!(fcf_frame_ver(fcf), 1);
                    assert_eq!(fcf_src_addr_mode(fcf), sam);
                }
            }
        }
    }

    #[test]
    fn test_compute_header_len() {
        // ACK frame: no addressing
        let fcf_ack = build_fcf(2, false, false, false, false, 0, 0, 0);
        assert_eq!(compute_header_len(fcf_ack), 3); // FCF + seqnum

        // Data frame with short dest+src, panid compress
        let fcf_data = build_fcf(1, false, false, true, true, 2, 0, 2);
        // 3 (base) + 2 (dest PAN) + 2 (dest short) + 2 (src short) = 9
        assert_eq!(compute_header_len(fcf_data), 9);

        // Data frame with short dest+src, no panid compress
        let fcf_data2 = build_fcf(1, false, false, true, false, 2, 0, 2);
        // 3 + 2 (dest PAN) + 2 (dest short) + 2 (src PAN) + 2 (src short) = 11
        assert_eq!(compute_header_len(fcf_data2), 11);

        // Data frame with long dest, short src, panid compress
        let fcf_data3 = build_fcf(1, false, false, false, true, 3, 0, 2);
        // 3 + 2 (dest PAN) + 8 (dest long) + 2 (src short) = 15
        assert_eq!(compute_header_len(fcf_data3), 15);

        // Data frame with long dest+src, no compress
        let fcf_data4 = build_fcf(1, false, false, false, false, 3, 0, 3);
        // 3 + 2 (dest PAN) + 8 (dest long) + 2 (src PAN) + 8 (src long) = 23
        assert_eq!(compute_header_len(fcf_data4), 23);
    }

    #[test]
    fn test_parse_data_frame_short() {
        let buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        assert_eq!(layer.fcf_frametype(&buf).unwrap(), 1);
        assert!(!layer.fcf_security(&buf).unwrap());
        assert!(!layer.fcf_pending(&buf).unwrap());
        assert!(layer.fcf_ackreq(&buf).unwrap());
        assert!(layer.fcf_panidcompress(&buf).unwrap());
        assert_eq!(layer.fcf_destaddrmode(&buf).unwrap(), 2);
        assert_eq!(layer.fcf_framever(&buf).unwrap(), 0);
        assert_eq!(layer.fcf_srcaddrmode(&buf).unwrap(), 2);
        assert_eq!(layer.seqnum(&buf).unwrap(), 0x05);

        assert_eq!(layer.dest_panid(&buf).unwrap(), Some(0x1234));
        assert_eq!(layer.dest_addr_short(&buf).unwrap(), Some(0xFFFF));
        assert_eq!(layer.dest_addr_long(&buf).unwrap(), None);

        // PAN ID compressed, so src_panid should be None
        assert_eq!(layer.src_panid(&buf).unwrap(), None);
        assert_eq!(layer.src_addr_short(&buf).unwrap(), Some(0x0001));
        assert_eq!(layer.src_addr_long(&buf).unwrap(), None);

        // Header length = 9
        assert_eq!(layer.header_len(&buf), 9);
    }

    #[test]
    fn test_parse_data_frame_long() {
        let buf = sample_data_frame_long();
        let layer = Dot15d4Layer::new(0, buf.len());

        assert_eq!(layer.fcf_frametype(&buf).unwrap(), 1);
        assert_eq!(layer.fcf_destaddrmode(&buf).unwrap(), 3);
        assert_eq!(layer.fcf_srcaddrmode(&buf).unwrap(), 3);
        assert!(!layer.fcf_panidcompress(&buf).unwrap());
        assert_eq!(layer.seqnum(&buf).unwrap(), 0x0A);

        assert_eq!(layer.dest_panid(&buf).unwrap(), Some(0x1234));
        assert_eq!(
            layer.dest_addr_long(&buf).unwrap(),
            Some(0x0102030405060708)
        );
        assert_eq!(layer.dest_addr_short(&buf).unwrap(), None);

        assert_eq!(layer.src_panid(&buf).unwrap(), Some(0xABCD));
        assert_eq!(layer.src_addr_long(&buf).unwrap(), Some(0x1112131415161718));
        assert_eq!(layer.src_addr_short(&buf).unwrap(), None);

        // Header: 3 + 2 + 8 + 2 + 8 = 23
        assert_eq!(layer.header_len(&buf), 23);
    }

    #[test]
    fn test_parse_ack_frame() {
        let buf = sample_ack_frame();
        let layer = Dot15d4Layer::new(0, buf.len());

        assert_eq!(layer.fcf_frametype(&buf).unwrap(), 2);
        assert_eq!(layer.fcf_destaddrmode(&buf).unwrap(), 0);
        assert_eq!(layer.fcf_srcaddrmode(&buf).unwrap(), 0);
        assert_eq!(layer.seqnum(&buf).unwrap(), 0x05);

        assert_eq!(layer.dest_panid(&buf).unwrap(), None);
        assert_eq!(layer.dest_addr_short(&buf).unwrap(), None);
        assert_eq!(layer.src_panid(&buf).unwrap(), None);
        assert_eq!(layer.src_addr_short(&buf).unwrap(), None);

        assert_eq!(layer.header_len(&buf), 3);
    }

    #[test]
    fn test_ack_answers() {
        let data_buf = sample_data_frame_short();
        let data_layer = Dot15d4Layer::new(0, data_buf.len());

        // ACK with matching sequence number
        let ack_buf = sample_ack_frame();
        let ack_layer = Dot15d4Layer::new(0, ack_buf.len());

        assert!(ack_layer.answers(&ack_buf, &data_layer, &data_buf));
    }

    #[test]
    fn test_ack_does_not_answer_wrong_seq() {
        let data_buf = sample_data_frame_short(); // seqnum = 0x05
        let data_layer = Dot15d4Layer::new(0, data_buf.len());

        // ACK with different sequence number
        let mut ack_buf = sample_ack_frame();
        ack_buf[2] = 0x06; // Different seqnum
        let ack_layer = Dot15d4Layer::new(0, ack_buf.len());

        assert!(!ack_layer.answers(&ack_buf, &data_layer, &data_buf));
    }

    #[test]
    fn test_summary() {
        let buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());
        let summary = layer.summary(&buf);
        assert!(summary.contains("Data"));
        assert!(summary.contains("ackreq(true)"));
        assert!(summary.contains("Short"));
        assert!(summary.contains("Seq#5"));
    }

    #[test]
    fn test_get_field() {
        let buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        let ft = layer.get_field(&buf, "fcf_frametype").unwrap().unwrap();
        assert_eq!(ft, FieldValue::U8(1));

        let seq = layer.get_field(&buf, "seqnum").unwrap().unwrap();
        assert_eq!(seq, FieldValue::U8(5));

        let dp = layer.get_field(&buf, "dest_panid").unwrap().unwrap();
        assert_eq!(dp, FieldValue::U16(0x1234));

        assert!(layer.get_field(&buf, "nonexistent").is_none());
    }

    #[test]
    fn test_set_field() {
        let mut buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        layer
            .set_field(&mut buf, "seqnum", FieldValue::U8(42))
            .unwrap()
            .unwrap();
        assert_eq!(layer.seqnum(&buf).unwrap(), 42);

        layer
            .set_field(&mut buf, "fcf_ackreq", FieldValue::Bool(false))
            .unwrap()
            .unwrap();
        assert!(!layer.fcf_ackreq(&buf).unwrap());
    }

    #[test]
    fn test_set_dest_panid() {
        let mut buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        layer.set_dest_panid(&mut buf, 0xABCD).unwrap();
        assert_eq!(layer.dest_panid(&buf).unwrap(), Some(0xABCD));
    }

    #[test]
    fn test_set_dest_addr_short() {
        let mut buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        layer.set_dest_addr_short(&mut buf, 0x1234).unwrap();
        assert_eq!(layer.dest_addr_short(&buf).unwrap(), Some(0x1234));
    }

    #[test]
    fn test_set_src_addr_short() {
        let mut buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        layer.set_src_addr_short(&mut buf, 0x5678).unwrap();
        assert_eq!(layer.src_addr_short(&buf).unwrap(), Some(0x5678));
    }

    #[test]
    fn test_fcs_layer_basic() {
        let mut frame = sample_data_frame_short();
        // Append FCS
        let fcs = crc::compute_fcs(&frame);
        frame.extend_from_slice(&fcs);

        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert_eq!(layer.fcf_frametype(&frame).unwrap(), 1);
        assert_eq!(layer.seqnum(&frame).unwrap(), 0x05);
        assert!(layer.verify_fcs(&frame).unwrap());
    }

    #[test]
    fn test_fcs_layer_corrupted() {
        let mut frame = sample_data_frame_short();
        // Append wrong FCS
        frame.extend_from_slice(&[0x00, 0x00]);

        let layer = Dot15d4FcsLayer::new(0, frame.len());
        assert!(!layer.verify_fcs(&frame).unwrap());
    }

    #[test]
    fn test_fcs_layer_get_field() {
        let mut frame = sample_data_frame_short();
        let fcs_val = crc::crc_ccitt_kermit(&frame);
        let fcs_bytes = fcs_val.to_le_bytes();
        frame.extend_from_slice(&fcs_bytes);

        let layer = Dot15d4FcsLayer::new(0, frame.len());
        let fcs = layer.get_field(&frame, "fcs").unwrap().unwrap();
        assert_eq!(fcs, FieldValue::U16(fcs_val));

        // Also access regular fields
        let seq = layer.get_field(&frame, "seqnum").unwrap().unwrap();
        assert_eq!(seq, FieldValue::U8(5));
    }

    #[test]
    fn test_fcs_layer_summary() {
        let mut frame = sample_data_frame_short();
        let fcs_bytes = crc::compute_fcs(&frame);
        frame.extend_from_slice(&fcs_bytes);

        let layer = Dot15d4FcsLayer::new(0, frame.len());
        let summary = layer.summary(&frame);
        assert!(summary.contains("802.15.4"));
        assert!(summary.contains("FCS="));
    }

    #[test]
    fn test_format_long_addr() {
        let addr: u64 = 0x0102030405060708;
        let formatted = Dot15d4Layer::format_long_addr(addr);
        assert_eq!(formatted, "01:02:03:04:05:06:07:08");
    }

    #[test]
    fn test_validate() {
        assert!(Dot15d4Layer::validate(&[0x00, 0x00, 0x00], 0).is_ok());
        assert!(Dot15d4Layer::validate(&[0x00, 0x00], 0).is_err());
        assert!(Dot15d4Layer::validate(&[0x00, 0x00, 0x00], 1).is_err());
    }

    #[test]
    fn test_field_names() {
        let names = Dot15d4Layer::field_names();
        assert!(names.contains(&"fcf_frametype"));
        assert!(names.contains(&"seqnum"));
        assert!(names.contains(&"dest_panid"));
        assert!(names.contains(&"src_addr_long"));
    }

    #[test]
    fn test_fcs_field_names() {
        let names = Dot15d4FcsLayer::field_names();
        assert!(names.contains(&"fcs"));
        assert!(names.contains(&"fcf_frametype"));
    }

    #[test]
    fn test_fcf_writers() {
        let mut buf = sample_data_frame_short();
        let layer = Dot15d4Layer::new(0, buf.len());

        // Change frame type to Beacon (0)
        layer.set_fcf_frametype(&mut buf, 0).unwrap();
        assert_eq!(layer.fcf_frametype(&buf).unwrap(), 0);

        // Toggle security
        layer.set_fcf_security(&mut buf, true).unwrap();
        assert!(layer.fcf_security(&buf).unwrap());

        // Toggle pending
        layer.set_fcf_pending(&mut buf, true).unwrap();
        assert!(layer.fcf_pending(&buf).unwrap());

        // Change frame version
        layer.set_fcf_framever(&mut buf, 1).unwrap();
        assert_eq!(layer.fcf_framever(&buf).unwrap(), 1);

        // Other fields should remain intact
        assert!(layer.fcf_ackreq(&buf).unwrap());
        assert!(layer.fcf_panidcompress(&buf).unwrap());
        assert_eq!(layer.fcf_destaddrmode(&buf).unwrap(), 2);
        assert_eq!(layer.fcf_srcaddrmode(&buf).unwrap(), 2);
    }
}
