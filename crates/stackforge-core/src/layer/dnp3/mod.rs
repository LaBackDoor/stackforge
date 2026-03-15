//! DNP3 (IEEE 1815) protocol layer implementation.
//!
//! DNP3 (Distributed Network Protocol) is a set of communication protocols
//! used between components in process automation systems. It is primarily
//! used in SCADA systems for communication between control centers and
//! remote terminal units (RTUs).
//!
//! This implementation provides a single `LayerKind::Dnp3` with sub-accessors
//! for the link, transport, and application layers.
//!
//! ## Link Layer Format
//!
//! ```text
//! Bytes 0-1: Start bytes (0x05 0x64)
//! Byte 2: Length (data following, excludes start bytes and CRC)
//! Byte 3: Control byte
//!   - bit 7: DIR (1=master→outstation, 0=outstation→master)
//!   - bit 6: PRM (1=primary, 0=secondary)
//!   - bit 5: FCB/DFC
//!   - bit 4: FCV/RES
//!   - bits 3-0: Function Code
//! Bytes 4-5: Destination address (u16 LE)
//! Bytes 6-7: Source address (u16 LE)
//! Bytes 8-9: CRC-16/DNP of bytes 0-7
//! Then: Data blocks, each up to 16 bytes + 2 byte CRC
//! ```
//!
//! ## Transport Layer (1 byte header in user data)
//!
//! ```text
//! Byte 0: [FIN(1)] [FIR(1)] [SEQ(6)]
//! ```
//!
//! ## Application Layer
//!
//! ```text
//! Byte 0: Application Control (FIR, FIN, CON, UNS, SEQ)
//! Byte 1: Function Code
//! Bytes 2-3: Internal Indications (IIN, response only, when FIR=1)
//! Then: Object headers
//! ```

pub mod application;
pub mod builder;
pub mod crc;
pub mod transport;

pub use application::{AppControl, Iin, app_func_name, group_name, is_response_func};
pub use builder::Dnp3Builder;
pub use crc::{dnp3_crc, verify_dnp3_crc};
pub use transport::TransportHeader;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum DNP3 frame size: link header (8 bytes) + header CRC (2 bytes).
pub const DNP3_MIN_HEADER_LEN: usize = 10;

/// Default DNP3 TCP port.
pub const DNP3_PORT: u16 = 20000;

/// DNP3 start bytes (magic number).
pub const DNP3_START_BYTES: [u8; 2] = [0x05, 0x64];

/// Field names for DNP3 layer (exposed for Python/generic access).
pub static DNP3_FIELD_NAMES: &[&str] = &[
    "start",
    "length",
    "control",
    "dir",
    "prm",
    "fcb",
    "fcv",
    "link_func",
    "dst",
    "src",
    "transport_fin",
    "transport_fir",
    "transport_seq",
    "app_fir",
    "app_fin",
    "app_con",
    "app_uns",
    "app_seq",
    "app_func",
    "iin",
];

/// Link layer primary function codes (PRM=1).
pub mod link_func_primary {
    pub const RESET_LINK: u8 = 0;
    pub const RESET_USER: u8 = 1;
    pub const TEST_LINK: u8 = 2;
    pub const USER_DATA: u8 = 3;
    pub const UNCONFIRMED_USER_DATA: u8 = 4;
    pub const REQUEST_LINK_STATUS: u8 = 9;
}

/// Link layer secondary function codes (PRM=0).
pub mod link_func_secondary {
    pub const ACK: u8 = 0;
    pub const NACK: u8 = 1;
    pub const LINK_STATUS: u8 = 11;
    pub const NOT_SUPPORTED: u8 = 15;
}

/// Return a human-readable name for a link layer function code.
#[must_use]
pub fn link_func_name(prm: bool, fc: u8) -> &'static str {
    if prm {
        match fc {
            0 => "RESET_LINK",
            1 => "RESET_USER",
            2 => "TEST_LINK",
            3 => "USER_DATA",
            4 => "UNCONFIRMED_USER_DATA",
            9 => "REQUEST_LINK_STATUS",
            _ => "UNKNOWN",
        }
    } else {
        match fc {
            0 => "ACK",
            1 => "NACK",
            11 => "LINK_STATUS",
            15 => "NOT_SUPPORTED",
            _ => "UNKNOWN",
        }
    }
}

/// Detect whether a byte buffer starts with a valid DNP3 frame.
#[inline]
#[must_use]
pub fn is_dnp3_payload(buf: &[u8]) -> bool {
    buf.len() >= DNP3_MIN_HEADER_LEN && buf[0] == 0x05 && buf[1] == 0x64
}

/// DNP3 protocol layer.
///
/// Provides zero-copy access to link, transport, and application layer fields
/// within a DNP3 frame stored in a packet buffer.
#[derive(Debug, Clone)]
pub struct Dnp3Layer {
    pub index: LayerIndex,
}

impl Dnp3Layer {
    /// Create a new DNP3 layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Get the raw slice for this layer.
    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Link Layer Accessors
    // ========================================================================

    /// Get the start bytes (should be [0x05, 0x64]).
    #[must_use]
    pub fn start_bytes(&self, buf: &[u8]) -> [u8; 2] {
        let s = self.slice(buf);
        if s.len() < 2 {
            return [0, 0];
        }
        [s[0], s[1]]
    }

    /// Get the link layer length field.
    pub fn link_length(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 1,
                have: s.len().saturating_sub(2),
            });
        }
        Ok(s[2])
    }

    /// Get the control byte.
    pub fn control(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 3,
                need: 1,
                have: s.len().saturating_sub(3),
            });
        }
        Ok(s[3])
    }

    /// Get the DIR (direction) bit: true = master→outstation.
    pub fn dir(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.control(buf)? & 0x80 != 0)
    }

    /// Get the PRM (primary) bit: true = primary message.
    pub fn prm(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.control(buf)? & 0x40 != 0)
    }

    /// Get the FCB (frame count bit) / DFC (data flow control) bit.
    pub fn fcb(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.control(buf)? & 0x20 != 0)
    }

    /// Get the FCV (frame count valid) / RES (reserved) bit.
    pub fn fcv(&self, buf: &[u8]) -> Result<bool, FieldError> {
        Ok(self.control(buf)? & 0x10 != 0)
    }

    /// Get the link layer function code (bits 3-0 of control byte).
    pub fn link_func(&self, buf: &[u8]) -> Result<u8, FieldError> {
        Ok(self.control(buf)? & 0x0F)
    }

    /// Get the link layer function name.
    pub fn link_func_name(&self, buf: &[u8]) -> Result<&'static str, FieldError> {
        let prm = self.prm(buf)?;
        let fc = self.link_func(buf)?;
        Ok(link_func_name(prm, fc))
    }

    /// Get the destination address (u16 LE).
    pub fn dst(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 4,
                need: 2,
                have: s.len().saturating_sub(4),
            });
        }
        Ok(u16::from_le_bytes([s[4], s[5]]))
    }

    /// Get the source address (u16 LE).
    pub fn src(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 6,
                need: 2,
                have: s.len().saturating_sub(6),
            });
        }
        Ok(u16::from_le_bytes([s[6], s[7]]))
    }

    /// Get the header CRC (u16 LE, bytes 8-9).
    pub fn header_crc(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 10 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 2,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(u16::from_le_bytes([s[8], s[9]]))
    }

    /// Verify the header CRC.
    pub fn verify_header_crc(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        if s.len() < 10 {
            return false;
        }
        verify_dnp3_crc(&s[..10])
    }

    // ========================================================================
    // Link Layer Setters
    // ========================================================================

    fn set_control(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let start = self.index.start;
        if start + 4 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: start + 3,
                need: 1,
                have: buf.len().saturating_sub(start + 3),
            });
        }
        buf[start + 3] = value;
        Ok(())
    }

    fn set_dst(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start;
        if start + 6 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: start + 4,
                need: 2,
                have: buf.len().saturating_sub(start + 4),
            });
        }
        let bytes = value.to_le_bytes();
        buf[start + 4] = bytes[0];
        buf[start + 5] = bytes[1];
        Ok(())
    }

    fn set_src(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let start = self.index.start;
        if start + 8 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: start + 6,
                need: 2,
                have: buf.len().saturating_sub(start + 6),
            });
        }
        let bytes = value.to_le_bytes();
        buf[start + 6] = bytes[0];
        buf[start + 7] = bytes[1];
        Ok(())
    }

    fn set_link_length(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let start = self.index.start;
        if start + 3 > buf.len() {
            return Err(FieldError::BufferTooShort {
                offset: start + 2,
                need: 1,
                have: buf.len().saturating_sub(start + 2),
            });
        }
        buf[start + 2] = value;
        Ok(())
    }

    // ========================================================================
    // User Data Extraction (strips data block CRCs)
    // ========================================================================

    /// Extract user data by stripping CRCs from the link data blocks.
    ///
    /// After the 10-byte link header, data comes in blocks of up to 18 bytes
    /// (16 data + 2 CRC). This method strips the CRCs to get raw user data.
    fn extract_user_data(&self, buf: &[u8]) -> Vec<u8> {
        let s = self.slice(buf);
        if s.len() <= 10 {
            return Vec::new();
        }
        let mut result = Vec::new();
        let mut pos = 10; // after link header + header CRC
        while pos < s.len() {
            let block_end = (pos + 16).min(s.len().saturating_sub(2));
            let data_len = block_end - pos;
            if data_len == 0 {
                break;
            }
            result.extend_from_slice(&s[pos..pos + data_len]);
            pos += data_len + 2; // skip CRC
        }
        result
    }

    // ========================================================================
    // Transport Layer Accessors
    // ========================================================================

    /// Get the raw transport header byte (first byte of user data).
    pub fn transport_header(&self, buf: &[u8]) -> Option<u8> {
        let user_data = self.extract_user_data(buf);
        user_data.first().copied()
    }

    /// Get the transport FIN (final fragment) flag.
    pub fn transport_fin(&self, buf: &[u8]) -> Option<bool> {
        self.transport_header(buf)
            .map(|b| TransportHeader::parse(b).fin)
    }

    /// Get the transport FIR (first fragment) flag.
    pub fn transport_fir(&self, buf: &[u8]) -> Option<bool> {
        self.transport_header(buf)
            .map(|b| TransportHeader::parse(b).fir)
    }

    /// Get the transport sequence number (0-63).
    pub fn transport_seq(&self, buf: &[u8]) -> Option<u8> {
        self.transport_header(buf)
            .map(|b| TransportHeader::parse(b).seq)
    }

    // ========================================================================
    // Application Layer Accessors
    // ========================================================================

    /// Get the application payload (user data after transport header).
    fn app_payload(&self, buf: &[u8]) -> Option<Vec<u8>> {
        let user_data = self.extract_user_data(buf);
        if user_data.len() >= 2 {
            // Skip transport header (1 byte)
            Some(user_data[1..].to_vec())
        } else {
            None
        }
    }

    /// Get the application control byte.
    pub fn app_control(&self, buf: &[u8]) -> Option<u8> {
        self.app_payload(buf).and_then(|p| p.first().copied())
    }

    /// Get the application FIR (first fragment) flag.
    pub fn app_fir(&self, buf: &[u8]) -> Option<bool> {
        self.app_control(buf).map(|b| AppControl::parse(b).fir)
    }

    /// Get the application FIN (final fragment) flag.
    pub fn app_fin(&self, buf: &[u8]) -> Option<bool> {
        self.app_control(buf).map(|b| AppControl::parse(b).fin)
    }

    /// Get the application CON (confirm requested) flag.
    pub fn app_con(&self, buf: &[u8]) -> Option<bool> {
        self.app_control(buf).map(|b| AppControl::parse(b).con)
    }

    /// Get the application UNS (unsolicited) flag.
    pub fn app_uns(&self, buf: &[u8]) -> Option<bool> {
        self.app_control(buf).map(|b| AppControl::parse(b).uns)
    }

    /// Get the application sequence number (0-15).
    pub fn app_seq(&self, buf: &[u8]) -> Option<u8> {
        self.app_control(buf).map(|b| AppControl::parse(b).seq)
    }

    /// Get the application function code.
    pub fn app_func(&self, buf: &[u8]) -> Option<u8> {
        self.app_payload(buf)
            .and_then(|p| if p.len() >= 2 { Some(p[1]) } else { None })
    }

    /// Get the application function name.
    pub fn app_func_name_str(&self, buf: &[u8]) -> Option<&'static str> {
        self.app_func(buf).map(app_func_name)
    }

    /// Get the IIN (Internal Indications) field.
    ///
    /// Only present in response frames (func code 0x81-0x83) when FIR=1.
    pub fn iin(&self, buf: &[u8]) -> Option<u16> {
        let payload = self.app_payload(buf)?;
        if payload.len() < 4 {
            return None;
        }
        let ac = AppControl::parse(payload[0]);
        let fc = payload[1];
        if ac.fir && is_response_func(fc) {
            Some(u16::from_le_bytes([payload[2], payload[3]]))
        } else {
            None
        }
    }

    // ========================================================================
    // Summary
    // ========================================================================

    /// Return a human-readable summary string.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let dst = self.dst(buf).unwrap_or(0);
        let src = self.src(buf).unwrap_or(0);

        if let Some(fc) = self.app_func(buf) {
            let func_name = app_func_name(fc);
            format!("DNP3 {func_name} src={src} dst={dst}")
        } else {
            let prm = self.prm(buf).unwrap_or(false);
            let lf = self.link_func(buf).unwrap_or(0);
            let lf_name = link_func_name(prm, lf);
            format!("DNP3 Link {lf_name} src={src} dst={dst}")
        }
    }

    /// Compute the header length (entire DNP3 frame within this layer).
    fn compute_header_len(&self, _buf: &[u8]) -> usize {
        self.index.end - self.index.start
    }

    // ========================================================================
    // Field Access
    // ========================================================================

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "start" => {
                let sb = self.start_bytes(buf);
                Some(Ok(FieldValue::U16(u16::from_be_bytes(sb))))
            },
            "length" => Some(self.link_length(buf).map(FieldValue::U8)),
            "control" => Some(self.control(buf).map(FieldValue::U8)),
            "dir" => Some(self.dir(buf).map(FieldValue::Bool)),
            "prm" => Some(self.prm(buf).map(FieldValue::Bool)),
            "fcb" => Some(self.fcb(buf).map(FieldValue::Bool)),
            "fcv" => Some(self.fcv(buf).map(FieldValue::Bool)),
            "link_func" => Some(self.link_func(buf).map(FieldValue::U8)),
            "dst" => Some(self.dst(buf).map(FieldValue::U16)),
            "src" => Some(self.src(buf).map(FieldValue::U16)),
            "transport_fin" => match self.transport_fin(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "transport_fir" => match self.transport_fir(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "transport_seq" => match self.transport_seq(buf) {
                Some(v) => Some(Ok(FieldValue::U8(v))),
                None => None,
            },
            "app_fir" => match self.app_fir(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "app_fin" => match self.app_fin(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "app_con" => match self.app_con(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "app_uns" => match self.app_uns(buf) {
                Some(v) => Some(Ok(FieldValue::Bool(v))),
                None => None,
            },
            "app_seq" => match self.app_seq(buf) {
                Some(v) => Some(Ok(FieldValue::U8(v))),
                None => None,
            },
            "app_func" => match self.app_func(buf) {
                Some(v) => Some(Ok(FieldValue::U8(v))),
                None => None,
            },
            "iin" => match self.iin(buf) {
                Some(v) => Some(Ok(FieldValue::U16(v))),
                None => None,
            },
            _ => None,
        }
    }

    /// Set a field value by name (link layer fields only).
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "length" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_link_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "length: expected U8, got {value:?}"
                    ))))
                }
            },
            "control" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_control(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "control: expected U8, got {value:?}"
                    ))))
                }
            },
            "dst" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_dst(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "dst: expected U16, got {value:?}"
                    ))))
                }
            },
            "src" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_src(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "src: expected U16, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for Dnp3Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dnp3
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        // Hash on src+dst addresses for flow matching
        let mut ret = Vec::with_capacity(4);
        if let Ok(dst) = self.dst(buf) {
            ret.extend_from_slice(&dst.to_le_bytes());
        }
        if let Ok(src) = self.src(buf) {
            ret.extend_from_slice(&src.to_le_bytes());
        }
        ret
    }

    fn field_names(&self) -> &'static [&'static str] {
        DNP3_FIELD_NAMES
    }
}

/// Show fields for DNP3 layer (used by `impl_layer_dispatch!`).
pub fn dnp3_show_fields(l: &Dnp3Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();

    let sb = l.start_bytes(buf);
    fields.push(("start", format!("{:#04x} {:#04x}", sb[0], sb[1])));

    fields.push((
        "length",
        l.link_length(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    fields.push((
        "control",
        l.control(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));

    fields.push((
        "dir",
        l.dir(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    fields.push((
        "prm",
        l.prm(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    fields.push((
        "fcb",
        l.fcb(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    fields.push((
        "fcv",
        l.fcv(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    let prm = l.prm(buf).unwrap_or(false);
    let lf = l.link_func(buf).unwrap_or(0);
    fields.push(("link_func", format!("{lf} ({})", link_func_name(prm, lf))));

    fields.push((
        "dst",
        l.dst(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    fields.push((
        "src",
        l.src(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    // Transport layer
    if let Some(fin) = l.transport_fin(buf) {
        fields.push(("transport_fin", fin.to_string()));
    }
    if let Some(fir) = l.transport_fir(buf) {
        fields.push(("transport_fir", fir.to_string()));
    }
    if let Some(seq) = l.transport_seq(buf) {
        fields.push(("transport_seq", seq.to_string()));
    }

    // Application layer
    if let Some(fir) = l.app_fir(buf) {
        fields.push(("app_fir", fir.to_string()));
    }
    if let Some(fin) = l.app_fin(buf) {
        fields.push(("app_fin", fin.to_string()));
    }
    if let Some(con) = l.app_con(buf) {
        fields.push(("app_con", con.to_string()));
    }
    if let Some(uns) = l.app_uns(buf) {
        fields.push(("app_uns", uns.to_string()));
    }
    if let Some(seq) = l.app_seq(buf) {
        fields.push(("app_seq", seq.to_string()));
    }
    if let Some(fc) = l.app_func(buf) {
        fields.push(("app_func", format!("{fc:#04x} ({})", app_func_name(fc))));
    }
    if let Some(iin) = l.iin(buf) {
        fields.push(("iin", format!("{iin:#06x}")));
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNP3 frame using the builder, and verify layer accessors.
    fn make_layer(buf: &[u8]) -> Dnp3Layer {
        let idx = LayerIndex::new(LayerKind::Dnp3, 0, buf.len());
        Dnp3Layer::new(idx)
    }

    #[test]
    fn test_is_dnp3_payload() {
        assert!(is_dnp3_payload(&[
            0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!is_dnp3_payload(&[
            0x05, 0x65, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!is_dnp3_payload(&[0x05, 0x64])); // too short
    }

    #[test]
    fn test_link_layer_read_request() {
        let frame = Dnp3Builder::new()
            .dir(true)
            .prm(true)
            .link_func(4)
            .dst(1)
            .src(0)
            .read()
            .build();

        let layer = make_layer(&frame);

        assert_eq!(layer.start_bytes(&frame), [0x05, 0x64]);
        assert!(layer.dir(&frame).unwrap());
        assert!(layer.prm(&frame).unwrap());
        assert_eq!(layer.link_func(&frame).unwrap(), 4);
        assert_eq!(
            layer.link_func_name(&frame).unwrap(),
            "UNCONFIRMED_USER_DATA"
        );
        assert_eq!(layer.dst(&frame).unwrap(), 1);
        assert_eq!(layer.src(&frame).unwrap(), 0);
        assert!(layer.verify_header_crc(&frame));
    }

    #[test]
    fn test_transport_layer_accessors() {
        let frame = Dnp3Builder::new()
            .transport_fir(true)
            .transport_fin(true)
            .transport_seq(5)
            .read()
            .build();

        let layer = make_layer(&frame);

        assert_eq!(layer.transport_fir(&frame), Some(true));
        assert_eq!(layer.transport_fin(&frame), Some(true));
        assert_eq!(layer.transport_seq(&frame), Some(5));
    }

    #[test]
    fn test_application_layer_read() {
        let frame = Dnp3Builder::new().app_seq(3).read().build();

        let layer = make_layer(&frame);

        assert_eq!(layer.app_func(&frame), Some(0x01));
        assert_eq!(layer.app_func_name_str(&frame), Some("READ"));
        assert_eq!(layer.app_fir(&frame), Some(true));
        assert_eq!(layer.app_fin(&frame), Some(true));
        assert_eq!(layer.app_con(&frame), Some(false));
        assert_eq!(layer.app_uns(&frame), Some(false));
        assert_eq!(layer.app_seq(&frame), Some(3));
        // READ is not a response, so no IIN
        assert_eq!(layer.iin(&frame), None);
    }

    #[test]
    fn test_application_layer_response() {
        let frame = Dnp3Builder::new().response().iin(0x8000).build();

        let layer = make_layer(&frame);

        assert_eq!(layer.app_func(&frame), Some(0x81));
        assert_eq!(layer.app_func_name_str(&frame), Some("RESPONSE"));
        assert!(layer.iin(&frame).is_some());
    }

    #[test]
    fn test_link_only_frame() {
        let frame = Dnp3Builder::new()
            .link_only()
            .link_func(9) // REQUEST_LINK_STATUS
            .build();

        let layer = make_layer(&frame);

        assert_eq!(layer.link_func(&frame).unwrap(), 9);
        assert_eq!(layer.transport_header(&frame), None);
        assert_eq!(layer.app_func(&frame), None);
    }

    #[test]
    fn test_get_field() {
        let frame = Dnp3Builder::new().dst(42).src(7).read().build();

        let layer = make_layer(&frame);

        assert_eq!(
            layer.get_field(&frame, "dst").unwrap().unwrap(),
            FieldValue::U16(42)
        );
        assert_eq!(
            layer.get_field(&frame, "src").unwrap().unwrap(),
            FieldValue::U16(7)
        );
        assert_eq!(
            layer.get_field(&frame, "dir").unwrap().unwrap(),
            FieldValue::Bool(true)
        );
        assert_eq!(
            layer.get_field(&frame, "app_func").unwrap().unwrap(),
            FieldValue::U8(0x01)
        );
        assert!(layer.get_field(&frame, "nonexistent").is_none());
    }

    #[test]
    fn test_set_field() {
        let mut frame = Dnp3Builder::new().dst(1).src(0).build();
        let layer = make_layer(&frame);

        // Set dst
        layer
            .set_field(&mut frame, "dst", FieldValue::U16(99))
            .unwrap()
            .unwrap();
        assert_eq!(layer.dst(&frame).unwrap(), 99);

        // Set src
        layer
            .set_field(&mut frame, "src", FieldValue::U16(42))
            .unwrap()
            .unwrap();
        assert_eq!(layer.src(&frame).unwrap(), 42);

        // Unknown field
        assert!(
            layer
                .set_field(&mut frame, "nonexistent", FieldValue::U8(0))
                .is_none()
        );
    }

    #[test]
    fn test_set_field_type_mismatch() {
        let mut frame = Dnp3Builder::new().build();
        let layer = make_layer(&frame);

        let result = layer
            .set_field(&mut frame, "dst", FieldValue::U8(1))
            .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_summary_with_app() {
        let frame = Dnp3Builder::new().dst(1).src(0).read().build();
        let layer = make_layer(&frame);
        let summary = layer.summary(&frame);
        assert!(summary.contains("READ"));
        assert!(summary.contains("src=0"));
        assert!(summary.contains("dst=1"));
    }

    #[test]
    fn test_summary_link_only() {
        let frame = Dnp3Builder::new().link_only().link_func(9).build();
        let layer = make_layer(&frame);
        let summary = layer.summary(&frame);
        assert!(summary.contains("Link"));
        assert!(summary.contains("REQUEST_LINK_STATUS"));
    }

    #[test]
    fn test_hashret() {
        let frame = Dnp3Builder::new().dst(1).src(2).build();
        let layer = make_layer(&frame);
        let hash = layer.hashret(&frame);
        assert_eq!(hash.len(), 4);
        // dst LE bytes + src LE bytes
        assert_eq!(hash[0..2], 1u16.to_le_bytes());
        assert_eq!(hash[2..4], 2u16.to_le_bytes());
    }

    #[test]
    fn test_field_names() {
        let layer = Dnp3Layer::new(LayerIndex::new(LayerKind::Dnp3, 0, 10));
        assert_eq!(layer.field_names(), DNP3_FIELD_NAMES);
    }

    #[test]
    fn test_show_fields() {
        let frame = Dnp3Builder::new().dst(1).src(0).read().build();
        let layer = make_layer(&frame);
        let fields = dnp3_show_fields(&layer, &frame);
        assert!(!fields.is_empty());
        // Should have at least the link layer fields
        let names: Vec<&str> = fields.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"start"));
        assert!(names.contains(&"dst"));
        assert!(names.contains(&"src"));
        assert!(names.contains(&"dir"));
    }

    #[test]
    fn test_write_confirm() {
        let frame = Dnp3Builder::new().confirm().app_seq(7).build();
        let layer = make_layer(&frame);
        assert_eq!(layer.app_func(&frame), Some(0x00));
        assert_eq!(layer.app_func_name_str(&frame), Some("CONFIRM"));
        assert_eq!(layer.app_seq(&frame), Some(7));
    }

    #[test]
    fn test_secondary_frame() {
        let frame = Dnp3Builder::new()
            .dir(false)
            .prm(false)
            .link_func(0) // ACK
            .link_only()
            .build();

        let layer = make_layer(&frame);
        assert!(!layer.prm(&frame).unwrap());
        assert_eq!(layer.link_func_name(&frame).unwrap(), "ACK");
    }

    #[test]
    fn test_objects_in_read() {
        // Class 0 data read: group 60, variation 1, qualifier 0x06
        let objects = vec![0x3C, 0x01, 0x06];
        let frame = Dnp3Builder::new().read().objects(objects).build();
        let layer = make_layer(&frame);
        assert_eq!(layer.app_func(&frame), Some(0x01));
        // Frame should be larger due to object data
        assert!(frame.len() > 15);
    }
}
