//! IEC 60870-5-104 (Telecontrol) protocol layer implementation.
//!
//! Implements IEC 60870-5-104 packet parsing as a zero-copy view into a packet
//! buffer. IEC 104 defines a TCP-based telecontrol protocol used extensively in
//! power system SCADA (Supervisory Control And Data Acquisition) networks.
//!
//! ## APCI (Application Protocol Control Information) — 6 bytes
//!
//! ```text
//! Byte 0:   Start byte (always 0x68)
//! Byte 1:   APDU Length (remaining bytes after this byte, max 253)
//! Bytes 2-5: Control field (4 bytes, format depends on type)
//! ```
//!
//! ## APDU Types
//!
//! | Type      | Detection            | Description                |
//! |-----------|----------------------|----------------------------|
//! | I-format  | byte[2] bit 0 = 0    | Information transfer       |
//! | S-format  | byte[2] bits 0-1 = 01| Supervisory (ack only)     |
//! | U-format  | byte[2] bits 0-1 = 11| Unnumbered (control)       |

pub mod asdu;
pub mod builder;
pub mod ioa;

pub use builder::Iec104Builder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

// ============================================================================
// Constants
// ============================================================================

/// Minimum header length: 6 bytes (APCI is always 6 bytes).
pub const IEC104_MIN_HEADER_LEN: usize = 6;

/// Default TCP port for IEC 60870-5-104.
pub const IEC104_PORT: u16 = 2404;

/// Start byte (always 0x68).
pub const IEC104_START_BYTE: u8 = 0x68;

/// Field names exported for Python/generic access.
pub static IEC104_FIELD_NAMES: &[&str] = &[
    "start",
    "apdu_length",
    "type",
    "tx",
    "rx",
    "u_type",
    "type_id",
    "sq",
    "num_objects",
    "cot",
    "org",
    "common_addr",
    "ioa",
];

// ============================================================================
// APDU Type enum
// ============================================================================

/// APDU format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApduType {
    /// I-format: Information transfer (carries ASDU).
    I,
    /// S-format: Supervisory (acknowledge only).
    S,
    /// U-format: Unnumbered (connection control).
    U,
}

impl std::fmt::Display for ApduType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::I => write!(f, "I"),
            Self::S => write!(f, "S"),
            Self::U => write!(f, "U"),
        }
    }
}

// ============================================================================
// Detection
// ============================================================================

/// Check whether a TCP payload looks like an IEC 60870-5-104 packet.
///
/// Validates start byte (0x68) and minimum length.
#[must_use]
pub fn is_iec104_payload(buf: &[u8]) -> bool {
    buf.len() >= IEC104_MIN_HEADER_LEN && buf[0] == IEC104_START_BYTE
}

// ============================================================================
// Type ID names
// ============================================================================

/// Return the symbolic name for an IEC 104 type identifier.
#[must_use]
pub fn type_id_name(tid: u8) -> &'static str {
    match tid {
        1 => "M_SP_NA_1",
        3 => "M_DP_NA_1",
        5 => "M_ST_NA_1",
        7 => "M_BO_NA_1",
        9 => "M_ME_NA_1",
        11 => "M_ME_NB_1",
        13 => "M_ME_NC_1",
        15 => "M_IT_NA_1",
        30 => "M_SP_TB_1",
        31 => "M_DP_TB_1",
        34 => "M_ME_TD_1",
        35 => "M_ME_TE_1",
        36 => "M_ME_TF_1",
        45 => "C_SC_NA_1",
        46 => "C_DC_NA_1",
        47 => "C_RC_NA_1",
        48 => "C_SE_NA_1",
        49 => "C_SE_NB_1",
        50 => "C_SE_NC_1",
        58 => "C_SC_TA_1",
        100 => "C_IC_NA_1",
        101 => "C_CI_NA_1",
        102 => "C_RD_NA_1",
        103 => "C_CS_NA_1",
        104 => "C_TS_NA_1",
        105 => "C_RP_NA_1",
        107 => "C_TS_TA_1",
        _ => "Unknown",
    }
}

// ============================================================================
// COT (Cause of Transmission) names
// ============================================================================

/// Return the symbolic name for a Cause of Transmission value.
#[must_use]
pub fn cot_name(cot: u8) -> &'static str {
    match cot {
        1 => "periodic/cyclic",
        2 => "background scan",
        3 => "spontaneous",
        4 => "initialized",
        5 => "request",
        6 => "activation",
        7 => "activation confirm",
        8 => "deactivation",
        9 => "deactivation confirm",
        10 => "activation termination",
        11 => "return info remote",
        12 => "return info local",
        13 => "file transfer",
        20 => "interrogated by station",
        21 => "interrogated by group 1",
        22 => "interrogated by group 2",
        23 => "interrogated by group 3",
        24 => "interrogated by group 4",
        25 => "interrogated by group 5",
        26 => "interrogated by group 6",
        27 => "interrogated by group 7",
        28 => "interrogated by group 8",
        29 => "interrogated by group 9",
        30 => "interrogated by group 10",
        31 => "interrogated by group 11",
        32 => "interrogated by group 12",
        33 => "interrogated by group 13",
        34 => "interrogated by group 14",
        35 => "interrogated by group 15",
        36 => "interrogated by group 16",
        37 => "interrogated by counter general",
        38 => "interrogated by counter group 1",
        39 => "interrogated by counter group 2",
        40 => "interrogated by counter group 3",
        41 => "interrogated by counter group 4",
        44 => "unknown type",
        45 => "unknown COT",
        46 => "unknown ASDU address",
        47 => "unknown IOA",
        _ => "reserved",
    }
}

// ============================================================================
// U-format subtype names
// ============================================================================

/// Return the symbolic name for a U-format control byte value.
#[must_use]
pub fn u_type_name(ut: u8) -> &'static str {
    match ut {
        0x07 => "STARTDT act",
        0x0B => "STARTDT con",
        0x13 => "STOPDT act",
        0x23 => "STOPDT con",
        0x43 => "TESTFR act",
        0x83 => "TESTFR con",
        _ => "Unknown",
    }
}

// ============================================================================
// Iec104Layer — zero-copy view into a packet buffer
// ============================================================================

/// IEC 60870-5-104 layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct Iec104Layer {
    pub index: LayerIndex,
}

impl Iec104Layer {
    /// Create a new IEC 104 layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create an IEC 104 layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Iec104, 0, len),
        }
    }

    /// Return a reference to the slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // APCI field accessors
    // ========================================================================

    /// Get the start byte (always 0x68).
    pub fn start(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 1,
                have: 0,
            });
        }
        Ok(s[0])
    }

    /// Get the APDU length field (byte 1).
    pub fn apdu_length(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 1,
                need: 1,
                have: s.len().saturating_sub(1),
            });
        }
        Ok(s[1])
    }

    /// Determine the APDU type from the control field.
    ///
    /// Returns `None` if the buffer is too short to determine the type.
    #[must_use]
    pub fn apdu_type(&self, buf: &[u8]) -> Option<ApduType> {
        let s = self.slice(buf);
        if s.len() < 3 {
            return None;
        }
        let b2 = s[2];
        if b2 & 0x01 == 0 {
            Some(ApduType::I)
        } else if b2 & 0x03 == 0x01 {
            Some(ApduType::S)
        } else {
            Some(ApduType::U)
        }
    }

    /// Get the APDU type as a human-readable string.
    #[must_use]
    pub fn apdu_type_name(&self, buf: &[u8]) -> &'static str {
        match self.apdu_type(buf) {
            Some(ApduType::I) => "I",
            Some(ApduType::S) => "S",
            Some(ApduType::U) => "U",
            None => "?",
        }
    }

    /// Get the send sequence number (I-format only).
    ///
    /// Extracted as `u16::from_le_bytes([byte2, byte3]) >> 1`.
    pub fn tx(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 2,
                have: s.len().saturating_sub(2),
            });
        }
        let raw = u16::from_le_bytes([s[2], s[3]]);
        Ok(raw >> 1)
    }

    /// Get the receive sequence number (I-format and S-format).
    ///
    /// Extracted from bytes 4-5 as `u16::from_le_bytes([byte4, byte5]) >> 1`.
    pub fn rx(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 4,
                need: 2,
                have: s.len().saturating_sub(4),
            });
        }
        let raw = u16::from_le_bytes([s[4], s[5]]);
        Ok(raw >> 1)
    }

    /// Get the U-format subtype byte (byte 2 of control field).
    pub fn u_type(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    // ========================================================================
    // ASDU field accessors (for I-format frames)
    // ========================================================================

    /// Check if this frame has an ASDU (I-format and enough bytes).
    #[must_use]
    pub fn has_asdu(&self, buf: &[u8]) -> bool {
        let s = self.slice(buf);
        if s.len() < IEC104_MIN_HEADER_LEN {
            return false;
        }
        // Must be I-format
        if s[2] & 0x01 != 0 {
            return false;
        }
        // Need at least APCI (6) + ASDU header (7: type_id + vsq + cot(2) + ca(2) + ioa_start(1))
        s.len() >= 13
    }

    /// Get the type identifier (byte 6, first ASDU byte).
    pub fn type_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 7 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 6,
                need: 1,
                have: s.len().saturating_sub(6),
            });
        }
        Ok(s[6])
    }

    /// Get the structure qualifier SQ bit (bit 7 of byte 7).
    ///
    /// `false` = individual addresses, `true` = sequence (single IOA, consecutive).
    pub fn sq(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 7,
                need: 1,
                have: s.len().saturating_sub(7),
            });
        }
        Ok(s[7] & 0x80 != 0)
    }

    /// Get the number of information objects (bits 0-6 of byte 7).
    pub fn num_objects(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 7,
                need: 1,
                have: s.len().saturating_sub(7),
            });
        }
        Ok(s[7] & 0x7F)
    }

    /// Get the cause of transmission (2 bytes LE, bytes 8-9).
    pub fn cot(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the COT test flag (bit 7 of byte 8).
    pub fn cot_test(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8] & 0x80 != 0)
    }

    /// Get the COT negative flag (bit 6 of byte 8).
    pub fn cot_negative(&self, buf: &[u8]) -> Result<bool, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8] & 0x40 != 0)
    }

    /// Get the COT cause value (bits 0-5 of byte 8).
    pub fn cot_cause(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8] & 0x3F)
    }

    /// Get the originator address (byte 9).
    pub fn org(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 10 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 9,
                need: 1,
                have: s.len().saturating_sub(9),
            });
        }
        Ok(s[9])
    }

    /// Get the common address (2 bytes LE, bytes 10-11).
    pub fn common_addr(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 12 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 10,
                need: 2,
                have: s.len().saturating_sub(10),
            });
        }
        Ok(u16::from_le_bytes([s[10], s[11]]))
    }

    /// Get the information object address (3 bytes LE, bytes 12-14, zero-extended to u32).
    pub fn ioa(&self, buf: &[u8]) -> Result<u32, FieldError> {
        let s = self.slice(buf);
        if s.len() < 15 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 12,
                need: 3,
                have: s.len().saturating_sub(12),
            });
        }
        Ok(u32::from(s[12]) | (u32::from(s[13]) << 8) | (u32::from(s[14]) << 16))
    }

    // ========================================================================
    // Summary
    // ========================================================================

    /// Get a human-readable summary of this IEC 104 frame.
    pub fn summary(&self, buf: &[u8]) -> String {
        let apdu_type = match self.apdu_type(buf) {
            Some(t) => t,
            None => return "IEC 104".to_string(),
        };

        match apdu_type {
            ApduType::U => {
                let ut = self.u_type(buf).unwrap_or(0);
                format!("IEC 104 U-format {}", u_type_name(ut))
            },
            ApduType::S => {
                let rx = self.rx(buf).unwrap_or(0);
                format!("IEC 104 S-format rx={rx}")
            },
            ApduType::I => {
                let tx = self.tx(buf).unwrap_or(0);
                let rx = self.rx(buf).unwrap_or(0);
                if self.has_asdu(buf) {
                    let tid = self.type_id(buf).unwrap_or(0);
                    let cause = self.cot_cause(buf).unwrap_or(0);
                    format!(
                        "IEC 104 I-format tx={tx} rx={rx} {} cot={}",
                        type_id_name(tid),
                        cot_name(cause)
                    )
                } else {
                    format!("IEC 104 I-format tx={tx} rx={rx}")
                }
            },
        }
    }

    /// Compute the header length for this layer.
    ///
    /// For IEC 104, the full APDU is: 2 (start + length) + length field value.
    /// But the APCI header is always 6 bytes.
    pub fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        if s.len() < 2 {
            return IEC104_MIN_HEADER_LEN;
        }
        // Total frame: start(1) + length_field(1) + apdu_length
        let total = 2 + usize::from(s[1]);
        total.min(s.len())
    }

    // ========================================================================
    // APCI set helpers (in-place mutation)
    // ========================================================================

    /// Set the send sequence number in-place (I-format, bytes 2-3).
    pub fn set_tx(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        let start = self.index.start;
        if buf.len() < start + 4 {
            return Err(FieldError::BufferTooShort {
                offset: start + 2,
                need: 2,
                have: buf.len().saturating_sub(start + 2),
            });
        }
        let shifted = val << 1;
        let bytes = shifted.to_le_bytes();
        buf[start + 2] = bytes[0];
        buf[start + 3] = bytes[1];
        Ok(())
    }

    /// Set the receive sequence number in-place (bytes 4-5).
    pub fn set_rx(&self, buf: &mut [u8], val: u16) -> Result<(), FieldError> {
        let start = self.index.start;
        if buf.len() < start + 6 {
            return Err(FieldError::BufferTooShort {
                offset: start + 4,
                need: 2,
                have: buf.len().saturating_sub(start + 4),
            });
        }
        let shifted = val << 1;
        let bytes = shifted.to_le_bytes();
        buf[start + 4] = bytes[0];
        buf[start + 5] = bytes[1];
        Ok(())
    }

    // ========================================================================
    // get_field / set_field
    // ========================================================================

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "start" => Some(self.start(buf).map(FieldValue::U8)),
            "apdu_length" => Some(self.apdu_length(buf).map(FieldValue::U8)),
            "type" => {
                let name = self.apdu_type_name(buf);
                Some(Ok(FieldValue::Str(name.to_string())))
            },
            "tx" => {
                // Only meaningful for I-format
                match self.apdu_type(buf) {
                    Some(ApduType::I) => Some(self.tx(buf).map(FieldValue::U16)),
                    _ => None,
                }
            },
            "rx" => {
                // Meaningful for I-format and S-format
                match self.apdu_type(buf) {
                    Some(ApduType::I) | Some(ApduType::S) => {
                        Some(self.rx(buf).map(FieldValue::U16))
                    },
                    _ => None,
                }
            },
            "u_type" => match self.apdu_type(buf) {
                Some(ApduType::U) => Some(self.u_type(buf).map(FieldValue::U8)),
                _ => None,
            },
            "type_id" => {
                if self.has_asdu(buf) {
                    Some(self.type_id(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "sq" => {
                if self.has_asdu(buf) {
                    Some(self.sq(buf).map(FieldValue::Bool))
                } else {
                    None
                }
            },
            "num_objects" => {
                if self.has_asdu(buf) {
                    Some(self.num_objects(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "cot" => {
                if self.has_asdu(buf) {
                    Some(self.cot(buf).map(FieldValue::U16))
                } else {
                    None
                }
            },
            "org" => {
                if self.has_asdu(buf) {
                    Some(self.org(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "common_addr" => {
                if self.has_asdu(buf) {
                    Some(self.common_addr(buf).map(FieldValue::U16))
                } else {
                    None
                }
            },
            "ioa" => {
                if self.has_asdu(buf) {
                    Some(self.ioa(buf).map(FieldValue::U32))
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    /// Set a field value by name (in-place mutation for APCI fields).
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "tx" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_tx(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "tx: expected U16, got {value:?}"
                    ))))
                }
            },
            "rx" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_rx(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "rx: expected U16, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

// ============================================================================
// Layer trait implementation
// ============================================================================

impl Layer for Iec104Layer {
    fn kind(&self) -> LayerKind {
        LayerKind::Iec104
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        IEC104_FIELD_NAMES
    }
}

// ============================================================================
// Show fields (for display / Python integration)
// ============================================================================

/// Generate show-fields output for an IEC 104 layer.
pub fn iec104_show_fields(l: &Iec104Layer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();

    fields.push((
        "start",
        l.start(buf)
            .map_or_else(|_| "?".into(), |v| format!("{v:#04x}")),
    ));
    fields.push((
        "apdu_length",
        l.apdu_length(buf)
            .map_or_else(|_| "?".into(), |v| v.to_string()),
    ));

    let apdu_type = match l.apdu_type(buf) {
        Some(t) => t,
        None => {
            fields.push(("type", "?".into()));
            return fields;
        },
    };
    fields.push(("type", apdu_type.to_string()));

    match apdu_type {
        ApduType::I => {
            fields.push((
                "tx",
                l.tx(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
            ));
            fields.push((
                "rx",
                l.rx(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
            ));

            if l.has_asdu(buf) {
                let tid = l.type_id(buf).unwrap_or(0);
                fields.push(("type_id", format!("{tid} ({})", type_id_name(tid))));
                fields.push((
                    "sq",
                    l.sq(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
                ));
                fields.push((
                    "num_objects",
                    l.num_objects(buf)
                        .map_or_else(|_| "?".into(), |v| v.to_string()),
                ));
                let cause = l.cot_cause(buf).unwrap_or(0);
                fields.push(("cot", format!("{cause} ({})", cot_name(cause))));
                fields.push((
                    "org",
                    l.org(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
                ));
                fields.push((
                    "common_addr",
                    l.common_addr(buf)
                        .map_or_else(|_| "?".into(), |v| v.to_string()),
                ));
                fields.push((
                    "ioa",
                    l.ioa(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
                ));
            }
        },
        ApduType::S => {
            fields.push((
                "rx",
                l.rx(buf).map_or_else(|_| "?".into(), |v| v.to_string()),
            ));
        },
        ApduType::U => {
            let ut = l.u_type(buf).unwrap_or(0);
            fields.push(("u_type", format!("{ut:#04x} ({})", u_type_name(ut))));
        },
    }

    fields
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer(buf: &[u8]) -> Iec104Layer {
        let idx = LayerIndex::new(LayerKind::Iec104, 0, buf.len());
        Iec104Layer::new(idx)
    }

    // ---- Detection ----

    #[test]
    fn test_is_iec104_payload() {
        assert!(is_iec104_payload(&[0x68, 0x04, 0x07, 0x00, 0x00, 0x00]));
        assert!(!is_iec104_payload(&[0x67, 0x04, 0x07, 0x00, 0x00, 0x00]));
        assert!(!is_iec104_payload(&[0x68, 0x04, 0x07])); // too short
        assert!(!is_iec104_payload(&[]));
    }

    // ---- U-format ----

    #[test]
    fn test_u_format_startdt_act() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        assert_eq!(l.start(&buf).unwrap(), 0x68);
        assert_eq!(l.apdu_length(&buf).unwrap(), 0x04);
        assert_eq!(l.apdu_type(&buf), Some(ApduType::U));
        assert_eq!(l.u_type(&buf).unwrap(), 0x07);
        assert_eq!(u_type_name(0x07), "STARTDT act");
    }

    #[test]
    fn test_u_format_testfr_con() {
        let buf = [0x68, 0x04, 0x83, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        assert_eq!(l.apdu_type(&buf), Some(ApduType::U));
        assert_eq!(l.u_type(&buf).unwrap(), 0x83);
        assert_eq!(u_type_name(0x83), "TESTFR con");
    }

    // ---- S-format ----

    #[test]
    fn test_s_format() {
        let buf = [0x68, 0x04, 0x01, 0x00, 0x0A, 0x00];
        let l = make_layer(&buf);
        assert_eq!(l.apdu_type(&buf), Some(ApduType::S));
        // RSN: 0x000A >> 1 = 5
        assert_eq!(l.rx(&buf).unwrap(), 5);
        assert!(!l.has_asdu(&buf));
    }

    // ---- I-format ----

    #[test]
    fn test_i_format_interrogation_command() {
        // I-format: tx=0, rx=0, C_IC_NA_1 (100), activation, CA=1, IOA=0, QOI=20
        let buf = [
            0x68, 0x0E, // start, length=14
            0x00, 0x00, // tx=0 (0<<1)
            0x00, 0x00, // rx=0 (0<<1)
            100,  // type_id = C_IC_NA_1
            0x01, // VSQ: SQ=0, num=1
            0x06, 0x00, // COT: activation (6), ORG=0
            0x01, 0x00, // Common addr = 1
            0x00, 0x00, 0x00, // IOA = 0
            0x14, // QOI = 20
        ];
        let l = make_layer(&buf);

        assert_eq!(l.apdu_type(&buf), Some(ApduType::I));
        assert_eq!(l.tx(&buf).unwrap(), 0);
        assert_eq!(l.rx(&buf).unwrap(), 0);
        assert!(l.has_asdu(&buf));
        assert_eq!(l.type_id(&buf).unwrap(), 100);
        assert_eq!(type_id_name(100), "C_IC_NA_1");
        assert!(!l.sq(&buf).unwrap());
        assert_eq!(l.num_objects(&buf).unwrap(), 1);
        assert_eq!(l.cot_cause(&buf).unwrap(), 6);
        assert!(!l.cot_test(&buf).unwrap());
        assert!(!l.cot_negative(&buf).unwrap());
        assert_eq!(l.org(&buf).unwrap(), 0);
        assert_eq!(l.common_addr(&buf).unwrap(), 1);
        assert_eq!(l.ioa(&buf).unwrap(), 0);
    }

    #[test]
    fn test_i_format_sequence_numbers() {
        // tx=100 → shifted=200=0x00C8, rx=50 → shifted=100=0x0064
        let buf = [
            0x68, 0x0E, 0xC8, 0x00, // tx=100
            0x64, 0x00, // rx=50
            1,    // type_id
            0x01, // VSQ
            0x03, 0x00, // COT
            0x01, 0x00, // CA
            0x01, 0x00, 0x00, // IOA=1
            0x01, // SIQ
        ];
        let l = make_layer(&buf);
        assert_eq!(l.tx(&buf).unwrap(), 100);
        assert_eq!(l.rx(&buf).unwrap(), 50);
    }

    #[test]
    fn test_i_format_cot_flags() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 45, // C_SC_NA_1
            0x01, 0xC7, 0x00, // COT: test=1, neg=1, cause=7
            0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
        ];
        let l = make_layer(&buf);
        assert!(l.cot_test(&buf).unwrap());
        assert!(l.cot_negative(&buf).unwrap());
        assert_eq!(l.cot_cause(&buf).unwrap(), 7);
    }

    #[test]
    fn test_ioa_3_byte() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 1, 0x01, 0x03, 0x00, 0x01, 0x00, 0x03, 0x02,
            0x01, // IOA = 0x010203
            0x01,
        ];
        let l = make_layer(&buf);
        assert_eq!(l.ioa(&buf).unwrap(), 0x010203);
    }

    // ---- get_field ----

    #[test]
    fn test_get_field_u_format() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        assert_eq!(l.get_field(&buf, "start"), Some(Ok(FieldValue::U8(0x68))));
        assert_eq!(
            l.get_field(&buf, "apdu_length"),
            Some(Ok(FieldValue::U8(0x04)))
        );
        assert_eq!(
            l.get_field(&buf, "type"),
            Some(Ok(FieldValue::Str("U".into())))
        );
        assert_eq!(l.get_field(&buf, "u_type"), Some(Ok(FieldValue::U8(0x07))));
        // tx/rx not available for U-format
        assert!(l.get_field(&buf, "tx").is_none());
        assert!(l.get_field(&buf, "rx").is_none());
        // ASDU fields not available
        assert!(l.get_field(&buf, "type_id").is_none());
    }

    #[test]
    fn test_get_field_s_format() {
        let buf = [0x68, 0x04, 0x01, 0x00, 0x0A, 0x00];
        let l = make_layer(&buf);
        assert_eq!(
            l.get_field(&buf, "type"),
            Some(Ok(FieldValue::Str("S".into())))
        );
        assert_eq!(l.get_field(&buf, "rx"), Some(Ok(FieldValue::U16(5))));
        assert!(l.get_field(&buf, "tx").is_none());
    }

    #[test]
    fn test_get_field_i_format() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];
        let l = make_layer(&buf);
        assert_eq!(
            l.get_field(&buf, "type"),
            Some(Ok(FieldValue::Str("I".into())))
        );
        assert_eq!(l.get_field(&buf, "tx"), Some(Ok(FieldValue::U16(0))));
        assert_eq!(l.get_field(&buf, "rx"), Some(Ok(FieldValue::U16(0))));
        assert_eq!(l.get_field(&buf, "type_id"), Some(Ok(FieldValue::U8(100))));
        assert_eq!(
            l.get_field(&buf, "common_addr"),
            Some(Ok(FieldValue::U16(1)))
        );
        assert_eq!(l.get_field(&buf, "ioa"), Some(Ok(FieldValue::U32(0))));
    }

    // ---- set_field ----

    #[test]
    fn test_set_field_tx_rx() {
        let mut buf = [0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);

        let result = l.set_field(&mut buf, "tx", FieldValue::U16(42));
        assert!(result.unwrap().is_ok());
        assert_eq!(l.tx(&buf).unwrap(), 42);

        let result = l.set_field(&mut buf, "rx", FieldValue::U16(99));
        assert!(result.unwrap().is_ok());
        assert_eq!(l.rx(&buf).unwrap(), 99);
    }

    #[test]
    fn test_set_field_wrong_type() {
        let mut buf = [0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        let result = l.set_field(&mut buf, "tx", FieldValue::U8(1));
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_set_field_unknown() {
        let mut buf = [0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        assert!(
            l.set_field(&mut buf, "unknown", FieldValue::U8(0))
                .is_none()
        );
    }

    // ---- Summary ----

    #[test]
    fn test_summary_u_format() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        let s = l.summary(&buf);
        assert!(s.contains("U-format"));
        assert!(s.contains("STARTDT act"));
    }

    #[test]
    fn test_summary_s_format() {
        let buf = [0x68, 0x04, 0x01, 0x00, 0x0A, 0x00];
        let l = make_layer(&buf);
        let s = l.summary(&buf);
        assert!(s.contains("S-format"));
        assert!(s.contains("rx=5"));
    }

    #[test]
    fn test_summary_i_format_with_asdu() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];
        let l = make_layer(&buf);
        let s = l.summary(&buf);
        assert!(s.contains("I-format"));
        assert!(s.contains("C_IC_NA_1"));
        assert!(s.contains("activation"));
    }

    // ---- header_len ----

    #[test]
    fn test_header_len_u_format() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        assert_eq!(l.compute_header_len(&buf), 6);
    }

    #[test]
    fn test_header_len_i_format() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];
        let l = make_layer(&buf);
        // 2 + 14 = 16
        assert_eq!(l.compute_header_len(&buf), 16);
    }

    // ---- type_id_name and cot_name ----

    #[test]
    fn test_type_id_names() {
        assert_eq!(type_id_name(1), "M_SP_NA_1");
        assert_eq!(type_id_name(45), "C_SC_NA_1");
        assert_eq!(type_id_name(100), "C_IC_NA_1");
        assert_eq!(type_id_name(255), "Unknown");
    }

    #[test]
    fn test_cot_names() {
        assert_eq!(cot_name(1), "periodic/cyclic");
        assert_eq!(cot_name(3), "spontaneous");
        assert_eq!(cot_name(6), "activation");
        assert_eq!(cot_name(20), "interrogated by station");
        assert_eq!(cot_name(44), "unknown type");
        assert_eq!(cot_name(0), "reserved");
    }

    // ---- at_start ----

    #[test]
    fn test_at_start() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = Iec104Layer::at_start(buf.len());
        assert_eq!(l.index.start, 0);
        assert_eq!(l.index.end, 6);
        assert_eq!(l.apdu_type(&buf), Some(ApduType::U));
    }

    // ---- show_fields ----

    #[test]
    fn test_show_fields_u_format() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let l = make_layer(&buf);
        let fields = iec104_show_fields(&l, &buf);
        assert!(fields.iter().any(|(n, _)| *n == "start"));
        assert!(fields.iter().any(|(n, _)| *n == "type"));
        assert!(fields.iter().any(|(n, _)| *n == "u_type"));
    }

    #[test]
    fn test_show_fields_i_format() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];
        let l = make_layer(&buf);
        let fields = iec104_show_fields(&l, &buf);
        assert!(fields.iter().any(|(n, _)| *n == "type_id"));
        assert!(fields.iter().any(|(n, _)| *n == "cot"));
        assert!(fields.iter().any(|(n, _)| *n == "ioa"));
    }

    // ---- SQ flag ----

    #[test]
    fn test_sq_flag() {
        let buf = [
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, 1,    // type_id
            0x8A, // VSQ: SQ=1, num=10
            0x14, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, // IOA=100
            0x01,
        ];
        let l = make_layer(&buf);
        assert!(l.sq(&buf).unwrap());
        assert_eq!(l.num_objects(&buf).unwrap(), 10);
    }

    // ---- Builder roundtrip ----

    #[test]
    fn test_builder_roundtrip_u_format() {
        let pkt = builder::Iec104Builder::new().testfr_act().build();
        let l = Iec104Layer::at_start(pkt.len());
        assert_eq!(l.apdu_type(&pkt).unwrap(), ApduType::U);
        assert_eq!(l.u_type(&pkt).unwrap(), 0x43);
    }

    #[test]
    fn test_builder_roundtrip_i_format() {
        let pkt = builder::Iec104Builder::new()
            .i_format()
            .tx(42)
            .rx(21)
            .type_id(100)
            .num_objects(1)
            .cot(6)
            .common_addr(1)
            .ioa(500)
            .asdu_data(vec![20])
            .build();
        let l = Iec104Layer::at_start(pkt.len());
        assert_eq!(l.apdu_type(&pkt).unwrap(), ApduType::I);
        assert_eq!(l.tx(&pkt).unwrap(), 42);
        assert_eq!(l.rx(&pkt).unwrap(), 21);
        assert_eq!(l.type_id(&pkt).unwrap(), 100);
        assert_eq!(l.num_objects(&pkt).unwrap(), 1);
        assert_eq!(l.cot_cause(&pkt).unwrap(), 6);
        assert_eq!(l.common_addr(&pkt).unwrap(), 1);
        assert_eq!(l.ioa(&pkt).unwrap(), 500);
    }
}
