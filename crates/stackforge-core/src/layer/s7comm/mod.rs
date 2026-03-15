//! S7 Communication Protocol (Siemens S7) layer implementation.
//!
//! S7comm is the proprietary protocol used for communication with Siemens S7
//! PLCs (Programmable Logic Controllers). It sits on top of COTP/TPKT in the
//! ISO-on-TCP protocol stack.
//!
//! ## Header Format
//!
//! ```text
//! Byte 0:    Protocol ID (always 0x32)
//! Byte 1:    ROSCTR (message type)
//! Bytes 2-3: Reserved (always 0x0000)
//! Bytes 4-5: PDU Reference (u16 BE)
//! Bytes 6-7: Parameter Length (u16 BE)
//! Bytes 8-9: Data Length (u16 BE)
//! ```
//!
//! For `Ack_Data` (ROSCTR=0x03), 2 extra bytes follow the base header:
//! ```text
//! Byte 10: Error Class
//! Byte 11: Error Code
//! ```

pub mod builder;

pub use builder::S7CommBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum S7comm header length (base header without error fields).
pub const S7COMM_MIN_HEADER_LEN: usize = 10;

/// S7comm protocol ID magic byte.
pub const S7COMM_MAGIC: u8 = 0x32;

/// Field names exported for Python/generic access.
pub static S7COMM_FIELD_NAMES: &[&str] = &[
    "protocol_id",
    "rosctr",
    "reserved",
    "pdu_ref",
    "param_length",
    "data_length",
    "error_class",
    "error_code",
    "function",
    "item_count",
];

/// ROSCTR (message type) constants.
pub mod rosctr {
    /// Job request
    pub const JOB: u8 = 0x01;
    /// Acknowledgement without data
    pub const ACK: u8 = 0x02;
    /// Acknowledgement with data
    pub const ACK_DATA: u8 = 0x03;
    /// Userdata (extensions)
    pub const USERDATA: u8 = 0x07;

    /// Get a human-readable name for a ROSCTR value.
    #[must_use]
    pub fn name(r: u8) -> &'static str {
        match r {
            JOB => "Job",
            ACK => "Ack",
            ACK_DATA => "Ack_Data",
            USERDATA => "Userdata",
            _ => "Unknown",
        }
    }
}

/// Function code constants (first byte of the parameter area).
pub mod function {
    /// CPU Services
    pub const CPU_SERVICES: u8 = 0x00;
    /// Setup Communication
    pub const SETUP_COMMUNICATION: u8 = 0xF0;
    /// Read Variable
    pub const READ_VAR: u8 = 0x04;
    /// Write Variable
    pub const WRITE_VAR: u8 = 0x05;
    /// Request Download
    pub const REQUEST_DOWNLOAD: u8 = 0x1A;
    /// Download Block
    pub const DOWNLOAD_BLOCK: u8 = 0x1B;
    /// Download Ended
    pub const DOWNLOAD_ENDED: u8 = 0x1C;
    /// Start Upload
    pub const START_UPLOAD: u8 = 0x1D;
    /// Upload
    pub const UPLOAD: u8 = 0x1E;
    /// End Upload
    pub const END_UPLOAD: u8 = 0x1F;
    /// PLC Control
    pub const PLC_CONTROL: u8 = 0x28;
    /// PLC Stop
    pub const PLC_STOP: u8 = 0x29;

    /// Get a human-readable name for a function code.
    #[must_use]
    pub fn name(f: u8) -> &'static str {
        match f {
            CPU_SERVICES => "CPU Services",
            SETUP_COMMUNICATION => "Setup Communication",
            READ_VAR => "Read Var",
            WRITE_VAR => "Write Var",
            REQUEST_DOWNLOAD => "Request Download",
            DOWNLOAD_BLOCK => "Download Block",
            DOWNLOAD_ENDED => "Download Ended",
            START_UPLOAD => "Start Upload",
            UPLOAD => "Upload",
            END_UPLOAD => "End Upload",
            PLC_CONTROL => "PLC Control",
            PLC_STOP => "PLC Stop",
            _ => "Unknown",
        }
    }
}

/// Convenience function: get human-readable name for a ROSCTR value.
#[inline]
#[must_use]
pub fn rosctr_name(r: u8) -> &'static str {
    rosctr::name(r)
}

/// Convenience function: get human-readable name for a function code.
#[inline]
#[must_use]
pub fn function_name(f: u8) -> &'static str {
    function::name(f)
}

/// Check if a buffer looks like an S7comm payload.
///
/// Checks for the magic byte (0x32) and minimum length.
#[inline]
#[must_use]
pub fn is_s7comm_payload(buf: &[u8]) -> bool {
    buf.len() >= S7COMM_MIN_HEADER_LEN && buf[0] == S7COMM_MAGIC
}

/// S7comm layer -- a zero-copy view into a packet buffer.
#[derive(Debug, Clone)]
pub struct S7CommLayer {
    pub index: LayerIndex,
}

impl S7CommLayer {
    /// Create a new S7comm layer from a layer index.
    #[must_use]
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    /// Create an S7comm layer starting at offset 0 (for standalone parsing).
    #[must_use]
    pub fn at_start() -> Self {
        Self {
            index: LayerIndex::new(LayerKind::S7Comm, 0, S7COMM_MIN_HEADER_LEN),
        }
    }

    /// Return a reference to a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // Field accessors (base header)
    // ========================================================================

    /// Get the Protocol ID (byte 0, should always be 0x32).
    pub fn protocol_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    /// Get the ROSCTR (message type, byte 1).
    pub fn rosctr(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    /// Get the human-readable ROSCTR name.
    pub fn rosctr_name(&self, buf: &[u8]) -> &'static str {
        self.rosctr(buf).map(rosctr::name).unwrap_or("Unknown")
    }

    /// Get the reserved field (bytes 2-3, should be 0x0000).
    pub fn reserved(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 2,
                need: 2,
                have: s.len().saturating_sub(2),
            });
        }
        Ok(u16::from_be_bytes([s[2], s[3]]))
    }

    /// Get the PDU Reference (bytes 4-5).
    pub fn pdu_ref(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 4,
                need: 2,
                have: s.len().saturating_sub(4),
            });
        }
        Ok(u16::from_be_bytes([s[4], s[5]]))
    }

    /// Get the Parameter Length (bytes 6-7).
    pub fn param_length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 6,
                need: 2,
                have: s.len().saturating_sub(6),
            });
        }
        Ok(u16::from_be_bytes([s[6], s[7]]))
    }

    /// Get the Data Length (bytes 8-9).
    pub fn data_length(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 10 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 2,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(u16::from_be_bytes([s[8], s[9]]))
    }

    // ========================================================================
    // Ack_Data error fields (only for ROSCTR=0x03)
    // ========================================================================

    /// Get the Error Class (byte 10, only valid for Ack_Data messages).
    pub fn error_class(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 11 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 10,
                need: 1,
                have: s.len().saturating_sub(10),
            });
        }
        Ok(s[10])
    }

    /// Get the Error Code (byte 11, only valid for Ack_Data messages).
    pub fn error_code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 12 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 11,
                need: 1,
                have: s.len().saturating_sub(11),
            });
        }
        Ok(s[11])
    }

    // ========================================================================
    // Parameter area accessors
    // ========================================================================

    /// Get the offset of the parameter area within the full buffer.
    fn param_area_offset(&self, buf: &[u8]) -> usize {
        let base = self.index.start;
        if self.is_ack_data(buf) {
            base + 12 // base header (10) + error fields (2)
        } else {
            base + 10 // base header only
        }
    }

    /// Get the function code (first byte of the parameter area).
    pub fn function(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.param_area_offset(buf);
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        Ok(buf[off])
    }

    /// Get the human-readable function name.
    pub fn function_name(&self, buf: &[u8]) -> &'static str {
        self.function(buf).map(function::name).unwrap_or("Unknown")
    }

    /// Get the item count (second byte of the parameter area, for Read/Write).
    pub fn item_count(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let off = self.param_area_offset(buf) + 1;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        Ok(buf[off])
    }

    // ========================================================================
    // Type checks
    // ========================================================================

    /// Check if this is a Job message.
    pub fn is_job(&self, buf: &[u8]) -> bool {
        self.rosctr(buf).map(|r| r == rosctr::JOB).unwrap_or(false)
    }

    /// Check if this is an Ack message.
    pub fn is_ack(&self, buf: &[u8]) -> bool {
        self.rosctr(buf).map(|r| r == rosctr::ACK).unwrap_or(false)
    }

    /// Check if this is an Ack_Data message.
    pub fn is_ack_data(&self, buf: &[u8]) -> bool {
        self.rosctr(buf)
            .map(|r| r == rosctr::ACK_DATA)
            .unwrap_or(false)
    }

    /// Check if this is a Userdata message.
    pub fn is_userdata(&self, buf: &[u8]) -> bool {
        self.rosctr(buf)
            .map(|r| r == rosctr::USERDATA)
            .unwrap_or(false)
    }

    // ========================================================================
    // Field writers
    // ========================================================================

    /// Set the ROSCTR field.
    pub fn set_rosctr(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 1;
        if buf.len() <= off {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the PDU Reference.
    pub fn set_pdu_ref(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 4;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the Parameter Length.
    pub fn set_param_length(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 6;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Set the Data Length.
    pub fn set_data_length(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 8;
        if buf.len() < off + 2 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 2,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // ========================================================================
    // Header length computation
    // ========================================================================

    /// Compute the total header length.
    ///
    /// The base header is 10 bytes. For Ack_Data (ROSCTR=0x03), there are
    /// 2 additional bytes (error_class + error_code), making it 12 bytes.
    fn compute_header_len(&self, buf: &[u8]) -> usize {
        if self.is_ack_data(buf) { 12 } else { 10 }
    }

    // ========================================================================
    // Summary / display
    // ========================================================================

    /// Generate a one-line summary of this S7comm layer.
    #[must_use]
    pub fn summary(&self, buf: &[u8]) -> String {
        let rosctr_name = self.rosctr_name(buf);
        let pdu_ref = self
            .pdu_ref(buf)
            .map_or_else(|_| "?".to_string(), |v| format!("{v:#06x}"));
        let func = self.function(buf).map(function::name).unwrap_or("?");

        if self.is_ack_data(buf) {
            let ec = self
                .error_class(buf)
                .map_or_else(|_| "?".to_string(), |v| format!("{v:#04x}"));
            format!("S7comm {rosctr_name} pdu_ref={pdu_ref} func={func} error_class={ec}")
        } else {
            format!("S7comm {rosctr_name} pdu_ref={pdu_ref} func={func}")
        }
    }

    // ========================================================================
    // Field access API
    // ========================================================================

    /// Get the field names for this layer.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        S7COMM_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "protocol_id" => Some(self.protocol_id(buf).map(FieldValue::U8)),
            "rosctr" => Some(self.rosctr(buf).map(FieldValue::U8)),
            "reserved" => Some(self.reserved(buf).map(FieldValue::U16)),
            "pdu_ref" => Some(self.pdu_ref(buf).map(FieldValue::U16)),
            "param_length" => Some(self.param_length(buf).map(FieldValue::U16)),
            "data_length" => Some(self.data_length(buf).map(FieldValue::U16)),
            "error_class" => {
                if self.is_ack_data(buf) {
                    Some(self.error_class(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "error_code" => {
                if self.is_ack_data(buf) {
                    Some(self.error_code(buf).map(FieldValue::U8))
                } else {
                    None
                }
            },
            "function" => Some(self.function(buf).map(FieldValue::U8)),
            "item_count" => Some(self.item_count(buf).map(FieldValue::U8)),
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
            "rosctr" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_rosctr(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "rosctr: expected U8, got {value:?}"
                    ))))
                }
            },
            "pdu_ref" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_pdu_ref(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "pdu_ref: expected U16, got {value:?}"
                    ))))
                }
            },
            "param_length" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_param_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "param_length: expected U16, got {value:?}"
                    ))))
                }
            },
            "data_length" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_data_length(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "data_length: expected U16, got {value:?}"
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for S7CommLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::S7Comm
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        S7COMM_FIELD_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Job/Setup Communication packet:
    /// Header(10) + Param(8): function=0xF0, reserved=0, max_amq_calling=1,
    /// max_amq_called=1, pdu_length=480
    fn job_setup_comm() -> Vec<u8> {
        vec![
            0x32, // protocol_id
            0x01, // rosctr = Job
            0x00, 0x00, // reserved
            0x00, 0x01, // pdu_ref = 1
            0x00, 0x08, // param_length = 8
            0x00, 0x00, // data_length = 0
            // Parameter area:
            0xF0, // function = Setup Communication
            0x00, // reserved
            0x00, 0x01, // max_amq_calling = 1
            0x00, 0x01, // max_amq_called = 1
            0x01, 0xE0, // pdu_length = 480
        ]
    }

    /// Build an Ack_Data packet (ROSCTR=0x03, has error fields).
    fn ack_data_setup_comm() -> Vec<u8> {
        vec![
            0x32, // protocol_id
            0x03, // rosctr = Ack_Data
            0x00, 0x00, // reserved
            0x00, 0x01, // pdu_ref = 1
            0x00, 0x08, // param_length = 8
            0x00, 0x00, // data_length = 0
            0x00, // error_class = 0 (no error)
            0x00, // error_code = 0
            // Parameter area:
            0xF0, // function = Setup Communication
            0x00, // reserved
            0x00, 0x01, // max_amq_calling
            0x00, 0x01, // max_amq_called
            0x01, 0xE0, // pdu_length = 480
        ]
    }

    /// Build a Job/Read Var packet.
    fn job_read_var() -> Vec<u8> {
        vec![
            0x32, // protocol_id
            0x01, // rosctr = Job
            0x00, 0x00, // reserved
            0x00, 0x02, // pdu_ref = 2
            0x00, 0x0E, // param_length = 14
            0x00, 0x00, // data_length = 0
            // Parameter area:
            0x04, // function = Read Var
            0x01, // item_count = 1
            // Item specification follows (12 bytes)
            0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn test_is_s7comm_payload() {
        assert!(is_s7comm_payload(&job_setup_comm()));
        assert!(!is_s7comm_payload(&[
            0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!is_s7comm_payload(&[0x32])); // too short
    }

    #[test]
    fn test_job_setup_fields() {
        let buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(s7.protocol_id(&buf).unwrap(), 0x32);
        assert_eq!(s7.rosctr(&buf).unwrap(), 0x01);
        assert!(s7.is_job(&buf));
        assert!(!s7.is_ack_data(&buf));
        assert_eq!(s7.reserved(&buf).unwrap(), 0);
        assert_eq!(s7.pdu_ref(&buf).unwrap(), 1);
        assert_eq!(s7.param_length(&buf).unwrap(), 8);
        assert_eq!(s7.data_length(&buf).unwrap(), 0);
        assert_eq!(s7.function(&buf).unwrap(), 0xF0);
        assert_eq!(s7.function_name(&buf), "Setup Communication");
    }

    #[test]
    fn test_ack_data_fields() {
        let buf = ack_data_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert!(s7.is_ack_data(&buf));
        assert_eq!(s7.rosctr_name(&buf), "Ack_Data");
        assert_eq!(s7.error_class(&buf).unwrap(), 0);
        assert_eq!(s7.error_code(&buf).unwrap(), 0);
        assert_eq!(s7.function(&buf).unwrap(), 0xF0);
    }

    #[test]
    fn test_job_header_len() {
        let buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(s7.compute_header_len(&buf), 10);
    }

    #[test]
    fn test_ack_data_header_len() {
        let buf = ack_data_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(s7.compute_header_len(&buf), 12);
    }

    #[test]
    fn test_read_var() {
        let buf = job_read_var();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(s7.function(&buf).unwrap(), 0x04);
        assert_eq!(s7.function_name(&buf), "Read Var");
        assert_eq!(s7.item_count(&buf).unwrap(), 1);
        assert_eq!(s7.pdu_ref(&buf).unwrap(), 2);
    }

    #[test]
    fn test_get_field() {
        let buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(
            s7.get_field(&buf, "protocol_id").unwrap().unwrap(),
            FieldValue::U8(0x32)
        );
        assert_eq!(
            s7.get_field(&buf, "rosctr").unwrap().unwrap(),
            FieldValue::U8(0x01)
        );
        assert_eq!(
            s7.get_field(&buf, "pdu_ref").unwrap().unwrap(),
            FieldValue::U16(1)
        );
        assert_eq!(
            s7.get_field(&buf, "function").unwrap().unwrap(),
            FieldValue::U8(0xF0)
        );
        // error_class not available for Job
        assert!(s7.get_field(&buf, "error_class").is_none());
        assert!(s7.get_field(&buf, "nonexistent").is_none());
    }

    #[test]
    fn test_get_field_ack_data_errors() {
        let buf = ack_data_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        assert_eq!(
            s7.get_field(&buf, "error_class").unwrap().unwrap(),
            FieldValue::U8(0)
        );
        assert_eq!(
            s7.get_field(&buf, "error_code").unwrap().unwrap(),
            FieldValue::U8(0)
        );
    }

    #[test]
    fn test_set_fields() {
        let mut buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        s7.set_pdu_ref(&mut buf, 42).unwrap();
        assert_eq!(s7.pdu_ref(&buf).unwrap(), 42);

        s7.set_rosctr(&mut buf, 0x03).unwrap();
        assert_eq!(s7.rosctr(&buf).unwrap(), 0x03);
    }

    #[test]
    fn test_summary_job() {
        let buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        let s = s7.summary(&buf);
        assert!(s.contains("Job"));
        assert!(s.contains("Setup Communication"));
    }

    #[test]
    fn test_summary_ack_data() {
        let buf = ack_data_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, buf.len());
        let s7 = S7CommLayer::new(idx);

        let s = s7.summary(&buf);
        assert!(s.contains("Ack_Data"));
        assert!(s.contains("error_class="));
    }

    #[test]
    fn test_type_checks() {
        let job_buf = job_setup_comm();
        let idx = LayerIndex::new(LayerKind::S7Comm, 0, job_buf.len());
        let s7 = S7CommLayer::new(idx);

        assert!(s7.is_job(&job_buf));
        assert!(!s7.is_ack(&job_buf));
        assert!(!s7.is_ack_data(&job_buf));
        assert!(!s7.is_userdata(&job_buf));
    }
}
