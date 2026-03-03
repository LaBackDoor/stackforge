//! TFTP (Trivial File Transfer Protocol) layer implementation.
//!
//! Implements RFC 1350 TFTP packet parsing as a zero-copy view into a packet buffer.
//!
//! TFTP operates over UDP port 69 and defines 5 packet types:
//!
//! ## Packet Types
//!
//! | Opcode | Abbreviation | Packet Type       |
//! |--------|--------------|-------------------|
//! | 1      | RRQ          | Read Request      |
//! | 2      | WRQ          | Write Request     |
//! | 3      | DATA         | Data              |
//! | 4      | ACK          | Acknowledgment    |
//! | 5      | ERROR        | Error             |
//!
//! ## Packet Formats
//!
//! **RRQ / WRQ:**
//! ```text
//! 2 bytes   string   1 byte   string   1 byte
//! +---------+--------+--------+--------+--------+
//! | Opcode  |Filename|   0    |  Mode  |   0    |
//! +---------+--------+--------+--------+--------+
//! ```
//!
//! **DATA:**
//! ```text
//! 2 bytes   2 bytes   n bytes
//! +---------+---------+--------+
//! | Opcode  |  Block# |  Data  |
//! +---------+---------+--------+
//! ```
//!
//! **ACK:**
//! ```text
//! 2 bytes   2 bytes
//! +---------+---------+
//! | Opcode  |  Block# |
//! +---------+---------+
//! ```
//!
//! **ERROR:**
//! ```text
//! 2 bytes   2 bytes   string   1 byte
//! +---------+---------+--------+--------+
//! | Opcode  | ErrorCode| ErrMsg |   0    |
//! +---------+---------+--------+--------+
//! ```

pub mod builder;
pub use builder::TftpBuilder;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Minimum TFTP header: opcode (2 bytes).
pub const TFTP_MIN_HEADER_LEN: usize = 2;

/// TFTP server UDP port.
pub const TFTP_PORT: u16 = 69;

/// Default TFTP data block size (bytes).
pub const TFTP_DEFAULT_BLOCK_SIZE: usize = 512;

// ============================================================================
// Opcode constants (RFC 1350 §5)
// ============================================================================
pub const OPCODE_RRQ: u16 = 1;
pub const OPCODE_WRQ: u16 = 2;
pub const OPCODE_DATA: u16 = 3;
pub const OPCODE_ACK: u16 = 4;
pub const OPCODE_ERROR: u16 = 5;

// ============================================================================
// Error code constants (RFC 1350 §5)
// ============================================================================
pub const ERR_UNDEFINED: u16 = 0;
pub const ERR_FILE_NOT_FOUND: u16 = 1;
pub const ERR_ACCESS_VIOLATION: u16 = 2;
pub const ERR_DISK_FULL: u16 = 3;
pub const ERR_ILLEGAL_OPERATION: u16 = 4;
pub const ERR_UNKNOWN_TID: u16 = 5;
pub const ERR_FILE_EXISTS: u16 = 6;
pub const ERR_NO_SUCH_USER: u16 = 7;

/// Field names for Python/generic access.
pub static TFTP_FIELD_NAMES: &[&str] = &[
    "opcode",
    "op_name",
    "filename",
    "mode",
    "block_num",
    "data",
    "error_code",
    "error_msg",
];

// ============================================================================
// Payload detection
// ============================================================================

/// Returns true if `buf` looks like a TFTP payload.
///
/// A valid TFTP packet starts with a 2-byte opcode in range [1, 5].
#[must_use]
pub fn is_tftp_payload(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    (1..=5).contains(&opcode)
}

/// Returns a human-readable name for a TFTP opcode.
#[must_use]
pub fn opcode_name(opcode: u16) -> &'static str {
    match opcode {
        OPCODE_RRQ => "RRQ",
        OPCODE_WRQ => "WRQ",
        OPCODE_DATA => "DATA",
        OPCODE_ACK => "ACK",
        OPCODE_ERROR => "ERROR",
        _ => "UNKNOWN",
    }
}

/// Returns a human-readable description for a TFTP error code.
#[must_use]
pub fn error_code_description(code: u16) -> &'static str {
    match code {
        ERR_UNDEFINED => "Not defined",
        ERR_FILE_NOT_FOUND => "File not found",
        ERR_ACCESS_VIOLATION => "Access violation",
        ERR_DISK_FULL => "Disk full or allocation exceeded",
        ERR_ILLEGAL_OPERATION => "Illegal TFTP operation",
        ERR_UNKNOWN_TID => "Unknown transfer ID",
        ERR_FILE_EXISTS => "File already exists",
        ERR_NO_SUCH_USER => "No such user",
        _ => "Unknown error",
    }
}

// ============================================================================
// TftpLayer - zero-copy view
// ============================================================================

/// A zero-copy view into a TFTP layer within a packet buffer.
#[must_use]
#[derive(Debug, Clone)]
pub struct TftpLayer {
    pub index: LayerIndex,
}

impl TftpLayer {
    pub fn new(index: LayerIndex) -> Self {
        Self { index }
    }

    pub fn at_start(len: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Tftp, 0, len),
        }
    }

    #[inline]
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.index.end.min(buf.len());
        &buf[self.index.start..end]
    }

    /// Returns the 2-byte opcode.
    pub fn opcode(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 2,
                have: s.len(),
            });
        }
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// Returns the opcode name.
    pub fn op_name(&self, buf: &[u8]) -> Result<String, FieldError> {
        self.opcode(buf).map(|op| opcode_name(op).to_string())
    }

    /// Returns the filename from a RRQ or WRQ packet.
    ///
    /// The filename is a null-terminated string starting at byte 2.
    pub fn filename(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_RRQ && opcode != OPCODE_WRQ {
            return Err(FieldError::InvalidValue(
                "filename only available in RRQ/WRQ packets".into(),
            ));
        }
        if s.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 3,
                have: s.len(),
            });
        }
        // Find null terminator
        let start = 2;
        let end = s[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(s.len(), |p| start + p);
        let name = std::str::from_utf8(&s[start..end])
            .map_err(|_| FieldError::InvalidValue("invalid UTF-8 in filename".into()))?;
        Ok(name.to_string())
    }

    /// Returns the mode string from a RRQ or WRQ packet ("netascii", "octet", "mail").
    pub fn mode(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_RRQ && opcode != OPCODE_WRQ {
            return Err(FieldError::InvalidValue(
                "mode only available in RRQ/WRQ packets".into(),
            ));
        }
        // Skip past opcode + filename + null
        let mut offset = 2;
        while offset < s.len() && s[offset] != 0 {
            offset += 1;
        }
        offset += 1; // skip null terminator

        let mode_start = offset;
        let mode_end = s[mode_start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(s.len(), |p| mode_start + p);

        let mode = std::str::from_utf8(&s[mode_start..mode_end])
            .map_err(|_| FieldError::InvalidValue("invalid UTF-8 in mode".into()))?;
        Ok(mode.to_ascii_lowercase())
    }

    /// Returns the block number from a DATA or ACK packet.
    pub fn block_num(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_DATA && opcode != OPCODE_ACK {
            return Err(FieldError::InvalidValue(
                "block_num only available in DATA/ACK packets".into(),
            ));
        }
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: s.len(),
            });
        }
        Ok(u16::from_be_bytes([s[2], s[3]]))
    }

    /// Returns the data payload from a DATA packet.
    pub fn data(&self, buf: &[u8]) -> Result<Vec<u8>, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_DATA {
            return Err(FieldError::InvalidValue(
                "data only available in DATA packets".into(),
            ));
        }
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: s.len(),
            });
        }
        Ok(s[4..].to_vec())
    }

    /// Returns the error code from an ERROR packet.
    pub fn error_code(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_ERROR {
            return Err(FieldError::InvalidValue(
                "error_code only available in ERROR packets".into(),
            ));
        }
        if s.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 4,
                have: s.len(),
            });
        }
        Ok(u16::from_be_bytes([s[2], s[3]]))
    }

    /// Returns the error message from an ERROR packet.
    pub fn error_msg(&self, buf: &[u8]) -> Result<String, FieldError> {
        let s = self.slice(buf);
        let opcode = self.opcode(buf)?;
        if opcode != OPCODE_ERROR {
            return Err(FieldError::InvalidValue(
                "error_msg only available in ERROR packets".into(),
            ));
        }
        if s.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start,
                need: 5,
                have: s.len(),
            });
        }
        let msg_start = 4;
        let msg_end = s[msg_start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(s.len(), |p| msg_start + p);
        let msg = std::str::from_utf8(&s[msg_start..msg_end])
            .map_err(|_| FieldError::InvalidValue("invalid UTF-8 in error message".into()))?;
        Ok(msg.to_string())
    }

    /// Get a field by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "opcode" => Some(self.opcode(buf).map(FieldValue::U16)),
            "op_name" => Some(self.op_name(buf).map(FieldValue::Str)),
            "filename" => Some(self.filename(buf).map(FieldValue::Str)),
            "mode" => Some(self.mode(buf).map(FieldValue::Str)),
            "block_num" => Some(self.block_num(buf).map(FieldValue::U16)),
            "data" => Some(self.data(buf).map(FieldValue::Bytes)),
            "error_code" => Some(self.error_code(buf).map(FieldValue::U16)),
            "error_msg" => Some(self.error_msg(buf).map(FieldValue::Str)),
            _ => None,
        }
    }
}

impl Layer for TftpLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Tftp
    }

    fn summary(&self, buf: &[u8]) -> String {
        let s = self.slice(buf);
        if s.len() < 2 {
            return "TFTP [truncated]".to_string();
        }
        let opcode = u16::from_be_bytes([s[0], s[1]]);
        match opcode {
            OPCODE_RRQ => {
                let fname = self.filename(buf).unwrap_or_default();
                let mode = self.mode(buf).unwrap_or_default();
                format!("TFTP Read Request File: {fname} Mode: {mode}")
            },
            OPCODE_WRQ => {
                let fname = self.filename(buf).unwrap_or_default();
                let mode = self.mode(buf).unwrap_or_default();
                format!("TFTP Write Request File: {fname} Mode: {mode}")
            },
            OPCODE_DATA => {
                let block = self.block_num(buf).unwrap_or(0);
                let data_len = if s.len() >= 4 { s.len() - 4 } else { 0 };
                format!("TFTP Data Block#{block} ({data_len} bytes)")
            },
            OPCODE_ACK => {
                let block = self.block_num(buf).unwrap_or(0);
                format!("TFTP Ack Block#{block}")
            },
            OPCODE_ERROR => {
                let code = self.error_code(buf).unwrap_or(0);
                let msg = self.error_msg(buf).unwrap_or_default();
                format!("TFTP Error Code: {code} Message: {msg}")
            },
            _ => format!("TFTP [unknown opcode {opcode}]"),
        }
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        if s.len() < 2 {
            return s.len();
        }
        let opcode = u16::from_be_bytes([s[0], s[1]]);
        match opcode {
            OPCODE_RRQ | OPCODE_WRQ => s.len(),         // variable
            OPCODE_DATA | OPCODE_ACK => 4.min(s.len()), // opcode + block#, data is payload
            OPCODE_ERROR => s.len(),
            _ => 2,
        }
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        if let Ok(block) = self.block_num(buf) {
            block.to_be_bytes().to_vec()
        } else if let Ok(op) = self.opcode(buf) {
            op.to_be_bytes().to_vec()
        } else {
            vec![]
        }
    }

    fn field_names(&self) -> &'static [&'static str] {
        TFTP_FIELD_NAMES
    }
}

/// Display fields for `TftpLayer` in `show()` output.
#[must_use]
pub fn tftp_show_fields(l: &TftpLayer, buf: &[u8]) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    if let Ok(op) = l.opcode(buf) {
        fields.push(("opcode", op.to_string()));
        fields.push(("op_name", opcode_name(op).to_string()));
        match op {
            OPCODE_RRQ | OPCODE_WRQ => {
                if let Ok(f) = l.filename(buf) {
                    fields.push(("filename", f));
                }
                if let Ok(m) = l.mode(buf) {
                    fields.push(("mode", m));
                }
            },
            OPCODE_DATA | OPCODE_ACK => {
                if let Ok(b) = l.block_num(buf) {
                    fields.push(("block_num", b.to_string()));
                }
            },
            OPCODE_ERROR => {
                if let Ok(c) = l.error_code(buf) {
                    fields.push(("error_code", c.to_string()));
                }
                if let Ok(m) = l.error_msg(buf) {
                    fields.push(("error_msg", m));
                }
            },
            _ => {},
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer(data: &[u8]) -> TftpLayer {
        TftpLayer::new(LayerIndex::new(LayerKind::Tftp, 0, data.len()))
    }

    #[test]
    fn test_tftp_detection() {
        // RRQ
        let rrq = b"\x00\x01file.txt\x00octet\x00";
        assert!(is_tftp_payload(rrq));
        // DATA
        assert!(is_tftp_payload(b"\x00\x03\x00\x01hello"));
        // ACK
        assert!(is_tftp_payload(b"\x00\x04\x00\x01"));
        // ERROR
        assert!(is_tftp_payload(b"\x00\x05\x00\x01File not found\x00"));
        // Invalid
        assert!(!is_tftp_payload(b"\x00\x06")); // opcode 6
        assert!(!is_tftp_payload(b"\x00")); // too short
        assert!(!is_tftp_payload(b"")); // empty
    }

    #[test]
    fn test_tftp_rrq_parsing() {
        let data = b"\x00\x01file.txt\x00octet\x00";
        let layer = make_layer(data);
        assert_eq!(layer.opcode(data).unwrap(), OPCODE_RRQ);
        assert_eq!(layer.op_name(data).unwrap(), "RRQ");
        assert_eq!(layer.filename(data).unwrap(), "file.txt");
        assert_eq!(layer.mode(data).unwrap(), "octet");
    }

    #[test]
    fn test_tftp_wrq_parsing() {
        let data = b"\x00\x02upload.bin\x00netascii\x00";
        let layer = make_layer(data);
        assert_eq!(layer.opcode(data).unwrap(), OPCODE_WRQ);
        assert_eq!(layer.filename(data).unwrap(), "upload.bin");
        assert_eq!(layer.mode(data).unwrap(), "netascii");
    }

    #[test]
    fn test_tftp_data_parsing() {
        let data = b"\x00\x03\x00\x01hello world data";
        let layer = make_layer(data);
        assert_eq!(layer.opcode(data).unwrap(), OPCODE_DATA);
        assert_eq!(layer.block_num(data).unwrap(), 1);
        assert_eq!(layer.data(data).unwrap(), b"hello world data");
    }

    #[test]
    fn test_tftp_ack_parsing() {
        let data = b"\x00\x04\x00\x05";
        let layer = make_layer(data);
        assert_eq!(layer.opcode(data).unwrap(), OPCODE_ACK);
        assert_eq!(layer.block_num(data).unwrap(), 5);
    }

    #[test]
    fn test_tftp_error_parsing() {
        let data = b"\x00\x05\x00\x01File not found\x00";
        let layer = make_layer(data);
        assert_eq!(layer.opcode(data).unwrap(), OPCODE_ERROR);
        assert_eq!(layer.error_code(data).unwrap(), ERR_FILE_NOT_FOUND);
        assert_eq!(layer.error_msg(data).unwrap(), "File not found");
    }

    #[test]
    fn test_tftp_error_code_descriptions() {
        assert_eq!(error_code_description(ERR_FILE_NOT_FOUND), "File not found");
        assert_eq!(
            error_code_description(ERR_ACCESS_VIOLATION),
            "Access violation"
        );
        assert_eq!(
            error_code_description(ERR_DISK_FULL),
            "Disk full or allocation exceeded"
        );
    }

    #[test]
    fn test_tftp_field_access() {
        let data = b"\x00\x04\x00\x02";
        let layer = make_layer(data);
        assert!(matches!(
            layer.get_field(data, "opcode"),
            Some(Ok(FieldValue::U16(4)))
        ));
        assert!(matches!(
            layer.get_field(data, "block_num"),
            Some(Ok(FieldValue::U16(2)))
        ));
        assert!(layer.get_field(data, "bad_field").is_none());
    }
}
