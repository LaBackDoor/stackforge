//! Modbus protocol layer implementation.
//!
//! Implements Modbus/TCP (MBAP), Modbus RTU, and Modbus ASCII frame formats.
//!
//! ## Modbus/TCP (MBAP) Header Format
//!
//! ```text
//! Offset  Size  Field
//! 0       2     Transaction ID (big-endian)
//! 2       2     Protocol ID (0x0000 for Modbus)
//! 4       2     Length (number of following bytes, including Unit ID)
//! 6       1     Unit ID (slave address)
//! 7       1     Function Code
//! 8..N    var   Data (function-code dependent)
//! ```
//!
//! ## Modbus RTU Frame Format
//!
//! ```text
//! Offset  Size  Field
//! 0       1     Slave Address
//! 1       1     Function Code
//! 2..N-2  var   Data
//! N-2     2     CRC-16 (little-endian)
//! ```
//!
//! ## Modbus ASCII Frame Format
//!
//! ```text
//! ':'  + hex(SlaveAddr + FuncCode + Data + LRC) + CR + LF
//! ```

pub mod builder;
pub mod crc;

pub use builder::ModbusBuilder;
pub use crc::{modbus_crc16, modbus_lrc, verify_crc16, verify_lrc};

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// Modbus/TCP default port.
pub const MODBUS_TCP_PORT: u16 = 502;

/// MBAP header length (transId + protoId + length + unitId = 7 bytes).
pub const MODBUS_MBAP_HEADER_LEN: usize = 7;

/// Minimum Modbus/TCP message: MBAP header (7) + function code (1) = 8 bytes.
pub const MODBUS_MIN_HEADER_LEN: usize = 8;

/// Modbus function code constants.
pub mod func_code {
    pub const READ_COILS: u8 = 0x01;
    pub const READ_DISCRETE_INPUTS: u8 = 0x02;
    pub const READ_HOLDING_REGISTERS: u8 = 0x03;
    pub const READ_INPUT_REGISTERS: u8 = 0x04;
    pub const WRITE_SINGLE_COIL: u8 = 0x05;
    pub const WRITE_SINGLE_REGISTER: u8 = 0x06;
    pub const READ_EXCEPTION_STATUS: u8 = 0x07;
    pub const DIAGNOSTICS: u8 = 0x08;
    pub const GET_COMM_EVENT_COUNTER: u8 = 0x0B;
    pub const GET_COMM_EVENT_LOG: u8 = 0x0C;
    pub const WRITE_MULTIPLE_COILS: u8 = 0x0F;
    pub const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
    pub const REPORT_SLAVE_ID: u8 = 0x11;
    pub const READ_FILE_RECORD: u8 = 0x14;
    pub const WRITE_FILE_RECORD: u8 = 0x15;
    pub const MASK_WRITE_REGISTER: u8 = 0x16;
    pub const READ_WRITE_MULTIPLE_REGISTERS: u8 = 0x17;
    pub const READ_FIFO_QUEUE: u8 = 0x18;
    pub const ENCAP_INTERFACE_TRANSPORT: u8 = 0x2B;
}

/// Modbus exception code constants.
pub mod except_code {
    pub const ILLEGAL_FUNCTION: u8 = 0x01;
    pub const ILLEGAL_DATA_ADDRESS: u8 = 0x02;
    pub const ILLEGAL_DATA_VALUE: u8 = 0x03;
    pub const SERVER_DEVICE_FAILURE: u8 = 0x04;
    pub const ACKNOWLEDGE: u8 = 0x05;
    pub const SERVER_DEVICE_BUSY: u8 = 0x06;
    pub const MEMORY_PARITY_ERROR: u8 = 0x08;
    pub const GATEWAY_PATH_UNAVAILABLE: u8 = 0x0A;
    pub const GATEWAY_TARGET_FAILED: u8 = 0x0B;
}

/// Field names exported for Python/generic access.
pub static MODBUS_FIELD_NAMES: &[&str] = &[
    "trans_id",
    "proto_id",
    "length",
    "unit_id",
    "func_code",
    "except_code",
    "start_addr",
    "quantity",
    "byte_count",
    "output_value",
    "register_val",
    "coil_status",
    "sub_func",
    "ref_addr",
    "and_mask",
    "or_mask",
    "data",
];

/// Modbus frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModbusFrameType {
    /// Modbus/TCP (MBAP header)
    Tcp,
    /// Modbus RTU (serial, binary with CRC-16)
    Rtu,
    /// Modbus ASCII (serial, ':' + hex + LRC + CRLF)
    Ascii,
}

/// Return a human-readable name for a Modbus function code.
pub fn func_code_name(fc: u8) -> &'static str {
    match fc & 0x7F {
        func_code::READ_COILS => "Read Coils",
        func_code::READ_DISCRETE_INPUTS => "Read Discrete Inputs",
        func_code::READ_HOLDING_REGISTERS => "Read Holding Registers",
        func_code::READ_INPUT_REGISTERS => "Read Input Registers",
        func_code::WRITE_SINGLE_COIL => "Write Single Coil",
        func_code::WRITE_SINGLE_REGISTER => "Write Single Register",
        func_code::READ_EXCEPTION_STATUS => "Read Exception Status",
        func_code::DIAGNOSTICS => "Diagnostics",
        func_code::GET_COMM_EVENT_COUNTER => "Get Comm Event Counter",
        func_code::GET_COMM_EVENT_LOG => "Get Comm Event Log",
        func_code::WRITE_MULTIPLE_COILS => "Write Multiple Coils",
        func_code::WRITE_MULTIPLE_REGISTERS => "Write Multiple Registers",
        func_code::REPORT_SLAVE_ID => "Report Slave ID",
        func_code::READ_FILE_RECORD => "Read File Record",
        func_code::WRITE_FILE_RECORD => "Write File Record",
        func_code::MASK_WRITE_REGISTER => "Mask Write Register",
        func_code::READ_WRITE_MULTIPLE_REGISTERS => "Read/Write Multiple Registers",
        func_code::READ_FIFO_QUEUE => "Read FIFO Queue",
        func_code::ENCAP_INTERFACE_TRANSPORT => "Encapsulated Interface Transport",
        _ => "Unknown",
    }
}

/// Return a human-readable name for a Modbus exception code.
pub fn except_code_name(ec: u8) -> &'static str {
    match ec {
        except_code::ILLEGAL_FUNCTION => "Illegal Function",
        except_code::ILLEGAL_DATA_ADDRESS => "Illegal Data Address",
        except_code::ILLEGAL_DATA_VALUE => "Illegal Data Value",
        except_code::SERVER_DEVICE_FAILURE => "Server Device Failure",
        except_code::ACKNOWLEDGE => "Acknowledge",
        except_code::SERVER_DEVICE_BUSY => "Server Device Busy",
        except_code::MEMORY_PARITY_ERROR => "Memory Parity Error",
        except_code::GATEWAY_PATH_UNAVAILABLE => "Gateway Path Unavailable",
        except_code::GATEWAY_TARGET_FAILED => "Gateway Target Device Failed",
        _ => "Unknown",
    }
}

/// Check if a TCP payload looks like a Modbus/TCP (MBAP) message.
///
/// Validates:
/// 1. At least 8 bytes (MBAP header + function code)
/// 2. Protocol ID at offset 2 is 0x0000
/// 3. Length field at offset 4 is sensible (>= 2, <= remaining)
pub fn is_modbus_tcp_payload(buf: &[u8]) -> bool {
    if buf.len() < MODBUS_MIN_HEADER_LEN {
        return false;
    }
    // Protocol ID must be 0x0000 for Modbus
    let proto_id = u16::from_be_bytes([buf[2], buf[3]]);
    if proto_id != 0x0000 {
        return false;
    }
    // Length field: number of bytes after the first 6 bytes (unitId + funcCode + data)
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    // Must be at least 2 (unitId + funcCode) and not exceed remaining data
    if length < 2 {
        return false;
    }
    // Sanity: length should not claim more data than we have
    if 6 + length > buf.len() + 256 {
        // Allow some slack for truncated captures
        return false;
    }
    true
}

// ============================================================================
// ModbusLayer -- zero-copy view
// ============================================================================

/// Modbus layer -- a zero-copy view into a packet buffer.
///
/// By default assumes Modbus/TCP (MBAP) framing since that is what appears
/// on the wire over TCP port 502.
#[derive(Debug, Clone)]
pub struct ModbusLayer {
    pub index: LayerIndex,
    pub frame_type: ModbusFrameType,
}

impl ModbusLayer {
    /// Create a new Modbus layer from a layer index (defaults to TCP framing).
    pub fn new(index: LayerIndex) -> Self {
        Self {
            index,
            frame_type: ModbusFrameType::Tcp,
        }
    }

    /// Create a Modbus layer with explicit frame type.
    pub fn with_frame_type(index: LayerIndex, frame_type: ModbusFrameType) -> Self {
        Self { index, frame_type }
    }

    /// Return a slice of the buffer corresponding to this layer.
    fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        self.index.slice(buf)
    }

    // ========================================================================
    // MBAP Header Accessors (Modbus/TCP)
    // ========================================================================

    /// Get the Transaction ID (MBAP bytes 0-1).
    pub fn trans_id(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the Protocol ID (MBAP bytes 2-3; should be 0x0000).
    pub fn proto_id(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the Length field (MBAP bytes 4-5).
    pub fn length(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the Unit ID (MBAP byte 6).
    pub fn unit_id(&self, buf: &[u8]) -> Result<u8, FieldError> {
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

    /// Get the Function Code (MBAP byte 7).
    pub fn func_code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 7,
                need: 1,
                have: s.len().saturating_sub(7),
            });
        }
        Ok(s[7])
    }

    /// Check if this is an exception response (function code has bit 7 set).
    pub fn is_error(&self, buf: &[u8]) -> bool {
        self.func_code(buf)
            .map(|fc| fc & 0x80 != 0)
            .unwrap_or(false)
    }

    /// Get the exception code (byte 8, only valid for error responses).
    pub fn except_code(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8])
    }

    // ========================================================================
    // PDU Data Accessors
    // ========================================================================

    /// Get the Start Address (bytes 8-9 for request PDUs like 0x01-0x06).
    pub fn start_addr(&self, buf: &[u8]) -> Result<u16, FieldError> {
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

    /// Get the Quantity field (bytes 10-11 for request PDUs like 0x01-0x04).
    pub fn quantity(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 12 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 10,
                need: 2,
                have: s.len().saturating_sub(10),
            });
        }
        Ok(u16::from_be_bytes([s[10], s[11]]))
    }

    /// Get the Byte Count field (byte 8 for response PDUs like 0x01-0x04).
    pub fn byte_count(&self, buf: &[u8]) -> Result<u8, FieldError> {
        let s = self.slice(buf);
        if s.len() < 9 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: s.len().saturating_sub(8),
            });
        }
        Ok(s[8])
    }

    /// Get the Output Value for Write Single Coil/Register (bytes 10-11).
    pub fn output_value(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.quantity(buf) // same offset (bytes 10-11)
    }

    /// Get the Register Value for Write Single Register (bytes 10-11).
    pub fn register_val(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.quantity(buf) // same offset (bytes 10-11)
    }

    /// Get the Sub-function code for Diagnostics (0x08) (bytes 8-9).
    pub fn sub_func(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.start_addr(buf) // same offset (bytes 8-9)
    }

    /// Get the Reference Address for Mask Write Register (0x16) (bytes 8-9).
    pub fn ref_addr(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.start_addr(buf) // same offset
    }

    /// Get the AND mask for Mask Write Register (0x16) (bytes 10-11).
    pub fn and_mask(&self, buf: &[u8]) -> Result<u16, FieldError> {
        self.quantity(buf) // same offset
    }

    /// Get the OR mask for Mask Write Register (0x16) (bytes 12-13).
    pub fn or_mask(&self, buf: &[u8]) -> Result<u16, FieldError> {
        let s = self.slice(buf);
        if s.len() < 14 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 12,
                need: 2,
                have: s.len().saturating_sub(12),
            });
        }
        Ok(u16::from_be_bytes([s[12], s[13]]))
    }

    /// Get the raw data bytes after the function code (bytes 8..end).
    pub fn data(&self, buf: &[u8]) -> Result<Vec<u8>, FieldError> {
        let s = self.slice(buf);
        if s.len() < 8 {
            return Err(FieldError::BufferTooShort {
                offset: self.index.start + 8,
                need: 1,
                have: 0,
            });
        }
        Ok(s[8..].to_vec())
    }

    // ========================================================================
    // Setters
    // ========================================================================

    /// Set the Transaction ID.
    pub fn set_trans_id(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start;
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

    /// Set the Unit ID.
    pub fn set_unit_id(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 6;
        if buf.len() < off + 1 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the Function Code.
    pub fn set_func_code(&self, buf: &mut [u8], value: u8) -> Result<(), FieldError> {
        let off = self.index.start + 7;
        if buf.len() < off + 1 {
            return Err(FieldError::BufferTooShort {
                offset: off,
                need: 1,
                have: buf.len().saturating_sub(off),
            });
        }
        buf[off] = value;
        Ok(())
    }

    /// Set the Start Address (bytes 8-9).
    pub fn set_start_addr(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
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

    /// Set the Quantity (bytes 10-11).
    pub fn set_quantity(&self, buf: &mut [u8], value: u16) -> Result<(), FieldError> {
        let off = self.index.start + 10;
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
    // Compute header length
    // ========================================================================

    fn compute_header_len(&self, buf: &[u8]) -> usize {
        let s = self.slice(buf);
        if s.len() < MODBUS_MIN_HEADER_LEN {
            return MODBUS_MIN_HEADER_LEN;
        }
        // For Modbus/TCP, the total message size = 6 (MBAP header) + length field
        let length = u16::from_be_bytes([s[4], s[5]]) as usize;
        let total = 6 + length;
        let max = self.index.end - self.index.start;
        total.min(max)
    }

    // ========================================================================
    // Summary
    // ========================================================================

    /// Generate a one-line summary of this Modbus layer.
    pub fn summary(&self, buf: &[u8]) -> String {
        let fc = match self.func_code(buf) {
            Ok(v) => v,
            Err(_) => return "Modbus".to_string(),
        };

        let fc_name = func_code_name(fc);

        if self.is_error(buf) {
            let ec = self
                .except_code(buf)
                .map(|v| format!("{} ({})", v, except_code_name(v)))
                .unwrap_or_else(|_| "?".to_string());
            return format!("Modbus Error fc={:#04x} except={}", fc, ec);
        }

        let tid = self
            .trans_id(buf)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let uid = self
            .unit_id(buf)
            .map(|v| format!("{:#04x}", v))
            .unwrap_or_else(|_| "?".to_string());

        format!("Modbus {} trans_id={} unit_id={}", fc_name, tid, uid)
    }

    // ========================================================================
    // Field Access API
    // ========================================================================

    /// Get the field names for this layer.
    pub fn field_names() -> &'static [&'static str] {
        MODBUS_FIELD_NAMES
    }

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "trans_id" => Some(self.trans_id(buf).map(FieldValue::U16)),
            "proto_id" => Some(self.proto_id(buf).map(FieldValue::U16)),
            "length" => Some(self.length(buf).map(FieldValue::U16)),
            "unit_id" => Some(self.unit_id(buf).map(FieldValue::U8)),
            "func_code" => Some(self.func_code(buf).map(FieldValue::U8)),
            "except_code" => {
                if self.is_error(buf) {
                    Some(self.except_code(buf).map(FieldValue::U8))
                } else {
                    Some(Ok(FieldValue::U8(0)))
                }
            },
            "start_addr" => Some(self.start_addr(buf).map(FieldValue::U16)),
            "quantity" => Some(self.quantity(buf).map(FieldValue::U16)),
            "byte_count" => Some(self.byte_count(buf).map(FieldValue::U8)),
            "output_value" => Some(self.output_value(buf).map(FieldValue::U16)),
            "register_val" => Some(self.register_val(buf).map(FieldValue::U16)),
            "coil_status" => Some(self.byte_count(buf).map(FieldValue::U8)),
            "sub_func" => Some(self.sub_func(buf).map(FieldValue::U16)),
            "ref_addr" => Some(self.ref_addr(buf).map(FieldValue::U16)),
            "and_mask" => Some(self.and_mask(buf).map(FieldValue::U16)),
            "or_mask" => Some(self.or_mask(buf).map(FieldValue::U16)),
            "data" => Some(self.data(buf).map(FieldValue::Bytes)),
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
            "trans_id" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_trans_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "trans_id: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "unit_id" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_unit_id(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "unit_id: expected U8, got {:?}",
                        value
                    ))))
                }
            },
            "func_code" => {
                if let FieldValue::U8(v) = value {
                    Some(self.set_func_code(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "func_code: expected U8, got {:?}",
                        value
                    ))))
                }
            },
            "start_addr" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_start_addr(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "start_addr: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            "quantity" => {
                if let FieldValue::U16(v) = value {
                    Some(self.set_quantity(buf, v))
                } else {
                    Some(Err(FieldError::InvalidValue(format!(
                        "quantity: expected U16, got {:?}",
                        value
                    ))))
                }
            },
            _ => None,
        }
    }
}

impl Layer for ModbusLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Modbus
    }

    fn summary(&self, data: &[u8]) -> String {
        self.summary(data)
    }

    fn header_len(&self, data: &[u8]) -> usize {
        self.compute_header_len(data)
    }

    fn field_names(&self) -> &'static [&'static str] {
        MODBUS_FIELD_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_layer(buf: &[u8]) -> ModbusLayer {
        let idx = LayerIndex::new(LayerKind::Modbus, 0, buf.len());
        ModbusLayer::new(idx)
    }

    // Read Coils Request: trans_id=0x0001, proto_id=0x0000, length=6,
    // unit_id=0x01, fc=0x01, start=0x0000, qty=0x000A
    fn read_coils_request() -> Vec<u8> {
        vec![
            0x00, 0x01, // trans_id
            0x00, 0x00, // proto_id
            0x00, 0x06, // length (unit + fc + data = 1 + 1 + 4 = 6)
            0x01, // unit_id
            0x01, // func_code: Read Coils
            0x00, 0x00, // start_addr
            0x00, 0x0A, // quantity
        ]
    }

    // Error response: trans_id=0x0001, proto_id=0x0000, length=3,
    // unit_id=0x01, fc=0x81 (error), except=0x02
    fn error_response() -> Vec<u8> {
        vec![
            0x00, 0x01, // trans_id
            0x00, 0x00, // proto_id
            0x00, 0x03, // length
            0x01, // unit_id
            0x81, // func_code (error: 0x80 | 0x01)
            0x02, // except_code: Illegal Data Address
        ]
    }

    #[test]
    fn test_read_coils_request_fields() {
        let data = read_coils_request();
        let layer = make_layer(&data);

        assert_eq!(layer.trans_id(&data).unwrap(), 1);
        assert_eq!(layer.proto_id(&data).unwrap(), 0);
        assert_eq!(layer.length(&data).unwrap(), 6);
        assert_eq!(layer.unit_id(&data).unwrap(), 1);
        assert_eq!(layer.func_code(&data).unwrap(), 0x01);
        assert!(!layer.is_error(&data));
        assert_eq!(layer.start_addr(&data).unwrap(), 0);
        assert_eq!(layer.quantity(&data).unwrap(), 10);
    }

    #[test]
    fn test_error_response_fields() {
        let data = error_response();
        let layer = make_layer(&data);

        assert_eq!(layer.trans_id(&data).unwrap(), 1);
        assert_eq!(layer.func_code(&data).unwrap(), 0x81);
        assert!(layer.is_error(&data));
        assert_eq!(layer.except_code(&data).unwrap(), 0x02);
    }

    #[test]
    fn test_summary_request() {
        let data = read_coils_request();
        let layer = make_layer(&data);
        let s = layer.summary(&data);
        assert!(s.contains("Read Coils"));
        assert!(s.contains("trans_id=1"));
    }

    #[test]
    fn test_summary_error() {
        let data = error_response();
        let layer = make_layer(&data);
        let s = layer.summary(&data);
        assert!(s.contains("Error"));
        assert!(s.contains("Illegal Data Address"));
    }

    #[test]
    fn test_get_field_api() {
        let data = read_coils_request();
        let layer = make_layer(&data);

        assert_eq!(
            layer.get_field(&data, "trans_id").unwrap().unwrap(),
            FieldValue::U16(1)
        );
        assert_eq!(
            layer.get_field(&data, "func_code").unwrap().unwrap(),
            FieldValue::U8(0x01)
        );
        assert_eq!(
            layer.get_field(&data, "start_addr").unwrap().unwrap(),
            FieldValue::U16(0)
        );
        assert!(layer.get_field(&data, "nonexistent").is_none());
    }

    #[test]
    fn test_set_field_api() {
        let mut data = read_coils_request();
        let layer = make_layer(&data);

        layer
            .set_field(&mut data, "trans_id", FieldValue::U16(42))
            .unwrap()
            .unwrap();
        assert_eq!(layer.trans_id(&data).unwrap(), 42);

        layer
            .set_field(&mut data, "unit_id", FieldValue::U8(0xFF))
            .unwrap()
            .unwrap();
        assert_eq!(layer.unit_id(&data).unwrap(), 0xFF);
    }

    #[test]
    fn test_detection_valid() {
        let data = read_coils_request();
        assert!(is_modbus_tcp_payload(&data));
    }

    #[test]
    fn test_detection_bad_proto_id() {
        let mut data = read_coils_request();
        data[2] = 0x01; // corrupt protocol ID
        assert!(!is_modbus_tcp_payload(&data));
    }

    #[test]
    fn test_detection_too_short() {
        assert!(!is_modbus_tcp_payload(&[0x00; 7]));
        assert!(!is_modbus_tcp_payload(&[]));
    }

    #[test]
    fn test_detection_bad_length() {
        let mut data = read_coils_request();
        data[4] = 0x00;
        data[5] = 0x01; // length = 1, too small (must be >= 2)
        assert!(!is_modbus_tcp_payload(&data));
    }

    #[test]
    fn test_header_len() {
        let data = read_coils_request();
        let layer = make_layer(&data);
        // 6 (MBAP) + 6 (length field value) = 12
        assert_eq!(layer.compute_header_len(&data), 12);
    }

    #[test]
    fn test_func_code_name() {
        assert_eq!(func_code_name(0x01), "Read Coils");
        assert_eq!(func_code_name(0x03), "Read Holding Registers");
        assert_eq!(func_code_name(0x10), "Write Multiple Registers");
        assert_eq!(func_code_name(0x81), "Read Coils"); // error bit stripped
        assert_eq!(func_code_name(0xFF), "Unknown");
    }

    #[test]
    fn test_except_code_name() {
        assert_eq!(except_code_name(0x01), "Illegal Function");
        assert_eq!(except_code_name(0x02), "Illegal Data Address");
        assert_eq!(except_code_name(0xFF), "Unknown");
    }

    #[test]
    fn test_write_single_coil() {
        // Write Single Coil: trans_id=2, unit=1, fc=0x05, addr=0x0013, value=0xFF00
        let data: Vec<u8> = vec![
            0x00, 0x02, // trans_id
            0x00, 0x00, // proto_id
            0x00, 0x06, // length
            0x01, // unit_id
            0x05, // func_code: Write Single Coil
            0x00, 0x13, // start_addr (coil address)
            0xFF, 0x00, // output_value (0xFF00 = ON)
        ];
        let layer = make_layer(&data);
        assert_eq!(layer.func_code(&data).unwrap(), 0x05);
        assert_eq!(layer.start_addr(&data).unwrap(), 0x0013);
        assert_eq!(layer.output_value(&data).unwrap(), 0xFF00);
    }

    #[test]
    fn test_mask_write_register() {
        // Mask Write Register: fc=0x16, ref_addr=0x0004, and=0x00F2, or=0x0025
        let data: Vec<u8> = vec![
            0x00, 0x01, // trans_id
            0x00, 0x00, // proto_id
            0x00, 0x08, // length (unit + fc + ref_addr + and_mask + or_mask = 1+1+2+2+2=8)
            0x01, // unit_id
            0x16, // func_code: Mask Write Register
            0x00, 0x04, // ref_addr
            0x00, 0xF2, // and_mask
            0x00, 0x25, // or_mask
        ];
        let layer = make_layer(&data);
        assert_eq!(layer.func_code(&data).unwrap(), 0x16);
        assert_eq!(layer.ref_addr(&data).unwrap(), 0x0004);
        assert_eq!(layer.and_mask(&data).unwrap(), 0x00F2);
        assert_eq!(layer.or_mask(&data).unwrap(), 0x0025);
    }

    #[test]
    fn test_layer_trait() {
        let data = read_coils_request();
        let layer = make_layer(&data);

        assert_eq!(layer.kind(), LayerKind::Modbus);
        assert!(!layer.field_names().is_empty());
        assert!(layer.field_names().contains(&"func_code"));
    }
}
