//! Modbus packet builder.
//!
//! Provides a fluent API for constructing Modbus/TCP, RTU, and ASCII frames.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::modbus::builder::ModbusBuilder;
//!
//! // Read Coils Request (Modbus/TCP)
//! let pkt = ModbusBuilder::new()
//!     .trans_id(1)
//!     .unit_id(1)
//!     .func_code(0x01)
//!     .start_addr(0x0000)
//!     .quantity(10)
//!     .build();
//! assert_eq!(pkt.len(), 12);
//! ```

use super::ModbusFrameType;
use super::crc::{modbus_crc16, modbus_lrc};

/// Builder for Modbus packets.
///
/// Supports three frame types:
/// - **TCP (MBAP)**: Default. Adds a 7-byte MBAP header.
/// - **RTU**: Binary serial framing with CRC-16 appended.
/// - **ASCII**: Hex-encoded with ':' prefix, LRC, and CRLF suffix.
#[derive(Debug, Clone)]
pub struct ModbusBuilder {
    frame_type: ModbusFrameType,
    trans_id: u16,
    proto_id: u16,
    unit_id: u8,
    func_code: u8,
    /// Raw PDU data bytes (after function code).
    pdu_data: Vec<u8>,
    // Convenience fields for common request types
    start_addr: Option<u16>,
    quantity: Option<u16>,
    output_value: Option<u16>,
    values: Vec<u16>,
    coil_values: Vec<bool>,
    sub_func: Option<u16>,
    and_mask: Option<u16>,
    or_mask: Option<u16>,
    /// Extra data bytes for diagnostics, file records, etc.
    extra_data: Vec<u8>,
}

impl Default for ModbusBuilder {
    fn default() -> Self {
        Self {
            frame_type: ModbusFrameType::Tcp,
            trans_id: 0,
            proto_id: 0,
            unit_id: 0,
            func_code: 0,
            pdu_data: Vec::new(),
            start_addr: None,
            quantity: None,
            output_value: None,
            values: Vec::new(),
            coil_values: Vec::new(),
            sub_func: None,
            and_mask: None,
            or_mask: None,
            extra_data: Vec::new(),
        }
    }
}

impl ModbusBuilder {
    /// Create a new Modbus builder with TCP (MBAP) framing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // Frame type setters
    // ========================================================================

    /// Use Modbus/TCP (MBAP) framing (default).
    #[must_use]
    pub fn tcp(mut self) -> Self {
        self.frame_type = ModbusFrameType::Tcp;
        self
    }

    /// Use Modbus RTU (serial binary) framing.
    #[must_use]
    pub fn rtu(mut self) -> Self {
        self.frame_type = ModbusFrameType::Rtu;
        self
    }

    /// Use Modbus ASCII (serial hex-encoded) framing.
    #[must_use]
    pub fn ascii(mut self) -> Self {
        self.frame_type = ModbusFrameType::Ascii;
        self
    }

    // ========================================================================
    // Field setters
    // ========================================================================

    /// Set the Transaction ID (MBAP only).
    #[must_use]
    pub fn trans_id(mut self, id: u16) -> Self {
        self.trans_id = id;
        self
    }

    /// Set the Protocol ID (MBAP only; should be 0x0000).
    #[must_use]
    pub fn proto_id(mut self, id: u16) -> Self {
        self.proto_id = id;
        self
    }

    /// Set the Unit ID / Slave Address.
    #[must_use]
    pub fn unit_id(mut self, id: u8) -> Self {
        self.unit_id = id;
        self
    }

    /// Set the Function Code.
    #[must_use]
    pub fn func_code(mut self, fc: u8) -> Self {
        self.func_code = fc;
        self
    }

    /// Set the Start Address (for Read/Write requests).
    #[must_use]
    pub fn start_addr(mut self, addr: u16) -> Self {
        self.start_addr = Some(addr);
        self
    }

    /// Set the Quantity (for Read requests).
    #[must_use]
    pub fn quantity(mut self, qty: u16) -> Self {
        self.quantity = Some(qty);
        self
    }

    /// Set the Output Value (for Write Single Coil/Register).
    #[must_use]
    pub fn output_value(mut self, val: u16) -> Self {
        self.output_value = Some(val);
        self
    }

    /// Set register values (for Write Multiple Registers).
    #[must_use]
    pub fn values(mut self, vals: Vec<u16>) -> Self {
        self.values = vals;
        self
    }

    /// Set coil values (for Write Multiple Coils).
    #[must_use]
    pub fn coil_values(mut self, vals: Vec<bool>) -> Self {
        self.coil_values = vals;
        self
    }

    /// Set the Sub-function code (for Diagnostics 0x08).
    #[must_use]
    pub fn sub_func(mut self, sf: u16) -> Self {
        self.sub_func = Some(sf);
        self
    }

    /// Set the AND mask (for Mask Write Register 0x16).
    #[must_use]
    pub fn and_mask(mut self, mask: u16) -> Self {
        self.and_mask = Some(mask);
        self
    }

    /// Set the OR mask (for Mask Write Register 0x16).
    #[must_use]
    pub fn or_mask(mut self, mask: u16) -> Self {
        self.or_mask = Some(mask);
        self
    }

    /// Set raw PDU data (after the function code).
    /// This overrides the automatic PDU building.
    #[must_use]
    pub fn pdu_data(mut self, data: Vec<u8>) -> Self {
        self.pdu_data = data;
        self
    }

    /// Set extra data bytes (for diagnostics data field, etc.).
    #[must_use]
    pub fn extra_data(mut self, data: Vec<u8>) -> Self {
        self.extra_data = data;
        self
    }

    // ========================================================================
    // Build
    // ========================================================================

    /// Build the PDU data bytes (everything after the function code).
    fn build_pdu(&self) -> Vec<u8> {
        // If raw PDU data is set, use it directly
        if !self.pdu_data.is_empty() {
            return self.pdu_data.clone();
        }

        let mut pdu = Vec::new();

        match self.func_code {
            // Read Coils, Read Discrete Inputs, Read Holding Registers, Read Input Registers
            0x01..=0x04 => {
                let addr = self.start_addr.unwrap_or(0);
                let qty = self.quantity.unwrap_or(1);
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&qty.to_be_bytes());
            },
            // Write Single Coil
            0x05 => {
                let addr = self.start_addr.unwrap_or(0);
                let val = self.output_value.unwrap_or(0xFF00);
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&val.to_be_bytes());
            },
            // Write Single Register
            0x06 => {
                let addr = self.start_addr.unwrap_or(0);
                let val = self.output_value.unwrap_or(0);
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&val.to_be_bytes());
            },
            // Read Exception Status, Report Slave ID
            0x07 | 0x11 => {
                // No data bytes in request
            },
            // Diagnostics
            0x08 => {
                let sf = self.sub_func.unwrap_or(0);
                pdu.extend_from_slice(&sf.to_be_bytes());
                pdu.extend_from_slice(&self.extra_data);
            },
            // Get Comm Event Counter, Get Comm Event Log
            0x0B | 0x0C => {
                // No data bytes in request
            },
            // Write Multiple Coils
            0x0F => {
                let addr = self.start_addr.unwrap_or(0);
                let qty = if self.coil_values.is_empty() {
                    self.quantity.unwrap_or(0)
                } else {
                    self.coil_values.len() as u16
                };
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&qty.to_be_bytes());

                if self.coil_values.is_empty() {
                    pdu.push(0); // byte count = 0
                } else {
                    // Pack booleans into bytes (LSB first)
                    let byte_count = self.coil_values.len().div_ceil(8);
                    pdu.push(byte_count as u8);
                    let mut bytes = vec![0u8; byte_count];
                    for (i, &coil) in self.coil_values.iter().enumerate() {
                        if coil {
                            bytes[i / 8] |= 1 << (i % 8);
                        }
                    }
                    pdu.extend_from_slice(&bytes);
                }
            },
            // Write Multiple Registers
            0x10 => {
                let addr = self.start_addr.unwrap_or(0);
                let qty = if self.values.is_empty() {
                    self.quantity.unwrap_or(0)
                } else {
                    self.values.len() as u16
                };
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&qty.to_be_bytes());

                let byte_count = (self.values.len() * 2) as u8;
                pdu.push(byte_count);
                for &val in &self.values {
                    pdu.extend_from_slice(&val.to_be_bytes());
                }
            },
            // Mask Write Register
            0x16 => {
                let addr = self.start_addr.unwrap_or(0);
                let and = self.and_mask.unwrap_or(0xFFFF);
                let or = self.or_mask.unwrap_or(0x0000);
                pdu.extend_from_slice(&addr.to_be_bytes());
                pdu.extend_from_slice(&and.to_be_bytes());
                pdu.extend_from_slice(&or.to_be_bytes());
            },
            // Read/Write Multiple Registers
            0x17 => {
                // Read part
                let read_addr = self.start_addr.unwrap_or(0);
                let read_qty = self.quantity.unwrap_or(0);
                pdu.extend_from_slice(&read_addr.to_be_bytes());
                pdu.extend_from_slice(&read_qty.to_be_bytes());
                // Write part: use extra_data for write address + quantity + byte_count + values
                pdu.extend_from_slice(&self.extra_data);
            },
            // Read FIFO Queue
            0x18 => {
                let addr = self.start_addr.unwrap_or(0);
                pdu.extend_from_slice(&addr.to_be_bytes());
            },
            // Encapsulated Interface Transport (MEI)
            0x2B => {
                pdu.extend_from_slice(&self.extra_data);
            },
            // Default: no automatic PDU data
            _ => {
                pdu.extend_from_slice(&self.extra_data);
            },
        }

        pdu
    }

    /// Compute the header size for this builder.
    #[must_use]
    pub fn header_size(&self) -> usize {
        match self.frame_type {
            ModbusFrameType::Tcp => {
                // MBAP (7) + func_code (1) + PDU data
                7 + 1 + self.build_pdu().len()
            },
            ModbusFrameType::Rtu => {
                // slave (1) + func_code (1) + PDU data + CRC (2)
                1 + 1 + self.build_pdu().len() + 2
            },
            ModbusFrameType::Ascii => {
                // ':' + hex(slave + fc + pdu + lrc) + CR + LF
                let inner_len = 1 + 1 + self.build_pdu().len() + 1; // slave + fc + pdu + lrc
                1 + inner_len * 2 + 2
            },
        }
    }

    /// Build the Modbus frame into bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let pdu = self.build_pdu();

        match self.frame_type {
            ModbusFrameType::Tcp => {
                let mut buf = Vec::with_capacity(7 + 1 + pdu.len());
                // MBAP header
                buf.extend_from_slice(&self.trans_id.to_be_bytes()); // Transaction ID
                buf.extend_from_slice(&self.proto_id.to_be_bytes()); // Protocol ID
                let length = (1 + 1 + pdu.len()) as u16; // unit_id + func_code + pdu_data
                buf.extend_from_slice(&length.to_be_bytes()); // Length
                buf.push(self.unit_id); // Unit ID
                buf.push(self.func_code); // Function Code
                buf.extend_from_slice(&pdu); // PDU data
                buf
            },
            ModbusFrameType::Rtu => {
                let mut frame = Vec::with_capacity(1 + 1 + pdu.len() + 2);
                frame.push(self.unit_id); // Slave Address
                frame.push(self.func_code); // Function Code
                frame.extend_from_slice(&pdu); // Data
                let crc = modbus_crc16(&frame);
                frame.push((crc & 0xFF) as u8); // CRC low byte
                frame.push((crc >> 8) as u8); // CRC high byte
                frame
            },
            ModbusFrameType::Ascii => {
                let mut inner = Vec::new();
                inner.push(self.unit_id);
                inner.push(self.func_code);
                inner.extend_from_slice(&pdu);
                let lrc = modbus_lrc(&inner);
                inner.push(lrc);

                // Encode as ASCII hex
                let mut buf = Vec::with_capacity(1 + inner.len() * 2 + 2);
                buf.push(b':');
                for &byte in &inner {
                    buf.push(hex_char(byte >> 4));
                    buf.push(hex_char(byte & 0x0F));
                }
                buf.push(b'\r');
                buf.push(b'\n');
                buf
            },
        }
    }
}

/// Convert a nibble (0-15) to its ASCII hex character (uppercase).
fn hex_char(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + (nibble - 10),
        _ => b'?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::modbus::crc::{verify_crc16, verify_lrc};
    use crate::layer::modbus::{ModbusLayer, is_modbus_tcp_payload};
    use crate::layer::{LayerIndex, LayerKind};

    #[test]
    fn test_read_coils_tcp() {
        let pkt = ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(0x01)
            .start_addr(0x0000)
            .quantity(10)
            .build();

        assert_eq!(pkt.len(), 12);
        assert!(is_modbus_tcp_payload(&pkt));

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.trans_id(&pkt).unwrap(), 1);
        assert_eq!(layer.unit_id(&pkt).unwrap(), 1);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x01);
        assert_eq!(layer.start_addr(&pkt).unwrap(), 0);
        assert_eq!(layer.quantity(&pkt).unwrap(), 10);
    }

    #[test]
    fn test_write_single_coil_tcp() {
        let pkt = ModbusBuilder::new()
            .trans_id(2)
            .unit_id(1)
            .func_code(0x05)
            .start_addr(0x0013)
            .output_value(0xFF00)
            .build();

        assert_eq!(pkt.len(), 12);

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x05);
        assert_eq!(layer.start_addr(&pkt).unwrap(), 0x0013);
        assert_eq!(layer.output_value(&pkt).unwrap(), 0xFF00);
    }

    #[test]
    fn test_write_multiple_registers_tcp() {
        let pkt = ModbusBuilder::new()
            .trans_id(3)
            .unit_id(1)
            .func_code(0x10)
            .start_addr(0x0001)
            .values(vec![0x000A, 0x0102])
            .build();

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x10);
        assert_eq!(layer.start_addr(&pkt).unwrap(), 0x0001);
        // quantity (from values.len())
        assert_eq!(layer.quantity(&pkt).unwrap(), 2);
    }

    #[test]
    fn test_mask_write_register_tcp() {
        let pkt = ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(0x16)
            .start_addr(0x0004)
            .and_mask(0x00F2)
            .or_mask(0x0025)
            .build();

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x16);
        assert_eq!(layer.ref_addr(&pkt).unwrap(), 0x0004);
        assert_eq!(layer.and_mask(&pkt).unwrap(), 0x00F2);
        assert_eq!(layer.or_mask(&pkt).unwrap(), 0x0025);
    }

    #[test]
    fn test_rtu_frame() {
        let pkt = ModbusBuilder::new()
            .rtu()
            .unit_id(1)
            .func_code(0x03)
            .start_addr(0x0000)
            .quantity(10)
            .build();

        // slave(1) + fc(1) + addr(2) + qty(2) + crc(2) = 8
        assert_eq!(pkt.len(), 8);
        assert_eq!(pkt[0], 1); // slave addr
        assert_eq!(pkt[1], 0x03); // func code
        assert!(verify_crc16(&pkt));
    }

    #[test]
    fn test_ascii_frame() {
        let pkt = ModbusBuilder::new()
            .ascii()
            .unit_id(1)
            .func_code(0x03)
            .start_addr(0x0000)
            .quantity(10)
            .build();

        // Should start with ':' and end with CRLF
        assert_eq!(pkt[0], b':');
        assert_eq!(pkt[pkt.len() - 2], b'\r');
        assert_eq!(pkt[pkt.len() - 1], b'\n');

        // Decode the hex content and verify LRC
        let hex_str = &pkt[1..pkt.len() - 2];
        let mut decoded = Vec::new();
        for chunk in hex_str.chunks(2) {
            let high = from_hex_char(chunk[0]).unwrap();
            let low = from_hex_char(chunk[1]).unwrap();
            decoded.push((high << 4) | low);
        }
        assert!(verify_lrc(&decoded));
    }

    #[test]
    fn test_default_builder() {
        let pkt = ModbusBuilder::new().build();
        // MBAP header (7) + func_code (1) = 8 bytes minimum
        assert_eq!(pkt.len(), 8);
        assert_eq!(pkt[7], 0); // func_code = 0
    }

    #[test]
    fn test_raw_pdu_data() {
        let pkt = ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(0x03)
            .pdu_data(vec![0x00, 0x00, 0x00, 0x0A])
            .build();

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x03);
        assert_eq!(layer.start_addr(&pkt).unwrap(), 0x0000);
        assert_eq!(layer.quantity(&pkt).unwrap(), 0x000A);
    }

    #[test]
    fn test_write_multiple_coils_tcp() {
        let pkt = ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(0x0F)
            .start_addr(0x0013)
            .coil_values(vec![
                true, false, true, true, false, false, true, true, true, false,
            ])
            .build();

        let idx = LayerIndex::new(LayerKind::Modbus, 0, pkt.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.func_code(&pkt).unwrap(), 0x0F);
        assert_eq!(layer.start_addr(&pkt).unwrap(), 0x0013);
        // Quantity = 10 coils
        assert_eq!(layer.quantity(&pkt).unwrap(), 10);
    }

    #[test]
    fn test_round_trip_read_holding_registers() {
        let original = ModbusBuilder::new()
            .trans_id(42)
            .unit_id(0x11)
            .func_code(0x03)
            .start_addr(0x006B)
            .quantity(3)
            .build();

        assert!(is_modbus_tcp_payload(&original));

        let idx = LayerIndex::new(LayerKind::Modbus, 0, original.len());
        let layer = ModbusLayer::new(idx);
        assert_eq!(layer.trans_id(&original).unwrap(), 42);
        assert_eq!(layer.unit_id(&original).unwrap(), 0x11);
        assert_eq!(layer.func_code(&original).unwrap(), 0x03);
        assert_eq!(layer.start_addr(&original).unwrap(), 0x006B);
        assert_eq!(layer.quantity(&original).unwrap(), 3);
    }

    /// Helper to decode a hex character.
    fn from_hex_char(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
}
