//! Modbus protocol integration tests.
//!
//! Tests Modbus/TCP (MBAP), RTU, and ASCII frame building, parsing,
//! field access, and error handling.

use stackforge_core::layer::modbus::{
    MODBUS_FIELD_NAMES, MODBUS_MBAP_HEADER_LEN, MODBUS_MIN_HEADER_LEN, MODBUS_TCP_PORT,
    ModbusBuilder, ModbusLayer, except_code, except_code_name, func_code, func_code_name,
    is_modbus_tcp_payload, verify_crc16, verify_lrc,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap Modbus bytes in Eth/IP/TCP/Modbus full-stack packet
// ============================================================================

fn build_modbus_stack_packet(modbus_builder: ModbusBuilder) -> Packet {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(10, 0, 0, 1))
                .dst(Ipv4Addr::new(10, 0, 0, 100))
                .ttl(64),
        ))
        .push(LayerStackEntry::Tcp(
            TcpBuilder::new().src_port(49152).dst_port(502),
        ))
        .push(LayerStackEntry::Modbus(modbus_builder))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(buf: &[u8]) -> ModbusLayer {
    let idx = LayerIndex::new(LayerKind::Modbus, 0, buf.len());
    ModbusLayer::new(idx)
}

// ============================================================================
// Read Coils request (fc=0x01) -- build and parse
// ============================================================================

#[test]
fn test_modbus_read_coils_request() {
    let pkt = build_modbus_stack_packet(
        ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(func_code::READ_COILS)
            .start_addr(0x0000)
            .quantity(10),
    );

    assert!(pkt.get_layer(LayerKind::Modbus).is_some());

    let mb = pkt.modbus().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(mb.trans_id(buf).unwrap(), 1);
    assert_eq!(mb.unit_id(buf).unwrap(), 1);
    assert_eq!(mb.func_code(buf).unwrap(), func_code::READ_COILS);
    assert_eq!(mb.start_addr(buf).unwrap(), 0x0000);
    assert_eq!(mb.quantity(buf).unwrap(), 10);
    assert!(!mb.is_error(buf));
}

// ============================================================================
// Read Coils response -- parse raw bytes
// ============================================================================

#[test]
fn test_modbus_read_coils_response() {
    // Response: trans_id=1, proto=0, length=4, unit=1, fc=0x01, byte_count=1, data=0xCD
    let raw: Vec<u8> = vec![
        0x00, 0x01, // trans_id
        0x00, 0x00, // proto_id
        0x00, 0x04, // length (unit + fc + byte_count + coil_data = 1+1+1+1=4)
        0x01, // unit_id
        0x01, // func_code: Read Coils response
        0x01, // byte_count
        0xCD, // coil status (bits 0-7 of coils 0-7)
    ];

    assert!(is_modbus_tcp_payload(&raw));
    let layer = make_layer(&raw);
    assert_eq!(layer.trans_id(&raw).unwrap(), 1);
    assert_eq!(layer.func_code(&raw).unwrap(), func_code::READ_COILS);
    assert_eq!(layer.byte_count(&raw).unwrap(), 1);
    assert!(!layer.is_error(&raw));
}

// ============================================================================
// Read Holding Registers -- build and parse
// ============================================================================

#[test]
fn test_modbus_read_holding_registers() {
    let raw = ModbusBuilder::new()
        .trans_id(42)
        .unit_id(0x11)
        .func_code(func_code::READ_HOLDING_REGISTERS)
        .start_addr(0x006B)
        .quantity(3)
        .build();

    assert!(is_modbus_tcp_payload(&raw));
    let layer = make_layer(&raw);
    assert_eq!(layer.trans_id(&raw).unwrap(), 42);
    assert_eq!(layer.unit_id(&raw).unwrap(), 0x11);
    assert_eq!(
        layer.func_code(&raw).unwrap(),
        func_code::READ_HOLDING_REGISTERS
    );
    assert_eq!(layer.start_addr(&raw).unwrap(), 0x006B);
    assert_eq!(layer.quantity(&raw).unwrap(), 3);
}

// ============================================================================
// Write Single Coil -- build and parse
// ============================================================================

#[test]
fn test_modbus_write_single_coil() {
    let raw = ModbusBuilder::new()
        .trans_id(2)
        .unit_id(1)
        .func_code(func_code::WRITE_SINGLE_COIL)
        .start_addr(0x0013)
        .output_value(0xFF00) // ON
        .build();

    let layer = make_layer(&raw);
    assert_eq!(layer.func_code(&raw).unwrap(), func_code::WRITE_SINGLE_COIL);
    assert_eq!(layer.start_addr(&raw).unwrap(), 0x0013);
    assert_eq!(layer.output_value(&raw).unwrap(), 0xFF00);
}

// ============================================================================
// Write Single Register -- build and parse
// ============================================================================

#[test]
fn test_modbus_write_single_register() {
    let raw = ModbusBuilder::new()
        .trans_id(3)
        .unit_id(1)
        .func_code(func_code::WRITE_SINGLE_REGISTER)
        .start_addr(0x0001)
        .output_value(0x0003)
        .build();

    let layer = make_layer(&raw);
    assert_eq!(
        layer.func_code(&raw).unwrap(),
        func_code::WRITE_SINGLE_REGISTER
    );
    assert_eq!(layer.start_addr(&raw).unwrap(), 0x0001);
    assert_eq!(layer.register_val(&raw).unwrap(), 0x0003);
}

// ============================================================================
// Error response -- parse and check except_code
// ============================================================================

#[test]
fn test_modbus_error_response() {
    // Error: trans_id=1, proto=0, length=3, unit=1, fc=0x81 (error), except=0x02
    let raw: Vec<u8> = vec![
        0x00, 0x01, // trans_id
        0x00, 0x00, // proto_id
        0x00, 0x03, // length
        0x01, // unit_id
        0x81, // func_code with error bit set (0x80 | READ_COILS)
        0x02, // except_code: Illegal Data Address
    ];

    let layer = make_layer(&raw);
    assert!(layer.is_error(&raw));
    assert_eq!(layer.func_code(&raw).unwrap(), 0x81);
    assert_eq!(
        layer.except_code(&raw).unwrap(),
        except_code::ILLEGAL_DATA_ADDRESS
    );

    let summary = layer.summary(&raw);
    assert!(summary.contains("Error"));
    assert!(summary.contains("Illegal Data Address"));
}

// ============================================================================
// Layer detection on port 502
// ============================================================================

#[test]
fn test_modbus_layer_detection() {
    let pkt = build_modbus_stack_packet(
        ModbusBuilder::new()
            .trans_id(1)
            .unit_id(1)
            .func_code(func_code::READ_COILS)
            .start_addr(0)
            .quantity(1),
    );

    assert!(pkt.get_layer(LayerKind::Modbus).is_some());

    let tcp = pkt.tcp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tcp.dst_port(buf).unwrap(), 502);
}

// ============================================================================
// MBAP header fields
// ============================================================================

#[test]
fn test_modbus_mbap_fields() {
    let raw = ModbusBuilder::new()
        .trans_id(0xABCD)
        .proto_id(0x0000)
        .unit_id(0x0F)
        .func_code(func_code::READ_DISCRETE_INPUTS)
        .start_addr(0x0100)
        .quantity(20)
        .build();

    let layer = make_layer(&raw);
    assert_eq!(layer.trans_id(&raw).unwrap(), 0xABCD);
    assert_eq!(layer.proto_id(&raw).unwrap(), 0x0000);
    assert_eq!(layer.unit_id(&raw).unwrap(), 0x0F);
    // Length should be: unit_id(1) + func_code(1) + data(4) = 6
    assert_eq!(layer.length(&raw).unwrap(), 6);
}

// ============================================================================
// Builder TCP mode
// ============================================================================

#[test]
fn test_modbus_builder_tcp() {
    let raw = ModbusBuilder::new()
        .tcp()
        .trans_id(0)
        .unit_id(0)
        .func_code(0)
        .build();

    // MBAP header (7) + func_code (1) = 8 bytes minimum
    assert_eq!(raw.len(), 8);
    // Protocol ID should be 0x0000
    assert_eq!(&raw[2..4], &[0x00, 0x00]);
}

// ============================================================================
// Field names
// ============================================================================

#[test]
fn test_modbus_field_names() {
    assert!(MODBUS_FIELD_NAMES.contains(&"trans_id"));
    assert!(MODBUS_FIELD_NAMES.contains(&"proto_id"));
    assert!(MODBUS_FIELD_NAMES.contains(&"length"));
    assert!(MODBUS_FIELD_NAMES.contains(&"unit_id"));
    assert!(MODBUS_FIELD_NAMES.contains(&"func_code"));
    assert!(MODBUS_FIELD_NAMES.contains(&"except_code"));
    assert!(MODBUS_FIELD_NAMES.contains(&"start_addr"));
    assert!(MODBUS_FIELD_NAMES.contains(&"quantity"));
    assert!(MODBUS_FIELD_NAMES.contains(&"byte_count"));
    assert!(MODBUS_FIELD_NAMES.contains(&"data"));
}

// ============================================================================
// RTU frame build and CRC verification
// ============================================================================

#[test]
fn test_modbus_rtu_frame_crc() {
    let raw = ModbusBuilder::new()
        .rtu()
        .unit_id(1)
        .func_code(func_code::READ_HOLDING_REGISTERS)
        .start_addr(0x0000)
        .quantity(10)
        .build();

    // slave(1) + fc(1) + addr(2) + qty(2) + crc(2) = 8
    assert_eq!(raw.len(), 8);
    assert_eq!(raw[0], 1); // slave addr
    assert_eq!(raw[1], 0x03); // func code
    assert!(verify_crc16(&raw));
}

// ============================================================================
// ASCII frame build and LRC verification
// ============================================================================

#[test]
fn test_modbus_ascii_frame_lrc() {
    let raw = ModbusBuilder::new()
        .ascii()
        .unit_id(1)
        .func_code(func_code::READ_HOLDING_REGISTERS)
        .start_addr(0x0000)
        .quantity(10)
        .build();

    // ASCII frame: ':' + hex data + CR + LF
    assert_eq!(raw[0], b':');
    assert_eq!(raw[raw.len() - 2], b'\r');
    assert_eq!(raw[raw.len() - 1], b'\n');

    // Decode the hex content and verify LRC
    let hex_str = &raw[1..raw.len() - 2];
    let mut decoded = Vec::new();
    for chunk in hex_str.chunks(2) {
        let high = from_hex(chunk[0]);
        let low = from_hex(chunk[1]);
        decoded.push((high << 4) | low);
    }
    assert!(verify_lrc(&decoded));
}

fn from_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => c - b'A' + 10,
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

// ============================================================================
// Write Multiple Registers
// ============================================================================

#[test]
fn test_modbus_write_multiple_registers() {
    let raw = ModbusBuilder::new()
        .trans_id(3)
        .unit_id(1)
        .func_code(func_code::WRITE_MULTIPLE_REGISTERS)
        .start_addr(0x0001)
        .values(vec![0x000A, 0x0102])
        .build();

    let layer = make_layer(&raw);
    assert_eq!(
        layer.func_code(&raw).unwrap(),
        func_code::WRITE_MULTIPLE_REGISTERS
    );
    assert_eq!(layer.start_addr(&raw).unwrap(), 0x0001);
    assert_eq!(layer.quantity(&raw).unwrap(), 2);
}

// ============================================================================
// Mask Write Register
// ============================================================================

#[test]
fn test_modbus_mask_write_register() {
    let raw = ModbusBuilder::new()
        .trans_id(1)
        .unit_id(1)
        .func_code(func_code::MASK_WRITE_REGISTER)
        .start_addr(0x0004)
        .and_mask(0x00F2)
        .or_mask(0x0025)
        .build();

    let layer = make_layer(&raw);
    assert_eq!(
        layer.func_code(&raw).unwrap(),
        func_code::MASK_WRITE_REGISTER
    );
    assert_eq!(layer.ref_addr(&raw).unwrap(), 0x0004);
    assert_eq!(layer.and_mask(&raw).unwrap(), 0x00F2);
    assert_eq!(layer.or_mask(&raw).unwrap(), 0x0025);
}

// ============================================================================
// Detection helpers
// ============================================================================

#[test]
fn test_modbus_detection_invalid_proto_id() {
    let mut raw = ModbusBuilder::new()
        .trans_id(1)
        .unit_id(1)
        .func_code(func_code::READ_COILS)
        .start_addr(0)
        .quantity(1)
        .build();

    // Corrupt protocol ID
    raw[2] = 0x01;
    assert!(!is_modbus_tcp_payload(&raw));
}

#[test]
fn test_modbus_detection_too_short() {
    assert!(!is_modbus_tcp_payload(&[0x00; 7]));
    assert!(!is_modbus_tcp_payload(&[]));
}

// ============================================================================
// get_field / set_field API
// ============================================================================

#[test]
fn test_modbus_get_set_field() {
    let mut raw = ModbusBuilder::new()
        .trans_id(1)
        .unit_id(1)
        .func_code(func_code::READ_COILS)
        .start_addr(0)
        .quantity(10)
        .build();

    let layer = make_layer(&raw);

    // get_field
    assert_eq!(
        layer.get_field(&raw, "trans_id").unwrap().unwrap(),
        FieldValue::U16(1)
    );
    assert_eq!(
        layer.get_field(&raw, "func_code").unwrap().unwrap(),
        FieldValue::U8(func_code::READ_COILS)
    );
    assert!(layer.get_field(&raw, "nonexistent").is_none());

    // set_field
    layer
        .set_field(&mut raw, "trans_id", FieldValue::U16(999))
        .unwrap()
        .unwrap();
    assert_eq!(layer.trans_id(&raw).unwrap(), 999);
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_modbus_constants() {
    assert_eq!(MODBUS_TCP_PORT, 502);
    assert_eq!(MODBUS_MBAP_HEADER_LEN, 7);
    assert_eq!(MODBUS_MIN_HEADER_LEN, 8);
}

// ============================================================================
// Function code and exception code names
// ============================================================================

#[test]
fn test_modbus_func_code_names() {
    assert_eq!(func_code_name(func_code::READ_COILS), "Read Coils");
    assert_eq!(
        func_code_name(func_code::READ_HOLDING_REGISTERS),
        "Read Holding Registers"
    );
    assert_eq!(
        func_code_name(func_code::WRITE_SINGLE_COIL),
        "Write Single Coil"
    );
    assert_eq!(
        func_code_name(func_code::WRITE_SINGLE_REGISTER),
        "Write Single Register"
    );
    assert_eq!(
        func_code_name(func_code::WRITE_MULTIPLE_REGISTERS),
        "Write Multiple Registers"
    );
    // Error bit should be stripped for name lookup
    assert_eq!(func_code_name(0x81), "Read Coils");
    assert_eq!(func_code_name(0xFF), "Unknown");
}

#[test]
fn test_modbus_except_code_names() {
    assert_eq!(
        except_code_name(except_code::ILLEGAL_FUNCTION),
        "Illegal Function"
    );
    assert_eq!(
        except_code_name(except_code::ILLEGAL_DATA_ADDRESS),
        "Illegal Data Address"
    );
    assert_eq!(
        except_code_name(except_code::ILLEGAL_DATA_VALUE),
        "Illegal Data Value"
    );
    assert_eq!(
        except_code_name(except_code::SERVER_DEVICE_FAILURE),
        "Server Device Failure"
    );
    assert_eq!(except_code_name(0xFF), "Unknown");
}
