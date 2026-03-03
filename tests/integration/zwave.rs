//! Z-Wave wireless protocol integration tests.
//!
//! Tests Z-Wave frame building, CRC computation, field access,
//! ACK/REQ frame formats, and builder flags.

use stackforge_core::FieldValue;
use stackforge_core::layer::zwave::{
    ZWAVE_FIELD_NAMES, ZWAVE_HEADER_LEN, ZWAVE_MIN_HEADER_LEN, ZWaveBuilder, ZWaveLayer, cmd_class,
    zwave_crc,
};
use stackforge_core::layer::{LayerIndex, LayerKind};

fn make_layer(buf: &[u8]) -> ZWaveLayer {
    let idx = LayerIndex::new(LayerKind::ZWave, 0, buf.len());
    ZWaveLayer::new(idx)
}

// ============================================================================
// ACK frame build
// ============================================================================

#[test]
fn test_zwave_ack_frame_build() {
    let pkt = ZWaveBuilder::new()
        .home_id(0x0161F498)
        .src(1)
        .dst(2)
        .ack()
        .build();

    // ACK frames are exactly 10 bytes
    assert_eq!(pkt.len(), ZWAVE_HEADER_LEN);
    assert_eq!(pkt.len(), 10);

    let zw = make_layer(&pkt);
    assert_eq!(zw.home_id(&pkt).unwrap(), 0x0161F498);
    assert_eq!(zw.src(&pkt).unwrap(), 1);
    assert_eq!(zw.dst(&pkt).unwrap(), 2);
    assert!(zw.is_ack(&pkt));
    assert_eq!(zw.length(&pkt).unwrap(), 10);

    // Verify CRC is correct
    assert!(zw.verify_crc(&pkt));
}

// ============================================================================
// REQ frame build with BASIC SET command
// ============================================================================

#[test]
fn test_zwave_req_frame_build() {
    let pkt = ZWaveBuilder::new()
        .home_id(0xDEADBEEF)
        .src(3)
        .dst(5)
        .cmd_class(cmd_class::BASIC)
        .cmd(0x01)
        .cmd_data(vec![0xFF])
        .build();

    // 10 (base) + 3 (cmd_class + cmd + data) = 13
    assert_eq!(pkt.len(), 13);

    let zw = make_layer(&pkt);
    assert!(!zw.is_ack(&pkt));
    assert_eq!(zw.home_id(&pkt).unwrap(), 0xDEADBEEF);
    assert_eq!(zw.src(&pkt).unwrap(), 3);
    assert_eq!(zw.dst(&pkt).unwrap(), 5);
    assert_eq!(zw.cmd_class(&pkt).unwrap(), cmd_class::BASIC);
    assert_eq!(zw.cmd(&pkt).unwrap(), 0x01);
    assert_eq!(zw.cmd_data(&pkt).unwrap(), &[0xFF]);
    assert_eq!(zw.length(&pkt).unwrap(), 13);
    assert!(zw.verify_crc(&pkt));
}

// ============================================================================
// CRC computation
// ============================================================================

#[test]
fn test_zwave_crc_computation() {
    // zwave_crc XORs all bytes starting from 0xFF
    assert_eq!(zwave_crc(&[]), 0xFF);
    assert_eq!(zwave_crc(&[0xFF]), 0x00);
    assert_eq!(zwave_crc(&[0x00]), 0xFF);
    assert_eq!(zwave_crc(&[0x01, 0x02]), 0xFF ^ 0x01 ^ 0x02);

    // Verify CRC of a built frame: the CRC of all bytes except the last should
    // equal the last byte
    let pkt = ZWaveBuilder::new()
        .home_id(0x01020304)
        .src(10)
        .dst(20)
        .cmd_class(cmd_class::BASIC)
        .cmd(0x01)
        .build();
    let computed = zwave_crc(&pkt[..pkt.len() - 1]);
    assert_eq!(computed, pkt[pkt.len() - 1]);
}

// ============================================================================
// SWITCH_BINARY frame
// ============================================================================

#[test]
fn test_zwave_switch_binary() {
    let pkt = ZWaveBuilder::new()
        .home_id(0xAABBCCDD)
        .src(1)
        .dst(4)
        .cmd_class(cmd_class::SWITCH_BINARY)
        .cmd(0x01) // SET
        .cmd_data(vec![0xFF]) // ON
        .build();

    let zw = make_layer(&pkt);
    assert_eq!(zw.cmd_class(&pkt).unwrap(), cmd_class::SWITCH_BINARY);
    assert_eq!(zw.cmd(&pkt).unwrap(), 0x01);
    assert_eq!(zw.cmd_data(&pkt).unwrap(), &[0xFF]);
    assert!(zw.verify_crc(&pkt));
}

// ============================================================================
// Sensor Multilevel frame
// ============================================================================

#[test]
fn test_zwave_sensor_multilevel() {
    let pkt = ZWaveBuilder::new()
        .home_id(0x11223344)
        .src(5)
        .dst(1)
        .cmd_class(cmd_class::SENSOR_MULTILEVEL)
        .cmd(0x05) // REPORT
        .cmd_data(vec![0x01, 0x22, 0x00, 0xE4]) // type=temperature, precision=1, scale=C, value
        .build();

    let zw = make_layer(&pkt);
    assert_eq!(zw.cmd_class(&pkt).unwrap(), cmd_class::SENSOR_MULTILEVEL);
    assert_eq!(zw.cmd(&pkt).unwrap(), 0x05);
    let data = zw.cmd_data(&pkt).unwrap();
    assert_eq!(data.len(), 4);
    assert_eq!(data[0], 0x01); // temperature type
    assert!(zw.verify_crc(&pkt));
}

// ============================================================================
// Frame control bits encoding
// ============================================================================

#[test]
fn test_zwave_frame_control_bits() {
    // All flags set
    let pkt = ZWaveBuilder::new()
        .routed(true)
        .ackreq(true)
        .lowpower(true)
        .speedmodified(true)
        .headertype(0x03)
        .ack()
        .build();

    let zw = make_layer(&pkt);
    assert!(zw.routed(&pkt).unwrap());
    assert!(zw.ackreq(&pkt).unwrap());
    assert!(zw.lowpower(&pkt).unwrap());
    assert!(zw.speedmodified(&pkt).unwrap());
    assert_eq!(zw.headertype(&pkt).unwrap(), 0x03);

    // Verify the frame control byte directly (byte 5)
    // routed=0x80, ackreq=0x40, lowpower=0x20, speedmodified=0x10, headertype=0x03
    assert_eq!(pkt[5], 0x80 | 0x40 | 0x20 | 0x10 | 0x03);

    // All flags clear
    let pkt2 = ZWaveBuilder::new()
        .routed(false)
        .ackreq(false)
        .lowpower(false)
        .speedmodified(false)
        .headertype(0)
        .ack()
        .build();

    let zw2 = make_layer(&pkt2);
    assert!(!zw2.routed(&pkt2).unwrap());
    assert!(!zw2.ackreq(&pkt2).unwrap());
    assert!(!zw2.lowpower(&pkt2).unwrap());
    assert!(!zw2.speedmodified(&pkt2).unwrap());
    assert_eq!(zw2.headertype(&pkt2).unwrap(), 0);
    assert_eq!(pkt2[5], 0x00);
}

// ============================================================================
// Beam control and sequence number encoding
// ============================================================================

#[test]
fn test_zwave_beam_sequence() {
    let pkt = ZWaveBuilder::new().beam_control(2).seqn(0x0A).ack().build();

    let zw = make_layer(&pkt);
    assert_eq!(zw.beam_control(&pkt).unwrap(), 2);
    assert_eq!(zw.seqn(&pkt).unwrap(), 0x0A);

    // beam/seq byte: (beam_control << 5) | seqn = (2 << 5) | 0x0A = 0x4A
    assert_eq!(pkt[6], 0x4A);
}

// ============================================================================
// Home ID big-endian encoding
// ============================================================================

#[test]
fn test_zwave_home_id_big_endian() {
    let pkt = ZWaveBuilder::new().home_id(0x01020304).ack().build();

    // First 4 bytes should be big-endian Home ID
    assert_eq!(pkt[0], 0x01);
    assert_eq!(pkt[1], 0x02);
    assert_eq!(pkt[2], 0x03);
    assert_eq!(pkt[3], 0x04);

    let zw = make_layer(&pkt);
    assert_eq!(zw.home_id(&pkt).unwrap(), 0x01020304);
}

// ============================================================================
// Field names
// ============================================================================

#[test]
fn test_zwave_builder_field_names() {
    assert!(ZWAVE_FIELD_NAMES.contains(&"home_id"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"src"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"dst"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"routed"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"ackreq"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"lowpower"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"speedmodified"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"headertype"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"beam_control"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"seqn"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"length"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"cmd_class"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"cmd"));
    assert!(ZWAVE_FIELD_NAMES.contains(&"crc"));
}

// ============================================================================
// Header length constant
// ============================================================================

#[test]
fn test_zwave_header_len_constant() {
    assert_eq!(ZWAVE_HEADER_LEN, 10);
    assert_eq!(ZWAVE_MIN_HEADER_LEN, 10);
}

// ============================================================================
// CRC corruption detection
// ============================================================================

#[test]
fn test_zwave_crc_corruption_detected() {
    let pkt = ZWaveBuilder::new()
        .home_id(0xCAFEBABE)
        .src(1)
        .dst(2)
        .cmd_class(cmd_class::BASIC)
        .cmd(0x01)
        .build();

    let zw = make_layer(&pkt);
    assert!(zw.verify_crc(&pkt));

    // Corrupt a byte and verify CRC fails
    let mut bad = pkt.clone();
    bad[4] ^= 0x01;
    assert!(!zw.verify_crc(&bad));
}

// ============================================================================
// get_field API
// ============================================================================

#[test]
fn test_zwave_get_field_api() {
    let pkt = ZWaveBuilder::new()
        .home_id(0xAABBCCDD)
        .src(10)
        .dst(20)
        .seqn(5)
        .cmd_class(cmd_class::SWITCH_BINARY)
        .cmd(0x01)
        .build();

    let zw = make_layer(&pkt);

    match zw.get_field(&pkt, "home_id").unwrap().unwrap() {
        FieldValue::U32(v) => assert_eq!(v, 0xAABBCCDD),
        other => panic!("expected U32, got {:?}", other),
    }
    match zw.get_field(&pkt, "src").unwrap().unwrap() {
        FieldValue::U8(v) => assert_eq!(v, 10),
        other => panic!("expected U8, got {:?}", other),
    }
    match zw.get_field(&pkt, "dst").unwrap().unwrap() {
        FieldValue::U8(v) => assert_eq!(v, 20),
        other => panic!("expected U8, got {:?}", other),
    }
    match zw.get_field(&pkt, "seqn").unwrap().unwrap() {
        FieldValue::U8(v) => assert_eq!(v, 5),
        other => panic!("expected U8, got {:?}", other),
    }

    // Unknown field should return None
    assert!(zw.get_field(&pkt, "nonexistent").is_none());
}
