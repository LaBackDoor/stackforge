//! IEEE 802.11 (WiFi / Dot11) integration tests
//!
//! Tests cover frame parsing, building, FCS verification, dynamic field access,
//! information elements, and LayerEnum integration.

use stackforge_core::layer::dot11::ie::Dot11Elt;
use stackforge_core::layer::dot11::types;
use stackforge_core::layer::dot11::{
    Dot11Builder, Dot11FcsLayer, Dot11Layer, build_frame_control, crc32_ieee,
};
use stackforge_core::prelude::*;

// ============================================================================
// Helper functions for constructing raw frames
// ============================================================================

/// Build a minimal beacon frame (management, subtype 8).
/// FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SC(2) = 24 bytes.
fn make_beacon_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 24];
    // FC byte0: subtype=8, type=0, proto=0 => (8 << 4) | (0 << 2) | 0 = 0x80
    buf[0] = 0x80;
    buf[1] = 0x00;
    // Duration = 0
    buf[2] = 0x00;
    buf[3] = 0x00;
    // Addr1 (DA) = broadcast
    buf[4..10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Addr2 (SA)
    buf[10..16].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Addr3 (BSSID)
    buf[16..22].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Sequence Control: seq=1, frag=0 => (1 << 4) | 0 = 0x0010
    buf[22] = 0x10;
    buf[23] = 0x00;
    buf
}

/// Build an ACK frame (control, subtype 13).
/// ACK has only FC(2) + Duration(2) + Addr1(6) = 10 bytes.
fn make_ack_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 10];
    // FC byte0: subtype=13, type=1, proto=0 => (13 << 4) | (1 << 2) = 0xD4
    buf[0] = 0xD4;
    buf[1] = 0x00;
    // Duration
    buf[2] = 0x3A;
    buf[3] = 0x01; // 0x013A = 314 microseconds
    // Addr1
    buf[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    buf
}

/// Build a standard data frame (type=2, subtype=0, 3-address).
fn make_data_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 24];
    // FC byte0: subtype=0, type=2, proto=0 => (0 << 4) | (2 << 2) = 0x08
    buf[0] = 0x08;
    // FC byte1: to_DS=1 (station -> AP)
    buf[1] = types::fc_flags::TO_DS;
    // Duration
    buf[2] = 0x00;
    buf[3] = 0x00;
    // Addr1 (RA / BSSID)
    buf[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
    // Addr2 (TA / SA)
    buf[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    // Addr3 (DA)
    buf[16..22].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    // Sequence Control: seq=100, frag=3 => (100 << 4) | 3 = 0x0643
    buf[22] = 0x43;
    buf[23] = 0x06;
    buf
}

/// Build a WDS (4-address) data frame with to_DS=1 AND from_DS=1.
fn make_wds_data_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 30];
    // FC byte0: subtype=0, type=2 => 0x08
    buf[0] = 0x08;
    // FC byte1: to_DS=1 | from_DS=1 => 0x03
    buf[1] = types::fc_flags::TO_DS | types::fc_flags::FROM_DS;
    // Duration
    buf[2] = 0x00;
    buf[3] = 0x00;
    // Addr1 (RA)
    buf[4..10].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    // Addr2 (TA)
    buf[10..16].copy_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
    // Addr3 (DA)
    buf[16..22].copy_from_slice(&[0x21, 0x22, 0x23, 0x24, 0x25, 0x26]);
    // Sequence Control
    buf[22] = 0x00;
    buf[23] = 0x00;
    // Addr4 (SA)
    buf[24..30].copy_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
    buf
}

/// Build an RTS frame (control, subtype 11).
/// RTS has FC(2) + Duration(2) + Addr1(6) + Addr2(6) = 16 bytes.
fn make_rts_frame() -> Vec<u8> {
    let mut buf = vec![0u8; 16];
    // FC byte0: subtype=11, type=1 => (11 << 4) | (1 << 2) = 0xB4
    buf[0] = 0xB4;
    buf[1] = 0x00;
    // Duration
    buf[2] = 0x80;
    buf[3] = 0x00; // 128 microseconds
    // Addr1 (RA)
    buf[4..10].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
    // Addr2 (TA)
    buf[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    buf
}

// ============================================================================
// 1. Beacon frame parsing (type=0, subtype=8)
// ============================================================================

#[test]
fn test_beacon_frame_parsing() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(layer.protocol_version(&buf).unwrap(), 0);
    assert_eq!(
        layer.frame_type(&buf).unwrap(),
        types::frame_type::MANAGEMENT
    );
    assert_eq!(layer.subtype(&buf).unwrap(), types::mgmt_subtype::BEACON);
    assert_eq!(layer.flags(&buf).unwrap(), 0);
}

#[test]
fn test_beacon_addresses() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Addr1 is broadcast for beacons
    assert!(layer.addr1(&buf).unwrap().is_broadcast());
    // Addr2 is the transmitter
    assert_eq!(
        layer.addr2(&buf).unwrap(),
        MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    // Addr3 is the BSSID (same as transmitter for beacon)
    assert_eq!(
        layer.addr3(&buf).unwrap(),
        MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    // Beacons do not have addr4
    assert!(!layer.has_addr4(&buf));
}

// ============================================================================
// 2. ACK frame parsing (type=1, subtype=13)
// ============================================================================

#[test]
fn test_ack_frame_parsing() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::CONTROL);
    assert_eq!(layer.subtype(&buf).unwrap(), types::ctrl_subtype::ACK);
    assert!(layer.is_control(&buf));
}

#[test]
fn test_ack_frame_addr1() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(
        layer.addr1(&buf).unwrap(),
        MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    );
}

#[test]
fn test_ack_frame_duration() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Duration is 0x013A = 314
    assert_eq!(layer.duration(&buf).unwrap(), 0x013A);
}

// ============================================================================
// 3. Data frame parsing (type=2, subtype=0)
// ============================================================================

#[test]
fn test_data_frame_parsing() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::DATA);
    assert_eq!(layer.subtype(&buf).unwrap(), types::data_subtype::DATA);
    assert!(!layer.is_control(&buf));
}

#[test]
fn test_data_frame_addresses() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(
        layer.addr1(&buf).unwrap(),
        MacAddress::new([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03])
    );
    assert_eq!(
        layer.addr2(&buf).unwrap(),
        MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );
    assert_eq!(
        layer.addr3(&buf).unwrap(),
        MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
    );
    assert!(!layer.has_addr4(&buf));
}

#[test]
fn test_data_frame_to_ds_flag() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert!(layer.to_ds(&buf).unwrap());
    assert!(!layer.from_ds(&buf).unwrap());
}

// ============================================================================
// 4. WDS (4-address) data frame
// ============================================================================

#[test]
fn test_wds_frame_parsing() {
    let buf = make_wds_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::DATA);
    assert!(layer.to_ds(&buf).unwrap());
    assert!(layer.from_ds(&buf).unwrap());
    assert!(layer.has_addr4(&buf));
}

#[test]
fn test_wds_frame_all_addresses() {
    let buf = make_wds_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(
        layer.addr1(&buf).unwrap(),
        MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    );
    assert_eq!(
        layer.addr2(&buf).unwrap(),
        MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
    );
    assert_eq!(
        layer.addr3(&buf).unwrap(),
        MacAddress::new([0x21, 0x22, 0x23, 0x24, 0x25, 0x26])
    );
    assert_eq!(
        layer.addr4(&buf).unwrap(),
        MacAddress::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36])
    );
}

// ============================================================================
// 5. Frame control flags parsing
// ============================================================================

#[test]
fn test_all_flags_set() {
    let mut buf = make_beacon_frame();
    buf[1] = 0xFF; // All flags set
    let layer = Dot11Layer::new(0, buf.len());

    assert!(layer.to_ds(&buf).unwrap());
    assert!(layer.from_ds(&buf).unwrap());
    assert!(layer.more_frag(&buf).unwrap());
    assert!(layer.retry(&buf).unwrap());
    assert!(layer.pwr_mgt(&buf).unwrap());
    assert!(layer.more_data(&buf).unwrap());
    assert!(layer.protected(&buf).unwrap());
    assert!(layer.htc_order(&buf).unwrap());
    assert_eq!(layer.flags(&buf).unwrap(), 0xFF);
}

#[test]
fn test_no_flags_set() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert!(!layer.to_ds(&buf).unwrap());
    assert!(!layer.from_ds(&buf).unwrap());
    assert!(!layer.more_frag(&buf).unwrap());
    assert!(!layer.retry(&buf).unwrap());
    assert!(!layer.pwr_mgt(&buf).unwrap());
    assert!(!layer.more_data(&buf).unwrap());
    assert!(!layer.protected(&buf).unwrap());
    assert!(!layer.htc_order(&buf).unwrap());
}

#[test]
fn test_individual_flags() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Retry + Protected
    buf[1] = types::fc_flags::RETRY | types::fc_flags::PROTECTED;
    assert!(!layer.to_ds(&buf).unwrap());
    assert!(!layer.from_ds(&buf).unwrap());
    assert!(!layer.more_frag(&buf).unwrap());
    assert!(layer.retry(&buf).unwrap());
    assert!(!layer.pwr_mgt(&buf).unwrap());
    assert!(!layer.more_data(&buf).unwrap());
    assert!(layer.protected(&buf).unwrap());
    assert!(!layer.htc_order(&buf).unwrap());

    // Power management + More data
    buf[1] = types::fc_flags::PWR_MGT | types::fc_flags::MORE_DATA;
    assert!(layer.pwr_mgt(&buf).unwrap());
    assert!(layer.more_data(&buf).unwrap());
    assert!(!layer.retry(&buf).unwrap());
    assert!(!layer.protected(&buf).unwrap());
}

// ============================================================================
// 6. Duration and address fields
// ============================================================================

#[test]
fn test_duration_field() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Duration bytes [0x3A, 0x01] in little-endian = 0x013A = 314
    assert_eq!(layer.duration(&buf).unwrap(), 314);
}

#[test]
fn test_duration_zero() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(layer.duration(&buf).unwrap(), 0);
}

#[test]
fn test_rts_frame_addresses() {
    let buf = make_rts_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::CONTROL);
    assert_eq!(layer.subtype(&buf).unwrap(), types::ctrl_subtype::RTS);
    assert_eq!(
        layer.addr1(&buf).unwrap(),
        MacAddress::new([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03])
    );
    assert_eq!(
        layer.addr2(&buf).unwrap(),
        MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );
    assert_eq!(layer.duration(&buf).unwrap(), 128);
}

// ============================================================================
// 7. Sequence control parsing (fragment + sequence number)
// ============================================================================

#[test]
fn test_sequence_control_parsing() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // SC bytes [0x43, 0x06] in little-endian = 0x0643
    // Fragment number = lower 4 bits = 0x3 = 3
    // Sequence number = upper 12 bits = 0x0643 >> 4 = 100
    assert_eq!(layer.seq_ctrl_raw(&buf).unwrap(), 0x0643);
    assert_eq!(layer.fragment_num(&buf).unwrap(), 3);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 100);
}

#[test]
fn test_sequence_control_beacon() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // SC = 0x0010 => frag=0, seq=1
    assert_eq!(layer.seq_ctrl_raw(&buf).unwrap(), 0x0010);
    assert_eq!(layer.fragment_num(&buf).unwrap(), 0);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 1);
}

#[test]
fn test_sequence_control_max_values() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Max seq=4095 (0xFFF), max frag=15 (0xF) => SC = 0xFFFF
    buf[22] = 0xFF;
    buf[23] = 0xFF;
    assert_eq!(layer.fragment_num(&buf).unwrap(), 15);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 4095);
}

// ============================================================================
// 8. Header length calculation per frame type
// ============================================================================

#[test]
fn test_header_len_management() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    // Management frames: 24 bytes
    assert_eq!(layer.compute_header_len(&buf), 24);
}

#[test]
fn test_header_len_ack() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());
    // ACK (control): FC(2) + Duration(2) + Addr1(6) = 10
    assert_eq!(layer.compute_header_len(&buf), 10);
}

#[test]
fn test_header_len_cts() {
    let mut buf = vec![0u8; 10];
    // FC: type=1 (control), subtype=12 (CTS) => (12 << 4) | (1 << 2) = 0xC4
    buf[0] = 0xC4;
    buf[1] = 0x00;
    let layer = Dot11Layer::new(0, buf.len());
    // CTS: 10 bytes like ACK
    assert_eq!(layer.compute_header_len(&buf), 10);
}

#[test]
fn test_header_len_rts() {
    let buf = make_rts_frame();
    let layer = Dot11Layer::new(0, buf.len());
    // RTS (control, not ACK/CTS): FC(2) + Duration(2) + Addr1(6) + Addr2(6) = 16
    assert_eq!(layer.compute_header_len(&buf), 16);
}

#[test]
fn test_header_len_data_3addr() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());
    // Standard data frame: 24 bytes
    assert_eq!(layer.compute_header_len(&buf), 24);
}

#[test]
fn test_header_len_data_4addr_wds() {
    let buf = make_wds_data_frame();
    let layer = Dot11Layer::new(0, buf.len());
    // WDS data frame: 30 bytes
    assert_eq!(layer.compute_header_len(&buf), 30);
}

// ============================================================================
// 9. FCS layer with CRC32 verification
// ============================================================================

#[test]
fn test_crc32_known_value() {
    // The CRC32 of "123456789" is a well-known test vector.
    let data = b"123456789";
    assert_eq!(crc32_ieee(data), 0xCBF43926);
}

#[test]
fn test_crc32_empty() {
    assert_eq!(crc32_ieee(b""), 0x00000000);
}

#[test]
fn test_fcs_layer_creation_and_verification() {
    let frame = make_beacon_frame();
    let fcs = crc32_ieee(&frame);

    // Append FCS to the frame
    let mut frame_with_fcs = frame.clone();
    frame_with_fcs.extend_from_slice(&fcs.to_le_bytes());

    let fcs_layer = Dot11FcsLayer::new(0, frame_with_fcs.len());
    assert_eq!(fcs_layer.fcs(&frame_with_fcs).unwrap(), fcs);
    assert!(fcs_layer.verify_fcs(&frame_with_fcs).unwrap());
}

#[test]
fn test_fcs_layer_bad_fcs() {
    let frame = make_beacon_frame();
    let mut frame_with_fcs = frame.clone();
    // Append a wrong FCS value
    frame_with_fcs.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let fcs_layer = Dot11FcsLayer::new(0, frame_with_fcs.len());
    assert!(!fcs_layer.verify_fcs(&frame_with_fcs).unwrap());
}

#[test]
fn test_fcs_layer_delegates_to_dot11() {
    let frame = make_beacon_frame();
    let fcs = crc32_ieee(&frame);
    let mut frame_with_fcs = frame.clone();
    frame_with_fcs.extend_from_slice(&fcs.to_le_bytes());

    let fcs_layer = Dot11FcsLayer::new(0, frame_with_fcs.len());
    // Verify that delegated methods work correctly
    assert_eq!(
        fcs_layer.frame_type(&frame_with_fcs).unwrap(),
        types::frame_type::MANAGEMENT
    );
    assert_eq!(
        fcs_layer.subtype(&frame_with_fcs).unwrap(),
        types::mgmt_subtype::BEACON
    );
    assert_eq!(fcs_layer.flags(&frame_with_fcs).unwrap(), 0);
    assert!(fcs_layer.addr1(&frame_with_fcs).unwrap().is_broadcast());
    assert_eq!(
        fcs_layer.addr2(&frame_with_fcs).unwrap(),
        MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(fcs_layer.duration(&frame_with_fcs).unwrap(), 0);
}

#[test]
fn test_fcs_layer_summary_contains_fcs() {
    let frame = make_beacon_frame();
    let fcs = crc32_ieee(&frame);
    let mut frame_with_fcs = frame.clone();
    frame_with_fcs.extend_from_slice(&fcs.to_le_bytes());

    let fcs_layer = Dot11FcsLayer::new(0, frame_with_fcs.len());
    let summary = fcs_layer.summary(&frame_with_fcs);
    assert!(summary.contains("FCS="));
    assert!(summary.contains("Management"));
    assert!(summary.contains("Beacon"));
}

#[test]
fn test_fcs_compute_fcs_static() {
    let data = make_beacon_frame();
    let computed = Dot11FcsLayer::compute_fcs(&data);
    assert_eq!(computed, crc32_ieee(&data));
}

// ============================================================================
// 10. Dynamic field access (get_field / set_field)
// ============================================================================

#[test]
fn test_get_field_type_and_subtype() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let ft = layer.get_field(&buf, "type").unwrap().unwrap();
    assert_eq!(ft, FieldValue::U8(types::frame_type::MANAGEMENT));

    let st = layer.get_field(&buf, "subtype").unwrap().unwrap();
    assert_eq!(st, FieldValue::U8(types::mgmt_subtype::BEACON));
}

#[test]
fn test_get_field_proto_and_flags() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let proto = layer.get_field(&buf, "proto").unwrap().unwrap();
    assert_eq!(proto, FieldValue::U8(0));

    let fc_field = layer.get_field(&buf, "FCfield").unwrap().unwrap();
    assert_eq!(fc_field, FieldValue::U8(0));
}

#[test]
fn test_get_field_duration() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let id = layer.get_field(&buf, "ID").unwrap().unwrap();
    assert_eq!(id, FieldValue::U16(314));
}

#[test]
fn test_get_field_addresses() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let a1 = layer.get_field(&buf, "addr1").unwrap().unwrap();
    assert_eq!(a1, FieldValue::Mac(MacAddress::BROADCAST));

    let a2 = layer.get_field(&buf, "addr2").unwrap().unwrap();
    assert_eq!(
        a2,
        FieldValue::Mac(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );

    let a3 = layer.get_field(&buf, "addr3").unwrap().unwrap();
    assert_eq!(
        a3,
        FieldValue::Mac(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
}

#[test]
fn test_get_field_addr4_present() {
    let buf = make_wds_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let a4 = layer.get_field(&buf, "addr4").unwrap().unwrap();
    assert_eq!(
        a4,
        FieldValue::Mac(MacAddress::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36]))
    );
}

#[test]
fn test_get_field_addr4_absent() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // addr4 should return None when not a WDS frame
    assert!(layer.get_field(&buf, "addr4").is_none());
}

#[test]
fn test_get_field_seq_ctrl() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let sc = layer.get_field(&buf, "SC").unwrap().unwrap();
    assert_eq!(sc, FieldValue::U16(0x0643));
}

#[test]
fn test_get_field_unknown() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert!(layer.get_field(&buf, "nonexistent").is_none());
}

#[test]
fn test_set_field_duration() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    layer
        .set_field(&mut buf, "ID", FieldValue::U16(0xABCD))
        .unwrap()
        .unwrap();
    assert_eq!(layer.duration(&buf).unwrap(), 0xABCD);
}

#[test]
fn test_set_field_addr1() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let new_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    layer
        .set_field(&mut buf, "addr1", FieldValue::Mac(new_mac))
        .unwrap()
        .unwrap();
    assert_eq!(layer.addr1(&buf).unwrap(), new_mac);
}

#[test]
fn test_set_field_addr2() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let new_mac = MacAddress::new([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02]);
    layer
        .set_field(&mut buf, "addr2", FieldValue::Mac(new_mac))
        .unwrap()
        .unwrap();
    assert_eq!(layer.addr2(&buf).unwrap(), new_mac);
}

#[test]
fn test_set_field_addr3() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let new_mac = MacAddress::new([0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x03]);
    layer
        .set_field(&mut buf, "addr3", FieldValue::Mac(new_mac))
        .unwrap()
        .unwrap();
    assert_eq!(layer.addr3(&buf).unwrap(), new_mac);
}

#[test]
fn test_set_field_seq_ctrl() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Set SC to seq=200, frag=5 => (200 << 4) | 5 = 0x0C85
    layer
        .set_field(&mut buf, "SC", FieldValue::U16(0x0C85))
        .unwrap()
        .unwrap();
    assert_eq!(layer.seq_ctrl_raw(&buf).unwrap(), 0x0C85);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 200);
    assert_eq!(layer.fragment_num(&buf).unwrap(), 5);
}

#[test]
fn test_set_field_type_mismatch() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    // Attempt to set addr1 with a U16 value should produce TypeMismatch error
    let result = layer
        .set_field(&mut buf, "addr1", FieldValue::U16(42))
        .unwrap();
    assert!(result.is_err());
}

#[test]
fn test_set_field_unknown_returns_none() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    assert!(
        layer
            .set_field(&mut buf, "nonexistent", FieldValue::U8(0))
            .is_none()
    );
}

// ============================================================================
// 11. Builder -> parse roundtrip
// ============================================================================

#[test]
fn test_builder_beacon_roundtrip() {
    let bssid = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let buf = Dot11Builder::new()
        .frame_type(types::frame_type::MANAGEMENT)
        .subtype(types::mgmt_subtype::BEACON)
        .flags(0)
        .duration(0)
        .addr1(MacAddress::BROADCAST)
        .addr2(bssid)
        .addr3(bssid)
        .seq_ctrl(0x0020) // seq=2, frag=0
        .build();

    assert_eq!(buf.len(), 24);

    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(layer.protocol_version(&buf).unwrap(), 0);
    assert_eq!(
        layer.frame_type(&buf).unwrap(),
        types::frame_type::MANAGEMENT
    );
    assert_eq!(layer.subtype(&buf).unwrap(), types::mgmt_subtype::BEACON);
    assert!(layer.addr1(&buf).unwrap().is_broadcast());
    assert_eq!(layer.addr2(&buf).unwrap(), bssid);
    assert_eq!(layer.addr3(&buf).unwrap(), bssid);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 2);
    assert_eq!(layer.fragment_num(&buf).unwrap(), 0);
}

#[test]
fn test_builder_data_frame_roundtrip() {
    let ra = MacAddress::new([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
    let ta = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let da = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

    let buf = Dot11Builder::new()
        .frame_type(types::frame_type::DATA)
        .subtype(types::data_subtype::DATA)
        .flags(types::fc_flags::TO_DS)
        .duration(500)
        .addr1(ra)
        .addr2(ta)
        .addr3(da)
        .seq_ctrl(0x0321) // seq=50, frag=1
        .build();

    assert_eq!(buf.len(), 24);

    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::DATA);
    assert_eq!(layer.subtype(&buf).unwrap(), types::data_subtype::DATA);
    assert!(layer.to_ds(&buf).unwrap());
    assert!(!layer.from_ds(&buf).unwrap());
    assert_eq!(layer.duration(&buf).unwrap(), 500);
    assert_eq!(layer.addr1(&buf).unwrap(), ra);
    assert_eq!(layer.addr2(&buf).unwrap(), ta);
    assert_eq!(layer.addr3(&buf).unwrap(), da);
    assert_eq!(layer.sequence_num(&buf).unwrap(), 50);
    assert_eq!(layer.fragment_num(&buf).unwrap(), 1);
}

#[test]
fn test_builder_wds_frame_roundtrip() {
    let a1 = MacAddress::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    let a2 = MacAddress::new([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
    let a3 = MacAddress::new([0x21, 0x22, 0x23, 0x24, 0x25, 0x26]);
    let a4 = MacAddress::new([0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);

    let buf = Dot11Builder::new()
        .frame_type(types::frame_type::DATA)
        .subtype(types::data_subtype::DATA)
        .flags(types::fc_flags::TO_DS | types::fc_flags::FROM_DS)
        .addr1(a1)
        .addr2(a2)
        .addr3(a3)
        .addr4(a4)
        .build();

    assert_eq!(buf.len(), 30);

    let layer = Dot11Layer::new(0, buf.len());
    assert!(layer.has_addr4(&buf));
    assert_eq!(layer.addr4(&buf).unwrap(), a4);
    assert_eq!(layer.compute_header_len(&buf), 30);
}

#[test]
fn test_builder_defaults() {
    // Default builder creates a management frame with all zero addresses
    let buf = Dot11Builder::new().build();

    assert_eq!(buf.len(), 24);

    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(
        layer.frame_type(&buf).unwrap(),
        types::frame_type::MANAGEMENT
    );
    assert_eq!(layer.subtype(&buf).unwrap(), 0);
    assert!(layer.addr1(&buf).unwrap().is_broadcast());
    assert_eq!(layer.addr2(&buf).unwrap(), MacAddress::ZERO);
    assert_eq!(layer.addr3(&buf).unwrap(), MacAddress::ZERO);
    assert_eq!(layer.duration(&buf).unwrap(), 0);
}

// ============================================================================
// 12. LayerEnum integration (show_fields, field_names)
// ============================================================================

#[test]
fn test_layer_enum_dot11_field_names() {
    let layer = Dot11Layer::new(0, 24);
    let layer_enum = LayerEnum::Dot11(layer);

    let names = layer_enum.field_names();
    assert_eq!(
        names,
        &[
            "type", "subtype", "proto", "FCfield", "ID", "addr1", "addr2", "addr3", "SC", "addr4"
        ]
    );
}

#[test]
fn test_layer_enum_dot11_kind() {
    let layer = Dot11Layer::new(0, 24);
    let layer_enum = LayerEnum::Dot11(layer);
    assert_eq!(layer_enum.kind(), LayerKind::Dot11);
}

#[test]
fn test_layer_enum_dot11_summary() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    let summary = layer_enum.summary(&buf);
    assert!(summary.contains("Management"));
    assert!(summary.contains("Beacon"));
}

#[test]
fn test_layer_enum_show_fields() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    let fields = layer_enum.show_fields(&buf);
    assert!(!fields.is_empty());

    // Check that well-known field names are present
    let field_names: Vec<&str> = fields.iter().map(|(name, _)| *name).collect();
    assert!(field_names.contains(&"type"));
    assert!(field_names.contains(&"subtype"));
    assert!(field_names.contains(&"addr1"));
}

#[test]
fn test_layer_enum_get_field() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    let ft = layer_enum.get_field(&buf, "type").unwrap().unwrap();
    assert_eq!(ft, FieldValue::U8(0));

    let a1 = layer_enum.get_field(&buf, "addr1").unwrap().unwrap();
    assert_eq!(a1, FieldValue::Mac(MacAddress::BROADCAST));
}

#[test]
fn test_layer_enum_set_field() {
    let mut buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    layer_enum
        .set_field(&mut buf, "ID", FieldValue::U16(999))
        .unwrap()
        .unwrap();

    let id = layer_enum.get_field(&buf, "ID").unwrap().unwrap();
    assert_eq!(id, FieldValue::U16(999));
}

#[test]
fn test_layer_enum_hashret() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    let hash = layer_enum.hashret(&buf);
    // hashret should include addr1 (6 bytes) + addr2 (6 bytes) = 12 bytes
    assert_eq!(hash.len(), 12);
}

#[test]
fn test_layer_enum_header_len() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    let layer_enum = LayerEnum::Dot11(layer);

    assert_eq!(layer_enum.header_len(&buf), 24);
}

// ============================================================================
// 13. IE parsing (SSID element)
// ============================================================================

#[test]
fn test_ie_ssid_creation() {
    let ssid = Dot11Elt::ssid("TestNetwork");
    assert_eq!(ssid.id, 0);
    assert_eq!(ssid.len, 11);
    assert_eq!(ssid.info, b"TestNetwork");
    assert!(ssid.is_ssid());
    assert_eq!(ssid.ssid_str().unwrap(), "TestNetwork");
}

#[test]
fn test_ie_ssid_empty() {
    let ssid = Dot11Elt::ssid("");
    assert_eq!(ssid.id, 0);
    assert_eq!(ssid.len, 0);
    assert!(ssid.info.is_empty());
    assert!(ssid.is_ssid());
    assert_eq!(ssid.ssid_str().unwrap(), "");
}

#[test]
fn test_ie_generic_element() {
    let elt = Dot11Elt::new(3, vec![0x06]); // DS Parameter Set, channel 6
    assert_eq!(elt.id, 3);
    assert_eq!(elt.len, 1);
    assert_eq!(elt.info, vec![0x06]);
    assert!(!elt.is_ssid());
    assert!(elt.ssid_str().is_none());
}

#[test]
fn test_ie_build_and_parse_roundtrip() {
    let ssid = Dot11Elt::ssid("MyWiFi");
    let wire = ssid.build();

    // Wire format: [ID=0, Len=6, 'M', 'y', 'W', 'i', 'F', 'i']
    assert_eq!(wire.len(), 8); // 2 (header) + 6 (data)
    assert_eq!(wire[0], 0); // ID
    assert_eq!(wire[1], 6); // Length
    assert_eq!(&wire[2..], b"MyWiFi");

    // Parse back
    let (parsed, consumed) = Dot11Elt::parse(&wire, 0).unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(parsed.id, 0);
    assert_eq!(parsed.len, 6);
    assert_eq!(parsed.ssid_str().unwrap(), "MyWiFi");
}

#[test]
fn test_ie_parse_multiple_elements() {
    let ssid = Dot11Elt::ssid("Test");
    let rates = Dot11Elt::new(1, vec![0x82, 0x84, 0x8b, 0x96]); // Supported rates
    let ds_param = Dot11Elt::new(3, vec![0x01]); // Channel 1

    let mut wire = Vec::new();
    wire.extend_from_slice(&ssid.build());
    wire.extend_from_slice(&rates.build());
    wire.extend_from_slice(&ds_param.build());

    let elements = Dot11Elt::parse_all(&wire, 0);
    assert_eq!(elements.len(), 3);
    assert_eq!(elements[0].id, 0);
    assert_eq!(elements[0].ssid_str().unwrap(), "Test");
    assert_eq!(elements[1].id, 1);
    assert_eq!(elements[1].info.len(), 4);
    assert_eq!(elements[2].id, 3);
    assert_eq!(elements[2].info, vec![0x01]);
}

#[test]
fn test_ie_parse_at_offset() {
    // Simulate IEs starting after a beacon header
    let header = vec![0u8; 24]; // Dot11 header
    let fixed_params = vec![0u8; 12]; // Beacon fixed parameters (timestamp + interval + capability)
    let ssid = Dot11Elt::ssid("OffsetTest");

    let mut buf = Vec::new();
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&fixed_params);
    buf.extend_from_slice(&ssid.build());

    let offset = 24 + 12; // After header + fixed params
    let (parsed, consumed) = Dot11Elt::parse(&buf, offset).unwrap();
    assert_eq!(consumed, 2 + 10); // ID + Len + "OffsetTest"
    assert_eq!(parsed.ssid_str().unwrap(), "OffsetTest");
}

#[test]
fn test_ie_parse_truncated_buffer() {
    // Buffer too short for even the ID/Len header
    let buf = vec![0x00]; // Only 1 byte
    let result = Dot11Elt::parse(&buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_ie_parse_truncated_data() {
    // Header says length=10, but only 3 bytes of data available
    let buf = vec![0x00, 0x0A, 0x41, 0x42, 0x43];
    let result = Dot11Elt::parse(&buf, 0);
    assert!(result.is_err());
}

#[test]
fn test_ie_parse_all_with_truncation() {
    // Two valid elements, followed by truncated data
    let ssid = Dot11Elt::ssid("OK");
    let mut wire = ssid.build();
    wire.push(0x03); // ID for DS params
    wire.push(0xFF); // Invalid length (way too long)

    let elements = Dot11Elt::parse_all(&wire, 0);
    // Should parse the first SSID element and stop at the truncated one
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].ssid_str().unwrap(), "OK");
}

// ============================================================================
// 14. Summary output
// ============================================================================

#[test]
fn test_summary_beacon() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let summary = layer.summary(&buf);
    assert!(summary.contains("802.11"));
    assert!(summary.contains("Management"));
    assert!(summary.contains("Beacon"));
    // Should contain addr2 and addr1
    assert!(summary.contains("00:11:22:33:44:55"));
    assert!(summary.contains("ff:ff:ff:ff:ff:ff"));
}

#[test]
fn test_summary_ack() {
    let buf = make_ack_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let summary = layer.summary(&buf);
    assert!(summary.contains("802.11"));
    assert!(summary.contains("Control"));
    assert!(summary.contains("Ack"));
    assert!(summary.contains("aa:bb:cc:dd:ee:ff"));
}

#[test]
fn test_summary_data() {
    let buf = make_data_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let summary = layer.summary(&buf);
    assert!(summary.contains("802.11"));
    assert!(summary.contains("Data"));
}

#[test]
fn test_summary_rts() {
    let buf = make_rts_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let summary = layer.summary(&buf);
    assert!(summary.contains("802.11"));
    assert!(summary.contains("Control"));
    assert!(summary.contains("RTS"));
}

// ============================================================================
// Additional: build_frame_control helper
// ============================================================================

#[test]
fn test_build_frame_control_beacon() {
    let fc = build_frame_control(
        0,
        types::frame_type::MANAGEMENT,
        types::mgmt_subtype::BEACON,
        0,
    );
    // byte0: (8 << 4) | (0 << 2) | 0 = 0x80, byte1: 0x00
    assert_eq!(fc.to_le_bytes(), [0x80, 0x00]);
}

#[test]
fn test_build_frame_control_ack() {
    let fc = build_frame_control(0, types::frame_type::CONTROL, types::ctrl_subtype::ACK, 0);
    // byte0: (13 << 4) | (1 << 2) | 0 = 0xD4, byte1: 0x00
    assert_eq!(fc.to_le_bytes(), [0xD4, 0x00]);
}

#[test]
fn test_build_frame_control_data_with_flags() {
    let fc = build_frame_control(
        0,
        types::frame_type::DATA,
        types::data_subtype::DATA,
        types::fc_flags::TO_DS,
    );
    // byte0: (0 << 4) | (2 << 2) | 0 = 0x08, byte1: 0x01 (to_DS)
    assert_eq!(fc.to_le_bytes(), [0x08, 0x01]);
}

#[test]
fn test_build_frame_control_roundtrip() {
    let fc = build_frame_control(
        0,
        types::frame_type::DATA,
        types::data_subtype::QOS_DATA,
        types::fc_flags::PROTECTED | types::fc_flags::FROM_DS,
    );
    let mut buf = vec![0u8; 24];
    buf[0..2].copy_from_slice(&fc.to_le_bytes());

    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(layer.protocol_version(&buf).unwrap(), 0);
    assert_eq!(layer.frame_type(&buf).unwrap(), types::frame_type::DATA);
    assert_eq!(layer.subtype(&buf).unwrap(), types::data_subtype::QOS_DATA);
    assert!(layer.protected(&buf).unwrap());
    assert!(layer.from_ds(&buf).unwrap());
    assert!(!layer.to_ds(&buf).unwrap());
}

// ============================================================================
// Additional: hashret and answers
// ============================================================================

#[test]
fn test_hashret_composition() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());

    let hash = layer.hashret(&buf);
    // hashret = addr1 (6 bytes) + addr2 (6 bytes)
    assert_eq!(hash.len(), 12);
    assert_eq!(&hash[0..6], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(&hash[6..12], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
}

#[test]
fn test_answers_management_assoc_req_resp() {
    // Association Request (subtype=0)
    let mut req = vec![0u8; 24];
    req[0] = 0x00; // type=0, subtype=0
    req[4..10].copy_from_slice(&[0xBB; 6]); // addr1
    req[10..16].copy_from_slice(&[0xAA; 6]); // addr2

    // Association Response (subtype=1)
    let mut resp = vec![0u8; 24];
    resp[0] = 0x10; // type=0, subtype=1
    resp[4..10].copy_from_slice(&[0xAA; 6]); // addr1 = req's addr2
    resp[10..16].copy_from_slice(&[0xBB; 6]); // addr2 = req's addr1

    let req_layer = Dot11Layer::new(0, req.len());
    let resp_layer = Dot11Layer::new(0, resp.len());

    // Response answers request
    assert!(resp_layer.answers(&resp, &req_layer, &req));
    // Request does not answer response
    assert!(!req_layer.answers(&req, &resp_layer, &resp));
}

#[test]
fn test_answers_different_types_returns_false() {
    let mgmt = make_beacon_frame();
    let ctrl = make_ack_frame();

    let mgmt_layer = Dot11Layer::new(0, mgmt.len());
    let ctrl_layer = Dot11Layer::new(0, ctrl.len());

    assert!(!mgmt_layer.answers(&mgmt, &ctrl_layer, &ctrl));
    assert!(!ctrl_layer.answers(&ctrl, &mgmt_layer, &mgmt));
}

#[test]
fn test_answers_control_always_false() {
    let ack1 = make_ack_frame();
    let ack2 = make_ack_frame();

    let layer1 = Dot11Layer::new(0, ack1.len());
    let layer2 = Dot11Layer::new(0, ack2.len());

    // Control frames never answer each other
    assert!(!layer1.answers(&ack1, &layer2, &ack2));
}

// ============================================================================
// Additional: Layer trait implementation
// ============================================================================

#[test]
fn test_layer_trait_kind() {
    let layer = Dot11Layer::new(0, 24);
    assert_eq!(layer.kind(), LayerKind::Dot11);
}

#[test]
fn test_layer_trait_header_len() {
    let buf = make_beacon_frame();
    let layer = Dot11Layer::new(0, buf.len());
    assert_eq!(layer.header_len(&buf), 24);

    let ack_buf = make_ack_frame();
    let ack_layer = Dot11Layer::new(0, ack_buf.len());
    assert_eq!(ack_layer.header_len(&ack_buf), 10);
}

#[test]
fn test_layer_trait_field_names() {
    let layer = Dot11Layer::new(0, 24);
    let names = layer.field_names();
    assert_eq!(names.len(), 10);
    assert!(names.contains(&"type"));
    assert!(names.contains(&"subtype"));
    assert!(names.contains(&"proto"));
    assert!(names.contains(&"FCfield"));
    assert!(names.contains(&"ID"));
    assert!(names.contains(&"addr1"));
    assert!(names.contains(&"addr2"));
    assert!(names.contains(&"addr3"));
    assert!(names.contains(&"SC"));
    assert!(names.contains(&"addr4"));
}

// ============================================================================
// Additional: Validation
// ============================================================================

#[test]
fn test_validate_sufficient_buffer() {
    let buf = vec![0u8; 24];
    assert!(Dot11Layer::validate(&buf, 0).is_ok());
}

#[test]
fn test_validate_insufficient_buffer() {
    let buf = vec![0u8; 5]; // Less than DOT11_MIN_HEADER_LEN (10)
    assert!(Dot11Layer::validate(&buf, 0).is_err());
}

#[test]
fn test_validate_with_offset() {
    let buf = vec![0u8; 20];
    // Offset 10 + 10 (min header) = 20, exactly fits
    assert!(Dot11Layer::validate(&buf, 10).is_ok());
    // Offset 11 + 10 = 21 > 20, does not fit
    assert!(Dot11Layer::validate(&buf, 11).is_err());
}
