//! IEEE 802.15.4 (Dot15d4 / Zigbee) integration tests
//!
//! Covers frame building, parsing, roundtrip verification, FCS computation,
//! dynamic field access, summary output, and LayerEnum integration.

use stackforge_core::layer::dot15d4::{
    self, Dot15d4FcsLayer, Dot15d4Layer,
    builder::{Dot15d4Builder, Dot15d4FcsBuilder},
    crc, types,
};
use stackforge_core::prelude::*;

// ============================================================================
// 1. Data frame with short addresses (build -> parse roundtrip)
// ============================================================================

#[test]
fn test_data_frame_short_addr_roundtrip() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(true)
        .panid_compress(true)
        .seqnum(42)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .build();

    // Expected: FCF(2) + seqnum(1) + dest_panid(2) + dest_short(2) + src_short(2) = 9
    assert_eq!(frame.len(), 9);

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::DATA
    );
    assert!(layer.fcf_ackreq(&frame).unwrap());
    assert!(layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 42);
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0xFFFF));
    // PAN ID compressed: src_panid should be None
    assert_eq!(layer.src_panid(&frame).unwrap(), None);
    assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x0001));
}

#[test]
fn test_data_frame_short_addr_no_compression() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .seqnum(10)
        .dest_panid(0xAAAA)
        .dest_addr_short(0x0002)
        .src_panid(0xBBBB)
        .src_addr_short(0x0003)
        .build();

    // FCF(2) + seqnum(1) + dest_panid(2) + dest_short(2) + src_panid(2) + src_short(2) = 11
    assert_eq!(frame.len(), 11);

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(!layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0xAAAA));
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0x0002));
    assert_eq!(layer.src_panid(&frame).unwrap(), Some(0xBBBB));
    assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x0003));
}

// ============================================================================
// 2. Data frame with long addresses (build -> parse roundtrip)
// ============================================================================

#[test]
fn test_data_frame_long_addr_roundtrip() {
    let dest_long: u64 = 0x0102030405060708;
    let src_long: u64 = 0x1112131415161718;

    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .seqnum(99)
        .dest_panid(0xCAFE)
        .dest_addr_long(dest_long)
        .src_panid(0xBEEF)
        .src_addr_long(src_long)
        .build();

    // FCF(2) + seqnum(1) + dest_panid(2) + dest_long(8) + src_panid(2) + src_long(8) = 23
    assert_eq!(frame.len(), 23);

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::DATA
    );
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::LONG
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::LONG
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 99);
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0xCAFE));
    assert_eq!(layer.dest_addr_long(&frame).unwrap(), Some(dest_long));
    assert_eq!(layer.src_panid(&frame).unwrap(), Some(0xBEEF));
    assert_eq!(layer.src_addr_long(&frame).unwrap(), Some(src_long));
}

#[test]
fn test_data_frame_mixed_addr_modes() {
    // Destination short, source long
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .seqnum(7)
        .dest_panid(0x1111)
        .dest_addr_short(0x0042)
        .src_panid(0x2222)
        .src_addr_long(0xAABBCCDDEEFF0011)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::LONG
    );
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0x0042));
    assert_eq!(
        layer.src_addr_long(&frame).unwrap(),
        Some(0xAABBCCDDEEFF0011)
    );
    // Short addr accessor on long-mode field should return None
    assert_eq!(layer.dest_addr_long(&frame).unwrap(), None);
    assert_eq!(layer.src_addr_short(&frame).unwrap(), None);
}

// ============================================================================
// 3. ACK frame (minimal, no addresses)
// ============================================================================

#[test]
fn test_ack_frame_minimal() {
    let frame = Dot15d4Builder::ack().seqnum(200).build();

    // ACK: FCF(2) + seqnum(1) = 3 bytes
    assert_eq!(frame.len(), 3);

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(layer.fcf_frametype(&frame).unwrap(), types::frame_type::ACK);
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 200);
    // No addresses present
    assert_eq!(layer.dest_panid(&frame).unwrap(), None);
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), None);
    assert_eq!(layer.dest_addr_long(&frame).unwrap(), None);
    assert_eq!(layer.src_panid(&frame).unwrap(), None);
    assert_eq!(layer.src_addr_short(&frame).unwrap(), None);
    assert_eq!(layer.src_addr_long(&frame).unwrap(), None);
}

#[test]
fn test_ack_answers_data_frame() {
    let data_frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(true)
        .seqnum(55)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let ack_frame = Dot15d4Builder::ack().seqnum(55).build();

    let data_layer = Dot15d4Layer::new(0, data_frame.len());
    let ack_layer = Dot15d4Layer::new(0, ack_frame.len());

    // ACK should answer the data frame
    assert!(ack_layer.answers(&ack_frame, &data_layer, &data_frame));

    // Data frame should NOT answer ACK
    assert!(!data_layer.answers(&data_frame, &ack_layer, &ack_frame));
}

#[test]
fn test_ack_does_not_answer_without_ackreq() {
    let data_frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(false)
        .seqnum(55)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let ack_frame = Dot15d4Builder::ack().seqnum(55).build();

    let data_layer = Dot15d4Layer::new(0, data_frame.len());
    let ack_layer = Dot15d4Layer::new(0, ack_frame.len());

    // ACK should NOT answer if ackreq was false
    assert!(!ack_layer.answers(&ack_frame, &data_layer, &data_frame));
}

#[test]
fn test_ack_wrong_seqnum_does_not_answer() {
    let data_frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(true)
        .seqnum(55)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let ack_frame = Dot15d4Builder::ack().seqnum(56).build();

    let data_layer = Dot15d4Layer::new(0, data_frame.len());
    let ack_layer = Dot15d4Layer::new(0, ack_frame.len());

    assert!(!ack_layer.answers(&ack_frame, &data_layer, &data_frame));
}

// ============================================================================
// 4. Beacon frame
// ============================================================================

#[test]
fn test_beacon_frame() {
    let frame = Dot15d4Builder::beacon().seqnum(0).build();

    // Beacon with no addressing: FCF(2) + seqnum(1) = 3
    assert_eq!(frame.len(), 3);

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::BEACON
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 0);
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
}

#[test]
fn test_beacon_frame_with_src_addr() {
    let frame = Dot15d4Builder::beacon()
        .seqnum(3)
        .src_panid(0xABCD)
        .src_addr_short(0x0000) // coordinator
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::BEACON
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
    assert_eq!(layer.src_panid(&frame).unwrap(), Some(0xABCD));
    assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x0000));
}

// ============================================================================
// 5. PAN ID compression
// ============================================================================

#[test]
fn test_panid_compression_enabled() {
    let frame = Dot15d4Builder::new()
        .panid_compress(true)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));
    // Source PAN ID is compressed (not present in frame)
    assert_eq!(layer.src_panid(&frame).unwrap(), None);
    assert_eq!(layer.src_addr_short(&frame).unwrap(), Some(0x0001));

    // Frame should be shorter due to compression (no src_panid 2 bytes)
    let frame_no_compress = Dot15d4Builder::new()
        .panid_compress(false)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .src_panid(0x1234)
        .src_addr_short(0x0001)
        .build();

    assert_eq!(frame.len() + 2, frame_no_compress.len());
}

#[test]
fn test_panid_compression_disabled() {
    let frame = Dot15d4Builder::new()
        .panid_compress(false)
        .dest_panid(0xAAAA)
        .dest_addr_short(0x0001)
        .src_panid(0xBBBB)
        .src_addr_short(0x0002)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(!layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0xAAAA));
    assert_eq!(layer.src_panid(&frame).unwrap(), Some(0xBBBB));
}

// ============================================================================
// 6. FCS computation and verification
// ============================================================================

#[test]
fn test_crc_ccitt_kermit_known_value() {
    // Known test vector from Kermit protocol
    let data = b"123456789";
    assert_eq!(crc::crc_ccitt_kermit(data), 0x2189);
}

#[test]
fn test_crc_empty() {
    assert_eq!(crc::crc_ccitt_kermit(&[]), 0x0000);
}

#[test]
fn test_compute_fcs_bytes() {
    let data = b"123456789";
    let fcs = crc::compute_fcs(data);
    // 0x2189 little-endian => [0x89, 0x21]
    assert_eq!(fcs, [0x89, 0x21]);
}

#[test]
fn test_verify_fcs_correct() {
    let frame_data = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .seqnum(5)
        .build();

    let expected_crc = crc::crc_ccitt_kermit(&frame_data);
    assert!(crc::verify_fcs(&frame_data, expected_crc));
}

#[test]
fn test_verify_fcs_incorrect() {
    let frame_data = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .seqnum(5)
        .build();

    assert!(!crc::verify_fcs(&frame_data, 0x0000));
}

#[test]
fn test_fcs_deterministic() {
    let data = [0x41, 0x88, 0x05, 0xFF, 0xFF, 0x34, 0x12];
    let crc1 = crc::crc_ccitt_kermit(&data);
    let crc2 = crc::crc_ccitt_kermit(&data);
    assert_eq!(crc1, crc2);
}

#[test]
fn test_fcs_layer_verify() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(10)
        .dest_panid(0xABCD)
        .dest_addr_short(0x0001)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
}

#[test]
fn test_fcs_layer_verify_corrupt() {
    let mut frame = Dot15d4FcsBuilder::new()
        .seqnum(10)
        .dest_panid(0xABCD)
        .dest_addr_short(0x0001)
        .build();

    // Corrupt the last byte (FCS)
    let len = frame.len();
    frame[len - 1] ^= 0xFF;

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(!layer.verify_fcs(&frame).unwrap());
}

// ============================================================================
// 7. FCS builder -> parse roundtrip
// ============================================================================

#[test]
fn test_fcs_builder_data_roundtrip() {
    let frame = Dot15d4FcsBuilder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(true)
        .panid_compress(true)
        .seqnum(77)
        .dest_panid(0xBEEF)
        .dest_addr_short(0x1234)
        .src_addr_short(0x5678)
        .build();

    // Header(9) + FCS(2) = 11
    assert_eq!(frame.len(), 11);

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::DATA
    );
    assert!(layer.fcf_ackreq(&frame).unwrap());
    assert!(layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.seqnum(&frame).unwrap(), 77);
}

#[test]
fn test_fcs_builder_ack_roundtrip() {
    let frame = Dot15d4FcsBuilder::ack().seqnum(99).build();

    // FCF(2) + seqnum(1) + FCS(2) = 5
    assert_eq!(frame.len(), 5);

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
    assert_eq!(layer.fcf_frametype(&frame).unwrap(), types::frame_type::ACK);
    assert_eq!(layer.seqnum(&frame).unwrap(), 99);
}

#[test]
fn test_fcs_builder_from_inner_builder() {
    let inner = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .seqnum(33)
        .dest_panid(0x1111)
        .dest_addr_short(0x2222);

    let fcs_builder = Dot15d4FcsBuilder::from_builder(inner);
    let frame = fcs_builder.build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
    assert_eq!(layer.seqnum(&frame).unwrap(), 33);
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::DATA
    );
}

#[test]
fn test_fcs_builder_beacon_roundtrip() {
    let frame = Dot15d4FcsBuilder::beacon().seqnum(0).build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::BEACON
    );
}

#[test]
fn test_fcs_builder_command_roundtrip() {
    let frame = Dot15d4FcsBuilder::command()
        .seqnum(15)
        .dest_panid(0x1234)
        .dest_addr_short(0x0001)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert!(layer.verify_fcs(&frame).unwrap());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::MAC_CMD
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 15);
}

#[test]
fn test_fcs_builder_total_size() {
    let builder = Dot15d4FcsBuilder::ack();
    assert_eq!(builder.total_size(), 5); // 3 + 2

    let builder = Dot15d4FcsBuilder::new()
        .dest_addr_short(0xFFFF)
        .panid_compress(true)
        .src_addr_short(0x0001);
    assert_eq!(builder.total_size(), 11); // 9 + 2
}

// ============================================================================
// 8. Frame control field parsing (all FCF flags)
// ============================================================================

#[test]
fn test_fcf_all_flags_set() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .security(true)
        .pending(true)
        .ackreq(true)
        .panid_compress(true)
        .frame_ver(1)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::DATA
    );
    assert!(layer.fcf_security(&frame).unwrap());
    assert!(layer.fcf_pending(&frame).unwrap());
    assert!(layer.fcf_ackreq(&frame).unwrap());
    assert!(layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.fcf_framever(&frame).unwrap(), 1);
}

#[test]
fn test_fcf_all_flags_cleared() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .security(false)
        .pending(false)
        .ackreq(false)
        .panid_compress(false)
        .frame_ver(0)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(!layer.fcf_security(&frame).unwrap());
    assert!(!layer.fcf_pending(&frame).unwrap());
    assert!(!layer.fcf_ackreq(&frame).unwrap());
    assert!(!layer.fcf_panidcompress(&frame).unwrap());
    assert_eq!(layer.fcf_framever(&frame).unwrap(), 0);
}

#[test]
fn test_fcf_frame_version_values() {
    for ver in 0..=3u8 {
        let frame = Dot15d4Builder::new()
            .frame_ver(ver)
            .dest_panid(0xFFFF)
            .dest_addr_short(0xFFFF)
            .build();

        let layer = Dot15d4Layer::new(0, frame.len());
        assert_eq!(layer.fcf_framever(&frame).unwrap(), ver);
    }
}

// ============================================================================
// 9. Address mode detection
// ============================================================================

#[test]
fn test_addr_mode_none() {
    let frame = Dot15d4Builder::new().no_dest_addr().no_src_addr().build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::NONE
    );
}

#[test]
fn test_addr_mode_short() {
    let frame = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_short(0x5678)
        .src_panid(0xABCD)
        .src_addr_short(0xEF01)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::SHORT
    );
}

#[test]
fn test_addr_mode_long() {
    let frame = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_long(0x0102030405060708)
        .src_panid(0xABCD)
        .src_addr_long(0x1112131415161718)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_destaddrmode(&frame).unwrap(),
        types::addr_mode::LONG
    );
    assert_eq!(
        layer.fcf_srcaddrmode(&frame).unwrap(),
        types::addr_mode::LONG
    );
}

#[test]
fn test_addr_mode_len_constants() {
    assert_eq!(types::addr_mode_len(types::addr_mode::NONE), 0);
    assert_eq!(types::addr_mode_len(types::addr_mode::SHORT), 2);
    assert_eq!(types::addr_mode_len(types::addr_mode::LONG), 8);
}

// ============================================================================
// 10. Dynamic field access (get_field / set_field)
// ============================================================================

#[test]
fn test_get_field_fcf_frametype() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let val = layer.get_field(&frame, "fcf_frametype").unwrap().unwrap();
    assert_eq!(val.as_u8(), Some(types::frame_type::DATA));
}

#[test]
fn test_get_field_fcf_booleans() {
    let frame = Dot15d4Builder::new()
        .ackreq(true)
        .pending(false)
        .security(false)
        .panid_compress(true)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());

    let ackreq = layer.get_field(&frame, "fcf_ackreq").unwrap().unwrap();
    assert_eq!(ackreq.as_bool(), Some(true));

    let pending = layer.get_field(&frame, "fcf_pending").unwrap().unwrap();
    assert_eq!(pending.as_bool(), Some(false));

    let security = layer.get_field(&frame, "fcf_security").unwrap().unwrap();
    assert_eq!(security.as_bool(), Some(false));

    let compress = layer
        .get_field(&frame, "fcf_panidcompress")
        .unwrap()
        .unwrap();
    assert_eq!(compress.as_bool(), Some(true));
}

#[test]
fn test_get_field_seqnum() {
    let frame = Dot15d4Builder::new()
        .seqnum(42)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let val = layer.get_field(&frame, "seqnum").unwrap().unwrap();
    assert_eq!(val.as_u8(), Some(42));
}

#[test]
fn test_get_field_addresses() {
    let frame = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_short(0x5678)
        .src_panid(0xABCD)
        .src_addr_short(0xEF01)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());

    let dest_panid = layer.get_field(&frame, "dest_panid").unwrap().unwrap();
    assert_eq!(dest_panid.as_u16(), Some(0x1234));

    let dest_addr = layer.get_field(&frame, "dest_addr_short").unwrap().unwrap();
    assert_eq!(dest_addr.as_u16(), Some(0x5678));

    let src_panid = layer.get_field(&frame, "src_panid").unwrap().unwrap();
    assert_eq!(src_panid.as_u16(), Some(0xABCD));

    let src_addr = layer.get_field(&frame, "src_addr_short").unwrap().unwrap();
    assert_eq!(src_addr.as_u16(), Some(0xEF01));
}

#[test]
fn test_get_field_unknown_returns_none() {
    let frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(layer.get_field(&frame, "nonexistent_field").is_none());
}

#[test]
fn test_set_field_seqnum() {
    let mut frame = Dot15d4Builder::new()
        .seqnum(10)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(layer.seqnum(&frame).unwrap(), 10);

    layer
        .set_field(&mut frame, "seqnum", FieldValue::U8(20))
        .unwrap()
        .unwrap();
    assert_eq!(layer.seqnum(&frame).unwrap(), 20);
}

#[test]
fn test_set_field_fcf_ackreq() {
    let mut frame = Dot15d4Builder::new()
        .ackreq(false)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(!layer.fcf_ackreq(&frame).unwrap());

    layer
        .set_field(&mut frame, "fcf_ackreq", FieldValue::Bool(true))
        .unwrap()
        .unwrap();
    assert!(layer.fcf_ackreq(&frame).unwrap());
}

#[test]
fn test_set_field_dest_panid() {
    let mut frame = Dot15d4Builder::new()
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));

    layer
        .set_field(&mut frame, "dest_panid", FieldValue::U16(0xABCD))
        .unwrap()
        .unwrap();
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0xABCD));
}

#[test]
fn test_set_field_invalid_type() {
    let mut frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    // Try setting a u8 field with a u16 value
    let result = layer.set_field(&mut frame, "seqnum", FieldValue::U16(0x1234));
    assert!(result.unwrap().is_err());
}

#[test]
fn test_set_field_unknown_returns_none() {
    let mut frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert!(
        layer
            .set_field(&mut frame, "nonexistent", FieldValue::U8(0))
            .is_none()
    );
}

// ============================================================================
// 10b. FCS layer dynamic field access
// ============================================================================

#[test]
fn test_fcs_layer_get_field_fcs() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(5)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    let fcs_val = layer.get_field(&frame, "fcs").unwrap().unwrap();
    assert!(fcs_val.as_u16().is_some());
}

#[test]
fn test_fcs_layer_get_field_delegates() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(42)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    let seq = layer.get_field(&frame, "seqnum").unwrap().unwrap();
    assert_eq!(seq.as_u8(), Some(42));
}

// ============================================================================
// 11. Summary output
// ============================================================================

#[test]
fn test_summary_data_frame() {
    let frame = Dot15d4Builder::new()
        .frame_type(types::frame_type::DATA)
        .ackreq(true)
        .seqnum(10)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .panid_compress(true)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let summary = layer.summary(&frame);

    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Data"));
    assert!(summary.contains("ackreq(true)"));
    assert!(summary.contains("Seq#10"));
}

#[test]
fn test_summary_ack_frame() {
    let frame = Dot15d4Builder::ack().seqnum(200).build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let summary = layer.summary(&frame);

    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Ack"));
    assert!(summary.contains("Seq#200"));
}

#[test]
fn test_summary_beacon_frame() {
    let frame = Dot15d4Builder::beacon().seqnum(0).build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let summary = layer.summary(&frame);

    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Beacon"));
    assert!(summary.contains("Seq#0"));
}

#[test]
fn test_summary_command_frame() {
    let frame = Dot15d4Builder::command()
        .seqnum(7)
        .dest_panid(0x1234)
        .dest_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    let summary = layer.summary(&frame);

    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Command"));
    assert!(summary.contains("Seq#7"));
}

#[test]
fn test_summary_fcs_layer_includes_fcs() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(5)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    let summary = layer.summary(&frame);

    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Data"));
    assert!(summary.contains("FCS="));
}

// ============================================================================
// 12. LayerEnum integration
// ============================================================================

#[test]
fn test_layer_enum_dot15d4() {
    let frame = Dot15d4Builder::new()
        .seqnum(5)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let inner_layer = Dot15d4Layer::new(0, frame.len());
    let layer_enum = LayerEnum::Dot15d4(inner_layer);

    assert_eq!(layer_enum.kind(), LayerKind::Dot15d4);

    let summary = layer_enum.summary(&frame);
    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("Data"));

    // Dynamic field access through LayerEnum
    let ft = layer_enum
        .get_field(&frame, "fcf_frametype")
        .unwrap()
        .unwrap();
    assert_eq!(ft.as_u8(), Some(types::frame_type::DATA));

    let seq = layer_enum.get_field(&frame, "seqnum").unwrap().unwrap();
    assert_eq!(seq.as_u8(), Some(5));
}

#[test]
fn test_layer_enum_dot15d4_fcs() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(50)
        .dest_panid(0xBEEF)
        .dest_addr_short(0x0001)
        .build();

    let inner_layer = Dot15d4FcsLayer::new(0, frame.len());
    let layer_enum = LayerEnum::Dot15d4Fcs(inner_layer);

    assert_eq!(layer_enum.kind(), LayerKind::Dot15d4Fcs);

    let summary = layer_enum.summary(&frame);
    assert!(summary.contains("802.15.4"));
    assert!(summary.contains("FCS="));

    let fcs_val = layer_enum.get_field(&frame, "fcs").unwrap().unwrap();
    assert!(fcs_val.as_u16().is_some());
}

#[test]
fn test_layer_enum_set_field() {
    let mut frame = Dot15d4Builder::new()
        .seqnum(1)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let inner_layer = Dot15d4Layer::new(0, frame.len());
    let layer_enum = LayerEnum::Dot15d4(inner_layer);

    layer_enum
        .set_field(&mut frame, "seqnum", FieldValue::U8(100))
        .unwrap()
        .unwrap();

    let seq = layer_enum.get_field(&frame, "seqnum").unwrap().unwrap();
    assert_eq!(seq.as_u8(), Some(100));
}

#[test]
fn test_layer_enum_field_names() {
    let layer = Dot15d4Layer::new(0, 10);
    let layer_enum = LayerEnum::Dot15d4(layer);

    let names = layer_enum.field_names();
    assert!(names.contains(&"fcf_frametype"));
    assert!(names.contains(&"seqnum"));
    assert!(names.contains(&"dest_panid"));
    assert!(names.contains(&"src_addr_short"));
    assert!(names.contains(&"src_addr_long"));
}

#[test]
fn test_layer_enum_fcs_field_names() {
    let layer = Dot15d4FcsLayer::new(0, 10);
    let layer_enum = LayerEnum::Dot15d4Fcs(layer);

    let names = layer_enum.field_names();
    assert!(names.contains(&"fcs"));
    assert!(names.contains(&"fcf_frametype"));
    assert!(names.contains(&"seqnum"));
}

// ============================================================================
// 13. Sequence number read/write
// ============================================================================

#[test]
fn test_seqnum_full_range() {
    for seq in [0u8, 1, 127, 128, 254, 255] {
        let frame = Dot15d4Builder::new()
            .seqnum(seq)
            .dest_panid(0xFFFF)
            .dest_addr_short(0xFFFF)
            .build();

        let layer = Dot15d4Layer::new(0, frame.len());
        assert_eq!(layer.seqnum(&frame).unwrap(), seq);
    }
}

#[test]
fn test_seqnum_set_via_set_field() {
    let mut frame = Dot15d4Builder::new()
        .seqnum(0)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());

    // Cycle through several values
    for seq in [1u8, 50, 100, 200, 255] {
        layer
            .set_field(&mut frame, "seqnum", FieldValue::U8(seq))
            .unwrap()
            .unwrap();
        assert_eq!(layer.seqnum(&frame).unwrap(), seq);
    }
}

#[test]
fn test_seqnum_preserved_in_fcs_layer() {
    let frame = Dot15d4FcsBuilder::new()
        .seqnum(177)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert_eq!(layer.seqnum(&frame).unwrap(), 177);
}

// ============================================================================
// 14. Command frame type
// ============================================================================

#[test]
fn test_command_frame_basic() {
    let frame = Dot15d4Builder::command()
        .seqnum(15)
        .dest_panid(0x1234)
        .dest_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::MAC_CMD
    );
    assert_eq!(layer.seqnum(&frame).unwrap(), 15);
    assert_eq!(layer.dest_panid(&frame).unwrap(), Some(0x1234));
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0x0001));
}

#[test]
fn test_command_frame_with_src_addr() {
    let frame = Dot15d4Builder::command()
        .seqnum(1)
        .dest_panid(0xAAAA)
        .dest_addr_short(0x0000) // coordinator
        .src_panid(0xAAAA)
        .src_addr_long(0x0102030405060708)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::MAC_CMD
    );
    assert_eq!(layer.dest_addr_short(&frame).unwrap(), Some(0x0000));
    assert_eq!(
        layer.src_addr_long(&frame).unwrap(),
        Some(0x0102030405060708)
    );
}

#[test]
fn test_command_frame_fcs() {
    let frame = Dot15d4FcsBuilder::command()
        .seqnum(5)
        .dest_panid(0xFFFF)
        .dest_addr_short(0x0000)
        .build();

    let layer = Dot15d4FcsLayer::new(0, frame.len());
    assert_eq!(
        layer.fcf_frametype(&frame).unwrap(),
        types::frame_type::MAC_CMD
    );
    assert!(layer.verify_fcs(&frame).unwrap());
}

// ============================================================================
// Additional edge cases and Layer trait tests
// ============================================================================

#[test]
fn test_compute_header_len_from_fcf() {
    // ACK frame: no addressing, header = 3
    let ack_frame = Dot15d4Builder::ack().build();
    let fcf = u16::from_le_bytes([ack_frame[0], ack_frame[1]]);
    assert_eq!(dot15d4::compute_header_len(fcf), 3);

    // Data frame with short dest only: FCF(2)+seq(1)+panid(2)+short(2) = 7
    let data_frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .no_src_addr()
        .build();
    let fcf = u16::from_le_bytes([data_frame[0], data_frame[1]]);
    assert_eq!(dot15d4::compute_header_len(fcf), 7);
}

#[test]
fn test_layer_kind_properties() {
    assert_eq!(LayerKind::Dot15d4.name(), "802.15.4");
    assert_eq!(LayerKind::Dot15d4Fcs.name(), "802.15.4 FCS");
    assert_eq!(LayerKind::Dot15d4.min_header_size(), 3);
    assert_eq!(LayerKind::Dot15d4Fcs.min_header_size(), 5);
}

#[test]
fn test_layer_trait_kind() {
    let frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(Layer::kind(&layer), LayerKind::Dot15d4);
}

#[test]
fn test_layer_trait_header_len() {
    let frame = Dot15d4Builder::new()
        .panid_compress(true)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .src_addr_short(0x0001)
        .build();

    let layer = Dot15d4Layer::new(0, frame.len());
    assert_eq!(Layer::header_len(&layer, &frame), frame.len());
}

#[test]
fn test_layer_trait_field_names() {
    let layer = Dot15d4Layer::new(0, 10);
    let names = Layer::field_names(&layer);
    assert!(!names.is_empty());
    assert!(names.contains(&"fcf_frametype"));
    assert!(names.contains(&"seqnum"));
}

#[test]
fn test_hashret_based_on_seqnum() {
    let frame1 = Dot15d4Builder::new()
        .seqnum(42)
        .dest_panid(0x1234)
        .dest_addr_short(0xFFFF)
        .build();

    let frame2 = Dot15d4Builder::ack().seqnum(42).build();

    let layer1 = Dot15d4Layer::new(0, frame1.len());
    let layer2 = Dot15d4Layer::new(0, frame2.len());

    assert_eq!(layer1.hashret(&frame1), layer2.hashret(&frame2));
}

#[test]
fn test_hashret_different_seqnum() {
    let frame1 = Dot15d4Builder::new()
        .seqnum(42)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let frame2 = Dot15d4Builder::new()
        .seqnum(43)
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();

    let layer1 = Dot15d4Layer::new(0, frame1.len());
    let layer2 = Dot15d4Layer::new(0, frame2.len());

    assert_ne!(layer1.hashret(&frame1), layer2.hashret(&frame2));
}

#[test]
fn test_frame_type_constants() {
    assert_eq!(types::frame_type::BEACON, 0);
    assert_eq!(types::frame_type::DATA, 1);
    assert_eq!(types::frame_type::ACK, 2);
    assert_eq!(types::frame_type::MAC_CMD, 3);
}

#[test]
fn test_frame_type_names() {
    assert_eq!(types::frame_type_name(types::frame_type::BEACON), "Beacon");
    assert_eq!(types::frame_type_name(types::frame_type::DATA), "Data");
    assert_eq!(types::frame_type_name(types::frame_type::ACK), "Ack");
    assert_eq!(
        types::frame_type_name(types::frame_type::MAC_CMD),
        "Command"
    );
}

#[test]
fn test_addr_mode_constants() {
    assert_eq!(types::addr_mode::NONE, 0);
    assert_eq!(types::addr_mode::SHORT, 2);
    assert_eq!(types::addr_mode::LONG, 3);
}

#[test]
fn test_dot15d4_builder_default() {
    let builder = Dot15d4Builder::new();
    assert_eq!(builder.frame_type, types::frame_type::DATA);
    assert!(!builder.security);
    assert!(!builder.pending);
    assert!(!builder.ackreq);
    assert!(!builder.panid_compress);
    assert_eq!(builder.frame_ver, 0);
    assert_eq!(builder.seqnum, 1);
}

#[test]
fn test_builder_header_size() {
    let b = Dot15d4Builder::ack();
    assert_eq!(b.header_size(), 3);

    let b = Dot15d4Builder::new()
        .dest_addr_short(0xFFFF)
        .panid_compress(true)
        .src_addr_short(0x0001);
    assert_eq!(b.header_size(), 9);

    let b = Dot15d4Builder::new()
        .dest_addr_long(0x0102030405060708)
        .src_addr_long(0x1112131415161718);
    assert_eq!(b.header_size(), 23);
}

#[test]
fn test_long_addr_formatting() {
    let formatted = Dot15d4Layer::format_long_addr(0x0102030405060708);
    assert_eq!(formatted, "01:02:03:04:05:06:07:08");
}

#[test]
fn test_next_layer_detection() {
    // Data frame -> Raw payload
    let data_frame = Dot15d4Builder::new()
        .dest_panid(0xFFFF)
        .dest_addr_short(0xFFFF)
        .build();
    let layer = Dot15d4Layer::new(0, data_frame.len());
    assert_eq!(layer.next_layer(&data_frame), Some(LayerKind::Raw));

    // ACK frame -> no payload
    let ack_frame = Dot15d4Builder::ack().build();
    let layer = Dot15d4Layer::new(0, ack_frame.len());
    assert_eq!(layer.next_layer(&ack_frame), None);

    // Beacon frame -> no payload
    let beacon_frame = Dot15d4Builder::beacon().build();
    let layer = Dot15d4Layer::new(0, beacon_frame.len());
    assert_eq!(layer.next_layer(&beacon_frame), None);

    // Command frame -> no payload
    let cmd_frame = Dot15d4Builder::command()
        .dest_panid(0xFFFF)
        .dest_addr_short(0x0000)
        .build();
    let layer = Dot15d4Layer::new(0, cmd_frame.len());
    assert_eq!(layer.next_layer(&cmd_frame), None);
}
