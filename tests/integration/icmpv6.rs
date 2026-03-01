//! ICMPv6 protocol integration tests.
//!
//! Tests ICMPv6 building, parsing, checksum calculation, and field access.

use stackforge_core::FieldValue;
use stackforge_core::layer::icmpv6::builder::Icmpv6Builder;
use stackforge_core::layer::icmpv6::{Icmpv6Layer, icmpv6_checksum, types, verify_icmpv6_checksum};
use stackforge_core::layer::{ICMPV6_MIN_HEADER_LEN, LayerIndex, LayerKind};
use std::net::Ipv6Addr;

// ============================================================================
// Helpers
// ============================================================================

fn make_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 8];
    buf[0] = types::ECHO_REQUEST;
    buf[1] = 0; // code
    buf[2] = 0; // checksum hi
    buf[3] = 0; // checksum lo
    buf[4] = (id >> 8) as u8;
    buf[5] = (id & 0xFF) as u8;
    buf[6] = (seq >> 8) as u8;
    buf[7] = (seq & 0xFF) as u8;
    buf
}

fn make_echo_reply(id: u16, seq: u16) -> Vec<u8> {
    let mut buf = make_echo_request(id, seq);
    buf[0] = types::ECHO_REPLY;
    buf
}

fn icmpv6_layer_for_buf(buf: &[u8]) -> Icmpv6Layer {
    Icmpv6Layer::new(LayerIndex::new(LayerKind::Icmpv6, 0, buf.len()))
}

// ============================================================================
// Echo request build and parse
// ============================================================================

#[test]
fn test_icmpv6_echo_request_type() {
    let buf = Icmpv6Builder::echo_request(0x1234, 1).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.icmpv6_type(&buf).unwrap(), types::ECHO_REQUEST);
}

#[test]
fn test_icmpv6_echo_request_code() {
    let buf = Icmpv6Builder::echo_request(0x1234, 1).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.code(&buf).unwrap(), 0);
}

#[test]
fn test_icmpv6_echo_request_id() {
    let buf = Icmpv6Builder::echo_request(0xABCD, 7).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.id(&buf).unwrap(), Some(0xABCD));
}

#[test]
fn test_icmpv6_echo_request_seq() {
    let buf = Icmpv6Builder::echo_request(1, 0x5678).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.seq(&buf).unwrap(), Some(0x5678));
}

#[test]
fn test_icmpv6_echo_request_seq_increments() {
    for i in 0..5u16 {
        let buf = Icmpv6Builder::echo_request(1, i).build();
        let layer = icmpv6_layer_for_buf(&buf);
        assert_eq!(layer.seq(&buf).unwrap(), Some(i));
    }
}

// ============================================================================
// Echo reply build and parse
// ============================================================================

#[test]
fn test_icmpv6_echo_reply_type() {
    let buf = Icmpv6Builder::echo_reply(0x5678, 10).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.icmpv6_type(&buf).unwrap(), types::ECHO_REPLY);
}

#[test]
fn test_icmpv6_echo_reply_id_seq_match() {
    let id = 0x9ABC;
    let seq = 42;
    let buf = Icmpv6Builder::echo_reply(id, seq).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.id(&buf).unwrap(), Some(id));
    assert_eq!(layer.seq(&buf).unwrap(), Some(seq));
}

// ============================================================================
// Neighbor solicitation
// ============================================================================

#[test]
fn test_icmpv6_neighbor_solicitation_type() {
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.icmpv6_type(&buf).unwrap(), types::NEIGHBOR_SOLICIT);
}

#[test]
fn test_icmpv6_neighbor_solicitation_code_is_zero() {
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.code(&buf).unwrap(), 0);
}

#[test]
fn test_icmpv6_neighbor_solicitation_target_address() {
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.target_addr(&buf).unwrap(), Some(target));
}

#[test]
fn test_icmpv6_neighbor_solicitation_size() {
    let target = Ipv6Addr::LOCALHOST;
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    assert_eq!(buf.len(), 24); // 8 base + 16 target addr
}

// ============================================================================
// Neighbor advertisement
// ============================================================================

#[test]
fn test_icmpv6_neighbor_advertisement_type() {
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
    let buf = Icmpv6Builder::neighbor_advertisement(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.icmpv6_type(&buf).unwrap(), types::NEIGHBOR_ADVERT);
}

#[test]
fn test_icmpv6_neighbor_advertisement_target_address() {
    let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let buf = Icmpv6Builder::neighbor_advertisement(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.target_addr(&buf).unwrap(), Some(target));
}

#[test]
fn test_icmpv6_neighbor_advertisement_so_flags() {
    let target = Ipv6Addr::LOCALHOST;
    let buf = Icmpv6Builder::neighbor_advertisement(target).build();
    // S and O flags set in byte 4 (bits 30 and 29 = 0x60 when in byte 4)
    assert_eq!(buf[4] & 0x60, 0x60);
}

// ============================================================================
// Checksum calculation
// ============================================================================

#[test]
fn test_icmpv6_checksum_echo_request() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let mut buf = make_echo_request(0x1234, 1);
    let csum = icmpv6_checksum(src, dst, &buf);
    buf[2] = (csum >> 8) as u8;
    buf[3] = (csum & 0xFF) as u8;

    assert!(verify_icmpv6_checksum(src, dst, &buf));
}

#[test]
fn test_icmpv6_checksum_echo_reply() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    let mut buf = make_echo_reply(0x1234, 1);
    let csum = icmpv6_checksum(src, dst, &buf);
    buf[2] = (csum >> 8) as u8;
    buf[3] = (csum & 0xFF) as u8;

    assert!(verify_icmpv6_checksum(src, dst, &buf));
}

#[test]
fn test_icmpv6_checksum_builder_auto_compute() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let buf = Icmpv6Builder::echo_request(0x5678, 3)
        .set_src_ip(src)
        .set_dst_ip(dst)
        .build();

    // Checksum should be non-zero (auto-computed)
    let chksum = u16::from_be_bytes([buf[2], buf[3]]);
    assert_ne!(chksum, 0);
    // And should verify correctly
    assert!(verify_icmpv6_checksum(src, dst, &buf));
}

#[test]
fn test_icmpv6_no_checksum_without_src_dst() {
    let buf = Icmpv6Builder::echo_request(1, 1).build();
    let chksum = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(chksum, 0);
}

#[test]
fn test_icmpv6_manual_checksum() {
    let buf = Icmpv6Builder::echo_request(1, 1).checksum(0xDEAD).build();
    let chksum = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(chksum, 0xDEAD);
}

// ============================================================================
// Type/code fields
// ============================================================================

#[test]
fn test_icmpv6_type_constants() {
    assert_eq!(types::ECHO_REQUEST, 128);
    assert_eq!(types::ECHO_REPLY, 129);
    assert_eq!(types::NEIGHBOR_SOLICIT, 135);
    assert_eq!(types::NEIGHBOR_ADVERT, 136);
    assert_eq!(types::ROUTER_SOLICIT, 133);
    assert_eq!(types::ROUTER_ADVERT, 134);
    assert_eq!(types::DEST_UNREACH, 1);
    assert_eq!(types::PKT_TOO_BIG, 2);
    assert_eq!(types::TIME_EXCEEDED, 3);
}

#[test]
fn test_icmpv6_type_name() {
    assert_eq!(types::name(types::ECHO_REQUEST), "echo-request");
    assert_eq!(types::name(types::ECHO_REPLY), "echo-reply");
    assert_eq!(types::name(types::NEIGHBOR_SOLICIT), "neighbor-solicit");
    assert_eq!(types::name(types::NEIGHBOR_ADVERT), "neighbor-advert");
    assert_eq!(types::name(99), "unknown");
}

// ============================================================================
// id/seq fields for echo
// ============================================================================

#[test]
fn test_icmpv6_id_not_available_for_ns() {
    let target = Ipv6Addr::LOCALHOST;
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.id(&buf).unwrap(), None);
}

#[test]
fn test_icmpv6_seq_not_available_for_ns() {
    let target = Ipv6Addr::LOCALHOST;
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.seq(&buf).unwrap(), None);
}

#[test]
fn test_icmpv6_mtu_packet_too_big() {
    let buf = Icmpv6Builder::pkt_too_big(1500, vec![]).build();
    let layer = icmpv6_layer_for_buf(&buf);
    assert_eq!(layer.mtu(&buf).unwrap(), Some(1500));
}

#[test]
fn test_icmpv6_mtu_not_available_for_echo() {
    let buf = make_echo_request(1, 1);
    let layer = Icmpv6Layer::at_start();
    assert_eq!(layer.mtu(&buf).unwrap(), None);
}

// ============================================================================
// Layer kind check
// ============================================================================

#[test]
fn test_icmpv6_layer_kind() {
    use stackforge_core::layer::Layer;
    let _buf = make_echo_request(1, 1);
    let layer = Icmpv6Layer::at_start();
    assert_eq!(layer.kind(), LayerKind::Icmpv6);
}

#[test]
fn test_icmpv6_header_len_constant() {
    assert_eq!(ICMPV6_MIN_HEADER_LEN, 8);
}

#[test]
fn test_icmpv6_header_len_method() {
    let buf = make_echo_request(1, 1);
    let layer = Icmpv6Layer::at_start();
    assert_eq!(layer.header_len(&buf), ICMPV6_MIN_HEADER_LEN);
}

// ============================================================================
// Summary format
// ============================================================================

#[test]
fn test_icmpv6_summary_echo_request() {
    let buf = make_echo_request(0x1234, 5);
    let layer = Icmpv6Layer::at_start();
    let s = layer.summary(&buf);
    assert!(s.contains("ICMPv6"));
    assert!(s.contains("echo-request"));
}

#[test]
fn test_icmpv6_summary_neighbor_solicitation() {
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 0, 0, 1);
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    let s = layer.summary(&buf);
    assert!(s.contains("neighbor-solicit"));
}

// ============================================================================
// Dynamic field access
// ============================================================================

#[test]
fn test_icmpv6_get_field_type() {
    let buf = make_echo_request(1, 1);
    let layer = Icmpv6Layer::at_start();
    if let Some(Ok(FieldValue::U8(t))) = layer.get_field(&buf, "type") {
        assert_eq!(t, types::ECHO_REQUEST);
    } else {
        panic!("expected type field");
    }
}

#[test]
fn test_icmpv6_get_field_code() {
    let buf = make_echo_request(1, 1);
    let layer = Icmpv6Layer::at_start();
    if let Some(Ok(FieldValue::U8(c))) = layer.get_field(&buf, "code") {
        assert_eq!(c, 0);
    } else {
        panic!("expected code field");
    }
}

#[test]
fn test_icmpv6_get_field_id() {
    let buf = make_echo_request(0x5678, 1);
    let layer = Icmpv6Layer::at_start();
    if let Some(Ok(FieldValue::U16(id))) = layer.get_field(&buf, "id") {
        assert_eq!(id, 0x5678);
    } else {
        panic!("expected id field");
    }
}

#[test]
fn test_icmpv6_get_field_seq() {
    let buf = make_echo_request(1, 0x9ABC);
    let layer = Icmpv6Layer::at_start();
    if let Some(Ok(FieldValue::U16(seq))) = layer.get_field(&buf, "seq") {
        assert_eq!(seq, 0x9ABC);
    } else {
        panic!("expected seq field");
    }
}

#[test]
fn test_icmpv6_field_names_complete() {
    let names = Icmpv6Layer::field_names();
    assert!(names.contains(&"type"));
    assert!(names.contains(&"code"));
    assert!(names.contains(&"chksum"));
    assert!(names.contains(&"id"));
    assert!(names.contains(&"seq"));
}

// ============================================================================
// answers() matching
// ============================================================================

#[test]
fn test_icmpv6_echo_reply_answers_request() {
    let req_buf = make_echo_request(0xABCD, 10);
    let rep_buf = make_echo_reply(0xABCD, 10);

    let req_layer = Icmpv6Layer::at_start();
    let rep_layer = Icmpv6Layer::at_start();

    assert!(rep_layer.answers(&rep_buf, &req_layer, &req_buf));
}

#[test]
fn test_icmpv6_echo_reply_wrong_id_does_not_answer() {
    let req_buf = make_echo_request(0xABCD, 10);
    let rep_buf = make_echo_reply(0x0001, 10); // different ID

    let req_layer = Icmpv6Layer::at_start();
    let rep_layer = Icmpv6Layer::at_start();

    assert!(!rep_layer.answers(&rep_buf, &req_layer, &req_buf));
}

#[test]
fn test_icmpv6_echo_reply_wrong_seq_does_not_answer() {
    let req_buf = make_echo_request(0xABCD, 10);
    let rep_buf = make_echo_reply(0xABCD, 99); // different seq

    let req_layer = Icmpv6Layer::at_start();
    let rep_layer = Icmpv6Layer::at_start();

    assert!(!rep_layer.answers(&rep_buf, &req_layer, &req_buf));
}

// ============================================================================
// hashret
// ============================================================================

#[test]
fn test_icmpv6_hashret_echo_request() {
    let buf = make_echo_request(0x1234, 5);
    let layer = Icmpv6Layer::at_start();
    let hash = layer.hashret(&buf);
    // hashret for echo = [id_hi, id_lo, seq_hi, seq_lo]
    assert_eq!(hash.len(), 4);
    assert_eq!(hash[0], 0x12);
    assert_eq!(hash[1], 0x34);
    assert_eq!(hash[2], 0x00);
    assert_eq!(hash[3], 0x05);
}

#[test]
fn test_icmpv6_hashret_ns_empty() {
    let target = Ipv6Addr::LOCALHOST;
    let buf = Icmpv6Builder::neighbor_solicitation(target).build();
    let layer = icmpv6_layer_for_buf(&buf);
    let hash = layer.hashret(&buf);
    // NS doesn't use id/seq for matching
    assert!(hash.is_empty());
}

// ============================================================================
// Packet size calculation
// ============================================================================

#[test]
fn test_icmpv6_builder_echo_size() {
    let payload = vec![0u8; 10];
    let buf = Icmpv6Builder::echo_request(1, 1).payload(payload).build();
    assert_eq!(buf.len(), 18); // 8 base + 10 payload
}

#[test]
fn test_icmpv6_builder_ns_size() {
    let buf = Icmpv6Builder::neighbor_solicitation(Ipv6Addr::LOCALHOST).build();
    assert_eq!(buf.len(), 24); // 8 + 16 target
}

#[test]
fn test_icmpv6_router_solicitation_size() {
    let buf = Icmpv6Builder::router_solicitation().build();
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[0], types::ROUTER_SOLICIT);
}

#[test]
fn test_icmpv6_router_advertisement_type() {
    let buf = Icmpv6Builder::router_advertisement().build();
    assert_eq!(buf[0], types::ROUTER_ADVERT);
}
