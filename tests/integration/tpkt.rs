//! TPKT (RFC 1006) integration tests.
//!
//! Tests TPKT builder, layer parsing, and detection.

use stackforge_core::layer::tpkt::{TpktBuilder, TpktLayer, is_tpkt_payload};
use stackforge_core::layer::{LayerIndex, LayerKind};

#[test]
fn test_tpkt_builder_default() {
    let pkt = TpktBuilder::new().build();
    assert_eq!(pkt.len(), 4);
    assert_eq!(pkt[0], 0x03); // version
    assert_eq!(pkt[1], 0x00); // reserved
    // length = 4 (header only, no payload)
    let len = u16::from_be_bytes([pkt[2], pkt[3]]);
    assert_eq!(len, 4);
}

#[test]
fn test_tpkt_detection() {
    assert!(is_tpkt_payload(&[0x03, 0x00, 0x00, 0x04]));
    assert!(!is_tpkt_payload(&[0x04, 0x00, 0x00, 0x04])); // wrong version
    assert!(!is_tpkt_payload(&[0x03, 0x01, 0x00, 0x04])); // wrong reserved
    assert!(!is_tpkt_payload(&[0x03])); // too short
}

#[test]
fn test_tpkt_with_payload() {
    let pkt = TpktBuilder::new()
        .payload(vec![0x02, 0xF0, 0x80]) // COTP DT
        .build();
    assert_eq!(pkt.len(), 7); // 4 + 3
    let len = u16::from_be_bytes([pkt[2], pkt[3]]);
    assert_eq!(len, 7);
}

#[test]
fn test_tpkt_layer_fields() {
    let pkt = TpktBuilder::new().payload(vec![0x01, 0x02]).build();
    let layer = TpktLayer::new(LayerIndex::new(LayerKind::Tpkt, 0, 4));
    assert_eq!(layer.version(&pkt).unwrap(), 3);
    assert_eq!(layer.reserved(&pkt).unwrap(), 0);
    assert_eq!(layer.length(&pkt).unwrap(), 6);
}
