//! DNP3 (IEEE 1815) protocol integration tests.
//!
//! Tests DNP3 builder, layer parsing, CRC verification, and field access.

use stackforge_core::layer::dnp3::crc::dnp3_crc;
use stackforge_core::layer::dnp3::{DNP3_MIN_HEADER_LEN, Dnp3Builder, Dnp3Layer, is_dnp3_payload};
use stackforge_core::layer::{LayerIndex, LayerKind};

#[test]
fn test_dnp3_detection() {
    assert!(is_dnp3_payload(&[
        0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    ]));
    assert!(!is_dnp3_payload(&[
        0x05, 0x65, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    ])); // wrong byte 1
    assert!(!is_dnp3_payload(&[]));
}

#[test]
fn test_dnp3_crc() {
    // Known CRC test vector for DNP3
    let data = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04];
    let crc = dnp3_crc(&data);
    // Verify CRC is non-zero for non-trivial data
    assert!(crc != 0);
}

#[test]
fn test_dnp3_builder_default() {
    let pkt = Dnp3Builder::new().build();
    assert!(pkt.len() >= DNP3_MIN_HEADER_LEN);
    assert_eq!(pkt[0], 0x05);
    assert_eq!(pkt[1], 0x64);
}

#[test]
fn test_dnp3_layer_fields() {
    let pkt = Dnp3Builder::new().dst(1).src(0).dir(true).prm(true).build();

    let layer = Dnp3Layer::new(LayerIndex::new(LayerKind::Dnp3, 0, pkt.len()));
    assert_eq!(layer.dst(&pkt).unwrap(), 1);
    assert_eq!(layer.src(&pkt).unwrap(), 0);
    assert!(layer.dir(&pkt).unwrap());
    assert!(layer.prm(&pkt).unwrap());
}

#[test]
fn test_dnp3_read_request() {
    let pkt = Dnp3Builder::new().dst(1).src(0).read().build();

    let layer = Dnp3Layer::new(LayerIndex::new(LayerKind::Dnp3, 0, pkt.len()));
    // Check link layer length is consistent with packet
    assert_eq!(
        layer.link_length(&pkt).unwrap() as usize + 5 <= pkt.len(),
        true
    );

    // Check application function code
    if let Some(fc) = layer.app_func(&pkt) {
        assert_eq!(fc, 0x01); // READ
    }
}

#[test]
fn test_dnp3_header_crc_valid() {
    let pkt = Dnp3Builder::new().dst(1).src(0).build();
    let layer = Dnp3Layer::new(LayerIndex::new(LayerKind::Dnp3, 0, pkt.len()));
    assert!(layer.verify_header_crc(&pkt));
}
