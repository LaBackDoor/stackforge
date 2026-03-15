//! COTP (ISO 8073) integration tests.
//!
//! Tests COTP builder, layer parsing for DT and CR PDU types.

use stackforge_core::layer::cotp::{CotpBuilder, CotpLayer};
use stackforge_core::layer::{LayerIndex, LayerKind};

#[test]
fn test_cotp_dt_default() {
    let pkt = CotpBuilder::new().build();
    // Default is DT with EOT: \x02\xF0\x80
    assert_eq!(pkt.len(), 3);
    assert_eq!(pkt[0], 0x02); // LI = 2
    assert_eq!(pkt[1], 0xF0); // PDU type DT
    assert_eq!(pkt[2] & 0x80, 0x80); // EOT bit set
}

#[test]
fn test_cotp_dt_layer() {
    let pkt = vec![0x02, 0xF0, 0x80];
    let layer = CotpLayer::new(LayerIndex::new(LayerKind::Cotp, 0, pkt.len()));
    assert_eq!(layer.length(&pkt).unwrap(), 2);
    assert_eq!(layer.pdu_type(&pkt).unwrap(), 0xF0);
    assert!(layer.is_dt(&pkt));
    assert!(layer.eot(&pkt).unwrap());
}

#[test]
fn test_cotp_cr() {
    let pkt = CotpBuilder::cr().dst_ref(0x0001).src_ref(0x0002).build();

    let layer = CotpLayer::new(LayerIndex::new(LayerKind::Cotp, 0, pkt.len()));
    assert!(layer.is_cr(&pkt));
    assert_eq!(layer.dst_ref(&pkt).unwrap(), 0x0001);
    assert_eq!(layer.src_ref(&pkt).unwrap(), 0x0002);
}
