//! IEC 60870-5-104 (Telecontrol) protocol integration tests.
//!
//! Tests IEC 104 builder, layer parsing for U/S/I-format APDUs, and
//! full-stack packet handling.

use stackforge_core::layer::iec104::{ApduType, Iec104Builder, Iec104Layer, is_iec104_payload};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn test_iec104_u_format_startdt() {
    let pkt = Iec104Builder::new().build(); // default: U-format STARTDT_ACT
    assert_eq!(pkt.len(), 6);
    assert_eq!(pkt[0], 0x68); // start byte
    assert_eq!(pkt[1], 0x04); // APDU length
}

#[test]
fn test_iec104_detection() {
    assert!(is_iec104_payload(&[0x68, 0x04, 0x07, 0x00, 0x00, 0x00]));
    assert!(!is_iec104_payload(&[0x69, 0x04, 0x07, 0x00, 0x00, 0x00])); // wrong start
    assert!(!is_iec104_payload(&[0x68])); // too short
}

#[test]
fn test_iec104_u_format_layer() {
    let pkt = Iec104Builder::new().startdt_act().build();
    let layer = Iec104Layer::new(LayerIndex::new(LayerKind::Iec104, 0, pkt.len()));
    assert_eq!(layer.apdu_type(&pkt), Some(ApduType::U));
    assert_eq!(layer.apdu_type_name(&pkt), "U");
}

#[test]
fn test_iec104_s_format() {
    let pkt = Iec104Builder::new().s_format().rx(10).build();
    let layer = Iec104Layer::new(LayerIndex::new(LayerKind::Iec104, 0, pkt.len()));
    assert_eq!(layer.apdu_type(&pkt), Some(ApduType::S));
    assert_eq!(layer.rx(&pkt).unwrap(), 10);
}

#[test]
fn test_iec104_i_format() {
    let pkt = Iec104Builder::new()
        .i_format()
        .tx(5)
        .rx(3)
        .type_id(1) // M_SP_NA_1
        .num_objects(1)
        .cot(3) // spontaneous
        .common_addr(1)
        .ioa(100)
        .asdu_data(vec![0x01]) // SIQ with SPI=1
        .build();

    let layer = Iec104Layer::new(LayerIndex::new(LayerKind::Iec104, 0, pkt.len()));
    assert_eq!(layer.apdu_type(&pkt), Some(ApduType::I));
    assert_eq!(layer.tx(&pkt).unwrap(), 5);
    assert_eq!(layer.rx(&pkt).unwrap(), 3);
    assert!(layer.has_asdu(&pkt));
    assert_eq!(layer.type_id(&pkt).unwrap(), 1);
    assert_eq!(layer.cot_cause(&pkt).unwrap(), 3);
    assert_eq!(layer.common_addr(&pkt).unwrap(), 1);
    assert_eq!(layer.ioa(&pkt).unwrap(), 100);
}

#[test]
fn test_iec104_testfr() {
    let pkt = Iec104Builder::new().testfr_act().build();
    assert_eq!(pkt, &[0x68, 0x04, 0x43, 0x00, 0x00, 0x00]);
}

#[test]
fn test_iec104_stopdt() {
    let pkt = Iec104Builder::new().stopdt_act().build();
    assert_eq!(pkt, &[0x68, 0x04, 0x13, 0x00, 0x00, 0x00]);
}

#[test]
fn test_iec104_packet_parse() {
    let iec_data = Iec104Builder::new().startdt_act().build();

    let mut full_packet = Vec::new();
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Ipv4);
    full_packet.extend_from_slice(&eth);

    let ip = Ipv4Builder::new()
        .src(Ipv4Addr::new(192, 168, 1, 1))
        .dst(Ipv4Addr::new(192, 168, 1, 2))
        .ttl(64)
        .protocol(6)
        .build();
    full_packet.extend_from_slice(&ip);

    let tcp = TcpBuilder::new().src_port(12345).dst_port(2404).build();
    full_packet.extend_from_slice(&tcp);
    full_packet.extend_from_slice(&iec_data);

    let ip_total = full_packet.len() - 14;
    full_packet[16] = ((ip_total >> 8) & 0xFF) as u8;
    full_packet[17] = (ip_total & 0xFF) as u8;

    let mut pkt = Packet::from_bytes(full_packet);
    pkt.parse().unwrap();

    assert!(pkt.get_layer(LayerKind::Iec104).is_some());
}
