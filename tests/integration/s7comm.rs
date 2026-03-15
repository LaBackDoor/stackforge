//! S7 Communication Protocol integration tests.
//!
//! Tests S7comm builder, layer parsing, and full-stack packet handling
//! (Ethernet/IP/TCP/TPKT/COTP/S7comm).

use stackforge_core::layer::cotp::CotpBuilder;
use stackforge_core::layer::s7comm::{S7COMM_MIN_HEADER_LEN, S7CommBuilder, S7CommLayer};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::tpkt::TpktBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn test_s7comm_builder_default() {
    let pkt = S7CommBuilder::new().build();
    assert!(pkt.len() >= S7COMM_MIN_HEADER_LEN);
    assert_eq!(pkt[0], 0x32); // Protocol ID
}

#[test]
fn test_s7comm_job() {
    let pkt = S7CommBuilder::job()
        .pdu_ref(0x0100)
        .function(0xF0) // Setup Communication
        .parameters(vec![0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0])
        .build();

    let layer = S7CommLayer::new(LayerIndex::new(LayerKind::S7Comm, 0, pkt.len()));
    assert_eq!(layer.protocol_id(&pkt).unwrap(), 0x32);
    assert_eq!(layer.rosctr(&pkt).unwrap(), 0x01); // Job
    assert_eq!(layer.pdu_ref(&pkt).unwrap(), 0x0100);
    assert!(layer.is_job(&pkt));
}

#[test]
fn test_s7comm_read_var() {
    let pkt = S7CommBuilder::job()
        .function(0x04) // Read Var
        .build();

    let layer = S7CommLayer::new(LayerIndex::new(LayerKind::S7Comm, 0, pkt.len()));
    assert_eq!(layer.function(&pkt).unwrap(), 0x04);
}

#[test]
fn test_s7comm_packet_parse() {
    // Build S7 Comm data
    let s7_data = S7CommBuilder::job()
        .function(0xF0)
        .parameters(vec![0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0])
        .build();

    // Build COTP DT
    let cotp_data = CotpBuilder::new().build();

    // Build TPKT wrapping COTP + S7
    let mut tpkt_payload = Vec::new();
    tpkt_payload.extend_from_slice(&cotp_data);
    tpkt_payload.extend_from_slice(&s7_data);
    let tpkt_data = TpktBuilder::new().payload(tpkt_payload).build();

    // Build full packet: Eth/IP/TCP(port 102)/TPKT/COTP/S7Comm
    let mut full_packet = Vec::new();

    // Ethernet header (14 bytes)
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Ipv4);
    full_packet.extend_from_slice(&eth);

    // IPv4 header (20 bytes)
    let ip = Ipv4Builder::new()
        .src(Ipv4Addr::new(192, 168, 1, 1))
        .dst(Ipv4Addr::new(192, 168, 1, 2))
        .ttl(64)
        .protocol(6)
        .build();
    full_packet.extend_from_slice(&ip);

    // TCP header (20 bytes)
    let tcp = TcpBuilder::new().src_port(12345).dst_port(102).build();
    full_packet.extend_from_slice(&tcp);

    // TPKT/COTP/S7 payload
    full_packet.extend_from_slice(&tpkt_data);

    // Fix IP total length
    let ip_total = full_packet.len() - 14;
    full_packet[16] = ((ip_total >> 8) & 0xFF) as u8;
    full_packet[17] = (ip_total & 0xFF) as u8;

    let mut pkt = Packet::from_bytes(full_packet);
    pkt.parse().unwrap();

    assert!(
        pkt.get_layer(LayerKind::Tpkt).is_some(),
        "TPKT layer not found"
    );
    assert!(
        pkt.get_layer(LayerKind::Cotp).is_some(),
        "COTP layer not found"
    );
    assert!(
        pkt.get_layer(LayerKind::S7Comm).is_some(),
        "S7Comm layer not found"
    );
}
