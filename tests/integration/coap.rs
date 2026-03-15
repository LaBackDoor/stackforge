//! CoAP (Constrained Application Protocol) integration tests.
//!
//! Tests CoAP builder, layer parsing, detection, and full-stack packet handling.

use stackforge_core::layer::coap::{COAP_MIN_HEADER_LEN, CoapBuilder, CoapLayer, is_coap_payload};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::udp::builder::UdpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn test_coap_builder_default() {
    let pkt = CoapBuilder::new().build();
    assert!(pkt.len() >= COAP_MIN_HEADER_LEN);
    // Version should be 1
    assert_eq!((pkt[0] >> 6) & 0x03, 1);
}

#[test]
fn test_coap_detection() {
    let pkt = CoapBuilder::new().build();
    assert!(is_coap_payload(&pkt));
    assert!(!is_coap_payload(&[]));
    assert!(!is_coap_payload(&[0x00, 0x00, 0x00, 0x00])); // ver != 1
}

#[test]
fn test_coap_get_request() {
    let pkt = CoapBuilder::new()
        .con()
        .get()
        .msg_id(0x1234)
        .token(vec![0xAB, 0xCD])
        .build();

    let layer = CoapLayer::new(LayerIndex::new(LayerKind::Coap, 0, pkt.len()));
    assert_eq!(layer.ver(&pkt).unwrap(), 1);
    assert_eq!(layer.msg_type(&pkt).unwrap(), 0); // CON
    assert_eq!(layer.tkl(&pkt).unwrap(), 2);
    assert_eq!(layer.code(&pkt).unwrap(), 1); // 0.01 GET
    assert_eq!(layer.msg_id(&pkt).unwrap(), 0x1234);
    assert_eq!(layer.token(&pkt).unwrap(), &[0xAB, 0xCD]);
}

#[test]
fn test_coap_post_with_payload() {
    let pkt = CoapBuilder::new()
        .non()
        .post()
        .msg_id(0x5678)
        .payload(b"hello".to_vec())
        .build();

    let layer = CoapLayer::new(LayerIndex::new(LayerKind::Coap, 0, pkt.len()));
    assert_eq!(layer.msg_type(&pkt).unwrap(), 1); // NON
    assert_eq!(layer.code_class(&pkt).unwrap(), 0);
    assert_eq!(layer.code_detail(&pkt).unwrap(), 2); // POST
    assert_eq!(layer.payload(&pkt), Some(b"hello".as_slice()));
}

#[test]
fn test_coap_with_options() {
    let pkt = CoapBuilder::new()
        .con()
        .get()
        .msg_id(1)
        .uri_path("test/path")
        .build();

    let layer = CoapLayer::new(LayerIndex::new(LayerKind::Coap, 0, pkt.len()));
    let options = layer.options(&pkt);
    // Uri-Path options (option number 11)
    let uri_opts: Vec<_> = options.iter().filter(|o| o.number == 11).collect();
    assert_eq!(uri_opts.len(), 2); // "test" and "path"
}

#[test]
fn test_coap_ack_response() {
    let pkt = CoapBuilder::new()
        .ack()
        .code(2, 5) // 2.05 Content
        .msg_id(100)
        .payload(b"data".to_vec())
        .build();

    let layer = CoapLayer::new(LayerIndex::new(LayerKind::Coap, 0, pkt.len()));
    assert_eq!(layer.msg_type(&pkt).unwrap(), 2); // ACK
    assert_eq!(layer.code_class(&pkt).unwrap(), 2);
    assert_eq!(layer.code_detail(&pkt).unwrap(), 5);
}

#[test]
fn test_coap_packet_parse() {
    let stack = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 1))
                .dst(Ipv4Addr::new(192, 168, 1, 2))
                .ttl(64),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(12345).dst_port(5683),
        ))
        .push(LayerStackEntry::Coap(
            CoapBuilder::new().con().get().msg_id(1),
        ));

    let bytes = stack.build();
    let mut pkt = Packet::from_bytes(bytes);
    pkt.parse().unwrap();

    assert!(pkt.get_layer(LayerKind::Coap).is_some());
    let coap = pkt.coap().unwrap();
    assert_eq!(coap.ver(pkt.as_bytes()).unwrap(), 1);
}
