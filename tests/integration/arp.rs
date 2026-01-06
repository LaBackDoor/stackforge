//! ARP layer integration tests

use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

fn make_arp_request() -> Vec<u8> {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    [eth, arp].concat()
}

fn make_arp_reply() -> Vec<u8> {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .src(MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .hwdst(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    .pdst(Ipv4Addr::new(192, 168, 1, 1))
    .build();

    [eth, arp].concat()
}

#[test]
fn test_arp_who_has_builder() {
    let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    assert_eq!(arp.len(), 28); // Standard Ethernet/IPv4 ARP

    let layer = ArpLayer::at_offset(0);
    assert!(layer.is_request(&arp));
    assert_eq!(layer.pdst(&arp).unwrap(), Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(layer.psrc(&arp).unwrap(), Ipv4Addr::new(192, 168, 1, 1));
}

#[test]
fn test_arp_is_at_builder() {
    let arp = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .pdst(Ipv4Addr::new(192, 168, 1, 1))
    .hwdst(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    .build();

    let layer = ArpLayer::at_offset(0);
    assert!(layer.is_reply(&arp));
    assert_eq!(layer.psrc(&arp).unwrap(), Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(
        layer.hwsrc(&arp).unwrap(),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn test_arp_answers() {
    // Build request
    let request = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    // Build matching reply
    let reply = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .pdst(Ipv4Addr::new(192, 168, 1, 1))
    .hwdst(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    .build();

    let req_layer = ArpLayer::at_offset(0);
    let reply_layer = ArpLayer::at_offset(0);

    // Reply should answer request
    assert!(reply_layer.answers(&reply, &req_layer, &request));

    // Request should not answer reply
    assert!(!req_layer.answers(&request, &reply_layer, &reply));
}

#[test]
fn test_arp_answers_wrong_ip() {
    // Build request for 192.168.1.100
    let request = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    // Build reply for different IP (192.168.1.200)
    let reply = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 200), // Wrong IP!
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .build();

    let req_layer = ArpLayer::at_offset(0);
    let reply_layer = ArpLayer::at_offset(0);

    // Should NOT match
    assert!(!reply_layer.answers(&reply, &req_layer, &request));
}

#[test]
fn test_arp_dynamic_field_access() {
    let arp = ArpBuilder::who_has(Ipv4Addr::new(10, 0, 0, 1))
        .hwsrc(MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]))
        .psrc(Ipv4Addr::new(10, 0, 0, 254))
        .build();

    let layer = ArpLayer::at_offset(0);

    // Access by name
    let psrc = layer.get_field(&arp, "psrc").unwrap().unwrap();
    assert_eq!(psrc.as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 254)));

    let hwsrc = layer.get_field(&arp, "hwsrc").unwrap().unwrap();
    assert_eq!(
        hwsrc.as_mac(),
        Some(MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]))
    );

    let op = layer.get_field(&arp, "op").unwrap().unwrap();
    assert_eq!(op.as_u16(), Some(arp_opcode::REQUEST));
}

#[test]
fn test_arp_summary_request() {
    let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    let layer = ArpLayer::at_offset(0);
    let summary = layer.summary(&arp);

    assert!(summary.contains("who has"));
    assert!(summary.contains("192.168.1.100"));
    assert!(summary.contains("192.168.1.1"));
}

#[test]
fn test_arp_summary_reply() {
    let arp = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .build();

    let layer = ArpLayer::at_offset(0);
    let summary = layer.summary(&arp);

    assert!(summary.contains("is at"));
    assert!(summary.contains("aa:bb:cc:dd:ee:ff"));
}

#[test]
fn test_arp_full_packet_with_ethernet() {
    // Build complete Ethernet + ARP packet
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    let mut packet_data = Vec::new();
    packet_data.extend_from_slice(&eth);
    packet_data.extend_from_slice(&arp);

    assert_eq!(packet_data.len(), 14 + 28); // Ethernet + ARP

    // Parse and verify
    let mut pkt = Packet::from_bytes(packet_data);
    pkt.parse().unwrap();

    assert_eq!(pkt.layer_count(), 2);

    let eth_layer = pkt.ethernet().unwrap();
    assert!(eth_layer.is_broadcast(pkt.as_bytes()));

    let arp_layer = pkt.arp().unwrap();
    assert!(arp_layer.is_request(pkt.as_bytes()));
}

#[test]
fn test_parse_real_arp_capture() {
    // Real ARP request captured from network
    let captured: Vec<u8> = vec![
        // Ethernet (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
        0x3c, 0x52, 0x82, 0x15, 0xa3, 0x4f, // src
        0x08, 0x06, // type: ARP
        // ARP (28 bytes)
        0x00, 0x01, // hwtype: Ethernet
        0x08, 0x00, // ptype: IPv4
        0x06, // hwlen
        0x04, // plen
        0x00, 0x01, // op: request
        0x3c, 0x52, 0x82, 0x15, 0xa3, 0x4f, // sender MAC
        0x0a, 0x00, 0x00, 0x01, // sender IP: 10.0.0.1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC: zeros
        0x0a, 0x00, 0x00, 0xfe, // target IP: 10.0.0.254
    ];

    let mut pkt = Packet::from_bytes(captured);
    pkt.parse().unwrap();

    assert_eq!(pkt.layer_count(), 2);

    let arp = pkt.arp().unwrap();
    assert!(arp.is_request(pkt.as_bytes()));
    assert_eq!(
        arp.psrc(pkt.as_bytes()).unwrap(),
        Ipv4Addr::new(10, 0, 0, 1)
    );
    assert_eq!(
        arp.pdst(pkt.as_bytes()).unwrap(),
        Ipv4Addr::new(10, 0, 0, 254)
    );
}

#[test]
fn test_arp_request_creation() {
    let arp_data = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .hwsrc(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    assert_eq!(arp_data.len(), ARP_HEADER_LEN);

    let arp = ArpLayer::at_offset(0);
    assert_eq!(arp.op(&arp_data).unwrap(), arp_opcode::REQUEST);
    assert_eq!(arp.hwtype(&arp_data).unwrap(), arp_hardware::ETHERNET);
    assert!(arp.is_request(&arp_data));
    assert!(arp.is_who_has(&arp_data));
}

#[test]
fn test_arp_reply_creation() {
    let arp_data = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
    )
    .build();

    let arp = ArpLayer::at_offset(0);
    assert_eq!(arp.op(&arp_data).unwrap(), arp_opcode::REPLY);
    assert!(arp.is_reply(&arp_data));
    assert!(arp.is_is_at(&arp_data));
}

#[test]
fn test_arp_ipv6_addresses() {
    // Create ARP-like packet with IPv6 addresses
    let arp_data = ArpBuilder::new()
        .hwtype(arp_hardware::ETHERNET)
        .ptype(0x86DD) // IPv6
        .hwlen(6)
        .plen(16)
        .op(arp_opcode::REQUEST)
        .psrc_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        .pdst_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        .build();

    // Size should be 8 (fixed) + 2*6 (hwaddr) + 2*16 (paddr) = 52
    assert_eq!(arp_data.len(), 52);

    let arp = ArpLayer::at_offset(0);
    assert_eq!(arp.plen(&arp_data).unwrap(), 16);
    assert_eq!(
        arp.psrc_v6(&arp_data).unwrap(),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    );
}

#[test]
fn test_arp_hashret_matching() {
    let request = make_arp_request();
    let reply = make_arp_reply();

    let mut req_pkt = Packet::from_bytes(request);
    let mut rep_pkt = Packet::from_bytes(reply);

    req_pkt.parse().unwrap();
    rep_pkt.parse().unwrap();

    // Request and reply should have same hashret (same op group)
    let req_arp = req_pkt.arp().unwrap();
    let rep_arp = rep_pkt.arp().unwrap();

    let req_hash = req_arp.hashret(req_pkt.as_bytes());
    let rep_hash = rep_arp.hashret(rep_pkt.as_bytes());

    assert_eq!(req_hash, rep_hash);
}

#[test]
fn test_arp_extract_padding() {
    let mut data = make_arp_request();
    // Add padding to make 64-byte frame
    data.resize(64, 0);

    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    let arp = pkt.arp().unwrap();
    let (payload, padding) = arp.extract_padding(pkt.as_bytes());

    // ARP has no payload
    assert!(payload.is_empty());
    // Should have padding
    assert!(!padding.is_empty());
}

#[test]
fn test_arp_resolve_dst_mac() {
    let request_data = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100)).build();

    let arp = ArpLayer::at_offset(0);
    let dst_mac = arp.resolve_dst_mac(&request_data);

    // ARP requests should resolve to broadcast
    assert_eq!(dst_mac, Some(MacAddress::BROADCAST));

    // ARP replies should not auto-resolve
    let reply_data =
        ArpBuilder::is_at(Ipv4Addr::new(192, 168, 1, 100), MacAddress::BROADCAST).build();

    let dst_mac = arp.resolve_dst_mac(&reply_data);
    assert_eq!(dst_mac, None);
}
