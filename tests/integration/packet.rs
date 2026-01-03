//! Packet struct integration tests

use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn test_packet_from_bytes() {
    let data = vec![1, 2, 3, 4, 5];
    let packet = Packet::from_bytes(data.clone());

    assert_eq!(packet.len(), 5);
    assert_eq!(packet.as_bytes(), &data[..]);
    assert!(!packet.is_dirty());
    assert!(!packet.is_parsed());
}

#[test]
fn test_packet_empty() {
    let packet = Packet::empty();

    assert_eq!(packet.len(), 0);
    assert!(packet.is_empty());
    assert_eq!(packet.layer_count(), 0);
}

#[test]
fn test_packet_parse_ethernet_arp() {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 100))
        .psrc(Ipv4Addr::new(192, 168, 1, 1))
        .build();

    let mut data = Vec::new();
    data.extend_from_slice(&eth);
    data.extend_from_slice(&arp);

    let mut packet = Packet::from_bytes(data);
    packet.parse().unwrap();

    assert!(packet.is_parsed());
    assert_eq!(packet.layer_count(), 2);

    assert!(packet.ethernet().is_some());
    assert!(packet.arp().is_some());
}

#[test]
fn test_packet_layer_bytes() {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::ZERO)
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::new().build();

    let mut data = Vec::new();
    data.extend_from_slice(&eth);
    data.extend_from_slice(&arp);

    let mut packet = Packet::from_bytes(data);
    packet.parse().unwrap();

    let eth_bytes = packet.layer_bytes(LayerKind::Ethernet).unwrap();
    assert_eq!(eth_bytes.len(), 14);

    let arp_bytes = packet.layer_bytes(LayerKind::Arp).unwrap();
    assert_eq!(arp_bytes.len(), 28);

    // Non-existent layer
    assert!(packet.layer_bytes(LayerKind::Tcp).is_err());
}

#[test]
fn test_packet_clone_zero_copy() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let packet1 = Packet::from_bytes(data);
    let packet2 = packet1.clone();

    // Both should have same content
    assert_eq!(packet1.as_bytes(), packet2.as_bytes());
    assert_eq!(packet1.len(), packet2.len());
}

#[test]
fn test_packet_copy_on_write() {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::new().build();

    let mut data = Vec::new();
    data.extend_from_slice(&eth);
    data.extend_from_slice(&arp);

    let mut pkt1 = Packet::from_bytes(data);
    pkt1.parse().unwrap();

    // Clone packet (should be zero-copy)
    let pkt2 = pkt1.clone();

    // Modify pkt1 - should trigger CoW
    let eth_layer = pkt1.ethernet().unwrap();
    pkt1.with_data_mut(|buf| {
        eth_layer
            .set_src(buf, MacAddress::new([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]))
            .unwrap();
    });

    assert!(pkt1.is_dirty());

    // Verify pkt2 is unchanged
    let eth2 = EthernetLayer::at_start();
    assert_eq!(
        eth2.src(pkt2.as_bytes()).unwrap(),
        MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );

    // Verify pkt1 was modified
    let eth1 = pkt1.ethernet().unwrap();
    assert_eq!(
        eth1.src(pkt1.as_bytes()).unwrap(),
        MacAddress::new([0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa])
    );
}

#[test]
fn test_packet_set_byte() {
    let mut packet = Packet::from_bytes(vec![1, 2, 3, 4, 5]);

    packet.set_byte(2, 99);

    assert_eq!(packet.as_bytes(), &[1, 2, 99, 4, 5]);
    assert!(packet.is_dirty());
}

#[test]
fn test_packet_set_bytes() {
    let mut packet = Packet::from_bytes(vec![1, 2, 3, 4, 5]);

    packet.set_bytes(1, &[10, 20, 30]);

    assert_eq!(packet.as_bytes(), &[1, 10, 20, 30, 5]);
    assert!(packet.is_dirty());
}

#[test]
fn test_packet_with_data_mut() {
    let mut packet = Packet::from_bytes(vec![1, 2, 3, 4, 5]);

    let sum = packet.with_data_mut(|data| {
        data[0] = 100;
        data.iter().map(|&x| x as u32).sum::<u32>()
    });

    assert_eq!(sum, 100 + 2 + 3 + 4 + 5);
    assert_eq!(packet.as_bytes()[0], 100);
    assert!(packet.is_dirty());
}

#[test]
fn test_packet_mark_dirty_clean() {
    let mut packet = Packet::from_bytes(vec![1, 2, 3]);

    assert!(!packet.is_dirty());

    packet.mark_dirty();
    assert!(packet.is_dirty());

    packet.mark_clean();
    assert!(!packet.is_dirty());
}

#[test]
fn test_packet_payload() {
    let eth = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::ZERO)
        .build_with_payload(LayerKind::Arp);

    let arp = ArpBuilder::new().build();

    let mut data = Vec::new();
    data.extend_from_slice(&eth);
    data.extend_from_slice(&arp);
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let mut packet = Packet::from_bytes(data);
    packet.parse().unwrap();

    let raw_bytes = packet
        .layer_bytes(LayerKind::Raw)
        .expect("Should parse trailing bytes as RawLayer");
    assert_eq!(raw_bytes, &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn test_packet_too_short_for_parse() {
    let data = vec![0x00; 10]; // Too short for Ethernet header
    let mut packet = Packet::from_bytes(data);

    // Should not error, just won't find any layers
    packet.parse().unwrap();
    assert_eq!(packet.layer_count(), 0);
}

#[test]
fn test_packet_from_slice() {
    let data = [1u8, 2, 3, 4, 5];
    let packet = Packet::from_slice(&data);

    assert_eq!(packet.len(), 5);
    assert_eq!(packet.as_bytes(), &data);
}

#[test]
fn test_packet_into_bytes() {
    let data = vec![1, 2, 3, 4, 5];
    let packet = Packet::from_bytes(data.clone());

    let bytes = packet.into_bytes();
    assert_eq!(&bytes[..], &data[..]);
}
