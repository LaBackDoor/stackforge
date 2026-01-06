//! Ethernet layer integration tests

use stackforge_core::prelude::*;

fn make_dot3_frame() -> Vec<u8> {
    Dot3Builder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .len(4)
        .build()
}

#[test]
fn test_ethernet_builder() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    assert_eq!(frame.len(), 14);

    let eth = EthernetLayer::at_start();
    assert!(eth.is_broadcast(&frame));
    assert_eq!(eth.ethertype(&frame).unwrap(), ethertype::ARP);
}

#[test]
fn test_ethernet_field_access() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        .src(MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        .ethertype(ethertype::IPV4)
        .build();

    let eth = EthernetLayer::at_start();

    assert_eq!(
        eth.dst(&frame).unwrap(),
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
    assert_eq!(
        eth.src(&frame).unwrap(),
        MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    );
    assert_eq!(eth.ethertype(&frame).unwrap(), ethertype::IPV4);
}

#[test]
fn test_ethernet_dynamic_field_access() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .ethertype(ethertype::ARP)
        .build();

    let eth = EthernetLayer::at_start();

    let dst = eth.get_field(&frame, "dst").unwrap().unwrap();
    assert!(matches!(dst, FieldValue::Mac(m) if m.is_broadcast()));

    let etype = eth.get_field(&frame, "type").unwrap().unwrap();
    assert!(matches!(etype, FieldValue::U16(0x0806)));
}

#[test]
fn test_ethernet_summary() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .build_with_payload(LayerKind::Arp);

    let eth = EthernetLayer::at_start();
    let summary = eth.summary(&frame);

    assert!(summary.contains("00:11:22:33:44:55"));
    assert!(summary.contains("ff:ff:ff:ff:ff:ff"));
    assert!(summary.contains("ARP"));
}

#[test]
fn test_mac_address_parsing() {
    let mac1 = MacAddress::parse("00:11:22:33:44:55").unwrap();
    let mac2 = MacAddress::parse("00-11-22-33-44-55").unwrap();
    assert_eq!(mac1, mac2);

    assert!(MacAddress::parse("invalid").is_err());
    assert!(MacAddress::parse("00:11:22").is_err());
}

#[test]
fn test_mac_address_properties() {
    assert!(MacAddress::BROADCAST.is_broadcast());
    assert!(MacAddress::BROADCAST.is_multicast());
    assert!(!MacAddress::ZERO.is_multicast());
    assert!(MacAddress::ZERO.is_zero());

    // Multicast: LSB of first byte set
    let multicast = MacAddress::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
    assert!(multicast.is_multicast());
    assert!(!multicast.is_unicast());

    // Locally administered: second LSB of first byte set
    let local = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert!(local.is_local());
}

#[test]
fn test_ethernet_frame_creation() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .ethertype(ethertype::IPV4)
        .build();

    assert_eq!(frame.len(), ETHERNET_HEADER_LEN);

    let eth = EthernetLayer::at_start();
    assert_eq!(eth.dst(&frame).unwrap(), MacAddress::BROADCAST);
    assert_eq!(eth.ethertype(&frame).unwrap(), ethertype::IPV4);
}

#[test]
fn test_ethernet_auto_ethertype() {
    let frame = EthernetBuilder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::ZERO)
        .build_with_payload(LayerKind::Arp);

    let eth = EthernetLayer::at_start();
    assert_eq!(eth.ethertype(&frame).unwrap(), ethertype::ARP);
}

#[test]
fn test_ethernet_dispatch_hook() {
    // Ethernet II (EtherType > 1500)
    let eth2 = EthernetBuilder::new().ethertype(ethertype::IPV4).build();
    assert!(is_ethernet_ii(&eth2, 0));
    assert!(!is_dot3(&eth2, 0));

    // 802.3 (Length <= 1500)
    let dot3 = Dot3Builder::new().len(100).build();
    assert!(is_dot3(&dot3, 0));
    assert!(!is_ethernet_ii(&dot3, 0));
}

#[test]
fn test_ethernet_hashret_and_answers() {
    let frame1 = EthernetBuilder::new().ethertype(ethertype::ARP).build();
    let frame2 = EthernetBuilder::new().ethertype(ethertype::ARP).build();

    let eth1 = EthernetLayer::at_start();
    let eth2 = EthernetLayer::at_start();

    // Same EtherType should match
    assert!(eth1.answers(&frame1, &eth2, &frame2));
    assert_eq!(eth1.hashret(&frame1), eth2.hashret(&frame2));
}

#[test]
fn test_dot3_frame_creation() {
    let frame = Dot3Builder::new()
        .dst(MacAddress::BROADCAST)
        .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        .len(100)
        .build();

    let dot3 = Dot3Layer::at_start();
    assert_eq!(dot3.len_field(&frame).unwrap(), 100);
}

#[test]
fn test_dot3_extract_padding() {
    let mut frame = Dot3Builder::new().len(4).build();
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // Payload
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Padding

    let dot3 = Dot3Layer::at_start();
    let (payload, padding) = dot3.extract_padding(&frame);

    assert_eq!(payload.len(), 4);
    assert_eq!(padding.len(), 4);
}
