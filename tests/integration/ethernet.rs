//! Ethernet layer integration tests

use stackforge_core::prelude::*;

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
