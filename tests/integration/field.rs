use stackforge_core::{Field, HardwareAddr, MacAddress, ProtocolAddr};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_ipv6_field_operations() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let mut buf = [0u8; 20];

    ip.write(&mut buf, 2).unwrap();
    let read_ip = Ipv6Addr::read(&buf, 2).unwrap();

    assert_eq!(ip, read_ip);
}

#[test]
fn test_mac_address_parsing() {
    let mac1 = MacAddress::parse("00:11:22:33:44:55").unwrap();
    let mac2 = MacAddress::parse("00-11-22-33-44-55").unwrap();

    assert_eq!(mac1, mac2);
    assert_eq!(mac1.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
}

#[test]
fn test_hardware_addr_enum() {
    let mac = MacAddress::new([0xaa; 6]);
    let hw_addr = HardwareAddr::from(mac);

    assert_eq!(hw_addr.len(), 6);
    assert_eq!(hw_addr.as_mac(), Some(mac));

    let raw = HardwareAddr::from_bytes(&[0x01, 0x02, 0x03]);
    assert_eq!(raw.len(), 3);
    assert_eq!(raw.as_mac(), None);
}

#[test]
fn test_protocol_addr_enum() {
    let ipv4 = ProtocolAddr::from(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(ipv4.len(), 4);
    assert_eq!(ipv4.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));

    let ipv6 = ProtocolAddr::from(Ipv6Addr::LOCALHOST);
    assert_eq!(ipv6.len(), 16);
    assert_eq!(ipv6.as_ipv6(), Some(Ipv6Addr::LOCALHOST));
}
