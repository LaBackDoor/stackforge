//! ARP layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::ArpBuilder;
use stackforge_core::layer::field::MacAddress;
use std::net::Ipv4Addr;

#[test]
fn test_arp_default() {
    let stackforge = ArpBuilder::new().build();
    let scapy = scapy_build("ARP()");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_who_has() {
    let stackforge = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 1)).build();
    let scapy = scapy_build(r#"ARP(op="who-has", pdst="192.168.1.1")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_is_at() {
    let stackforge = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 1),
        MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap(),
    )
    .build();
    let scapy = scapy_build(r#"ARP(op="is-at", psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_request_full() {
    let stackforge = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 1))
        .hwsrc(MacAddress::parse("00:11:22:33:44:55").unwrap())
        .psrc(Ipv4Addr::new(192, 168, 1, 100))
        .build();
    let scapy = scapy_build(
        r#"ARP(hwsrc="00:11:22:33:44:55", psrc="192.168.1.100", pdst="192.168.1.1", op="who-has")"#,
    );
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_reply_full() {
    let stackforge = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 1),
        MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap(),
    )
    .hwdst(MacAddress::parse("00:11:22:33:44:55").unwrap())
    .pdst(Ipv4Addr::new(192, 168, 1, 100))
    .build();
    let scapy = scapy_build(
        r#"ARP(hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", hwdst="00:11:22:33:44:55", pdst="192.168.1.100", op="is-at")"#,
    );
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_hwtype_ethernet() {
    let stackforge = ArpBuilder::new().hwtype(1).build();
    let scapy = scapy_build("ARP(hwtype=1)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_ptype_ipv4() {
    let stackforge = ArpBuilder::new().ptype(0x0800).build();
    let scapy = scapy_build("ARP(ptype=0x0800)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_gratuitous() {
    let stackforge = ArpBuilder::is_at(Ipv4Addr::new(192, 168, 1, 1), MacAddress::ZERO)
        .pdst(Ipv4Addr::new(192, 168, 1, 1))
        .build();
    let scapy = scapy_build(r#"ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.1")"#);
    // May differ in hwsrc field
    compare_bytes_masked(&stackforge, &scapy, &[(8, 14)]).unwrap();
}

#[test]
fn test_arp_broadcast_hwdst() {
    let stackforge = ArpBuilder::new()
        .hwdst(MacAddress::BROADCAST)
        .pdst(Ipv4Addr::new(192, 168, 1, 1))
        .build();
    let scapy = scapy_build(r#"ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_zero_hwdst() {
    let stackforge = ArpBuilder::new()
        .hwdst(MacAddress::ZERO)
        .pdst(Ipv4Addr::new(192, 168, 1, 1))
        .build();
    let scapy = scapy_build(r#"ARP(hwdst="00:00:00:00:00:00", pdst="192.168.1.1")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_various_ips() {
    let ip_addresses = vec![
        (10, 0, 0, 1),
        (172, 16, 0, 1),
        (192, 168, 1, 1),
        (8, 8, 8, 8),
        (255, 255, 255, 255),
    ];

    for (a, b, c, d) in ip_addresses {
        let ip = Ipv4Addr::new(a, b, c, d);
        let stackforge = ArpBuilder::new().pdst(ip).build();
        let scapy = scapy_build(&format!(r#"ARP(pdst="{}")"#, ip));
        compare_bytes(&stackforge, &scapy).unwrap_or_else(|e| {
            panic!("IP {} mismatch: {}", ip, e);
        });
    }
}

#[test]
fn test_arp_length() {
    let stackforge = ArpBuilder::new().build();
    assert_eq!(stackforge.len(), 28, "ARP packet should be 28 bytes");
}

#[test]
fn test_arp_hwtype_offset() {
    let stackforge = ArpBuilder::new().hwtype(1).build();
    // Hardware type at bytes 0-1 (big-endian)
    assert_eq!(&stackforge[0..2], &[0x00, 0x01]);
}

#[test]
fn test_arp_ptype_offset() {
    let stackforge = ArpBuilder::new().ptype(0x0800).build();
    // Protocol type at bytes 2-3 (big-endian)
    assert_eq!(&stackforge[2..4], &[0x08, 0x00]);
}

#[test]
fn test_arp_hwlen_offset() {
    let stackforge = ArpBuilder::new().build();
    // Hardware length at byte 4
    assert_eq!(stackforge[4], 6); // Ethernet MAC is 6 bytes
}

#[test]
fn test_arp_plen_offset() {
    let stackforge = ArpBuilder::new().build();
    // Protocol length at byte 5
    assert_eq!(stackforge[5], 4); // IPv4 address is 4 bytes
}

#[test]
fn test_arp_op_offset() {
    let stackforge = ArpBuilder::who_has(Ipv4Addr::new(192, 168, 1, 1)).build();
    // Operation at bytes 6-7 (big-endian, 1=request)
    assert_eq!(&stackforge[6..8], &[0x00, 0x01]);
}

#[test]
fn test_arp_op_is_at_value() {
    let stackforge = ArpBuilder::is_at(Ipv4Addr::new(192, 168, 1, 1), MacAddress::ZERO).build();
    // Operation at bytes 6-7 (big-endian, 2=reply)
    assert_eq!(&stackforge[6..8], &[0x00, 0x02]);
}

#[test]
fn test_arp_probe() {
    let stackforge = ArpBuilder::new()
        .psrc(Ipv4Addr::new(0, 0, 0, 0))
        .pdst(Ipv4Addr::new(192, 168, 1, 1))
        .build();
    let scapy = scapy_build(r#"ARP(psrc="0.0.0.0", pdst="192.168.1.1")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_announcement() {
    let stackforge = ArpBuilder::is_at(
        Ipv4Addr::new(192, 168, 1, 100),
        MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap(),
    )
    .hwdst(MacAddress::ZERO)
    .pdst(Ipv4Addr::new(192, 168, 1, 100))
    .build();
    let scapy = scapy_build(
        r#"ARP(op="is-at", hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.100", hwdst="00:00:00:00:00:00", pdst="192.168.1.100")"#,
    );
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_different_subnets() {
    let stackforge = ArpBuilder::new()
        .psrc(Ipv4Addr::new(10, 0, 0, 1))
        .pdst(Ipv4Addr::new(192, 168, 1, 1))
        .build();
    let scapy = scapy_build(r#"ARP(psrc="10.0.0.1", pdst="192.168.1.1")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_arp_multicast_hwsrc() {
    let stackforge = ArpBuilder::new()
        .hwsrc(MacAddress::parse("01:00:5e:00:00:01").unwrap())
        .build();
    let scapy = scapy_build(r#"ARP(hwsrc="01:00:5e:00:00:01")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}
