//! Ethernet layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::EthernetBuilder;
use stackforge_core::layer::field::MacAddress;

#[test]
fn test_ethernet_default() {
    let stackforge = EthernetBuilder::new().build();
    let scapy = scapy_build("Ether()");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_broadcast() {
    let stackforge = EthernetBuilder::new().dst(MacAddress::BROADCAST).build();
    let scapy = scapy_build(r#"Ether(dst="ff:ff:ff:ff:ff:ff")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_custom_addresses() {
    let stackforge = EthernetBuilder::new()
        .dst(MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap())
        .src(MacAddress::parse("11:22:33:44:55:66").unwrap())
        .build();
    let scapy = scapy_build(r#"Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_zero_mac() {
    let stackforge = EthernetBuilder::new().src(MacAddress::ZERO).build();
    let scapy = scapy_build(r#"Ether(src="00:00:00:00:00:00")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_multicast() {
    let stackforge = EthernetBuilder::new()
        .dst(MacAddress::parse("01:00:5e:00:00:01").unwrap())
        .build();
    let scapy = scapy_build(r#"Ether(dst="01:00:5e:00:00:01")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_ethertype_ipv4() {
    let stackforge = EthernetBuilder::new().ethertype(0x0800).build();
    let scapy = scapy_build("Ether(type=0x0800)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_ethertype_arp() {
    let stackforge = EthernetBuilder::new().ethertype(0x0806).build();
    let scapy = scapy_build("Ether(type=0x0806)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_ethertype_ipv6() {
    let stackforge = EthernetBuilder::new().ethertype(0x86DD).build();
    let scapy = scapy_build("Ether(type=0x86dd)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_ethertype_8021q() {
    let stackforge = EthernetBuilder::new().ethertype(0x8100).build();
    let scapy = scapy_build("Ether(type=0x8100)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_all_ones_src() {
    let stackforge = EthernetBuilder::new().src(MacAddress::BROADCAST).build();
    let scapy = scapy_build(r#"Ether(src="ff:ff:ff:ff:ff:ff")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_custom_ethertype() {
    let stackforge = EthernetBuilder::new().ethertype(0x9000).build();
    let scapy = scapy_build("Ether(type=0x9000)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_length() {
    let stackforge = EthernetBuilder::new().build();
    assert_eq!(stackforge.len(), 14, "Ethernet frame should be 14 bytes");
}

#[test]
fn test_ethernet_dst_offset() {
    let stackforge = EthernetBuilder::new()
        .dst(MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap())
        .build();
    // Destination MAC at bytes 0-5
    assert_eq!(&stackforge[0..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
}

#[test]
fn test_ethernet_src_offset() {
    let stackforge = EthernetBuilder::new()
        .src(MacAddress::parse("11:22:33:44:55:66").unwrap())
        .build();
    // Source MAC at bytes 6-11
    assert_eq!(&stackforge[6..12], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
}

#[test]
fn test_ethernet_type_offset() {
    let stackforge = EthernetBuilder::new().ethertype(0x0800).build();
    // EtherType at bytes 12-13 (big-endian)
    assert_eq!(&stackforge[12..14], &[0x08, 0x00]);
}

#[test]
fn test_ethernet_local_admin_bit() {
    let stackforge = EthernetBuilder::new()
        .src(MacAddress::parse("02:00:00:00:00:01").unwrap())
        .build();
    let scapy = scapy_build(r#"Ether(src="02:00:00:00:00:01")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_unicast_dst() {
    let stackforge = EthernetBuilder::new()
        .dst(MacAddress::parse("00:11:22:33:44:55").unwrap())
        .build();
    let scapy = scapy_build(r#"Ether(dst="00:11:22:33:44:55")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ethernet_various_ethertypes() {
    let ethertypes = vec![
        (0x0800, "IPv4"),
        (0x0806, "ARP"),
        (0x86DD, "IPv6"),
        (0x8100, "802.1Q"),
        (0x88CC, "LLDP"),
        (0x8847, "MPLS unicast"),
        (0x8848, "MPLS multicast"),
    ];

    for (etype, name) in ethertypes {
        let stackforge = EthernetBuilder::new().ethertype(etype).build();
        let scapy = scapy_build(&format!("Ether(type={})", etype));
        compare_bytes(&stackforge, &scapy).unwrap_or_else(|e| {
            panic!("{} (0x{:04x}) mismatch: {}", name, etype, e);
        });
    }
}

#[test]
fn test_ethernet_sequential_macs() {
    for i in 0..5 {
        let mac = MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, i]);
        let stackforge = EthernetBuilder::new().dst(mac).build();
        let scapy = scapy_build(&format!(r#"Ether(dst="00:00:00:00:00:{:02x}")"#, i));
        compare_bytes(&stackforge, &scapy).unwrap_or_else(|e| {
            panic!("MAC {:?} mismatch: {}", mac, e);
        });
    }
}

#[test]
fn test_ethernet_boundary_ethertypes() {
    // Test values around 1500 (802.3 vs Ethernet II boundary)
    let ethertypes = vec![0x05DC, 0x0600, 0x0800, 0xFFFF];

    for etype in ethertypes {
        let stackforge = EthernetBuilder::new().ethertype(etype).build();
        let scapy = scapy_build(&format!("Ether(type={})", etype));
        compare_bytes(&stackforge, &scapy).unwrap_or_else(|e| {
            panic!("EtherType 0x{:04x} mismatch: {}", etype, e);
        });
    }
}
