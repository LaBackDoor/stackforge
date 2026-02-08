//! UDP layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::udp::UdpBuilder;

#[test]
fn test_udp_default() {
    let stackforge = UdpBuilder::new().build();
    let scapy = scapy_build("UDP()");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_udp_custom_ports() {
    let stackforge = UdpBuilder::new().src_port(5000).dst_port(6000).build();
    let scapy = scapy_build("UDP(sport=5000, dport=6000)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_udp_dns_port() {
    let stackforge = UdpBuilder::new().dst_port(53).build();
    let scapy = scapy_build("UDP(dport=53)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_udp_length() {
    let stackforge = UdpBuilder::new().build();
    assert_eq!(stackforge.len(), 8, "UDP header should be 8 bytes");
}
