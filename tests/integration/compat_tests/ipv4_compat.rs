//! IPv4 layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::ipv4::Ipv4Builder;
use std::net::Ipv4Addr;

#[test]
fn test_ipv4_default() {
    let stackforge = Ipv4Builder::new().build();
    let scapy = scapy_build("IP()");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_custom_addresses() {
    let stackforge = Ipv4Builder::new()
        .src(Ipv4Addr::new(10, 0, 0, 1))
        .dst(Ipv4Addr::new(10, 0, 0, 2))
        .build();
    let scapy = scapy_build(r#"IP(src="10.0.0.1", dst="10.0.0.2")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_custom_ttl() {
    let stackforge = Ipv4Builder::new().ttl(128).build();
    let scapy = scapy_build("IP(ttl=128)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_df_flag() {
    let stackforge = Ipv4Builder::new().dont_fragment().build();
    let scapy = scapy_build(r#"IP(flags="DF")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_mf_flag() {
    let stackforge = Ipv4Builder::new().more_fragments().build();
    let scapy = scapy_build(r#"IP(flags="MF")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_custom_id() {
    let stackforge = Ipv4Builder::new().id(0x1234).build();
    let scapy = scapy_build("IP(id=0x1234)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_custom_tos() {
    let stackforge = Ipv4Builder::new().tos(0x10).build();
    let scapy = scapy_build("IP(tos=0x10)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_ipv4_length() {
    let stackforge = Ipv4Builder::new().build();
    assert_eq!(
        stackforge.len(),
        20,
        "IPv4 header should be 20 bytes minimum"
    );
}

#[test]
fn test_ipv4_with_payload() {
    let stackforge = Ipv4Builder::new().payload(b"test".to_vec()).build();
    let scapy = scapy_build(r#"IP()/Raw(load=b"test")"#);
    // Compare just the IP header (first 20 bytes)
    compare_bytes(&stackforge[..20], &scapy[..20]).unwrap();
}

#[test]
fn test_ipv4_fragment_offset() {
    let stackforge = Ipv4Builder::new().frag_offset(100).build();
    let scapy = scapy_build("IP(frag=100)");
    compare_bytes(&stackforge, &scapy).unwrap();
}
