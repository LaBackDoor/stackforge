//! ICMP layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::icmp::IcmpBuilder;

#[test]
fn test_icmp_echo_request() {
    let stackforge = IcmpBuilder::echo_request(1, 1).build();
    let scapy = scapy_build("ICMP(type=8, id=1, seq=1)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_echo_reply() {
    let stackforge = IcmpBuilder::echo_reply(1, 1).build();
    let scapy = scapy_build("ICMP(type=0, id=1, seq=1)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_dest_unreach() {
    let stackforge = IcmpBuilder::dest_unreach(3).build();
    let scapy = scapy_build("ICMP(type=3, code=3)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_time_exceeded() {
    let stackforge = IcmpBuilder::time_exceeded(0).build();
    let scapy = scapy_build("ICMP(type=11, code=0)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_echo_request_custom_id() {
    let stackforge = IcmpBuilder::echo_request(0x1234, 1).build();
    let scapy = scapy_build("ICMP(type=8, id=0x1234, seq=1)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_echo_request_custom_seq() {
    let stackforge = IcmpBuilder::echo_request(1, 100).build();
    let scapy = scapy_build("ICMP(type=8, id=1, seq=100)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_dest_unreach_port() {
    let stackforge = IcmpBuilder::dest_unreach(3).build();
    let scapy = scapy_build("ICMP(type=3, code=3)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_icmp_dest_unreach_host() {
    let stackforge = IcmpBuilder::dest_unreach(1).build();
    let scapy = scapy_build("ICMP(type=3, code=1)");
    compare_bytes(&stackforge, &scapy).unwrap();
}
