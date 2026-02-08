//! TCP layer compatibility tests with Scapy.

use super::*;
use stackforge_core::layer::tcp::TcpBuilder;

#[test]
fn test_tcp_default() {
    let stackforge = TcpBuilder::new().build();
    let scapy = scapy_build("TCP()");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_custom_ports() {
    let stackforge = TcpBuilder::new().src_port(12345).dst_port(80).build();
    let scapy = scapy_build("TCP(sport=12345, dport=80)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_syn_flag() {
    let stackforge = TcpBuilder::new().syn().build();
    let scapy = scapy_build(r#"TCP(flags="S")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_synack_flags() {
    let stackforge = TcpBuilder::new().syn().ack().build();
    let scapy = scapy_build(r#"TCP(flags="SA")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_fin_flag() {
    let stackforge = TcpBuilder::new().fin().build();
    let scapy = scapy_build(r#"TCP(flags="F")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_rst_flag() {
    let stackforge = TcpBuilder::new().rst().build();
    let scapy = scapy_build(r#"TCP(flags="R")"#);
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_custom_seq() {
    let stackforge = TcpBuilder::new().seq(1000).build();
    let scapy = scapy_build("TCP(seq=1000)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_custom_ack() {
    let stackforge = TcpBuilder::new().ack_num(2000).build();
    let scapy = scapy_build("TCP(ack=2000)");
    compare_bytes(&stackforge, &scapy).unwrap();
}

#[test]
fn test_tcp_length() {
    let stackforge = TcpBuilder::new().build();
    assert_eq!(
        stackforge.len(),
        20,
        "TCP header should be 20 bytes minimum"
    );
}
