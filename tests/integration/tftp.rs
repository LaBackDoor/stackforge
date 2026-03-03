//! TFTP (Trivial File Transfer Protocol) integration tests.
//!
//! Tests TFTP parsing, building, full-stack UDP packet handling, and field access
//! for RRQ, WRQ, DATA, ACK, and ERROR packet types.

use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tftp::{
    ERR_ACCESS_VIOLATION, ERR_DISK_FULL, ERR_FILE_EXISTS, ERR_FILE_NOT_FOUND,
    ERR_ILLEGAL_OPERATION, OPCODE_ACK, OPCODE_DATA, OPCODE_ERROR, OPCODE_RRQ, OPCODE_WRQ,
    TFTP_DEFAULT_BLOCK_SIZE, TFTP_MIN_HEADER_LEN, TFTP_PORT, TftpBuilder, TftpLayer,
    error_code_description, is_tftp_payload, opcode_name,
};
use stackforge_core::layer::udp::builder::UdpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap TFTP bytes in Eth/IP/UDP on port 69
// ============================================================================

fn build_tftp_udp_packet(payload: Vec<u8>) -> Packet {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(10, 0, 0, 1))
                .dst(Ipv4Addr::new(10, 0, 0, 2))
                .ttl(64),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(54321).dst_port(69),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> TftpLayer {
    TftpLayer::new(LayerIndex::new(LayerKind::Tftp, 0, data.len()))
}

// ============================================================================
// Builder tests: RRQ / WRQ
// ============================================================================

#[test]
fn test_tftp_builder_rrq() {
    let bytes = TftpBuilder::new().rrq("test.txt", "octet").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_RRQ);
    assert_eq!(layer.filename(&bytes).unwrap(), "test.txt");
    assert_eq!(layer.mode(&bytes).unwrap(), "octet");
}

#[test]
fn test_tftp_builder_rrq_netascii() {
    let bytes = TftpBuilder::new().rrq("readme.txt", "netascii").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_RRQ);
    assert_eq!(layer.filename(&bytes).unwrap(), "readme.txt");
    assert_eq!(layer.mode(&bytes).unwrap(), "netascii");
}

#[test]
fn test_tftp_builder_wrq() {
    let bytes = TftpBuilder::new().wrq("upload.bin", "octet").build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_WRQ);
    assert_eq!(layer.filename(&bytes).unwrap(), "upload.bin");
    assert_eq!(layer.mode(&bytes).unwrap(), "octet");
}

// ============================================================================
// Builder tests: DATA / ACK
// ============================================================================

#[test]
fn test_tftp_builder_data_block1() {
    let data_payload = b"Hello TFTP world!";
    let bytes = TftpBuilder::new().data(1, data_payload.as_ref()).build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_DATA);
    assert_eq!(layer.block_num(&bytes).unwrap(), 1);
    assert_eq!(layer.data(&bytes).unwrap(), data_payload);
}

#[test]
fn test_tftp_builder_data_large_block() {
    let large_data: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
    let bytes = TftpBuilder::new().data(5, large_data.clone()).build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.block_num(&bytes).unwrap(), 5);
    assert_eq!(layer.data(&bytes).unwrap(), large_data);
}

#[test]
fn test_tftp_builder_data_empty() {
    // Last DATA block with no data = end of transfer
    let bytes = TftpBuilder::new().data(42, &[] as &[u8]).build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_DATA);
    assert_eq!(layer.block_num(&bytes).unwrap(), 42);
    assert_eq!(layer.data(&bytes).unwrap(), &[] as &[u8]);
}

#[test]
fn test_tftp_builder_ack() {
    let bytes = TftpBuilder::new().ack(3).build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_ACK);
    assert_eq!(layer.block_num(&bytes).unwrap(), 3);
    assert_eq!(bytes.len(), 4); // exactly 4 bytes for ACK
}

#[test]
fn test_tftp_builder_ack_zero() {
    // ACK 0 acknowledges the WRQ
    let bytes = TftpBuilder::new().ack(0).build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_ACK);
    assert_eq!(layer.block_num(&bytes).unwrap(), 0);
}

// ============================================================================
// Builder tests: ERROR
// ============================================================================

#[test]
fn test_tftp_builder_error_file_not_found() {
    let bytes = TftpBuilder::new().error_file_not_found().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.opcode(&bytes).unwrap(), OPCODE_ERROR);
    assert_eq!(layer.error_code(&bytes).unwrap(), ERR_FILE_NOT_FOUND);
    assert_eq!(layer.error_msg(&bytes).unwrap(), "File not found");
}

#[test]
fn test_tftp_builder_error_access_violation() {
    let bytes = TftpBuilder::new().error_access_violation().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.error_code(&bytes).unwrap(), ERR_ACCESS_VIOLATION);
    assert_eq!(layer.error_msg(&bytes).unwrap(), "Access violation");
}

#[test]
fn test_tftp_builder_error_disk_full() {
    let bytes = TftpBuilder::new().error_disk_full().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.error_code(&bytes).unwrap(), ERR_DISK_FULL);
}

#[test]
fn test_tftp_builder_error_illegal_op() {
    let bytes = TftpBuilder::new().error_illegal_op().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.error_code(&bytes).unwrap(), ERR_ILLEGAL_OPERATION);
}

#[test]
fn test_tftp_builder_error_file_exists() {
    let bytes = TftpBuilder::new().error_file_exists().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.error_code(&bytes).unwrap(), ERR_FILE_EXISTS);
}

#[test]
fn test_tftp_builder_custom_error() {
    let bytes = TftpBuilder::new()
        .error(0, b"Custom error message".as_ref())
        .build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.error_code(&bytes).unwrap(), 0);
    assert_eq!(layer.error_msg(&bytes).unwrap(), "Custom error message");
}

// ============================================================================
// Detection: is_tftp_payload
// ============================================================================

#[test]
fn test_tftp_detection_valid_opcodes() {
    // All valid opcodes (1-5)
    assert!(is_tftp_payload(&[0x00, 0x01, b'f', b'i'])); // RRQ
    assert!(is_tftp_payload(&[0x00, 0x02, b'f', b'i'])); // WRQ
    assert!(is_tftp_payload(&[0x00, 0x03, 0x00, 0x01])); // DATA
    assert!(is_tftp_payload(&[0x00, 0x04, 0x00, 0x01])); // ACK
    assert!(is_tftp_payload(&[0x00, 0x05, 0x00, 0x01])); // ERROR
}

#[test]
fn test_tftp_detection_built_packets() {
    let rrq = TftpBuilder::new().rrq("test.txt", "octet").build();
    assert!(is_tftp_payload(&rrq));

    let ack = TftpBuilder::new().ack(1).build();
    assert!(is_tftp_payload(&ack));

    let data = TftpBuilder::new().data(1, b"hello").build();
    assert!(is_tftp_payload(&data));
}

#[test]
fn test_tftp_detection_invalid() {
    assert!(!is_tftp_payload(b"")); // empty
    assert!(!is_tftp_payload(&[0x00])); // too short
    assert!(!is_tftp_payload(&[0x00, 0x06])); // invalid opcode 6
    assert!(!is_tftp_payload(&[0x00, 0x00])); // opcode 0
    assert!(!is_tftp_payload(&[0xFF, 0xFF])); // opcode 65535
}

// ============================================================================
// Layer field access: opcode names
// ============================================================================

#[test]
fn test_tftp_opcode_names() {
    assert_eq!(opcode_name(OPCODE_RRQ), "RRQ");
    assert_eq!(opcode_name(OPCODE_WRQ), "WRQ");
    assert_eq!(opcode_name(OPCODE_DATA), "DATA");
    assert_eq!(opcode_name(OPCODE_ACK), "ACK");
    assert_eq!(opcode_name(OPCODE_ERROR), "ERROR");
    assert_eq!(opcode_name(99), "UNKNOWN");
}

#[test]
fn test_tftp_error_code_descriptions() {
    assert_eq!(error_code_description(ERR_FILE_NOT_FOUND), "File not found");
    assert_eq!(
        error_code_description(ERR_ACCESS_VIOLATION),
        "Access violation"
    );
    assert_eq!(
        error_code_description(ERR_DISK_FULL),
        "Disk full or allocation exceeded"
    );
    assert_eq!(
        error_code_description(ERR_ILLEGAL_OPERATION),
        "Illegal TFTP operation"
    );
    assert_eq!(
        error_code_description(ERR_FILE_EXISTS),
        "File already exists"
    );
}

// ============================================================================
// Full-stack packet parsing via UDP port 69
// ============================================================================

#[test]
fn test_tftp_full_stack_rrq() {
    let payload = TftpBuilder::new().rrq("test.txt", "octet").build();
    let pkt = build_tftp_udp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Udp).is_some());
    assert!(pkt.get_layer(LayerKind::Tftp).is_some());

    let tftp = pkt.tftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tftp.opcode(buf).unwrap(), OPCODE_RRQ);
    assert_eq!(tftp.filename(buf).unwrap(), "test.txt");
    assert_eq!(tftp.mode(buf).unwrap(), "octet");
}

#[test]
fn test_tftp_full_stack_data() {
    let payload = TftpBuilder::new().data(1, b"hello world".as_ref()).build();
    let pkt = build_tftp_udp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Tftp).is_some());
    let tftp = pkt.tftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tftp.opcode(buf).unwrap(), OPCODE_DATA);
    assert_eq!(tftp.block_num(buf).unwrap(), 1);
    assert_eq!(tftp.data(buf).unwrap(), b"hello world");
}

#[test]
fn test_tftp_full_stack_ack() {
    let payload = TftpBuilder::new().ack(2).build();
    let pkt = build_tftp_udp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Tftp).is_some());
    let tftp = pkt.tftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tftp.opcode(buf).unwrap(), OPCODE_ACK);
    assert_eq!(tftp.block_num(buf).unwrap(), 2);
}

#[test]
fn test_tftp_full_stack_error() {
    let payload = TftpBuilder::new().error_file_not_found().build();
    let pkt = build_tftp_udp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Tftp).is_some());
    let tftp = pkt.tftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(tftp.opcode(buf).unwrap(), OPCODE_ERROR);
    assert_eq!(tftp.error_code(buf).unwrap(), ERR_FILE_NOT_FOUND);
    assert_eq!(tftp.error_msg(buf).unwrap(), "File not found");
}

#[test]
fn test_tftp_non_tftp_port_not_detected() {
    // Build a packet on port 9999 (not 69)
    let payload = TftpBuilder::new().ack(1).build();
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(10, 0, 0, 1))
                .dst(Ipv4Addr::new(10, 0, 0, 2))
                .ttl(64),
        ))
        .push(LayerStackEntry::Udp(
            UdpBuilder::new().src_port(54321).dst_port(9999),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    assert!(pkt.get_layer(LayerKind::Tftp).is_none());
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_tftp_constants() {
    assert_eq!(TFTP_PORT, 69);
    assert_eq!(TFTP_MIN_HEADER_LEN, 2);
    assert_eq!(TFTP_DEFAULT_BLOCK_SIZE, 512);
    assert_eq!(OPCODE_RRQ, 1);
    assert_eq!(OPCODE_WRQ, 2);
    assert_eq!(OPCODE_DATA, 3);
    assert_eq!(OPCODE_ACK, 4);
    assert_eq!(OPCODE_ERROR, 5);
}
