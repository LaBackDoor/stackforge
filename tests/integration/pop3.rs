//! POP3 (Post Office Protocol version 3) integration tests.
//!
//! Tests POP3 parsing, building, full-stack packet handling, and field access
//! for both server responses (+OK/-ERR) and client commands.

use stackforge_core::layer::pop3::{
    CMD_CAPA, CMD_DELE, CMD_LIST, CMD_NOOP, CMD_PASS, CMD_QUIT, CMD_RETR, CMD_RSET, CMD_STAT,
    CMD_TOP, CMD_UIDL, CMD_USER, POP3_FIELD_NAMES, POP3_MIN_HEADER_LEN, POP3_PORT, Pop3Builder,
    Pop3Layer, is_pop3_payload,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap POP3 bytes in Eth/IP/TCP on port 110
// ============================================================================

fn build_pop3_tcp_packet(payload: Vec<u8>) -> Packet {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 10))
                .dst(Ipv4Addr::new(192, 168, 1, 20))
                .ttl(64),
        ))
        .push(LayerStackEntry::Tcp(
            TcpBuilder::new().src_port(54321).dst_port(110),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> Pop3Layer {
    Pop3Layer::new(LayerIndex::new(LayerKind::Pop3, 0, data.len()))
}

// ============================================================================
// Builder tests: server responses
// ============================================================================

#[test]
fn test_pop3_builder_server_ready() {
    let bytes = Pop3Builder::new().server_ready().build();
    assert_eq!(bytes, b"+OK POP3 server ready\r\n");
}

#[test]
fn test_pop3_builder_ok() {
    let bytes = Pop3Builder::new().ok("User accepted").build();
    assert_eq!(bytes, b"+OK User accepted\r\n");
}

#[test]
fn test_pop3_builder_ok_empty() {
    let bytes = Pop3Builder::new().ok("").build();
    assert_eq!(bytes, b"+OK\r\n");
}

#[test]
fn test_pop3_builder_err() {
    let bytes = Pop3Builder::new().err("Permission denied").build();
    assert_eq!(bytes, b"-ERR Permission denied\r\n");
}

#[test]
fn test_pop3_builder_err_empty() {
    let bytes = Pop3Builder::new().err("").build();
    assert_eq!(bytes, b"-ERR\r\n");
}

#[test]
fn test_pop3_builder_permission_denied() {
    let bytes = Pop3Builder::new().permission_denied().build();
    assert_eq!(bytes, b"-ERR Permission denied\r\n");
}

#[test]
fn test_pop3_builder_unknown_command() {
    let bytes = Pop3Builder::new().unknown_command().build();
    assert_eq!(bytes, b"-ERR Unknown command\r\n");
}

#[test]
fn test_pop3_builder_user_accepted() {
    let bytes = Pop3Builder::new().user_accepted().build();
    assert_eq!(bytes, b"+OK Password required\r\n");
}

#[test]
fn test_pop3_builder_logged_in() {
    let bytes = Pop3Builder::new().logged_in().build();
    assert_eq!(bytes, b"+OK logged in\r\n");
}

#[test]
fn test_pop3_builder_stat_reply() {
    let bytes = Pop3Builder::new().stat_reply(5, 2048).build();
    assert_eq!(bytes, b"+OK 5 2048\r\n");
}

#[test]
fn test_pop3_builder_list_reply_multiline() {
    let bytes = Pop3Builder::new()
        .list_reply(vec![(1, 512), (2, 1024), (3, 256)])
        .build();
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.starts_with("+OK 3 messages\r\n"));
    assert!(s.contains("1 512\r\n"));
    assert!(s.contains("2 1024\r\n"));
    assert!(s.contains("3 256\r\n"));
    assert!(s.ends_with(".\r\n"));
}

// ============================================================================
// Builder tests: client commands
// ============================================================================

#[test]
fn test_pop3_builder_user() {
    let bytes = Pop3Builder::new().user("alice").build();
    assert_eq!(bytes, b"USER alice\r\n");
}

#[test]
fn test_pop3_builder_pass() {
    let bytes = Pop3Builder::new().pass("secret").build();
    assert_eq!(bytes, b"PASS secret\r\n");
}

#[test]
fn test_pop3_builder_stat() {
    let bytes = Pop3Builder::new().stat().build();
    assert_eq!(bytes, b"STAT\r\n");
}

#[test]
fn test_pop3_builder_list_no_arg() {
    let bytes = Pop3Builder::new().list(None).build();
    assert_eq!(bytes, b"LIST\r\n");
}

#[test]
fn test_pop3_builder_list_with_arg() {
    let bytes = Pop3Builder::new().list(Some(3)).build();
    assert_eq!(bytes, b"LIST 3\r\n");
}

#[test]
fn test_pop3_builder_retr() {
    let bytes = Pop3Builder::new().retr(1).build();
    assert_eq!(bytes, b"RETR 1\r\n");
}

#[test]
fn test_pop3_builder_dele() {
    let bytes = Pop3Builder::new().dele(2).build();
    assert_eq!(bytes, b"DELE 2\r\n");
}

#[test]
fn test_pop3_builder_noop() {
    let bytes = Pop3Builder::new().noop().build();
    assert_eq!(bytes, b"NOOP\r\n");
}

#[test]
fn test_pop3_builder_rset() {
    let bytes = Pop3Builder::new().rset().build();
    assert_eq!(bytes, b"RSET\r\n");
}

#[test]
fn test_pop3_builder_top() {
    let bytes = Pop3Builder::new().top(1, 5).build();
    assert_eq!(bytes, b"TOP 1 5\r\n");
}

#[test]
fn test_pop3_builder_uidl_no_arg() {
    let bytes = Pop3Builder::new().uidl(None).build();
    assert_eq!(bytes, b"UIDL\r\n");
}

#[test]
fn test_pop3_builder_uidl_with_arg() {
    let bytes = Pop3Builder::new().uidl(Some(1)).build();
    assert_eq!(bytes, b"UIDL 1\r\n");
}

#[test]
fn test_pop3_builder_quit() {
    let bytes = Pop3Builder::new().quit().build();
    assert_eq!(bytes, b"QUIT\r\n");
}

#[test]
fn test_pop3_builder_capa() {
    let bytes = Pop3Builder::new().capa().build();
    assert_eq!(bytes, b"CAPA\r\n");
}

#[test]
fn test_pop3_builder_apop() {
    let bytes = Pop3Builder::new().apop("alice", "c4a5e7bc9b7e0fd9").build();
    assert_eq!(bytes, b"APOP alice c4a5e7bc9b7e0fd9\r\n");
}

#[test]
fn test_pop3_builder_multiline_body_with_dot_stuffing() {
    let bytes = Pop3Builder::new()
        .ok_multiline(
            "message follows",
            vec![
                "From: sender@example.com".to_string(),
                "Subject: Test".to_string(),
                ".dotline".to_string(), // should be byte-stuffed to "..dotline"
            ],
        )
        .build();
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.starts_with("+OK message follows\r\n"));
    assert!(s.contains("From: sender@example.com\r\n"));
    assert!(s.contains("..dotline\r\n")); // byte-stuffed
    assert!(s.ends_with(".\r\n")); // terminator
}

// ============================================================================
// Detection: is_pop3_payload
// ============================================================================

#[test]
fn test_pop3_detection_valid_responses() {
    assert!(is_pop3_payload(b"+OK POP3 server ready\r\n"));
    assert!(is_pop3_payload(b"-ERR Permission denied\r\n"));
    assert!(is_pop3_payload(b"+OK\r\n"));
    assert!(is_pop3_payload(b"-ERR\r\n"));
    assert!(is_pop3_payload(b"+OK 5 2048\r\n"));
}

#[test]
fn test_pop3_detection_valid_commands() {
    assert!(is_pop3_payload(b"USER alice\r\n"));
    assert!(is_pop3_payload(b"PASS secret\r\n"));
    assert!(is_pop3_payload(b"STAT\r\n"));
    assert!(is_pop3_payload(b"LIST\r\n"));
    assert!(is_pop3_payload(b"RETR 1\r\n"));
    assert!(is_pop3_payload(b"DELE 1\r\n"));
    assert!(is_pop3_payload(b"NOOP\r\n"));
    assert!(is_pop3_payload(b"RSET\r\n"));
    assert!(is_pop3_payload(b"TOP 1 5\r\n"));
    assert!(is_pop3_payload(b"UIDL\r\n"));
    assert!(is_pop3_payload(b"QUIT\r\n"));
    assert!(is_pop3_payload(b"CAPA\r\n"));
}

#[test]
fn test_pop3_detection_invalid() {
    assert!(!is_pop3_payload(b""));
    assert!(!is_pop3_payload(b"HTTP/1.1 200 OK\r\n"));
    assert!(!is_pop3_payload(b"\x00\x01\x02\x03"));
    assert!(!is_pop3_payload(b"FOOBAR\r\n"));
    assert!(!is_pop3_payload(b"EHLO example.com\r\n")); // SMTP, not POP3
}

// ============================================================================
// Layer parsing: Pop3Layer field access on raw bytes
// ============================================================================

#[test]
fn test_pop3_layer_ok_response() {
    let data = b"+OK POP3 server ready\r\n";
    let layer = make_layer(data);
    assert!(layer.is_response(data));
    assert!(layer.is_ok(data));
    assert!(!layer.is_err_response(data));
    assert_eq!(layer.response_text(data).unwrap(), "POP3 server ready");
}

#[test]
fn test_pop3_layer_err_response() {
    let data = b"-ERR Permission denied\r\n";
    let layer = make_layer(data);
    assert!(layer.is_response(data));
    assert!(!layer.is_ok(data));
    assert!(layer.is_err_response(data));
    assert_eq!(layer.response_text(data).unwrap(), "Permission denied");
}

#[test]
fn test_pop3_layer_stat_response() {
    let data = b"+OK 5 2048\r\n";
    let layer = make_layer(data);
    assert!(layer.is_ok(data));
    assert_eq!(layer.response_text(data).unwrap(), "5 2048");
}

#[test]
fn test_pop3_layer_user_command() {
    let data = b"USER alice\r\n";
    let layer = make_layer(data);
    assert!(!layer.is_response(data));
    assert_eq!(layer.command(data).unwrap(), CMD_USER);
    assert_eq!(layer.args(data).unwrap(), "alice");
}

#[test]
fn test_pop3_layer_pass_command() {
    let data = b"PASS secret\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_PASS);
    assert_eq!(layer.args(data).unwrap(), "secret");
}

#[test]
fn test_pop3_layer_retr_command() {
    let data = b"RETR 5\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_RETR);
    assert_eq!(layer.args(data).unwrap(), "5");
}

#[test]
fn test_pop3_layer_dele_command() {
    let data = b"DELE 3\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_DELE);
    assert_eq!(layer.args(data).unwrap(), "3");
}

#[test]
fn test_pop3_layer_top_command() {
    let data = b"TOP 2 10\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_TOP);
    assert_eq!(layer.args(data).unwrap(), "2 10");
}

#[test]
fn test_pop3_layer_stat_no_args() {
    let data = b"STAT\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_STAT);
    assert_eq!(layer.args(data).unwrap(), "");
}

#[test]
fn test_pop3_layer_quit_no_args() {
    let data = b"QUIT\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_QUIT);
    assert_eq!(layer.args(data).unwrap(), "");
}

#[test]
fn test_pop3_layer_raw() {
    let data = b"+OK POP3 server ready\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.raw(data), "+OK POP3 server ready\r\n");
}

// ============================================================================
// Full-stack packet parsing
// ============================================================================

#[test]
fn test_pop3_full_stack_server_greeting() {
    let payload = Pop3Builder::new().server_ready().build();
    let pkt = build_pop3_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Pop3).is_some());

    let pop3 = pkt.pop3().unwrap();
    let buf = pkt.as_bytes();
    assert!(pop3.is_ok(buf));
    assert_eq!(pop3.response_text(buf).unwrap(), "POP3 server ready");
}

#[test]
fn test_pop3_full_stack_user_command() {
    let payload = Pop3Builder::new().user("alice").build();
    let pkt = build_pop3_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Pop3).is_some());
    let pop3 = pkt.pop3().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(pop3.command(buf).unwrap(), "USER");
    assert_eq!(pop3.args(buf).unwrap(), "alice");
    assert!(!pop3.is_response(buf));
}

#[test]
fn test_pop3_full_stack_err_response() {
    let payload = Pop3Builder::new().permission_denied().build();
    let pkt = build_pop3_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Pop3).is_some());
    let pop3 = pkt.pop3().unwrap();
    let buf = pkt.as_bytes();
    assert!(pop3.is_err_response(buf));
    assert_eq!(pop3.response_text(buf).unwrap(), "Permission denied");
}

#[test]
fn test_pop3_full_stack_stat() {
    let payload = Pop3Builder::new().stat_reply(10, 4096).build();
    let pkt = build_pop3_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Pop3).is_some());
    let pop3 = pkt.pop3().unwrap();
    let buf = pkt.as_bytes();
    assert!(pop3.is_ok(buf));
    assert_eq!(pop3.response_text(buf).unwrap(), "10 4096");
}

#[test]
fn test_pop3_non_pop3_port_not_detected() {
    let raw = LayerStack::new()
        .push(LayerStackEntry::Ethernet(
            EthernetBuilder::new()
                .dst(MacAddress::BROADCAST)
                .src(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ))
        .push(LayerStackEntry::Ipv4(
            Ipv4Builder::new()
                .src(Ipv4Addr::new(192, 168, 1, 10))
                .dst(Ipv4Addr::new(192, 168, 1, 20))
                .ttl(64),
        ))
        .push(LayerStackEntry::Tcp(
            TcpBuilder::new().src_port(54321).dst_port(9999),
        ))
        .push(LayerStackEntry::Raw(b"+OK POP3 server ready\r\n".to_vec()))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    assert!(pkt.get_layer(LayerKind::Pop3).is_none());
}

// ============================================================================
// Constants and field names
// ============================================================================

#[test]
fn test_pop3_constants() {
    assert_eq!(POP3_PORT, 110);
    assert_eq!(POP3_MIN_HEADER_LEN, 4);
}

#[test]
fn test_pop3_field_names() {
    assert!(POP3_FIELD_NAMES.contains(&"command"));
    assert!(POP3_FIELD_NAMES.contains(&"args"));
    assert!(POP3_FIELD_NAMES.contains(&"is_ok"));
    assert!(POP3_FIELD_NAMES.contains(&"is_err"));
    assert!(POP3_FIELD_NAMES.contains(&"response_text"));
    assert!(POP3_FIELD_NAMES.contains(&"is_response"));
    assert!(POP3_FIELD_NAMES.contains(&"raw"));
}

#[test]
fn test_pop3_command_constants() {
    assert_eq!(CMD_USER, "USER");
    assert_eq!(CMD_PASS, "PASS");
    assert_eq!(CMD_STAT, "STAT");
    assert_eq!(CMD_LIST, "LIST");
    assert_eq!(CMD_RETR, "RETR");
    assert_eq!(CMD_DELE, "DELE");
    assert_eq!(CMD_NOOP, "NOOP");
    assert_eq!(CMD_RSET, "RSET");
    assert_eq!(CMD_TOP, "TOP");
    assert_eq!(CMD_UIDL, "UIDL");
    assert_eq!(CMD_QUIT, "QUIT");
    assert_eq!(CMD_CAPA, "CAPA");
}
