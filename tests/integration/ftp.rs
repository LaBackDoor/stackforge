//! FTP (File Transfer Protocol) integration tests.
//!
//! Tests FTP parsing, building, full-stack packet handling, and field access
//! for both server replies and client commands.

use stackforge_core::layer::ftp::{
    CMD_LIST, CMD_PASS, CMD_PASV, CMD_QUIT, CMD_RETR, CMD_STOR, CMD_USER, FTP_CONTROL_PORT,
    FTP_FIELD_NAMES, FTP_MIN_HEADER_LEN, FtpBuilder, FtpLayer, FtpMessageKind,
    REPLY_CLOSING_CONTROL, REPLY_NOT_LOGGED_IN, REPLY_PASSIVE, REPLY_SERVICE_READY,
    REPLY_USER_LOGGED_IN, REPLY_USER_OK_NEED_PASS, is_ftp_payload, reply_code_description,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap FTP bytes in Eth/IP/TCP full-stack packet on port 21
// ============================================================================

fn build_ftp_tcp_packet(payload: Vec<u8>) -> Packet {
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
            TcpBuilder::new().src_port(54321).dst_port(21),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> FtpLayer {
    FtpLayer::new(LayerIndex::new(LayerKind::Ftp, 0, data.len()))
}

// ============================================================================
// Builder tests: server replies
// ============================================================================

#[test]
fn test_ftp_builder_service_ready() {
    let bytes = FtpBuilder::new().service_ready("FTP Server ready").build();
    assert_eq!(bytes, b"220 FTP Server ready\r\n");
}

#[test]
fn test_ftp_builder_closing_control() {
    let bytes = FtpBuilder::new().goodbye().build();
    assert_eq!(bytes, b"221 Goodbye\r\n");
}

#[test]
fn test_ftp_builder_user_logged_in() {
    let bytes = FtpBuilder::new()
        .user_logged_in("User logged in, proceed")
        .build();
    assert_eq!(bytes, b"230 User logged in, proceed\r\n");
}

#[test]
fn test_ftp_builder_password_required() {
    let bytes = FtpBuilder::new().password_required().build();
    assert_eq!(bytes, b"331 Password required\r\n");
}

#[test]
fn test_ftp_builder_not_logged_in() {
    let bytes = FtpBuilder::new().not_logged_in().build();
    assert_eq!(bytes, b"530 Not logged in\r\n");
}

#[test]
fn test_ftp_builder_passive_mode() {
    let bytes = FtpBuilder::new()
        .passive_mode(192, 168, 1, 1, 200, 50)
        .build();
    assert_eq!(bytes, b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n");
}

#[test]
fn test_ftp_builder_transfer_complete() {
    let bytes = FtpBuilder::new().transfer_complete().build();
    assert_eq!(bytes, b"226 Transfer complete\r\n");
}

#[test]
fn test_ftp_builder_file_unavailable() {
    let bytes = FtpBuilder::new().file_unavailable("No such file").build();
    assert_eq!(bytes, b"550 No such file\r\n");
}

#[test]
fn test_ftp_builder_syntax_error() {
    let bytes = FtpBuilder::new()
        .syntax_error("Unrecognized command")
        .build();
    assert_eq!(bytes, b"500 Unrecognized command\r\n");
}

#[test]
fn test_ftp_builder_service_not_available() {
    let bytes = FtpBuilder::new().service_not_available().build();
    assert_eq!(
        bytes,
        b"421 Service not available, closing control connection\r\n"
    );
}

// ============================================================================
// Builder tests: client commands
// ============================================================================

#[test]
fn test_ftp_builder_user_command() {
    let bytes = FtpBuilder::new().user("anonymous").build();
    assert_eq!(bytes, b"USER anonymous\r\n");
}

#[test]
fn test_ftp_builder_pass_command() {
    let bytes = FtpBuilder::new().pass("secret").build();
    assert_eq!(bytes, b"PASS secret\r\n");
}

#[test]
fn test_ftp_builder_retr_command() {
    let bytes = FtpBuilder::new().retr("file.txt").build();
    assert_eq!(bytes, b"RETR file.txt\r\n");
}

#[test]
fn test_ftp_builder_stor_command() {
    let bytes = FtpBuilder::new().stor("upload.dat").build();
    assert_eq!(bytes, b"STOR upload.dat\r\n");
}

#[test]
fn test_ftp_builder_list_command() {
    let bytes = FtpBuilder::new().list("/pub").build();
    assert_eq!(bytes, b"LIST /pub\r\n");
}

#[test]
fn test_ftp_builder_pasv_command() {
    let bytes = FtpBuilder::new().pasv().build();
    assert_eq!(bytes, b"PASV\r\n");
}

#[test]
fn test_ftp_builder_quit_command() {
    let bytes = FtpBuilder::new().quit().build();
    assert_eq!(bytes, b"QUIT\r\n");
}

#[test]
fn test_ftp_builder_port_command() {
    let bytes = FtpBuilder::new().port(192, 168, 1, 2, 100, 30).build();
    assert_eq!(bytes, b"PORT 192,168,1,2,100,30\r\n");
}

#[test]
fn test_ftp_builder_cwd_command() {
    let bytes = FtpBuilder::new().cwd("/home/user").build();
    assert_eq!(bytes, b"CWD /home/user\r\n");
}

#[test]
fn test_ftp_builder_noop_command() {
    let bytes = FtpBuilder::new().noop().build();
    assert_eq!(bytes, b"NOOP\r\n");
}

#[test]
fn test_ftp_builder_multiline_feat_reply() {
    let bytes = FtpBuilder::new()
        .feat_reply(vec!["SIZE".to_string(), "MDTM".to_string()])
        .build();
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.starts_with("211-"));
    assert!(s.contains("SIZE\r\n"));
    assert!(s.contains("MDTM\r\n"));
    assert!(s.ends_with("211 End\r\n"));
}

#[test]
fn test_ftp_builder_auth_command() {
    let bytes = FtpBuilder::new().auth("TLS").build();
    assert_eq!(bytes, b"AUTH TLS\r\n");
}

// ============================================================================
// Detection: is_ftp_payload
// ============================================================================

#[test]
fn test_ftp_detection_valid_replies() {
    assert!(is_ftp_payload(b"220 Service ready\r\n"));
    assert!(is_ftp_payload(b"331 Password required\r\n"));
    assert!(is_ftp_payload(b"230 User logged in\r\n"));
    assert!(is_ftp_payload(b"550 File not found\r\n"));
    assert!(is_ftp_payload(b"221 Goodbye\r\n"));
    assert!(is_ftp_payload(
        b"227 Entering Passive Mode (1,2,3,4,5,6)\r\n"
    ));
    assert!(is_ftp_payload(b"530 Not logged in\r\n"));
}

#[test]
fn test_ftp_detection_valid_commands() {
    assert!(is_ftp_payload(b"USER anonymous\r\n"));
    assert!(is_ftp_payload(b"PASS secret\r\n"));
    assert!(is_ftp_payload(b"LIST\r\n"));
    assert!(is_ftp_payload(b"QUIT\r\n"));
    assert!(is_ftp_payload(b"RETR file.txt\r\n"));
    assert!(is_ftp_payload(b"STOR upload.dat\r\n"));
    assert!(is_ftp_payload(b"PASV\r\n"));
    assert!(is_ftp_payload(b"NOOP\r\n"));
}

#[test]
fn test_ftp_detection_multiline_response() {
    assert!(is_ftp_payload(b"220-Welcome to FTP\r\n220 Ready\r\n"));
}

#[test]
fn test_ftp_detection_invalid() {
    assert!(!is_ftp_payload(b""));
    assert!(!is_ftp_payload(b"GET / HTTP/1.1\r\n"));
    assert!(!is_ftp_payload(b"\x00\x00\x00\x01"));
    assert!(!is_ftp_payload(b"ab")); // too short
    assert!(!is_ftp_payload(b"FOOBAR\r\n")); // not an FTP command
}

// ============================================================================
// Layer parsing: FtpLayer field access on raw bytes
// ============================================================================

#[test]
fn test_ftp_layer_reply_code_220() {
    let data = b"220 Service ready for new user\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_SERVICE_READY);
    assert_eq!(
        layer.reply_text(data).unwrap(),
        "Service ready for new user"
    );
    assert!(layer.is_response(data));
    assert!(!layer.is_multiline(data));
    assert_eq!(layer.message_kind(data), FtpMessageKind::Reply);
}

#[test]
fn test_ftp_layer_reply_code_221() {
    let data = b"221 Goodbye\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_CLOSING_CONTROL);
    assert_eq!(layer.reply_text(data).unwrap(), "Goodbye");
}

#[test]
fn test_ftp_layer_reply_code_230() {
    let data = b"230 User logged in, proceed\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_USER_LOGGED_IN);
    assert!(layer.is_response(data));
}

#[test]
fn test_ftp_layer_reply_code_331() {
    let data = b"331 Password required\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_USER_OK_NEED_PASS);
    assert_eq!(layer.reply_text(data).unwrap(), "Password required");
}

#[test]
fn test_ftp_layer_reply_code_530() {
    let data = b"530 Not logged in\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_NOT_LOGGED_IN);
    assert!(layer.is_response(data));
}

#[test]
fn test_ftp_layer_multiline_reply() {
    let data = b"220-Welcome to FTP\r\n220 Ready\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_SERVICE_READY);
    assert!(layer.is_multiline(data));
}

#[test]
fn test_ftp_layer_command_user() {
    let data = b"USER anonymous\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_USER);
    assert_eq!(layer.args(data).unwrap(), "anonymous");
    assert!(!layer.is_response(data));
    assert_eq!(layer.message_kind(data), FtpMessageKind::Command);
}

#[test]
fn test_ftp_layer_command_pass() {
    let data = b"PASS secret\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_PASS);
    assert_eq!(layer.args(data).unwrap(), "secret");
}

#[test]
fn test_ftp_layer_command_retr() {
    let data = b"RETR file.txt\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_RETR);
    assert_eq!(layer.args(data).unwrap(), "file.txt");
}

#[test]
fn test_ftp_layer_command_stor() {
    let data = b"STOR upload.dat\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_STOR);
    assert_eq!(layer.args(data).unwrap(), "upload.dat");
}

#[test]
fn test_ftp_layer_command_list_no_args() {
    let data = b"LIST\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_LIST);
    assert_eq!(layer.args(data).unwrap(), "");
}

#[test]
fn test_ftp_layer_command_quit() {
    let data = b"QUIT\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_QUIT);
    assert_eq!(layer.args(data).unwrap(), "");
    assert!(!layer.is_response(data));
}

#[test]
fn test_ftp_layer_passive_mode_response() {
    let data = b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_PASSIVE);
    assert!(layer.reply_text(data).unwrap().contains("Passive Mode"));
}

#[test]
fn test_ftp_layer_raw_access() {
    let data = b"220 Ready\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.raw(data), "220 Ready\r\n");
}

// ============================================================================
// Full-stack packet parsing
// ============================================================================

#[test]
fn test_ftp_full_stack_server_greeting() {
    let payload = FtpBuilder::new().service_ready("FTP Server ready").build();
    let pkt = build_ftp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Ftp).is_some());

    let ftp = pkt.ftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(ftp.reply_code(buf).unwrap(), REPLY_SERVICE_READY);
    assert!(ftp.is_response(buf));
}

#[test]
fn test_ftp_full_stack_user_command() {
    let payload = FtpBuilder::new().user("alice").build();
    let pkt = build_ftp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ftp).is_some());
    let ftp = pkt.ftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(ftp.command(buf).unwrap(), "USER");
    assert_eq!(ftp.args(buf).unwrap(), "alice");
    assert!(!ftp.is_response(buf));
}

#[test]
fn test_ftp_full_stack_quit_command() {
    let payload = FtpBuilder::new().quit().build();
    let pkt = build_ftp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ftp).is_some());
    let ftp = pkt.ftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(ftp.command(buf).unwrap(), "QUIT");
}

#[test]
fn test_ftp_full_stack_pasv_response() {
    let payload = FtpBuilder::new().passive_mode(10, 0, 0, 1, 200, 50).build();
    let pkt = build_ftp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ftp).is_some());
    let ftp = pkt.ftp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(ftp.reply_code(buf).unwrap(), REPLY_PASSIVE);
    assert!(ftp.is_response(buf));
}

#[test]
fn test_ftp_full_stack_multiline_response() {
    let payload = FtpBuilder::new()
        .feat_reply(vec!["SIZE".to_string(), "MDTM".to_string()])
        .build();
    let pkt = build_ftp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ftp).is_some());
    let ftp = pkt.ftp().unwrap();
    let buf = pkt.as_bytes();
    assert!(ftp.is_multiline(buf));
}

#[test]
fn test_ftp_non_ftp_port_not_detected() {
    // Build a packet on port 8080, not port 21
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
            TcpBuilder::new().src_port(54321).dst_port(8080),
        ))
        .push(LayerStackEntry::Raw(b"220 FTP Ready\r\n".to_vec()))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    // Should NOT be detected as FTP (wrong port, will be detected as HTTP or raw)
    assert!(pkt.get_layer(LayerKind::Ftp).is_none());
}

// ============================================================================
// Constants and reply code descriptions
// ============================================================================

#[test]
fn test_ftp_constants() {
    assert_eq!(FTP_CONTROL_PORT, 21);
    assert_eq!(FTP_MIN_HEADER_LEN, 4);
    assert_eq!(REPLY_SERVICE_READY, 220);
    assert_eq!(REPLY_CLOSING_CONTROL, 221);
    assert_eq!(REPLY_USER_LOGGED_IN, 230);
    assert_eq!(REPLY_USER_OK_NEED_PASS, 331);
    assert_eq!(REPLY_NOT_LOGGED_IN, 530);
}

#[test]
fn test_ftp_reply_code_descriptions() {
    assert_eq!(reply_code_description(220), "Service ready for new user");
    assert_eq!(
        reply_code_description(221),
        "Service closing control connection"
    );
    assert_eq!(reply_code_description(230), "User logged in, proceed");
    assert_eq!(reply_code_description(331), "User name okay, need password");
    assert_eq!(reply_code_description(530), "Not logged in");
    assert_eq!(
        reply_code_description(550),
        "Requested action not taken; file unavailable"
    );
}

#[test]
fn test_ftp_field_names() {
    assert!(FTP_FIELD_NAMES.contains(&"command"));
    assert!(FTP_FIELD_NAMES.contains(&"args"));
    assert!(FTP_FIELD_NAMES.contains(&"reply_code"));
    assert!(FTP_FIELD_NAMES.contains(&"reply_text"));
    assert!(FTP_FIELD_NAMES.contains(&"is_response"));
    assert!(FTP_FIELD_NAMES.contains(&"is_multiline"));
    assert!(FTP_FIELD_NAMES.contains(&"raw"));
}

#[test]
fn test_ftp_commands_constants() {
    assert_eq!(CMD_USER, "USER");
    assert_eq!(CMD_PASS, "PASS");
    assert_eq!(CMD_RETR, "RETR");
    assert_eq!(CMD_STOR, "STOR");
    assert_eq!(CMD_LIST, "LIST");
    assert_eq!(CMD_PASV, "PASV");
    assert_eq!(CMD_QUIT, "QUIT");
}
