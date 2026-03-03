//! SMTP (Simple Mail Transfer Protocol) integration tests.
//!
//! Tests SMTP parsing, building, full-stack packet handling, and field access
//! for both server replies and client commands.

use stackforge_core::layer::smtp::{
    CMD_AUTH, CMD_DATA, CMD_EHLO, CMD_HELO, CMD_MAIL, CMD_QUIT, CMD_RCPT, CMD_STARTTLS,
    REPLY_AUTH_FAILED, REPLY_AUTH_SUCCESS, REPLY_CLOSING, REPLY_DATA_INPUT, REPLY_OK,
    REPLY_SERVICE_READY, SMTP_FIELD_NAMES, SMTP_MIN_HEADER_LEN, SMTP_PORT, SMTP_SUBMISSION_PORT,
    SMTPS_PORT, SmtpBuilder, SmtpLayer, is_smtp_payload, reply_code_description,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap SMTP bytes in Eth/IP/TCP on port 25
// ============================================================================

fn build_smtp_tcp_packet(payload: Vec<u8>) -> Packet {
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
            TcpBuilder::new().src_port(54321).dst_port(25),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> SmtpLayer {
    SmtpLayer::new(LayerIndex::new(LayerKind::Smtp, 0, data.len()))
}

// ============================================================================
// Builder tests: server replies
// ============================================================================

#[test]
fn test_smtp_builder_service_ready() {
    let bytes = SmtpBuilder::new().service_ready("mail.example.com").build();
    assert_eq!(bytes, b"220 mail.example.com ESMTP\r\n");
}

#[test]
fn test_smtp_builder_closing() {
    let bytes = SmtpBuilder::new().closing().build();
    assert_eq!(bytes, b"221 Bye\r\n");
}

#[test]
fn test_smtp_builder_auth_success() {
    let bytes = SmtpBuilder::new().auth_success().build();
    assert_eq!(bytes, b"235 Authentication successful\r\n");
}

#[test]
fn test_smtp_builder_ok() {
    let bytes = SmtpBuilder::new().ok("OK").build();
    assert_eq!(bytes, b"250 OK\r\n");
}

#[test]
fn test_smtp_builder_start_mail_input() {
    let bytes = SmtpBuilder::new().start_mail_input().build();
    assert_eq!(bytes, b"354 Start mail input; end with <CRLF>.<CRLF>\r\n");
}

#[test]
fn test_smtp_builder_service_unavailable() {
    let bytes = SmtpBuilder::new().service_unavailable().build();
    assert_eq!(bytes, b"421 Service not available\r\n");
}

#[test]
fn test_smtp_builder_auth_failed() {
    let bytes = SmtpBuilder::new().auth_failed().build();
    assert_eq!(bytes, b"535 Authentication credentials invalid\r\n");
}

#[test]
fn test_smtp_builder_mailbox_not_found() {
    let bytes = SmtpBuilder::new()
        .mailbox_not_found("User not found")
        .build();
    assert_eq!(bytes, b"550 User not found\r\n");
}

#[test]
fn test_smtp_builder_auth_required() {
    let bytes = SmtpBuilder::new().auth_required().build();
    assert_eq!(bytes, b"530 Authentication required\r\n");
}

#[test]
fn test_smtp_builder_ehlo_response_multiline() {
    let bytes = SmtpBuilder::new()
        .ehlo_response(
            "mail.example.com",
            vec![
                "PIPELINING".to_string(),
                "SIZE 10485760".to_string(),
                "AUTH LOGIN PLAIN".to_string(),
            ],
        )
        .build();
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.starts_with("250-mail.example.com\r\n"));
    assert!(s.contains("250-PIPELINING\r\n"));
    assert!(s.contains("250-SIZE 10485760\r\n"));
    assert!(s.contains("250-AUTH LOGIN PLAIN\r\n"));
    assert!(s.ends_with("250 OK\r\n"));
}

#[test]
fn test_smtp_builder_auth_challenge() {
    let bytes = SmtpBuilder::new().auth_challenge("dXNlcm5hbWU=").build();
    assert_eq!(bytes, b"334 dXNlcm5hbWU=\r\n");
}

// ============================================================================
// Builder tests: client commands
// ============================================================================

#[test]
fn test_smtp_builder_ehlo() {
    let bytes = SmtpBuilder::new().ehlo("client.example.com").build();
    assert_eq!(bytes, b"EHLO client.example.com\r\n");
}

#[test]
fn test_smtp_builder_helo() {
    let bytes = SmtpBuilder::new().helo("client.example.com").build();
    assert_eq!(bytes, b"HELO client.example.com\r\n");
}

#[test]
fn test_smtp_builder_mail_from() {
    let bytes = SmtpBuilder::new().mail_from("user@example.com").build();
    assert_eq!(bytes, b"MAIL FROM:<user@example.com>\r\n");
}

#[test]
fn test_smtp_builder_rcpt_to() {
    let bytes = SmtpBuilder::new().rcpt_to("dest@example.com").build();
    assert_eq!(bytes, b"RCPT TO:<dest@example.com>\r\n");
}

#[test]
fn test_smtp_builder_data() {
    let bytes = SmtpBuilder::new().data().build();
    assert_eq!(bytes, b"DATA\r\n");
}

#[test]
fn test_smtp_builder_quit() {
    let bytes = SmtpBuilder::new().quit().build();
    assert_eq!(bytes, b"QUIT\r\n");
}

#[test]
fn test_smtp_builder_starttls() {
    let bytes = SmtpBuilder::new().starttls().build();
    assert_eq!(bytes, b"STARTTLS\r\n");
}

#[test]
fn test_smtp_builder_auth_login() {
    let bytes = SmtpBuilder::new().auth("LOGIN", "").build();
    assert_eq!(bytes, b"AUTH LOGIN\r\n");
}

#[test]
fn test_smtp_builder_auth_plain_with_initial() {
    let bytes = SmtpBuilder::new()
        .auth("PLAIN", "AGFsaWNlAHNlY3JldA==")
        .build();
    assert_eq!(bytes, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
}

#[test]
fn test_smtp_builder_rset() {
    let bytes = SmtpBuilder::new().rset().build();
    assert_eq!(bytes, b"RSET\r\n");
}

#[test]
fn test_smtp_builder_noop() {
    let bytes = SmtpBuilder::new().noop().build();
    assert_eq!(bytes, b"NOOP\r\n");
}

#[test]
fn test_smtp_builder_vrfy() {
    let bytes = SmtpBuilder::new().vrfy("user@example.com").build();
    assert_eq!(bytes, b"VRFY user@example.com\r\n");
}

// ============================================================================
// Detection: is_smtp_payload
// ============================================================================

#[test]
fn test_smtp_detection_valid_replies() {
    assert!(is_smtp_payload(b"220 mail.example.com ESMTP Postfix\r\n"));
    assert!(is_smtp_payload(b"250 OK\r\n"));
    assert!(is_smtp_payload(b"354 Start mail input\r\n"));
    assert!(is_smtp_payload(b"421 Service not available\r\n"));
    assert!(is_smtp_payload(b"500 Syntax error\r\n"));
    assert!(is_smtp_payload(b"535 Authentication failed\r\n"));
}

#[test]
fn test_smtp_detection_valid_commands() {
    assert!(is_smtp_payload(b"EHLO example.com\r\n"));
    assert!(is_smtp_payload(b"HELO example.com\r\n"));
    assert!(is_smtp_payload(b"MAIL FROM:<user@example.com>\r\n"));
    assert!(is_smtp_payload(b"RCPT TO:<dest@example.com>\r\n"));
    assert!(is_smtp_payload(b"DATA\r\n"));
    assert!(is_smtp_payload(b"QUIT\r\n"));
    assert!(is_smtp_payload(b"STARTTLS\r\n"));
    assert!(is_smtp_payload(b"AUTH LOGIN\r\n"));
}

#[test]
fn test_smtp_detection_multiline() {
    assert!(is_smtp_payload(
        b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n"
    ));
}

#[test]
fn test_smtp_detection_invalid() {
    assert!(!is_smtp_payload(b""));
    assert!(!is_smtp_payload(b"GET / HTTP/1.1\r\n"));
    assert!(!is_smtp_payload(b"\x00\x01\x02\x03"));
    assert!(!is_smtp_payload(b"FOOBAR\r\n"));
}

// ============================================================================
// Layer parsing: SmtpLayer field access on raw bytes
// ============================================================================

#[test]
fn test_smtp_layer_reply_220() {
    let data = b"220 mail.example.com ESMTP Postfix\r\n";
    let layer = make_layer(data);
    assert!(layer.is_response(data));
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_SERVICE_READY);
    assert!(layer.reply_text(data).unwrap().contains("ESMTP"));
    assert!(!layer.is_multiline(data));
}

#[test]
fn test_smtp_layer_reply_250_ok() {
    let data = b"250 OK\r\n";
    let layer = make_layer(data);
    assert!(layer.is_response(data));
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_OK);
    assert_eq!(layer.reply_text(data).unwrap(), "OK");
}

#[test]
fn test_smtp_layer_reply_354_start_input() {
    let data = b"354 Start mail input; end with <CRLF>.<CRLF>\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_DATA_INPUT);
}

#[test]
fn test_smtp_layer_multiline_reply() {
    let data = b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n";
    let layer = make_layer(data);
    assert!(layer.is_multiline(data));
    assert_eq!(layer.reply_code(data).unwrap(), 250);
}

#[test]
fn test_smtp_layer_command_ehlo() {
    let data = b"EHLO client.example.com\r\n";
    let layer = make_layer(data);
    assert!(!layer.is_response(data));
    assert_eq!(layer.command(data).unwrap(), CMD_EHLO);
    assert_eq!(layer.args(data).unwrap(), "client.example.com");
}

#[test]
fn test_smtp_layer_command_mail_from() {
    let data = b"MAIL FROM:<sender@example.com>\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_MAIL);
    assert_eq!(layer.mailfrom(data).unwrap(), "sender@example.com");
}

#[test]
fn test_smtp_layer_command_rcpt_to() {
    let data = b"RCPT TO:<recipient@example.com>\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_RCPT);
    assert_eq!(layer.rcptto(data).unwrap(), "recipient@example.com");
}

#[test]
fn test_smtp_layer_command_data() {
    let data = b"DATA\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_DATA);
    assert_eq!(layer.args(data).unwrap(), "");
}

#[test]
fn test_smtp_layer_command_quit() {
    let data = b"QUIT\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_QUIT);
    assert!(!layer.is_response(data));
}

#[test]
fn test_smtp_layer_starttls() {
    let data = b"STARTTLS\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.command(data).unwrap(), CMD_STARTTLS);
}

#[test]
fn test_smtp_layer_reply_535() {
    let data = b"535 Authentication credentials invalid\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.reply_code(data).unwrap(), REPLY_AUTH_FAILED);
}

#[test]
fn test_smtp_layer_raw() {
    let data = b"250 OK\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.raw(data), "250 OK\r\n");
}

// ============================================================================
// Full-stack packet parsing
// ============================================================================

#[test]
fn test_smtp_full_stack_server_greeting() {
    let payload = SmtpBuilder::new().service_ready("mail.example.com").build();
    let pkt = build_smtp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Smtp).is_some());

    let smtp = pkt.smtp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(smtp.reply_code(buf).unwrap(), REPLY_SERVICE_READY);
    assert!(smtp.is_response(buf));
}

#[test]
fn test_smtp_full_stack_ehlo() {
    let payload = SmtpBuilder::new().ehlo("client.example.com").build();
    let pkt = build_smtp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Smtp).is_some());
    let smtp = pkt.smtp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(smtp.command(buf).unwrap(), "EHLO");
    assert_eq!(smtp.args(buf).unwrap(), "client.example.com");
}

#[test]
fn test_smtp_full_stack_mail_from() {
    let payload = SmtpBuilder::new().mail_from("user@example.com").build();
    let pkt = build_smtp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Smtp).is_some());
    let smtp = pkt.smtp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(smtp.mailfrom(buf).unwrap(), "user@example.com");
}

#[test]
fn test_smtp_full_stack_rcpt_to() {
    let payload = SmtpBuilder::new().rcpt_to("dest@example.com").build();
    let pkt = build_smtp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Smtp).is_some());
    let smtp = pkt.smtp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(smtp.rcptto(buf).unwrap(), "dest@example.com");
}

#[test]
fn test_smtp_full_stack_starttls() {
    let payload = SmtpBuilder::new().starttls().build();
    let pkt = build_smtp_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Smtp).is_some());
    let smtp = pkt.smtp().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(smtp.command(buf).unwrap(), "STARTTLS");
}

#[test]
fn test_smtp_non_smtp_port_not_detected() {
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
        .push(LayerStackEntry::Raw(
            b"220 mail.example.com ESMTP\r\n".to_vec(),
        ))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    assert!(pkt.get_layer(LayerKind::Smtp).is_none());
}

// ============================================================================
// Constants and reply code descriptions
// ============================================================================

#[test]
fn test_smtp_constants() {
    assert_eq!(SMTP_PORT, 25);
    assert_eq!(SMTP_SUBMISSION_PORT, 587);
    assert_eq!(SMTPS_PORT, 465);
    assert_eq!(SMTP_MIN_HEADER_LEN, 4);
    assert_eq!(REPLY_SERVICE_READY, 220);
    assert_eq!(REPLY_CLOSING, 221);
    assert_eq!(REPLY_OK, 250);
    assert_eq!(REPLY_DATA_INPUT, 354);
}

#[test]
fn test_smtp_reply_code_descriptions() {
    assert_eq!(reply_code_description(220), "Service ready");
    assert_eq!(
        reply_code_description(250),
        "Requested mail action okay, completed"
    );
    assert_eq!(
        reply_code_description(354),
        "Start mail input; end with <CRLF>.<CRLF>"
    );
    assert_eq!(
        reply_code_description(421),
        "Service not available, closing channel"
    );
    assert_eq!(
        reply_code_description(500),
        "Syntax error, command unrecognized"
    );
    assert_eq!(
        reply_code_description(535),
        "Authentication credentials invalid"
    );
}

#[test]
fn test_smtp_field_names() {
    assert!(SMTP_FIELD_NAMES.contains(&"command"));
    assert!(SMTP_FIELD_NAMES.contains(&"args"));
    assert!(SMTP_FIELD_NAMES.contains(&"reply_code"));
    assert!(SMTP_FIELD_NAMES.contains(&"reply_text"));
    assert!(SMTP_FIELD_NAMES.contains(&"is_response"));
    assert!(SMTP_FIELD_NAMES.contains(&"is_multiline"));
    assert!(SMTP_FIELD_NAMES.contains(&"mailfrom"));
    assert!(SMTP_FIELD_NAMES.contains(&"rcptto"));
}

#[test]
fn test_smtp_command_constants() {
    assert_eq!(CMD_EHLO, "EHLO");
    assert_eq!(CMD_HELO, "HELO");
    assert_eq!(CMD_MAIL, "MAIL");
    assert_eq!(CMD_RCPT, "RCPT");
    assert_eq!(CMD_DATA, "DATA");
    assert_eq!(CMD_QUIT, "QUIT");
    assert_eq!(CMD_STARTTLS, "STARTTLS");
    assert_eq!(CMD_AUTH, "AUTH");
}

#[test]
fn test_smtp_auth_success_reply() {
    let bytes = SmtpBuilder::new().auth_success().build();
    let layer = make_layer(&bytes);
    assert_eq!(layer.reply_code(&bytes).unwrap(), REPLY_AUTH_SUCCESS);
}
