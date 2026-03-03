//! IMAP (Internet Message Access Protocol) integration tests.
//!
//! Tests IMAP parsing, building, full-stack packet handling, and field access
//! for client commands, tagged responses, untagged responses, and continuation requests.

use stackforge_core::layer::imap::{
    CMD_CAPABILITY, CMD_CLOSE, CMD_COPY, CMD_CREATE, CMD_DELETE, CMD_EXAMINE, CMD_EXPUNGE,
    CMD_FETCH, CMD_LOGIN, CMD_LOGOUT, CMD_NOOP, CMD_SEARCH, CMD_SELECT, CMD_STARTTLS, CMD_STORE,
    CMD_SUBSCRIBE, CMD_UNSUBSCRIBE, IMAP_FIELD_NAMES, IMAP_MIN_HEADER_LEN, IMAP_PORT, ImapBuilder,
    ImapLayer, STATUS_BAD, STATUS_BYE, STATUS_NO, STATUS_OK, STATUS_PREAUTH, is_imap_payload,
};
use stackforge_core::layer::stack::{LayerStack, LayerStackEntry};
use stackforge_core::layer::tcp::builder::TcpBuilder;
use stackforge_core::layer::{EthernetBuilder, LayerIndex, LayerKind};
use stackforge_core::prelude::*;
use std::net::Ipv4Addr;

// ============================================================================
// Helper: wrap IMAP bytes in Eth/IP/TCP on port 143
// ============================================================================

fn build_imap_tcp_packet(payload: Vec<u8>) -> Packet {
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
            TcpBuilder::new().src_port(54321).dst_port(143),
        ))
        .push(LayerStackEntry::Raw(payload))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    pkt
}

fn make_layer(data: &[u8]) -> ImapLayer {
    ImapLayer::new(LayerIndex::new(LayerKind::Imap, 0, data.len()))
}

// ============================================================================
// Builder tests: server responses
// ============================================================================

#[test]
fn test_imap_builder_server_greeting() {
    let bytes = ImapBuilder::new()
        .server_greeting("IMAP4rev1 Service Ready")
        .build();
    assert_eq!(bytes, b"* OK IMAP4rev1 Service Ready\r\n");
}

#[test]
fn test_imap_builder_bye() {
    let bytes = ImapBuilder::new().bye("Server logging out").build();
    assert_eq!(bytes, b"* BYE Server logging out\r\n");
}

#[test]
fn test_imap_builder_capability_response() {
    let bytes = ImapBuilder::new()
        .capability("IMAP4rev1 AUTH=PLAIN STARTTLS")
        .build();
    assert_eq!(bytes, b"* CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS\r\n");
}

#[test]
fn test_imap_builder_exists() {
    let bytes = ImapBuilder::new().exists(5).build();
    assert_eq!(bytes, b"* 5 EXISTS\r\n");
}

#[test]
fn test_imap_builder_recent() {
    let bytes = ImapBuilder::new().recent(2).build();
    assert_eq!(bytes, b"* 2 RECENT\r\n");
}

#[test]
fn test_imap_builder_expunge_notify() {
    let bytes = ImapBuilder::new().expunge_notify(3).build();
    assert_eq!(bytes, b"* 3 EXPUNGE\r\n");
}

#[test]
fn test_imap_builder_tagged_ok() {
    let bytes = ImapBuilder::new().ok("A001", "LOGIN completed").build();
    assert_eq!(bytes, b"A001 OK LOGIN completed\r\n");
}

#[test]
fn test_imap_builder_tagged_no() {
    let bytes = ImapBuilder::new().no("A002", "login failed").build();
    assert_eq!(bytes, b"A002 NO login failed\r\n");
}

#[test]
fn test_imap_builder_tagged_bad() {
    let bytes = ImapBuilder::new().bad("A003", "unknown command").build();
    assert_eq!(bytes, b"A003 BAD unknown command\r\n");
}

#[test]
fn test_imap_builder_continuation() {
    let bytes = ImapBuilder::new().continuation("go ahead").build();
    assert_eq!(bytes, b"+ go ahead\r\n");
}

#[test]
fn test_imap_builder_continuation_empty() {
    let bytes = ImapBuilder::new().continuation("").build();
    assert_eq!(bytes, b"+ \r\n");
}

// ============================================================================
// Builder tests: client commands
// ============================================================================

#[test]
fn test_imap_builder_capability_cmd() {
    let bytes = ImapBuilder::new().capability_cmd("A001").build();
    assert_eq!(bytes, b"A001 CAPABILITY\r\n");
}

#[test]
fn test_imap_builder_noop() {
    let bytes = ImapBuilder::new().noop("A002").build();
    assert_eq!(bytes, b"A002 NOOP\r\n");
}

#[test]
fn test_imap_builder_logout() {
    let bytes = ImapBuilder::new().logout("A003").build();
    assert_eq!(bytes, b"A003 LOGOUT\r\n");
}

#[test]
fn test_imap_builder_login() {
    let bytes = ImapBuilder::new()
        .login("A001", "alice", "password123")
        .build();
    assert_eq!(bytes, b"A001 LOGIN alice password123\r\n");
}

#[test]
fn test_imap_builder_select() {
    let bytes = ImapBuilder::new().select("A002", "INBOX").build();
    assert_eq!(bytes, b"A002 SELECT INBOX\r\n");
}

#[test]
fn test_imap_builder_examine() {
    let bytes = ImapBuilder::new().examine("A003", "Sent").build();
    assert_eq!(bytes, b"A003 EXAMINE Sent\r\n");
}

#[test]
fn test_imap_builder_fetch() {
    let bytes = ImapBuilder::new().fetch("A004", "1:*", "FLAGS").build();
    assert_eq!(bytes, b"A004 FETCH 1:* FLAGS\r\n");
}

#[test]
fn test_imap_builder_store() {
    let bytes = ImapBuilder::new()
        .store("A005", "1", "+FLAGS", "\\Seen")
        .build();
    assert_eq!(bytes, b"A005 STORE 1 +FLAGS (\\Seen)\r\n");
}

#[test]
fn test_imap_builder_search() {
    let bytes = ImapBuilder::new().search("A006", "UNSEEN").build();
    assert_eq!(bytes, b"A006 SEARCH UNSEEN\r\n");
}

#[test]
fn test_imap_builder_copy() {
    let bytes = ImapBuilder::new().copy("A007", "1:5", "Archive").build();
    assert_eq!(bytes, b"A007 COPY 1:5 Archive\r\n");
}

#[test]
fn test_imap_builder_expunge() {
    let bytes = ImapBuilder::new().expunge("A008").build();
    assert_eq!(bytes, b"A008 EXPUNGE\r\n");
}

#[test]
fn test_imap_builder_close() {
    let bytes = ImapBuilder::new().close("A009").build();
    assert_eq!(bytes, b"A009 CLOSE\r\n");
}

#[test]
fn test_imap_builder_create() {
    let bytes = ImapBuilder::new().create("A010", "NewMailbox").build();
    assert_eq!(bytes, b"A010 CREATE NewMailbox\r\n");
}

#[test]
fn test_imap_builder_delete() {
    let bytes = ImapBuilder::new().delete("A011", "OldMailbox").build();
    assert_eq!(bytes, b"A011 DELETE OldMailbox\r\n");
}

#[test]
fn test_imap_builder_subscribe() {
    let bytes = ImapBuilder::new().subscribe("A012", "INBOX.Work").build();
    assert_eq!(bytes, b"A012 SUBSCRIBE INBOX.Work\r\n");
}

#[test]
fn test_imap_builder_unsubscribe() {
    let bytes = ImapBuilder::new().unsubscribe("A013", "INBOX.Old").build();
    assert_eq!(bytes, b"A013 UNSUBSCRIBE INBOX.Old\r\n");
}

#[test]
fn test_imap_builder_starttls() {
    let bytes = ImapBuilder::new().starttls("A014").build();
    assert_eq!(bytes, b"A014 STARTTLS\r\n");
}

#[test]
fn test_imap_builder_uid_fetch() {
    let bytes = ImapBuilder::new().uid("A015", "FETCH", "1:* FLAGS").build();
    assert_eq!(bytes, b"A015 UID FETCH 1:* FLAGS\r\n");
}

// ============================================================================
// Detection: is_imap_payload
// ============================================================================

#[test]
fn test_imap_detection_untagged_responses() {
    assert!(is_imap_payload(b"* OK IMAP4rev1 server ready\r\n"));
    assert!(is_imap_payload(b"* 3 EXISTS\r\n"));
    assert!(is_imap_payload(b"* BYE server closing\r\n"));
    assert!(is_imap_payload(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"));
    assert!(is_imap_payload(b"* 2 RECENT\r\n"));
}

#[test]
fn test_imap_detection_continuation() {
    assert!(is_imap_payload(b"+ go ahead\r\n"));
    assert!(is_imap_payload(b"+ \r\n"));
}

#[test]
fn test_imap_detection_tagged_responses() {
    assert!(is_imap_payload(b"A001 OK LOGIN completed\r\n"));
    assert!(is_imap_payload(b"A002 NO login failed\r\n"));
    assert!(is_imap_payload(b"A003 BAD command unknown\r\n"));
}

#[test]
fn test_imap_detection_client_commands() {
    assert!(is_imap_payload(b"A001 LOGIN user pass\r\n"));
    assert!(is_imap_payload(b"A002 SELECT INBOX\r\n"));
    assert!(is_imap_payload(b"A003 FETCH 1:* FLAGS\r\n"));
    assert!(is_imap_payload(b"A004 NOOP\r\n"));
    assert!(is_imap_payload(b"A005 LOGOUT\r\n"));
    assert!(is_imap_payload(b"A006 CAPABILITY\r\n"));
}

#[test]
fn test_imap_detection_invalid() {
    assert!(!is_imap_payload(b""));
    assert!(!is_imap_payload(b"GET / HTTP/1.1\r\n"));
    assert!(!is_imap_payload(b"+OK POP3 server ready\r\n")); // POP3, not IMAP
    assert!(!is_imap_payload(b"ab")); // too short
}

// ============================================================================
// Layer parsing: ImapLayer field access on raw bytes
// ============================================================================

#[test]
fn test_imap_layer_untagged_ok() {
    let data = b"* OK IMAP4rev1 Service Ready\r\n";
    let layer = make_layer(data);
    assert!(layer.is_untagged(data));
    assert!(!layer.is_tagged_response(data));
    assert!(!layer.is_continuation(data));
    assert_eq!(layer.tag(data).unwrap(), "*");
    assert_eq!(layer.command(data).unwrap(), "OK");
    assert_eq!(layer.args(data).unwrap(), "IMAP4rev1 Service Ready");
}

#[test]
fn test_imap_layer_untagged_exists() {
    let data = b"* 3 EXISTS\r\n";
    let layer = make_layer(data);
    assert!(layer.is_untagged(data));
    assert_eq!(layer.tag(data).unwrap(), "*");
    assert_eq!(layer.command(data).unwrap(), "3");
    assert_eq!(layer.args(data).unwrap(), "EXISTS");
}

#[test]
fn test_imap_layer_tagged_ok() {
    let data = b"A001 OK LOGIN completed\r\n";
    let layer = make_layer(data);
    assert!(!layer.is_untagged(data));
    assert!(layer.is_tagged_response(data));
    assert!(!layer.is_continuation(data));
    assert_eq!(layer.tag(data).unwrap(), "A001");
    assert_eq!(layer.command(data).unwrap(), "OK");
    assert_eq!(layer.status(data).unwrap(), STATUS_OK);
    assert_eq!(layer.args(data).unwrap(), "LOGIN completed");
}

#[test]
fn test_imap_layer_tagged_no() {
    let data = b"A002 NO login failed: wrong password\r\n";
    let layer = make_layer(data);
    assert!(layer.is_tagged_response(data));
    assert_eq!(layer.tag(data).unwrap(), "A002");
    assert_eq!(layer.status(data).unwrap(), STATUS_NO);
}

#[test]
fn test_imap_layer_tagged_bad() {
    let data = b"A003 BAD unknown command\r\n";
    let layer = make_layer(data);
    assert!(layer.is_tagged_response(data));
    assert_eq!(layer.status(data).unwrap(), STATUS_BAD);
}

#[test]
fn test_imap_layer_client_login() {
    let data = b"A001 LOGIN alice password123\r\n";
    let layer = make_layer(data);
    assert!(layer.is_client_command(data));
    assert_eq!(layer.tag(data).unwrap(), "A001");
    assert_eq!(layer.command(data).unwrap(), "LOGIN");
    assert_eq!(layer.args(data).unwrap(), "alice password123");
}

#[test]
fn test_imap_layer_client_select() {
    let data = b"A002 SELECT INBOX\r\n";
    let layer = make_layer(data);
    assert!(layer.is_client_command(data));
    assert_eq!(layer.command(data).unwrap(), "SELECT");
    assert_eq!(layer.args(data).unwrap(), "INBOX");
}

#[test]
fn test_imap_layer_client_fetch() {
    let data = b"A003 FETCH 1:* (FLAGS BODY[HEADER])\r\n";
    let layer = make_layer(data);
    assert!(layer.is_client_command(data));
    assert_eq!(layer.command(data).unwrap(), "FETCH");
}

#[test]
fn test_imap_layer_continuation() {
    let data = b"+ dXNlcm5hbWU=\r\n";
    let layer = make_layer(data);
    assert!(layer.is_continuation(data));
    assert!(!layer.is_untagged(data));
    assert!(!layer.is_tagged_response(data));
    assert_eq!(layer.tag(data).unwrap(), "+");
}

#[test]
fn test_imap_layer_bye_untagged() {
    let data = b"* BYE Server is shutting down\r\n";
    let layer = make_layer(data);
    assert!(layer.is_untagged(data));
    assert_eq!(layer.command(data).unwrap(), "BYE");
    assert_eq!(layer.args(data).unwrap(), "Server is shutting down");
}

#[test]
fn test_imap_layer_raw() {
    let data = b"A001 OK LOGIN completed\r\n";
    let layer = make_layer(data);
    assert_eq!(layer.raw(data), "A001 OK LOGIN completed\r\n");
}

// ============================================================================
// Full-stack packet parsing
// ============================================================================

#[test]
fn test_imap_full_stack_server_greeting() {
    let payload = ImapBuilder::new()
        .server_greeting("IMAP4rev1 Service Ready")
        .build();
    let pkt = build_imap_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Ethernet).is_some());
    assert!(pkt.get_layer(LayerKind::Ipv4).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());
    assert!(pkt.get_layer(LayerKind::Imap).is_some());

    let imap = pkt.imap().unwrap();
    let buf = pkt.as_bytes();
    assert!(imap.is_untagged(buf));
    assert_eq!(imap.tag(buf).unwrap(), "*");
    assert_eq!(imap.command(buf).unwrap(), "OK");
}

#[test]
fn test_imap_full_stack_login_command() {
    let payload = ImapBuilder::new().login("A001", "alice", "s3cr3t").build();
    let pkt = build_imap_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Imap).is_some());
    let imap = pkt.imap().unwrap();
    let buf = pkt.as_bytes();
    assert!(imap.is_client_command(buf));
    assert_eq!(imap.tag(buf).unwrap(), "A001");
    assert_eq!(imap.command(buf).unwrap(), "LOGIN");
}

#[test]
fn test_imap_full_stack_tagged_ok() {
    let payload = ImapBuilder::new().ok("A001", "LOGIN completed").build();
    let pkt = build_imap_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Imap).is_some());
    let imap = pkt.imap().unwrap();
    let buf = pkt.as_bytes();
    assert!(imap.is_tagged_response(buf));
    assert_eq!(imap.status(buf).unwrap(), "OK");
}

#[test]
fn test_imap_full_stack_fetch() {
    let payload = ImapBuilder::new()
        .fetch("A003", "1:*", "(FLAGS BODY[HEADER])")
        .build();
    let pkt = build_imap_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Imap).is_some());
    let imap = pkt.imap().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(imap.command(buf).unwrap(), "FETCH");
}

#[test]
fn test_imap_full_stack_select() {
    let payload = ImapBuilder::new().select("A002", "INBOX").build();
    let pkt = build_imap_tcp_packet(payload);

    assert!(pkt.get_layer(LayerKind::Imap).is_some());
    let imap = pkt.imap().unwrap();
    let buf = pkt.as_bytes();
    assert_eq!(imap.command(buf).unwrap(), "SELECT");
    assert_eq!(imap.args(buf).unwrap(), "INBOX");
}

#[test]
fn test_imap_non_imap_port_not_detected() {
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
            b"* OK IMAP4rev1 Service Ready\r\n".to_vec(),
        ))
        .build();

    let mut pkt = Packet::from_bytes(raw);
    pkt.parse().unwrap();
    assert!(pkt.get_layer(LayerKind::Imap).is_none());
}

// ============================================================================
// Constants and field names
// ============================================================================

#[test]
fn test_imap_constants() {
    assert_eq!(IMAP_PORT, 143);
    assert_eq!(IMAP_MIN_HEADER_LEN, 4);
    assert_eq!(STATUS_OK, "OK");
    assert_eq!(STATUS_NO, "NO");
    assert_eq!(STATUS_BAD, "BAD");
    assert_eq!(STATUS_BYE, "BYE");
    assert_eq!(STATUS_PREAUTH, "PREAUTH");
}

#[test]
fn test_imap_field_names() {
    assert!(IMAP_FIELD_NAMES.contains(&"tag"));
    assert!(IMAP_FIELD_NAMES.contains(&"command"));
    assert!(IMAP_FIELD_NAMES.contains(&"args"));
    assert!(IMAP_FIELD_NAMES.contains(&"status"));
    assert!(IMAP_FIELD_NAMES.contains(&"text"));
    assert!(IMAP_FIELD_NAMES.contains(&"is_untagged"));
    assert!(IMAP_FIELD_NAMES.contains(&"is_continuation"));
    assert!(IMAP_FIELD_NAMES.contains(&"is_tagged_response"));
    assert!(IMAP_FIELD_NAMES.contains(&"is_client_command"));
    assert!(IMAP_FIELD_NAMES.contains(&"raw"));
}

#[test]
fn test_imap_command_constants() {
    assert_eq!(CMD_CAPABILITY, "CAPABILITY");
    assert_eq!(CMD_NOOP, "NOOP");
    assert_eq!(CMD_LOGOUT, "LOGOUT");
    assert_eq!(CMD_LOGIN, "LOGIN");
    assert_eq!(CMD_SELECT, "SELECT");
    assert_eq!(CMD_EXAMINE, "EXAMINE");
    assert_eq!(CMD_FETCH, "FETCH");
    assert_eq!(CMD_STORE, "STORE");
    assert_eq!(CMD_SEARCH, "SEARCH");
    assert_eq!(CMD_COPY, "COPY");
    assert_eq!(CMD_EXPUNGE, "EXPUNGE");
    assert_eq!(CMD_CLOSE, "CLOSE");
    assert_eq!(CMD_STARTTLS, "STARTTLS");
}
