"""Tests for the SMTP (Simple Mail Transfer Protocol) layer implementation.

These tests validate parsing, field access, building, and stacking of SMTP packets.
SMTP operates over TCP port 25 (relay), 587 (submission), 465 (SMTPS).
"""

import struct

from stackforge import SMTP, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_smtp(smtp_bytes: bytes, sport: int = 54321, dport: int = 25) -> bytes:
    """Wrap raw SMTP bytes inside Ethernet/IPv4/TCP(port 25) frame."""
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x08,
            0x00,
        ]
    )
    tcp_header_len = 20
    ip_total = 20 + tcp_header_len + len(smtp_bytes)
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        6,
        0,
        0x7F000001,
        0x7F000001,
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        1000,
        0,
        (5 << 4),
        0x10,
        65535,
        0,
        0,
    )
    return eth + ip + tcp + smtp_bytes


# ============================================================================
# Tests 1-8: Builder tests (server replies)
# ============================================================================


def test_build_service_ready():
    """Build a 220 service ready (server greeting)."""
    smtp = SMTP(reply_code=220, reply_text="mail.example.com ESMTP")
    data = smtp.bytes()
    assert isinstance(data, bytes)
    assert data == b"220 mail.example.com ESMTP\r\n"


def test_build_closing():
    """Build a 221 closing reply."""
    smtp = SMTP(reply_code=221, reply_text="Bye")
    data = smtp.bytes()
    assert data == b"221 Bye\r\n"


def test_build_auth_success():
    """Build a 235 authentication successful reply."""
    smtp = SMTP(reply_code=235, reply_text="Authentication successful")
    data = smtp.bytes()
    assert data == b"235 Authentication successful\r\n"


def test_build_ok():
    """Build a 250 OK reply."""
    smtp = SMTP(reply_code=250, reply_text="OK")
    data = smtp.bytes()
    assert data == b"250 OK\r\n"


def test_build_start_mail_input():
    """Build a 354 start mail input reply."""
    smtp = SMTP(reply_code=354, reply_text="Start mail input; end with <CRLF>.<CRLF>")
    data = smtp.bytes()
    assert data == b"354 Start mail input; end with <CRLF>.<CRLF>\r\n"


def test_build_service_unavailable():
    """Build a 421 service unavailable reply."""
    smtp = SMTP(reply_code=421, reply_text="Service not available")
    data = smtp.bytes()
    assert data == b"421 Service not available\r\n"


def test_build_auth_failed():
    """Build a 535 authentication failed reply."""
    smtp = SMTP(reply_code=535, reply_text="Authentication credentials invalid")
    data = smtp.bytes()
    assert data == b"535 Authentication credentials invalid\r\n"


def test_build_mailbox_not_found():
    """Build a 550 mailbox not found reply."""
    smtp = SMTP(reply_code=550, reply_text="User not found")
    data = smtp.bytes()
    assert data == b"550 User not found\r\n"


# ============================================================================
# Tests 9-16: Builder tests (client commands)
# ============================================================================


def test_build_ehlo():
    """Build an EHLO command."""
    smtp = SMTP(command="EHLO", args="client.example.com")
    data = smtp.bytes()
    assert data == b"EHLO client.example.com\r\n"


def test_build_helo():
    """Build a HELO command."""
    smtp = SMTP(command="HELO", args="client.example.com")
    data = smtp.bytes()
    assert data == b"HELO client.example.com\r\n"


def test_build_mail_from():
    """Build a MAIL FROM command."""
    smtp = SMTP(command="MAIL", args="FROM:<user@example.com>")
    data = smtp.bytes()
    assert data == b"MAIL FROM:<user@example.com>\r\n"


def test_build_rcpt_to():
    """Build a RCPT TO command."""
    smtp = SMTP(command="RCPT", args="TO:<dest@example.com>")
    data = smtp.bytes()
    assert data == b"RCPT TO:<dest@example.com>\r\n"


def test_build_data_command():
    """Build a DATA command."""
    smtp = SMTP(command="DATA")
    data = smtp.bytes()
    assert data == b"DATA\r\n"


def test_build_quit():
    """Build a QUIT command."""
    smtp = SMTP(command="QUIT")
    data = smtp.bytes()
    assert data == b"QUIT\r\n"


def test_build_starttls():
    """Build a STARTTLS command."""
    smtp = SMTP(command="STARTTLS")
    data = smtp.bytes()
    assert data == b"STARTTLS\r\n"


def test_build_auth():
    """Build an AUTH command."""
    smtp = SMTP(command="AUTH", args="LOGIN")
    data = smtp.bytes()
    assert data == b"AUTH LOGIN\r\n"


# ============================================================================
# Tests 17-22: Parsing tests
# ============================================================================


def test_parse_service_ready():
    """Parse a 220 service ready reply on port 25."""
    smtp_bytes = b"220 mail.example.com ESMTP Postfix\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


def test_parse_ehlo_command():
    """Parse an EHLO command on port 25."""
    smtp_bytes = b"EHLO client.example.com\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


def test_parse_mail_from():
    """Parse a MAIL FROM command."""
    smtp_bytes = b"MAIL FROM:<user@example.com>\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


def test_parse_250_ok():
    """Parse a 250 OK response."""
    smtp_bytes = b"250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


def test_parse_multiline_ehlo_response():
    """Parse a multi-line EHLO response."""
    smtp_bytes = b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


def test_parse_starttls():
    """Parse a STARTTLS command."""
    smtp_bytes = b"STARTTLS\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)


# ============================================================================
# Tests 23-32: Field access tests
# ============================================================================


def test_field_reply_code_220():
    """Verify reply_code is 220 for service ready."""
    smtp_bytes = b"220 mail.example.com ESMTP Postfix\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 220


def test_field_reply_code_250():
    """Verify reply_code is 250 for OK."""
    smtp_bytes = b"250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 250


def test_field_reply_code_354():
    """Verify reply_code is 354 for start mail input."""
    smtp_bytes = b"354 Start mail input; end with <CRLF>.<CRLF>\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 354


def test_field_reply_code_535():
    """Verify reply_code is 535 for auth failed."""
    smtp_bytes = b"535 Authentication credentials invalid\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 535


def test_field_is_response_true():
    """Verify is_response is True for server replies."""
    smtp_bytes = b"250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is True


def test_field_is_response_false():
    """Verify is_response is False for client commands."""
    smtp_bytes = b"EHLO client.example.com\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is False


def test_field_command_ehlo():
    """Verify command field for EHLO."""
    smtp_bytes = b"EHLO client.example.com\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "command") == "EHLO"


def test_field_args_ehlo():
    """Verify args field for EHLO."""
    smtp_bytes = b"EHLO client.example.com\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "args") == "client.example.com"


def test_field_mailfrom():
    """Verify mailfrom field for MAIL FROM command."""
    smtp_bytes = b"MAIL FROM:<sender@example.com>\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "mailfrom") == "sender@example.com"


def test_field_rcptto():
    """Verify rcptto field for RCPT TO command."""
    smtp_bytes = b"RCPT TO:<recipient@example.com>\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "rcptto") == "recipient@example.com"


# ============================================================================
# Tests 33-37: Layer detection and edge cases
# ============================================================================


def test_has_layer_smtp():
    """Verify has_layer returns True for SMTP and related layers."""
    smtp_bytes = b"220 mail.example.com ESMTP\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Udp)


def test_layer_order_smtp():
    """Verify the expected layer order: Ethernet / IPv4 / TCP / SMTP."""
    smtp_bytes = b"220 mail.example.com ESMTP\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Smtp in kinds
    tcp_pos = kinds.index(LayerKind.Tcp)
    smtp_pos = kinds.index(LayerKind.Smtp)
    assert smtp_pos > tcp_pos, "SMTP should come after TCP"


def test_non_smtp_port_not_detected():
    """TCP traffic not on port 25 should NOT be detected as SMTP."""
    smtp_bytes = b"220 mail.example.com ESMTP\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Smtp)


def test_get_layer_bytes_smtp():
    """Verify get_layer_bytes returns the correct SMTP bytes."""
    smtp_bytes = b"220 mail.example.com ESMTP\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Smtp)
    assert layer_bytes == smtp_bytes


def test_show_includes_smtp():
    """Verify show() includes SMTP information."""
    smtp_bytes = b"220 mail.example.com ESMTP\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "SMTP" in show


# ============================================================================
# Tests 38-42: Build and parse roundtrip
# ============================================================================


def test_build_and_parse_roundtrip_reply():
    """Build a 220 reply, wrap in Eth/IP/TCP, parse back, verify fields."""
    smtp = SMTP(reply_code=220, reply_text="mail.example.com ESMTP")
    built = smtp.bytes()
    raw = make_eth_ip_tcp_smtp(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is True


def test_build_and_parse_roundtrip_command():
    """Build an EHLO command, wrap in Eth/IP/TCP, parse back."""
    smtp = SMTP(command="EHLO", args="client.example.com")
    built = smtp.bytes()
    raw = make_eth_ip_tcp_smtp(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "command") == "EHLO"


def test_field_is_multiline_false():
    """Verify is_multiline is False for single-line replies."""
    smtp_bytes = b"250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "is_multiline") is False


def test_field_is_multiline_true():
    """Verify is_multiline is True for multi-line EHLO responses."""
    smtp_bytes = b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n"
    raw = make_eth_ip_tcp_smtp(smtp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Smtp, "is_multiline") is True


def test_layer_kind_smtp_identity():
    """Verify LayerKind.Smtp can be imported and used."""
    assert LayerKind.Smtp is not None
