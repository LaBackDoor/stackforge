"""UTS-driven SMTP tests.

Translates assertions from tests/uts/smtp.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw SMTP bytes
must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_smtp() constructs a minimal such frame targeting TCP port 25.
"""

import struct

from stackforge import SMTP, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 25) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame carrying the given payload."""
    tcp_header_len = 20
    ip_total = 20 + tcp_header_len + len(payload)

    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst MAC
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,  # src MAC
            0x08,
            0x00,  # EtherType: IPv4
        ]
    )
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
    return eth + ip + tcp + payload


def _parse_smtp(smtp_bytes: bytes, dport: int = 25) -> Packet:
    """Wrap raw SMTP bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(smtp_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: SMTP 220 Service Ready
# ============================================================================


def test_uts_smtp_220_service_ready_build():
    """
    UTS: p = SMTP(reply_code=220, reply_text="mail.example.com ESMTP")
         assert bytes(p) == b"220 mail.example.com ESMTP\\r\\n"
    """
    smtp = SMTP(reply_code=220, reply_text="mail.example.com ESMTP")
    data = smtp.bytes()
    assert data == b"220 mail.example.com ESMTP\r\n"


def test_uts_smtp_220_dissect():
    """
    UTS: s = b"220 mail.example.com ESMTP Postfix\\r\\n"
         p = SMTP(s)
         assert p.reply_code == 220
         assert p.is_response is True
    """
    smtp_payload = b"220 mail.example.com ESMTP Postfix\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp), "SMTP layer not found"
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is True


# ============================================================================
# UTS: SMTP 250 OK
# ============================================================================


def test_uts_smtp_250_ok_build():
    """
    UTS: p = SMTP(reply_code=250, reply_text="OK")
         assert bytes(p) == b"250 OK\\r\\n"
    """
    smtp = SMTP(reply_code=250, reply_text="OK")
    data = smtp.bytes()
    assert data == b"250 OK\r\n"


def test_uts_smtp_250_ok_dissect():
    """
    UTS: s = b"250 OK\\r\\n"
         p = SMTP(s)
         assert p.reply_code == 250
    """
    smtp_payload = b"250 OK\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 250


# ============================================================================
# UTS: SMTP 354 Start Mail Input
# ============================================================================


def test_uts_smtp_354_start_mail_input():
    """
    UTS: p = SMTP(reply_code=354, reply_text="Start mail input; end with <CRLF>.<CRLF>")
         assert bytes(p) == b"354 Start mail input; end with <CRLF>.<CRLF>\\r\\n"
    """
    smtp = SMTP(reply_code=354, reply_text="Start mail input; end with <CRLF>.<CRLF>")
    data = smtp.bytes()
    assert data == b"354 Start mail input; end with <CRLF>.<CRLF>\r\n"


# ============================================================================
# UTS: SMTP EHLO command
# ============================================================================


def test_uts_smtp_ehlo_build():
    """
    UTS: p = SMTP(command="EHLO", args="client.example.com")
         assert bytes(p) == b"EHLO client.example.com\\r\\n"
    """
    smtp = SMTP(command="EHLO", args="client.example.com")
    data = smtp.bytes()
    assert data == b"EHLO client.example.com\r\n"


def test_uts_smtp_ehlo_dissect():
    """
    UTS: s = b"EHLO client.example.com\\r\\n"
         p = SMTP(s)
         assert p.command == "EHLO"
         assert p.args == "client.example.com"
         assert p.is_response is False
    """
    smtp_payload = b"EHLO client.example.com\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "command") == "EHLO"
    assert pkt.getfieldval(LayerKind.Smtp, "args") == "client.example.com"
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is False


# ============================================================================
# UTS: SMTP MAIL FROM command
# ============================================================================


def test_uts_smtp_mail_from_build():
    """
    UTS: p = SMTP(command="MAIL", args="FROM:<user@example.com>")
         assert bytes(p) == b"MAIL FROM:<user@example.com>\\r\\n"
    """
    smtp = SMTP(command="MAIL", args="FROM:<user@example.com>")
    data = smtp.bytes()
    assert data == b"MAIL FROM:<user@example.com>\r\n"


def test_uts_smtp_mail_from_mailfrom_field():
    """
    UTS: s = b"MAIL FROM:<sender@example.com>\\r\\n"
         p = SMTP(s)
         assert p.mailfrom == "sender@example.com"
    """
    smtp_payload = b"MAIL FROM:<sender@example.com>\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "mailfrom") == "sender@example.com"


# ============================================================================
# UTS: SMTP RCPT TO command
# ============================================================================


def test_uts_smtp_rcpt_to_build():
    """
    UTS: p = SMTP(command="RCPT", args="TO:<dest@example.com>")
         assert bytes(p) == b"RCPT TO:<dest@example.com>\\r\\n"
    """
    smtp = SMTP(command="RCPT", args="TO:<dest@example.com>")
    data = smtp.bytes()
    assert data == b"RCPT TO:<dest@example.com>\r\n"


def test_uts_smtp_rcpt_to_rcptto_field():
    """
    UTS: s = b"RCPT TO:<recipient@example.com>\\r\\n"
         p = SMTP(s)
         assert p.rcptto == "recipient@example.com"
    """
    smtp_payload = b"RCPT TO:<recipient@example.com>\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "rcptto") == "recipient@example.com"


# ============================================================================
# UTS: SMTP DATA command
# ============================================================================


def test_uts_smtp_data_command():
    """
    UTS: p = SMTP(command="DATA")
         assert bytes(p) == b"DATA\\r\\n"
    """
    smtp = SMTP(command="DATA")
    data = smtp.bytes()
    assert data == b"DATA\r\n"


# ============================================================================
# UTS: SMTP QUIT command
# ============================================================================


def test_uts_smtp_quit_command():
    """
    UTS: p = SMTP(command="QUIT")
         assert bytes(p) == b"QUIT\\r\\n"
    """
    smtp = SMTP(command="QUIT")
    data = smtp.bytes()
    assert data == b"QUIT\r\n"


# ============================================================================
# UTS: SMTP STARTTLS command
# ============================================================================


def test_uts_smtp_starttls_command():
    """
    UTS: p = SMTP(command="STARTTLS")
         assert bytes(p) == b"STARTTLS\\r\\n"
    """
    smtp = SMTP(command="STARTTLS")
    data = smtp.bytes()
    assert data == b"STARTTLS\r\n"


# ============================================================================
# UTS: SMTP multiline EHLO response
# ============================================================================


def test_uts_smtp_multiline_ehlo_response():
    """
    UTS: s = b"250-mail.example.com\\r\\n250-PIPELINING\\r\\n250 OK\\r\\n"
         p = SMTP(s)
         assert p.reply_code == 250
         assert p.is_multiline is True
    """
    smtp_payload = b"250-mail.example.com\r\n250-PIPELINING\r\n250 OK\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 250
    assert pkt.getfieldval(LayerKind.Smtp, "is_multiline") is True


# ============================================================================
# UTS: SMTP 535 authentication failed
# ============================================================================


def test_uts_smtp_535_auth_failed():
    """
    UTS: s = b"535 Authentication credentials invalid\\r\\n"
         p = SMTP(s)
         assert p.reply_code == 535
    """
    smtp_payload = b"535 Authentication credentials invalid\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 535


# ============================================================================
# UTS: Verify all layers present
# ============================================================================


def test_uts_smtp_has_all_layers():
    """Verify Ethernet/IPv4/TCP/SMTP layers are all present."""
    smtp_payload = b"220 mail.example.com ESMTP\r\n"
    pkt = _parse_smtp(smtp_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Smtp)


# ============================================================================
# UTS: Non-SMTP port detection
# ============================================================================


def test_uts_smtp_non_port_25_not_detected():
    """SMTP traffic on non-SMTP port should not be detected."""
    smtp_payload = b"220 mail.example.com ESMTP\r\n"
    pkt = _parse_smtp(smtp_payload, dport=9999)

    assert not pkt.has_layer(LayerKind.Smtp)


# ============================================================================
# UTS: Builder roundtrip
# ============================================================================


def test_uts_smtp_builder_roundtrip():
    """Build an SMTP reply and verify it can be parsed back."""
    smtp = SMTP(reply_code=220, reply_text="mail.example.com ESMTP")
    data = smtp.bytes()

    pkt = _parse_smtp(data)
    assert pkt.has_layer(LayerKind.Smtp)
    assert pkt.getfieldval(LayerKind.Smtp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Smtp, "is_response") is True
