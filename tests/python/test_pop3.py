"""Tests for the POP3 (Post Office Protocol v3) layer implementation.

These tests validate parsing, field access, building, and stacking of POP3 packets.
POP3 operates over TCP port 110. Server replies start with +OK or -ERR.
Client commands include USER, PASS, STAT, LIST, RETR, DELE, QUIT, etc.
"""

import struct

from stackforge import POP3, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_pop3(pop3_bytes: bytes, sport: int = 54321, dport: int = 110) -> bytes:
    """Wrap raw POP3 bytes inside Ethernet/IPv4/TCP(port 110) frame."""
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
    ip_total = 20 + tcp_header_len + len(pop3_bytes)
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
    return eth + ip + tcp + pop3_bytes


# ============================================================================
# Tests 1-5: Builder tests (server replies)
# ============================================================================


def test_build_ok_server_ready():
    """Build a +OK POP3 server ready reply."""
    pop3 = POP3(ok=True, text="POP3 server ready")
    data = pop3.bytes()
    assert isinstance(data, bytes)
    assert data == b"+OK POP3 server ready\r\n"


def test_build_ok_empty():
    """Build a +OK reply with no text."""
    pop3 = POP3(ok=True, text="")
    data = pop3.bytes()
    assert data == b"+OK\r\n"


def test_build_err_permission_denied():
    """Build a -ERR Permission denied reply."""
    pop3 = POP3(ok=False, text="Permission denied")
    data = pop3.bytes()
    assert data == b"-ERR Permission denied\r\n"


def test_build_err_empty():
    """Build a -ERR reply with no text."""
    pop3 = POP3(ok=False, text="")
    data = pop3.bytes()
    assert data == b"-ERR\r\n"


def test_build_ok_logged_in():
    """Build a +OK logged in reply."""
    pop3 = POP3(ok=True, text="logged in")
    data = pop3.bytes()
    assert data == b"+OK logged in\r\n"


# ============================================================================
# Tests 6-10: Parsing tests
# ============================================================================


def test_parse_ok_server_ready():
    """Parse a +OK POP3 server ready reply on port 110."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)


def test_parse_err_response():
    """Parse a -ERR response on port 110."""
    pop3_bytes = b"-ERR Permission denied\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)


def test_parse_user_command():
    """Parse a USER command on port 110."""
    pop3_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)


def test_parse_pass_command():
    """Parse a PASS command."""
    pop3_bytes = b"PASS secret\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)


def test_parse_stat_command():
    """Parse a STAT command."""
    pop3_bytes = b"STAT\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)


# ============================================================================
# Tests 11-20: Field access tests
# ============================================================================


def test_field_is_ok_true():
    """Verify is_ok is True for +OK replies."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True


def test_field_is_ok_false():
    """Verify is_ok is False for -ERR replies."""
    pop3_bytes = b"-ERR Permission denied\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is False


def test_field_is_err_true():
    """Verify is_err is True for -ERR replies."""
    pop3_bytes = b"-ERR Unknown command\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_err") is True


def test_field_is_err_false():
    """Verify is_err is False for +OK replies."""
    pop3_bytes = b"+OK logged in\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_err") is False


def test_field_is_response_true():
    """Verify is_response is True for +OK and -ERR."""
    pop3_bytes = b"+OK 3 1024\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_response") is True


def test_field_is_response_false():
    """Verify is_response is False for client commands."""
    pop3_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "is_response") is False


def test_field_response_text():
    """Verify response_text for +OK reply."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "POP3 server ready"


def test_field_response_text_err():
    """Verify response_text for -ERR reply."""
    pop3_bytes = b"-ERR Permission denied\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "Permission denied"


def test_field_command_user():
    """Verify command field for USER command."""
    pop3_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "USER"


def test_field_args_user():
    """Verify args field for USER command."""
    pop3_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "alice"


# ============================================================================
# Tests 21-24: Layer detection and edge cases
# ============================================================================


def test_has_layer_pop3():
    """Verify has_layer returns True for POP3 and related layers."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Udp)


def test_layer_order_pop3():
    """Verify the expected layer order: Ethernet / IPv4 / TCP / POP3."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Pop3 in kinds
    tcp_pos = kinds.index(LayerKind.Tcp)
    pop3_pos = kinds.index(LayerKind.Pop3)
    assert pop3_pos > tcp_pos, "POP3 should come after TCP"


def test_non_pop3_port_not_detected():
    """TCP traffic not on port 110 should NOT be detected as POP3."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Pop3)


def test_get_layer_bytes_pop3():
    """Verify get_layer_bytes returns the correct POP3 bytes."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Pop3)
    assert layer_bytes == pop3_bytes


# ============================================================================
# Tests 25-29: Additional parsing tests for various commands
# ============================================================================


def test_parse_retr_command():
    """Parse a RETR command."""
    pop3_bytes = b"RETR 1\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "RETR"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "1"


def test_parse_dele_command():
    """Parse a DELE command."""
    pop3_bytes = b"DELE 2\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "DELE"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "2"


def test_parse_quit_command():
    """Parse a QUIT command."""
    pop3_bytes = b"QUIT\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "QUIT"


def test_parse_list_command():
    """Parse a LIST command."""
    pop3_bytes = b"LIST\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "LIST"


def test_parse_top_command():
    """Parse a TOP command."""
    pop3_bytes = b"TOP 1 5\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "TOP"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "1 5"


# ============================================================================
# Tests 30-34: Build and parse roundtrip
# ============================================================================


def test_build_and_parse_roundtrip_ok():
    """Build a +OK reply, wrap in Eth/IP/TCP, parse back, verify fields."""
    pop3 = POP3(ok=True, text="POP3 server ready")
    built = pop3.bytes()
    raw = make_eth_ip_tcp_pop3(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True
    assert pkt.getfieldval(LayerKind.Pop3, "is_response") is True


def test_build_and_parse_roundtrip_err():
    """Build a -ERR reply, wrap in Eth/IP/TCP, parse back."""
    pop3 = POP3(ok=False, text="Permission denied")
    built = pop3.bytes()
    raw = make_eth_ip_tcp_pop3(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_err") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "Permission denied"


def test_show_includes_pop3():
    """Verify show() includes POP3 information."""
    pop3_bytes = b"+OK POP3 server ready\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "POP3" in show


def test_stat_response_fields():
    """Verify response_text for a STAT response."""
    pop3_bytes = b"+OK 3 1024\r\n"
    raw = make_eth_ip_tcp_pop3(pop3_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "3 1024"


def test_layer_kind_pop3_identity():
    """Verify LayerKind.Pop3 can be imported and used."""
    assert LayerKind.Pop3 is not None
