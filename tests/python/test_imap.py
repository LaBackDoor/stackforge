"""Tests for the IMAP (Internet Message Access Protocol) layer implementation.

These tests validate parsing, field access, building, and stacking of IMAP packets.
IMAP operates over TCP port 143. Messages are tagged/untagged/continuation-style.
"""

import struct

from stackforge import IMAP, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_imap(imap_bytes: bytes, sport: int = 54321, dport: int = 143) -> bytes:
    """Wrap raw IMAP bytes inside Ethernet/IPv4/TCP(port 143) frame."""
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
    ip_total = 20 + tcp_header_len + len(imap_bytes)
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
    return eth + ip + tcp + imap_bytes


# ============================================================================
# Tests 1-7: Builder tests (server responses)
# ============================================================================


def test_build_server_greeting():
    """Build a server greeting untagged OK response."""
    imap = IMAP(status="OK", tag="*", text="IMAP4rev1 Service Ready")
    data = imap.bytes()
    assert isinstance(data, bytes)
    assert data == b"* OK IMAP4rev1 Service Ready\r\n"


def test_build_tagged_ok():
    """Build a tagged OK response."""
    imap = IMAP(status="OK", tag="A001", text="LOGIN completed")
    data = imap.bytes()
    assert data == b"A001 OK LOGIN completed\r\n"


def test_build_tagged_no():
    """Build a tagged NO response."""
    imap = IMAP(status="NO", tag="A002", text="login failed")
    data = imap.bytes()
    assert data == b"A002 NO login failed\r\n"


def test_build_tagged_bad():
    """Build a tagged BAD response."""
    imap = IMAP(status="BAD", tag="A003", text="unknown command")
    data = imap.bytes()
    assert data == b"A003 BAD unknown command\r\n"


def test_build_bye():
    """Build a BYE untagged response."""
    imap = IMAP(status="BYE", tag="*", text="Server logging out")
    data = imap.bytes()
    assert data == b"* BYE Server logging out\r\n"


def test_build_capability_response():
    """Build a CAPABILITY untagged response."""
    imap = IMAP(command="CAPABILITY", tag="*", args="IMAP4rev1 AUTH=PLAIN STARTTLS")
    data = imap.bytes()
    assert data == b"* CAPABILITY IMAP4rev1 AUTH=PLAIN STARTTLS\r\n"


def test_build_exists_untagged():
    """Build a numeric untagged EXISTS response."""
    imap = IMAP(command="3", tag="*", args="EXISTS")
    data = imap.bytes()
    assert data == b"* 3 EXISTS\r\n"


# ============================================================================
# Tests 8-13: Builder tests (client commands)
# ============================================================================


def test_build_login_command():
    """Build a LOGIN client command."""
    imap = IMAP(command="LOGIN", tag="A001", args="alice password123")
    data = imap.bytes()
    assert data == b"A001 LOGIN alice password123\r\n"


def test_build_select_command():
    """Build a SELECT client command."""
    imap = IMAP(command="SELECT", tag="A002", args="INBOX")
    data = imap.bytes()
    assert data == b"A002 SELECT INBOX\r\n"


def test_build_fetch_command():
    """Build a FETCH client command."""
    imap = IMAP(command="FETCH", tag="A003", args="1:* FLAGS")
    data = imap.bytes()
    assert data == b"A003 FETCH 1:* FLAGS\r\n"


def test_build_logout_command():
    """Build a LOGOUT client command."""
    imap = IMAP(command="LOGOUT", tag="A004")
    data = imap.bytes()
    assert data == b"A004 LOGOUT\r\n"


def test_build_noop_command():
    """Build a NOOP client command."""
    imap = IMAP(command="NOOP", tag="A005")
    data = imap.bytes()
    assert data == b"A005 NOOP\r\n"


def test_build_search_command():
    """Build a SEARCH client command."""
    imap = IMAP(command="SEARCH", tag="A006", args="UNSEEN")
    data = imap.bytes()
    assert data == b"A006 SEARCH UNSEEN\r\n"


# ============================================================================
# Tests 14-19: Parsing tests
# ============================================================================


def test_parse_server_greeting():
    """Parse an untagged OK server greeting on port 143."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


def test_parse_tagged_ok_response():
    """Parse a tagged OK response."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


def test_parse_client_login_command():
    """Parse a client LOGIN command."""
    imap_bytes = b"A001 LOGIN alice password123\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


def test_parse_client_select_command():
    """Parse a client SELECT command."""
    imap_bytes = b"A002 SELECT INBOX\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


def test_parse_untagged_exists():
    """Parse an untagged EXISTS notification."""
    imap_bytes = b"* 3 EXISTS\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


def test_parse_continuation():
    """Parse a continuation request."""
    imap_bytes = b"+ go ahead\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)


# ============================================================================
# Tests 20-29: Field access tests
# ============================================================================


def test_field_is_untagged_true():
    """Verify is_untagged is True for untagged responses."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True


def test_field_is_untagged_false():
    """Verify is_untagged is False for tagged responses."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is False


def test_field_is_tagged_response_true():
    """Verify is_tagged_response is True for tagged OK/NO/BAD."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "is_tagged_response") is True


def test_field_is_client_command_true():
    """Verify is_client_command is True for client commands."""
    imap_bytes = b"A001 LOGIN alice password123\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True


def test_field_is_client_command_false():
    """Verify is_client_command is False for server responses."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is False


def test_field_tag_for_tagged_response():
    """Verify tag field for tagged responses."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "A001"


def test_field_tag_for_untagged():
    """Verify tag is * for untagged responses."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "*"


def test_field_command_ok():
    """Verify command field is OK for tagged OK response."""
    imap_bytes = b"A001 OK LOGIN completed\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "command") == "OK"


def test_field_command_login():
    """Verify command field for LOGIN client command."""
    imap_bytes = b"A001 LOGIN alice password123\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "command") == "LOGIN"


def test_field_args_login():
    """Verify args field for LOGIN client command."""
    imap_bytes = b"A001 LOGIN alice password123\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Imap, "args") == "alice password123"


# ============================================================================
# Tests 30-34: Layer detection and edge cases
# ============================================================================


def test_has_layer_imap():
    """Verify has_layer returns True for IMAP and related layers."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Udp)


def test_layer_order_imap():
    """Verify the expected layer order: Ethernet / IPv4 / TCP / IMAP."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Imap in kinds
    tcp_pos = kinds.index(LayerKind.Tcp)
    imap_pos = kinds.index(LayerKind.Imap)
    assert imap_pos > tcp_pos, "IMAP should come after TCP"


def test_non_imap_port_not_detected():
    """TCP traffic not on port 143 should NOT be detected as IMAP."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Imap)


def test_get_layer_bytes_imap():
    """Verify get_layer_bytes returns the correct IMAP bytes."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Imap)
    assert layer_bytes == imap_bytes


def test_show_includes_imap():
    """Verify show() includes IMAP information."""
    imap_bytes = b"* OK IMAP4rev1 Service Ready\r\n"
    raw = make_eth_ip_tcp_imap(imap_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "IMAP" in show


# ============================================================================
# Tests 35-38: Build and parse roundtrip
# ============================================================================


def test_build_and_parse_roundtrip_greeting():
    """Build a server greeting, wrap in Eth/IP/TCP, parse back, verify fields."""
    imap = IMAP(status="OK", tag="*", text="IMAP4rev1 Service Ready")
    built = imap.bytes()
    raw = make_eth_ip_tcp_imap(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "*"


def test_build_and_parse_roundtrip_tagged_ok():
    """Build a tagged OK, wrap in Eth/IP/TCP, parse back."""
    imap = IMAP(status="OK", tag="A001", text="LOGIN completed")
    built = imap.bytes()
    raw = make_eth_ip_tcp_imap(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_tagged_response") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "A001"
    assert pkt.getfieldval(LayerKind.Imap, "command") == "OK"


def test_build_and_parse_roundtrip_login_command():
    """Build a LOGIN command, wrap in Eth/IP/TCP, parse back."""
    imap = IMAP(command="LOGIN", tag="A001", args="alice password123")
    built = imap.bytes()
    raw = make_eth_ip_tcp_imap(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "LOGIN"


def test_layer_kind_imap_identity():
    """Verify LayerKind.Imap can be imported and used."""
    assert LayerKind.Imap is not None
