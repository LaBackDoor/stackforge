"""UTS-driven POP3 tests.

Translates assertions from tests/uts/pop3.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw POP3 bytes
must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_pop3() constructs a minimal such frame targeting TCP port 110.
"""

import struct

from stackforge import POP3, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 110) -> bytes:
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


def _parse_pop3(pop3_bytes: bytes, dport: int = 110) -> Packet:
    """Wrap raw POP3 bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(pop3_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: POP3 +OK server ready
# ============================================================================


def test_uts_pop3_ok_server_ready_build():
    """
    UTS: p = POP3(ok=True, text="POP3 server ready")
         assert bytes(p) == b"+OK POP3 server ready\\r\\n"
    """
    pop3 = POP3(ok=True, text="POP3 server ready")
    data = pop3.bytes()
    assert data == b"+OK POP3 server ready\r\n"


def test_uts_pop3_ok_server_ready_dissect():
    """
    UTS: s = b"+OK POP3 server ready\\r\\n"
         p = POP3(s)
         assert p.is_ok is True
         assert p.is_response is True
         assert p.response_text == "POP3 server ready"
    """
    pop3_payload = b"+OK POP3 server ready\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3), "POP3 layer not found"
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True
    assert pkt.getfieldval(LayerKind.Pop3, "is_response") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "POP3 server ready"


# ============================================================================
# UTS: POP3 +OK empty
# ============================================================================


def test_uts_pop3_ok_empty_build():
    """
    UTS: p = POP3(ok=True, text="")
         assert bytes(p) == b"+OK\\r\\n"
    """
    pop3 = POP3(ok=True, text="")
    data = pop3.bytes()
    assert data == b"+OK\r\n"


# ============================================================================
# UTS: POP3 -ERR permission denied
# ============================================================================


def test_uts_pop3_err_permission_denied_build():
    """
    UTS: p = POP3(ok=False, text="Permission denied")
         assert bytes(p) == b"-ERR Permission denied\\r\\n"
    """
    pop3 = POP3(ok=False, text="Permission denied")
    data = pop3.bytes()
    assert data == b"-ERR Permission denied\r\n"


def test_uts_pop3_err_permission_denied_dissect():
    """
    UTS: s = b"-ERR Permission denied\\r\\n"
         p = POP3(s)
         assert p.is_ok is False
         assert p.is_err is True
         assert p.response_text == "Permission denied"
    """
    pop3_payload = b"-ERR Permission denied\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is False
    assert pkt.getfieldval(LayerKind.Pop3, "is_err") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "Permission denied"


# ============================================================================
# UTS: POP3 -ERR empty
# ============================================================================


def test_uts_pop3_err_empty_build():
    """
    UTS: p = POP3(ok=False, text="")
         assert bytes(p) == b"-ERR\\r\\n"
    """
    pop3 = POP3(ok=False, text="")
    data = pop3.bytes()
    assert data == b"-ERR\r\n"


# ============================================================================
# UTS: POP3 USER command
# ============================================================================


def test_uts_pop3_user_command_dissect():
    """
    UTS: s = b"USER alice\\r\\n"
         p = POP3(s)
         assert p.is_response is False
         assert p.command == "USER"
         assert p.args == "alice"
    """
    pop3_payload = b"USER alice\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_response") is False
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "USER"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "alice"


# ============================================================================
# UTS: POP3 PASS command
# ============================================================================


def test_uts_pop3_pass_command_dissect():
    """
    UTS: s = b"PASS secret\\r\\n"
         p = POP3(s)
         assert p.command == "PASS"
         assert p.args == "secret"
    """
    pop3_payload = b"PASS secret\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "PASS"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "secret"


# ============================================================================
# UTS: POP3 STAT command (no args)
# ============================================================================


def test_uts_pop3_stat_command_dissect():
    """
    UTS: s = b"STAT\\r\\n"
         p = POP3(s)
         assert p.command == "STAT"
         assert p.args == ""
    """
    pop3_payload = b"STAT\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "STAT"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == ""


# ============================================================================
# UTS: POP3 RETR command
# ============================================================================


def test_uts_pop3_retr_command_dissect():
    """
    UTS: s = b"RETR 1\\r\\n"
         p = POP3(s)
         assert p.command == "RETR"
         assert p.args == "1"
    """
    pop3_payload = b"RETR 1\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "RETR"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "1"


# ============================================================================
# UTS: POP3 DELE command
# ============================================================================


def test_uts_pop3_dele_command_dissect():
    """
    UTS: s = b"DELE 2\\r\\n"
         p = POP3(s)
         assert p.command == "DELE"
         assert p.args == "2"
    """
    pop3_payload = b"DELE 2\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "DELE"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "2"


# ============================================================================
# UTS: POP3 QUIT command
# ============================================================================


def test_uts_pop3_quit_command_dissect():
    """
    UTS: s = b"QUIT\\r\\n"
         p = POP3(s)
         assert p.command == "QUIT"
    """
    pop3_payload = b"QUIT\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "QUIT"


# ============================================================================
# UTS: POP3 STAT response
# ============================================================================


def test_uts_pop3_stat_response():
    """
    UTS: s = b"+OK 3 1024\\r\\n"
         p = POP3(s)
         assert p.is_ok is True
         assert p.response_text == "3 1024"
    """
    pop3_payload = b"+OK 3 1024\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "3 1024"


# ============================================================================
# UTS: POP3 TOP command
# ============================================================================


def test_uts_pop3_top_command():
    """
    UTS: s = b"TOP 1 5\\r\\n"
         p = POP3(s)
         assert p.command == "TOP"
         assert p.args == "1 5"
    """
    pop3_payload = b"TOP 1 5\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "command") == "TOP"
    assert pkt.getfieldval(LayerKind.Pop3, "args") == "1 5"


# ============================================================================
# UTS: Verify all layers present
# ============================================================================


def test_uts_pop3_has_all_layers():
    """Verify Ethernet/IPv4/TCP/POP3 layers are all present."""
    pop3_payload = b"+OK POP3 server ready\r\n"
    pkt = _parse_pop3(pop3_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Pop3)
    assert not pkt.has_layer(LayerKind.Udp)


# ============================================================================
# UTS: Non-POP3 port detection
# ============================================================================


def test_uts_pop3_non_port_110_not_detected():
    """POP3 traffic on non-port-110 should not be detected."""
    pop3_payload = b"+OK POP3 server ready\r\n"
    pkt = _parse_pop3(pop3_payload, dport=9999)

    assert not pkt.has_layer(LayerKind.Pop3)


# ============================================================================
# UTS: Builder roundtrip
# ============================================================================


def test_uts_pop3_builder_roundtrip_ok():
    """Build a +OK reply and verify it can be parsed back."""
    pop3 = POP3(ok=True, text="POP3 server ready")
    data = pop3.bytes()

    pkt = _parse_pop3(data)
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_ok") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "POP3 server ready"


def test_uts_pop3_builder_roundtrip_err():
    """Build a -ERR reply and verify it can be parsed back."""
    pop3 = POP3(ok=False, text="Unknown command")
    data = pop3.bytes()

    pkt = _parse_pop3(data)
    assert pkt.has_layer(LayerKind.Pop3)
    assert pkt.getfieldval(LayerKind.Pop3, "is_err") is True
    assert pkt.getfieldval(LayerKind.Pop3, "response_text") == "Unknown command"
