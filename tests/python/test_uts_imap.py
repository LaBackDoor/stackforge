"""UTS-driven IMAP tests.

Translates assertions from tests/uts/imap.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw IMAP bytes
must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_imap() constructs a minimal such frame targeting TCP port 143.
"""

import struct

from stackforge import IMAP, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 143) -> bytes:
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


def _parse_imap(imap_bytes: bytes, dport: int = 143) -> Packet:
    """Wrap raw IMAP bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(imap_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: IMAP server greeting (untagged OK)
# ============================================================================


def test_uts_imap_server_greeting_build():
    """
    UTS: p = IMAP(status="OK", tag="*", text="IMAP4rev1 Service Ready")
         assert bytes(p) == b"* OK IMAP4rev1 Service Ready\\r\\n"
    """
    imap = IMAP(status="OK", tag="*", text="IMAP4rev1 Service Ready")
    data = imap.bytes()
    assert data == b"* OK IMAP4rev1 Service Ready\r\n"


def test_uts_imap_server_greeting_dissect():
    """
    UTS: s = b"* OK IMAP4rev1 Service Ready\\r\\n"
         p = IMAP(s)
         assert p.is_untagged is True
         assert p.tag == "*"
         assert p.command == "OK"
    """
    imap_payload = b"* OK IMAP4rev1 Service Ready\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap), "IMAP layer not found"
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "*"
    assert pkt.getfieldval(LayerKind.Imap, "command") == "OK"


# ============================================================================
# UTS: IMAP tagged OK response
# ============================================================================


def test_uts_imap_tagged_ok_build():
    """
    UTS: p = IMAP(status="OK", tag="A001", text="LOGIN completed")
         assert bytes(p) == b"A001 OK LOGIN completed\\r\\n"
    """
    imap = IMAP(status="OK", tag="A001", text="LOGIN completed")
    data = imap.bytes()
    assert data == b"A001 OK LOGIN completed\r\n"


def test_uts_imap_tagged_ok_dissect():
    """
    UTS: s = b"A001 OK LOGIN completed\\r\\n"
         p = IMAP(s)
         assert p.is_tagged_response is True
         assert p.tag == "A001"
         assert p.command == "OK"
         assert p.status == "OK"
         assert p.args == "LOGIN completed"
    """
    imap_payload = b"A001 OK LOGIN completed\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_tagged_response") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "A001"
    assert pkt.getfieldval(LayerKind.Imap, "command") == "OK"
    assert pkt.getfieldval(LayerKind.Imap, "status") == "OK"
    assert pkt.getfieldval(LayerKind.Imap, "args") == "LOGIN completed"


# ============================================================================
# UTS: IMAP tagged NO response
# ============================================================================


def test_uts_imap_tagged_no_build():
    """
    UTS: p = IMAP(status="NO", tag="A002", text="login failed")
         assert bytes(p) == b"A002 NO login failed\\r\\n"
    """
    imap = IMAP(status="NO", tag="A002", text="login failed")
    data = imap.bytes()
    assert data == b"A002 NO login failed\r\n"


def test_uts_imap_tagged_no_dissect():
    """
    UTS: s = b"A002 NO login failed\\r\\n"
         p = IMAP(s)
         assert p.is_tagged_response is True
         assert p.tag == "A002"
         assert p.status == "NO"
    """
    imap_payload = b"A002 NO login failed\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_tagged_response") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "A002"
    assert pkt.getfieldval(LayerKind.Imap, "status") == "NO"


# ============================================================================
# UTS: IMAP tagged BAD response
# ============================================================================


def test_uts_imap_tagged_bad_dissect():
    """
    UTS: s = b"A003 BAD unknown command\\r\\n"
         p = IMAP(s)
         assert p.status == "BAD"
    """
    imap_payload = b"A003 BAD unknown command\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "status") == "BAD"


# ============================================================================
# UTS: IMAP untagged BYE
# ============================================================================


def test_uts_imap_bye_dissect():
    """
    UTS: s = b"* BYE Server logging out\\r\\n"
         p = IMAP(s)
         assert p.is_untagged is True
         assert p.command == "BYE"
         assert p.status == "BYE"
    """
    imap_payload = b"* BYE Server logging out\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "BYE"
    assert pkt.getfieldval(LayerKind.Imap, "status") == "BYE"


# ============================================================================
# UTS: IMAP client LOGIN command
# ============================================================================


def test_uts_imap_client_login_build():
    """
    UTS: p = IMAP(command="LOGIN", tag="A001", args="alice password123")
         assert bytes(p) == b"A001 LOGIN alice password123\\r\\n"
    """
    imap = IMAP(command="LOGIN", tag="A001", args="alice password123")
    data = imap.bytes()
    assert data == b"A001 LOGIN alice password123\r\n"


def test_uts_imap_client_login_dissect():
    """
    UTS: s = b"A001 LOGIN alice password123\\r\\n"
         p = IMAP(s)
         assert p.is_client_command is True
         assert p.tag == "A001"
         assert p.command == "LOGIN"
         assert p.args == "alice password123"
    """
    imap_payload = b"A001 LOGIN alice password123\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "A001"
    assert pkt.getfieldval(LayerKind.Imap, "command") == "LOGIN"
    assert pkt.getfieldval(LayerKind.Imap, "args") == "alice password123"


# ============================================================================
# UTS: IMAP client SELECT command
# ============================================================================


def test_uts_imap_client_select_dissect():
    """
    UTS: s = b"A002 SELECT INBOX\\r\\n"
         p = IMAP(s)
         assert p.is_client_command is True
         assert p.command == "SELECT"
         assert p.args == "INBOX"
    """
    imap_payload = b"A002 SELECT INBOX\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "SELECT"
    assert pkt.getfieldval(LayerKind.Imap, "args") == "INBOX"


# ============================================================================
# UTS: IMAP client FETCH command
# ============================================================================


def test_uts_imap_client_fetch_dissect():
    """
    UTS: s = b"A003 FETCH 1:* (FLAGS BODY[HEADER])\\r\\n"
         p = IMAP(s)
         assert p.is_client_command is True
         assert p.command == "FETCH"
    """
    imap_payload = b"A003 FETCH 1:* (FLAGS BODY[HEADER])\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "FETCH"


# ============================================================================
# UTS: IMAP continuation request
# ============================================================================


def test_uts_imap_continuation_dissect():
    """
    UTS: s = b"+ go ahead\\r\\n"
         p = IMAP(s)
         assert p.is_continuation is True
         assert p.tag == "+"
    """
    imap_payload = b"+ go ahead\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_continuation") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "+"


# ============================================================================
# UTS: IMAP untagged EXISTS
# ============================================================================


def test_uts_imap_untagged_exists_dissect():
    """
    UTS: s = b"* 3 EXISTS\\r\\n"
         p = IMAP(s)
         assert p.is_untagged is True
         assert p.tag == "*"
    """
    imap_payload = b"* 3 EXISTS\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True
    assert pkt.getfieldval(LayerKind.Imap, "tag") == "*"


# ============================================================================
# UTS: Verify all layers present
# ============================================================================


def test_uts_imap_has_all_layers():
    """Verify Ethernet/IPv4/TCP/IMAP layers are all present."""
    imap_payload = b"* OK IMAP4rev1 Service Ready\r\n"
    pkt = _parse_imap(imap_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Imap)
    assert not pkt.has_layer(LayerKind.Udp)


# ============================================================================
# UTS: Non-IMAP port detection
# ============================================================================


def test_uts_imap_non_port_143_not_detected():
    """IMAP traffic on non-port-143 should not be detected."""
    imap_payload = b"* OK IMAP4rev1 Service Ready\r\n"
    pkt = _parse_imap(imap_payload, dport=9999)

    assert not pkt.has_layer(LayerKind.Imap)


# ============================================================================
# UTS: Builder roundtrip
# ============================================================================


def test_uts_imap_builder_roundtrip_greeting():
    """Build an IMAP server greeting and verify it can be parsed back."""
    imap = IMAP(status="OK", tag="*", text="IMAP4rev1 Service Ready")
    data = imap.bytes()

    pkt = _parse_imap(data)
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_untagged") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "OK"


def test_uts_imap_builder_roundtrip_login():
    """Build an IMAP LOGIN command and verify it can be parsed back."""
    imap = IMAP(command="LOGIN", tag="A001", args="alice password123")
    data = imap.bytes()

    pkt = _parse_imap(data)
    assert pkt.has_layer(LayerKind.Imap)
    assert pkt.getfieldval(LayerKind.Imap, "is_client_command") is True
    assert pkt.getfieldval(LayerKind.Imap, "command") == "LOGIN"
