"""UTS-driven FTP tests.

Translates assertions from tests/uts/ftp.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw FTP bytes
must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_ftp() constructs a minimal such frame targeting TCP port 21.
"""

import struct

from stackforge import FTP, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 21) -> bytes:
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


def _parse_ftp(ftp_bytes: bytes, dport: int = 21) -> Packet:
    """Wrap raw FTP bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(ftp_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: FTP 220 Service Ready reply
# ============================================================================


def test_uts_ftp_220_service_ready_build():
    """
    UTS: p = FTP(reply_code=220, reply_text="FTP Server ready")
         assert bytes(p) == b"220 FTP Server ready\\r\\n"
    """
    ftp = FTP(reply_code=220, reply_text="FTP Server ready")
    data = ftp.bytes()
    assert data == b"220 FTP Server ready\r\n"


def test_uts_ftp_220_dissect():
    """
    UTS: s = b"220 FTP Server ready\\r\\n"
         p = FTP(s)
         assert p.reply_code == 220
         assert p.is_response is True
    """
    ftp_payload = b"220 FTP Server ready\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp), "FTP layer not found"
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is True


# ============================================================================
# UTS: FTP 221 Goodbye
# ============================================================================


def test_uts_ftp_221_goodbye_build():
    """
    UTS: p = FTP(reply_code=221, reply_text="Goodbye")
         assert bytes(p) == b"221 Goodbye\\r\\n"
    """
    ftp = FTP(reply_code=221, reply_text="Goodbye")
    data = ftp.bytes()
    assert data == b"221 Goodbye\r\n"


# ============================================================================
# UTS: FTP 331 Password required
# ============================================================================


def test_uts_ftp_331_password_required():
    """
    UTS: s = b"331 Password required\\r\\n"
         p = FTP(s)
         assert p.reply_code == 331
    """
    ftp_payload = b"331 Password required\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 331
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is True


# ============================================================================
# UTS: FTP USER command
# ============================================================================


def test_uts_ftp_user_command_build():
    """
    UTS: p = FTP(command="USER", args="anonymous")
         assert bytes(p) == b"USER anonymous\\r\\n"
    """
    ftp = FTP(command="USER", args="anonymous")
    data = ftp.bytes()
    assert data == b"USER anonymous\r\n"


def test_uts_ftp_user_command_dissect():
    """
    UTS: s = b"USER alice\\r\\n"
         p = FTP(s)
         assert p.command == "USER"
         assert p.args == "alice"
         assert p.is_response is False
    """
    ftp_payload = b"USER alice\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "USER"
    assert pkt.getfieldval(LayerKind.Ftp, "args") == "alice"
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is False


# ============================================================================
# UTS: FTP PASS command
# ============================================================================


def test_uts_ftp_pass_command_build():
    """
    UTS: p = FTP(command="PASS", args="secret")
         assert bytes(p) == b"PASS secret\\r\\n"
    """
    ftp = FTP(command="PASS", args="secret")
    data = ftp.bytes()
    assert data == b"PASS secret\r\n"


# ============================================================================
# UTS: FTP RETR command
# ============================================================================


def test_uts_ftp_retr_command():
    """
    UTS: p = FTP(command="RETR", args="file.txt")
         assert bytes(p) == b"RETR file.txt\\r\\n"
    Verify RETR can be built and parsed.
    """
    ftp = FTP(command="RETR", args="file.txt")
    data = ftp.bytes()
    assert data == b"RETR file.txt\r\n"

    pkt = _parse_ftp(data)
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "RETR"
    assert pkt.getfieldval(LayerKind.Ftp, "args") == "file.txt"


# ============================================================================
# UTS: FTP LIST command (no arguments)
# ============================================================================


def test_uts_ftp_list_no_args():
    """
    UTS: p = FTP(command="LIST")
         assert bytes(p) == b"LIST\\r\\n"
    """
    ftp = FTP(command="LIST")
    data = ftp.bytes()
    assert data == b"LIST\r\n"


# ============================================================================
# UTS: FTP QUIT command
# ============================================================================


def test_uts_ftp_quit_command():
    """
    UTS: p = FTP(command="QUIT")
         assert bytes(p) == b"QUIT\\r\\n"
    """
    ftp = FTP(command="QUIT")
    data = ftp.bytes()
    assert data == b"QUIT\r\n"


# ============================================================================
# UTS: FTP 530 Not logged in
# ============================================================================


def test_uts_ftp_530_not_logged_in():
    """
    UTS: s = b"530 Not logged in\\r\\n"
         p = FTP(s)
         assert p.reply_code == 530
    """
    ftp_payload = b"530 Not logged in\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 530


# ============================================================================
# UTS: FTP 230 User logged in
# ============================================================================


def test_uts_ftp_230_user_logged_in():
    """
    UTS: s = b"230 User logged in, proceed\\r\\n"
         p = FTP(s)
         assert p.reply_code == 230
    """
    ftp_payload = b"230 User logged in, proceed\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 230
    assert pkt.getfieldval(LayerKind.Ftp, "reply_text") == "User logged in, proceed"


# ============================================================================
# UTS: FTP multiline response
# ============================================================================


def test_uts_ftp_multiline_response():
    """
    UTS: s = b"220-Welcome to FTP\\r\\n220 Ready\\r\\n"
         p = FTP(s)
         assert p.is_multiline is True
    """
    ftp_payload = b"220-Welcome to FTP\r\n220 Ready\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "is_multiline") is True


# ============================================================================
# UTS: FTP 227 Passive Mode
# ============================================================================


def test_uts_ftp_227_passive_mode():
    """
    UTS: s = b"227 Entering Passive Mode (192,168,1,1,200,50)\\r\\n"
         p = FTP(s)
         assert p.reply_code == 227
    """
    ftp_payload = b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 227


# ============================================================================
# UTS: Verify all layers present
# ============================================================================


def test_uts_ftp_has_all_layers():
    """Verify Ethernet/IPv4/TCP/FTP layers are all present."""
    ftp_payload = b"220 FTP Server ready\r\n"
    pkt = _parse_ftp(ftp_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Ftp)


# ============================================================================
# UTS: Non-FTP port detection
# ============================================================================


def test_uts_ftp_non_port_21_not_detected():
    """FTP traffic on non-port-21 should not be detected as FTP."""
    ftp_payload = b"220 FTP Server ready\r\n"
    pkt = _parse_ftp(ftp_payload, dport=9999)

    assert not pkt.has_layer(LayerKind.Ftp)


# ============================================================================
# UTS: Builder roundtrip
# ============================================================================


def test_uts_ftp_builder_roundtrip():
    """Build an FTP reply and verify it can be parsed back."""
    ftp = FTP(reply_code=220, reply_text="FTP Server ready")
    data = ftp.bytes()

    pkt = _parse_ftp(data)
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Ftp, "reply_text") == "FTP Server ready"
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is True
