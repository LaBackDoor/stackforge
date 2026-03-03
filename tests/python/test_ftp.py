"""Tests for the FTP (File Transfer Protocol) layer implementation.

These tests validate parsing, field access, building, and stacking of FTP packets.
FTP operates on TCP port 21 for the control connection.
"""

import struct

from stackforge import FTP, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_ftp(ftp_bytes: bytes, sport: int = 54321, dport: int = 21) -> bytes:
    """Wrap raw FTP bytes inside Ethernet/IPv4/TCP(port 21) frame."""
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
    ip_total = 20 + tcp_header_len + len(ftp_bytes)
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
    return eth + ip + tcp + ftp_bytes


# ============================================================================
# Tests 1-7: Builder tests (server replies)
# ============================================================================


def test_build_service_ready():
    """Build a 220 Service Ready reply and verify raw bytes."""
    ftp = FTP(reply_code=220, reply_text="FTP Server ready")
    data = ftp.bytes()
    assert isinstance(data, bytes)
    assert data == b"220 FTP Server ready\r\n"


def test_build_closing_control():
    """Build a 221 Goodbye reply."""
    ftp = FTP(reply_code=221, reply_text="Goodbye")
    data = ftp.bytes()
    assert data == b"221 Goodbye\r\n"


def test_build_user_logged_in():
    """Build a 230 User logged in reply."""
    ftp = FTP(reply_code=230, reply_text="User logged in, proceed")
    data = ftp.bytes()
    assert data == b"230 User logged in, proceed\r\n"


def test_build_password_required():
    """Build a 331 Password required reply."""
    ftp = FTP(reply_code=331, reply_text="Password required")
    data = ftp.bytes()
    assert data == b"331 Password required\r\n"


def test_build_not_logged_in():
    """Build a 530 Not logged in reply."""
    ftp = FTP(reply_code=530, reply_text="Not logged in")
    data = ftp.bytes()
    assert data == b"530 Not logged in\r\n"


def test_build_passive_mode():
    """Build a 227 Entering Passive Mode reply."""
    ftp = FTP(reply_code=227, reply_text="Entering Passive Mode (192,168,1,1,200,50)")
    data = ftp.bytes()
    assert data == b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n"


def test_build_file_unavailable():
    """Build a 550 File unavailable reply."""
    ftp = FTP(reply_code=550, reply_text="No such file or directory")
    data = ftp.bytes()
    assert data == b"550 No such file or directory\r\n"


# ============================================================================
# Tests 8-14: Builder tests (client commands)
# ============================================================================


def test_build_user_command():
    """Build a USER command."""
    ftp = FTP(command="USER", args="anonymous")
    data = ftp.bytes()
    assert data == b"USER anonymous\r\n"


def test_build_pass_command():
    """Build a PASS command."""
    ftp = FTP(command="PASS", args="secret")
    data = ftp.bytes()
    assert data == b"PASS secret\r\n"


def test_build_retr_command():
    """Build a RETR command."""
    ftp = FTP(command="RETR", args="file.txt")
    data = ftp.bytes()
    assert data == b"RETR file.txt\r\n"


def test_build_stor_command():
    """Build a STOR command."""
    ftp = FTP(command="STOR", args="upload.dat")
    data = ftp.bytes()
    assert data == b"STOR upload.dat\r\n"


def test_build_list_command_no_args():
    """Build a LIST command with no arguments."""
    ftp = FTP(command="LIST")
    data = ftp.bytes()
    assert data == b"LIST\r\n"


def test_build_list_command_with_path():
    """Build a LIST command with a path."""
    ftp = FTP(command="LIST", args="/pub")
    data = ftp.bytes()
    assert data == b"LIST /pub\r\n"


def test_build_quit_command():
    """Build a QUIT command."""
    ftp = FTP(command="QUIT")
    data = ftp.bytes()
    assert data == b"QUIT\r\n"


# ============================================================================
# Tests 15-20: Parsing tests
# ============================================================================


def test_parse_service_ready():
    """Parse a 220 service ready reply on port 21."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


def test_parse_user_command():
    """Parse a USER command on port 21."""
    ftp_bytes = b"USER anonymous\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


def test_parse_password_required():
    """Parse a 331 password required reply."""
    ftp_bytes = b"331 Password required\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


def test_parse_user_logged_in():
    """Parse a 230 user logged in reply."""
    ftp_bytes = b"230 User logged in, proceed\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


def test_parse_passive_mode():
    """Parse a 227 entering passive mode reply."""
    ftp_bytes = b"227 Entering Passive Mode (192,168,1,1,200,50)\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


def test_parse_not_logged_in():
    """Parse a 530 not logged in reply."""
    ftp_bytes = b"530 Not logged in\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)


# ============================================================================
# Tests 21-30: Field access tests
# ============================================================================


def test_field_reply_code_220():
    """Verify reply_code is 220 for service ready."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 220


def test_field_reply_code_331():
    """Verify reply_code is 331 for password required."""
    ftp_bytes = b"331 Password required\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 331


def test_field_reply_code_530():
    """Verify reply_code is 530 for not logged in."""
    ftp_bytes = b"530 Not logged in\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 530


def test_field_reply_text():
    """Verify reply_text for a 220 response."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "reply_text") == "FTP Server ready"


def test_field_is_response_true():
    """Verify is_response is True for server replies."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is True


def test_field_is_response_false():
    """Verify is_response is False for client commands."""
    ftp_bytes = b"USER anonymous\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is False


def test_field_command_user():
    """Verify command field for USER command."""
    ftp_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "USER"


def test_field_args_user():
    """Verify args field for USER command."""
    ftp_bytes = b"USER alice\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "args") == "alice"


def test_field_is_multiline_false():
    """Verify is_multiline is False for single-line replies."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "is_multiline") is False


def test_field_is_multiline_true():
    """Verify is_multiline is True for multi-line replies."""
    ftp_bytes = b"220-Welcome to FTP\r\n220 Ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Ftp, "is_multiline") is True


# ============================================================================
# Tests 31-34: has_layer and layer detection tests
# ============================================================================


def test_has_layer_ftp():
    """Verify has_layer returns True for FTP and related layers."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Udp)


def test_layer_order_ftp():
    """Verify the expected layer order: Ethernet / IPv4 / TCP / FTP."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Ethernet in kinds
    assert LayerKind.Ipv4 in kinds
    assert LayerKind.Tcp in kinds
    assert LayerKind.Ftp in kinds
    tcp_pos = kinds.index(LayerKind.Tcp)
    ftp_pos = kinds.index(LayerKind.Ftp)
    assert ftp_pos > tcp_pos, "FTP should come after TCP"


def test_non_ftp_port_no_layer():
    """TCP traffic not on port 21 should NOT be detected as FTP."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Ftp)


def test_get_layer_bytes_ftp():
    """Verify get_layer_bytes returns the correct FTP bytes."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Ftp)
    assert layer_bytes == ftp_bytes


# ============================================================================
# Tests 35-38: Build and parse roundtrip
# ============================================================================


def test_build_and_parse_roundtrip_reply():
    """Build a 220 reply, wrap in Eth/IP/TCP, parse it back, verify fields."""
    ftp = FTP(reply_code=220, reply_text="Welcome")
    built = ftp.bytes()
    raw = make_eth_ip_tcp_ftp(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "reply_code") == 220
    assert pkt.getfieldval(LayerKind.Ftp, "is_response") is True


def test_build_and_parse_roundtrip_command():
    """Build a USER command, wrap in Eth/IP/TCP, parse it back."""
    ftp = FTP(command="USER", args="bob")
    built = ftp.bytes()
    raw = make_eth_ip_tcp_ftp(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "USER"
    assert pkt.getfieldval(LayerKind.Ftp, "args") == "bob"


def test_show_includes_ftp():
    """Verify show() includes FTP information."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "FTP" in show


def test_fields_property_ftp():
    """Verify 'fields' property includes FTP field names."""
    ftp_bytes = b"220 FTP Server ready\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    fields = pkt.fields
    assert "reply_code" in fields or "command" in fields  # at least one FTP field


# ============================================================================
# Tests 39-42: LayerKind identity
# ============================================================================


def test_layer_kind_identity():
    """Verify LayerKind.Ftp can be imported and used."""
    assert LayerKind.Ftp is not None


def test_ftp_builder_bytes_method():
    """Verify .bytes() works on FTP builder."""
    ftp = FTP(reply_code=220, reply_text="Ready")
    data = ftp.bytes()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_parse_retr_command():
    """Parse a RETR command."""
    ftp_bytes = b"RETR file.txt\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "RETR"
    assert pkt.getfieldval(LayerKind.Ftp, "args") == "file.txt"


def test_parse_pasv_command():
    """Parse a PASV command."""
    ftp_bytes = b"PASV\r\n"
    raw = make_eth_ip_tcp_ftp(ftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ftp)
    assert pkt.getfieldval(LayerKind.Ftp, "command") == "PASV"
