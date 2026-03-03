"""Tests for the TFTP (Trivial File Transfer Protocol) layer implementation.

These tests validate parsing, field access, building, and stacking of TFTP packets.
TFTP operates over UDP port 69 and has 5 packet types: RRQ, WRQ, DATA, ACK, ERROR.
"""

import struct

from stackforge import TFTP, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_udp_tftp(tftp_bytes: bytes, sport: int = 54321, dport: int = 69) -> bytes:
    """Wrap raw TFTP bytes inside Ethernet/IPv4/UDP(port 69) frame."""
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
    udp_len = 8 + len(tftp_bytes)
    ip_total = 20 + udp_len
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        17,
        0,
        0x7F000001,
        0x7F000001,
    )
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + tftp_bytes


# ============================================================================
# Tests 1-5: Builder tests (RRQ/WRQ)
# ============================================================================


def test_build_rrq():
    """Build a Read Request (RRQ) packet."""
    tftp = TFTP(opcode=1, filename="test.txt", mode="octet")
    data = tftp.bytes()
    assert isinstance(data, bytes)
    # Opcode: \x00\x01 (RRQ)
    assert data[0:2] == b"\x00\x01"
    assert b"test.txt" in data
    assert b"octet" in data
    # null terminators after filename and mode
    assert b"\x00" in data[2:]


def test_build_wrq():
    """Build a Write Request (WRQ) packet."""
    tftp = TFTP(opcode=2, filename="upload.bin", mode="octet")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x02"
    assert b"upload.bin" in data
    assert b"octet" in data


def test_build_data():
    """Build a DATA packet."""
    tftp = TFTP(opcode=3, block=1, data=b"hello world")
    data = tftp.bytes()
    # Opcode: \x00\x03 (DATA)
    assert data[0:2] == b"\x00\x03"
    # Block number: \x00\x01
    assert data[2:4] == b"\x00\x01"
    # Data payload
    assert b"hello world" in data


def test_build_ack():
    """Build an ACK packet."""
    tftp = TFTP(opcode=4, block=3)
    data = tftp.bytes()
    assert data == b"\x00\x04\x00\x03"
    assert len(data) == 4


def test_build_error():
    """Build an ERROR packet."""
    tftp = TFTP(opcode=5, error_code=1, error_msg="File not found")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x05"
    assert data[2:4] == b"\x00\x01"
    assert b"File not found" in data


# ============================================================================
# Tests 6-10: Parsing tests
# ============================================================================


def test_parse_rrq():
    """Parse a TFTP RRQ packet on port 69."""
    tftp_bytes = b"\x00\x01test.txt\x00octet\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)


def test_parse_data():
    """Parse a TFTP DATA packet."""
    tftp_bytes = b"\x00\x03\x00\x01hello world data"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)


def test_parse_ack():
    """Parse a TFTP ACK packet."""
    tftp_bytes = b"\x00\x04\x00\x05"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)


def test_parse_error():
    """Parse a TFTP ERROR packet."""
    tftp_bytes = b"\x00\x05\x00\x01File not found\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)


def test_parse_wrq():
    """Parse a TFTP WRQ packet."""
    tftp_bytes = b"\x00\x02upload.bin\x00netascii\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)


# ============================================================================
# Tests 11-17: Field access tests
# ============================================================================


def test_field_opcode_rrq():
    """Verify opcode field for RRQ."""
    tftp_bytes = b"\x00\x01test.txt\x00octet\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 1


def test_field_opcode_data():
    """Verify opcode field for DATA."""
    tftp_bytes = b"\x00\x03\x00\x01hello world"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 3


def test_field_opcode_ack():
    """Verify opcode field for ACK."""
    tftp_bytes = b"\x00\x04\x00\x07"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 4


def test_field_block_num_data():
    """Verify block_num for DATA packet."""
    tftp_bytes = b"\x00\x03\x00\x05hello"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 5


def test_field_block_num_ack():
    """Verify block_num for ACK packet."""
    tftp_bytes = b"\x00\x04\x00\x0a"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 10


def test_field_error_code():
    """Verify error_code for ERROR packet."""
    tftp_bytes = b"\x00\x05\x00\x02Access violation\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "error_code") == 2


def test_field_error_msg():
    """Verify error_msg for ERROR packet."""
    tftp_bytes = b"\x00\x05\x00\x01File not found\x00"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Tftp, "error_msg") == "File not found"


# ============================================================================
# Tests 18-20: Layer detection and edge cases
# ============================================================================


def test_has_layer_tftp():
    """Verify has_layer returns True for TFTP and related layers."""
    tftp_bytes = b"\x00\x04\x00\x01"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Udp)
    assert not pkt.has_layer(LayerKind.Tcp)


def test_non_tftp_port_not_detected():
    """UDP traffic not on port 69 should NOT be detected as TFTP."""
    tftp_bytes = b"\x00\x04\x00\x01"
    raw = make_eth_ip_udp_tftp(tftp_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Tftp)


def test_get_layer_bytes_tftp():
    """Verify get_layer_bytes returns the correct TFTP bytes."""
    tftp_bytes = b"\x00\x04\x00\x01"
    raw = make_eth_ip_udp_tftp(tftp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Tftp)
    assert layer_bytes == tftp_bytes
