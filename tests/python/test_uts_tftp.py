"""UTS-driven TFTP tests.

Translates assertions from tests/uts/tftp.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw TFTP bytes
must be wrapped in an Ethernet/IPv4/UDP frame before parsing.  The helper
_wrap_tftp() constructs a minimal such frame targeting UDP port 69.
"""

import struct

from stackforge import TFTP, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_udp(payload: bytes, sport: int = 12345, dport: int = 69) -> bytes:
    """Build a minimal Ethernet/IPv4/UDP frame carrying the given payload."""
    udp_len = 8 + len(payload)
    ip_total = 20 + udp_len

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
        17,
        0,
        0x7F000001,
        0x7F000001,
    )
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + payload


def _parse_tftp(tftp_bytes: bytes, dport: int = 69) -> Packet:
    """Wrap raw TFTP bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_udp(tftp_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: TFTP RRQ (Read Request) opcode=1
# ============================================================================


def test_uts_tftp_rrq_build():
    """
    UTS: p = TFTP(opcode=1, filename="test.txt", mode="octet")
         data = bytes(p)
         assert data[0:2] == b"\\x00\\x01"
         assert b"test.txt" in data
         assert b"octet" in data
    """
    tftp = TFTP(opcode=1, filename="test.txt", mode="octet")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x01"
    assert b"test.txt" in data
    assert b"octet" in data


def test_uts_tftp_rrq_dissect():
    """
    UTS: s = b"\\x00\\x01test.txt\\x00octet\\x00"
         p = TFTP(s)
         assert p.opcode == 1
         assert p.filename == "test.txt"
         assert p.mode == "octet"
    """
    tftp_payload = b"\x00\x01test.txt\x00octet\x00"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp), "TFTP layer not found"
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 1


# ============================================================================
# UTS: TFTP WRQ (Write Request) opcode=2
# ============================================================================


def test_uts_tftp_wrq_build():
    """
    UTS: p = TFTP(opcode=2, filename="upload.bin", mode="octet")
         assert data[0:2] == b"\\x00\\x02"
    """
    tftp = TFTP(opcode=2, filename="upload.bin", mode="octet")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x02"
    assert b"upload.bin" in data


def test_uts_tftp_wrq_dissect():
    """
    UTS: s = b"\\x00\\x02upload.bin\\x00netascii\\x00"
         p = TFTP(s)
         assert p.opcode == 2
    """
    tftp_payload = b"\x00\x02upload.bin\x00netascii\x00"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 2


# ============================================================================
# UTS: TFTP DATA opcode=3
# ============================================================================


def test_uts_tftp_data_build():
    """
    UTS: p = TFTP(opcode=3, block=1, data=b"hello world")
         assert data[0:2] == b"\\x00\\x03"
         assert data[2:4] == b"\\x00\\x01"
         assert b"hello world" in data
    """
    tftp = TFTP(opcode=3, block=1, data=b"hello world")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x03"
    assert data[2:4] == b"\x00\x01"
    assert b"hello world" in data


def test_uts_tftp_data_dissect():
    """
    UTS: s = b"\\x00\\x03\\x00\\x05hello world"
         p = TFTP(s)
         assert p.opcode == 3
         assert p.block_num == 5
    """
    tftp_payload = b"\x00\x03\x00\x05hello world"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 3
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 5


# ============================================================================
# UTS: TFTP ACK opcode=4
# ============================================================================


def test_uts_tftp_ack_build():
    """
    UTS: p = TFTP(opcode=4, block=3)
         assert data == b"\\x00\\x04\\x00\\x03"
         assert len(data) == 4
    """
    tftp = TFTP(opcode=4, block=3)
    data = tftp.bytes()
    assert data == b"\x00\x04\x00\x03"
    assert len(data) == 4


def test_uts_tftp_ack_dissect():
    """
    UTS: s = b"\\x00\\x04\\x00\\x07"
         p = TFTP(s)
         assert p.opcode == 4
         assert p.block_num == 7
    """
    tftp_payload = b"\x00\x04\x00\x07"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 4
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 7


# ============================================================================
# UTS: TFTP ERROR opcode=5
# ============================================================================


def test_uts_tftp_error_build():
    """
    UTS: p = TFTP(opcode=5, error_code=1, error_msg="File not found")
         assert data[0:2] == b"\\x00\\x05"
         assert data[2:4] == b"\\x00\\x01"
         assert b"File not found" in data
    """
    tftp = TFTP(opcode=5, error_code=1, error_msg="File not found")
    data = tftp.bytes()
    assert data[0:2] == b"\x00\x05"
    assert data[2:4] == b"\x00\x01"
    assert b"File not found" in data


def test_uts_tftp_error_dissect():
    """
    UTS: s = b"\\x00\\x05\\x00\\x02Access violation\\x00"
         p = TFTP(s)
         assert p.opcode == 5
         assert p.error_code == 2
         assert p.error_msg == "Access violation"
    """
    tftp_payload = b"\x00\x05\x00\x02Access violation\x00"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 5
    assert pkt.getfieldval(LayerKind.Tftp, "error_code") == 2
    assert pkt.getfieldval(LayerKind.Tftp, "error_msg") == "Access violation"


# ============================================================================
# UTS: TFTP ACK block 0 (acknowledge WRQ)
# ============================================================================


def test_uts_tftp_ack_zero():
    """
    UTS: s = b"\\x00\\x04\\x00\\x00"
         p = TFTP(s)
         assert p.opcode == 4
         assert p.block_num == 0
    """
    tftp_payload = b"\x00\x04\x00\x00"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 4
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 0


# ============================================================================
# UTS: TFTP DATA large block
# ============================================================================


def test_uts_tftp_data_large_block():
    """
    UTS: s = b"\\x00\\x03\\x00\\x0a" + b"X" * 512
         p = TFTP(s)
         assert p.opcode == 3
         assert p.block_num == 10
    """
    tftp_payload = b"\x00\x03\x00\x0a" + b"X" * 512
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 3
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 10


# ============================================================================
# UTS: Verify all layers present
# ============================================================================


def test_uts_tftp_has_all_layers():
    """Verify Ethernet/IPv4/UDP/TFTP layers are all present."""
    tftp_payload = b"\x00\x04\x00\x01"
    pkt = _parse_tftp(tftp_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Udp)
    assert pkt.has_layer(LayerKind.Tftp)
    assert not pkt.has_layer(LayerKind.Tcp)


# ============================================================================
# UTS: Non-port-69 not detected
# ============================================================================


def test_uts_tftp_non_port_69_not_detected():
    """TFTP traffic on non-port-69 should not be detected as TFTP."""
    tftp_payload = b"\x00\x04\x00\x01"
    pkt = _parse_tftp(tftp_payload, dport=9999)

    assert not pkt.has_layer(LayerKind.Tftp)


# ============================================================================
# UTS: Builder roundtrip
# ============================================================================


def test_uts_tftp_builder_roundtrip_rrq():
    """Build a TFTP RRQ and verify it can be parsed back."""
    tftp = TFTP(opcode=1, filename="test.txt", mode="octet")
    data = tftp.bytes()

    pkt = _parse_tftp(data)
    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 1


def test_uts_tftp_builder_roundtrip_ack():
    """Build a TFTP ACK and verify it can be parsed back."""
    tftp = TFTP(opcode=4, block=5)
    data = tftp.bytes()

    pkt = _parse_tftp(data)
    assert pkt.has_layer(LayerKind.Tftp)
    assert pkt.getfieldval(LayerKind.Tftp, "opcode") == 4
    assert pkt.getfieldval(LayerKind.Tftp, "block_num") == 5
