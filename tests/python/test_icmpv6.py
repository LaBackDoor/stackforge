"""Tests for ICMPv6 protocol parsing and field access via the Python API.

Since ICMPv6 is not currently exposed as a Python class, we test via raw
packet parsing using manually constructed byte buffers.
"""

import ipaddress
import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
ICMPV6_NEIGHBOR_SOLICIT = 135
ICMPV6_NEIGHBOR_ADVERT = 136
ICMPV6_ROUTER_SOLICIT = 133
ICMPV6_ROUTER_ADVERT = 134
ICMPV6_DEST_UNREACH = 1
ICMPV6_PKT_TOO_BIG = 2
ICMPV6_TIME_EXCEEDED = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_icmpv6_echo_request(
    icmpv6_type: int, code: int, id_: int, seq: int, payload: bytes = b""
) -> bytes:
    """Build a raw ICMPv6 echo request/reply (8-byte header + payload)."""
    header = struct.pack("!BBHHH", icmpv6_type, code, 0, id_, seq)
    return header + payload


def _make_icmpv6_ns(target: str) -> bytes:
    """Build a raw Neighbor Solicitation (8-byte header + 16-byte target)."""
    target_bytes = ipaddress.IPv6Address(target).packed
    header = struct.pack("!BBH", ICMPV6_NEIGHBOR_SOLICIT, 0, 0) + b"\x00\x00\x00\x00"
    return header + target_bytes


def _ipv6_header(
    src: str, dst: str, next_header: int, payload_len: int, hop_limit: int = 64
) -> bytes:
    src_bytes = ipaddress.IPv6Address(src).packed
    dst_bytes = ipaddress.IPv6Address(dst).packed
    vtcfl = (6 << 28).to_bytes(4, "big")
    return vtcfl + struct.pack("!HBB", payload_len, next_header, hop_limit) + src_bytes + dst_bytes


def _eth_header() -> bytes:
    return bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0x86,
            0xDD,  # EtherType IPv6
        ]
    )


def _build_eth_ipv6_icmpv6(
    icmpv6_bytes: bytes, src: str = "2001:db8::1", dst: str = "2001:db8::2"
) -> bytes:
    """Build Ethernet/IPv6/ICMPv6 packet."""
    ipv6 = _ipv6_header(src, dst, next_header=58, payload_len=len(icmpv6_bytes))
    return _eth_header() + ipv6 + icmpv6_bytes


# ---------------------------------------------------------------------------
# LayerKind.Icmpv6 existence
# ---------------------------------------------------------------------------


def test_layerkind_icmpv6_exists():
    assert hasattr(LayerKind, "Icmpv6")


# ---------------------------------------------------------------------------
# Parse Ethernet/IPv6/ICMPv6 echo request
# ---------------------------------------------------------------------------


def test_parse_icmpv6_echo_request_layers():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0x1234, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv6)
    assert pkt.has_layer(LayerKind.Icmpv6)


def test_parse_icmpv6_echo_request_type_field():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0x1234, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    t = pkt.getfieldval(LayerKind.Icmpv6, "type")
    assert t == ICMPV6_ECHO_REQUEST


def test_parse_icmpv6_echo_request_code_field():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0x1234, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    code = pkt.getfieldval(LayerKind.Icmpv6, "code")
    assert code == 0


def test_parse_icmpv6_echo_request_id_field():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0xABCD, 7)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    id_val = pkt.getfieldval(LayerKind.Icmpv6, "id")
    assert id_val == 0xABCD


def test_parse_icmpv6_echo_request_seq_field():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 1, 0x5678)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    seq = pkt.getfieldval(LayerKind.Icmpv6, "seq")
    assert seq == 0x5678


# ---------------------------------------------------------------------------
# Parse ICMPv6 echo reply
# ---------------------------------------------------------------------------


def test_parse_icmpv6_echo_reply_type():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REPLY, 0, 0x1234, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    t = pkt.getfieldval(LayerKind.Icmpv6, "type")
    assert t == ICMPV6_ECHO_REPLY


def test_parse_icmpv6_echo_reply_layer_present():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REPLY, 0, 0x5678, 3)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)


# ---------------------------------------------------------------------------
# Parse IPv6 layer under ICMPv6
# ---------------------------------------------------------------------------


def test_parse_icmpv6_parent_ipv6_src():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 1, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6, src="2001:db8::1", dst="2001:db8::2")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "2001:db8::1" in str(src)


def test_parse_icmpv6_parent_ipv6_next_header_58():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 1, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    nh = pkt.getfieldval(LayerKind.Ipv6, "nh")
    assert nh == 58


# ---------------------------------------------------------------------------
# ICMPv6 type constants verification via raw parsing
# ---------------------------------------------------------------------------


def test_icmpv6_type_constant_echo_request():
    assert ICMPV6_ECHO_REQUEST == 128


def test_icmpv6_type_constant_echo_reply():
    assert ICMPV6_ECHO_REPLY == 129


def test_icmpv6_type_constant_neighbor_solicit():
    assert ICMPV6_NEIGHBOR_SOLICIT == 135


def test_icmpv6_type_constant_neighbor_advert():
    assert ICMPV6_NEIGHBOR_ADVERT == 136


# ---------------------------------------------------------------------------
# Neighbor Solicitation
# ---------------------------------------------------------------------------


def test_parse_icmpv6_neighbor_solicitation_type():
    ns = _make_icmpv6_ns("fe80::1")
    raw = _build_eth_ipv6_icmpv6(ns)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    t = pkt.getfieldval(LayerKind.Icmpv6, "type")
    assert t == ICMPV6_NEIGHBOR_SOLICIT


def test_parse_icmpv6_neighbor_solicitation_code_zero():
    ns = _make_icmpv6_ns("fe80::1")
    raw = _build_eth_ipv6_icmpv6(ns)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    code = pkt.getfieldval(LayerKind.Icmpv6, "code")
    assert code == 0


# ---------------------------------------------------------------------------
# Get layer bytes
# ---------------------------------------------------------------------------


def test_icmpv6_get_layer_bytes():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0x1234, 5)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    icmpv6_bytes = pkt.get_layer_bytes(LayerKind.Icmpv6)
    assert len(icmpv6_bytes) >= 8
    assert icmpv6_bytes[0] == ICMPV6_ECHO_REQUEST


def test_icmpv6_get_layer_bytes_echo_reply():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REPLY, 0, 0xABCD, 10)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    b = pkt.get_layer_bytes(LayerKind.Icmpv6)
    assert b[0] == ICMPV6_ECHO_REPLY


# ---------------------------------------------------------------------------
# ICMPv6 with payload
# ---------------------------------------------------------------------------


def test_icmpv6_echo_with_data_payload():
    data = b"ping-data-here"
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 1, 1, data)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    # The ICMPv6 layer bytes should include the data
    b = pkt.get_layer_bytes(LayerKind.Icmpv6)
    assert b"ping-data-here" in b


# ---------------------------------------------------------------------------
# Checksum field exists
# ---------------------------------------------------------------------------


def test_icmpv6_chksum_field_exists():
    icmpv6 = _make_icmpv6_echo_request(ICMPV6_ECHO_REQUEST, 0, 0x1234, 1)
    raw = _build_eth_ipv6_icmpv6(icmpv6)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Icmpv6)
    # chksum field should be accessible (may be 0 since we didn't compute it)
    chksum = pkt.getfieldval(LayerKind.Icmpv6, "chksum")
    assert isinstance(chksum, int)
