"""Tests for IPv6 protocol parsing and field access via the Python API."""

import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_raw_ipv6(
    src: str = "::1",
    dst: str = "::1",
    next_header: int = 59,
    hop_limit: int = 64,
    payload: bytes = b"",
) -> bytes:
    """Manually construct a raw IPv6 header (40 bytes) + payload."""
    import ipaddress

    src_bytes = ipaddress.IPv6Address(src).packed
    dst_bytes = ipaddress.IPv6Address(dst).packed
    payload_len = len(payload)

    # Version=6, TC=0, FL=0 packed into 4 bytes (big-endian)
    vtcfl = (6 << 28).to_bytes(4, "big")
    header = (
        vtcfl + struct.pack("!HBB", payload_len, next_header, hop_limit) + src_bytes + dst_bytes
    )
    assert len(header) == 40
    return header + payload


def _build_eth_ipv6(
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    next_header: int = 59,
    hop_limit: int = 64,
    payload: bytes = b"",
) -> bytes:
    """Build a raw Ethernet/IPv6 frame."""
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst MAC
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,  # src MAC
            0x86,
            0xDD,  # EtherType IPv6
        ]
    )
    ipv6 = _build_raw_ipv6(src, dst, next_header, hop_limit, payload)
    return eth + ipv6


# ---------------------------------------------------------------------------
# Import checks
# ---------------------------------------------------------------------------


def test_layerkind_ipv6_exists():
    """LayerKind.Ipv6 must exist."""
    assert hasattr(LayerKind, "Ipv6")


def test_packet_import():
    """Packet must be importable."""
    assert Packet is not None


# ---------------------------------------------------------------------------
# Packet.from_bytes with raw IPv6 inside Ethernet
# ---------------------------------------------------------------------------


def test_parse_eth_ipv6_has_ipv6_layer():
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)


def test_parse_eth_ipv6_has_ethernet_layer():
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ethernet)


def test_parse_ipv6_version_field():
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    # version field via attribute access
    v = pkt.version
    assert v == 6


def test_parse_ipv6_hop_limit_default():
    raw = _build_eth_ipv6(hop_limit=64)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    hl = pkt.hlim
    assert hl == 64


def test_parse_ipv6_hop_limit_custom():
    raw = _build_eth_ipv6(hop_limit=128)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    hl = pkt.hlim
    assert hl == 128


def test_parse_ipv6_src_address():
    raw = _build_eth_ipv6(src="2001:db8::1", dst="2001:db8::2")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    # Use getfieldval to target the IPv6 layer specifically (pkt.src would
    # resolve to the Ethernet src MAC via __getattr__)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "2001:db8::1" in str(src)


def test_parse_ipv6_dst_address():
    raw = _build_eth_ipv6(src="2001:db8::1", dst="2001:db8::2")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "2001:db8::2" in str(dst)


def test_parse_ipv6_src_loopback():
    raw = _build_eth_ipv6(src="::1", dst="::1")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    s = str(src)
    assert "::1" in s or "0:0:0:0:0:0:0:1" in s


def test_parse_ipv6_next_header_icmpv6():
    # Provide a minimal ICMPv6 echo-request payload (8 bytes) so the parser
    # has enough data and does not raise "buffer too short".
    icmpv6_stub = bytes([128, 0, 0, 0, 0x00, 0x01, 0x00, 0x01])
    raw = _build_eth_ipv6(next_header=58, payload=icmpv6_stub)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    nh = pkt.getfieldval(LayerKind.Ipv6, "nh")
    assert nh == 58


def test_parse_ipv6_next_header_tcp():
    # Provide a minimal 20-byte TCP stub so the parser does not fail.
    tcp_stub = b"\x00" * 20
    raw = _build_eth_ipv6(next_header=6, payload=tcp_stub)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    nh = pkt.getfieldval(LayerKind.Ipv6, "nh")
    assert nh == 6


def test_parse_ipv6_next_header_udp():
    # Provide a minimal 8-byte UDP stub so the parser does not fail.
    udp_stub = b"\x00" * 8
    raw = _build_eth_ipv6(next_header=17, payload=udp_stub)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    nh = pkt.getfieldval(LayerKind.Ipv6, "nh")
    assert nh == 17


def test_parse_ipv6_payload_len():
    payload = b"hello ipv6"
    raw = _build_eth_ipv6(payload=payload)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    plen = pkt.plen
    assert plen == len(payload)


def test_parse_ipv6_link_local_src():
    raw = _build_eth_ipv6(src="fe80::1", dst="ff02::1")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "fe80" in str(src).lower()


def test_parse_ipv6_multicast_dst():
    raw = _build_eth_ipv6(src="fe80::1", dst="ff02::1")
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "ff02" in str(dst).lower()


# ---------------------------------------------------------------------------
# Packet.from_bytes — IPv6-only (no Ethernet) via get_layer_bytes
# ---------------------------------------------------------------------------


def test_ipv6_get_layer_bytes():
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    ipv6_bytes = pkt.get_layer_bytes(LayerKind.Ipv6)
    assert len(ipv6_bytes) >= 40


# ---------------------------------------------------------------------------
# Ethernet layer stacking: IPv6 ethertype = 0x86DD
# ---------------------------------------------------------------------------


def test_eth_ipv6_ethertype():
    """Ethernet frame carrying IPv6 should have EtherType 0x86DD."""
    raw = _build_eth_ipv6()
    # EtherType is at bytes 12-13 in Ethernet header
    ethertype = struct.unpack("!H", raw[12:14])[0]
    assert ethertype == 0x86DD


def test_eth_ipv6_ethertype_parsed():
    """The parsed Ethernet layer should have ethertype 0x86DD."""
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ethernet)
    # access ethertype from packet
    et = pkt.type
    assert et == 0x86DD


# ---------------------------------------------------------------------------
# LayerKind for IPv6
# ---------------------------------------------------------------------------


def test_layerkind_ipv6_value():
    """LayerKind.Ipv6 should be accessible and usable."""
    assert LayerKind.Ipv6 == LayerKind.Ipv6


def test_has_layer_ipv6_negative():
    """Packet with only Ethernet/IPv4 should NOT have IPv6 layer."""
    eth_ipv4 = bytes(
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
            0x08,
            0x00,  # EtherType IPv4
            0x45,
            0x00,
            0x00,
            0x14,
            0x00,
            0x00,
            0x40,
            0x00,
            0x40,
            0x3B,
            0x00,
            0x00,
            192,
            168,
            1,
            1,
            192,
            168,
            1,
            2,
        ]
    )
    pkt = Packet(eth_ipv4)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Ipv6)


# ---------------------------------------------------------------------------
# Field access via getfieldval
# ---------------------------------------------------------------------------


def test_getfieldval_ipv6_hop_limit():
    raw = _build_eth_ipv6(hop_limit=255)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    hl = pkt.getfieldval(LayerKind.Ipv6, "hlim")
    assert hl == 255


def test_getfieldval_ipv6_nh():
    # Include a small dummy ICMPv6 payload so the parser does not fail with
    # "buffer too short".  We only verify the nh field value from the IPv6 header.
    icmpv6_stub = bytes([128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01])  # echo request
    raw = _build_eth_ipv6(next_header=58, payload=icmpv6_stub)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    nh = pkt.getfieldval(LayerKind.Ipv6, "nh")
    assert nh == 58


def test_getfieldval_ipv6_plen():
    payload = b"x" * 20
    raw = _build_eth_ipv6(payload=payload)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    plen = pkt.getfieldval(LayerKind.Ipv6, "plen")
    assert plen == 20


# ---------------------------------------------------------------------------
# fields property
# ---------------------------------------------------------------------------


def test_ipv6_fields_property():
    raw = _build_eth_ipv6()
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ipv6)
    fields = pkt.fields
    # Should contain IPv6 field names
    assert isinstance(fields, list)
    # At least some fields should be present
    assert len(fields) > 0
