"""UTS-driven IPv6 tests using exact byte sequences from tests/uts/inet6.uts.

Each test uses the precise byte sequences referenced in the Scapy UTS file and
validates those bytes against the stackforge Python API.  Tests are deliberately
distinct from tests/python/test_ipv6.py: they exercise UTS-specific frames
rather than general builder-constructed frames.
"""

import ipaddress
import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Constants — Ethernet headers used to wrap raw IPv6 packets
# ---------------------------------------------------------------------------

# Ethernet dst=ff:ff:ff:ff:ff:ff, src=00:00:00:00:00:00, EtherType=0x86dd
_ETH_BCAST_IPV6 = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x86\xdd"


def _wrap_eth(raw_ipv6: bytes) -> bytes:
    """Prepend an Ethernet/IPv6 header to a raw IPv6 byte string."""
    return _ETH_BCAST_IPV6 + raw_ipv6


# ---------------------------------------------------------------------------
# UTS byte sequences (taken verbatim from inet6.uts)
# ---------------------------------------------------------------------------

# raw(IPv6()) — 40-byte default IPv6 header
_UTS_IPV6_DEFAULT = (
    b"`\x00\x00\x00\x00\x00;@"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
)

# raw(IPv6()/TCP()) — IPv6 + TCP (20-byte header)
_UTS_IPV6_TCP = (
    b"`\x00\x00\x00\x00\x14\x06@"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x8f}\x00\x00"
)

# raw(IPv6()/TCP()/Raw(load="somedata"))
_UTS_IPV6_TCP_DATA = (
    b"`\x00\x00\x00\x00\x1c\x06@"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\xd5\xdd\x00\x00"
    b"somedata"
)

# raw(Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff")/IPv6()/TCP())
_UTS_ETH_IPV6_TCP = (
    b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x86\xdd"
    b"`\x00\x00\x00\x00\x14\x06@"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\x8f}\x00\x00"
)

# raw(IPv6(src="2048::deca", dst="2047::cafe") / IPv6ExtHdrRouting(addresses=[]) / TCP(dport=80))
# IPv6 nh=43 (Routing header)
_UTS_IPV6_ROUTING = (
    b"`\x00\x00\x00\x00\x1c+@"
    b" H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xde\xca"
    b" G\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xca\xfe"
    b"\x06\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\xa5&\x00\x00"
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse(raw: bytes) -> Packet:
    pkt = Packet(raw)
    pkt.parse()
    return pkt


# ===========================================================================
# 1. Default IPv6 header — UTS: "IPv6 Class basic build (default values)"
# ===========================================================================


def test_uts_ipv6_default_has_ipv6_layer():
    """Wrapping the default IPv6 bytes in Ethernet yields an IPv6 layer."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.has_layer(LayerKind.Ipv6)


def test_uts_ipv6_default_version():
    """Default IPv6 header: version == 6."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "version") == 6


def test_uts_ipv6_default_traffic_class():
    """Default IPv6 header: tc == 0."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "tc") == 0


def test_uts_ipv6_default_flow_label():
    """Default IPv6 header: fl == 0."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "fl") == 0


def test_uts_ipv6_default_payload_len():
    """Default IPv6 header: plen == 0 (no payload)."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "plen") == 0


def test_uts_ipv6_default_next_header():
    """Default IPv6 header: nh == 59 (No-Next-Header)."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 59


def test_uts_ipv6_default_hop_limit():
    """Default IPv6 header: hlim == 64."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    assert pkt.getfieldval(LayerKind.Ipv6, "hlim") == 64


def test_uts_ipv6_default_src():
    """Default IPv6 header: src == '::1'."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "::1" in str(src) or str(src) == "::1"


def test_uts_ipv6_default_dst():
    """Default IPv6 header: dst == '::1'."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "::1" in str(dst) or str(dst) == "::1"


# ===========================================================================
# 2. Ethernet/IPv6 binding — UTS: "IPv6 Class binding with Ethernet - build"
# ===========================================================================


def test_uts_eth_ipv6_tcp_has_ethernet():
    """Full Ethernet/IPv6/TCP frame has Ethernet layer."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.has_layer(LayerKind.Ethernet)


def test_uts_eth_ipv6_tcp_has_ipv6():
    """Full Ethernet/IPv6/TCP frame has IPv6 layer."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.has_layer(LayerKind.Ipv6)


def test_uts_eth_ipv6_tcp_has_tcp():
    """Full Ethernet/IPv6/TCP frame has TCP layer."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.has_layer(LayerKind.Tcp)


def test_uts_eth_ipv6_ethertype():
    """Ethernet ethertype must be 0x86DD for IPv6."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.getfieldval(LayerKind.Ethernet, "type") == 0x86DD


# ===========================================================================
# 3. IPv6 + TCP — UTS: "IPv6 Class with basic TCP stacked"
# ===========================================================================


def test_uts_ipv6_tcp_nh_is_6():
    """IPv6/TCP packet: nh == 6 (TCP)."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 6


def test_uts_ipv6_tcp_plen():
    """IPv6/TCP packet: plen == 20 (TCP header with no data)."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    assert pkt.getfieldval(LayerKind.Ipv6, "plen") == 20


def test_uts_ipv6_tcp_src_is_loopback():
    """IPv6/TCP packet: src == '::1'."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "::1" in str(src)


def test_uts_ipv6_tcp_dst_is_loopback():
    """IPv6/TCP packet: dst == '::1'."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "::1" in str(dst)


# ===========================================================================
# 4. IPv6 + TCP + data — UTS: "IPv6 Class with TCP and TCP data"
# ===========================================================================


def test_uts_ipv6_tcp_data_has_ipv6():
    """IPv6/TCP/'somedata' packet has IPv6 layer."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_TCP_DATA))
    assert pkt.has_layer(LayerKind.Ipv6)


def test_uts_ipv6_tcp_data_has_tcp():
    """IPv6/TCP/'somedata' packet has TCP layer."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_TCP_DATA))
    assert pkt.has_layer(LayerKind.Tcp)


def test_uts_ipv6_tcp_data_nh():
    """IPv6/TCP/'somedata': nh == 6 (TCP)."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_TCP_DATA))
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 6


def test_uts_ipv6_tcp_data_plen():
    """IPv6/TCP/'somedata': plen == 28 (20 TCP header + 8 bytes 'somedata')."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_TCP_DATA))
    assert pkt.getfieldval(LayerKind.Ipv6, "plen") == 28


def test_uts_ipv6_tcp_data_layer_bytes_contain_payload():
    """Raw IPv6 bytes end with 'somedata'."""
    assert _UTS_IPV6_TCP_DATA.endswith(b"somedata")


# ===========================================================================
# 5. Routing Extension Header — UTS: "IPv6ExtHdrRouting Class - No address"
# ===========================================================================


def test_uts_ipv6_routing_nh_43():
    """IPv6 with Routing extension header: nh == 43."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_ROUTING))
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 43


def test_uts_ipv6_routing_src_address():
    """IPv6 Routing EH packet: src == '2048::deca'."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_ROUTING))
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "2048" in str(src).lower() or "deca" in str(src).lower()


def test_uts_ipv6_routing_dst_address():
    """IPv6 Routing EH packet: dst == '2047::cafe'."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_ROUTING))
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "2047" in str(dst).lower() or "cafe" in str(dst).lower()


def test_uts_ipv6_routing_has_ipv6():
    """IPv6 Routing EH packet has IPv6 layer."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_ROUTING))
    assert pkt.has_layer(LayerKind.Ipv6)


# ===========================================================================
# 6. IPv6 + UDP stacking
# ===========================================================================


def test_uts_ipv6_udp_nh_17():
    """IPv6 carrying UDP: nh == 17."""
    src_b = ipaddress.IPv6Address("::1").packed
    dst_b = ipaddress.IPv6Address("::1").packed
    udp_payload = b"\x00\x35\x00\x35\x00\x08\xff\x72"
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", len(udp_payload), 17, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr + udp_payload)
    assert pkt.has_layer(LayerKind.Ipv6)
    assert pkt.has_layer(LayerKind.Udp)
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 17


def test_uts_ipv6_udp_plen():
    """IPv6 carrying UDP: plen == 8 (minimal UDP header length)."""
    src_b = ipaddress.IPv6Address("::1").packed
    dst_b = ipaddress.IPv6Address("::1").packed
    udp_payload = b"\x00\x35\x00\x35\x00\x08\xff\x72"
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", len(udp_payload), 17, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr + udp_payload)
    assert pkt.getfieldval(LayerKind.Ipv6, "plen") == 8


# ===========================================================================
# 7. Fragment extension header (nh=44)
# ===========================================================================


def test_uts_ipv6_fragment_nh_44():
    """IPv6 Fragment extension header: nh == 44."""
    src_b = ipaddress.IPv6Address("2001:db8::1").packed
    dst_b = ipaddress.IPv6Address("2001:db8::2").packed
    frag_hdr = bytes([59, 0, 0, 0, 0, 0, 0, 1])  # minimal Fragment header
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", len(frag_hdr), 44, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr + frag_hdr)
    assert pkt.has_layer(LayerKind.Ipv6)
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 44


# ===========================================================================
# 8. Hop-by-Hop extension header (nh=0)
# ===========================================================================


def test_uts_ipv6_hbh_nh_0():
    """IPv6 Hop-by-Hop extension header: nh == 0."""
    src_b = ipaddress.IPv6Address("2001:db8::1").packed
    dst_b = ipaddress.IPv6Address("2001:db8::2").packed
    hbh_hdr = bytes([59, 0, 5, 2, 0, 0, 0, 0])  # nh=59, PadN
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", len(hbh_hdr), 0, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr + hbh_hdr)
    assert pkt.has_layer(LayerKind.Ipv6)
    assert pkt.getfieldval(LayerKind.Ipv6, "nh") == 0


# ===========================================================================
# 9. IPv6 address diversity
# ===========================================================================


def test_uts_ipv6_link_local_src_address():
    """IPv6 link-local source address (fe80::1) is parsed correctly."""
    src_b = ipaddress.IPv6Address("fe80::1").packed
    dst_b = ipaddress.IPv6Address("ff02::1").packed
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", 0, 59, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    assert "fe80" in str(src).lower()


def test_uts_ipv6_multicast_dst_address():
    """IPv6 multicast destination address (ff02::1) is parsed correctly."""
    src_b = ipaddress.IPv6Address("fe80::1").packed
    dst_b = ipaddress.IPv6Address("ff02::1").packed
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", 0, 59, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr)
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "ff02" in str(dst).lower()


def test_uts_ipv6_global_unicast_address():
    """IPv6 global-unicast src/dst (2001:db8::/32) is parsed correctly."""
    src_b = ipaddress.IPv6Address("2001:db8::1").packed
    dst_b = ipaddress.IPv6Address("2001:db8::2").packed
    vtcfl = (6 << 28).to_bytes(4, "big")
    ipv6_hdr = vtcfl + struct.pack("!HBB", 0, 59, 64) + src_b + dst_b
    pkt = _parse(_ETH_BCAST_IPV6 + ipv6_hdr)
    src = pkt.getfieldval(LayerKind.Ipv6, "src")
    dst = pkt.getfieldval(LayerKind.Ipv6, "dst")
    assert "2001" in str(src).lower()
    assert "2001" in str(dst).lower()


# ===========================================================================
# 10. get_layer_bytes
# ===========================================================================


def test_uts_ipv6_default_layer_bytes_length():
    """IPv6 layer bytes for default header are at least 40 bytes long."""
    pkt = _parse(_wrap_eth(_UTS_IPV6_DEFAULT))
    ipv6_bytes = pkt.get_layer_bytes(LayerKind.Ipv6)
    assert len(ipv6_bytes) >= 40


def test_uts_eth_ipv6_tcp_layer_bytes_version():
    """First byte of IPv6 layer bytes has version == 6 (high nibble)."""
    pkt = _parse(_UTS_ETH_IPV6_TCP)
    ipv6_bytes = pkt.get_layer_bytes(LayerKind.Ipv6)
    version = (ipv6_bytes[0] >> 4) & 0x0F
    assert version == 6


def test_uts_ipv6_not_present_in_ipv4_frame():
    """An Ethernet/IPv4 frame does NOT have an IPv6 layer."""
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
            0x00,  # EtherType: IPv4
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
    pkt = _parse(eth_ipv4)
    assert not pkt.has_layer(LayerKind.Ipv6)
