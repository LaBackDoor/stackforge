"""UTS-driven DHCP tests.

Translates assertions from tests/uts/dhcp.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw DHCP bytes
must be wrapped in an Ethernet/IPv4/UDP frame before parsing.
"""

import socket
import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_udp(payload: bytes, sport: int = 68, dport: int = 67) -> bytes:
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
        0x00000000,
        0xFFFFFFFF,
    )
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + payload


MAGIC_COOKIE = bytes([99, 130, 83, 99])


def _bootp_header(
    op=1,
    htype=1,
    hlen=6,
    hops=0,
    xid=0,
    secs=0,
    flags=0,
    ciaddr="0.0.0.0",
    yiaddr="0.0.0.0",
    siaddr="0.0.0.0",
    giaddr="0.0.0.0",
    chaddr=b"\x00" * 16,
):
    """Build a 236-byte BOOTP header."""
    hdr = struct.pack("!BBBB", op, htype, hlen, hops)
    hdr += struct.pack("!I", xid)
    hdr += struct.pack("!HH", secs, flags)
    hdr += socket.inet_aton(ciaddr)
    hdr += socket.inet_aton(yiaddr)
    hdr += socket.inet_aton(siaddr)
    hdr += socket.inet_aton(giaddr)
    if len(chaddr) < 16:
        chaddr = chaddr + b"\x00" * (16 - len(chaddr))
    hdr += chaddr[:16]
    hdr += b"\x00" * 64  # sname
    hdr += b"\x00" * 128  # file
    return hdr


def _opt(code, data=b""):
    """Build a single TLV option."""
    if code in (0, 255):
        return bytes([code])
    return bytes([code, len(data)]) + data


def _parse(raw: bytes) -> Packet:
    pkt = Packet(raw)
    pkt.parse()
    return pkt


# ---------------------------------------------------------------------------
# UTS: BOOTP basic
# ---------------------------------------------------------------------------


def test_uts_bootp_op_request():
    """BOOTP op=1 is a request."""
    dhcp = _bootp_header(op=1) + MAGIC_COOKIE + _opt(255)
    pkt = _parse(_build_eth_ipv4_udp(dhcp))
    assert pkt.op == 1


def test_uts_bootp_op_reply():
    """BOOTP op=2 is a reply."""
    dhcp = _bootp_header(op=2) + MAGIC_COOKIE + _opt(255)
    pkt = _parse(_build_eth_ipv4_udp(dhcp, sport=67, dport=68))
    assert pkt.op == 2


def test_uts_bootp_xid():
    """Transaction ID preserved."""
    dhcp = _bootp_header(xid=0xAABBCCDD) + MAGIC_COOKIE + _opt(255)
    pkt = _parse(_build_eth_ipv4_udp(dhcp))
    assert pkt.xid == 0xAABBCCDD


def test_uts_bootp_chaddr():
    """Client hardware address parsed."""
    mac = b"\x00\x01\x02\x03\x04\x05"
    chaddr = mac + b"\x00" * 10
    dhcp = _bootp_header(chaddr=chaddr) + MAGIC_COOKIE + _opt(255)
    pkt = _parse(_build_eth_ipv4_udp(dhcp))
    assert pkt.chaddr is not None


# ---------------------------------------------------------------------------
# UTS: DHCP build — message type
# ---------------------------------------------------------------------------


def test_uts_dhcp_discover():
    """Scapy: DHCP(options=[("message-type","discover"),"end"])."""
    mac = b"\x00\x01\x02\x03\x04\x05"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, htype=1, hlen=6, chaddr=chaddr)
    opts = _opt(53, bytes([1])) + _opt(255)  # message-type=discover + end
    dhcp_payload = bootp + MAGIC_COOKIE + opts

    raw = _build_eth_ipv4_udp(dhcp_payload)
    pkt = _parse(raw)

    assert pkt.has_layer(LayerKind.Dhcp)
    assert pkt.msg_type == 1
    # Verify magic cookie is present in layer bytes
    layer_bytes = pkt.get_layer_bytes(LayerKind.Dhcp)
    assert layer_bytes[236:240] == MAGIC_COOKIE


def test_uts_dhcp_offer():
    """Message type = Offer (2)."""
    mac = b"\x05\x04\x03\x02\x01\x00"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(
        op=2,
        chaddr=chaddr,
        yiaddr="192.168.1.100",
        siaddr="192.168.1.1",
    )
    opts = _opt(53, bytes([2])) + _opt(54, socket.inet_aton("192.168.1.1")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.msg_type == 2
    assert pkt.yiaddr == "192.168.1.100"
    assert pkt.server_id == "192.168.1.1"


def test_uts_dhcp_request():
    """Message type = Request (3) with requested_addr."""
    mac = b"\x00\x01\x02\x03\x04\x05"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, flags=0x8000, chaddr=chaddr)
    opts = (
        _opt(53, bytes([3]))
        + _opt(50, socket.inet_aton("192.168.0.1"))
        + _opt(54, socket.inet_aton("192.168.0.254"))
        + _opt(255)
    )
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)

    assert pkt.msg_type == 3
    assert pkt.requested_ip == "192.168.0.1"
    assert pkt.server_id == "192.168.0.254"


def test_uts_dhcp_ack():
    """Message type = ACK (5)."""
    mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(
        op=2,
        xid=0x11223344,
        chaddr=chaddr,
        yiaddr="10.0.0.50",
        siaddr="10.0.0.1",
    )
    opts = (
        _opt(53, bytes([5]))
        + _opt(54, socket.inet_aton("10.0.0.1"))
        + _opt(51, struct.pack("!I", 86400))
        + _opt(255)
    )
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.msg_type == 5
    assert pkt.lease_time == 86400
    assert pkt.server_id == "10.0.0.1"


def test_uts_dhcp_nak():
    """Message type = NAK (6)."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([6])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.msg_type == 6


def test_uts_dhcp_release():
    """Message type = Release (7)."""
    mac = b"\x00\x11\x22\x33\x44\x55"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr, ciaddr="192.168.1.100")
    opts = _opt(53, bytes([7])) + _opt(54, socket.inet_aton("192.168.1.1")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)

    assert pkt.msg_type == 7
    assert pkt.ciaddr == "192.168.1.100"


def test_uts_dhcp_inform():
    """Message type = Inform (8)."""
    mac = b"\x00\x11\x22\x33\x44\x55"
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr, ciaddr="192.168.1.100")
    opts = _opt(53, bytes([8])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)

    assert pkt.msg_type == 8


# ---------------------------------------------------------------------------
# UTS: DHCP options
# ---------------------------------------------------------------------------


def test_uts_dhcp_subnet_mask():
    """Option 1: subnet mask."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([5])) + _opt(1, socket.inet_aton("255.255.255.0")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.subnet_mask == "255.255.255.0"


def test_uts_dhcp_router():
    """Option 3: router."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([5])) + _opt(3, socket.inet_aton("192.168.1.1")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.router == "192.168.1.1"


def test_uts_dhcp_dns():
    """Option 6: DNS servers."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    dns_data = socket.inet_aton("8.8.8.8") + socket.inet_aton("8.8.4.4")
    opts = _opt(53, bytes([5])) + _opt(6, dns_data) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    dns_val = str(pkt.dns)
    assert "8.8.8.8" in dns_val
    assert "8.8.4.4" in dns_val


def test_uts_dhcp_lease_time():
    """Option 51: lease time."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([5])) + _opt(51, struct.pack("!I", 7200)) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.lease_time == 7200


def test_uts_dhcp_requested_addr():
    """Option 50: requested IP address."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr)
    opts = _opt(53, bytes([3])) + _opt(50, socket.inet_aton("192.168.0.1")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)

    assert pkt.requested_ip == "192.168.0.1"


def test_uts_dhcp_server_id():
    """Option 54: server identifier."""
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([5])) + _opt(54, socket.inet_aton("10.0.0.1")) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)

    assert pkt.server_id == "10.0.0.1"


# ---------------------------------------------------------------------------
# UTS: DHCP summary
# ---------------------------------------------------------------------------


def test_uts_summary_discover():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr)
    opts = _opt(53, bytes([1])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)
    assert "DHCP Discover" in pkt.summary()


def test_uts_summary_offer():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([2])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)
    assert "DHCP Offer" in pkt.summary()


def test_uts_summary_request():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr)
    opts = _opt(53, bytes([3])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)
    assert "DHCP Request" in pkt.summary()


def test_uts_summary_ack():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([5])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)
    assert "DHCP ACK" in pkt.summary()


def test_uts_summary_nak():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=2, chaddr=chaddr)
    opts = _opt(53, bytes([6])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
    pkt = _parse(raw)
    assert "DHCP NAK" in pkt.summary()


def test_uts_summary_release():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr)
    opts = _opt(53, bytes([7])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)
    assert "DHCP Release" in pkt.summary()


def test_uts_summary_inform():
    mac = b"\x00" * 6
    chaddr = mac + b"\x00" * 10
    bootp = _bootp_header(op=1, chaddr=chaddr)
    opts = _opt(53, bytes([8])) + _opt(255)
    raw = _build_eth_ipv4_udp(bootp + MAGIC_COOKIE + opts)
    pkt = _parse(raw)
    assert "DHCP Inform" in pkt.summary()
