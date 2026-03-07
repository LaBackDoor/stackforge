"""Tests for the DHCP (Dynamic Host Configuration Protocol) layer implementation.

Tests validate parsing, field access, and DHCP options for packets
wrapped in Ethernet/IPv4/UDP frames on ports 67/68.
"""

import struct

from stackforge import LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def _build_bootp_header(
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
    sname=b"\x00" * 64,
    file=b"\x00" * 128,
):
    """Build a 236-byte BOOTP header."""
    import socket

    header = struct.pack("!BBBB", op, htype, hlen, hops)
    header += struct.pack("!I", xid)
    header += struct.pack("!HH", secs, flags)
    header += socket.inet_aton(ciaddr)
    header += socket.inet_aton(yiaddr)
    header += socket.inet_aton(siaddr)
    header += socket.inet_aton(giaddr)
    if isinstance(chaddr, (list, tuple)):
        chaddr = bytes(chaddr) + b"\x00" * (16 - len(chaddr))
    header += chaddr[:16]
    header += sname[:64]
    header += file[:128]
    return header


MAGIC_COOKIE = bytes([99, 130, 83, 99])


def _build_dhcp_options(*options):
    """Build DHCP options bytes. Each option is (code, data_bytes).
    Special: 255 = END, 0 = PAD (no length)."""
    result = b""
    for opt in options:
        if isinstance(opt, int):
            result += bytes([opt])
        else:
            code, data = opt
            if code in (0, 255):
                result += bytes([code])
            else:
                result += bytes([code, len(data)]) + data
    return result


def _build_dhcp_discover(mac_bytes, xid=0x12345678):
    """Build a complete DHCP Discover payload."""
    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    bootp = _build_bootp_header(op=1, xid=xid, flags=0x8000, chaddr=chaddr)
    opts = _build_dhcp_options(
        (53, bytes([1])),  # Message Type: Discover
        255,  # END
    )
    return bootp + MAGIC_COOKIE + opts


def _build_dhcp_offer(mac_bytes, xid, yiaddr, siaddr, lease_time=3600):
    """Build a complete DHCP Offer payload."""
    import socket

    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    bootp = _build_bootp_header(op=2, xid=xid, yiaddr=yiaddr, siaddr=siaddr, chaddr=chaddr)
    opts = _build_dhcp_options(
        (53, bytes([2])),  # Message Type: Offer
        (54, socket.inet_aton(siaddr)),  # Server ID
        (51, struct.pack("!I", lease_time)),  # Lease Time
        (1, socket.inet_aton("255.255.255.0")),  # Subnet Mask
        (3, socket.inet_aton(siaddr)),  # Router
        (6, socket.inet_aton("8.8.8.8")),  # DNS
        255,  # END
    )
    return bootp + MAGIC_COOKIE + opts


def _build_dhcp_request(mac_bytes, xid, requested_ip, server_ip):
    """Build a complete DHCP Request payload."""
    import socket

    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    bootp = _build_bootp_header(op=1, xid=xid, flags=0x8000, chaddr=chaddr)
    opts = _build_dhcp_options(
        (53, bytes([3])),  # Message Type: Request
        (50, socket.inet_aton(requested_ip)),  # Requested IP
        (54, socket.inet_aton(server_ip)),  # Server ID
        255,  # END
    )
    return bootp + MAGIC_COOKIE + opts


def _build_dhcp_ack(mac_bytes, xid, yiaddr, siaddr, lease_time=3600):
    """Build a complete DHCP ACK payload."""
    import socket

    chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    bootp = _build_bootp_header(op=2, xid=xid, yiaddr=yiaddr, siaddr=siaddr, chaddr=chaddr)
    opts = _build_dhcp_options(
        (53, bytes([5])),  # Message Type: ACK
        (54, socket.inet_aton(siaddr)),  # Server ID
        (51, struct.pack("!I", lease_time)),  # Lease Time
        (1, socket.inet_aton("255.255.255.0")),  # Subnet Mask
        (3, socket.inet_aton(siaddr)),  # Router
        (6, socket.inet_aton("8.8.8.8") + socket.inet_aton("8.8.4.4")),  # DNS
        255,  # END
    )
    return bootp + MAGIC_COOKIE + opts


def _wrap_in_eth_ip_udp(dhcp_payload, sport=68, dport=67):
    """Wrap DHCP payload in Ethernet/IPv4/UDP frame."""
    udp_len = 8 + len(dhcp_payload)
    ip_total = 20 + udp_len

    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst MAC (broadcast)
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
        0,  # proto=UDP
        0x00000000,  # src: 0.0.0.0
        0xFFFFFFFF,  # dst: 255.255.255.255
    )
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + dhcp_payload


def _parse(raw_bytes):
    """Create and parse a Packet from raw bytes."""
    pkt = Packet(raw_bytes)
    pkt.parse()
    return pkt


# ============================================================================
# DHCP Layer Detection
# ============================================================================


class TestDhcpDetection:
    """Test that DHCP packets on ports 67/68 are correctly detected."""

    def test_discover_detected(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp, sport=68, dport=67)
        pkt = _parse(raw)
        assert pkt.has_layer(LayerKind.Dhcp)

    def test_offer_detected(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 0x12345678, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.has_layer(LayerKind.Dhcp)

    def test_non_dhcp_udp_not_detected(self):
        """UDP on port 9999 should not be detected as DHCP."""
        payload = b"\x00" * 300
        udp_len = 8 + len(payload)
        ip_total = 20 + udp_len
        eth = bytes([0xFF] * 6 + [0x00] * 6 + [0x08, 0x00])
        ip = struct.pack("!BBHHHBBHII", 0x45, 0, ip_total, 1, 0, 64, 17, 0, 0x7F000001, 0x7F000001)
        udp = struct.pack("!HHHH", 9999, 9999, udp_len, 0)
        pkt = _parse(eth + ip + udp + payload)
        assert not pkt.has_layer(LayerKind.Dhcp)


# ============================================================================
# BOOTP Header Fields
# ============================================================================


class TestBootpFields:
    """Test BOOTP header field access via pkt.fieldname."""

    def _make_discover(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac, xid=0xDEADBEEF)
        raw = _wrap_in_eth_ip_udp(dhcp)
        return _parse(raw)

    def test_op(self):
        pkt = self._make_discover()
        assert pkt.op == 1

    def test_htype(self):
        pkt = self._make_discover()
        assert pkt.htype == 1

    def test_hlen(self):
        pkt = self._make_discover()
        assert pkt.hlen == 6

    def test_hops(self):
        pkt = self._make_discover()
        assert pkt.hops == 0

    def test_xid(self):
        pkt = self._make_discover()
        assert pkt.xid == 0xDEADBEEF

    def test_secs(self):
        pkt = self._make_discover()
        assert pkt.secs == 0

    def test_flags(self):
        pkt = self._make_discover()
        # Use getfieldval since 'flags' exists in both IPv4 and DHCP layers
        assert pkt.getfieldval(LayerKind.Dhcp, "flags") == 0x8000

    def test_ciaddr(self):
        pkt = self._make_discover()
        assert pkt.ciaddr == "0.0.0.0"

    def test_yiaddr(self):
        pkt = self._make_discover()
        assert pkt.yiaddr == "0.0.0.0"

    def test_siaddr(self):
        pkt = self._make_discover()
        assert pkt.siaddr == "0.0.0.0"

    def test_giaddr(self):
        pkt = self._make_discover()
        assert pkt.giaddr == "0.0.0.0"

    def test_chaddr(self):
        pkt = self._make_discover()
        chaddr = pkt.chaddr
        assert chaddr is not None


# ============================================================================
# DHCP Options
# ============================================================================


class TestDhcpOptions:
    """Test DHCP option field access."""

    def test_msg_type_discover(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.msg_type == 1

    def test_msg_type_offer(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 0x12345678, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.msg_type == 2

    def test_msg_type_request(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_request(mac, 0xAABBCCDD, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.msg_type == 3

    def test_msg_type_ack(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_ack(mac, 0xAABBCCDD, "10.0.0.50", "10.0.0.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.msg_type == 5

    def test_server_id(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 0x12345678, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.server_id == "192.168.1.1"

    def test_requested_ip(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_request(mac, 0xAABBCCDD, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.requested_ip == "192.168.1.100"

    def test_lease_time(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 1, "192.168.1.100", "192.168.1.1", lease_time=7200)
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.lease_time == 7200

    def test_subnet_mask(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 1, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.subnet_mask == "255.255.255.0"

    def test_router(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 1, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert pkt.router == "192.168.1.1"

    def test_dns(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 1, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        dns = pkt.dns
        assert dns is not None
        assert "8.8.8.8" in str(dns)


# ============================================================================
# getfieldval
# ============================================================================


class TestGetfieldval:
    """Test getfieldval with layer-specific field access."""

    def test_dhcp_msg_type(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.getfieldval(LayerKind.Dhcp, "msg_type") == 1

    def test_dhcp_xid(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac, xid=0xCAFEBABE)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.getfieldval(LayerKind.Dhcp, "xid") == 0xCAFEBABE

    def test_dhcp_op(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        assert pkt.getfieldval(LayerKind.Dhcp, "op") == 1


# ============================================================================
# Summary
# ============================================================================


class TestSummary:
    """Test packet summary output."""

    def test_discover_summary(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        summary = pkt.summary()
        assert "DHCP Discover" in summary

    def test_offer_summary(self):
        mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        dhcp = _build_dhcp_offer(mac, 1, "192.168.1.100", "192.168.1.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert "DHCP Offer" in pkt.summary()

    def test_ack_summary(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_ack(mac, 1, "10.0.0.50", "10.0.0.1")
        raw = _wrap_in_eth_ip_udp(dhcp, sport=67, dport=68)
        pkt = _parse(raw)
        assert "DHCP ACK" in pkt.summary()


# ============================================================================
# Fields property
# ============================================================================


class TestFields:
    """Test the fields property for DHCP packets."""

    def test_fields_contains_dhcp_fields(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        fields = pkt.fields
        assert "op" in fields
        assert "xid" in fields
        assert "msg_type" in fields
        assert "chaddr" in fields


# ============================================================================
# Layer bytes
# ============================================================================


class TestLayerBytes:
    """Test get_layer_bytes for DHCP."""

    def test_dhcp_layer_bytes(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        dhcp = _build_dhcp_discover(mac)
        raw = _wrap_in_eth_ip_udp(dhcp)
        pkt = _parse(raw)
        layer_bytes = pkt.get_layer_bytes(LayerKind.Dhcp)
        assert layer_bytes is not None
        assert len(layer_bytes) > 240
        # Verify magic cookie in DHCP layer bytes
        assert layer_bytes[236:240] == MAGIC_COOKIE


# ============================================================================
# Full DHCP Handshake
# ============================================================================


class TestDhcpHandshake:
    """Test a complete DORA (Discover-Offer-Request-ACK) handshake."""

    def test_dora_sequence(self):
        mac = b"\x00\x11\x22\x33\x44\x55"
        xid = 0xAABBCCDD

        # 1. Discover
        discover = _build_dhcp_discover(mac, xid)
        pkt1 = _parse(_wrap_in_eth_ip_udp(discover, sport=68, dport=67))
        assert pkt1.msg_type == 1
        assert pkt1.xid == xid

        # 2. Offer
        offer = _build_dhcp_offer(mac, xid, "192.168.1.100", "192.168.1.1")
        pkt2 = _parse(_wrap_in_eth_ip_udp(offer, sport=67, dport=68))
        assert pkt2.msg_type == 2
        assert pkt2.xid == xid
        assert pkt2.yiaddr == "192.168.1.100"

        # 3. Request
        request = _build_dhcp_request(mac, xid, "192.168.1.100", "192.168.1.1")
        pkt3 = _parse(_wrap_in_eth_ip_udp(request, sport=68, dport=67))
        assert pkt3.msg_type == 3
        assert pkt3.requested_ip == "192.168.1.100"

        # 4. ACK
        ack = _build_dhcp_ack(mac, xid, "192.168.1.100", "192.168.1.1", lease_time=86400)
        pkt4 = _parse(_wrap_in_eth_ip_udp(ack, sport=67, dport=68))
        assert pkt4.msg_type == 5
        assert pkt4.yiaddr == "192.168.1.100"
        assert pkt4.lease_time == 86400


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_min_bootp_with_cookie(self):
        """Minimal DHCP packet: 236 BOOTP + 4 cookie + END."""
        bootp = _build_bootp_header()
        raw = _wrap_in_eth_ip_udp(bootp + MAGIC_COOKIE + bytes([255]))
        pkt = _parse(raw)
        assert pkt.has_layer(LayerKind.Dhcp)

    def test_multiple_dns_servers(self):
        """Test DHCP with multiple DNS servers in single option."""
        import socket

        mac = b"\x00\x11\x22\x33\x44\x55"
        chaddr = mac + b"\x00" * 10
        bootp = _build_bootp_header(
            op=2, xid=1, yiaddr="10.0.0.50", siaddr="10.0.0.1", chaddr=chaddr
        )
        dns_data = (
            socket.inet_aton("8.8.8.8") + socket.inet_aton("8.8.4.4") + socket.inet_aton("1.1.1.1")
        )
        opts = _build_dhcp_options(
            (53, bytes([5])),  # ACK
            (6, dns_data),  # DNS servers
            255,
        )
        raw = _wrap_in_eth_ip_udp(bootp + MAGIC_COOKIE + opts, sport=67, dport=68)
        pkt = _parse(raw)
        dns_val = pkt.dns
        assert dns_val is not None
        dns_str = str(dns_val)
        assert "8.8.8.8" in dns_str
        assert "8.8.4.4" in dns_str
        assert "1.1.1.1" in dns_str
