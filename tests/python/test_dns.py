"""Tests for DNS protocol parsing and field access via the Python API."""

import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Packet construction helpers
# ---------------------------------------------------------------------------


def _build_eth_ip_udp(sport: int, dport: int, payload: bytes) -> bytes:
    """Build a raw Ethernet/IPv4/UDP frame wrapping *payload*."""
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len

    # Ethernet header (14 bytes)
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst: broadcast
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,  # src
            0x08,
            0x00,  # EtherType: IPv4
        ]
    )

    # IPv4 header (20 bytes, no options, checksum=0)
    ip = bytes(
        [
            0x45,
            0x00,
            (ip_len >> 8) & 0xFF,
            ip_len & 0xFF,
            0x00,
            0x01,  # ID
            0x40,
            0x00,  # DF flag
            0x40,  # TTL=64
            0x11,  # protocol=UDP
            0x00,
            0x00,  # checksum (not validated by parser)
            192,
            168,
            1,
            1,  # src
            8,
            8,
            8,
            8,  # dst
        ]
    )

    # UDP header (8 bytes)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)

    return eth + ip + udp + payload


def _dns_query(
    qid: int = 0xABCD, name: str = "example.com", rd: bool = True, qtype: int = 1
) -> bytes:
    """Build a minimal DNS query packet."""
    flags = 0x0100 if rd else 0x0000  # QR=0, RD=rd

    # Encode name as DNS labels
    labels = b""
    for part in name.split("."):
        enc = part.encode()
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"

    question = labels + struct.pack("!HH", qtype, 1)  # qtype, qclass=IN
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    return header + question


def _dns_response(
    qid: int = 0xABCD,
    name: str = "example.com",
    answer_ip: tuple = (93, 184, 216, 34),
    ttl: int = 3600,
    rcode: int = 0,
    aa: bool = False,
    ra: bool = True,
) -> bytes:
    """Build a minimal DNS A-record response packet."""
    flags = 0x8000  # QR=1
    if ra:
        flags |= 0x0080
    if aa:
        flags |= 0x0400
    flags |= rcode & 0x0F

    # Encode question name as DNS labels
    labels = b""
    for part in name.split("."):
        enc = part.encode()
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"

    question = labels + struct.pack("!HH", 1, 1)  # A, IN

    # Answer RR: name pointer (0xC00C → offset 12), type=A, class=IN, ttl, rdlength=4
    rdata = bytes(answer_ip)
    answer = (
        struct.pack("!H", 0xC00C)  # name pointer to offset 12
        + struct.pack("!HHiH", 1, 1, ttl, 4)  # type, class, ttl, rdlen
        + rdata
    )

    header = struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0)
    return header + question + answer


def _make_dns_query_pkt(
    name: str = "example.com", qtype: int = 1, qid: int = 0xABCD, rd: bool = True
) -> Packet:
    dns_bytes = _dns_query(qid=qid, name=name, qtype=qtype, rd=rd)
    raw = _build_eth_ip_udp(12345, 53, dns_bytes)
    pkt = Packet(raw)
    pkt.parse()
    return pkt


def _make_dns_response_pkt(
    name: str = "example.com",
    answer_ip: tuple = (93, 184, 216, 34),
    rcode: int = 0,
    aa: bool = False,
    ra: bool = True,
) -> Packet:
    dns_bytes = _dns_response(name=name, answer_ip=answer_ip, rcode=rcode, aa=aa, ra=ra)
    raw = _build_eth_ip_udp(53, 12345, dns_bytes)
    pkt = Packet(raw)
    pkt.parse()
    return pkt


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------


class TestDnsLayerDetection:
    """Verify that DNS is correctly identified when stacked over UDP/53."""

    def test_dns_query_has_dns_layer(self):
        pkt = _make_dns_query_pkt()
        assert pkt.has_layer(LayerKind.Dns)

    def test_dns_response_has_dns_layer(self):
        pkt = _make_dns_response_pkt()
        assert pkt.has_layer(LayerKind.Dns)

    def test_dns_layer_count(self):
        pkt = _make_dns_query_pkt()
        # Ethernet + IPv4 + UDP + DNS = 4
        assert pkt.layer_count == 4

    def test_udp_port_non_53_no_dns(self):
        """UDP packet on port 80 should NOT have a DNS layer."""
        dns_bytes = _dns_query()
        raw = _build_eth_ip_udp(12345, 80, dns_bytes)
        pkt = Packet(raw)
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dns)

    def test_dns_layer_kind_name(self):
        assert LayerKind.Dns.name() == "DNS"

    def test_dns_layer_kind_min_header_size(self):
        assert LayerKind.Dns.min_header_size() == 12  # DNS header is 12 bytes


class TestDnsHeaderFields:
    """Verify DNS header field parsing via attribute access and getfieldval()."""

    def test_query_id(self):
        pkt = _make_dns_query_pkt()
        # Use getfieldval(LayerKind.Dns, 'id') to avoid conflict with IPv4 id
        assert pkt.getfieldval(LayerKind.Dns, "id") == 0xABCD

    def test_query_qr_is_false(self):
        """QR=0 means this is a query."""
        pkt = _make_dns_query_pkt()
        assert pkt.qr is False

    def test_response_qr_is_true(self):
        """QR=1 means this is a response."""
        pkt = _make_dns_response_pkt()
        assert pkt.qr is True

    def test_query_rd_set(self):
        """RD=1: recursion desired."""
        pkt = _make_dns_query_pkt()
        assert pkt.rd is True

    def test_query_rd_not_set(self):
        """Build a query without RD and verify RD=0."""
        pkt = _make_dns_query_pkt(rd=False)
        assert pkt.rd is False

    def test_query_qdcount(self):
        pkt = _make_dns_query_pkt()
        assert pkt.qdcount == 1

    def test_query_ancount_zero(self):
        pkt = _make_dns_query_pkt()
        assert pkt.ancount == 0

    def test_query_nscount_zero(self):
        pkt = _make_dns_query_pkt()
        assert pkt.nscount == 0

    def test_query_arcount_zero(self):
        pkt = _make_dns_query_pkt()
        assert pkt.arcount == 0

    def test_response_ancount(self):
        pkt = _make_dns_response_pkt()
        assert pkt.ancount == 1

    def test_response_qdcount(self):
        pkt = _make_dns_response_pkt()
        assert pkt.qdcount == 1

    def test_opcode_standard_query(self):
        """Standard query has opcode=0."""
        pkt = _make_dns_query_pkt()
        assert pkt.opcode == 0

    def test_rcode_no_error_in_response(self):
        pkt = _make_dns_response_pkt()
        assert pkt.rcode == 0

    def test_aa_not_set_in_query(self):
        pkt = _make_dns_query_pkt()
        assert pkt.aa is False

    def test_tc_not_set(self):
        pkt = _make_dns_query_pkt()
        assert pkt.tc is False

    def test_ra_not_set_in_query(self):
        pkt = _make_dns_query_pkt()
        assert pkt.ra is False

    def test_ra_set_in_response(self):
        pkt = _make_dns_response_pkt(ra=True)
        assert pkt.ra is True

    def test_z_bit_zero(self):
        pkt = _make_dns_query_pkt()
        assert pkt.z is False

    def test_different_query_ids(self):
        for qid in [0x0000, 0x0001, 0xFFFF, 0x1234]:
            pkt = _make_dns_query_pkt(qid=qid)
            assert pkt.getfieldval(LayerKind.Dns, "id") == qid


class TestDnsQueryTypes:
    """Verify that different DNS query types parse correctly."""

    def test_a_query_qtype_1(self):
        pkt = _make_dns_query_pkt(qtype=1)
        assert pkt.has_layer(LayerKind.Dns)
        assert pkt.qdcount == 1

    def test_aaaa_query(self):
        pkt = _make_dns_query_pkt(name="example.com", qtype=28)
        assert pkt.has_layer(LayerKind.Dns)

    def test_mx_query(self):
        pkt = _make_dns_query_pkt(name="example.com", qtype=15)
        assert pkt.has_layer(LayerKind.Dns)

    def test_ns_query(self):
        pkt = _make_dns_query_pkt(name="example.com", qtype=2)
        assert pkt.has_layer(LayerKind.Dns)


class TestDnsRcode:
    """Verify rcode field parsing."""

    def test_nxdomain_response(self):
        """RCODE=3 means NXDOMAIN."""
        pkt = _make_dns_response_pkt(rcode=3)
        assert pkt.has_layer(LayerKind.Dns)
        assert pkt.rcode == 3

    def test_servfail_response(self):
        """RCODE=2 means SERVFAIL."""
        pkt = _make_dns_response_pkt(rcode=2)
        assert pkt.rcode == 2

    def test_refused_response(self):
        """RCODE=5 means REFUSED."""
        pkt = _make_dns_response_pkt(rcode=5)
        assert pkt.rcode == 5


class TestDnsShow:
    """Verify that show() and summary() output include DNS information."""

    def test_show_contains_dns(self):
        pkt = _make_dns_query_pkt()
        output = pkt.show()
        assert "DNS" in output

    def test_show_contains_id_hex(self):
        pkt = _make_dns_query_pkt()
        output = pkt.show()
        # 0xABCD should appear as "abcd" or "43981" in the show output
        assert "abcd" in output.lower() or "43981" in output

    def test_summary_contains_dns(self):
        pkt = _make_dns_query_pkt()
        s = pkt.summary()
        assert "DNS" in s

    def test_query_show_has_qr_field(self):
        pkt = _make_dns_query_pkt()
        output = pkt.show()
        # show() output should contain field names
        assert "id" in output.lower() or "qr" in output.lower()

    def test_response_show_has_ancount(self):
        pkt = _make_dns_response_pkt()
        output = pkt.show()
        assert "ancount" in output.lower() or "an=" in output.lower()


class TestDnsLayerStack:
    """Verify DNS interacts correctly with the rest of the layer stack."""

    def test_dns_with_ethernet_layer(self):
        pkt = _make_dns_query_pkt()
        assert pkt.has_layer(LayerKind.Ethernet)

    def test_dns_with_ipv4_layer(self):
        pkt = _make_dns_query_pkt()
        assert pkt.has_layer(LayerKind.Ipv4)

    def test_dns_with_udp_layer(self):
        pkt = _make_dns_query_pkt()
        assert pkt.has_layer(LayerKind.Udp)

    def test_layers_property_includes_dns(self):
        pkt = _make_dns_query_pkt()
        kinds = [idx.kind for idx in pkt.layers]
        assert LayerKind.Dns in kinds

    def test_dns_layer_index_bounds(self):
        """The DNS layer should start after Ether(14)+IPv4(20)+UDP(8)=42."""
        pkt = _make_dns_query_pkt()
        for idx in pkt.layers:
            if idx.kind == LayerKind.Dns:
                assert idx.start == 42
                assert idx.end > idx.start
                break

    def test_ipv4_src_field_accessible(self):
        """getfieldval() with LayerKind.Ipv4 accesses IPv4 src."""
        pkt = _make_dns_query_pkt()
        src = pkt.getfieldval(LayerKind.Ipv4, "src")
        assert src == "192.168.1.1"

    def test_udp_dport_field_accessible(self):
        """pkt.dport returns the UDP destination port."""
        pkt = _make_dns_query_pkt()
        assert pkt.dport == 53


class TestDnsFieldNames:
    """Verify that DNS field names are available via pkt.fields."""

    def test_fields_includes_id(self):
        pkt = _make_dns_query_pkt()
        assert "id" in pkt.fields

    def test_fields_includes_qr(self):
        pkt = _make_dns_query_pkt()
        assert "qr" in pkt.fields

    def test_fields_includes_opcode(self):
        pkt = _make_dns_query_pkt()
        assert "opcode" in pkt.fields

    def test_fields_includes_counts(self):
        pkt = _make_dns_query_pkt()
        names = pkt.fields
        for f in ("qdcount", "ancount", "nscount", "arcount"):
            assert f in names

    def test_dns_qr_field_access_via_attr(self):
        """DNS-unique field 'qr' is accessible as pkt.qr."""
        pkt = _make_dns_query_pkt()
        assert pkt.qr is False

    def test_dns_id_via_getfieldval(self):
        """DNS 'id' conflicts with IPv4 'id'; use getfieldval for precision."""
        pkt = _make_dns_query_pkt()
        assert pkt.getfieldval(LayerKind.Dns, "id") == 0xABCD


class TestDnsLayerBytes:
    """Verify get_layer_bytes() returns the correct DNS payload."""

    def test_dns_layer_bytes_length(self):
        dns_bytes = _dns_query()
        raw = _build_eth_ip_udp(12345, 53, dns_bytes)
        pkt = Packet(raw)
        pkt.parse()
        layer_bytes = pkt.get_layer_bytes(LayerKind.Dns)
        assert len(layer_bytes) == len(dns_bytes)

    def test_dns_layer_bytes_starts_with_id(self):
        dns_bytes = _dns_query(qid=0x1234)
        raw = _build_eth_ip_udp(12345, 53, dns_bytes)
        pkt = Packet(raw)
        pkt.parse()
        layer_bytes = pkt.get_layer_bytes(LayerKind.Dns)
        # First two bytes are the ID in big-endian
        assert layer_bytes[0] == 0x12
        assert layer_bytes[1] == 0x34


# ---------------------------------------------------------------------------
# Tests using real captured packets from the UTS regression suite
# ---------------------------------------------------------------------------

# Real mDNS response captured from the network (from tests/uts/dns.uts line 72).
# Ethernet/IPv4/UDP(5353)/DNS — QR=1, AA=1, qdcount=0, ancount=3, arcount=4
UTS_MDNS_RESPONSE = (
    b"\x01\x00^\x00\x00\xfb$\xa2\xe1\x90\xa9]\x08\x00E\x00\x01P\\\xdd\x00\x00"
    b"\xff\x11\xbb\x93\xc0\xa8\x00\x88\xe0\x00\x00\xfb\x14\xe9\x14\xe9\x01<*\x81"
    b"\x00\x00\x84\x00\x00\x00\x00\x03\x00\x00\x00\x04"
    b"\x01B\x019\x015\x019\x013\x014\x017\x013\x016\x017\x010\x012\x010\x01D"
    b"\x018\x011\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010\x010"
    b"\x018\x01E\x01F\x03ip6\x04arpa\x00\x00\x0c\x80\x01\x00\x00\x00x\x00\x0f"
    b"\x07Zalmoid\x05local\x00\x011\x01A\x019\x014\x017\x01E\x01A\x014\x01B\x01A"
    b"\x01F\x01B\x012\x011\x014\x010\x010\x016\x01E\x01F\x017\x011\x01F\x012\x015"
    b"\x013\x01E\x010\x011\x010\x01A\x012\xc0L\x00\x0c\x80\x01\x00\x00\x00x\x00"
    b"\x02\xc0`\x03136\x010\x03168\x03192\x07in-addr\xc0P\x00\x0c\x80\x01\x00\x00"
    b"\x00x\x00\x02\xc0`\xc0\x0c\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\x0c\x00"
    b"\x02\x00\x08\xc0o\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0o\x00\x02\x00\x08"
    b"\xc0\xbd\x00/\x80\x01\x00\x00\x00x\x00\x06\xc0\xbd\x00\x02\x00\x08\x00\x00"
    b")\x05\xa0\x00\x00\x11\x94\x00\x12\x00\x04\x00\x0e\x00\xc1&\xa2\xe1\x90\xa9"
    b"]$\xa2\xe1\x90\xa9]"
)


class TestDnsUtsFrames:
    """Tests using real captured packets from the UTS regression suite."""

    def test_uts_mdns_response_has_dns_layer(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.has_layer(LayerKind.Dns)

    def test_uts_mdns_response_layer_count(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        # Ethernet + IPv4 + UDP + DNS = 4
        assert pkt.layer_count == 4

    def test_uts_mdns_has_ethernet(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.has_layer(LayerKind.Ethernet)

    def test_uts_mdns_has_ipv4(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.has_layer(LayerKind.Ipv4)

    def test_uts_mdns_has_udp(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.has_layer(LayerKind.Udp)

    def test_uts_mdns_id_is_zero(self):
        """mDNS responses typically have ID=0."""
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.getfieldval(LayerKind.Dns, "id") == 0

    def test_uts_mdns_qr_is_response(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.qr is True

    def test_uts_mdns_aa_is_set(self):
        """mDNS responses are authoritative."""
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.aa is True

    def test_uts_mdns_qdcount_zero(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.qdcount == 0

    def test_uts_mdns_ancount(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.ancount == 3

    def test_uts_mdns_arcount(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.arcount == 4

    def test_uts_mdns_rcode_zero(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.rcode == 0

    def test_uts_mdns_rd_not_set(self):
        """mDNS responses typically don't have RD set."""
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert pkt.rd is False

    def test_uts_mdns_show_contains_dns(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        output = pkt.show()
        assert "DNS" in output

    def test_uts_mdns_summary_contains_dns(self):
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        assert "DNS" in pkt.summary()

    def test_uts_mdns_dns_layer_starts_at_offset_42(self):
        """DNS layer should start at Ether(14)+IPv4(20)+UDP(8)=42."""
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        for idx in pkt.layers:
            if idx.kind == LayerKind.Dns:
                assert idx.start == 42
                break

    def test_uts_mdns_get_layer_bytes_flags(self):
        """DNS layer bytes at offset 2 should have QR=1, AA=1 (0x84)."""
        pkt = Packet(UTS_MDNS_RESPONSE)
        pkt.parse()
        dns_bytes = pkt.get_layer_bytes(LayerKind.Dns)
        assert dns_bytes[0] == 0x00  # ID high
        assert dns_bytes[1] == 0x00  # ID low
        assert dns_bytes[2] == 0x84  # flags high: QR=1, AA=1

    # UTS DNS simple request: raw(DNS()) ==
    # b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00
    #   \x03www\x07example\x03com\x00\x00\x01\x00\x01'
    UTS_DNS_SIMPLE_REQUEST = (
        b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    )

    def test_uts_simple_request_via_udp53(self):
        """Wrap the UTS simple DNS request in Ether/IP/UDP(53) and parse."""
        raw = _build_eth_ip_udp(12345, 53, self.UTS_DNS_SIMPLE_REQUEST)
        pkt = Packet(raw)
        pkt.parse()
        assert pkt.has_layer(LayerKind.Dns)

    def test_uts_simple_request_id(self):
        raw = _build_eth_ip_udp(12345, 53, self.UTS_DNS_SIMPLE_REQUEST)
        pkt = Packet(raw)
        pkt.parse()
        assert pkt.getfieldval(LayerKind.Dns, "id") == 0

    def test_uts_simple_request_rd_set(self):
        """Default DNS() has RD=1 (flags byte 0x01 0x00)."""
        raw = _build_eth_ip_udp(12345, 53, self.UTS_DNS_SIMPLE_REQUEST)
        pkt = Packet(raw)
        pkt.parse()
        assert pkt.rd is True

    def test_uts_simple_request_qdcount(self):
        raw = _build_eth_ip_udp(12345, 53, self.UTS_DNS_SIMPLE_REQUEST)
        pkt = Packet(raw)
        pkt.parse()
        assert pkt.qdcount == 1

    def test_uts_simple_request_qr_is_query(self):
        raw = _build_eth_ip_udp(12345, 53, self.UTS_DNS_SIMPLE_REQUEST)
        pkt = Packet(raw)
        pkt.parse()
        assert pkt.qr is False
