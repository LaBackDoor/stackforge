"""UTS-driven QUIC tests.

These tests use the exact byte sequences from tests/uts/quic.uts and validate
field access against the expected values from that Scapy reference test suite.

Since Packet.parse() always assumes Ethernet as the first layer, raw QUIC bytes
must be wrapped in an Ethernet/IPv4/UDP frame before parsing.  The helper
_wrap_quic() constructs a minimal such frame.
"""

import struct

import pytest
from stackforge import QUIC, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_udp(quic_bytes: bytes, dport: int = 443) -> bytes:
    """Build a minimal Ethernet/IPv4/UDP frame carrying the given QUIC payload."""
    udp_len = 8 + len(quic_bytes)
    ip_len = 20 + udp_len

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
    ip = bytes(
        [
            0x45,
            0x00,  # version/IHL, DSCP/ECN
            (ip_len >> 8) & 0xFF,
            ip_len & 0xFF,  # total length
            0x00,
            0x01,  # identification
            0x40,
            0x00,  # DF, fragment offset
            0x40,  # TTL = 64
            0x11,  # protocol = UDP
            0x00,
            0x00,  # checksum (unused)
            10,
            0,
            0,
            1,  # src IP
            10,
            0,
            0,
            2,  # dst IP
        ]
    )
    udp = struct.pack("!HHHH", 12345, dport, udp_len, 0)
    return eth + ip + udp + quic_bytes


def _parse_quic(quic_bytes: bytes, dport: int = 443) -> Packet:
    """Wrap raw QUIC bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_udp(quic_bytes, dport)
    pkt = Packet(frame + quic_bytes)
    pkt.parse()
    return pkt


def _field(pkt: Packet, name: str):
    """Shorthand for pkt.getfieldval(LayerKind.Quic, name)."""
    return pkt.getfieldval(LayerKind.Quic, name)


# ---------------------------------------------------------------------------
# UTS test data (from tests/uts/quic.uts)
# ---------------------------------------------------------------------------

# Client Initial Packet (quic.uts line 12)
_CLIENT_INITIAL_BYTES = bytes.fromhex(
    "c00000000108000102030405060705635f636964004103001c36a7ed78716be9711ba498b7ed868443bb2e"
    "0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7"
    "f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab385"
    "8a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3b"
    "c787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd09"
    "55e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d403"
    "2170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099"
)

# Server Initial Packet (quic.uts line 25)
_SERVER_INITIAL_BYTES = bytes.fromhex(
    "c00000000105635f63696405735f63696400407500836855d5d9c823d07c616882ca770279249864b556e5"
    "1632257e2d8ab1fd0dc04b18b9203fb919d8ef5a33f378a627db674d3c7fce6ca5bb3e8cf90109cbb9556"
    "65fc1a4b93d05f6eb83252f6631bcadc7402c10f65c52ed15b4429c9f64d84d64fa406cf0b517a926d62a"
    "54a9294136b143b033"
)

# Server Handshake Packet (quic.uts line 38)
_SERVER_HANDSHAKE_BYTES = bytes.fromhex(
    "e00000000105635f63696405735f63696440cf014420f919681c3f0f102a30f5e647a3399abf54bc8e804"
    "53134996ba33099056242f3b8e662bbfce42f3ef2b6ba87159147489f8479e849284e983fd905320a62fc"
    "7d67e9587797096ca60101d0b2685d8747811178133ad9172b7ff8ea83fd81a814bae27b953a97d57ebff"
    "4b4710dba8df82a6b49d7d7fa3d8179cbdb8683d4bfa832645401e5a56a76535f71c6fb3e616c241bb1f4"
    "3bc147c296f591402997ed49aa0c55e31721d03e14114af2dc458ae03944de5126fe08d66a6ef3ba2ed10"
    "25f98fea6d6024998184687dc06"
)

# Build test packet from quic.uts line 50:
# QUIC_Initial(DstConnID=..., SrcConnID=..., PacketNumber=0xFF)
# => b'\xc0\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR'
# =>   b'\x03\xf7\x10Q\x00\x00\xff'
_BUILD_TEST_BYTES = (
    b"\xc0\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR"
    b"\x03\xf7\x10Q\x00\x00\xff"
)


# ---------------------------------------------------------------------------
# UTS Test 1: Dissect Client Initial Packet (quic.uts lines 8-19)
# ---------------------------------------------------------------------------


class TestClientInitialPacket:
    """Validates fields from quic.uts 'Dissect Client Initial Packet'."""

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(_CLIENT_INITIAL_BYTES)

    def test_has_quic_layer(self, pkt):
        assert pkt.has_layer(LayerKind.Quic)

    def test_long_packet_type_is_initial(self, pkt):
        """LongPacketType == 0 (Initial)."""
        assert _field(pkt, "long_packet_type") == 0

    def test_dst_conn_id(self, pkt):
        """DstConnID == b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"."""
        assert _field(pkt, "dst_conn_id") == b"\x00\x01\x02\x03\x04\x05\x06\x07"

    def test_dst_conn_id_len(self, pkt):
        assert _field(pkt, "dst_conn_id_len") == 8

    def test_src_conn_id(self, pkt):
        """SrcConnID == b"c_cid"."""
        assert _field(pkt, "src_conn_id") == b"c_cid"

    def test_src_conn_id_len(self, pkt):
        assert _field(pkt, "src_conn_id_len") == 5

    def test_version(self, pkt):
        """QUIC version == 1 (0x00000001)."""
        assert _field(pkt, "version") == 1

    def test_length(self, pkt):
        """Length == 259."""
        assert _field(pkt, "length") == 259

    def test_packet_number(self, pkt):
        """PacketNumber == 0."""
        assert _field(pkt, "packet_number") == 0

    def test_header_form_is_long(self, pkt):
        assert _field(pkt, "header_form") == 1

    def test_fixed_bit(self, pkt):
        assert _field(pkt, "fixed_bit") == 1

    def test_packet_number_len_is_zero(self, pkt):
        """packet_number_len bits (1-0 of byte 0) == 0 (encodes 1-byte PN)."""
        assert _field(pkt, "packet_number_len") == 0


# ---------------------------------------------------------------------------
# UTS Test 2: Dissect Server Initial Packet (quic.uts lines 21-32)
# ---------------------------------------------------------------------------


class TestServerInitialPacket:
    """Validates fields from quic.uts 'Dissect Server Initial Packet'."""

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(_SERVER_INITIAL_BYTES)

    def test_has_quic_layer(self, pkt):
        assert pkt.has_layer(LayerKind.Quic)

    def test_long_packet_type_is_initial(self, pkt):
        """LongPacketType == 0 (Initial)."""
        assert _field(pkt, "long_packet_type") == 0

    def test_dst_conn_id(self, pkt):
        """DstConnID == b"c_cid"."""
        assert _field(pkt, "dst_conn_id") == b"c_cid"

    def test_src_conn_id(self, pkt):
        """SrcConnID == b"s_cid"."""
        assert _field(pkt, "src_conn_id") == b"s_cid"

    def test_length(self, pkt):
        """Length == 117."""
        assert _field(pkt, "length") == 117

    def test_packet_number(self, pkt):
        """PacketNumber == 0."""
        assert _field(pkt, "packet_number") == 0

    def test_version(self, pkt):
        assert _field(pkt, "version") == 1


# ---------------------------------------------------------------------------
# UTS Test 3: Dissect Server Handshake Packet (quic.uts lines 34-43)
# ---------------------------------------------------------------------------


class TestServerHandshakePacket:
    """Validates fields from quic.uts 'Dissect Server Handshake Packet'."""

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(_SERVER_HANDSHAKE_BYTES)

    def test_has_quic_layer(self, pkt):
        assert pkt.has_layer(LayerKind.Quic)

    def test_long_packet_type_is_handshake(self, pkt):
        """LongPacketType == 2 (Handshake; 0xe0 -> bits 5-4 = 0b10)."""
        assert _field(pkt, "long_packet_type") == 2

    def test_dst_conn_id(self, pkt):
        """DstConnID == b"c_cid"."""
        assert _field(pkt, "dst_conn_id") == b"c_cid"

    def test_src_conn_id(self, pkt):
        """SrcConnID == b"s_cid"."""
        assert _field(pkt, "src_conn_id") == b"s_cid"

    def test_packet_number(self, pkt):
        """PacketNumber == 1."""
        assert _field(pkt, "packet_number") == 1

    def test_version(self, pkt):
        assert _field(pkt, "version") == 1

    def test_header_form(self, pkt):
        assert _field(pkt, "header_form") == 1


# ---------------------------------------------------------------------------
# UTS Test 4: QuicPacketNumberField variable lengths (quic.uts lines 45-73)
# Validates the exact wire bytes from the UTS build test and field access.
# ---------------------------------------------------------------------------


class TestBuildPacket1BytePN:
    """quic.uts lines 49-55: parse exact Scapy-produced bytes and check fields.

    Scapy's QUIC_Initial(DstConnID=..., SrcConnID=..., PacketNumber=0xFF) produces
    wire bytes with Length=0 (Scapy does not auto-compute the length).  Our parser
    correctly reads DstConnIDLen, SrcConnIDLen, PacketNumberLen, and PacketNumber
    from those bytes regardless.
    """

    @pytest.fixture(scope="class")
    def pkt(self):
        # Use the exact UTS bytes (Scapy output with Length=0)
        return _parse_quic(_BUILD_TEST_BYTES)

    def test_has_quic_layer(self, pkt):
        assert pkt.has_layer(LayerKind.Quic)

    def test_dst_conn_id_len(self, pkt):
        """DstConnIDLen == 15."""
        assert _field(pkt, "dst_conn_id_len") == 15

    def test_src_conn_id_len(self, pkt):
        """SrcConnIDLen == 3."""
        assert _field(pkt, "src_conn_id_len") == 3

    def test_packet_number_len(self, pkt):
        """PacketNumberLen == 0 (means 1-byte packet number)."""
        assert _field(pkt, "packet_number_len") == 0

    def test_packet_number(self, pkt):
        """PacketNumber == 0xFF = 255."""
        assert _field(pkt, "packet_number") == 0xFF

    def test_long_packet_type(self, pkt):
        assert _field(pkt, "long_packet_type") == 0  # Initial

    def test_version(self, pkt):
        assert _field(pkt, "version") == 1


class TestBuildPacket2BytePN:
    """quic.uts lines 57-61: Scapy bytes with 2-byte PN -> PacketNumberLen=1.

    Scapy produces length=0 in the wire bytes (it does not auto-compute length).
    We parse the exact Scapy bytes and verify PacketNumberLen and PacketNumber.
    We also verify our builder encodes 2-byte PNs with the correct first byte.
    """

    # Exact Scapy-produced bytes from quic.uts line 58
    _UTS_BYTES = (
        b"\xc1\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR"
        b"\x03\xf7\x10Q\x00\x00\xff\xff"
    )

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(self._UTS_BYTES)

    def test_first_byte_pn_len_field(self):
        """First byte encodes packet_number_len=1 (0xc1 & 0x03 == 1)."""
        assert self._UTS_BYTES[0] & 0x03 == 1

    def test_packet_number_len_is_1(self, pkt):
        """PacketNumberLen == 1 for 2-byte packet number."""
        assert _field(pkt, "packet_number_len") == 1

    def test_packet_number(self, pkt):
        """PacketNumber == 0xFFFF."""
        assert _field(pkt, "packet_number") == 0xFFFF

    def test_builder_encodes_2byte_pn(self):
        """Our builder also produces pn_len field=1 when PacketNumber requires 2 bytes."""
        raw = QUIC(
            dst_conn_id=list(b"\x70\xa2\x8e\x40\x96\xc5\x7d\xd0\xff\xb6\xc3\xd8\x1b\xca\x52"),
            src_conn_id=list(b"\xf7\x10\x51"),
            packet_number=0xFFFF,
        )
        quic_bytes = bytes(raw.build())
        # First byte should have pn_len bits = 1 (0xc1)
        assert quic_bytes[0] & 0x03 == 1
        # Verify round-trip
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "packet_number_len") == 1
        assert _field(pkt, "packet_number") == 0xFFFF


class TestBuildPacket3BytePN:
    """quic.uts lines 63-67: Scapy bytes with 3-byte PN -> PacketNumberLen=2."""

    # Exact Scapy-produced bytes from quic.uts line 64
    _UTS_BYTES = (
        b"\xc2\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR"
        b"\x03\xf7\x10Q\x00\x00\xff\xff\xff"
    )

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(self._UTS_BYTES)

    def test_first_byte_pn_len_field(self):
        """First byte encodes packet_number_len=2 (0xc2 & 0x03 == 2)."""
        assert self._UTS_BYTES[0] & 0x03 == 2

    def test_packet_number_len_is_2(self, pkt):
        """PacketNumberLen == 2 for 3-byte packet number."""
        assert _field(pkt, "packet_number_len") == 2

    def test_packet_number(self, pkt):
        """PacketNumber == 0xFFFFFF."""
        assert _field(pkt, "packet_number") == 0xFFFFFF

    def test_builder_encodes_3byte_pn(self):
        """Our builder produces pn_len field=2 when PacketNumber requires 3 bytes."""
        raw = QUIC(
            dst_conn_id=list(b"\x70\xa2\x8e\x40\x96\xc5\x7d\xd0\xff\xb6\xc3\xd8\x1b\xca\x52"),
            src_conn_id=list(b"\xf7\x10\x51"),
            packet_number=0xFFFFFF,
        )
        quic_bytes = bytes(raw.build())
        assert quic_bytes[0] & 0x03 == 2
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "packet_number_len") == 2
        assert _field(pkt, "packet_number") == 0xFFFFFF


class TestBuildPacket4BytePN:
    """quic.uts lines 69-73: Scapy bytes with 4-byte PN -> PacketNumberLen=3."""

    # Exact Scapy-produced bytes from quic.uts line 70
    _UTS_BYTES = (
        b"\xc3\x00\x00\x00\x01\x0fp\xa2\x8e@\x96\xc5}\xd0\xff\xb6\xc3\xd8\x1b\xcaR"
        b"\x03\xf7\x10Q\x00\x00\xff\xff\xff\xff"
    )

    @pytest.fixture(scope="class")
    def pkt(self):
        return _parse_quic(self._UTS_BYTES)

    def test_first_byte_pn_len_field(self):
        """First byte encodes packet_number_len=3 (0xc3 & 0x03 == 3)."""
        assert self._UTS_BYTES[0] & 0x03 == 3

    def test_packet_number_len_is_3(self, pkt):
        """PacketNumberLen == 3 for 4-byte packet number."""
        assert _field(pkt, "packet_number_len") == 3

    def test_packet_number(self, pkt):
        """PacketNumber == 0xFFFFFFFF."""
        assert _field(pkt, "packet_number") == 0xFFFFFFFF

    def test_builder_encodes_4byte_pn(self):
        """Our builder produces pn_len field=3 when PacketNumber requires 4 bytes."""
        raw = QUIC(
            dst_conn_id=list(b"\x70\xa2\x8e\x40\x96\xc5\x7d\xd0\xff\xb6\xc3\xd8\x1b\xca\x52"),
            src_conn_id=list(b"\xf7\x10\x51"),
            packet_number=0xFFFFFFFF,
        )
        quic_bytes = bytes(raw.build())
        assert quic_bytes[0] & 0x03 == 3
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "packet_number_len") == 3
        assert _field(pkt, "packet_number") == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# UTS Test 5: QuicVarIntField - variable length roundtrips (quic.uts lines 87-105)
#
# Note: The Scapy UTS tests set Length= explicitly.  Our builder auto-computes
# the length field from (packet_number_bytes + payload_bytes).  We verify the
# *parsed* length field from known wire bytes produced by the builder.
# ---------------------------------------------------------------------------


class TestVarIntLengthRoundtrip:
    """Roundtrip tests for the length varint field.

    quic.uts line 91: QUIC_Initial(Length=1)
      => b'\\xc0\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x00'
    Our builder produces the same wire bytes when no payload and 0 token =>
    packet_number(0)=1 byte, payload=0 bytes => length=1.
    """

    def test_length_1_wire_bytes(self):
        """Empty payload + pn=0 => length varint = 1 (1-byte encoding)."""
        # Our builder: Initial, no DCID, no SCID, no payload, pn=0 (default)
        raw = QUIC.initial()
        quic_bytes = bytes(raw.build())
        # Expected from quic.uts line 92: b'\xc0\x00\x00\x00\x01\x00\x00\x00\x01\x00'
        expected = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x01\x00"
        assert quic_bytes == expected, f"got {quic_bytes.hex()}"

    def test_length_1_roundtrip(self):
        """Parsed length from the above wire bytes == 1."""
        quic_bytes = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x01\x00"
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "length") == 1

    def test_length_512_wire_bytes(self):
        """quic.uts line 96: QUIC_Initial(Length=1<<9) => 2-byte varint."""
        # Produce this by using a 511-byte payload + 1-byte pn
        quic_bytes = b"\xc0\x00\x00\x00\x01\x00\x00\x00B\x00\x00"
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "length") == 512

    def test_length_131072_wire_bytes(self):
        """quic.uts line 100: QUIC_Initial(Length=1<<17) => 4-byte varint."""
        quic_bytes = b"\xc0\x00\x00\x00\x01\x00\x00\x00\x80\x02\x00\x00\x00"
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "length") == 1 << 17

    def test_length_max_varint_wire_bytes(self):
        """quic.uts line 103: max 62-bit varint => 8-byte encoding."""
        quic_bytes = b"\xc0\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00"
        pkt = _parse_quic(quic_bytes)
        assert _field(pkt, "length") == 4611686018427387903
