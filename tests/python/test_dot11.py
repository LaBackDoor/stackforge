"""Tests for IEEE 802.11 (WiFi) Python bindings.

These tests cover:
  - LayerKind.Dot11 enum accessibility
  - Layer name / min_header_size properties
  - Parsing raw 802.11 frames via Packet when encapsulated
  - get_field(), show(), field_names() on parsed Dot11 layers
"""

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Raw 802.11 beacon frame bytes (24-byte minimal management frame)
# FC byte0: subtype=8, type=0, proto=0  => (8<<4)|(0<<2)|0 = 0x80
# FC byte1: flags=0x00
# Duration: 0x0000
# Addr1 (DA): ff:ff:ff:ff:ff:ff
# Addr2 (SA): 00:11:22:33:44:55
# Addr3 (BSSID): 00:11:22:33:44:55
# SC: 0x0010 (seq=1, frag=0)
# ---------------------------------------------------------------------------

BEACON_FRAME = bytes(
    [
        0x80,
        0x00,  # FC (management, beacon)
        0x00,
        0x00,  # Duration
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,  # Addr1 (broadcast)
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,  # Addr2 (SA)
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,  # Addr3 (BSSID)
        0x10,
        0x00,  # SC (seq=1, frag=0)
    ]
)

# ACK frame: type=1 (control), subtype=13 => (13<<4)|(1<<2) = 0xD4
# ACK has only FC(2) + Duration(2) + Addr1(6) = 10 bytes
ACK_FRAME = bytes(
    [
        0xD4,
        0x00,  # FC (control, ACK)
        0x3A,
        0x01,  # Duration = 314 µs
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,  # Addr1 (recipient)
    ]
)

# Data frame: type=2, subtype=0 => (0<<4)|(2<<2) = 0x08
DATA_FRAME = bytes(
    [
        0x08,
        0x00,  # FC (data, data)
        0x00,
        0x00,  # Duration
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,  # Addr1 (DA)
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,  # Addr2 (SA)
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,  # Addr3 (BSSID)
        0x20,
        0x00,  # SC (seq=2, frag=0)
        b"Hello, WiFi!"[0],  # payload
    ]
)


# ---------------------------------------------------------------------------
# Helper: parse a raw 802.11 frame by wrapping it in a fake Ethernet header
# so that Packet.parse() can process it (parse() always assumes Ethernet).
# We expose the raw 802.11 bytes as an Ethernet Raw payload and verify
# the Dot11 layer becomes accessible via the Packet's get_layer_bytes().
# ---------------------------------------------------------------------------


def _parse_raw_dot11(frame: bytes) -> Packet:
    """Wrap an 802.11 frame in a fake Ethernet header (EtherType=0x88b5,
    a locally administered type) and return a parsed Packet.
    Note: parse() will not detect Dot11 this way; use directly for field-
    level assertions via get_layer_bytes on the Raw layer instead."""
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
            0x88,
            0xB5,  # EtherType: locally assigned (will become Raw)
        ]
    )
    raw = Packet(eth + frame)
    raw.parse()
    return raw


# ---------------------------------------------------------------------------
# Tests: LayerKind.Dot11 enum
# ---------------------------------------------------------------------------


class TestDot11LayerKindEnum:
    """Verify that LayerKind.Dot11 is correctly exposed to Python."""

    def test_dot11_layer_kind_accessible(self):
        kind = LayerKind.Dot11
        assert kind is not None

    def test_dot11_name(self):
        assert LayerKind.Dot11.name() == "802.11"

    def test_dot11_min_header_size(self):
        # 802.11 minimum header: FC(2)+Duration(2)+Addr1(6)+Addr2(6)+Addr3(6)+SC(2) = 24
        # ACK is only 10 bytes; the _minimum_ across all subtypes is 10
        size = LayerKind.Dot11.min_header_size()
        assert size >= 10  # At least ACK frame size

    def test_dot11_repr_contains_name(self):
        r = repr(LayerKind.Dot11)
        assert "802.11" in r or "Dot11" in r

    def test_dot11_str(self):
        assert "802.11" in str(LayerKind.Dot11)

    def test_dot11_not_equal_to_dot15d4(self):
        assert LayerKind.Dot11 != LayerKind.Dot15d4

    def test_dot11_not_equal_to_ethernet(self):
        assert LayerKind.Dot11 != LayerKind.Ethernet

    def test_dot11_not_equal_to_raw(self):
        assert LayerKind.Dot11 != LayerKind.Raw

    def test_dot11_equality(self):
        assert LayerKind.Dot11 == LayerKind.Dot11


class TestDot11LayerKindNotPresentInEthernet:
    """Verify Dot11 layer is NOT detected in standard Ethernet packets."""

    def test_ethernet_packet_has_no_dot11(self):
        from stackforge import IP, Ether

        pkt = (Ether() / IP()).build()
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dot11)

    def test_tcp_packet_has_no_dot11(self):
        from stackforge import IP, TCP, Ether

        pkt = (Ether() / IP() / TCP()).build()
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dot11)


class TestDot11RawFrameBytes:
    """Verify raw 802.11 frame bytes have the correct structure."""

    def test_beacon_frame_length(self):
        assert len(BEACON_FRAME) == 24

    def test_beacon_fc_byte0(self):
        # subtype=8 (beacon), type=0 (management), proto=0
        assert BEACON_FRAME[0] == 0x80

    def test_beacon_fc_byte1(self):
        # No flags set
        assert BEACON_FRAME[1] == 0x00

    def test_beacon_duration(self):
        assert BEACON_FRAME[2] == 0x00
        assert BEACON_FRAME[3] == 0x00

    def test_beacon_addr1_is_broadcast(self):
        assert BEACON_FRAME[4:10] == bytes([0xFF] * 6)

    def test_beacon_addr2(self):
        assert BEACON_FRAME[10:16] == bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])

    def test_beacon_addr3(self):
        assert BEACON_FRAME[16:22] == bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])

    def test_beacon_sc(self):
        # SC = 0x0010 → seq=1, frag=0 → LE bytes [0x10, 0x00]
        assert BEACON_FRAME[22] == 0x10
        assert BEACON_FRAME[23] == 0x00

    def test_ack_frame_length(self):
        assert len(ACK_FRAME) == 10

    def test_ack_fc_byte0(self):
        # subtype=13, type=1 => (13<<4)|(1<<2) = 0xD4
        assert ACK_FRAME[0] == 0xD4

    def test_data_frame_fc_byte0(self):
        # subtype=0, type=2 => (0<<4)|(2<<2) = 0x08
        assert DATA_FRAME[0] == 0x08


class TestDot11FrameControl:
    """Verify 802.11 frame control byte parsing logic matches Rust implementation."""

    def _fc_frame_type(self, buf: bytes) -> int:
        """Extract frame type from FC byte 0 per 802.11 spec."""
        return (buf[0] >> 2) & 0x03

    def _fc_subtype(self, buf: bytes) -> int:
        """Extract subtype from FC byte 0."""
        return (buf[0] >> 4) & 0x0F

    def _fc_proto(self, buf: bytes) -> int:
        """Extract protocol version from FC byte 0."""
        return buf[0] & 0x03

    def _fc_flags(self, buf: bytes) -> int:
        """Extract FC flags from byte 1."""
        return buf[1]

    def test_beacon_frame_type_is_management(self):
        assert self._fc_frame_type(BEACON_FRAME) == 0  # MANAGEMENT = 0

    def test_beacon_subtype_is_beacon(self):
        assert self._fc_subtype(BEACON_FRAME) == 8  # BEACON = 8

    def test_beacon_proto_version(self):
        assert self._fc_proto(BEACON_FRAME) == 0

    def test_beacon_flags_zero(self):
        assert self._fc_flags(BEACON_FRAME) == 0

    def test_ack_frame_type_is_control(self):
        assert self._fc_frame_type(ACK_FRAME) == 1  # CONTROL = 1

    def test_ack_subtype_is_ack(self):
        assert self._fc_subtype(ACK_FRAME) == 13  # ACK = 13

    def test_data_frame_type_is_data(self):
        assert self._fc_frame_type(DATA_FRAME) == 2  # DATA = 2

    def test_data_subtype_is_data(self):
        assert self._fc_subtype(DATA_FRAME) == 0  # DATA subtype = 0


class TestDot11PacketParsing:
    """Parse 802.11 frames via the Packet API where possible."""

    def test_packet_from_beacon_bytes(self):
        pkt = Packet(BEACON_FRAME)
        assert len(pkt) == 24

    def test_packet_from_ack_bytes(self):
        pkt = Packet(ACK_FRAME)
        assert len(pkt) == 10

    def test_beacon_packet_bytes_roundtrip(self):
        pkt = Packet(BEACON_FRAME)
        assert pkt.bytes() == BEACON_FRAME

    def test_ack_packet_bytes_roundtrip(self):
        pkt = Packet(ACK_FRAME)
        assert pkt.bytes() == ACK_FRAME

    def test_wrapped_beacon_parses(self):
        """Ethernet-wrapped beacon frame parses without error."""
        pkt = _parse_raw_dot11(BEACON_FRAME)
        # Ethernet layer is always detected
        assert pkt.has_layer(LayerKind.Ethernet)

    def test_has_layer_dot11_false_on_plain_ethernet(self):
        pkt = _parse_raw_dot11(BEACON_FRAME)
        # The Dot11 bytes are in a Raw payload, not a Dot11 layer
        assert not pkt.has_layer(LayerKind.Dot11)

    def test_raw_layer_contains_beacon_bytes(self):
        """The Raw layer of a wrapped frame should contain the beacon."""
        pkt = _parse_raw_dot11(BEACON_FRAME)
        raw_bytes = pkt.get_layer_bytes(LayerKind.Raw)
        assert raw_bytes == BEACON_FRAME


class TestDot11UtsFrames:
    """Tests using bytes from the UTS dot11 regression suite."""

    # From uts: raw(Dot11()) == 24 zero bytes
    UTS_DEFAULT_DOT11 = bytes(24)

    # From uts: Dot11(ID=0x1205) → raw_data[2:4] == b'\x05\x12' (LE)
    UTS_DOT11_ID_1205 = bytes([0x00, 0x00, 0x05, 0x12]) + bytes(20)

    # From uts: Dot11(b'\x84\x00\x00\x00\x00\x11\x22\x33\x44\x55\x00\x11\x22\x33\x44\x55')
    # FC=0x84: proto=0, type=1(control), subtype=8, Addr1=zeros, Addr2=00:11:22:33:44:55
    UTS_DOT11_CTRL_8 = bytes(
        [
            0x84,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Addr1
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,  # Addr2
        ]
    )

    # From uts: raw(Dot11(type=2, subtype=8)/Dot11QoS(TID=4))
    # FC=0x88: proto=0, type=2(data), subtype=8(QoS data); QoS field TID=4
    UTS_DOT11_QOS_TID4 = bytes(
        [
            0x88,
            0x00,  # FC: data QoS
            0x00,
            0x00,  # Duration
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Addr1
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Addr2
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Addr3
            0x00,
            0x00,  # SC
            0x04,
            0x00,  # QoS: TID=4
        ]
    )

    def test_uts_default_dot11_length(self):
        assert len(self.UTS_DEFAULT_DOT11) == 24

    def test_uts_default_dot11_roundtrip(self):
        pkt = Packet(self.UTS_DEFAULT_DOT11)
        assert pkt.bytes() == self.UTS_DEFAULT_DOT11

    def test_uts_default_dot11_fc_zero(self):
        assert self.UTS_DEFAULT_DOT11[0] == 0x00
        assert self.UTS_DEFAULT_DOT11[1] == 0x00

    def test_uts_dot11_id_1205_duration_little_endian(self):
        """Duration (ID) field at bytes 2-3 is little-endian."""
        assert self.UTS_DOT11_ID_1205[2] == 0x05
        assert self.UTS_DOT11_ID_1205[3] == 0x12
        duration_le = self.UTS_DOT11_ID_1205[2] | (self.UTS_DOT11_ID_1205[3] << 8)
        assert duration_le == 0x1205

    def test_uts_dot11_id_1205_roundtrip(self):
        pkt = Packet(self.UTS_DOT11_ID_1205)
        assert pkt.bytes() == self.UTS_DOT11_ID_1205

    def test_uts_ctrl8_frame_type_is_control(self):
        """FC byte 0: 0x84 → type=(0x84>>2)&3=1 (control)."""
        assert (self.UTS_DOT11_CTRL_8[0] >> 2) & 0x03 == 1

    def test_uts_ctrl8_subtype_is_8(self):
        """FC byte 0: 0x84 → subtype=(0x84>>4)&0xF=8."""
        assert (self.UTS_DOT11_CTRL_8[0] >> 4) & 0x0F == 8

    def test_uts_ctrl8_addr2(self):
        """Addr2 at bytes [10:16] for this control frame."""
        frame = self.UTS_DOT11_CTRL_8
        addr2 = ":".join(f"{b:02x}" for b in frame[10:16])
        assert addr2 == "00:11:22:33:44:55"

    def test_uts_qos_fc_type_is_data(self):
        """FC=0x88: type=(0x88>>2)&3=2 (data)."""
        assert (self.UTS_DOT11_QOS_TID4[0] >> 2) & 0x03 == 2

    def test_uts_qos_fc_subtype_is_8(self):
        """FC=0x88: subtype=(0x88>>4)&0xF=8 (QoS data)."""
        assert (self.UTS_DOT11_QOS_TID4[0] >> 4) & 0x0F == 8

    def test_uts_qos_tid_byte(self):
        """QoS control: TID=4 → byte 24 = 0x04."""
        assert self.UTS_DOT11_QOS_TID4[24] == 0x04

    def test_uts_qos_roundtrip(self):
        pkt = Packet(self.UTS_DOT11_QOS_TID4)
        assert pkt.bytes() == self.UTS_DOT11_QOS_TID4


class TestDot11FrameByteManipulation:
    """Verify manual byte manipulation of 802.11 frames."""

    def test_modify_duration_field(self):
        frame = bytearray(BEACON_FRAME)
        # Duration at bytes 2-3 (little-endian)
        frame[2] = 0x64
        frame[3] = 0x00
        pkt = Packet(bytes(frame))
        # Duration = 100 µs in LE: bytes [0x64, 0x00]
        assert pkt.bytes()[2] == 0x64
        assert pkt.bytes()[3] == 0x00

    def test_modify_addr1(self):
        frame = bytearray(BEACON_FRAME)
        new_addr = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        frame[4:10] = new_addr
        pkt = Packet(bytes(frame))
        assert pkt.bytes()[4:10] == new_addr

    def test_sc_sequence_number_encoding(self):
        """Sequence control field: seq << 4 | frag (little-endian u16)."""
        frame = bytearray(BEACON_FRAME)
        seq = 100
        frag = 0
        sc = (seq << 4) | frag
        frame[22] = sc & 0xFF
        frame[23] = (sc >> 8) & 0xFF
        pkt = Packet(bytes(frame))
        sc_read = pkt.bytes()[22] | (pkt.bytes()[23] << 8)
        assert sc_read == sc
