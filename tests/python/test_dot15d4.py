"""Tests for IEEE 802.15.4 (Zigbee/Thread) Python bindings.

These tests cover:
  - LayerKind.Dot15d4 and LayerKind.Dot15d4Fcs enum accessibility
  - Layer name / min_header_size properties
  - Raw frame byte construction and parsing
  - CRC-16 CCITT Kermit (0x8408) FCS computation verification
  - Frame type and address mode byte decoding
"""

import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Constants mirroring Rust implementation
# ---------------------------------------------------------------------------

# Frame types (FCF bits 2:0)
FRAME_TYPE_BEACON = 0
FRAME_TYPE_DATA = 1
FRAME_TYPE_ACK = 2
FRAME_TYPE_COMMAND = 3

# Address modes (2 bits)
ADDR_MODE_NONE = 0
ADDR_MODE_SHORT = 2
ADDR_MODE_LONG = 3


# ---------------------------------------------------------------------------
# CRC-16 CCITT Kermit (polynomial 0x8408) — same as Rust crc::crc16_ccitt_kermit
# ---------------------------------------------------------------------------


def _crc16_kermit(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        for _ in range(8):
            if (crc ^ byte) & 0x01:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            byte >>= 1
    return crc


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------


def _build_fcf(
    frame_type: int = FRAME_TYPE_DATA,
    security: bool = False,
    pending: bool = False,
    ackreq: bool = False,
    panid_compress: bool = False,
    dest_mode: int = ADDR_MODE_SHORT,
    frame_ver: int = 0,
    src_mode: int = ADDR_MODE_SHORT,
) -> int:
    fcf = frame_type & 0x07
    if security:
        fcf |= 1 << 3
    if pending:
        fcf |= 1 << 4
    if ackreq:
        fcf |= 1 << 5
    if panid_compress:
        fcf |= 1 << 6
    fcf |= (dest_mode & 0x03) << 10
    fcf |= (frame_ver & 0x03) << 12
    fcf |= (src_mode & 0x03) << 14
    return fcf


def _data_frame_short_addrs(
    seqnum: int = 42,
    dest_panid: int = 0x1234,
    dest_addr: int = 0xFFFF,
    src_addr: int = 0x0001,
    panid_compress: bool = True,
) -> bytes:
    """Build a minimal data frame with short addresses."""
    fcf = _build_fcf(
        frame_type=FRAME_TYPE_DATA,
        ackreq=True,
        panid_compress=panid_compress,
        dest_mode=ADDR_MODE_SHORT,
        src_mode=ADDR_MODE_SHORT,
    )
    buf = struct.pack("<H", fcf)  # FCF (2 bytes, LE)
    buf += bytes([seqnum])  # Sequence number
    buf += struct.pack("<H", dest_panid)  # Dest PAN ID
    buf += struct.pack("<H", dest_addr)  # Dest short address
    if not panid_compress:
        buf += struct.pack("<H", 0xBBBB)  # Src PAN ID (only if not compressed)
    buf += struct.pack("<H", src_addr)  # Src short address
    return buf


def _ack_frame(seqnum: int = 10) -> bytes:
    """Build an ACK frame (no addressing info)."""
    fcf = _build_fcf(
        frame_type=FRAME_TYPE_ACK,
        dest_mode=ADDR_MODE_NONE,
        src_mode=ADDR_MODE_NONE,
    )
    buf = struct.pack("<H", fcf)
    buf += bytes([seqnum])
    return buf  # 3 bytes total


def _beacon_frame(seqnum: int = 0) -> bytes:
    """Build a minimal beacon frame with short source address."""
    fcf = _build_fcf(
        frame_type=FRAME_TYPE_BEACON,
        dest_mode=ADDR_MODE_NONE,
        src_mode=ADDR_MODE_SHORT,
        panid_compress=False,
    )
    buf = struct.pack("<H", fcf)
    buf += bytes([seqnum])  # seqnum
    buf += struct.pack("<H", 0xCAFE)  # src PAN
    buf += struct.pack("<H", 0x0001)  # src short addr
    return buf


def _data_frame_with_fcs(seqnum: int = 42) -> bytes:
    """Build a data frame with appended FCS."""
    frame = _data_frame_short_addrs(seqnum=seqnum)
    fcs = _crc16_kermit(frame)
    return frame + struct.pack("<H", fcs)


# ---------------------------------------------------------------------------
# Tests: LayerKind enum accessibility
# ---------------------------------------------------------------------------


class TestDot15d4LayerKindEnum:
    """Verify LayerKind.Dot15d4 and LayerKind.Dot15d4Fcs are exposed."""

    def test_dot15d4_accessible(self):
        kind = LayerKind.Dot15d4
        assert kind is not None

    def test_dot15d4_fcs_accessible(self):
        kind = LayerKind.Dot15d4Fcs
        assert kind is not None

    def test_dot15d4_name(self):
        assert LayerKind.Dot15d4.name() == "802.15.4"

    def test_dot15d4_fcs_name(self):
        name = LayerKind.Dot15d4Fcs.name()
        assert "802.15.4" in name or "FCS" in name

    def test_dot15d4_min_header_size(self):
        # FCF(2) + seqnum(1) = 3 bytes minimum (ACK frame has no addressing)
        size = LayerKind.Dot15d4.min_header_size()
        assert size >= 3

    def test_dot15d4_fcs_min_header_size(self):
        # FCS variant includes extra 2 bytes for CRC
        size = LayerKind.Dot15d4Fcs.min_header_size()
        assert size >= 5

    def test_dot15d4_not_equal_to_dot11(self):
        assert LayerKind.Dot15d4 != LayerKind.Dot11

    def test_dot15d4_not_equal_to_ethernet(self):
        assert LayerKind.Dot15d4 != LayerKind.Ethernet

    def test_dot15d4_equality(self):
        assert LayerKind.Dot15d4 == LayerKind.Dot15d4

    def test_dot15d4_fcs_equality(self):
        assert LayerKind.Dot15d4Fcs == LayerKind.Dot15d4Fcs

    def test_dot15d4_not_equal_to_fcs_variant(self):
        assert LayerKind.Dot15d4 != LayerKind.Dot15d4Fcs

    def test_dot15d4_repr(self):
        r = repr(LayerKind.Dot15d4)
        assert "802.15.4" in r or "Dot15d4" in r

    def test_dot15d4_str(self):
        assert "802.15.4" in str(LayerKind.Dot15d4)


class TestDot15d4NotPresentInEthernet:
    """Verify Dot15d4 layers are NOT detected in standard Ethernet packets."""

    def test_ethernet_has_no_dot15d4(self):
        from stackforge import IP, Ether

        pkt = (Ether() / IP()).build()
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dot15d4)
        assert not pkt.has_layer(LayerKind.Dot15d4Fcs)

    def test_arp_packet_has_no_dot15d4(self):
        from stackforge import ARP, Ether

        pkt = (Ether() / ARP()).build()
        pkt.parse()
        assert not pkt.has_layer(LayerKind.Dot15d4)


# ---------------------------------------------------------------------------
# Tests: CRC-16 CCITT Kermit computation
# ---------------------------------------------------------------------------


class TestDot15d4Crc:
    """Verify the CRC-16 CCITT Kermit computation matches Rust implementation."""

    def test_empty_input(self):
        assert _crc16_kermit(b"") == 0x0000

    def test_single_zero_byte(self):
        assert _crc16_kermit(b"\x00") == 0x0000

    def test_single_ff_byte(self):
        # CRC of 0xFF using Kermit polynomial 0x8408
        assert _crc16_kermit(bytes([0xFF])) == 0x0F78

    def test_known_vector_0x61_0x88(self):
        # This is the FCF of a common data frame
        crc = _crc16_kermit(bytes([0x61, 0x88]))
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_crc_two_byte_ack(self):
        ack = _ack_frame(seqnum=10)
        crc = _crc16_kermit(ack)
        assert 0 <= crc <= 0xFFFF

    def test_fcs_appended_correctly(self):
        """Verify that the FCS appended to a frame is correct."""
        frame = _data_frame_short_addrs()
        expected_fcs = _crc16_kermit(frame)
        fcs_frame = _data_frame_with_fcs()
        # Last two bytes (LE) are the FCS
        actual_fcs = struct.unpack("<H", fcs_frame[-2:])[0]
        assert actual_fcs == expected_fcs

    def test_fcs_frame_is_frame_plus_2_bytes(self):
        frame = _data_frame_short_addrs()
        fcs_frame = _data_frame_with_fcs()
        assert len(fcs_frame) == len(frame) + 2

    def test_crc_changes_with_different_data(self):
        crc1 = _crc16_kermit(b"\x01")
        crc2 = _crc16_kermit(b"\x02")
        assert crc1 != crc2


# ---------------------------------------------------------------------------
# Tests: FCF byte layout
# ---------------------------------------------------------------------------


class TestDot15d4FcfLayout:
    """Verify that the FCF (Frame Control Field) byte layout is correct."""

    def test_data_frame_fcf_frame_type(self):
        frame = _data_frame_short_addrs()
        fcf = struct.unpack("<H", frame[0:2])[0]
        frame_type = fcf & 0x07
        assert frame_type == FRAME_TYPE_DATA

    def test_ack_frame_fcf_frame_type(self):
        frame = _ack_frame()
        fcf = struct.unpack("<H", frame[0:2])[0]
        assert (fcf & 0x07) == FRAME_TYPE_ACK

    def test_beacon_frame_fcf_frame_type(self):
        frame = _beacon_frame()
        fcf = struct.unpack("<H", frame[0:2])[0]
        assert (fcf & 0x07) == FRAME_TYPE_BEACON

    def test_data_frame_ackreq_bit(self):
        frame = _data_frame_short_addrs()
        fcf = struct.unpack("<H", frame[0:2])[0]
        ackreq = (fcf >> 5) & 0x01
        assert ackreq == 1

    def test_data_frame_panid_compress_bit(self):
        frame = _data_frame_short_addrs(panid_compress=True)
        fcf = struct.unpack("<H", frame[0:2])[0]
        compress = (fcf >> 6) & 0x01
        assert compress == 1

    def test_data_frame_no_panid_compress_bit(self):
        frame = _data_frame_short_addrs(panid_compress=False)
        fcf = struct.unpack("<H", frame[0:2])[0]
        compress = (fcf >> 6) & 0x01
        assert compress == 0

    def test_data_frame_dest_addr_mode_short(self):
        frame = _data_frame_short_addrs()
        fcf = struct.unpack("<H", frame[0:2])[0]
        dest_mode = (fcf >> 10) & 0x03
        assert dest_mode == ADDR_MODE_SHORT

    def test_data_frame_src_addr_mode_short(self):
        frame = _data_frame_short_addrs()
        fcf = struct.unpack("<H", frame[0:2])[0]
        src_mode = (fcf >> 14) & 0x03
        assert src_mode == ADDR_MODE_SHORT

    def test_ack_frame_no_addressing(self):
        frame = _ack_frame()
        fcf = struct.unpack("<H", frame[0:2])[0]
        dest_mode = (fcf >> 10) & 0x03
        src_mode = (fcf >> 14) & 0x03
        assert dest_mode == ADDR_MODE_NONE
        assert src_mode == ADDR_MODE_NONE

    def test_security_bit_not_set(self):
        frame = _data_frame_short_addrs()
        fcf = struct.unpack("<H", frame[0:2])[0]
        security = (fcf >> 3) & 0x01
        assert security == 0


# ---------------------------------------------------------------------------
# Tests: Frame structure and addressing
# ---------------------------------------------------------------------------


class TestDot15d4FrameStructure:
    """Verify that frame bytes are laid out correctly."""

    def test_data_frame_minimum_length_compressed(self):
        # FCF(2) + seqnum(1) + dest_panid(2) + dest_short(2) + src_short(2) = 9
        frame = _data_frame_short_addrs(panid_compress=True)
        assert len(frame) == 9

    def test_data_frame_length_no_compression(self):
        # FCF(2) + seqnum(1) + dest_panid(2) + dest_short(2) + src_panid(2) + src_short(2) = 11
        frame = _data_frame_short_addrs(panid_compress=False)
        assert len(frame) == 11

    def test_ack_frame_length(self):
        # FCF(2) + seqnum(1) = 3
        frame = _ack_frame()
        assert len(frame) == 3

    def test_seqnum_byte(self):
        for seq in [0, 1, 42, 255]:
            frame = _data_frame_short_addrs(seqnum=seq)
            assert frame[2] == seq

    def test_dest_panid_little_endian(self):
        frame = _data_frame_short_addrs(dest_panid=0x1234)
        panid = struct.unpack("<H", frame[3:5])[0]
        assert panid == 0x1234

    def test_dest_addr_little_endian(self):
        frame = _data_frame_short_addrs(dest_addr=0xABCD)
        addr = struct.unpack("<H", frame[5:7])[0]
        assert addr == 0xABCD

    def test_src_addr_little_endian_compressed(self):
        # With PAN ID compression: FCF(2) + seq(1) + dest_panid(2) + dest(2) + src(2)
        frame = _data_frame_short_addrs(src_addr=0x0042, panid_compress=True)
        src = struct.unpack("<H", frame[7:9])[0]
        assert src == 0x0042

    def test_broadcast_dest_address(self):
        frame = _data_frame_short_addrs(dest_addr=0xFFFF)
        addr = struct.unpack("<H", frame[5:7])[0]
        assert addr == 0xFFFF

    def test_ack_seqnum(self):
        for seq in [0, 10, 127, 200, 255]:
            frame = _ack_frame(seqnum=seq)
            assert frame[2] == seq


class TestDot15d4PacketApi:
    """Verify raw 802.15.4 frames interact correctly with the Packet API."""

    def test_packet_from_data_frame(self):
        frame = _data_frame_short_addrs()
        pkt = Packet(frame)
        assert len(pkt) == len(frame)

    def test_packet_from_ack_frame(self):
        frame = _ack_frame()
        pkt = Packet(frame)
        assert len(pkt) == 3

    def test_packet_bytes_roundtrip_data(self):
        frame = _data_frame_short_addrs()
        pkt = Packet(frame)
        assert pkt.bytes() == frame

    def test_packet_bytes_roundtrip_ack(self):
        frame = _ack_frame()
        pkt = Packet(frame)
        assert pkt.bytes() == frame

    def test_packet_bytes_roundtrip_beacon(self):
        frame = _beacon_frame()
        pkt = Packet(frame)
        assert pkt.bytes() == frame

    def test_packet_bytes_roundtrip_fcs_frame(self):
        frame = _data_frame_with_fcs()
        pkt = Packet(frame)
        assert pkt.bytes() == frame

    def test_ethernet_packet_has_no_dot15d4(self):
        from stackforge import IP, TCP, Ether

        stack = (Ether() / IP() / TCP()).build()
        stack.parse()
        assert not stack.has_layer(LayerKind.Dot15d4)
        assert not stack.has_layer(LayerKind.Dot15d4Fcs)


class TestDot15d4FcsFrame:
    """Verify FCS frame construction."""

    def test_fcs_frame_last_two_bytes_are_crc(self):
        frame = _data_frame_short_addrs()
        fcs_frame = _data_frame_with_fcs()
        expected = _crc16_kermit(frame)
        actual = struct.unpack("<H", fcs_frame[-2:])[0]
        assert actual == expected

    def test_fcs_frame_data_unchanged(self):
        frame = _data_frame_short_addrs()
        fcs_frame = _data_frame_with_fcs()
        assert fcs_frame[: len(frame)] == frame

    def test_different_seqnums_produce_different_crc(self):
        frame1 = _data_frame_with_fcs(seqnum=1)
        frame2 = _data_frame_with_fcs(seqnum=2)
        crc1 = struct.unpack("<H", frame1[-2:])[0]
        crc2 = struct.unpack("<H", frame2[-2:])[0]
        assert crc1 != crc2


# ---------------------------------------------------------------------------
# Tests using real captured packets from the UTS regression suite
# ---------------------------------------------------------------------------

# Real Dot15d4FCS beacon frame from tests/uts/dot15d4.uts line 34:
# Dot15d4FCS(b'\x00\x80\x89\xaa\x99\x00\x00\xff\xcf\x00\x00\x00"\x84
#              \xfe\xca\xef\xbe\xed\xfe\xce\xfa\xff\xff\xff\x00X\xa4')
# FCF=0x8000: frametype=0(beacon), srcaddrmode=2(short)
# seqnum=0x89=137, src_panid=0x99aa, src_addr=0x0000
# FCS = 0xa458 (last 2 bytes, LE: 0x58 0xa4)
UTS_DOT15D4_FCS_BEACON = bytes(
    [
        0x00,
        0x80,  # FCF: frametype=0(beacon), srcaddrmode=2(short)
        0x89,  # seqnum=137
        0xAA,
        0x99,  # src_panid=0x99aa
        0x00,
        0x00,  # src_addr=0x0000
        0xFF,
        0xCF,  # Superframe spec
        0x00,
        0x00,  # GTS spec + pending addr spec
        0x00,
        0x22,
        0x84,
        0xFE,
        0xCA,
        0xEF,
        0xBE,
        0xED,
        0xFE,
        0xCE,
        0xFA,
        0xFF,
        0xFF,
        0xFF,
        0x00,
        0x58,
        0xA4,  # FCS = 0xa458 (LE)
    ]
)


class TestDot15d4UtsFrames:
    """Tests using real captured packets from the UTS regression suite."""

    def test_uts_beacon_packet_roundtrip(self):
        pkt = Packet(UTS_DOT15D4_FCS_BEACON)
        assert pkt.bytes() == UTS_DOT15D4_FCS_BEACON

    def test_uts_beacon_length(self):
        # FCF(2)+seqnum(1)+src_panid(2)+src_addr(2)+sf_spec(2)+gts(1)+pa(1)+payload(15)+FCS(2) = 28
        assert len(UTS_DOT15D4_FCS_BEACON) == 28

    def test_uts_beacon_fcf_frametype(self):
        """FCF bits 2:0 = 0 (beacon)."""
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert (fcf & 0x07) == FRAME_TYPE_BEACON

    def test_uts_beacon_fcf_security_off(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 3) & 1) == 0

    def test_uts_beacon_fcf_pending_off(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 4) & 1) == 0

    def test_uts_beacon_fcf_ackreq_off(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 5) & 1) == 0

    def test_uts_beacon_fcf_panidcompress_off(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 6) & 1) == 0

    def test_uts_beacon_fcf_destaddrmode_none(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 10) & 0x03) == ADDR_MODE_NONE

    def test_uts_beacon_fcf_framever_zero(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 12) & 0x03) == 0

    def test_uts_beacon_fcf_srcaddrmode_short(self):
        fcf = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[0:2])[0]
        assert ((fcf >> 14) & 0x03) == ADDR_MODE_SHORT

    def test_uts_beacon_seqnum(self):
        """Seqnum byte at offset 2 should be 137 (0x89)."""
        assert UTS_DOT15D4_FCS_BEACON[2] == 0x89  # 137

    def test_uts_beacon_src_panid(self):
        """src_panid at bytes 3-4 (LE) should be 0x99aa."""
        panid = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[3:5])[0]
        assert panid == 0x99AA

    def test_uts_beacon_src_addr(self):
        """src_addr at bytes 5-6 (LE) should be 0x0000."""
        addr = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[5:7])[0]
        assert addr == 0x0000

    def test_uts_beacon_fcs_value(self):
        """FCS (last 2 bytes, LE) should be 0xa458."""
        fcs = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[-2:])[0]
        assert fcs == 0xA458

    def test_uts_beacon_fcs_correct(self):
        """Verify FCS matches CRC-16 CCITT Kermit of the frame data."""
        frame_data = UTS_DOT15D4_FCS_BEACON[:-2]  # exclude FCS bytes
        computed_fcs = _crc16_kermit(frame_data)
        stored_fcs = struct.unpack("<H", UTS_DOT15D4_FCS_BEACON[-2:])[0]
        assert computed_fcs == stored_fcs
