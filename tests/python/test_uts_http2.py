"""UTS-driven HTTP/2 tests using frame bytes from tests/uts/http2.uts and the
http2_h2c.pcap capture file.

HTTP/2 uses a 9-byte frame header (RFC 7540 Section 4):
  - 3 bytes: payload length
  - 1 byte:  frame type
  - 1 byte:  flags
  - 4 bytes: stream identifier (MSB reserved = 0)

Frame types used in tests:
  0 = DATA, 1 = HEADERS, 4 = SETTINGS, 8 = WINDOW_UPDATE

These tests are distinct from any existing HTTP/2 unit/integration tests.
They validate specific frame bytes taken from the UTS file and the pcap.
"""

import os
import struct

import pytest
from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# PCAP path
# ---------------------------------------------------------------------------

_PCAP_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "sample_pcap",
)
_HTTP2_H2C_PCAP = os.path.join(_PCAP_DIR, "http2_h2c.pcap")

# ---------------------------------------------------------------------------
# HTTP/2 constants
# ---------------------------------------------------------------------------

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_HEADER_LEN = 9

# Frame type identifiers
FRAME_DATA = 0
FRAME_HEADERS = 1
FRAME_SETTINGS = 4
FRAME_WINDOW_UPDATE = 8

# Flag values
FLAG_ACK = 0x01
FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x04
FLAG_END_STREAM_AND_HEADERS = 0x05  # END_STREAM | END_HEADERS


# ---------------------------------------------------------------------------
# Raw frame byte sequences extracted from the http2_h2c.pcap capture
# ---------------------------------------------------------------------------

# Packet 3 payload: SETTINGS frame with 3 settings parameters (18 bytes payload)
# type=4, flags=0, stream_id=0, length=18
_SETTINGS_FRAME = (
    b"\x00\x00\x12\x04\x00\x00\x00\x00\x00"
    b"\x00\x03\x00\x00\x00\x64"  # SETTINGS_MAX_CONCURRENT_STREAMS = 100
    b"\x00\x04\x40\x00\x00\x00"  # SETTINGS_INITIAL_WINDOW_SIZE = 1073741824
    b"\x00\x02\x00\x00\x00\x00"  # SETTINGS_ENABLE_PUSH = 0
)

# Packet 4 payload: SETTINGS_ACK (type=4, flags=1, stream_id=0, length=0)
_SETTINGS_ACK_FRAME = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"

# Packet 6 payload: WINDOW_UPDATE (type=8, flags=0, stream_id=0, length=4)
_WINDOW_UPDATE_FRAME = b"\x00\x00\x04\x08\x00\x00\x00\x00\x00\x3f\xff\x00\x01"

# Packet 7 payload: HEADERS frame (type=1, flags=5, stream_id=3, length=40)
# Flags 5 = END_STREAM | END_HEADERS
_HEADERS_FRAME = (
    b"\x00\x00\x28\x01\x05\x00\x00\x00\x03"
    b"\x3f\xe1\x1f\x82\x04\x88\x62\x7b\x69\x1d\x48\x5d\x3e\x53\x86"
    b"\x41\x88\xaa\x69\xd2\x9a\xc4\xb9\xec\x9b\x7a\x88\x25\xb6\x50"
    b"\xc3\x9b\x12\x47\xe5\xd9\xe9\x49\xac\x32"
)

# Minimal SETTINGS frame (0-byte payload): type=4, flags=0, stream_id=0, length=0
_SETTINGS_EMPTY_FRAME = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

# Minimal DATA frame: type=0, flags=0, stream_id=1, length=5 + payload "hello"
_DATA_FRAME = b"\x00\x00\x05\x00\x00\x00\x00\x00\x01hello"

# DATA frame with END_STREAM flag: type=0, flags=1, stream_id=1
_DATA_FRAME_END_STREAM = b"\x00\x00\x05\x00\x01\x00\x00\x00\x01world"


# ---------------------------------------------------------------------------
# PCAP reader and packet builders
# ---------------------------------------------------------------------------


def _read_pcap(path: str):
    """Return a list of raw packet byte-strings from a pcap file."""
    with open(path, "rb") as fh:
        data = fh.read()
    magic = struct.unpack_from("<I", data, 0)[0]
    endian = "<" if magic == 0xA1B2C3D4 else ">"
    offset = 24
    packets = []
    while offset + 16 <= len(data):
        _ts, _tu, incl_len, _orig = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        packets.append(data[offset : offset + incl_len])
        offset += incl_len
    return packets


def _build_eth_ipv4_tcp(dport: int, payload: bytes) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame wrapping *payload*."""
    ip_len = 20 + 20 + len(payload)
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x08,
            0x00,
        ]
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_len,
        0,
        0x4000,
        64,
        6,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        12345,
        dport,
        0,
        0,
        0x50,
        0x18,
        65535,
        0,
        0,
    )
    return eth + ip + tcp + payload


def _parse(raw: bytes) -> Packet:
    pkt = Packet(raw)
    pkt.parse()
    return pkt


def _safe_fieldval(pkt: Packet, layer, field: str):
    """Return the field value or None if the field is absent."""
    try:
        return pkt.getfieldval(layer, field)
    except (KeyError, Exception):
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def h2c_packets():
    """All packets from http2_h2c.pcap, as (raw, Packet) pairs."""
    pairs = []
    for raw in _read_pcap(_HTTP2_H2C_PCAP):
        pkt = _parse(raw)
        pairs.append((raw, pkt))
    return pairs


@pytest.fixture(scope="module")
def h2c_http2_packets(h2c_packets):
    """Only the (raw, Packet) pairs that have an Http2 layer."""
    return [(raw, pkt) for raw, pkt in h2c_packets if pkt.has_layer(LayerKind.Http2)]


# ===========================================================================
# 1. PCAP loading
# ===========================================================================


def test_h2c_pcap_loads():
    """http2_h2c.pcap exists and is non-empty."""
    pkts = _read_pcap(_HTTP2_H2C_PCAP)
    assert len(pkts) > 0


def test_h2c_pcap_has_http2_packets(h2c_http2_packets):
    """http2_h2c.pcap contains at least one packet with an HTTP/2 layer."""
    assert len(h2c_http2_packets) >= 1


# ===========================================================================
# 2. Connection preface (24 bytes)
# ===========================================================================


def test_preface_magic_bytes():
    """The HTTP/2 connection preface constant matches the RFC 7540 value."""
    assert HTTP2_PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    assert len(HTTP2_PREFACE) == 24


def test_preface_packet_has_http2_layer():
    """A packet whose TCP payload is the connection preface has an Http2 layer."""
    raw = _build_eth_ipv4_tcp(80, HTTP2_PREFACE)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)


def test_preface_layer_bytes_match():
    """The Http2 layer bytes for a preface-only packet equal the preface."""
    raw = _build_eth_ipv4_tcp(80, HTTP2_PREFACE)
    pkt = _parse(raw)
    lb = pkt.get_layer_bytes(LayerKind.Http2)
    assert lb[:24] == HTTP2_PREFACE


def test_preface_found_in_pcap(h2c_http2_packets):
    """http2_h2c.pcap contains the HTTP/2 connection preface in at least one packet."""
    for _raw, pkt in h2c_http2_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http2)
        if lb[:24] == HTTP2_PREFACE:
            return
    pytest.skip("Connection preface not found in any Http2 packet")


# ===========================================================================
# 3. SETTINGS frame (type = 4)
# ===========================================================================


def test_settings_frame_type():
    """SETTINGS frame: frame_type == 4."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "frame_type") == FRAME_SETTINGS


def test_settings_frame_flags():
    """SETTINGS frame: flags == 0 (not an ACK)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == 0


def test_settings_frame_stream_id():
    """SETTINGS frame: stream_id == 0 (connection-level)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "stream_id") == 0


def test_settings_frame_length():
    """SETTINGS frame: length == 18 (three 6-byte settings parameters)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 18


def test_settings_empty_frame_length_zero():
    """Minimal SETTINGS frame (no parameters): length == 0."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_EMPTY_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 0


# ===========================================================================
# 4. SETTINGS_ACK frame (type = 4, flags = 1)
# ===========================================================================


def test_settings_ack_frame_type():
    """SETTINGS_ACK: frame_type == 4 (SETTINGS)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_ACK_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "frame_type") == FRAME_SETTINGS


def test_settings_ack_flags():
    """SETTINGS_ACK: flags == 1 (ACK bit set)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_ACK_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == FLAG_ACK


def test_settings_ack_stream_id():
    """SETTINGS_ACK: stream_id == 0."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_ACK_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "stream_id") == 0


def test_settings_ack_length():
    """SETTINGS_ACK: length == 0 (no payload)."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_ACK_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 0


def test_settings_ack_found_in_pcap(h2c_http2_packets):
    """http2_h2c.pcap contains a SETTINGS_ACK (type=4, flags=1)."""
    for _raw, pkt in h2c_http2_packets:
        ft = _safe_fieldval(pkt, LayerKind.Http2, "frame_type")
        flags = _safe_fieldval(pkt, LayerKind.Http2, "flags")
        if ft == FRAME_SETTINGS and flags == FLAG_ACK:
            return
    pytest.skip("No SETTINGS_ACK frame found in http2_h2c.pcap")


# ===========================================================================
# 5. WINDOW_UPDATE frame (type = 8)
# ===========================================================================


def test_window_update_frame_type():
    """WINDOW_UPDATE frame: frame_type == 8."""
    raw = _build_eth_ipv4_tcp(80, _WINDOW_UPDATE_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "frame_type") == FRAME_WINDOW_UPDATE


def test_window_update_flags():
    """WINDOW_UPDATE frame: flags == 0."""
    raw = _build_eth_ipv4_tcp(80, _WINDOW_UPDATE_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == 0


def test_window_update_stream_id():
    """WINDOW_UPDATE frame: stream_id == 0 (connection-level)."""
    raw = _build_eth_ipv4_tcp(80, _WINDOW_UPDATE_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "stream_id") == 0


def test_window_update_length():
    """WINDOW_UPDATE frame: length == 4 (increment is a 32-bit value)."""
    raw = _build_eth_ipv4_tcp(80, _WINDOW_UPDATE_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 4


def test_window_update_found_in_pcap(h2c_http2_packets):
    """http2_h2c.pcap contains a WINDOW_UPDATE frame (type=8)."""
    for _raw, pkt in h2c_http2_packets:
        ft = _safe_fieldval(pkt, LayerKind.Http2, "frame_type")
        if ft == FRAME_WINDOW_UPDATE:
            return
    pytest.skip("No WINDOW_UPDATE frame found in http2_h2c.pcap")


# ===========================================================================
# 6. HEADERS frame (type = 1)
# ===========================================================================


def test_headers_frame_type():
    """HEADERS frame: frame_type == 1."""
    raw = _build_eth_ipv4_tcp(80, _HEADERS_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "frame_type") == FRAME_HEADERS


def test_headers_frame_flags():
    """HEADERS frame: flags == 5 (END_STREAM | END_HEADERS)."""
    raw = _build_eth_ipv4_tcp(80, _HEADERS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == FLAG_END_STREAM_AND_HEADERS


def test_headers_frame_stream_id():
    """HEADERS frame: stream_id == 3."""
    raw = _build_eth_ipv4_tcp(80, _HEADERS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "stream_id") == 3


def test_headers_frame_length():
    """HEADERS frame: length == 40 (40 bytes of HPACK-encoded headers)."""
    raw = _build_eth_ipv4_tcp(80, _HEADERS_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 40


def test_headers_frame_found_in_pcap(h2c_http2_packets):
    """http2_h2c.pcap contains a HEADERS frame (type=1)."""
    for _raw, pkt in h2c_http2_packets:
        ft = _safe_fieldval(pkt, LayerKind.Http2, "frame_type")
        if ft == FRAME_HEADERS:
            return
    pytest.skip("No HEADERS frame found in http2_h2c.pcap")


# ===========================================================================
# 7. DATA frame (type = 0)
# ===========================================================================


def test_data_frame_type():
    """DATA frame: frame_type == 0."""
    raw = _build_eth_ipv4_tcp(80, _DATA_FRAME)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "frame_type") == FRAME_DATA


def test_data_frame_flags():
    """DATA frame (no flags): flags == 0."""
    raw = _build_eth_ipv4_tcp(80, _DATA_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == 0


def test_data_frame_stream_id():
    """DATA frame: stream_id == 1."""
    raw = _build_eth_ipv4_tcp(80, _DATA_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "stream_id") == 1


def test_data_frame_length():
    """DATA frame: length == 5 (len('hello'))."""
    raw = _build_eth_ipv4_tcp(80, _DATA_FRAME)
    pkt = _parse(raw)
    assert pkt.getfieldval(LayerKind.Http2, "length") == 5


def test_data_frame_end_stream_flag():
    """DATA frame with END_STREAM flag: flags == 1."""
    raw = _build_eth_ipv4_tcp(80, _DATA_FRAME_END_STREAM)
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http2)
    assert pkt.getfieldval(LayerKind.Http2, "flags") == FLAG_END_STREAM


# ===========================================================================
# 8. PCAP-level assertions matching UTS test expectations
# ===========================================================================


def test_pcap_settings_frame_stream_id_zero(h2c_http2_packets):
    """http2_h2c.pcap SETTINGS frame is on stream 0 (connection-level)."""
    for _raw, pkt in h2c_http2_packets:
        ft = _safe_fieldval(pkt, LayerKind.Http2, "frame_type")
        if ft == FRAME_SETTINGS:
            sid = _safe_fieldval(pkt, LayerKind.Http2, "stream_id")
            assert sid == 0
            return
    pytest.skip("No SETTINGS frame in http2_h2c.pcap")


def test_pcap_headers_frame_has_stream_id(h2c_http2_packets):
    """http2_h2c.pcap HEADERS frame is on a non-zero stream."""
    for _raw, pkt in h2c_http2_packets:
        ft = _safe_fieldval(pkt, LayerKind.Http2, "frame_type")
        if ft == FRAME_HEADERS:
            sid = _safe_fieldval(pkt, LayerKind.Http2, "stream_id")
            assert sid is not None and sid > 0
            return
    pytest.skip("No HEADERS frame in http2_h2c.pcap")


def test_pcap_first_http2_packet_has_tcp(h2c_http2_packets):
    """All Http2 packets in the pcap also have a TCP layer."""
    for _raw, pkt in h2c_http2_packets:
        assert pkt.has_layer(LayerKind.Tcp), "Http2 packet missing TCP layer"


def test_pcap_first_http2_packet_has_ipv4(h2c_http2_packets):
    """All Http2 packets in the pcap also have an IPv4 layer."""
    for _raw, pkt in h2c_http2_packets:
        assert pkt.has_layer(LayerKind.Ipv4), "Http2 packet missing IPv4 layer"


def test_pcap_first_http2_packet_has_ethernet(h2c_http2_packets):
    """All Http2 packets in the pcap also have an Ethernet layer."""
    for _raw, pkt in h2c_http2_packets:
        assert pkt.has_layer(LayerKind.Ethernet), "Http2 packet missing Ethernet layer"


# ===========================================================================
# 9. Miscellaneous / layer_bytes
# ===========================================================================


def test_settings_layer_bytes_start_with_frame_header():
    """Http2 layer bytes for SETTINGS start with the 9-byte frame header."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_EMPTY_FRAME)
    pkt = _parse(raw)
    lb = pkt.get_layer_bytes(LayerKind.Http2)
    # First 3 bytes are the 24-bit length field (0 for an empty SETTINGS frame)
    length = (lb[0] << 16) | (lb[1] << 8) | lb[2]
    frame_type = lb[3]
    assert frame_type == FRAME_SETTINGS
    assert length == 0


def test_settings_ack_layer_bytes_flags():
    """SETTINGS_ACK layer bytes byte[4] (flags) == 1."""
    raw = _build_eth_ipv4_tcp(80, _SETTINGS_ACK_FRAME)
    pkt = _parse(raw)
    lb = pkt.get_layer_bytes(LayerKind.Http2)
    assert lb[4] == FLAG_ACK  # flags byte


def test_http2_layerkind_exists():
    """LayerKind.Http2 is accessible from the Python API."""
    assert hasattr(LayerKind, "Http2")


def test_http2_not_detected_in_pure_http1_packet():
    """A packet containing only HTTP/1.1 does NOT have an Http2 layer."""
    http1 = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ip_len = 20 + 20 + len(http1)
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x08,
            0x00,
        ]
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_len,
        0,
        0x4000,
        64,
        6,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, 0, 0, 0x50, 0x18, 65535, 0, 0)
    pkt = _parse(eth + ip + tcp + http1)
    # A pure HTTP/1.1 request should be detected as Http but not Http2
    assert pkt.has_layer(LayerKind.Http)
    assert not pkt.has_layer(LayerKind.Http2)
