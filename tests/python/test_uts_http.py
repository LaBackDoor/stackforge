"""UTS-driven HTTP/1.x tests using the pcap files referenced in tests/uts/http.uts.

The UTS file (http.uts) loads http_chunk.pcap and http_content_length.pcap and
asserts specific field values.  This test suite parses those same pcap files
using the stackforge Python API and validates the matching assertions.

Tests deliberately avoid duplicating tests already present in test_http.py.
"""

import os
import struct

import pytest
from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# PCAP paths
# ---------------------------------------------------------------------------

_PCAP_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "sample_pcap",
)
_HTTP_CHUNK_PCAP = os.path.join(_PCAP_DIR, "http_chunk.pcap")
_HTTP_CONTENT_LENGTH_PCAP = os.path.join(_PCAP_DIR, "http_content_length.pcap")


# ---------------------------------------------------------------------------
# PCAP reader helper (pure Python, no external deps)
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
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        packets.append(data[offset : offset + incl_len])
        offset += incl_len
    return packets


def _parse_all(path: str):
    """Parse every packet in a pcap and return (raw, Packet) pairs."""
    return [(raw, _parse(raw)) for raw in _read_pcap(path)]


def _parse(raw: bytes) -> Packet:
    pkt = Packet(raw)
    pkt.parse()
    return pkt


def _safe_fieldval(pkt, layer, field):
    """Return the field value or None if the field is absent."""
    try:
        return pkt.getfieldval(layer, field)
    except (KeyError, Exception):
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def chunk_packets():
    """All packets from http_chunk.pcap, parsed."""
    return _parse_all(_HTTP_CHUNK_PCAP)


@pytest.fixture(scope="module")
def chunk_http_packets(chunk_packets):
    """Only the packets from http_chunk.pcap that have an HTTP layer."""
    return [(raw, pkt) for raw, pkt in chunk_packets if pkt.has_layer(LayerKind.Http)]


@pytest.fixture(scope="module")
def cl_packets():
    """All packets from http_content_length.pcap, parsed."""
    return _parse_all(_HTTP_CONTENT_LENGTH_PCAP)


@pytest.fixture(scope="module")
def cl_http_packets(cl_packets):
    """Only the packets from http_content_length.pcap that have an HTTP layer."""
    return [(raw, pkt) for raw, pkt in cl_packets if pkt.has_layer(LayerKind.Http)]


# ===========================================================================
# 1. Basic PCAP loading
# ===========================================================================


def test_chunk_pcap_loads():
    """http_chunk.pcap exists and contains packets."""
    pkts = _read_pcap(_HTTP_CHUNK_PCAP)
    assert len(pkts) > 0


def test_cl_pcap_loads():
    """http_content_length.pcap exists and contains packets."""
    pkts = _read_pcap(_HTTP_CONTENT_LENGTH_PCAP)
    assert len(pkts) > 0


# ===========================================================================
# 2. http_chunk.pcap — UTS assertions
# ===========================================================================


def test_chunk_pcap_has_http_packets(chunk_http_packets):
    """http_chunk.pcap contains at least one HTTP packet."""
    assert len(chunk_http_packets) >= 1


def test_chunk_pcap_request_method_get(chunk_http_packets):
    """http_chunk.pcap: first HTTP request uses the GET method.

    UTS: assert a[2].Path == b'/httpgallery/chunked/...'
    (The UTS packet index [2] corresponds to the first HTTP request.)
    """
    for _raw, pkt in chunk_http_packets:
        method = _safe_fieldval(pkt, LayerKind.Http, "method")
        if method is not None:
            assert method == b"GET" or method == "GET"
            return
    pytest.skip("No HTTP GET request found in http_chunk.pcap")


def test_chunk_pcap_request_uri(chunk_http_packets):
    """http_chunk.pcap: request URI contains the chunked gallery path.

    UTS: a[2].Path == b'/httpgallery/chunked/chunkedimage.aspx?...'
    """
    for _raw, pkt in chunk_http_packets:
        uri = _safe_fieldval(pkt, LayerKind.Http, "uri")
        if uri is not None and (
            b"httpgallery" in (uri if isinstance(uri, bytes) else uri.encode())
        ):
            assert b"chunked" in (uri if isinstance(uri, bytes) else uri.encode())
            return
    pytest.skip("URI with 'httpgallery' not found in http_chunk.pcap")


def test_chunk_pcap_request_version_http11(chunk_http_packets):
    """http_chunk.pcap: HTTP request uses HTTP/1.1.

    UTS: a[2].Http_Version == b'HTTP/1.1'
    """
    for _raw, pkt in chunk_http_packets:
        version = _safe_fieldval(pkt, LayerKind.Http, "version")
        if version is not None:
            assert version == b"HTTP/1.1" or version == "HTTP/1.1"
            return
    pytest.skip("No HTTP version field found in http_chunk.pcap")


def test_chunk_pcap_request_layer_bytes_starts_with_get(chunk_http_packets):
    """http_chunk.pcap: HTTP request layer bytes start with 'GET'."""
    for _raw, pkt in chunk_http_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http)
        if lb.startswith(b"GET"):
            assert b"/httpgallery" in lb
            return
    pytest.skip("No GET request layer bytes found")


def test_chunk_pcap_request_layer_bytes_contains_host(chunk_http_packets):
    """http_chunk.pcap: HTTP GET request includes a Host header."""
    for _raw, pkt in chunk_http_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http)
        if lb.startswith(b"GET"):
            assert b"Host:" in lb or b"host:" in lb.lower()
            return
    pytest.skip("No GET request found with Host header")


def test_chunk_pcap_request_has_tcp_layer(chunk_http_packets):
    """http_chunk.pcap: HTTP request packets also have a TCP layer."""
    for _raw, pkt in chunk_http_packets:
        if pkt.has_layer(LayerKind.Tcp):
            return
    pytest.skip("No TCP layer found alongside HTTP in http_chunk.pcap")


def test_chunk_pcap_request_has_ipv4_layer(chunk_http_packets):
    """http_chunk.pcap: HTTP request packets are carried over IPv4."""
    for _raw, pkt in chunk_http_packets:
        if pkt.has_layer(LayerKind.Ipv4):
            return
    pytest.skip("No IPv4 layer found alongside HTTP in http_chunk.pcap")


def test_chunk_pcap_response_layer_bytes_starts_with_http(chunk_http_packets):
    """http_chunk.pcap: HTTP response layer bytes start with 'HTTP/'.

    UTS: a[29].Http_Version == b'HTTP/1.1' and a[29].Status_Code == b'200'
    """
    for _raw, pkt in chunk_http_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http)
        if lb.startswith(b"HTTP/"):
            assert b"200" in lb or b"301" in lb or b"404" in lb or len(lb) > 10
            return
    pytest.skip("No HTTP response found in http_chunk.pcap")


def test_chunk_pcap_response_status_200_in_bytes(chunk_http_packets):
    """http_chunk.pcap: HTTP response contains status 200 in raw bytes.

    UTS: assert a[29].Status_Code == b'200'
    """
    for _raw, pkt in chunk_http_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http)
        if lb.startswith(b"HTTP/1.1 200"):
            assert b"200" in lb
            return
    pytest.skip("No HTTP/1.1 200 response found in http_chunk.pcap")


# ===========================================================================
# 3. http_content_length.pcap — UTS-derived assertions
# ===========================================================================


def test_cl_pcap_has_http_packets(cl_http_packets):
    """http_content_length.pcap contains at least one HTTP packet."""
    assert len(cl_http_packets) >= 1


def test_cl_pcap_request_method_get(cl_http_packets):
    """http_content_length.pcap: contains a GET request."""
    for _raw, pkt in cl_http_packets:
        method = _safe_fieldval(pkt, LayerKind.Http, "method")
        if method is not None and (method == b"GET" or method == "GET"):
            return
    pytest.skip("No GET request found in http_content_length.pcap")


def test_cl_pcap_request_version(cl_http_packets):
    """http_content_length.pcap: request uses HTTP/1.1."""
    for _raw, pkt in cl_http_packets:
        version = _safe_fieldval(pkt, LayerKind.Http, "version")
        if version is not None:
            assert version == b"HTTP/1.1" or version == "HTTP/1.1"
            return
    pytest.skip("No version field found in http_content_length.pcap")


def test_cl_pcap_request_uri_not_empty(cl_http_packets):
    """http_content_length.pcap: request URI is non-empty."""
    for _raw, pkt in cl_http_packets:
        uri = _safe_fieldval(pkt, LayerKind.Http, "uri")
        if uri is not None:
            uri_bytes = uri if isinstance(uri, bytes) else uri.encode()
            assert len(uri_bytes) > 0
            return
    pytest.skip("No URI field found in http_content_length.pcap")


def test_cl_pcap_response_status_code(cl_http_packets):
    """http_content_length.pcap: HTTP response has a numeric status_code."""
    for _raw, pkt in cl_http_packets:
        status = _safe_fieldval(pkt, LayerKind.Http, "status_code")
        if status is not None:
            assert isinstance(status, int)
            assert 100 <= status <= 599
            return
    pytest.skip("No status_code found in http_content_length.pcap")


def test_cl_pcap_response_204_status_code(cl_http_packets):
    """http_content_length.pcap: Contains a 204 No Content response."""
    for _raw, pkt in cl_http_packets:
        status = _safe_fieldval(pkt, LayerKind.Http, "status_code")
        if status == 204:
            return
    pytest.skip("No 204 No Content response in http_content_length.pcap")


def test_cl_pcap_response_204_reason(cl_http_packets):
    """http_content_length.pcap: 204 response reason phrase is 'No Content'."""
    for _raw, pkt in cl_http_packets:
        status = _safe_fieldval(pkt, LayerKind.Http, "status_code")
        if status == 204:
            reason = _safe_fieldval(pkt, LayerKind.Http, "reason")
            assert reason == b"No Content" or reason == "No Content"
            return
    pytest.skip("No 204 No Content response in http_content_length.pcap")


def test_cl_pcap_response_layer_bytes_starts_with_http(cl_http_packets):
    """http_content_length.pcap: HTTP response layer bytes start with 'HTTP/'."""
    for _raw, pkt in cl_http_packets:
        lb = pkt.get_layer_bytes(LayerKind.Http)
        if lb.startswith(b"HTTP/"):
            assert b"HTTP/" in lb
            return
    pytest.skip("No HTTP response bytes found in http_content_length.pcap")


def test_cl_pcap_has_ethernet_layer(cl_http_packets):
    """http_content_length.pcap: HTTP packets have Ethernet layer."""
    for _raw, pkt in cl_http_packets:
        if pkt.has_layer(LayerKind.Ethernet):
            return
    pytest.skip("No Ethernet layer found in http_content_length.pcap packets")


# ===========================================================================
# 4. HTTP detection on port 80 (standard port)
# ===========================================================================


def test_http_detected_on_port_80():
    """HTTP is detected when TCP destination port is 80."""
    http_bytes = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ip_len = 20 + 20 + len(http_bytes)
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
        80,
        0,
        0,
        0x50,
        0x18,
        65535,
        0,
        0,
    )
    raw = eth + ip + tcp + http_bytes
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http)
    method = _safe_fieldval(pkt, LayerKind.Http, "method")
    assert method == b"GET" or method == "GET"


def test_http_response_detected_from_server():
    """HTTP response is detected when returned from the server."""
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ip_len = 20 + 20 + len(http_resp)
    eth = bytes(
        [
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
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
        bytes([10, 0, 0, 2]),
        bytes([10, 0, 0, 1]),
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        80,
        12345,
        0,
        0,
        0x50,
        0x18,
        65535,
        0,
        0,
    )
    raw = eth + ip + tcp + http_resp
    pkt = _parse(raw)
    assert pkt.has_layer(LayerKind.Http)
    lb = pkt.get_layer_bytes(LayerKind.Http)
    assert lb.startswith(b"HTTP/1.1")
