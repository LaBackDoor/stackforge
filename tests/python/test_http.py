"""Tests for HTTP/1.x protocol parsing and field access via the Python API.

HTTP parsing is tested via raw bytes parsed as Packet, since HTTP layers
are identified by the stackforge engine when carried over TCP.
"""

import struct

from stackforge import LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_raw_http_request(
    method: str = "GET",
    uri: str = "/",
    version: str = "HTTP/1.1",
    headers: dict = None,
    body: bytes = b"",
) -> bytes:
    """Build a raw HTTP/1.x request byte string."""
    lines = [f"{method} {uri} {version}\r\n"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    raw = "".join(lines).encode() + body
    return raw


def _build_raw_http_response(
    status: int = 200,
    reason: str = "OK",
    version: str = "HTTP/1.1",
    headers: dict = None,
    body: bytes = b"",
) -> bytes:
    """Build a raw HTTP/1.x response byte string."""
    lines = [f"{version} {status} {reason}\r\n"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    raw = "".join(lines).encode() + body
    return raw


def _eth_ipv4_tcp_prefix(payload_len: int) -> bytes:
    """Build Ethernet/IPv4/TCP header prepended to HTTP payload."""
    tcp_len = 20
    ip_len = 20 + tcp_len + payload_len
    # Ethernet (14)
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
    # IPv4 (20)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,  # version/IHL, DSCP/ECN
        ip_len,
        0,  # total length, ID
        0x4000,
        64,
        6,
        0,  # flags/frag, TTL, proto=TCP, checksum
        bytes([10, 0, 0, 1]),  # src
        bytes([10, 0, 0, 2]),  # dst
    )
    # TCP (20 bytes, minimal — data offset=5)
    tcp = struct.pack(
        "!HHIIBBHHH",
        12345,
        80,  # sport=12345, dport=80
        0,
        0,  # seq=0, ack=0
        0x50,
        0x18,  # data_offset=5<<4, flags=ACK
        65535,
        0,
        0,  # window, checksum, urgent
    )
    return eth + ip + tcp


def _packet_with_http_request(method="GET", uri="/", headers=None, body=b"") -> Packet:
    """Build a Packet containing an HTTP request over Ethernet/IPv4/TCP."""
    http_bytes = _build_raw_http_request(method, uri, headers=headers, body=body)
    prefix = _eth_ipv4_tcp_prefix(len(http_bytes))
    raw = prefix + http_bytes
    pkt = Packet(raw)
    pkt.parse()
    return pkt


def _packet_with_http_response(status=200, reason="OK", headers=None, body=b"") -> Packet:
    """Build a Packet containing an HTTP response over Ethernet/IPv4/TCP."""
    http_bytes = _build_raw_http_response(status, reason, headers=headers, body=body)
    prefix = _eth_ipv4_tcp_prefix(len(http_bytes))
    raw = prefix + http_bytes
    pkt = Packet(raw)
    pkt.parse()
    return pkt


# ---------------------------------------------------------------------------
# LayerKind.Http existence
# ---------------------------------------------------------------------------


def test_layerkind_http_exists():
    assert hasattr(LayerKind, "Http")


# ---------------------------------------------------------------------------
# HTTP GET request parse
# ---------------------------------------------------------------------------


def test_http_get_request_has_http_layer():
    pkt = _packet_with_http_request("GET", "/index.html")
    assert pkt.has_layer(LayerKind.Http)


def test_http_get_method():
    pkt = _packet_with_http_request("GET", "/index.html")
    assert pkt.has_layer(LayerKind.Http)
    method = pkt.getfieldval(LayerKind.Http, "method")
    assert method == b"GET" or method == "GET"


def test_http_get_uri():
    pkt = _packet_with_http_request("GET", "/api/data")
    assert pkt.has_layer(LayerKind.Http)
    uri = pkt.getfieldval(LayerKind.Http, "uri")
    assert uri == b"/api/data" or uri == "/api/data"


def test_http_get_version():
    pkt = _packet_with_http_request("GET", "/")
    assert pkt.has_layer(LayerKind.Http)
    version = pkt.getfieldval(LayerKind.Http, "version")
    assert version == b"HTTP/1.1" or version == "HTTP/1.1"


# ---------------------------------------------------------------------------
# HTTP POST request parse
# ---------------------------------------------------------------------------


def test_http_post_request_method():
    pkt = _packet_with_http_request("POST", "/submit")
    assert pkt.has_layer(LayerKind.Http)
    method = pkt.getfieldval(LayerKind.Http, "method")
    assert method == b"POST" or method == "POST"


def test_http_post_request_uri():
    pkt = _packet_with_http_request("POST", "/api/v2/items")
    assert pkt.has_layer(LayerKind.Http)
    uri = pkt.getfieldval(LayerKind.Http, "uri")
    assert b"items" in (uri if isinstance(uri, bytes) else uri.encode())


def test_http_post_with_body_and_content_length():
    body = b"key=value"
    headers = {"Content-Length": str(len(body))}
    pkt = _packet_with_http_request("POST", "/submit", headers=headers, body=body)
    assert pkt.has_layer(LayerKind.Http)


# ---------------------------------------------------------------------------
# HTTP response 200 OK parse
# ---------------------------------------------------------------------------


def test_http_response_200_has_http_layer():
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)


def test_http_response_200_status_code():
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)
    status = pkt.getfieldval(LayerKind.Http, "status_code")
    assert status == 200


def test_http_response_200_reason():
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)
    reason = pkt.getfieldval(LayerKind.Http, "reason")
    assert reason == b"OK" or reason == "OK"


# ---------------------------------------------------------------------------
# HTTP response 404 parse
# ---------------------------------------------------------------------------


def test_http_response_404_status_code():
    pkt = _packet_with_http_response(404, "Not Found")
    assert pkt.has_layer(LayerKind.Http)
    status = pkt.getfieldval(LayerKind.Http, "status_code")
    assert status == 404


def test_http_response_404_reason():
    pkt = _packet_with_http_response(404, "Not Found")
    assert pkt.has_layer(LayerKind.Http)
    reason = pkt.getfieldval(LayerKind.Http, "reason")
    assert b"Not Found" in (reason if isinstance(reason, bytes) else reason.encode())


# ---------------------------------------------------------------------------
# TCP + HTTP stack: HTTP must be detected
# ---------------------------------------------------------------------------


def test_tcp_http_stack_has_tcp_layer():
    pkt = _packet_with_http_request("GET", "/")
    assert pkt.has_layer(LayerKind.Tcp)


def test_tcp_http_stack_has_ipv4_layer():
    pkt = _packet_with_http_request("GET", "/")
    assert pkt.has_layer(LayerKind.Ipv4)


def test_tcp_http_stack_has_ethernet_layer():
    pkt = _packet_with_http_request("GET", "/")
    assert pkt.has_layer(LayerKind.Ethernet)


# ---------------------------------------------------------------------------
# HTTP field: version
# ---------------------------------------------------------------------------


def test_http_response_version_11():
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)
    version = pkt.getfieldval(LayerKind.Http, "version")
    assert version == b"HTTP/1.1" or version == "HTTP/1.1"


def test_http_request_version_10():
    http_bytes = _build_raw_http_request(version="HTTP/1.0")
    prefix = _eth_ipv4_tcp_prefix(len(http_bytes))
    pkt = Packet(prefix + http_bytes)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Http)
    version = pkt.getfieldval(LayerKind.Http, "version")
    assert version == b"HTTP/1.0" or version == "HTTP/1.0"


# ---------------------------------------------------------------------------
# Header value lookup
# ---------------------------------------------------------------------------


def test_http_layer_bytes_contains_host_header():
    pkt = _packet_with_http_request("GET", "/", headers={"Host": "example.com"})
    assert pkt.has_layer(LayerKind.Http)
    http_bytes = pkt.get_layer_bytes(LayerKind.Http)
    assert b"Host: example.com" in http_bytes


def test_http_layer_bytes_contains_content_type():
    headers = {"Content-Type": "application/json"}
    pkt = _packet_with_http_request("POST", "/api", headers=headers, body=b"{}")
    assert pkt.has_layer(LayerKind.Http)
    http_bytes = pkt.get_layer_bytes(LayerKind.Http)
    assert b"Content-Type: application/json" in http_bytes


# ---------------------------------------------------------------------------
# Various HTTP methods
# ---------------------------------------------------------------------------


def test_http_delete_request():
    pkt = _packet_with_http_request("DELETE", "/resource/1")
    assert pkt.has_layer(LayerKind.Http)
    method = pkt.getfieldval(LayerKind.Http, "method")
    assert method == b"DELETE" or method == "DELETE"


def test_http_put_request():
    pkt = _packet_with_http_request("PUT", "/resource/1")
    assert pkt.has_layer(LayerKind.Http)
    method = pkt.getfieldval(LayerKind.Http, "method")
    assert method == b"PUT" or method == "PUT"


def test_http_head_request():
    pkt = _packet_with_http_request("HEAD", "/")
    assert pkt.has_layer(LayerKind.Http)
    method = pkt.getfieldval(LayerKind.Http, "method")
    assert method == b"HEAD" or method == "HEAD"


# ---------------------------------------------------------------------------
# HTTP response codes
# ---------------------------------------------------------------------------


def test_http_response_201_created():
    pkt = _packet_with_http_response(201, "Created")
    assert pkt.has_layer(LayerKind.Http)
    status = pkt.getfieldval(LayerKind.Http, "status_code")
    assert status == 201


def test_http_response_500_server_error():
    pkt = _packet_with_http_response(500, "Internal Server Error")
    assert pkt.has_layer(LayerKind.Http)
    status = pkt.getfieldval(LayerKind.Http, "status_code")
    assert status == 500


def test_http_response_301_moved_permanently():
    pkt = _packet_with_http_response(301, "Moved Permanently")
    assert pkt.has_layer(LayerKind.Http)
    status = pkt.getfieldval(LayerKind.Http, "status_code")
    assert status == 301


# ---------------------------------------------------------------------------
# HTTP get_layer_bytes
# ---------------------------------------------------------------------------


def test_http_get_layer_bytes_starts_with_method():
    pkt = _packet_with_http_request("GET", "/path")
    assert pkt.has_layer(LayerKind.Http)
    b = pkt.get_layer_bytes(LayerKind.Http)
    assert b.startswith(b"GET /path")


def test_http_get_layer_bytes_response_starts_with_http():
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)
    b = pkt.get_layer_bytes(LayerKind.Http)
    assert b.startswith(b"HTTP/1.1 200 OK")


# ---------------------------------------------------------------------------
# fields property for HTTP
# ---------------------------------------------------------------------------


def test_http_fields_property():
    pkt = _packet_with_http_request("GET", "/")
    assert pkt.has_layer(LayerKind.Http)
    fields = pkt.fields
    assert isinstance(fields, list)


# ---------------------------------------------------------------------------
# Negative tests: request fields return None for response
# ---------------------------------------------------------------------------


def test_http_response_method_returns_none():
    """HTTP response should not expose a 'method' field value."""
    pkt = _packet_with_http_response(200, "OK")
    assert pkt.has_layer(LayerKind.Http)
    # method field doesn't apply to responses — should return None or raise KeyError
    try:
        method = pkt.getfieldval(LayerKind.Http, "method")
        assert method is None
    except (KeyError, AttributeError):
        pass  # field not found in response — expected behavior
