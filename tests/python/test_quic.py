"""Tests for QUIC protocol parsing and field access via the Python API.

QUIC is detected when carried over UDP with destination port 443 or 4433.
We test via raw bytes parsed as Packet (Ethernet/IPv4/UDP/QUIC) since
the QUIC Python builder class (`QUIC`) can also construct packets directly.
"""

import struct

from stackforge import QUIC, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_udp(dport: int, payload: bytes) -> bytes:
    """Build Ethernet/IPv4/UDP prefix with the given destination port."""
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len

    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst MAC (broadcast)
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,  # src MAC
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
            0x01,  # ID
            0x40,
            0x00,  # DF flag, frag offset
            0x40,  # TTL=64
            0x11,  # protocol=UDP (17)
            0x00,
            0x00,  # checksum (not validated)
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

    return eth + ip + udp + payload


def _make_quic_initial_bytes(
    dst_conn_id: bytes = b"\x01\x02\x03\x04",
    src_conn_id: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    """Build a minimal QUIC Initial long-header packet."""
    quic = QUIC.initial(
        dst_conn_id=list(dst_conn_id),
        src_conn_id=list(src_conn_id) if src_conn_id else None,
        payload=list(payload) if payload else None,
    )
    return bytes(quic.build())


def _make_quic_one_rtt_bytes(payload: bytes = b"\x01") -> bytes:
    """Build a minimal QUIC 1-RTT (short-header) packet."""
    quic = QUIC.one_rtt(payload=list(payload))
    return bytes(quic.build())


def _packet_with_quic_initial(
    dport: int = 443,
    dst_conn_id: bytes = b"\x01\x02\x03\x04",
) -> Packet:
    """Build a Packet containing a QUIC Initial packet over Ethernet/IPv4/UDP."""
    quic_bytes = _make_quic_initial_bytes(dst_conn_id=dst_conn_id)
    prefix = _build_eth_ipv4_udp(dport, quic_bytes)
    pkt = Packet(prefix + quic_bytes)
    pkt.parse()
    return pkt


def _packet_with_quic_one_rtt(dport: int = 443) -> Packet:
    """Build a Packet containing a QUIC 1-RTT packet over Ethernet/IPv4/UDP."""
    quic_bytes = _make_quic_one_rtt_bytes()
    prefix = _build_eth_ipv4_udp(dport, quic_bytes)
    pkt = Packet(prefix + quic_bytes)
    pkt.parse()
    return pkt


# ---------------------------------------------------------------------------
# LayerKind.Quic existence
# ---------------------------------------------------------------------------


def test_layerkind_quic_exists():
    assert hasattr(LayerKind, "Quic")


# ---------------------------------------------------------------------------
# QUIC builder — basic sanity
# ---------------------------------------------------------------------------


def test_quic_class_importable():
    assert QUIC is not None


def test_quic_initial_builds_bytes():
    quic = QUIC.initial()
    raw = bytes(quic.build())
    assert isinstance(raw, bytes)
    assert len(raw) > 0


def test_quic_initial_long_header_bit():
    quic = QUIC.initial()
    raw = bytes(quic.build())
    # Long header: bit 7 of byte 0 is set
    assert raw[0] & 0x80 == 0x80


def test_quic_initial_fixed_bit():
    quic = QUIC.initial()
    raw = bytes(quic.build())
    # Fixed bit: bit 6 of byte 0 is set
    assert raw[0] & 0x40 == 0x40


def test_quic_initial_packet_type_bits():
    quic = QUIC.initial()
    raw = bytes(quic.build())
    # Initial packet type bits (5-4) should be 0b00
    assert (raw[0] & 0x30) >> 4 == 0x00


def test_quic_handshake_builds_bytes():
    quic = QUIC.handshake()
    raw = bytes(quic.build())
    assert isinstance(raw, bytes)
    assert len(raw) > 0


def test_quic_handshake_packet_type_bits():
    quic = QUIC.handshake()
    raw = bytes(quic.build())
    # Handshake packet type bits (5-4) should be 0b10
    assert (raw[0] & 0x30) >> 4 == 0x02


def test_quic_one_rtt_builds_bytes():
    quic = QUIC.one_rtt()
    raw = bytes(quic.build())
    assert isinstance(raw, bytes)
    assert len(raw) > 0


def test_quic_one_rtt_short_header_bit():
    quic = QUIC.one_rtt(payload=[0x01])
    raw = bytes(quic.build())
    # Short header: bit 7 of byte 0 is 0
    assert raw[0] & 0x80 == 0x00


def test_quic_one_rtt_fixed_bit():
    quic = QUIC.one_rtt(payload=[0x01])
    raw = bytes(quic.build())
    # Fixed bit: bit 6 is set
    assert raw[0] & 0x40 == 0x40


# ---------------------------------------------------------------------------
# QUIC parse via Packet.from_bytes over UDP port 443
# ---------------------------------------------------------------------------


def test_quic_packet_has_quic_layer_port_443():
    pkt = _packet_with_quic_initial(dport=443)
    assert pkt.has_layer(LayerKind.Quic)


def test_quic_packet_has_quic_layer_port_4433():
    pkt = _packet_with_quic_initial(dport=4433)
    assert pkt.has_layer(LayerKind.Quic)


def test_quic_packet_has_udp_layer():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Udp)


def test_quic_packet_has_ipv4_layer():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Ipv4)


def test_quic_packet_has_ethernet_layer():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Ethernet)


# ---------------------------------------------------------------------------
# QUIC field access via getfieldval
# ---------------------------------------------------------------------------


def test_quic_header_form_long():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Quic)
    header_form = pkt.getfieldval(LayerKind.Quic, "header_form")
    assert header_form == 1  # long header


def test_quic_header_form_short():
    pkt = _packet_with_quic_one_rtt()
    assert pkt.has_layer(LayerKind.Quic)
    header_form = pkt.getfieldval(LayerKind.Quic, "header_form")
    assert header_form == 0  # short header


def test_quic_version_field_initial():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Quic)
    version = pkt.getfieldval(LayerKind.Quic, "version")
    assert version == 1  # QUIC v1


def test_quic_header_form_differentiates_short_from_long():
    """Short-header packets have header_form=0; long-header packets have header_form=1."""
    long_pkt = _packet_with_quic_initial()
    short_pkt = _packet_with_quic_one_rtt()
    assert long_pkt.getfieldval(LayerKind.Quic, "header_form") == 1
    assert short_pkt.getfieldval(LayerKind.Quic, "header_form") == 0


def test_quic_packet_type_initial():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Quic)
    ptype = pkt.getfieldval(LayerKind.Quic, "packet_type")
    # Initial packet type = 0
    assert ptype == 0


# ---------------------------------------------------------------------------
# QUIC get_layer_bytes
# ---------------------------------------------------------------------------


def test_quic_get_layer_bytes_initial_long_header():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Quic)
    b = pkt.get_layer_bytes(LayerKind.Quic)
    assert isinstance(b, bytes)
    assert len(b) > 0
    # First byte: long header bit and fixed bit
    assert b[0] & 0x80 == 0x80
    assert b[0] & 0x40 == 0x40


def test_quic_get_layer_bytes_one_rtt_short_header():
    pkt = _packet_with_quic_one_rtt()
    assert pkt.has_layer(LayerKind.Quic)
    b = pkt.get_layer_bytes(LayerKind.Quic)
    assert isinstance(b, bytes)
    assert len(b) > 0
    # First byte: short header — bit 7 is 0, fixed bit (bit 6) is 1
    assert b[0] & 0x80 == 0x00
    assert b[0] & 0x40 == 0x40


# ---------------------------------------------------------------------------
# QUIC builder: dst_conn_id is embedded in the packet
# ---------------------------------------------------------------------------


def test_quic_initial_dst_conn_id_in_bytes():
    conn_id = b"\xde\xad\xbe\xef"
    quic = QUIC.initial(dst_conn_id=list(conn_id))
    raw = bytes(quic.build())
    assert conn_id in raw


def test_quic_initial_with_payload():
    payload = [0x01]  # PING frame
    quic = QUIC.initial(payload=payload)
    raw = bytes(quic.build())
    assert 0x01 in raw


# ---------------------------------------------------------------------------
# QUIC fields property
# ---------------------------------------------------------------------------


def test_quic_fields_property():
    pkt = _packet_with_quic_initial()
    assert pkt.has_layer(LayerKind.Quic)
    fields = pkt.fields
    assert isinstance(fields, list)


# ---------------------------------------------------------------------------
# No QUIC layer when UDP port is not 443/4433
# ---------------------------------------------------------------------------


def test_no_quic_layer_on_non_quic_port():
    quic_bytes = _make_quic_initial_bytes()
    prefix = _build_eth_ipv4_udp(9999, quic_bytes)
    pkt = Packet(prefix + quic_bytes)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Quic)


# ---------------------------------------------------------------------------
# New field tests: long_packet_type, packet_number_len,
#                  dst_conn_id, src_conn_id, dst_conn_id_len,
#                  src_conn_id_len, length, packet_number
# ---------------------------------------------------------------------------


def _packet_with_quic_bytes(quic_bytes: bytes, dport: int = 443) -> "Packet":
    """Wrap raw QUIC bytes in Ethernet/IPv4/UDP and parse."""
    prefix = _build_eth_ipv4_udp(dport, quic_bytes)
    pkt = Packet(prefix + quic_bytes)
    pkt.parse()
    return pkt


def test_quic_long_packet_type_initial():
    quic_bytes = _make_quic_initial_bytes()
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    lpt = pkt.getfieldval(LayerKind.Quic, "long_packet_type")
    assert lpt == 0  # Initial


def test_quic_long_packet_type_handshake():
    quic = QUIC.handshake(dst_conn_id=[0x01, 0x02])
    quic_bytes = bytes(quic.build())
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    lpt = pkt.getfieldval(LayerKind.Quic, "long_packet_type")
    assert lpt == 2  # Handshake


def test_quic_packet_number_len_zero():
    """Default packet_number=0 is encoded in 1 byte; encoded len field = 0."""
    quic_bytes = _make_quic_initial_bytes()
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    pnl = pkt.getfieldval(LayerKind.Quic, "packet_number_len")
    assert pnl == 0  # bits 1-0 = 0 => 1-byte packet number


def test_quic_dst_conn_id_len():
    conn_id = b"\xde\xad\xbe\xef"
    quic_bytes = _make_quic_initial_bytes(dst_conn_id=conn_id)
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    dcil = pkt.getfieldval(LayerKind.Quic, "dst_conn_id_len")
    assert dcil == len(conn_id)  # 4


def test_quic_src_conn_id_len_zero():
    quic_bytes = _make_quic_initial_bytes(src_conn_id=b"")
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    scil = pkt.getfieldval(LayerKind.Quic, "src_conn_id_len")
    assert scil == 0


def test_quic_src_conn_id_len_nonzero():
    quic_bytes = _make_quic_initial_bytes(src_conn_id=b"\xaa\xbb\xcc")
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    scil = pkt.getfieldval(LayerKind.Quic, "src_conn_id_len")
    assert scil == 3


def test_quic_dst_conn_id_bytes():
    conn_id = b"\x01\x02\x03\x04"
    quic_bytes = _make_quic_initial_bytes(dst_conn_id=conn_id)
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    dcid = pkt.getfieldval(LayerKind.Quic, "dst_conn_id")
    assert isinstance(dcid, bytes)
    assert dcid == conn_id


def test_quic_src_conn_id_bytes():
    src_conn_id = b"\xaa\xbb"
    quic_bytes = _make_quic_initial_bytes(src_conn_id=src_conn_id)
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    scid = pkt.getfieldval(LayerKind.Quic, "src_conn_id")
    assert isinstance(scid, bytes)
    assert scid == src_conn_id


def test_quic_src_conn_id_empty():
    quic_bytes = _make_quic_initial_bytes(src_conn_id=b"")
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    scid = pkt.getfieldval(LayerKind.Quic, "src_conn_id")
    assert scid == b""


def test_quic_length_field_initial_empty_payload():
    """Initial with no payload, pn=0 (1 byte) => length = 1."""
    quic_bytes = _make_quic_initial_bytes(payload=b"")
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    length = pkt.getfieldval(LayerKind.Quic, "length")
    assert length == 1  # 1 byte packet number + 0 payload


def test_quic_length_field_initial_with_payload():
    """Initial with 2-byte payload, pn=0 (1 byte) => length = 3."""
    quic_bytes = _make_quic_initial_bytes(payload=b"\xaa\xbb")
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    length = pkt.getfieldval(LayerKind.Quic, "length")
    assert length == 3  # 1 byte pn + 2 bytes payload


def test_quic_packet_number_initial_zero():
    quic_bytes = _make_quic_initial_bytes()
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    pn = pkt.getfieldval(LayerKind.Quic, "packet_number")
    assert pn == 0


def test_quic_field_names_includes_new_fields():
    """Ensure all new field names are listed in pkt.fields."""
    quic_bytes = _make_quic_initial_bytes()
    pkt = _packet_with_quic_bytes(quic_bytes)
    assert pkt.has_layer(LayerKind.Quic)
    fields = pkt.fields
    expected = [
        "dst_conn_id",
        "src_conn_id",
        "dst_conn_id_len",
        "src_conn_id_len",
        "long_packet_type",
        "packet_number_len",
        "length",
        "packet_number",
    ]
    for f in expected:
        assert f in fields, f"expected field '{f}' not found in pkt.fields: {fields}"
