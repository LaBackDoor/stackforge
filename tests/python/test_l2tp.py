"""Tests for the L2TP (Layer 2 Tunneling Protocol) layer implementation.

These tests validate parsing, field access, and building of L2TPv2 packets.
"""

import struct

from stackforge import L2TP, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_udp_l2tp(l2tp_bytes: bytes) -> bytes:
    """Wrap raw L2TP bytes inside an Ethernet/IPv4/UDP(dport=1701) frame
    so that the stackforge parser can detect the L2TP layer."""
    # Ethernet header (14 bytes): dst, src, ethertype=0x0800
    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,  # src
            0x08,
            0x00,  # ethertype = IPv4
        ]
    )
    udp_len = 8 + len(l2tp_bytes)
    ip_total = 20 + udp_len
    # Minimal IPv4 header (20 bytes)
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,  # version/IHL, DSCP/ECN
        ip_total,  # total length
        1,
        0,  # id=1, flags/frag=0
        64,
        17,  # TTL=64, proto=UDP
        0,  # checksum (not validated by parser)
        0x7F000001,  # src 127.0.0.1
        0x7F000001,  # dst 127.0.0.1
    )
    # UDP header (8 bytes): sport=1701, dport=1701, length, checksum
    udp = struct.pack("!HHHH", 1701, 1701, udp_len, 0)
    return eth + ip + udp + l2tp_bytes


# ============================================================================
# Test 1: Parse default L2TP data bytes
# ============================================================================


def test_parse_default_l2tp():
    """Parse the minimal L2TP data packet: flags=0x0002, tid=0, sid=0."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.L2tp), "L2TP layer not found"


def test_parse_default_l2tp_fields():
    """Verify field values for the default L2TP packet."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.tunnel_id == 0
    assert pkt.session_id == 0
    # Use layer-specific access since 'version' is also a field in IPv4
    assert pkt.getfieldval(LayerKind.L2tp, "version") == 2
    assert pkt.msg_type == 0  # data


def test_parse_default_l2tp_no_length_field():
    """The default L2TP has L=0, so getfieldval returns 0 (no length field)."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    # flags word should be 0x0002
    flags = pkt.getfieldval(LayerKind.L2tp, "flags")
    assert flags == 0x0002


# ============================================================================
# Test 2: Parse L2TP control+length bytes
# ============================================================================


def test_parse_control_length_l2tp():
    """Parse the L2TP control+length packet with T=1, L=1."""
    # Matches UTS: bytes(L2TP(hdr="control+length", tunnel_id=1, session_id=2))
    # = b'\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00'
    # Note: Scapy uses 0xC002 (no S bit) but includes Ns+Nr in the payload
    # Our parser sees: flags=0xC002, length=12, tid=1, sid=2
    l2tp_bytes = b"\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.L2tp), "L2TP layer not found"


def test_parse_control_length_fields():
    """Check field values for the L2TP control+length packet."""
    l2tp_bytes = b"\xc0\x02\x00\x0c\x00\x01\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    # T=1 (bit15 of flags word 0xC002 = 1)
    assert pkt.msg_type == 1, f"Expected control (1), got {pkt.msg_type}"
    # tunnel_id=1, session_id=2
    assert pkt.tunnel_id == 1, f"Expected tunnel_id=1, got {pkt.tunnel_id}"
    assert pkt.session_id == 2, f"Expected session_id=2, got {pkt.session_id}"
    # L bit is set, so length field is present = 12
    length = pkt.getfieldval(LayerKind.L2tp, "length")
    assert length == 12, f"Expected length=12, got {length}"


# ============================================================================
# Test 3: has_layer
# ============================================================================


def test_has_layer():
    """Verify has_layer works for L2TP."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.L2tp)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Udp)
    assert not pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Dns)


# ============================================================================
# Test 4: Field access via attribute and getfieldval
# ============================================================================


def test_field_access_tunnel_session():
    """Verify tunnel_id and session_id can be read via __getattr__."""
    l2tp_bytes = b"\x00\x02\x12\x34\x56\x78"  # tunnel=0x1234, session=0x5678
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.tunnel_id == 0x1234
    assert pkt.session_id == 0x5678


def test_getfieldval_layer_specific():
    """Verify getfieldval with LayerKind.L2tp for layer-specific access."""
    l2tp_bytes = b"\x00\x02\xab\xcd\xef\x01"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    tid = pkt.getfieldval(LayerKind.L2tp, "tunnel_id")
    sid = pkt.getfieldval(LayerKind.L2tp, "session_id")
    assert tid == 0xABCD
    assert sid == 0xEF01


def test_fields_property():
    """Verify 'fields' property lists L2TP field names."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    fields = pkt.fields
    assert "tunnel_id" in fields
    assert "session_id" in fields
    assert "version" in fields
    assert "msg_type" in fields
    assert "flags" in fields


# ============================================================================
# Test 5: Build L2TP packets with the builder
# ============================================================================


def test_build_default():
    """Build the default L2TP data packet and verify bytes."""
    l2tp = L2TP()
    data = l2tp.bytes()
    assert data == b"\x00\x02\x00\x00\x00\x00", f"Unexpected bytes: {data.hex()}"


def test_build_with_tunnel_session():
    """Build L2TP with custom tunnel_id and session_id."""
    l2tp = L2TP(tunnel_id=42, session_id=99)
    data = l2tp.bytes()
    assert len(data) == 6
    flags = (data[0] << 8) | data[1]
    assert flags == 0x0002  # data, ver=2
    tid = (data[2] << 8) | data[3]
    sid = (data[4] << 8) | data[5]
    assert tid == 42
    assert sid == 99


def test_build_control_message():
    """Build a control message (T bit set)."""
    l2tp = L2TP(msg_type=1)
    data = l2tp.bytes()
    assert len(data) == 6
    flags = (data[0] << 8) | data[1]
    assert flags & 0x8000, "T bit should be set"
    assert flags & 0x000F == 2, "version should be 2"


def test_build_with_length():
    """Build L2TP with L bit set."""
    l2tp = L2TP(msg_type=1, has_length=True)
    data = l2tp.bytes()
    assert len(data) == 8  # flags(2) + length(2) + tid(2) + sid(2)
    flags = (data[0] << 8) | data[1]
    assert flags & 0x4000, "L bit should be set"
    length = (data[2] << 8) | data[3]
    assert length == 8, f"Expected length=8, got {length}"


def test_build_with_sequence():
    """Build L2TP with S bit set (Ns and Nr present)."""
    l2tp = L2TP(has_sequence=True)
    data = l2tp.bytes()
    assert len(data) == 10  # flags(2) + tid(2) + sid(2) + ns(2) + nr(2)
    flags = (data[0] << 8) | data[1]
    assert flags & 0x0800, "S bit should be set"


def test_build_control_with_length_and_sequence():
    """Build L2TP control message with L+S, matching our builder's 12-byte output."""
    l2tp = L2TP(msg_type=1, has_length=True, has_sequence=True, tunnel_id=1, session_id=2)
    data = l2tp.bytes()
    # 12 bytes: flags(2) + length(2) + tid(2) + sid(2) + ns(2) + nr(2)
    assert len(data) == 12, f"Expected 12 bytes, got {len(data)}"
    flags = (data[0] << 8) | data[1]
    # T=1 (bit15), L=1 (bit14), S=1 (bit11), ver=2
    assert flags & 0x8000, "T bit not set"
    assert flags & 0x4000, "L bit not set"
    assert flags & 0x0800, "S bit not set"
    assert flags & 0x000F == 2, "ver != 2"
    length = (data[2] << 8) | data[3]
    assert length == 12
    tid = (data[4] << 8) | data[5]
    sid = (data[6] << 8) | data[7]
    assert tid == 1
    assert sid == 2
    ns = (data[8] << 8) | data[9]
    nr = (data[10] << 8) | data[11]
    assert ns == 0
    assert nr == 0


def test_build_and_parse_roundtrip():
    """Build an L2TP packet and then parse it back, verifying field values."""
    l2tp = L2TP(tunnel_id=0x1234, session_id=0x5678)
    built = l2tp.bytes()
    raw = make_eth_ip_udp_l2tp(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.L2tp)
    assert pkt.tunnel_id == 0x1234
    assert pkt.session_id == 0x5678


# ============================================================================
# Test 6: get_layer_bytes
# ============================================================================


def test_get_layer_bytes():
    """Verify get_layer_bytes returns the correct L2TP header bytes."""
    l2tp_bytes = b"\x00\x02\x00\x01\x00\x02"  # ver=2, tid=1, sid=2
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.L2tp)
    # The layer bytes should start with the L2TP header
    assert layer_bytes[:6] == l2tp_bytes


# ============================================================================
# Test 7: Layer order
# ============================================================================


def test_layer_order():
    """Verify the expected layer order: Ethernet / IPv4 / UDP / L2TP."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Ethernet in kinds
    assert LayerKind.Ipv4 in kinds
    assert LayerKind.Udp in kinds
    assert LayerKind.L2tp in kinds
    # L2TP should come after UDP
    udp_pos = kinds.index(LayerKind.Udp)
    l2tp_pos = kinds.index(LayerKind.L2tp)
    assert l2tp_pos > udp_pos, "L2TP should be after UDP"


# ============================================================================
# Test 8: LayerKind.L2tp identity
# ============================================================================


def test_layer_kind_identity():
    """Verify LayerKind.L2tp can be imported and used."""
    assert LayerKind.L2tp is not None
    # The name should be 'L2TP'
    assert "L2TP" in str(LayerKind.L2tp)


# ============================================================================
# Test 9: Show output
# ============================================================================


def test_show_includes_l2tp():
    """Verify show() includes L2TP fields."""
    l2tp_bytes = b"\x00\x02\x00\x0a\x00\x0b"  # tid=10, sid=11
    raw = make_eth_ip_udp_l2tp(l2tp_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "L2TP" in show
    assert "tunnel_id" in show
    assert "session_id" in show


# ============================================================================
# Test 10: Non-L2TP UDP port does not create L2TP layer
# ============================================================================


def test_non_l2tp_port_no_layer():
    """UDP traffic not on port 1701 should NOT be detected as L2TP."""
    l2tp_bytes = b"\x00\x02\x00\x00\x00\x00"
    # Build frame with port 9999 instead of 1701
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
    udp_len = 8 + len(l2tp_bytes)
    ip_total = 20 + udp_len
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
        0x7F000001,
        0x7F000001,
    )
    udp = struct.pack("!HHHH", 9999, 9999, udp_len, 0)
    raw = eth + ip + udp + l2tp_bytes
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.L2tp)
