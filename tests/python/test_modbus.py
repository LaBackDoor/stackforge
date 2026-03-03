"""Tests for the Modbus protocol layer implementation.

These tests validate parsing, field access, building, and stacking of
Modbus/TCP (MBAP) packets through the Python bindings.
"""

import struct

from stackforge import IP, TCP, Ether, LayerKind, Modbus, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_modbus(modbus_bytes: bytes, sport: int = 502, dport: int = 502) -> bytes:
    """Wrap raw Modbus/TCP bytes inside an Ethernet/IPv4/TCP(dport=502) frame
    so that the stackforge parser can detect the Modbus layer."""
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
    tcp_header_len = 20
    ip_total = 20 + tcp_header_len + len(modbus_bytes)
    # Minimal IPv4 header (20 bytes)
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,  # version/IHL, DSCP/ECN
        ip_total,  # total length
        1,
        0,  # id=1, flags/frag=0
        64,
        6,  # TTL=64, proto=TCP
        0,  # checksum (not validated by parser)
        0x7F000001,  # src 127.0.0.1
        0x7F000001,  # dst 127.0.0.1
    )
    # TCP header (20 bytes): sport, dport, seq, ack, offset+flags, window, checksum, urgent
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        1000,
        0,
        (5 << 4),
        0x10,  # data offset=5 (20 bytes), flags=ACK
        65535,
        0,
        0,
    )
    return eth + ip + tcp + modbus_bytes


# ============================================================================
# Builder Tests
# ============================================================================


def test_builder_default():
    """Modbus() with no arguments builds a valid default MBAP frame."""
    m = Modbus()
    data = m.build()
    # MBAP header (7) + func_code (1) = 8 bytes minimum
    assert len(data) == 8
    # All fields should be zero defaults
    assert data[0:2] == b"\x00\x00"  # trans_id=0
    assert data[2:4] == b"\x00\x00"  # proto_id=0
    assert data[6] == 0  # unit_id=0
    assert data[7] == 0  # func_code=0


def test_builder_read_coils_request():
    """Build a Read Coils request with explicit data bytes."""
    m = Modbus(trans_id=1, unit_id=1, func_code=0x01, data=b"\x00\x00\x00\x0a")
    data = m.build()
    # 7 (MBAP) + 1 (fc) + 4 (data) = 12
    assert len(data) == 12
    assert data[0:2] == b"\x00\x01"  # trans_id=1
    assert data[6] == 1  # unit_id=1
    assert data[7] == 0x01  # func_code=Read Coils
    assert data[8:12] == b"\x00\x00\x00\x0a"  # start_addr=0, quantity=10


def test_builder_read_holding_registers():
    """Build a Read Holding Registers request."""
    m = Modbus(trans_id=2, unit_id=1, func_code=0x03, data=b"\x00\x00\x00\x01")
    data = m.build()
    assert len(data) == 12
    assert data[7] == 0x03  # func_code=Read Holding Registers


def test_builder_write_single_coil():
    """Build a Write Single Coil request (addr=100, value=ON)."""
    m = Modbus(trans_id=3, unit_id=1, func_code=0x05, data=b"\x00\x64\xff\x00")
    data = m.build()
    assert len(data) == 12
    assert data[7] == 0x05
    assert data[8:10] == b"\x00\x64"  # addr=100
    assert data[10:12] == b"\xff\x00"  # value=ON


def test_builder_write_single_register():
    """Build a Write Single Register request (addr=1, value=3)."""
    m = Modbus(trans_id=4, unit_id=1, func_code=0x06, data=b"\x00\x01\x00\x03")
    data = m.build()
    assert len(data) == 12
    assert data[7] == 0x06
    assert data[8:10] == b"\x00\x01"  # addr=1
    assert data[10:12] == b"\x00\x03"  # value=3


def test_builder_custom_func_code():
    """Build with a custom function code and arbitrary data payload."""
    m = Modbus(trans_id=99, unit_id=0x0A, func_code=0x41, data=b"\xde\xad\xbe\xef")
    data = m.build()
    assert data[0:2] == b"\x00\x63"  # trans_id=99
    assert data[6] == 0x0A  # unit_id=10
    assert data[7] == 0x41  # func_code=0x41
    assert data[8:12] == b"\xde\xad\xbe\xef"


def test_builder_proto_id():
    """Build with an explicit proto_id (should normally be 0)."""
    m = Modbus(trans_id=1, proto_id=0, unit_id=1, func_code=0x01, data=b"\x00\x00\x00\x01")
    data = m.build()
    assert data[2:4] == b"\x00\x00"  # proto_id=0


def test_builder_bytes_method():
    """Verify .bytes() returns the same result as .build()."""
    m = Modbus(trans_id=5, unit_id=2, func_code=0x03, data=b"\x00\x00\x00\x05")
    assert m.build() == m.bytes()


# ============================================================================
# Parsing Tests -- Raw Modbus/TCP wrapped in Eth/IP/TCP
# ============================================================================


def test_parse_read_coils_request():
    """Parse a Read Coils Request from raw bytes."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 1
    assert pkt.proto_id == 0
    assert pkt.length == 6
    assert pkt.unit_id == 0xFF
    assert pkt.func_code == 0x01
    assert pkt.start_addr == 0
    assert pkt.quantity == 10


def test_parse_read_coils_response():
    """Parse a Read Coils Response from raw bytes."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x04\xff\x01\x01\x03"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 1
    assert pkt.func_code == 0x01
    assert pkt.length == 4
    assert pkt.byte_count == 1
    # data after func_code should include byte_count + coil bytes
    data = pkt.getfieldval(LayerKind.Modbus, "data")
    assert data == b"\x01\x03"


def test_parse_read_holding_registers_request():
    """Parse a Read Holding Registers Request."""
    modbus_bytes = b"\x00\x02\x00\x00\x00\x06\xff\x03\x00\x00\x00\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 2
    assert pkt.func_code == 0x03
    assert pkt.start_addr == 0
    assert pkt.quantity == 1


def test_parse_read_holding_registers_response():
    """Parse a Read Holding Registers Response."""
    modbus_bytes = b"\x00\x02\x00\x00\x00\x05\xff\x03\x02\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 2
    assert pkt.func_code == 0x03
    assert pkt.length == 5
    assert pkt.byte_count == 2


def test_parse_write_single_coil_request():
    """Parse a Write Single Coil Request (addr=100, ON=0xFF00)."""
    modbus_bytes = b"\x00\x03\x00\x00\x00\x06\xff\x05\x00\x64\xff\x00"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 3
    assert pkt.func_code == 0x05
    assert pkt.start_addr == 100
    # output_value (same offset as quantity) = 0xFF00
    assert pkt.getfieldval(LayerKind.Modbus, "output_value") == 0xFF00


def test_parse_write_single_register_request():
    """Parse a Write Single Register Request (addr=1, value=3)."""
    modbus_bytes = b"\x00\x04\x00\x00\x00\x06\xff\x06\x00\x01\x00\x03"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 4
    assert pkt.func_code == 0x06
    assert pkt.start_addr == 1
    # register_val (same offset as quantity) = 3
    assert pkt.getfieldval(LayerKind.Modbus, "register_val") == 3


def test_parse_error_response():
    """Parse an Error Response (func=0x81 = error for func 0x01, except_code=2)."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x03\xff\x81\x02"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 1
    assert pkt.func_code == 0x81
    assert pkt.length == 3
    assert pkt.except_code == 2


def test_parse_write_multiple_registers():
    """Parse a Write Multiple Registers Request."""
    # trans_id=5, proto_id=0, length=0x0b=11, unit_id=0xFF, fc=0x10,
    # start_addr=0x0001, quantity=0x0002, byte_count=4, data=[0x000a, 0x0102]
    modbus_bytes = b"\x00\x05\x00\x00\x00\x0b\xff\x10\x00\x01\x00\x02\x04\x00\x0a\x01\x02"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 5
    assert pkt.func_code == 0x10
    assert pkt.start_addr == 1
    assert pkt.quantity == 2
    assert pkt.length == 11


# ============================================================================
# Field Access Tests
# ============================================================================


def test_field_access_trans_id():
    """Access trans_id via attribute on packet."""
    modbus_bytes = b"\x00\x0a\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.trans_id == 10


def test_field_access_proto_id():
    """proto_id should always be 0 for standard Modbus/TCP."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.proto_id == 0


def test_field_access_length():
    """Access MBAP length field."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.length == 6


def test_field_access_unit_id():
    """Access unit_id via attribute."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\x0b\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.unit_id == 0x0B


def test_field_access_func_code():
    """Access func_code via attribute."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x04\x00\x00\x00\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.func_code == 0x04


def test_field_access_start_addr():
    """Access start_addr for read/write requests."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x10\x00\x08"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.start_addr == 16


def test_field_access_quantity():
    """Access quantity for read requests."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x10\x00\x08"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.quantity == 8


def test_field_access_byte_count():
    """Access byte_count for response PDUs."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x05\xff\x03\x02\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.byte_count == 2


def test_field_access_except_code():
    """Access except_code for error responses."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x03\xff\x81\x02"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.except_code == 2


def test_getfieldval_layer_specific():
    """Use getfieldval with LayerKind.Modbus for layer-specific field access."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x03\x00\x00\x00\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x03
    assert pkt.getfieldval(LayerKind.Modbus, "trans_id") == 1
    assert pkt.getfieldval(LayerKind.Modbus, "unit_id") == 0xFF
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


# ============================================================================
# has_layer Tests
# ============================================================================


def test_has_layer_modbus():
    """has_layer returns True for a valid Modbus/TCP packet."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)


def test_has_layer_all_layers():
    """Verify all expected layers are present in Eth/IP/TCP/Modbus stack."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Modbus)
    assert not pkt.has_layer(LayerKind.Udp)
    assert not pkt.has_layer(LayerKind.Dns)


# ============================================================================
# Stacking Test (Ether/IP/TCP/Modbus)
# ============================================================================


def test_stacking_ether_ip_tcp_modbus():
    """Build a full Ether/IP/TCP/Modbus stack and verify Modbus is detected."""
    stack = (
        Ether()
        / IP()
        / TCP(dport=502)
        / Modbus(trans_id=1, unit_id=1, func_code=0x03, data=b"\x00\x00\x00\x01")
    )
    raw = stack.bytes()
    parsed = Packet(raw)
    parsed.parse()
    assert parsed.has_layer(LayerKind.Modbus)
    assert parsed.func_code == 0x03
    assert parsed.trans_id == 1


def test_stacking_modbus_alone_build():
    """Build Modbus alone and verify raw bytes match expected MBAP format."""
    m = Modbus(trans_id=7, unit_id=3, func_code=0x01, data=b"\x00\x00\x00\x08")
    raw = m.build()
    # Parse the MBAP header manually
    assert struct.unpack("!H", raw[0:2])[0] == 7  # trans_id
    assert struct.unpack("!H", raw[2:4])[0] == 0  # proto_id
    length = struct.unpack("!H", raw[4:6])[0]
    assert length == 6  # unit_id(1) + func_code(1) + data(4)
    assert raw[6] == 3  # unit_id
    assert raw[7] == 0x01  # func_code
    assert raw[8:12] == b"\x00\x00\x00\x08"


# ============================================================================
# Builder Bytes / Round-trip Tests
# ============================================================================


def test_builder_length_field_auto():
    """Verify the MBAP length field is auto-calculated correctly."""
    m = Modbus(trans_id=1, unit_id=1, func_code=0x03, data=b"\x00\x00\x00\x01")
    raw = m.build()
    length = struct.unpack("!H", raw[4:6])[0]
    # length = unit_id(1) + func_code(1) + data(4) = 6
    assert length == 6


def test_builder_roundtrip_parse():
    """Build a Modbus/TCP packet, wrap in Eth/IP/TCP, parse, and verify fields."""
    m = Modbus(trans_id=42, unit_id=0x11, func_code=0x03, data=b"\x00\x6b\x00\x03")
    modbus_raw = m.build()
    full_raw = make_eth_ip_tcp_modbus(modbus_raw)
    pkt = Packet(full_raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.trans_id == 42
    assert pkt.getfieldval(LayerKind.Modbus, "unit_id") == 0x11
    assert pkt.func_code == 0x03
    assert pkt.start_addr == 0x006B
    assert pkt.quantity == 3


def test_builder_empty_data():
    """Build Modbus with func_code but no data bytes."""
    m = Modbus(trans_id=0, unit_id=0, func_code=0x07)
    raw = m.build()
    # 7 (MBAP) + 1 (fc) = 8 bytes
    assert len(raw) == 8
    assert raw[7] == 0x07


def test_builder_large_data():
    """Build Modbus with a large data payload."""
    payload = bytes(range(256))
    m = Modbus(trans_id=100, unit_id=1, func_code=0x10, data=payload)
    raw = m.build()
    # 7 (MBAP) + 1 (fc) + 256 (data) = 264
    assert len(raw) == 264
    length = struct.unpack("!H", raw[4:6])[0]
    assert length == 258  # unit_id(1) + func_code(1) + data(256)


# ============================================================================
# Edge Cases and Additional Coverage
# ============================================================================


def test_parse_read_discrete_inputs_request():
    """Parse a Read Discrete Inputs Request (fc=0x02)."""
    modbus_bytes = b"\x00\x0a\x00\x00\x00\x06\x01\x02\x00\xc4\x00\x16"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.func_code == 0x02
    assert pkt.start_addr == 0x00C4  # 196
    assert pkt.quantity == 0x0016  # 22


def test_parse_read_input_registers_request():
    """Parse a Read Input Registers Request (fc=0x04)."""
    modbus_bytes = b"\x00\x0b\x00\x00\x00\x06\x01\x04\x00\x08\x00\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.func_code == 0x04
    assert pkt.start_addr == 8
    assert pkt.quantity == 1


def test_parse_error_illegal_function():
    """Parse an error response with except_code=1 (Illegal Function)."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x03\xff\x83\x01"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.func_code == 0x83  # error for func 0x03
    assert pkt.except_code == 1  # Illegal Function


def test_parse_error_illegal_data_value():
    """Parse an error response with except_code=3 (Illegal Data Value)."""
    modbus_bytes = b"\x00\x02\x00\x00\x00\x03\xff\x86\x03"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.func_code == 0x86  # error for func 0x06
    assert pkt.except_code == 3  # Illegal Data Value


def test_get_layer_bytes():
    """Verify get_layer_bytes returns the Modbus layer slice."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Modbus)
    # The returned bytes should start with the MBAP header
    assert layer_bytes[:2] == b"\x00\x01"  # trans_id
    assert layer_bytes[7] == 0x01  # func_code


def test_fields_property():
    """Verify 'fields' property includes Modbus field names."""
    modbus_bytes = b"\x00\x01\x00\x00\x00\x06\xff\x01\x00\x00\x00\x0a"
    raw = make_eth_ip_tcp_modbus(modbus_bytes)
    pkt = Packet(raw)
    pkt.parse()
    fields = pkt.fields
    assert "trans_id" in fields
    assert "proto_id" in fields
    assert "func_code" in fields
    assert "unit_id" in fields
    assert "start_addr" in fields
    assert "quantity" in fields
    assert "byte_count" in fields
    assert "except_code" in fields
    assert "data" in fields


def test_modbus_repr():
    """Verify the __repr__ output of the Modbus builder."""
    m = Modbus()
    assert repr(m) == "<Modbus>"


def test_stacking_roundtrip_write_single_register():
    """Stack Ether/IP/TCP/Modbus for Write Single Register and round-trip."""
    stack = (
        Ether()
        / IP()
        / TCP(dport=502)
        / Modbus(trans_id=10, unit_id=5, func_code=0x06, data=b"\x00\x01\x00\x03")
    )
    raw = stack.bytes()
    parsed = Packet(raw)
    parsed.parse()
    assert parsed.has_layer(LayerKind.Modbus)
    assert parsed.trans_id == 10
    assert parsed.func_code == 0x06
    assert parsed.start_addr == 1
    assert parsed.getfieldval(LayerKind.Modbus, "register_val") == 3
