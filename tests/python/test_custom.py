"""Tests for the stackforge custom protocol API.

The custom module (stackforge.custom) provides a Scapy-like framework for
defining custom protocol layers in pure Python.  Tests cover:
  - All field types (ByteField, ShortField, IntField, LongField, StrLenField)
  - CustomLayer subclassing, serialization, parsing, and field access
  - CustomLayerStack / operator for layer stacking
  - Registry helpers (get_protocol, list_protocols)
  - Error handling for unknown fields and parse edge cases
"""

import struct

import pytest
from stackforge.custom import (
    ByteField,
    CustomLayer,
    CustomLayerStack,
    IntField,
    LongField,
    ShortField,
    StrLenField,
    get_protocol,
    list_protocols,
)

# ---------------------------------------------------------------------------
# Simple protocol fixture used throughout the tests
# ---------------------------------------------------------------------------


class PingProto(CustomLayer):
    name = "PingProto"
    fields_desc = [
        ByteField("opcode", 0),
        ShortField("length", 0),
        IntField("seq", 0),
    ]


class SmallProto(CustomLayer):
    name = "SmallProto"
    fields_desc = [
        ByteField("flags", 0x00),
        ByteField("type_", 0x01),
    ]


class LargeProto(CustomLayer):
    name = "LargeProto"
    fields_desc = [
        LongField("timestamp", 0),
        IntField("checksum", 0),
    ]


class BlobProto(CustomLayer):
    name = "BlobProto"
    fields_desc = [
        StrLenField("magic", b"\x00\x00\x00\x00", length=4),
        ByteField("version", 1),
    ]


# ---------------------------------------------------------------------------
# Field type sizes
# ---------------------------------------------------------------------------


def test_byte_field_size():
    f = ByteField("x", 0)
    assert f.size == 1


def test_short_field_size():
    f = ShortField("x", 0)
    assert f.size == 2


def test_int_field_size():
    f = IntField("x", 0)
    assert f.size == 4


def test_long_field_size():
    f = LongField("x", 0)
    assert f.size == 8


def test_strlenfield_size():
    f = StrLenField("x", b"\x00\x00", length=2)
    assert f.size == 2


# ---------------------------------------------------------------------------
# Field pack/unpack roundtrips
# ---------------------------------------------------------------------------


def test_byte_field_pack_unpack():
    f = ByteField("x", 0)
    packed = f.pack(255)
    assert packed == bytes([255])
    val, consumed = f.unpack(packed, 0)
    assert val == 255
    assert consumed == 1


def test_short_field_pack_unpack():
    f = ShortField("x", 0)
    packed = f.pack(0x1234)
    assert packed == b"\x12\x34"
    val, consumed = f.unpack(packed, 0)
    assert val == 0x1234
    assert consumed == 2


def test_int_field_pack_unpack():
    f = IntField("x", 0)
    packed = f.pack(0xDEADBEEF)
    assert packed == b"\xde\xad\xbe\xef"
    val, consumed = f.unpack(packed, 0)
    assert val == 0xDEADBEEF
    assert consumed == 4


def test_long_field_pack_unpack():
    f = LongField("x", 0)
    value = 0x0102030405060708
    packed = f.pack(value)
    assert len(packed) == 8
    val, consumed = f.unpack(packed, 0)
    assert val == value
    assert consumed == 8


def test_strlenfield_pack_unpack():
    f = StrLenField("x", b"\x00\x00\x00\x00", length=4)
    packed = f.pack(b"\xca\xfe\xba\xbe")
    assert packed == b"\xca\xfe\xba\xbe"
    val, consumed = f.unpack(packed, 0)
    assert val == b"\xca\xfe\xba\xbe"
    assert consumed == 4


def test_strlenfield_pads_short_value():
    f = StrLenField("x", b"\x00" * 4, length=4)
    packed = f.pack(b"\x01\x02")  # only 2 bytes, should be padded
    assert len(packed) == 4
    assert packed == b"\x01\x02\x00\x00"


def test_strlenfield_truncates_long_value():
    f = StrLenField("x", b"\x00" * 4, length=4)
    packed = f.pack(b"\x01\x02\x03\x04\x05\x06")  # 6 bytes, truncate to 4
    assert len(packed) == 4
    assert packed == b"\x01\x02\x03\x04"


# ---------------------------------------------------------------------------
# CustomLayer: defaults and construction
# ---------------------------------------------------------------------------


def test_custom_layer_default_values():
    pkt = PingProto()
    assert pkt.opcode == 0
    assert pkt.length == 0
    assert pkt.seq == 0


def test_custom_layer_keyword_overrides():
    pkt = PingProto(opcode=3, length=10, seq=42)
    assert pkt.opcode == 3
    assert pkt.length == 10
    assert pkt.seq == 42


def test_custom_layer_unknown_field_raises():
    with pytest.raises(TypeError):
        PingProto(nonexistent=99)


# ---------------------------------------------------------------------------
# CustomLayer: serialization (__bytes__)
# ---------------------------------------------------------------------------


def test_custom_layer_bytes_length():
    pkt = PingProto()
    raw = bytes(pkt)
    # opcode(1) + length(2) + seq(4) = 7
    assert len(raw) == 7


def test_custom_layer_len_dunder():
    pkt = PingProto()
    assert len(pkt) == 7


def test_custom_layer_bytes_values():
    pkt = PingProto(opcode=0x05, length=0x0003, seq=0xDEADBEEF)
    raw = bytes(pkt)
    assert raw[0] == 0x05
    assert raw[1:3] == b"\x00\x03"
    assert raw[3:7] == b"\xde\xad\xbe\xef"


def test_custom_layer_bytes_defaults():
    pkt = PingProto()
    assert bytes(pkt) == b"\x00\x00\x00\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# CustomLayer: parsing from bytes
# ---------------------------------------------------------------------------


def test_custom_layer_parse_roundtrip():
    original = PingProto(opcode=7, length=100, seq=999)
    raw = bytes(original)
    parsed = PingProto.parse(raw)
    assert parsed.opcode == 7
    assert parsed.length == 100
    assert parsed.seq == 999


def test_custom_layer_parse_blob():
    raw = b"\xca\xfe\xba\xbe\x02"
    parsed = BlobProto.parse(raw)
    assert parsed.magic == b"\xca\xfe\xba\xbe"
    assert parsed.version == 2


def test_custom_layer_parse_partial_data():
    # Only provide the first byte — remaining fields fall back to defaults
    raw = bytes([0xFF])
    parsed = SmallProto.parse(raw)
    assert parsed.flags == 0xFF
    assert parsed.type_ == 0x01  # default


def test_custom_layer_parse_large_proto():
    ts = 0x0102030405060708
    csum = 0xABCD1234
    raw = struct.pack("!QI", ts, csum)
    parsed = LargeProto.parse(raw)
    assert parsed.timestamp == ts
    assert parsed.checksum == csum


# ---------------------------------------------------------------------------
# CustomLayer: attribute get/set
# ---------------------------------------------------------------------------


def test_custom_layer_getattr():
    pkt = PingProto(seq=77)
    assert pkt.seq == 77


def test_custom_layer_setattr():
    pkt = PingProto()
    pkt.opcode = 9
    assert pkt.opcode == 9


def test_custom_layer_setattr_then_bytes():
    pkt = PingProto()
    pkt.seq = 1
    raw = bytes(pkt)
    assert raw[3:7] == b"\x00\x00\x00\x01"


def test_custom_layer_getattr_missing_raises():
    pkt = PingProto()
    with pytest.raises(AttributeError):
        _ = pkt.does_not_exist


# ---------------------------------------------------------------------------
# CustomLayer: show()
# ---------------------------------------------------------------------------


def test_custom_layer_show_contains_name():
    pkt = PingProto(opcode=1)
    s = pkt.show()
    assert "PingProto" in s


def test_custom_layer_show_contains_field_names():
    pkt = PingProto(opcode=1, length=2, seq=3)
    s = pkt.show()
    assert "opcode" in s
    assert "length" in s
    assert "seq" in s


def test_custom_layer_show_contains_values():
    pkt = PingProto(opcode=42)
    s = pkt.show()
    assert "42" in s


# ---------------------------------------------------------------------------
# CustomLayerStack: / operator
# ---------------------------------------------------------------------------


def test_custom_layer_stack_truediv():
    a = SmallProto(flags=0x01, type_=0x02)
    b = SmallProto(flags=0x03, type_=0x04)
    stack = a / b
    assert isinstance(stack, CustomLayerStack)


def test_custom_layer_stack_bytes():
    a = SmallProto(flags=0x01, type_=0x02)
    b = SmallProto(flags=0x03, type_=0x04)
    stack = a / b
    raw = bytes(stack)
    assert raw == b"\x01\x02\x03\x04"


def test_custom_layer_stack_len():
    a = SmallProto()
    b = SmallProto()
    stack = a / b
    assert len(stack) == 4


def test_custom_layer_stack_triple():
    a = SmallProto(flags=0xAA, type_=0xBB)
    b = SmallProto(flags=0xCC, type_=0xDD)
    c = SmallProto(flags=0xEE, type_=0xFF)
    stack = a / b / c
    raw = bytes(stack)
    assert raw == b"\xaa\xbb\xcc\xdd\xee\xff"


# ---------------------------------------------------------------------------
# Protocol registry
# ---------------------------------------------------------------------------


def test_get_protocol_returns_class():
    cls = get_protocol("PingProto")
    assert cls is PingProto


def test_get_protocol_returns_none_for_unknown():
    result = get_protocol("NoSuchProtocol")
    assert result is None


def test_list_protocols_contains_registered():
    names = list_protocols()
    assert isinstance(names, list)
    assert "PingProto" in names
    assert "SmallProto" in names
    assert "LargeProto" in names


def test_list_protocols_does_not_contain_empty():
    """The base CustomLayer itself (with no fields_desc) should not appear."""
    names = list_protocols()
    # Base class name "Custom" should not appear since fields_desc is empty
    # (subclasses register themselves only when fields_desc is non-empty)
    assert "Custom" not in names
