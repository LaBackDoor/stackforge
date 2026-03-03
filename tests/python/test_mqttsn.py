"""Tests for the MQTT-SN (MQTT for Sensor Networks) layer implementation.

These tests validate parsing, field access, building, and stacking of MQTT-SN
packets as implemented in the stackforge Rust core with Python bindings.

MQTT-SN is detected on UDP port 1883.
"""

import struct

from stackforge import IP, MQTTSN, UDP, Ether, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_udp_mqttsn(mqttsn_bytes: bytes, sport: int = 1883, dport: int = 1883) -> bytes:
    """Wrap raw MQTT-SN bytes inside an Ethernet/IPv4/UDP(port=1883) frame
    so that the stackforge parser can detect the MQTT-SN layer."""
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
    udp_len = 8 + len(mqttsn_bytes)
    ip_total = 20 + udp_len
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,  # version/IHL, DSCP/ECN
        ip_total,  # total length
        1,
        0,  # id=1, flags/frag=0
        64,
        17,  # TTL=64, proto=UDP
        0,  # checksum (not validated)
        0x7F000001,  # src 127.0.0.1
        0x7F000001,  # dst 127.0.0.1
    )
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    return eth + ip + udp + mqttsn_bytes


# ============================================================================
# 1. Builder tests
# ============================================================================


def test_build_advertise():
    """Build an ADVERTISE message with gw_id and duration."""
    mqttsn = MQTTSN(msg_type=0x00, gw_id=1, duration=300)
    data = mqttsn.bytes()
    # ADVERTISE: length(1) + type(1) + gw_id(1) + duration(2) = 5 bytes
    assert len(data) == 5
    assert data[0] == 5  # length
    assert data[1] == 0x00  # ADVERTISE
    assert data[2] == 1  # gw_id
    assert (data[3] << 8 | data[4]) == 300  # duration BE


def test_build_searchgw():
    """Build a SEARCHGW message with radius."""
    mqttsn = MQTTSN(msg_type=0x01, radius=3)
    data = mqttsn.bytes()
    # SEARCHGW: length(1) + type(1) + radius(1) = 3 bytes
    assert len(data) == 3
    assert data[0] == 3
    assert data[1] == 0x01  # SEARCHGW
    assert data[2] == 3  # radius


def test_build_connect():
    """Build a CONNECT message with clean_session, duration, client_id, prot_id."""
    mqttsn = MQTTSN(
        msg_type=0x04,
        clean_session=True,
        duration=60,
        client_id=b"sensor1",
        prot_id=1,
    )
    data = mqttsn.bytes()
    # CONNECT: length(1) + type(1) + flags(1) + prot_id(1) + duration(2) + client_id(7) = 13
    assert len(data) == 13
    assert data[0] == 13  # length
    assert data[1] == 0x04  # CONNECT
    # flags byte: clean_session=True -> bit2 set => 0x04
    flags = data[2]
    assert flags & 0x04 != 0, "CleanSession bit should be set"
    assert data[3] == 1  # prot_id
    assert (data[4] << 8 | data[5]) == 60  # duration
    assert data[6:] == b"sensor1"


def test_build_publish():
    """Build a PUBLISH message with qos, tid, mid, data."""
    mqttsn = MQTTSN(msg_type=0x0C, qos=1, tid=1, mid=1, data=b"temp=22.5")
    data = mqttsn.bytes()
    # PUBLISH: length(1) + type(1) + flags(1) + tid(2) + mid(2) + payload(9) = 16
    assert len(data) == 16
    assert data[0] == 16
    assert data[1] == 0x0C  # PUBLISH
    # flags: QoS=1 -> bits 6-5 = 01 -> 0x20
    flags = data[2]
    assert (flags >> 5) & 0x03 == 1, "QoS should be 1"
    assert (data[3] << 8 | data[4]) == 1  # tid
    assert (data[5] << 8 | data[6]) == 1  # mid
    assert data[7:] == b"temp=22.5"


def test_build_subscribe():
    """Build a SUBSCRIBE message with qos, mid, and topic_name."""
    mqttsn = MQTTSN(msg_type=0x12, qos=1, mid=2, topic_name=b"sensors/temp")
    data = mqttsn.bytes()
    # SUBSCRIBE: length(1) + type(1) + flags(1) + mid(2) + topic_name(12) = 17
    assert len(data) == 17
    assert data[0] == 17
    assert data[1] == 0x12  # SUBSCRIBE
    flags = data[2]
    assert (flags >> 5) & 0x03 == 1, "QoS should be 1"
    assert (data[3] << 8 | data[4]) == 2  # mid
    assert data[5:] == b"sensors/temp"


def test_build_pingreq():
    """Build a minimal PINGREQ message (no body)."""
    mqttsn = MQTTSN(msg_type=0x16)
    data = mqttsn.bytes()
    # PINGREQ with no client_id: length(1) + type(1) = 2 bytes
    assert len(data) == 2
    assert data[0] == 2
    assert data[1] == 0x16  # PINGREQ


def test_build_disconnect():
    """Build a minimal DISCONNECT message (no duration)."""
    mqttsn = MQTTSN(msg_type=0x18)
    data = mqttsn.bytes()
    # DISCONNECT with duration=0: length(1) + type(1) = 2 bytes
    assert len(data) == 2
    assert data[0] == 2
    assert data[1] == 0x18  # DISCONNECT


# ============================================================================
# 2. Parsing tests
# ============================================================================


def test_parse_advertise():
    """Parse an ADVERTISE message from raw bytes wrapped in Eth/IP/UDP."""
    # len=5, type=0x00, gw_id=0x8e, duration=0xd483
    mqttsn_bytes = b"\x05\x00\x8e\xd4\x83"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn), "MQTT-SN layer not found"


def test_parse_advertise_fields():
    """Verify ADVERTISE field values after parsing."""
    mqttsn_bytes = b"\x05\x00\x8e\xd4\x83"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    # Field "type" is 0x00 (ADVERTISE)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x00
    assert pkt.gw_id == 0x8E
    assert pkt.duration == 0xD483


def test_parse_searchgw():
    """Parse a SEARCHGW message."""
    # len=3, type=0x01, radius=0xaf
    mqttsn_bytes = b"\x03\x01\xaf"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x01
    assert pkt.radius == 0xAF


def test_parse_connect():
    """Parse a CONNECT message with flags, prot_id, duration, client_id."""
    # len=10, type=0x04, flags=0x04 (clean_session), prot_id=1, duration=60, client_id='test'
    mqttsn_bytes = b"\x0a\x04\x04\x01\x00\x3c\x74\x65\x73\x74"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x04
    assert pkt.cleansess is True
    assert pkt.prot_id == 1
    assert pkt.duration == 60
    assert pkt.client_id == "test"


def test_parse_publish():
    """Parse a PUBLISH message with flags, tid, mid, and data."""
    # len=11, type=0x0c, flags=0x20 (QoS=1), tid=0x0001, mid=0x0001, data='temp'
    mqttsn_bytes = b"\x0b\x0c\x20\x00\x01\x00\x01temp"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x0C
    assert pkt.qos == 1
    assert pkt.tid == 1
    assert pkt.mid == 1
    assert pkt.data == b"temp"


def test_parse_pingreq():
    """Parse a minimal PINGREQ message."""
    mqttsn_bytes = b"\x02\x16"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x16


def test_parse_pingresp():
    """Parse a minimal PINGRESP message."""
    mqttsn_bytes = b"\x02\x17"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x17


def test_parse_disconnect():
    """Parse a minimal DISCONNECT message (no duration)."""
    mqttsn_bytes = b"\x02\x18"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x18


# ============================================================================
# 3. Field access tests
# ============================================================================


def test_field_access_gw_id_and_duration():
    """Verify gw_id and duration can be read via __getattr__."""
    mqttsn_bytes = b"\x05\x00\x42\x01\x2c"  # ADVERTISE: gw_id=0x42, duration=300
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.gw_id == 0x42
    assert pkt.duration == 300


def test_field_access_radius():
    """Verify radius can be read for SEARCHGW."""
    mqttsn_bytes = b"\x03\x01\x05"  # SEARCHGW, radius=5
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.radius == 5


def test_field_access_client_id():
    """Verify client_id can be read for CONNECT."""
    # CONNECT: len=12, type=0x04, flags=0x04, prot_id=1, dur=30, client_id='mydev1'
    mqttsn_bytes = b"\x0c\x04\x04\x01\x00\x1e\x6d\x79\x64\x65\x76\x31"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.client_id == "mydev1"


def test_field_access_tid_mid_data():
    """Verify tid, mid, and data for a PUBLISH message."""
    # PUBLISH: len=12, type=0x0c, flags=0x40(QoS=2), tid=0x00ff, mid=0x0042, data='hello'
    # Total = 1(len) + 1(type) + 1(flags) + 2(tid) + 2(mid) + 5(data) = 12
    mqttsn_bytes = b"\x0c\x0c\x40\x00\xff\x00\x42hello"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.tid == 0x00FF
    assert pkt.mid == 0x0042
    assert pkt.data == b"hello"


def test_getfieldval_layer_specific():
    """Verify getfieldval with LayerKind.MqttSn for layer-specific access."""
    mqttsn_bytes = b"\x05\x00\x01\x00\x0a"  # ADVERTISE: gw_id=1, duration=10
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x00
    assert pkt.getfieldval(LayerKind.MqttSn, "gw_id") == 1
    assert pkt.getfieldval(LayerKind.MqttSn, "duration") == 10
    assert pkt.getfieldval(LayerKind.MqttSn, "length") == 5


def test_getfieldval_flags_byte():
    """Verify flags byte access via getfieldval for a PUBLISH with QoS+DUP."""
    # PUBLISH: flags = DUP(1) + QoS(1) + Retain(0) = 0x80 | 0x20 = 0xA0
    mqttsn_bytes = b"\x09\x0c\xa0\x00\x01\x00\x01XY"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    flags = pkt.getfieldval(LayerKind.MqttSn, "flags")
    assert flags == 0xA0
    assert pkt.dup is True
    assert pkt.qos == 1
    assert pkt.retain is False


# ============================================================================
# 4. has_layer tests
# ============================================================================


def test_has_layer_mqttsn():
    """Verify has_layer returns True for MqttSn on a valid MQTT-SN packet."""
    mqttsn_bytes = b"\x02\x16"  # PINGREQ
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Udp)
    assert not pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Dns)


def test_non_mqttsn_port_no_layer():
    """UDP traffic not on port 1883 should NOT be detected as MQTT-SN."""
    mqttsn_bytes = b"\x02\x16"  # PINGREQ
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.MqttSn)


# ============================================================================
# 5. Layer order and stacking tests
# ============================================================================


def test_layer_order():
    """Verify the expected layer order: Ethernet / IPv4 / UDP / MqttSn."""
    mqttsn_bytes = b"\x02\x17"  # PINGRESP
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Ethernet in kinds
    assert LayerKind.Ipv4 in kinds
    assert LayerKind.Udp in kinds
    assert LayerKind.MqttSn in kinds
    # MQTT-SN should come after UDP
    udp_pos = kinds.index(LayerKind.Udp)
    mqttsn_pos = kinds.index(LayerKind.MqttSn)
    assert mqttsn_pos > udp_pos, "MQTT-SN should be after UDP"


def test_stacking_ether_ip_udp_mqttsn():
    """Build a stacked Ether/IP/UDP/MQTTSN packet and verify it parses."""
    pkt = Ether() / IP() / UDP(sport=1883, dport=1883) / MQTTSN(msg_type=0x0C, data=b"hello")
    built = pkt.build()
    built.parse()
    assert built.has_layer(LayerKind.MqttSn)
    assert built.has_layer(LayerKind.Ethernet)
    assert built.has_layer(LayerKind.Ipv4)
    assert built.has_layer(LayerKind.Udp)
    assert built.getfieldval(LayerKind.MqttSn, "type") == 0x0C
    assert built.data == b"hello"


# ============================================================================
# 6. Builder bytes and roundtrip tests
# ============================================================================


def test_builder_bytes_pingresp():
    """Verify builder bytes for a simple PINGRESP."""
    mqttsn = MQTTSN(msg_type=0x17)
    data = mqttsn.bytes()
    assert data == b"\x02\x17"


def test_builder_bytes_disconnect_with_duration():
    """Verify builder bytes for DISCONNECT with a non-zero duration."""
    mqttsn = MQTTSN(msg_type=0x18, duration=0x0312)
    data = mqttsn.bytes()
    assert data == b"\x04\x18\x03\x12"


def test_build_and_parse_roundtrip_advertise():
    """Build an ADVERTISE, wrap in Eth/IP/UDP, parse, and verify fields."""
    mqttsn = MQTTSN(msg_type=0x00, gw_id=0x98, duration=0x2B9A)
    built = mqttsn.bytes()
    raw = make_eth_ip_udp_mqttsn(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x00
    assert pkt.gw_id == 0x98
    assert pkt.duration == 0x2B9A


def test_build_and_parse_roundtrip_publish():
    """Build a PUBLISH, wrap, parse, and verify all fields."""
    mqttsn = MQTTSN(msg_type=0x0C, qos=2, dup=True, tid=0xBEEF, mid=0xCAFE, data=b"payload")
    built = mqttsn.bytes()
    raw = make_eth_ip_udp_mqttsn(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.getfieldval(LayerKind.MqttSn, "type") == 0x0C
    assert pkt.dup is True
    assert pkt.qos == 2
    assert pkt.tid == 0xBEEF
    assert pkt.mid == 0xCAFE
    assert pkt.data == b"payload"


def test_build_and_parse_roundtrip_connect():
    """Build a CONNECT, wrap, parse, and verify flags and client_id."""
    mqttsn = MQTTSN(
        msg_type=0x04,
        clean_session=True,
        will=True,
        prot_id=1,
        duration=120,
        client_id=b"device42",
    )
    built = mqttsn.bytes()
    raw = make_eth_ip_udp_mqttsn(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.cleansess is True
    assert pkt.will is True
    assert pkt.prot_id == 1
    assert pkt.duration == 120
    assert pkt.client_id == "device42"


# ============================================================================
# 7. get_layer_bytes and fields property tests
# ============================================================================


def test_get_layer_bytes():
    """Verify get_layer_bytes returns the correct MQTT-SN bytes."""
    mqttsn_bytes = b"\x05\x00\x01\x00\x3c"  # ADVERTISE: gw_id=1, duration=60
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.MqttSn)
    assert layer_bytes == mqttsn_bytes


def test_fields_property():
    """Verify the fields property contains expected MQTT-SN field names."""
    mqttsn_bytes = b"\x02\x16"  # PINGREQ
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    fields = pkt.fields
    assert "type" in fields
    assert "gw_id" in fields
    assert "duration" in fields
    assert "tid" in fields
    assert "mid" in fields
    assert "data" in fields
    assert "client_id" in fields


# ============================================================================
# 8. show() and LayerKind identity tests
# ============================================================================


def test_show_includes_mqttsn():
    """Verify show() output mentions MQTT-SN."""
    mqttsn_bytes = b"\x05\x00\x01\x00\x3c"
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "MQTT" in show


def test_layer_kind_identity():
    """Verify LayerKind.MqttSn can be imported and used."""
    assert LayerKind.MqttSn is not None


# ============================================================================
# 9. Edge-case and additional message type tests
# ============================================================================


def test_build_connack():
    """Build a CONNACK message with return_code."""
    mqttsn = MQTTSN(msg_type=0x05, return_code=0)
    data = mqttsn.bytes()
    # CONNACK: length(1) + type(1) + return_code(1) = 3
    assert len(data) == 3
    assert data[1] == 0x05
    assert data[2] == 0  # accepted


def test_parse_connack():
    """Parse a CONNACK message and verify return_code."""
    mqttsn_bytes = b"\x03\x05\x02"  # CONNACK, return_code=2 (rejected: invalid TID)
    raw = make_eth_ip_udp_mqttsn(mqttsn_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.MqttSn)
    assert pkt.return_code == 2


def test_build_register():
    """Build a REGISTER message with tid, mid, and topic_name."""
    mqttsn = MQTTSN(msg_type=0x0A, tid=1, mid=2, topic_name=b"sensors/temp")
    data = mqttsn.bytes()
    # REGISTER: length(1) + type(1) + tid(2) + mid(2) + topic(12) = 18
    assert len(data) == 18
    assert data[0] == 18
    assert data[1] == 0x0A
    assert data[6:] == b"sensors/temp"


def test_build_puback():
    """Build a PUBACK message with tid, mid, return_code."""
    mqttsn = MQTTSN(msg_type=0x0D, tid=1, mid=2, return_code=0)
    data = mqttsn.bytes()
    # PUBACK: length(1) + type(1) + tid(2) + mid(2) + rc(1) = 7
    assert len(data) == 7
    assert data[1] == 0x0D
    assert data[6] == 0  # accepted
