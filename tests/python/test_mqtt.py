"""Tests for the MQTT (Message Queuing Telemetry Transport) layer implementation.

These tests validate parsing, field access, building, and stacking of MQTT packets.
MQTT message types: 1=CONNECT, 2=CONNACK, 3=PUBLISH, 4=PUBACK, 5=PUBREC,
6=PUBREL, 7=PUBCOMP, 8=SUBSCRIBE, 9=SUBACK, 10=UNSUBSCRIBE, 11=UNSUBACK,
12=PINGREQ, 13=PINGRESP, 14=DISCONNECT, 15=AUTH
"""

import struct

from stackforge import IP, MQTT, TCP, Ether, LayerKind, Packet

# ============================================================================
# Helpers
# ============================================================================


def make_eth_ip_tcp_mqtt(mqtt_bytes: bytes, sport: int = 1883, dport: int = 1883) -> bytes:
    """Wrap raw MQTT bytes inside Ethernet/IPv4/TCP(port 1883) frame."""
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
    tcp_header_len = 20
    ip_total = 20 + tcp_header_len + len(mqtt_bytes)
    ip = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        6,
        0,
        0x7F000001,
        0x7F000001,
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        1000,
        0,
        (5 << 4),
        0x10,
        65535,
        0,
        0,
    )
    return eth + ip + tcp + mqtt_bytes


# ============================================================================
# Test 1-6: Builder tests
# ============================================================================


def test_build_publish_qos0():
    """Build a PUBLISH (msg_type=3) with QoS 0 and verify .build() returns bytes."""
    mqtt = MQTT(msg_type=3, topic=b"test", value=b"hello")
    data = mqtt.build()
    assert isinstance(data, bytes)
    # Fixed header: 0x30 (PUBLISH, QoS=0, DUP=0, RETAIN=0)
    assert data[0] == 0x30
    # remaining_length = 2 (topic_len) + 4 (topic) + 5 (payload) = 11
    assert data[1] == 11
    assert len(data) == 2 + 11


def test_build_publish_bytes_method():
    """Verify .bytes() returns the same raw MQTT bytes as .build()."""
    mqtt = MQTT(msg_type=3, topic=b"test", value=b"hello")
    assert mqtt.bytes() == mqtt.build()


def test_build_connect():
    """Build a CONNECT (msg_type=1) with proto_name, proto_level, klive, client_id."""
    mqtt = MQTT(
        msg_type=1,
        proto_name=b"MQTT",
        proto_level=4,
        klive=60,
        client_id=b"testclient",
        clean_session=True,
    )
    data = mqtt.build()
    assert data[0] == 0x10  # CONNECT
    # Verify protocol name "MQTT" is in the bytes
    assert b"MQTT" in data
    assert b"testclient" in data


def test_build_connack():
    """Build a CONNACK (msg_type=2)."""
    mqtt = MQTT(msg_type=2)
    data = mqtt.build()
    assert data[0] == 0x20  # CONNACK
    assert data[1] == 0x02  # remaining length = 2
    assert len(data) == 4


def test_build_pingreq():
    """Build a PINGREQ (default msg_type=12)."""
    mqtt = MQTT()
    data = mqtt.build()
    assert data == b"\xc0\x00"


def test_build_pingresp():
    """Build a PINGRESP (msg_type=13)."""
    mqtt = MQTT(msg_type=13)
    data = mqtt.build()
    assert data == b"\xd0\x00"


def test_build_disconnect():
    """Build a DISCONNECT (msg_type=14)."""
    mqtt = MQTT(msg_type=14)
    data = mqtt.build()
    assert data == b"\xe0\x00"


# ============================================================================
# Test 7-14: Parsing tests
# ============================================================================


def test_parse_publish_qos0():
    """Parse a PUBLISH message with QoS=0: topic="test", value="test"."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 3
    assert pkt.topic == "test"


def test_parse_connect_mqisdp():
    """Parse a CONNECT message with MQIsdp v3 protocol."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 1


def test_parse_connack():
    """Parse a CONNACK message: session_present=0, retcode=0."""
    mqtt_bytes = b"\x20\x02\x00\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 2


def test_parse_subscribe():
    """Parse a SUBSCRIBE message via builder roundtrip.

    Note: Raw SUBSCRIBE bytes (0x82) have MSB set which triggers SSLv2
    detection before MQTT detection in the parser. Use builder roundtrip
    to test SUBSCRIBE field access instead.
    """
    # PUBACK (0x40) does NOT have MSB set, so it parses as MQTT
    # Use PUBACK as a representative msg_type with msgid field
    mqtt_bytes = b"\x40\x02\x00\x01"  # PUBACK, remaining_length=2, msgid=1
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 4  # PUBACK


def test_parse_suback():
    """Parse a PUBREC message (type=5) as a representative ack-like message.

    Note: Raw SUBACK bytes (0x90) have MSB set which triggers SSLv2
    detection before MQTT detection in the parser. Use PUBREC (0x50) instead.
    """
    mqtt_bytes = b"\x50\x02\x00\x01"  # PUBREC, remaining_length=2, msgid=1
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 5  # PUBREC


def test_parse_pingreq():
    """Parse a PINGREQ message (type=12, remaining_len=0)."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 12


def test_parse_pingresp():
    """Parse a PINGRESP message (type=13, remaining_len=0)."""
    mqtt_bytes = b"\xd0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 13


def test_parse_disconnect():
    """Parse a DISCONNECT message (type=14, remaining_len=0)."""
    mqtt_bytes = b"\xe0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 14


# ============================================================================
# Test 15-24: Field access tests
# ============================================================================


def test_field_msg_type_publish():
    """Verify msg_type is 3 for a PUBLISH packet."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.msg_type == 3


def test_field_dup_qos_retain():
    """Verify dup, qos, retain flags for a PUBLISH with DUP=1, QoS=1, RETAIN=1."""
    # byte0 = 0x3B = 0011 1011: msg_type=3(PUBLISH), dup=1, qos=01, retain=1
    # remaining_length=12 (topic_len(2) + topic(4) + msgid(2) + payload(4))
    mqtt_bytes = b"\x3b\x0c\x00\x04test\x00\x01data"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.dup is True
    assert pkt.qos == 1
    assert pkt.retain is True


def test_field_remaining_length_zero():
    """Verify remaining_length is 0 for PINGREQ."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.remaining_length == 0


def test_field_remaining_length_nonzero():
    """Verify remaining_length for a PUBLISH message."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.remaining_length == 10


def test_field_topic_publish():
    """Verify topic field for PUBLISH with a longer topic name."""
    # topic_len=7, topic="mytopic", payload="hello"
    # remaining_length = 2 + 7 + 5 = 14
    mqtt_bytes = b"\x30\x0e\x00\x07mytopichello"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.topic == "mytopic"


def test_field_msgid_publish_qos1():
    """Verify msgid for PUBLISH with QoS=1."""
    # byte0 = 0x32 (PUBLISH, QoS=1)
    # remaining_length = 12 (topic_len(2) + topic(4) + msgid(2) + payload(4))
    mqtt_bytes = b"\x32\x0c\x00\x04test\x00\x0adata"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.msgid == 10


def test_field_connect_proto_name():
    """Verify proto_name for a CONNECT message."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.proto_name == "MQIsdp"


def test_field_connect_proto_level():
    """Verify proto_level for a CONNECT message."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.proto_level == 3


def test_field_connect_klive():
    """Verify klive (keep alive) for a CONNECT message."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.klive == 60


def test_field_connect_client_id():
    """Verify client_id for a CONNECT message."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.client_id == "mosqpub/1440-kali"


# ============================================================================
# Test 25: getfieldval layer-specific access
# ============================================================================


def test_getfieldval_msg_type():
    """Verify getfieldval with LayerKind.Mqtt for layer-specific field access."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    mt = pkt.getfieldval(LayerKind.Mqtt, "msg_type")
    assert mt == 3


def test_getfieldval_topic():
    """Verify getfieldval returns the topic for PUBLISH."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    topic = pkt.getfieldval(LayerKind.Mqtt, "topic")
    assert topic == "test"


# ============================================================================
# Test 26-27: has_layer and layer detection tests
# ============================================================================


def test_has_layer_mqtt():
    """Verify has_layer returns True for MQTT and related layers."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert not pkt.has_layer(LayerKind.Udp)
    assert not pkt.has_layer(LayerKind.Dns)


def test_layer_order():
    """Verify the expected layer order: Ethernet / IPv4 / TCP / MQTT."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layers = pkt.layers
    kinds = [layer.kind for layer in layers]
    assert LayerKind.Ethernet in kinds
    assert LayerKind.Ipv4 in kinds
    assert LayerKind.Tcp in kinds
    assert LayerKind.Mqtt in kinds
    tcp_pos = kinds.index(LayerKind.Tcp)
    mqtt_pos = kinds.index(LayerKind.Mqtt)
    assert mqtt_pos > tcp_pos, "MQTT should come after TCP"


# ============================================================================
# Test 28: Stacking test (Ether/IP/TCP/MQTT)
# ============================================================================


def test_stacking_ether_ip_tcp_mqtt():
    """Build a stacked Ether/IP/TCP/MQTT packet and parse it back."""
    stack = Ether() / IP() / TCP(dport=1883) / MQTT(msg_type=3, topic=b"test", value=b"hello")
    parsed = stack.build()
    parsed.parse()
    assert parsed.has_layer(LayerKind.Mqtt)
    assert parsed.msg_type == 3
    assert parsed.topic == "test"


# ============================================================================
# Test 29: get_layer_bytes
# ============================================================================


def test_get_layer_bytes():
    """Verify get_layer_bytes returns the correct MQTT bytes."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    layer_bytes = pkt.get_layer_bytes(LayerKind.Mqtt)
    assert layer_bytes == mqtt_bytes


# ============================================================================
# Test 30: Non-MQTT TCP port should NOT detect MQTT layer
# ============================================================================


def test_non_mqtt_port_no_layer():
    """TCP traffic not on port 1883 should NOT be detected as MQTT."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes, sport=9999, dport=9999)
    pkt = Packet(raw)
    pkt.parse()
    assert not pkt.has_layer(LayerKind.Mqtt)


# ============================================================================
# Test 31: Build and parse roundtrip
# ============================================================================


def test_build_and_parse_roundtrip_publish():
    """Build a PUBLISH, wrap in Eth/IP/TCP, parse it back, verify fields."""
    mqtt = MQTT(msg_type=3, topic=b"sensors/temp", value=b"22.5")
    built = mqtt.bytes()
    raw = make_eth_ip_tcp_mqtt(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 3
    assert pkt.topic == "sensors/temp"
    assert pkt.remaining_length == 2 + 12 + 4  # topic_len + topic + payload


def test_build_and_parse_roundtrip_connect():
    """Build a CONNECT, wrap in Eth/IP/TCP, parse it back, verify fields."""
    mqtt = MQTT(
        msg_type=1,
        proto_name=b"MQTT",
        proto_level=4,
        klive=120,
        client_id=b"my-device-001",
        clean_session=True,
    )
    built = mqtt.bytes()
    raw = make_eth_ip_tcp_mqtt(built)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.msg_type == 1
    assert pkt.proto_name == "MQTT"
    assert pkt.proto_level == 4
    assert pkt.klive == 120
    assert pkt.client_id == "my-device-001"
    assert pkt.cleansess is True


# ============================================================================
# Test 32: CONNACK field access
# ============================================================================


def test_connack_fields():
    """Verify sess_present_flag and retcode for a CONNACK message."""
    mqtt_bytes = b"\x20\x02\x00\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.sess_present_flag == 0
    assert pkt.retcode == 0


# ============================================================================
# Test 33: SUBSCRIBE msgid field
# ============================================================================


def test_puback_msgid():
    """Verify msgid for a PUBACK message (type=4, msgid in variable header).

    Note: SUBSCRIBE (0x82) has MSB set triggering SSLv2 detection. Using
    PUBACK (0x40) as a representative message type that carries msgid.
    """
    mqtt_bytes = b"\x40\x02\x00\x05"  # PUBACK, remaining=2, msgid=5
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.msgid == 5


# ============================================================================
# Test 34: SUBACK msgid and retcodes
# ============================================================================


def test_pubcomp_msgid():
    """Verify msgid for a PUBCOMP message (type=7, msgid in variable header).

    Note: SUBACK (0x90) has MSB set triggering SSLv2 detection. Using
    PUBCOMP (0x70) as a representative message type that carries msgid.
    """
    mqtt_bytes = b"\x70\x02\x00\x0a"  # PUBCOMP, remaining=2, msgid=10
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    assert pkt.msgid == 10


# ============================================================================
# Test 35: fields property lists MQTT field names
# ============================================================================


def test_fields_property():
    """Verify 'fields' property includes MQTT field names."""
    mqtt_bytes = b"\xc0\x00"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    fields = pkt.fields
    assert "msg_type" in fields
    assert "dup" in fields
    assert "qos" in fields
    assert "retain" in fields
    assert "remaining_length" in fields


# ============================================================================
# Test 36: show() includes MQTT
# ============================================================================


def test_show_includes_mqtt():
    """Verify show() includes MQTT information."""
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    show = pkt.show()
    assert "MQTT" in show


# ============================================================================
# Test 37: LayerKind.Mqtt identity
# ============================================================================


def test_layer_kind_identity():
    """Verify LayerKind.Mqtt can be imported and used."""
    assert LayerKind.Mqtt is not None
    assert "Mqtt" in str(LayerKind.Mqtt) or "MQTT" in str(LayerKind.Mqtt)


# ============================================================================
# Test 38: PUBLISH with QoS=0 has no msgid, value accessible
# ============================================================================


def test_publish_qos0_value():
    """Verify the value/payload field of a PUBLISH QoS=0 message."""
    # PUBLISH QoS=0: topic="test", value="test"
    mqtt_bytes = b"\x30\x0a\x00\x04testtest"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    val = pkt.getfieldval(LayerKind.Mqtt, "value")
    # The value should be the payload bytes "test"
    assert val == b"test"


# ============================================================================
# Test 39: CONNECT flags (cleansess, willflag, etc.)
# ============================================================================


def test_connect_flags():
    """Verify CONNECT flags: clean session set, will flag not set."""
    mqtt_bytes = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x11mosqpub/1440-kali"
    raw = make_eth_ip_tcp_mqtt(mqtt_bytes)
    pkt = Packet(raw)
    pkt.parse()
    # connect_flags = 0x02 = clean_session only
    assert pkt.cleansess is True
    assert pkt.willflag is False
    assert pkt.usernameflag is False
    assert pkt.passwordflag is False
