"""UTS-driven MQTT tests.

Translates assertions from tests/uts/mqtt.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw MQTT bytes
must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_mqtt() constructs a minimal such frame targeting TCP port 1883.
"""

import struct

from stackforge import MQTT, LayerKind, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 1883) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame carrying the given payload."""
    tcp_header_len = 20
    ip_total = 20 + tcp_header_len + len(payload)

    eth = bytes(
        [
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # dst MAC
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,  # src MAC
            0x08,
            0x00,  # EtherType: IPv4
        ]
    )
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
    return eth + ip + tcp + payload


def _parse_mqtt(mqtt_bytes: bytes, dport: int = 1883) -> Packet:
    """Wrap raw MQTT bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(mqtt_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: Fixed header and MQTTPublish, packet dissection
# ============================================================================


def test_uts_mqtt_publish_dissect():
    """
    UTS: s = b'\\x30\\x0a\\x00\\x04testtest'
         publish = MQTT(s)
         assert publish.type == 3
         assert publish.QOS == 0
         assert publish.DUP == 0
         assert publish.RETAIN == 0
         assert publish.len == 10
         assert publish[MQTTPublish].length == 4
         assert publish[MQTTPublish].topic == b'test'
         assert publish[MQTTPublish].value == b'test'
    """
    mqtt_payload = b"\x30\x0a\x00\x04testtest"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 3
    assert pkt.getfieldval(LayerKind.Mqtt, "qos") == 0
    assert pkt.getfieldval(LayerKind.Mqtt, "dup") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "retain") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "remaining_length") == 10
    assert pkt.getfieldval(LayerKind.Mqtt, "topic_len") == 4
    assert pkt.getfieldval(LayerKind.Mqtt, "topic") == "test"
    assert pkt.getfieldval(LayerKind.Mqtt, "value") == b"test"


# ============================================================================
# UTS: MQTTConnect, packet dissection
# ============================================================================


def test_uts_mqtt_connect_dissect():
    """
    UTS: s = b'\\x10\\x1f\\x00\\x06MQIsdp\\x03\\x02\\x00<\\x00\\x11mosqpub/1440-kali'
         connect = MQTT(s)
         assert connect.protoname == b'MQIsdp'
         assert connect.protolevel == 3
         assert connect.usernameflag == 0
         assert connect.passwordflag == 0
         assert connect.willretainflag == 0
         assert connect.willQOSflag == 0
         assert connect.willflag == 0
         assert connect.cleansess == 1
         assert connect.reserved == 0
         assert connect.klive == 60
         assert connect.clientIdlen == 17
         assert connect.clientId == b'mosqpub/1440-kali'
    """
    mqtt_payload = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00<\x00\x11mosqpub/1440-kali"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 1  # CONNECT
    assert pkt.getfieldval(LayerKind.Mqtt, "proto_name") == "MQIsdp"
    assert pkt.getfieldval(LayerKind.Mqtt, "proto_level") == 3
    assert pkt.getfieldval(LayerKind.Mqtt, "usernameflag") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "passwordflag") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "willretainflag") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "willQOSflag") == 0
    assert pkt.getfieldval(LayerKind.Mqtt, "willflag") is False
    assert pkt.getfieldval(LayerKind.Mqtt, "cleansess") is True
    assert pkt.getfieldval(LayerKind.Mqtt, "klive") == 60
    assert pkt.getfieldval(LayerKind.Mqtt, "client_id") == "mosqpub/1440-kali"


def test_uts_mqtt_connect_remaining_length():
    """Verify the remaining length in the CONNECT packet."""
    mqtt_payload = b"\x10\x1f\x00\x06MQIsdp\x03\x02\x00<\x00\x11mosqpub/1440-kali"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.getfieldval(LayerKind.Mqtt, "remaining_length") == 0x1F


# ============================================================================
# UTS: MQTTConnack, packet dissection
# ============================================================================


def test_uts_mqtt_connack_dissect():
    """
    UTS: s = b'\\x20\\x02\\x00\\x00'
         connack = MQTT(s)
         assert connack.sessPresentFlag == 0
         assert connack.retcode == 0
    """
    mqtt_payload = b"\x20\x02\x00\x00"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 2  # CONNACK
    assert pkt.getfieldval(LayerKind.Mqtt, "sess_present_flag") == 0
    assert pkt.getfieldval(LayerKind.Mqtt, "retcode") == 0


# ============================================================================
# UTS: MQTTSubscribe, packet dissection
# ============================================================================


def test_uts_mqtt_subscribe_dissect():
    """
    UTS: s = b'\\x82\\x09\\x00\\x01\\x00\\x04test\\x01'
         subscribe = MQTT(s)
         assert subscribe.msgid == 1
         assert subscribe.topics[0].length == 4
         assert subscribe.topics[0].topic == b'test'
         assert subscribe.topics[0].QOS == 1
    """
    mqtt_payload = b"\x82\x09\x00\x01\x00\x04test\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 8  # SUBSCRIBE
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: MQTTSuback, packet dissection
# ============================================================================


def test_uts_mqtt_suback_dissect():
    """
    UTS: s = b'\\x90\\x03\\x00\\x01\\x00'
         suback = MQTT(s)
         assert suback.msgid == 1
         assert suback.retcodes == [0]
    """
    mqtt_payload = b"\x90\x03\x00\x01\x00"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 9  # SUBACK
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1
    assert pkt.getfieldval(LayerKind.Mqtt, "retcodes") == b"\x00"


def test_uts_mqtt_suback_multi_retcodes():
    """
    UTS: s = b'\\x90\\x03\\x00\\x01\\x00\\x01'
         suback = MQTT(s)
         assert suback.msgid == 1
         assert suback.retcodes == [0, 1]
    """
    mqtt_payload = b"\x90\x04\x00\x01\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1
    assert pkt.getfieldval(LayerKind.Mqtt, "retcodes") == b"\x00\x01"


# ============================================================================
# UTS: PINGREQ
# ============================================================================


def test_uts_mqtt_pingreq():
    """
    UTS: MQTT pingreq has type == 12.
         b'\\xc0\\x00' -> type=12
    """
    mqtt_payload = b"\xc0\x00"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 12  # PINGREQ
    assert pkt.getfieldval(LayerKind.Mqtt, "remaining_length") == 0


# ============================================================================
# UTS: DISCONNECT
# ============================================================================


def test_uts_mqtt_disconnect():
    """
    UTS: dc.type == 14 for DISCONNECT.
         b'\\xe0\\x00' -> type=14
    """
    mqtt_payload = b"\xe0\x00"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 14  # DISCONNECT
    assert pkt.getfieldval(LayerKind.Mqtt, "remaining_length") == 0


# ============================================================================
# UTS: MQTTUnsubscribe, packet dissection
# ============================================================================


def test_uts_mqtt_unsubscribe_dissect():
    """
    UTS: u = b'\\xA2\\x09\\x00\\x01\\x00\\x03\\x61\\x2F\\x62'
         unsubscribe = MQTT(u)
         assert unsubscribe.msgid == 1
         assert unsubscribe.topics[0].length == 3
         assert unsubscribe.topics[0].topic == b'a/b'
    """
    mqtt_payload = b"\xa2\x09\x00\x01\x00\x03\x61\x2f\x62"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 10  # UNSUBSCRIBE
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: MQTTUnsuback, packet dissection
# ============================================================================


def test_uts_mqtt_unsuback_dissect():
    """
    UTS: u = b'\\xb0\\x02\\x00\\x01'
         unsuback = MQTT(u)
         assert unsuback.type == 11
         assert unsuback.msgid == 1
    """
    mqtt_payload = b"\xb0\x02\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 11  # UNSUBACK
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: MQTTPubrec, packet dissection
# ============================================================================


def test_uts_mqtt_pubrec_dissect():
    """
    UTS: s = b'P\\x02\\x00\\x01'
         pubrec = MQTT(s)
         assert pubrec.msgid == 1
    """
    mqtt_payload = b"\x50\x02\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt), "MQTT layer not found"
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 5  # PUBREC
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: MQTT without payload -> b'\x10\x00'
# ============================================================================


def test_uts_mqtt_default_build():
    """
    UTS: p = MQTT()
         assert bytes(p) == b'\\x10\\x00'

    Scapy defaults to CONNECT, but Stackforge defaults to PINGREQ (\\xC0\\x00).
    Verify that the default builder produces a valid 2-byte MQTT packet.
    """
    builder = MQTT()
    data = builder.bytes()
    # Default builder produces msg_type=12 (PINGREQ), remaining_length=0
    assert data[0] >> 4 == 12  # PINGREQ type in high nibble
    assert data[1] == 0  # remaining length = 0


# ============================================================================
# UTS: MQTTPublish with QOS=1 (has msgid)
# ============================================================================


def test_uts_mqtt_publish_qos1():
    """
    UTS: p1 = MQTT(QOS=1) / MQTTPublish(topic=topicC, msgid=1234, value="msg1")
         => type=3, QOS=1 implies DUP bit position and msgid present.
    """
    # Build a PUBLISH with QoS=1: type=3, DUP=0, QoS=1, RETAIN=0
    # Fixed header: 0x32 = 0011 0010 -> type=3, dup=0, qos=1, retain=0
    topic = b"testtopic/command"
    msgid = 1234
    value = b"msg1"
    topic_len = struct.pack("!H", len(topic))
    msgid_bytes = struct.pack("!H", msgid)
    payload = topic_len + topic + msgid_bytes + value
    remaining_len = len(payload)
    mqtt_payload = bytes([0x32, remaining_len]) + payload

    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 3
    assert pkt.getfieldval(LayerKind.Mqtt, "qos") == 1
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1234
    assert pkt.getfieldval(LayerKind.Mqtt, "topic") == "testtopic/command"
    assert pkt.getfieldval(LayerKind.Mqtt, "value") == b"msg1"


# ============================================================================
# Additional: Verify layers present
# ============================================================================


def test_uts_mqtt_has_all_layers():
    """Verify Ethernet/IPv4/TCP/MQTT layers are all present."""
    mqtt_payload = b"\x30\x0a\x00\x04testtest"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Mqtt)


# ============================================================================
# UTS: PUBACK type=4
# ============================================================================


def test_uts_mqtt_puback():
    """
    UTS: PUBACK has type == 4.
         b'\\x40\\x02\\x00\\x01' -> type=4, msgid=1
    """
    mqtt_payload = b"\x40\x02\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 4  # PUBACK
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: PUBREL type=6
# ============================================================================


def test_uts_mqtt_pubrel():
    """
    PUBREL has type == 6.
    b'\\x62\\x02\\x00\\x01' -> type=6, qos=1, msgid=1
    """
    mqtt_payload = b"\x62\x02\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 6  # PUBREL
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: PUBCOMP type=7
# ============================================================================


def test_uts_mqtt_pubcomp():
    """
    PUBCOMP has type == 7.
    b'\\x70\\x02\\x00\\x01' -> type=7, msgid=1
    """
    mqtt_payload = b"\x70\x02\x00\x01"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 7  # PUBCOMP
    assert pkt.getfieldval(LayerKind.Mqtt, "msgid") == 1


# ============================================================================
# UTS: PINGRESP type=13
# ============================================================================


def test_uts_mqtt_pingresp():
    """
    PINGRESP has type == 13.
    b'\\xd0\\x00' -> type=13
    """
    mqtt_payload = b"\xd0\x00"
    pkt = _parse_mqtt(mqtt_payload)

    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 13  # PINGRESP
    assert pkt.getfieldval(LayerKind.Mqtt, "remaining_length") == 0


# ============================================================================
# Builder: verify MQTT builder produces parseable bytes
# ============================================================================


def test_uts_mqtt_builder_roundtrip():
    """Build an MQTT PUBLISH and verify it can be parsed back."""
    builder = MQTT(msg_type=3, topic=b"test", value=b"hello")
    data = builder.bytes()

    pkt = _parse_mqtt(data)
    assert pkt.has_layer(LayerKind.Mqtt)
    assert pkt.getfieldval(LayerKind.Mqtt, "msg_type") == 3
    assert pkt.getfieldval(LayerKind.Mqtt, "topic") == "test"
    assert pkt.getfieldval(LayerKind.Mqtt, "value") == b"hello"
