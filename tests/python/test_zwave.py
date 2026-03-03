"""Tests for the Z-Wave wireless protocol layer implementation.

These tests validate building, field access, CRC verification, and frame
structure of Z-Wave packets. Since Z-Wave is a wireless protocol and not
carried over Ethernet/IP/TCP/UDP, tests focus on the builder API and raw
byte verification rather than Packet.parse()-based parsing.
"""

import struct

from stackforge import ZWave

# ============================================================================
# Helpers
# ============================================================================


def compute_zwave_crc(data: bytes) -> int:
    """Compute Z-Wave CRC: XOR all bytes starting from 0xFF."""
    crc = 0xFF
    for b in data:
        crc ^= b
    return crc


# ============================================================================
# Z-Wave command class constants
# ============================================================================

CC_BASIC = 0x20
CC_SWITCH_BINARY = 0x25
CC_SWITCH_MULTILEVEL = 0x26
CC_SENSOR_BINARY = 0x30
CC_SENSOR_MULTILEVEL = 0x31
CC_METER = 0x32
CC_CONFIGURATION = 0x70
CC_ALARM = 0x71
CC_BATTERY = 0x80
CC_WAKE_UP = 0x84
CC_ASSOCIATION = 0x85
CC_VERSION = 0x86
CC_SECURITY = 0x98


# ============================================================================
# Test 1: Build default ACK frame
# ============================================================================


def test_build_default_ack():
    """Build default ZWave() with no cmd_class -- produces a 10-byte ACK frame."""
    zw = ZWave()
    data = zw.bytes()
    # Default builder: home_id=0, src=1, dst=2, ackreq=True, no cmd_class -> ACK
    assert len(data) == 10, f"Expected 10-byte ACK frame, got {len(data)}"


def test_build_default_field_values():
    """Verify default field positions in the built ACK frame."""
    zw = ZWave()
    data = zw.bytes()
    # Home ID at bytes 0-3 (big-endian)
    home_id = struct.unpack("!I", data[0:4])[0]
    assert home_id == 0, f"Expected home_id=0, got {home_id:#010x}"
    # Source at byte 4
    assert data[4] == 1, f"Expected src=1, got {data[4]}"
    # Destination at byte 8
    assert data[8] == 2, f"Expected dst=2, got {data[8]}"


# ============================================================================
# Test 2: Build ACK frame with custom home_id, src, dst
# ============================================================================


def test_build_ack_custom_ids():
    """Build ACK frame with custom home_id, src, and dst."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, ackreq=False)
    data = zw.bytes()
    assert len(data) == 10, f"Expected 10 bytes, got {len(data)}"
    # Home ID at bytes 0-3 big-endian
    home_id = struct.unpack("!I", data[0:4])[0]
    assert home_id == 0x12345678
    # Source at byte 4
    assert data[4] == 1
    # Destination at byte 8
    assert data[8] == 2
    # CRC at byte 9
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[9] == expected_crc


# ============================================================================
# Test 3: Build REQ frame with BASIC SET
# ============================================================================


def test_build_req_basic_set():
    """Build REQ frame with BASIC SET command (cmd_class=0x20, cmd=0x01, data=0xFF)."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=CC_BASIC, cmd=0x01, cmd_data=b"\xff")
    data = zw.bytes()
    # 10 header + 3 payload (cmd_class + cmd + 1 byte data) = 13
    assert len(data) == 13, f"Expected 13 bytes, got {len(data)}"
    # cmd_class at byte 9
    assert data[9] == CC_BASIC
    # cmd at byte 10
    assert data[10] == 0x01
    # cmd_data at byte 11
    assert data[11] == 0xFF
    # CRC at byte 12
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[12] == expected_crc


# ============================================================================
# Test 4: Build REQ frame with SWITCH_BINARY
# ============================================================================


def test_build_req_switch_binary():
    """Build REQ frame with SWITCH_BINARY ON command."""
    zw = ZWave(
        home_id=0xAABBCCDD, src=5, dst=10, cmd_class=CC_SWITCH_BINARY, cmd=0x01, cmd_data=b"\xff"
    )
    data = zw.bytes()
    assert len(data) == 13
    home_id = struct.unpack("!I", data[0:4])[0]
    assert home_id == 0xAABBCCDD
    assert data[4] == 5  # src
    assert data[8] == 10  # dst
    assert data[9] == CC_SWITCH_BINARY
    assert data[10] == 0x01
    assert data[11] == 0xFF


# ============================================================================
# Test 5: Frame control flags encoding
# ============================================================================


def test_frame_control_flags():
    """Verify frame control byte encoding: routed=bit7, ackreq=bit6, etc."""
    zw = ZWave(
        home_id=0x12345678,
        src=1,
        dst=2,
        routed=True,
        ackreq=True,
        lowpower=False,
        speedmodified=False,
    )
    data = zw.bytes()
    fc = data[5]
    # routed -> bit 7
    assert fc & 0x80 != 0, "routed bit should be set"
    # ackreq -> bit 6
    assert fc & 0x40 != 0, "ackreq bit should be set"
    # lowpower -> bit 5
    assert fc & 0x20 == 0, "lowpower bit should be clear"
    # speedmodified -> bit 4
    assert fc & 0x10 == 0, "speedmodified bit should be clear"


def test_frame_control_all_flags():
    """Verify all frame control flags set simultaneously."""
    zw = ZWave(
        home_id=0x12345678,
        src=1,
        dst=2,
        routed=True,
        ackreq=True,
        lowpower=True,
        speedmodified=True,
        headertype=0x03,
    )
    data = zw.bytes()
    fc = data[5]
    assert fc & 0x80 != 0, "routed bit should be set"
    assert fc & 0x40 != 0, "ackreq bit should be set"
    assert fc & 0x20 != 0, "lowpower bit should be set"
    assert fc & 0x10 != 0, "speedmodified bit should be set"
    assert fc & 0x0F == 0x03, f"headertype should be 3, got {fc & 0x0F}"


# ============================================================================
# Test 6: Beam control and sequence number encoding
# ============================================================================


def test_beam_control_and_sequence():
    """Verify beam/sequence byte encoding: beam_control at bits 6-5, seqn at bits 3-0."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, seqn=7, beam_control=1)
    data = zw.bytes()
    beam_seqn = data[6]
    # beam_control at bits 6-5
    beam = (beam_seqn >> 5) & 0x03
    assert beam == 1, f"Expected beam_control=1, got {beam}"
    # seqn at bits 3-0
    seqn = beam_seqn & 0x0F
    assert seqn == 7, f"Expected seqn=7, got {seqn}"


def test_beam_control_max():
    """Verify beam_control=3 (maximum 2-bit value) and seqn=15 (maximum 4-bit)."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, beam_control=3, seqn=15)
    data = zw.bytes()
    beam_seqn = data[6]
    beam = (beam_seqn >> 5) & 0x03
    assert beam == 3
    seqn = beam_seqn & 0x0F
    assert seqn == 15


# ============================================================================
# Test 7: CRC verification
# ============================================================================


def test_crc_ack_frame():
    """Verify CRC is correct for an ACK frame."""
    zw = ZWave(home_id=0x01020304, src=10, dst=20)
    data = zw.bytes()
    expected_crc = compute_zwave_crc(data[:-1])
    assert (
        data[-1] == expected_crc
    ), f"CRC mismatch: got {data[-1]:#04x}, expected {expected_crc:#04x}"


def test_crc_req_frame():
    """Verify CRC is correct for a REQ frame with payload."""
    zw = ZWave(
        home_id=0xDEADBEEF, src=3, dst=5, cmd_class=CC_SWITCH_BINARY, cmd=0x01, cmd_data=b"\xff"
    )
    data = zw.bytes()
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[-1] == expected_crc


# ============================================================================
# Test 8: Home ID is big-endian
# ============================================================================


def test_home_id_big_endian():
    """Verify home_id is stored in big-endian byte order."""
    zw = ZWave(home_id=0xDEADBEEF, src=1, dst=2)
    data = zw.bytes()
    assert data[0] == 0xDE
    assert data[1] == 0xAD
    assert data[2] == 0xBE
    assert data[3] == 0xEF


# ============================================================================
# Test 9: Length field matches actual frame length
# ============================================================================


def test_length_field_ack():
    """Verify length field at byte 7 matches actual ACK frame length (10)."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2)
    data = zw.bytes()
    assert data[7] == 10, f"Expected length=10, got {data[7]}"
    assert len(data) == data[7]


def test_length_field_req():
    """Verify length field at byte 7 matches actual REQ frame length."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=CC_BASIC, cmd=0x01, cmd_data=b"\xff")
    data = zw.bytes()
    assert data[7] == 13, f"Expected length=13, got {data[7]}"
    assert len(data) == data[7]


# ============================================================================
# Test 10: bytes() and build() return identical results
# ============================================================================


def test_bytes_equals_build():
    """Verify ZWave.bytes() and ZWave.build() return the same bytes."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=CC_BASIC, cmd=0x01)
    assert zw.bytes() == zw.build()


# ============================================================================
# Test 11: repr
# ============================================================================


def test_repr():
    """Verify repr(ZWave()) returns '<ZWave>'."""
    zw = ZWave()
    assert repr(zw) == "<ZWave>"


# ============================================================================
# Test 12: Stacking with raw bytes via / operator
# ============================================================================


def test_stacking_with_raw_bytes():
    """Test ZWave / b'\\xFF' stacking produces a LayerStack that can be built."""
    stack = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=CC_BASIC, cmd=0x01) / b"\xff"
    data = stack.build()
    # The built bytes should contain both the Z-Wave frame and the raw suffix
    assert len(data) > 10


# ============================================================================
# Test 13-16: Multiple command classes
# ============================================================================


def test_sensor_multilevel():
    """Build REQ frame with SENSOR_MULTILEVEL command class."""
    zw = ZWave(
        home_id=0x11223344,
        src=1,
        dst=3,
        cmd_class=CC_SENSOR_MULTILEVEL,
        cmd=0x05,
        cmd_data=b"\x01\x22\x00\x64",
    )
    data = zw.bytes()
    # 10 + 6 (cmd_class + cmd + 4 bytes data) = 16
    assert len(data) == 16
    assert data[9] == CC_SENSOR_MULTILEVEL
    assert data[10] == 0x05
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[-1] == expected_crc


def test_battery_report():
    """Build REQ frame with BATTERY command class (battery level report)."""
    zw = ZWave(home_id=0xABCD1234, src=2, dst=1, cmd_class=CC_BATTERY, cmd=0x03, cmd_data=b"\x64")
    data = zw.bytes()
    # 10 + 3 = 13
    assert len(data) == 13
    assert data[9] == CC_BATTERY
    assert data[10] == 0x03
    assert data[11] == 0x64  # battery level 100%


def test_configuration_set():
    """Build REQ frame with CONFIGURATION command class."""
    zw = ZWave(
        home_id=0x55667788,
        src=1,
        dst=5,
        cmd_class=CC_CONFIGURATION,
        cmd=0x04,
        cmd_data=b"\x01\x01\x0a",
    )
    data = zw.bytes()
    # 10 + 5 = 15
    assert len(data) == 15
    assert data[9] == CC_CONFIGURATION


def test_alarm_report():
    """Build REQ frame with ALARM/NOTIFICATION command class."""
    zw = ZWave(
        home_id=0x99AABBCC,
        src=4,
        dst=1,
        cmd_class=CC_ALARM,
        cmd=0x05,
        cmd_data=b"\x00\x00\x00\xff\x07\x08\x00",
    )
    data = zw.bytes()
    # 10 + 9 = 19
    assert len(data) == 19
    assert data[9] == CC_ALARM
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[-1] == expected_crc


# ============================================================================
# Test 17: REQ frame with no cmd_data
# ============================================================================


def test_req_no_cmd_data():
    """Build REQ frame with cmd_class and cmd but no cmd_data."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=CC_VERSION, cmd=0x11)
    data = zw.bytes()
    # 10 + 2 (cmd_class + cmd, no data) = 12
    assert len(data) == 12
    assert data[9] == CC_VERSION
    assert data[10] == 0x11
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[-1] == expected_crc


# ============================================================================
# Test 18: Large payload
# ============================================================================


def test_large_payload():
    """Build REQ frame with a large payload (200 bytes of cmd_data)."""
    payload = bytes(range(200))
    zw = ZWave(home_id=0xCAFEBABE, src=10, dst=20, cmd_class=0x91, cmd=0x42, cmd_data=payload)
    data = zw.bytes()
    # 10 + 2 + 200 = 212
    assert len(data) == 212
    # length field at byte 7 wraps around for u8 (212 mod 256 = 212, fits in u8)
    assert data[7] == 212
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[-1] == expected_crc


# ============================================================================
# Test 19: Security command class
# ============================================================================


def test_security_command_class():
    """Build REQ frame with SECURITY command class (nonce exchange)."""
    nonce_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    zw = ZWave(
        home_id=0xFEDCBA98, src=1, dst=2, cmd_class=CC_SECURITY, cmd=0x80, cmd_data=nonce_data
    )
    data = zw.bytes()
    # 10 + 10 = 20
    assert len(data) == 20
    assert data[9] == CC_SECURITY
    assert data[10] == 0x80  # SECURITY_NONCE_GET
    assert data[11:19] == nonce_data


# ============================================================================
# Test 20: Full frame structure validation
# ============================================================================


def test_full_frame_structure():
    """Validate every byte position in a known REQ frame."""
    zw = ZWave(
        home_id=0x01020304,
        src=0x05,
        dst=0x06,
        routed=True,
        ackreq=False,
        lowpower=True,
        speedmodified=False,
        headertype=0x01,
        beam_control=2,
        seqn=3,
        cmd_class=CC_BASIC,
        cmd=0x01,
        cmd_data=b"\xff",
    )
    data = zw.bytes()

    # Byte 0-3: Home ID (big-endian)
    assert data[0:4] == b"\x01\x02\x03\x04"

    # Byte 4: Source node ID
    assert data[4] == 0x05

    # Byte 5: Frame control
    # routed=1(bit7), ackreq=0(bit6), lowpower=1(bit5), speedmodified=0(bit4), headertype=1(bits3-0)
    expected_fc = 0x80 | 0x20 | 0x01  # = 0xA1
    assert data[5] == expected_fc, f"Expected FC={expected_fc:#04x}, got {data[5]:#04x}"

    # Byte 6: Beam/Sequence
    # beam_control=2(bits6-5), seqn=3(bits3-0)
    expected_bs = (2 << 5) | 3  # = 0x43
    assert data[6] == expected_bs, f"Expected beam_seqn={expected_bs:#04x}, got {data[6]:#04x}"

    # Byte 7: Length = 13 (10 header + 3 payload)
    assert data[7] == 13

    # Byte 8: Destination node ID
    assert data[8] == 0x06

    # Byte 9: cmd_class
    assert data[9] == CC_BASIC

    # Byte 10: cmd
    assert data[10] == 0x01

    # Byte 11: cmd_data
    assert data[11] == 0xFF

    # Byte 12: CRC
    expected_crc = compute_zwave_crc(data[:-1])
    assert data[12] == expected_crc

    # Total length
    assert len(data) == 13
