"""UTS-driven Z-Wave tests.

Translates assertions from tests/uts/zwave.uts into Stackforge Python tests.

Z-Wave is a wireless protocol (not TCP/UDP based), so tests use the builder
to construct frames and verify raw bytes, CRC computation, and field positions.
"""

from stackforge import ZWave

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _zwave_crc(data: bytes) -> int:
    """Compute Z-Wave CRC: XOR all bytes starting from 0xFF."""
    crc = 0xFF
    for b in data:
        crc ^= b
    return crc


# ============================================================================
# UTS: Z-Wave ACK frame
# ============================================================================


def test_uts_zwave_ack_frame():
    """
    UTS: home_id=0x12345678, src=1, frameCtrl=0x40 (ackreq), beamSeqn=0x00,
         length=10, dst=2, crc=0xbe
    b = b'\\x12\\x34\\x56\\x78\\x01\\x40\\x00\\x0a\\x02\\xbe'
    """
    zw = ZWave(home_id=0x12345678, src=1, dst=2, ackreq=True)
    built = zw.bytes()

    assert len(built) == 10, f"ACK frame should be 10 bytes, got {len(built)}"
    # Verify fields by checking raw bytes
    assert built[0:4] == b"\x12\x34\x56\x78"  # home_id
    assert built[4] == 1  # src
    assert built[8] == 2  # dst
    assert built[7] == 10  # length
    # Verify CRC
    assert _zwave_crc(built[:-1]) == built[-1], "CRC mismatch"


def test_uts_zwave_ack_frame_parse():
    """Verify ACK frame field values match the UTS test vector."""
    zw = ZWave(home_id=0x12345678, src=1, dst=2, ackreq=True)
    built = zw.bytes()

    # Verify the expected bytes match
    expected_without_crc = b"\x12\x34\x56\x78\x01\x40\x00\x0a\x02"
    expected_crc = _zwave_crc(expected_without_crc)
    assert built == expected_without_crc + bytes([expected_crc])


# ============================================================================
# UTS: Z-Wave REQ frame with SWITCH_BINARY
# ============================================================================


def test_uts_zwave_switch_binary_req():
    """
    UTS: home_id=0xDEADBEEF, src=3, dst=5, cmd_class=0x25, cmd=0x01, data=0xFF
    b = b'\\xde\\xad\\xbe\\xef\\x03\\x40\\x00\\x0d\\x05\\x25\\x01\\xff\\x4d'
    """
    zw = ZWave(
        home_id=0xDEADBEEF,
        src=3,
        dst=5,
        cmd_class=0x25,
        cmd=0x01,
        cmd_data=b"\xff",
    )
    built = zw.bytes()

    # REQ = 10 + 3 (cmd_class + cmd + data) = 13
    assert len(built) == 13, f"REQ frame should be 13 bytes, got {len(built)}"
    assert built[0:4] == b"\xde\xad\xbe\xef"  # home_id
    assert built[4] == 3  # src
    assert built[8] == 5  # dst
    assert built[7] == 13  # length
    assert built[9] == 0x25  # cmd_class (SWITCH_BINARY)
    assert built[10] == 0x01  # cmd (SET)
    assert built[11] == 0xFF  # data
    # Verify CRC
    assert _zwave_crc(built[:-1]) == built[-1]


# ============================================================================
# UTS: Z-Wave REQ frame with BASIC SET
# ============================================================================


def test_uts_zwave_basic_set():
    """
    UTS: home_id=0x01020304, src=10, dst=20, cmd_class=0x20, cmd=0x01, data=0xFF
    b = b'\\x01\\x02\\x03\\x04\\x0a\\x40\\x00\\x0d\\x14\\x20\\x01\\xff\\x76'
    """
    zw = ZWave(
        home_id=0x01020304,
        src=10,
        dst=20,
        cmd_class=0x20,
        cmd=0x01,
        cmd_data=b"\xff",
    )
    built = zw.bytes()

    assert len(built) == 13
    assert built[0:4] == b"\x01\x02\x03\x04"  # home_id
    assert built[4] == 10  # src
    assert built[8] == 20  # dst
    assert built[9] == 0x20  # cmd_class (BASIC)
    assert built[10] == 0x01  # cmd (SET)
    assert built[11] == 0xFF  # data
    assert _zwave_crc(built[:-1]) == built[-1]


# ============================================================================
# UTS: Z-Wave BASIC GET (no data)
# ============================================================================


def test_uts_zwave_basic_get():
    """
    UTS: home_id=0x01020304, src=10, dst=20, cmd_class=0x20, cmd=0x02 (GET)
    b = b'\\x01\\x02\\x03\\x04\\x0a\\x40\\x00\\x0c\\x14\\x20\\x02\\x8b'
    """
    zw = ZWave(
        home_id=0x01020304,
        src=10,
        dst=20,
        cmd_class=0x20,
        cmd=0x02,
    )
    built = zw.bytes()

    # REQ = 10 + 2 (cmd_class + cmd, no data) = 12
    assert len(built) == 12
    assert built[7] == 12  # length
    assert built[9] == 0x20  # cmd_class
    assert built[10] == 0x02  # cmd (GET)
    assert _zwave_crc(built[:-1]) == built[-1]


# ============================================================================
# UTS: Z-Wave routed frame
# ============================================================================


def test_uts_zwave_routed_frame():
    """
    UTS: home_id=0xAABBCCDD, src=5, routed=True, ackreq=True, seqn=3,
         dst=10, cmd_class=0x25, cmd=0x01, data=0x00
    b = b'\\xaa\\xbb\\xcc\\xdd\\x05\\xc0\\x03\\x0d\\x0a\\x25\\x01\\x00\\x1a'
    """
    zw = ZWave(
        home_id=0xAABBCCDD,
        src=5,
        dst=10,
        routed=True,
        ackreq=True,
        seqn=3,
        cmd_class=0x25,
        cmd=0x01,
        cmd_data=b"\x00",
    )
    built = zw.bytes()

    assert len(built) == 13
    assert built[0:4] == b"\xaa\xbb\xcc\xdd"  # home_id
    assert built[4] == 5  # src
    assert built[5] & 0x80 != 0  # routed bit set
    assert built[5] & 0x40 != 0  # ackreq bit set
    assert built[6] & 0x0F == 3  # seqn
    assert built[8] == 10  # dst
    assert built[9] == 0x25  # cmd_class
    assert built[10] == 0x01  # cmd
    assert built[11] == 0x00  # data
    assert _zwave_crc(built[:-1]) == built[-1]


# ============================================================================
# UTS: Z-Wave default ACK (home_id=0)
# ============================================================================


def test_uts_zwave_default_ack():
    """
    UTS: Default ZWave() produces an ACK with home_id=0, src=1, dst=2.
    b = b'\\x00\\x00\\x00\\x00\\x01\\x40\\x00\\x0a\\x02\\xb6'
    """
    zw = ZWave()
    built = zw.bytes()

    assert len(built) == 10
    assert built[0:4] == b"\x00\x00\x00\x00"  # home_id = 0
    assert built[4] == 1  # src (default)
    assert built[8] == 2  # dst (default)
    assert built[7] == 10  # length
    assert _zwave_crc(built[:-1]) == built[-1]


# ============================================================================
# UTS: Z-Wave CRC verification
# ============================================================================


def test_uts_zwave_crc_correct():
    """
    UTS: Verify CRC is correct (XOR checksum starting from 0xFF).
    b = b'\\x12\\x34\\x56\\x78\\x01\\x40\\x00\\x0a\\x02\\xbe'
    crc = 0xFF; for byte in b[:-1]: crc ^= byte
    assert crc == b[-1]
    """
    ack_data = b"\x12\x34\x56\x78\x01\x40\x00\x0a\x02"
    expected_crc = _zwave_crc(ack_data)
    assert expected_crc == 0xBE, f"Expected CRC 0xBE, got {expected_crc:#04x}"


def test_uts_zwave_crc_req_frame():
    """Verify CRC for REQ frame: DEADBEEF + SWITCH_BINARY."""
    req_data = b"\xde\xad\xbe\xef\x03\x40\x00\x0d\x05\x25\x01\xff"
    expected_crc = _zwave_crc(req_data)
    assert expected_crc == 0x4D, f"Expected CRC 0x4D, got {expected_crc:#04x}"


# ============================================================================
# UTS: Z-Wave frame control flags
# ============================================================================


def test_uts_zwave_frame_ctrl_all_flags():
    """
    UTS: routed=1, ackreq=1, lowpower=1, speedmodified=1, headertype=0x03
         frameCtrl = 0x80 | 0x40 | 0x20 | 0x10 | 0x03 = 0xF3
    """
    zw = ZWave(
        routed=True,
        ackreq=True,
        lowpower=True,
        speedmodified=True,
        headertype=3,
    )
    built = zw.bytes()

    fc = built[5]
    assert fc & 0x80 != 0, "routed bit not set"
    assert fc & 0x40 != 0, "ackreq bit not set"
    assert fc & 0x20 != 0, "lowpower bit not set"
    assert fc & 0x10 != 0, "speedmodified bit not set"
    assert fc & 0x0F == 3, f"headertype should be 3, got {fc & 0x0F}"


# ============================================================================
# UTS: Z-Wave beam control and sequence
# ============================================================================


def test_uts_zwave_beam_control_and_sequence():
    """
    UTS: beam_control=2, seqn=0x0A
         beamSeqn = (2 << 5) | 0x0A = 0x4A
    """
    zw = ZWave(beam_control=2, seqn=0x0A)
    built = zw.bytes()

    bs = built[6]
    beam = (bs >> 5) & 0x03
    seqn = bs & 0x0F
    assert beam == 2, f"beam_control should be 2, got {beam}"
    assert seqn == 0x0A, f"seqn should be 0x0A, got {seqn}"


# ============================================================================
# Additional: Length field correctness
# ============================================================================


def test_uts_zwave_length_ack():
    """ACK frame length field should be 10."""
    zw = ZWave()
    built = zw.bytes()
    assert built[7] == 10


def test_uts_zwave_length_req():
    """REQ frame with 1 byte data should have length=13."""
    zw = ZWave(cmd_class=0x20, cmd=0x01, cmd_data=b"\xaa")
    built = zw.bytes()
    assert built[7] == 13
    assert len(built) == 13


def test_uts_zwave_length_req_no_data():
    """REQ frame with no data should have length=12."""
    zw = ZWave(cmd_class=0x20, cmd=0x01)
    built = zw.bytes()
    assert built[7] == 12
    assert len(built) == 12


# ============================================================================
# Builder roundtrip: build and verify byte matches
# ============================================================================


def test_uts_zwave_roundtrip_crc():
    """Build a frame and verify CRC matches the computed value."""
    zw = ZWave(
        home_id=0xCAFEBABE,
        src=10,
        dst=20,
        cmd_class=0x91,
        cmd=0x42,
        cmd_data=b"\x01\x02\x03",
    )
    built = zw.bytes()

    # Verify CRC
    computed_crc = _zwave_crc(built[:-1])
    assert (
        computed_crc == built[-1]
    ), f"CRC mismatch: computed {computed_crc:#04x}, frame has {built[-1]:#04x}"

    # Verify frame structure
    assert len(built) == 10 + 5  # header(9) + crc(1) + cmd_class(1) + cmd(1) + data(3) = 15
    assert built[7] == 15  # length field
