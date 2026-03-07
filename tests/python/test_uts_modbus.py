"""UTS-driven Modbus tests.

Translates assertions from tests/uts/modbus.uts into Stackforge Python tests.

Since Packet.parse() always assumes Ethernet as the first layer, raw Modbus/TCP
bytes must be wrapped in an Ethernet/IPv4/TCP frame before parsing.  The helper
_wrap_modbus() constructs a minimal such frame targeting TCP port 502.
"""

import struct

from stackforge import LayerKind, Modbus, Packet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_eth_ipv4_tcp(payload: bytes, sport: int = 12345, dport: int = 502) -> bytes:
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


def _parse_modbus(modbus_bytes: bytes, dport: int = 502) -> Packet:
    """Wrap raw Modbus/TCP bytes and return a parsed Packet."""
    frame = _build_eth_ipv4_tcp(modbus_bytes, dport=dport)
    pkt = Packet(frame)
    pkt.parse()
    return pkt


# ============================================================================
# UTS: MBAP default values
# ============================================================================


def test_uts_modbus_mbap_default():
    """
    UTS: raw(ModbusADURequest()) == b'\\x00\\x00\\x00\\x00\\x00\\x01\\xff'
    Verify MBAP header default values using a valid frame.

    The Scapy default has length=1 (only unitId, no funcCode), which isn't a
    valid Modbus request.  We use a minimal valid frame with length=2 to test
    the MBAP field values.
    """
    # Minimal valid: trans_id=0, proto_id=0, length=2, unit_id=0xFF, func_code=0x01
    modbus_payload = b"\x00\x00\x00\x00\x00\x02\xff\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus), "Modbus layer not found"
    assert pkt.getfieldval(LayerKind.Modbus, "trans_id") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "proto_id") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "unit_id") == 0xFF


# ============================================================================
# UTS: Read Coils (Function Code 0x01)
# ============================================================================


def test_uts_modbus_read_coils_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x01\\x00\\x00\\x00\\x01')
         isinstance(p.payload, ModbusPDU01ReadCoilsRequest)
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x01\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x01
    assert pkt.getfieldval(LayerKind.Modbus, "trans_id") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "unit_id") == 0xFF
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_read_coils_response():
    """
    UTS: p = ModbusADUResponse(b'\\x00\\x00\\x00\\x00\\x00\\x04\\xff\\x01\\x01\\x01')
         isinstance(p.payload, ModbusPDU01ReadCoilsResponse)
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x04\xff\x01\x01\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x01
    assert pkt.getfieldval(LayerKind.Modbus, "byte_count") == 1


def test_uts_modbus_read_coils_error():
    """
    UTS: p = ModbusADUResponse(b'\\x00\\x00\\x00\\x00\\x00\\x03\\xff\\x81\\x02')
         isinstance(p.payload, ModbusPDU01ReadCoilsError)
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x81\x02"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x81
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 2


# ============================================================================
# UTS: Read Discrete Inputs (Function Code 0x02)
# ============================================================================


def test_uts_modbus_read_discrete_inputs_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x02\\x00\\x00\\x00\\x01')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x02\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x02
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_read_discrete_inputs_error():
    """
    UTS: p = ModbusADUResponse(b'\\x00\\x00\\x00\\x00\\x00\\x03\\xff\\x82\\x01')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x82\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x82
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Read Holding Registers (Function Code 0x03)
# ============================================================================


def test_uts_modbus_read_holding_registers_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x03\\x00\\x00\\x00\\x01')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x03\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x03
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_read_holding_registers_request_custom():
    """
    UTS: raw(ModbusPDU03ReadHoldingRegistersRequest(startAddr=2048, quantity=16))
         == b'\\x03\\x08\\x00\\x00\\x10'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x03\x08\x00\x00\x10"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x03
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0x0800
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 16


def test_uts_modbus_read_holding_registers_error():
    """
    UTS: raw(ModbusPDU03ReadHoldingRegistersError()) == b'\\x83\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x83\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x83
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Read Input Registers (Function Code 0x04)
# ============================================================================


def test_uts_modbus_read_input_registers_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x04\\x00\\x00\\x00\\x01')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x04\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x04
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_read_input_registers_error():
    """
    UTS: raw(ModbusPDU04ReadInputRegistersError()) == b'\\x84\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x84\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x84
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Write Single Coil (Function Code 0x05)
# ============================================================================


def test_uts_modbus_write_single_coil_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x05\\x00\\x00\\x00\\x00')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x05\x00\x00\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x05
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "output_value") == 0


def test_uts_modbus_write_single_coil_error():
    """
    UTS: raw(ModbusPDU05WriteSingleCoilError()) == b'\\x85\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x85\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x85
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Write Single Register (Function Code 0x06)
# ============================================================================


def test_uts_modbus_write_single_register_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x06\\x00\\x00\\x00\\x00')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x06\x00\x00\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x06
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "register_val") == 0


def test_uts_modbus_write_single_register_error():
    """
    UTS: raw(ModbusPDU06WriteSingleRegisterError()) == b'\\x86\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x86\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x86
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Diagnostics (Function Code 0x08)
# ============================================================================


def test_uts_modbus_diagnostics_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x06\\xff\\x08\\x00\\x00\\x00\\x00')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x08\x00\x00\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x08
    assert pkt.getfieldval(LayerKind.Modbus, "sub_func") == 0


def test_uts_modbus_diagnostics_error():
    """
    UTS: raw(ModbusPDU08DiagnosticsError()) == b'\\x88\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x88\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x88
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Mask Write Register (Function Code 0x16)
# ============================================================================


def test_uts_modbus_mask_write_register_request():
    """
    UTS: p = ModbusADURequest(
        b'\\x00\\x00\\x00\\x00\\x00\\x08\\xff\\x16\\x00\\x00\\xff\\xff\\x00\\x00'
    )
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x08\xff\x16\x00\x00\xff\xff\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x16
    assert pkt.getfieldval(LayerKind.Modbus, "ref_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "and_mask") == 0xFFFF
    assert pkt.getfieldval(LayerKind.Modbus, "or_mask") == 0


def test_uts_modbus_mask_write_register_error():
    """
    UTS: raw(ModbusPDU16MaskWriteRegisterError()) == b'\\x96\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x96\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x96
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Write Multiple Coils (Function Code 0x0F)
# ============================================================================


def test_uts_modbus_write_multiple_coils_request():
    """
    UTS: p = ModbusADURequest(
        b'\\x00\\x00\\x00\\x00\\x00\\x08\\xff\\x0f\\x00\\x00\\x00\\x01\\x01\\x00'
    )
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x08\xff\x0f\x00\x00\x00\x01\x01\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x0F
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_write_multiple_coils_error():
    """
    UTS: raw(ModbusPDU0FWriteMultipleCoilsError()) == b'\\x8f\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x8f\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x8F
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Write Multiple Registers (Function Code 0x10)
# ============================================================================


def test_uts_modbus_write_multiple_registers_request():
    """
    UTS: p = ModbusADURequest(
        b'\\x00\\x00\\x00\\x00\\x00\\x09\\xff\\x10\\x00\\x00\\x00\\x01\\x02\\x00\\x00'
    )
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x09\xff\x10\x00\x00\x00\x01\x02\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x10
    assert pkt.getfieldval(LayerKind.Modbus, "start_addr") == 0
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 1


def test_uts_modbus_write_multiple_registers_error():
    """
    UTS: raw(ModbusPDU10WriteMultipleRegistersError()) == b'\\x90\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x90\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x90
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: MBAP with custom trans_id and unit_id
# ============================================================================


def test_uts_modbus_custom_trans_id():
    """Verify non-zero transaction ID is parsed correctly."""
    modbus_payload = b"\x00\x42\x00\x00\x00\x06\x01\x01\x00\x00\x00\x0a"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "trans_id") == 0x0042
    assert pkt.getfieldval(LayerKind.Modbus, "unit_id") == 0x01
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x01
    assert pkt.getfieldval(LayerKind.Modbus, "quantity") == 10


# ============================================================================
# Verify all layers present
# ============================================================================


def test_uts_modbus_has_all_layers():
    """Verify Ethernet/IPv4/TCP/Modbus layers are all present."""
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x01\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Ethernet)
    assert pkt.has_layer(LayerKind.Ipv4)
    assert pkt.has_layer(LayerKind.Tcp)
    assert pkt.has_layer(LayerKind.Modbus)


# ============================================================================
# UTS: Read/Write Multiple Registers (Function Code 0x17)
# ============================================================================


def test_uts_modbus_read_write_multiple_registers_request():
    """
    UTS: p = ModbusADURequest(
        b'\\x00\\x00\\x00\\x00\\x00\\x0d\\xff\\x17\\x00\\x00\\x00\\x01'
        b'\\x00\\x00\\x00\\x01\\x02\\x00\\x00')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x0d\xff\x17\x00\x00\x00\x01\x00\x00\x00\x01\x02\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x17


def test_uts_modbus_read_write_multiple_registers_error():
    """
    UTS: raw(ModbusPDU17ReadWriteMultipleRegistersError()) == b'\\x97\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x97\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x97
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# UTS: Read FIFO Queue (Function Code 0x18)
# ============================================================================


def test_uts_modbus_read_fifo_queue_request():
    """
    UTS: p = ModbusADURequest(b'\\x00\\x00\\x00\\x00\\x00\\x04\\xff\\x18\\x00\\x00')
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x04\xff\x18\x00\x00"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x18


def test_uts_modbus_read_fifo_queue_error():
    """
    UTS: raw(ModbusPDU18ReadFIFOQueueError()) == b'\\x98\\x01'
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x03\xff\x98\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x98
    assert pkt.getfieldval(LayerKind.Modbus, "except_code") == 1


# ============================================================================
# Builder: verify Modbus builder produces parseable bytes
# ============================================================================


def test_uts_modbus_builder_roundtrip():
    """Build a Modbus Read Coils request and verify it can be parsed back."""
    builder = Modbus(
        trans_id=0x0001,
        proto_id=0x0000,
        unit_id=0x01,
        func_code=0x01,
        data=b"\x00\x00\x00\x0a",
    )
    data = builder.bytes()

    pkt = _parse_modbus(data)
    assert pkt.has_layer(LayerKind.Modbus)
    assert pkt.getfieldval(LayerKind.Modbus, "trans_id") == 1
    assert pkt.getfieldval(LayerKind.Modbus, "func_code") == 0x01


# ============================================================================
# UTS: MBAP length field
# ============================================================================


def test_uts_modbus_mbap_length_field():
    """
    UTS: The length field in the MBAP header counts bytes after the 6-byte
    MBAP header (unit_id + func_code + data).
    Read Coils Request: length=6 (unit=1 + fc=1 + data=4).
    """
    modbus_payload = b"\x00\x00\x00\x00\x00\x06\xff\x01\x00\x00\x00\x01"
    pkt = _parse_modbus(modbus_payload)

    assert pkt.getfieldval(LayerKind.Modbus, "length") == 6
