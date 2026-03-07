"""Type stubs for the stackforge native Rust extension."""

from typing import Any, Callable, Iterator, Optional, Union

class LayerKind:
    """Protocol layer type identifier."""

    Ethernet: LayerKind
    Dot3: LayerKind
    Arp: LayerKind
    Ipv4: LayerKind
    Ipv6: LayerKind
    Icmp: LayerKind
    Icmpv6: LayerKind
    Tcp: LayerKind
    Udp: LayerKind
    Dns: LayerKind
    Dot1Q: LayerKind
    Dot1AD: LayerKind
    Dot1AH: LayerKind
    LLC: LayerKind
    SNAP: LayerKind
    Ssh: LayerKind
    Tls: LayerKind
    Dot15d4: LayerKind
    Dot15d4Fcs: LayerKind
    Dot11: LayerKind
    Http: LayerKind
    Quic: LayerKind
    Generic: LayerKind
    Http2: LayerKind
    L2tp: LayerKind
    Mqtt: LayerKind
    MqttSn: LayerKind
    Modbus: LayerKind
    ZWave: LayerKind
    Ftp: LayerKind
    Tftp: LayerKind
    Smtp: LayerKind
    Pop3: LayerKind
    Imap: LayerKind
    Raw: LayerKind

    def name(self) -> str:
        """Returns the human-readable name of this layer kind."""
        ...
    def min_header_size(self) -> int:
        """Returns the minimum header size for this layer type."""
        ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class LayerIndex:
    """Lightweight index describing a protocol layer's position in a packet."""

    kind: LayerKind
    start: int
    end: int

    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...

class Packet:
    """Main packet container with zero-copy buffer and layer indices."""

    def __init__(self, data: bytes) -> None:
        """Create a new packet from raw bytes. Call parse() before accessing layers."""
        ...
    @staticmethod
    def empty() -> Packet:
        """Create an empty packet."""
        ...
    @property
    def is_dirty(self) -> bool: ...
    @property
    def layer_count(self) -> int: ...
    @property
    def is_parsed(self) -> bool: ...
    @property
    def layers(self) -> list[LayerIndex]: ...
    @property
    def fields(self) -> list[str]:
        """Return all field names across all layers."""
        ...
    def bytes(self) -> bytes:
        """Return the raw packet bytes."""
        ...
    def parse(self) -> None:
        """Parse the packet, identifying layer boundaries. Assumes Ethernet as first layer."""
        ...
    def has_layer(self, kind: LayerKind) -> bool:
        """Check if the packet contains a specific layer type."""
        ...
    def get_layer_bytes(self, kind: LayerKind) -> bytes:
        """Get the raw bytes for a specific layer."""
        ...
    def payload(self) -> bytes:
        """Get the packet payload bytes."""
        ...
    def show(self) -> str:
        """Return a human-readable packet dissection."""
        ...
    def summary(self) -> str:
        """Return a one-line packet summary."""
        ...
    def hexdump(self) -> str:
        """Return a hex dump of the packet."""
        ...
    def getfieldval(self, kind: LayerKind, name: str) -> Any:
        """Get a field value from a specific layer."""
        ...
    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __getattr__(self, name: str) -> Any: ...
    def __setattr__(self, name: str, value: Any) -> None: ...

class LayerStack:
    """A stack of protocol layers that can be built into a packet."""

    def __init__(self) -> None: ...
    def build(self) -> Packet:
        """Build this layer stack into a Packet."""
        ...
    def bytes(self) -> bytes:
        """Serialize the layer stack to bytes."""
        ...
    def show(self) -> str: ...
    def summary(self) -> str: ...
    def __len__(self) -> int: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class Ether:
    """Ethernet II frame builder."""

    def __init__(
        self,
        dst: Optional[str] = None,
        src: Optional[str] = None,
        type: Optional[int] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class IP:
    """IPv4 packet builder."""

    def __init__(
        self,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        ttl: Optional[int] = None,
        proto: Optional[int] = None,
        id: Optional[int] = None,
        flags: Optional[Union[int, str]] = None,
        frag: Optional[int] = None,
        tos: Optional[int] = None,
        len: Optional[int] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class TCP:
    """TCP segment builder."""

    def __init__(
        self,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
        seq: Optional[int] = None,
        ack: Optional[int] = None,
        flags: Optional[Union[int, str]] = None,
        window: Optional[int] = None,
        dataofs: Optional[int] = None,
        urgptr: Optional[int] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class UDP:
    """UDP datagram builder."""

    def __init__(
        self,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
        len: Optional[int] = None,
        chksum: Optional[int] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class ICMP:
    """ICMP packet builder."""

    def __init__(
        self,
        type: Optional[int] = 8,
        code: Optional[int] = 0,
        chksum: Optional[int] = None,
    ) -> None: ...
    @classmethod
    def echo_request(cls, id: int, seq: int) -> ICMP: ...
    @classmethod
    def echo_reply(cls, id: int, seq: int) -> ICMP: ...
    @classmethod
    def dest_unreach(cls, code: int) -> ICMP: ...
    @classmethod
    def dest_unreach_need_frag(cls, mtu: int) -> ICMP: ...
    @classmethod
    def redirect(cls, code: int, gateway: str) -> ICMP: ...
    @classmethod
    def time_exceeded(cls, code: int = 0) -> ICMP: ...
    @classmethod
    def param_problem(cls, ptr: int) -> ICMP: ...
    @classmethod
    def timestamp_request(
        cls, id: int, seq: int, ts_ori: int = 0, ts_rx: int = 0, ts_tx: int = 0
    ) -> ICMP: ...
    @classmethod
    def timestamp_reply(
        cls, id: int, seq: int, ts_ori: int, ts_rx: int, ts_tx: int
    ) -> ICMP: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class ARP:
    """ARP packet builder."""

    def __init__(
        self,
        op: Optional[Union[int, str]] = None,
        hwtype: Optional[int] = None,
        ptype: Optional[int] = None,
        hwsrc: Optional[str] = None,
        psrc: Optional[str] = None,
        hwdst: Optional[str] = None,
        pdst: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class Raw:
    """Raw payload builder."""

    def __init__(self, load: Optional[Union[bytes, str]] = None) -> None: ...
    @staticmethod
    def from_hex(hex_str: str) -> Raw:
        """Create a Raw payload from a hex string."""
        ...
    @staticmethod
    def zeros(length: int) -> Raw:
        """Create a Raw payload of zero bytes."""
        ...
    @staticmethod
    def repeat(byte: int, count: int) -> Raw:
        """Create a Raw payload repeating a single byte."""
        ...
    @staticmethod
    def pattern(pattern: list[int], length: int) -> Raw:
        """Create a Raw payload from a repeating pattern."""
        ...
    @property
    def load(self) -> bytes: ...
    @property
    def hex(self) -> str: ...
    def hexdump(self) -> str: ...
    def pad(self, min_len: int) -> Raw: ...
    def pad_with(self, min_len: int, byte: int) -> Raw: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class SSH:
    """SSH protocol builder."""

    def __init__(self, version: Optional[str] = None) -> None: ...
    @classmethod
    def version_exchange(cls, version: str) -> SSH: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class TLS:
    """TLS record builder."""

    def __init__(
        self,
        type: Optional[int] = None,
        version: Optional[int] = None,
        len: Optional[int] = None,
        fragment: Optional[list[int]] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class IPv6:
    """IPv6 packet builder."""

    def __init__(
        self,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        hop_limit: Optional[int] = None,
        traffic_class: Optional[int] = None,
        flow_label: Optional[int] = None,
        next_header: Optional[int] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class ICMPv6:
    """ICMPv6 packet builder."""

    def __init__(
        self,
        type: Optional[int] = 128,
        code: Optional[int] = 0,
        chksum: Optional[int] = None,
    ) -> None: ...
    @classmethod
    def echo_request(cls, id: int, seq: int) -> ICMPv6: ...
    @classmethod
    def echo_reply(cls, id: int, seq: int) -> ICMPv6: ...
    @classmethod
    def neighbor_solicitation(cls, target: str) -> ICMPv6: ...
    @classmethod
    def neighbor_advertisement(cls, target: str) -> ICMPv6: ...
    @classmethod
    def router_solicitation(cls) -> ICMPv6: ...
    @classmethod
    def router_advertisement(cls) -> ICMPv6: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class HTTP:
    """HTTP/1.x request builder."""

    def __init__(
        self,
        method: Optional[str] = None,
        uri: Optional[str] = None,
        version: Optional[str] = None,
        body: Optional[bytes] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class HTTPResponse:
    """HTTP/1.x response builder."""

    def __init__(
        self,
        status: Optional[int] = None,
        reason: Optional[str] = None,
        version: Optional[str] = None,
        body: Optional[bytes] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class QUIC:
    """QUIC transport protocol builder."""

    def __init__(
        self,
        dst_conn_id: Optional[bytes] = None,
        src_conn_id: Optional[bytes] = None,
        payload: Optional[bytes] = None,
        packet_number: Optional[int] = None,
    ) -> None: ...
    @classmethod
    def initial(
        cls,
        dst_conn_id: Optional[bytes] = None,
        src_conn_id: Optional[bytes] = None,
        payload: Optional[bytes] = None,
    ) -> QUIC: ...
    @classmethod
    def handshake(
        cls,
        dst_conn_id: Optional[bytes] = None,
        payload: Optional[bytes] = None,
    ) -> QUIC: ...
    @classmethod
    def one_rtt(
        cls,
        dst_conn_id: Optional[bytes] = None,
        payload: Optional[bytes] = None,
    ) -> QUIC: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class HTTP2:
    """HTTP/2 protocol builder."""

    def __init__(self, include_preface: bool = True) -> None: ...
    @classmethod
    def settings_ack(cls) -> HTTP2: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class L2TP:
    """L2TPv2 protocol builder."""

    def __init__(
        self,
        msg_type: Optional[int] = None,
        has_length: Optional[bool] = None,
        has_sequence: Optional[bool] = None,
        tunnel_id: Optional[int] = None,
        session_id: Optional[int] = None,
        ns: Optional[int] = None,
        nr: Optional[int] = None,
        payload: Optional[bytes] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class MQTT:
    """MQTT messaging protocol builder."""

    def __init__(
        self,
        msg_type: Optional[int] = None,
        dup: Optional[bool] = None,
        qos: Optional[int] = None,
        retain: Optional[bool] = None,
        topic: Optional[bytes] = None,
        msgid: Optional[int] = None,
        value: Optional[bytes] = None,
        proto_name: Optional[bytes] = None,
        proto_level: Optional[int] = None,
        klive: Optional[int] = None,
        client_id: Optional[bytes] = None,
        clean_session: Optional[bool] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class MQTTSN:
    """MQTT-SN (Sensor Networks) protocol builder."""

    def __init__(
        self,
        msg_type: Optional[int] = None,
        dup: Optional[bool] = None,
        qos: Optional[int] = None,
        retain: Optional[bool] = None,
        will: Optional[bool] = None,
        clean_session: Optional[bool] = None,
        tid_type: Optional[int] = None,
        gw_id: Optional[int] = None,
        duration: Optional[int] = None,
        return_code: Optional[int] = None,
        tid: Optional[int] = None,
        mid: Optional[int] = None,
        data: Optional[bytes] = None,
        topic_name: Optional[bytes] = None,
        client_id: Optional[bytes] = None,
        prot_id: Optional[int] = None,
        radius: Optional[int] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class Modbus:
    """Modbus industrial protocol builder."""

    def __init__(
        self,
        trans_id: Optional[int] = None,
        proto_id: Optional[int] = None,
        unit_id: Optional[int] = None,
        func_code: Optional[int] = None,
        data: Optional[bytes] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class ZWave:
    """Z-Wave smart home protocol builder."""

    def __init__(
        self,
        home_id: Optional[int] = None,
        src: Optional[int] = None,
        dst: Optional[int] = None,
        routed: Optional[bool] = None,
        ackreq: Optional[bool] = None,
        lowpower: Optional[bool] = None,
        speedmodified: Optional[bool] = None,
        headertype: Optional[int] = None,
        beam_control: Optional[int] = None,
        seqn: Optional[int] = None,
        cmd_class: Optional[int] = None,
        cmd: Optional[int] = None,
        cmd_data: Optional[bytes] = None,
    ) -> None: ...
    def build(self) -> bytes: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __rtruediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class FTP:
    """FTP protocol builder."""

    def __init__(
        self,
        command: Optional[str] = None,
        args: Optional[str] = None,
        reply_code: Optional[int] = None,
        reply_text: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class TFTP:
    """TFTP protocol builder."""

    def __init__(
        self,
        opcode: Optional[int] = None,
        filename: Optional[str] = None,
        mode: Optional[str] = None,
        block: Optional[int] = None,
        data: Optional[bytes] = None,
        error_code: Optional[int] = None,
        error_msg: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class SMTP:
    """SMTP email protocol builder."""

    def __init__(
        self,
        command: Optional[str] = None,
        args: Optional[str] = None,
        reply_code: Optional[int] = None,
        reply_text: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class POP3:
    """POP3 email retrieval protocol builder."""

    def __init__(
        self,
        ok: Optional[bool] = None,
        text: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

class IMAP:
    """IMAP email access protocol builder."""

    def __init__(
        self,
        tag: Optional[str] = None,
        command: Optional[str] = None,
        args: Optional[str] = None,
        status: Optional[str] = None,
        text: Optional[str] = None,
    ) -> None: ...
    def bytes(self) -> bytes: ...
    def __truediv__(self, other: Any) -> LayerStack: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# PCAP I/O
# ---------------------------------------------------------------------------

class PcapPacket:
    """A captured packet with PCAP metadata (timestamp, wire length).

    Returned by :func:`rdpcap` and :class:`PcapReader`.  Wraps a parsed
    :class:`Packet` together with capture-time metadata such as the original
    wire length and timestamp.

    Properties:
        packet: The underlying parsed ``Packet`` object.
        time: Capture timestamp as seconds since the Unix epoch (float).
        wirelen: Original on-the-wire length in bytes before any truncation
            by the capture snaplen.
        interface_id: Interface index from PcapNG files, or ``None`` for
            classic PCAP.

    Example::

        pkts = rdpcap("capture.pcap")
        for p in pkts:
            print(f"{p.time:.6f}  {p.summary()}")
            print(f"  wire length: {p.wirelen}, captured: {len(p)}")
    """

    @property
    def packet(self) -> Packet:
        """The underlying parsed Packet object."""
        ...
    @property
    def time(self) -> float:
        """Capture timestamp as seconds since the Unix epoch."""
        ...
    @property
    def wirelen(self) -> int:
        """Original on-the-wire length in bytes."""
        ...
    @property
    def interface_id(self) -> Optional[int]:
        """PcapNG interface index, or None for classic PCAP files."""
        ...
    def show(self) -> str:
        """Return a human-readable packet dissection with PCAP metadata."""
        ...
    def summary(self) -> str:
        """Return a one-line packet summary."""
        ...
    def hexdump(self) -> str:
        """Return a hex dump of the packet bytes."""
        ...
    def bytes(self) -> bytes:
        """Return the raw packet bytes."""
        ...
    def __repr__(self) -> str: ...
    def __len__(self) -> int: ...

class PcapReader:
    """Iterator-based PCAP/PCAPNG file reader for memory-efficient processing.

    Reads packets one at a time from a PCAP or PcapNG file without loading
    the entire file into memory.  Useful for processing large capture files
    that would not fit in RAM.

    Supports the iterator protocol and can be used in ``for`` loops.

    Args:
        filename: Path to a PCAP (``.pcap``) or PcapNG (``.pcapng``) file.

    Raises:
        OSError: If the file cannot be opened or is not a valid PCAP/PcapNG.

    Example::

        for pkt in PcapReader("large_capture.pcap"):
            if pkt.packet.has_layer(LayerKind.Tcp):
                print(pkt.summary())
    """

    def __init__(self, filename: str) -> None: ...
    def __iter__(self) -> Iterator[PcapPacket]: ...
    def __next__(self) -> PcapPacket: ...

# ---------------------------------------------------------------------------
# Flow extraction
# ---------------------------------------------------------------------------

class FlowConfig:
    """Configuration for the stateful flow extraction engine.

    Controls timeouts, buffer sizes, and optional tracking features used by
    :func:`extract_flows` and :func:`extract_flows_from_packets`.

    Args:
        tcp_established_timeout: Seconds before an established TCP flow
            expires (default: 86400 = 24 hours).
        tcp_half_open_timeout: Seconds before a half-open TCP flow (SYN sent,
            no SYN-ACK) expires (default: 5).
        tcp_time_wait_timeout: Seconds a TCP flow stays in TIME_WAIT after
            FIN exchange (default: 120).
        udp_timeout: Seconds before an idle UDP flow expires (default: 120).
        max_reassembly_buffer: Maximum bytes for TCP stream reassembly per
            direction (default: 16 MB).
        max_ooo_fragments: Maximum out-of-order TCP segments buffered before
            dropping (default: 100).
        track_max_packet_len: If True, track the largest packet size per
            direction (``forward_max_packet_len`` / ``reverse_max_packet_len``
            on :class:`Conversation`).  Disabled by default for minimal
            overhead.
        track_max_flow_len: If True, track the largest single packet across
            the entire flow (``max_flow_len`` on :class:`Conversation`).
            Disabled by default.
        memory_budget: Optional hard memory budget in bytes for the flow
            table.  When set, flows may be spilled to disk.
        spill_dir: Directory for spilling flow state when *memory_budget* is
            exceeded.
        verbose: Print progress messages during extraction (default: False).
        store_packet_indices: Store per-flow packet index lists (default:
            True).  Disable to save memory when indices are not needed.
        progress_interval: Print a progress line every *N* packets when
            *verbose* is True (default: 100000).

    Example::

        cfg = FlowConfig(
            tcp_established_timeout=3600,
            track_max_packet_len=True,
        )
        flows = extract_flows("capture.pcap", config=cfg)
    """

    def __init__(
        self,
        tcp_established_timeout: float = 86400.0,
        tcp_half_open_timeout: float = 5.0,
        tcp_time_wait_timeout: float = 120.0,
        udp_timeout: float = 120.0,
        max_reassembly_buffer: int = 16777216,
        max_ooo_fragments: int = 100,
        track_max_packet_len: bool = False,
        track_max_flow_len: bool = False,
        memory_budget: Optional[int] = None,
        spill_dir: Optional[str] = None,
        verbose: bool = False,
        store_packet_indices: bool = True,
        progress_interval: int = 100000,
    ) -> None: ...
    def __repr__(self) -> str: ...

class Conversation:
    """A network conversation/flow extracted from packet data.

    Represents a bidirectional network flow between two endpoints, as
    returned by :func:`extract_flows` or :func:`extract_flows_from_packets`.

    Contains addressing information, packet/byte counts per direction,
    timing, TCP state and reassembly data, ICMP echo correlation, and
    optional per-packet-length tracking.

    Example::

        flows = extract_flows("capture.pcap")
        for flow in flows:
            print(flow.summary())
            if flow.reassembled_forward:
                print(f"  forward payload: {len(flow.reassembled_forward)} bytes")
    """

    @property
    def src_addr(self) -> str:
        """Source IP address (initiator of the flow)."""
        ...
    @property
    def dst_addr(self) -> str:
        """Destination IP address (responder)."""
        ...
    @property
    def src_port(self) -> int:
        """Source transport port."""
        ...
    @property
    def dst_port(self) -> int:
        """Destination transport port."""
        ...
    @property
    def protocol(self) -> str:
        """Transport protocol name (e.g. ``"TCP"``, ``"UDP"``, ``"ICMP"``)."""
        ...
    @property
    def status(self) -> str:
        """Flow status string (e.g. ``"established"``, ``"closed"``, ``"timeout"``)."""
        ...
    @property
    def start_time(self) -> float:
        """Timestamp of the first packet in the flow (seconds since epoch)."""
        ...
    @property
    def duration(self) -> float:
        """Duration of the flow in seconds (last packet time minus first)."""
        ...
    @property
    def forward_packets(self) -> int:
        """Number of packets from source to destination."""
        ...
    @property
    def reverse_packets(self) -> int:
        """Number of packets from destination to source."""
        ...
    @property
    def forward_bytes(self) -> int:
        """Total bytes from source to destination."""
        ...
    @property
    def reverse_bytes(self) -> int:
        """Total bytes from destination to source."""
        ...
    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        ...
    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        ...
    @property
    def forward_max_packet_len(self) -> Optional[int]:
        """Largest packet size (bytes) in the forward direction, or None if tracking disabled."""
        ...
    @property
    def reverse_max_packet_len(self) -> Optional[int]:
        """Largest packet size (bytes) in the reverse direction, or None if tracking disabled."""
        ...
    @property
    def max_flow_len(self) -> Optional[int]:
        """Largest single packet (bytes) in the entire flow, or None if tracking disabled."""
        ...
    @property
    def packet_indices(self) -> list[int]:
        """Indices of this flow's packets in the original capture order."""
        ...
    @property
    def tcp_state(self) -> Optional[str]:
        """TCP state machine state (e.g. ``"ESTABLISHED"``, ``"CLOSED"``), or None for non-TCP."""
        ...
    @property
    def dropped_segments(self) -> int:
        """Total TCP segments dropped due to reassembly buffer limits."""
        ...
    @property
    def dropped_segments_fwd(self) -> int:
        """TCP segments dropped in the forward direction."""
        ...
    @property
    def dropped_segments_rev(self) -> int:
        """TCP segments dropped in the reverse direction."""
        ...
    @property
    def zwave_home_id(self) -> Optional[int]:
        """Z-Wave Home ID for Z-Wave flows, or None."""
        ...
    @property
    def zwave_command_count(self) -> Optional[int]:
        """Number of Z-Wave command frames in the flow, or None."""
        ...
    @property
    def zwave_ack_count(self) -> Optional[int]:
        """Number of Z-Wave ACK frames in the flow, or None."""
        ...
    @property
    def icmp_type(self) -> Optional[int]:
        """ICMP message type for ICMP flows, or None for non-ICMP."""
        ...
    @property
    def icmp_code(self) -> Optional[int]:
        """ICMP message code for ICMP flows, or None for non-ICMP."""
        ...
    @property
    def icmp_identifier(self) -> Optional[int]:
        """ICMP echo identifier used to correlate request/reply pairs, or None."""
        ...
    @property
    def icmp_request_count(self) -> Optional[int]:
        """Number of ICMP echo requests in the flow, or None for non-ICMP."""
        ...
    @property
    def icmp_reply_count(self) -> Optional[int]:
        """Number of ICMP echo replies in the flow, or None for non-ICMP."""
        ...
    @property
    def icmp_last_seq(self) -> Optional[int]:
        """Sequence number of the last ICMP echo message, or None for non-ICMP."""
        ...
    @property
    def reassembled_forward(self) -> Optional[bytes]:
        """Reassembled TCP payload from source to destination, or None if unavailable."""
        ...
    @property
    def reassembled_reverse(self) -> Optional[bytes]:
        """Reassembled TCP payload from destination to source, or None if unavailable."""
        ...
    def show(self) -> str:
        """Return a detailed multi-line flow description."""
        ...
    def summary(self) -> str:
        """Return a one-line flow summary."""
        ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Live capture / sniffing
# ---------------------------------------------------------------------------

class Sniffer:
    """Iterator-based live packet sniffer.

    Opens a network interface for packet capture and yields parsed
    :class:`Packet` objects one at a time.  Supports BPF filters, packet
    count limits, timeouts, and the context-manager protocol for automatic
    cleanup.

    The GIL is released while waiting for the next packet, so other Python
    threads can run concurrently.

    Args:
        iface: Network interface name (e.g. ``"en0"``, ``"eth0"``).
            Defaults to the system default interface.
        filter: BPF filter expression (e.g. ``"tcp port 80"``).
        count: Stop after capturing *count* packets.  ``0`` means unlimited.
        timeout: Stop after *timeout* seconds.  ``None`` means no timeout.
        snaplen: Maximum bytes to capture per packet (default: 65535).
        promisc: Enable promiscuous mode (default: True).

    Raises:
        ValueError: If the interface is not found or the BPF filter is
            invalid.
        OSError: If capture permissions are insufficient (may need root/sudo).

    Example::

        # Iterate directly
        for pkt in Sniffer(iface="en0", filter="udp", count=5):
            print(pkt.summary())

        # Context manager ensures cleanup
        with Sniffer(iface="en0", count=10) as s:
            for pkt in s:
                print(pkt.summary())
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        filter: Optional[str] = None,
        count: int = 0,
        timeout: Optional[float] = None,
        snaplen: int = 65535,
        promisc: bool = True,
    ) -> None: ...
    def stop(self) -> None:
        """Stop the sniffer and release the capture handle."""
        ...
    def stats(self) -> dict[str, Any]:
        """Return capture statistics.

        Returns:
            A dict with keys:
                - ``"interface"`` (str): The capture interface name.
                - ``"stopped"`` (bool): Whether the capture has finished.
        """
        ...
    def __iter__(self) -> Iterator[Packet]: ...
    def __next__(self) -> Packet: ...
    def __enter__(self) -> Sniffer: ...
    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> bool: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Automata / Answering Machines
# ---------------------------------------------------------------------------

class AutomatonConfig:
    """Configuration for an automaton runtime.

    Specifies the network interface, optional BPF filter, and capture
    parameters used when starting an :class:`AnsweringMachine` or
    :class:`DhcpServerAM`.

    Args:
        iface: Network interface name (e.g. ``"en0"``).  Defaults to the
            system default interface.
        bpf_filter: Optional BPF filter string applied to incoming packets.
        snaplen: Maximum bytes to capture per packet (default: 65535).
        promisc: Enable promiscuous mode (default: True).

    Example::

        config = AutomatonConfig(iface="en0", bpf_filter="udp port 67")
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        snaplen: int = 65535,
        promisc: bool = True,
    ) -> None: ...

class AnsweringMachine:
    """Callback-based answering machine for custom protocol handling.

    Sniffs packets on a network interface and automatically sends replies
    based on user-supplied callback functions.  Runs on a dedicated
    background thread with its own async runtime.

    Args:
        is_request: A callable ``(Packet) -> bool`` that returns True for
            packets that should receive a reply.
        make_reply: A callable ``(Packet) -> Optional[bytes]`` that builds
            the raw reply bytes, or returns ``None`` to skip.
        bpf_filter: Optional BPF filter override applied before
            ``is_request`` is called.

    Raises:
        RuntimeError: If ``start()`` is called while already running.

    Example::

        def is_request(pkt):
            return pkt.has_layer(LayerKind.Arp)

        def make_reply(pkt):
            # Build an ARP reply
            reply = (Ether(dst=pkt.src) / ARP(op="is-at", pdst=pkt.psrc))
            return reply.bytes()

        am = AnsweringMachine(is_request, make_reply, bpf_filter="arp")
        am.start(AutomatonConfig(iface="en0"))
        # ... answering machine runs in the background ...
        am.stop()
    """

    def __init__(
        self,
        is_request: Callable[[Packet], bool],
        make_reply: Callable[[Packet], Optional[bytes]],
        bpf_filter: Optional[str] = None,
    ) -> None: ...
    def start(self, config: AutomatonConfig) -> None:
        """Start the answering machine on a background thread.

        Args:
            config: Capture configuration specifying the interface and filter.

        Raises:
            RuntimeError: If already running.
            OSError: If the capture device cannot be opened.
        """
        ...
    def stop(self) -> None:
        """Stop the answering machine and join the background thread."""
        ...
    @property
    def is_running(self) -> bool:
        """True if the answering machine is currently running."""
        ...
    def __enter__(self) -> AnsweringMachine: ...
    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None: ...

class DhcpPoolConfig:
    """DHCP address pool configuration.

    Defines the IP range, network parameters, and lease timing for a
    :class:`DhcpServerAM`.

    Args:
        pool_start: First IP address in the allocation pool
            (default: ``"192.168.1.100"``).
        pool_end: Last IP address in the allocation pool
            (default: ``"192.168.1.200"``).
        server_ip: IP address of the DHCP server itself
            (default: ``"192.168.1.1"``).
        subnet_mask: Subnet mask (default: ``"255.255.255.0"``).
        gateway: Default gateway advertised to clients
            (default: ``"192.168.1.1"``).
        dns_servers: List of DNS server IP strings.  Defaults to
            ``["8.8.8.8", "8.8.4.4"]``.
        domain: Optional domain name for DHCP option 15.
        lease_time: Lease duration in seconds (default: 86400 = 24 hours).
        renewal_time: DHCP T1 renewal time in seconds.  Defaults to
            ``lease_time / 2`` if not specified.
        rebinding_time: DHCP T2 rebinding time in seconds.  Defaults to
            ``lease_time * 7/8`` if not specified.

    Example::

        pool = DhcpPoolConfig(
            pool_start="10.0.0.10",
            pool_end="10.0.0.200",
            server_ip="10.0.0.1",
            dns_servers=["1.1.1.1"],
        )
    """

    def __init__(
        self,
        pool_start: str = "192.168.1.100",
        pool_end: str = "192.168.1.200",
        server_ip: str = "192.168.1.1",
        subnet_mask: str = "255.255.255.0",
        gateway: str = "192.168.1.1",
        dns_servers: Optional[list[str]] = None,
        domain: Optional[str] = None,
        lease_time: int = 86400,
        renewal_time: Optional[int] = None,
        rebinding_time: Optional[int] = None,
    ) -> None: ...
    def __repr__(self) -> str: ...

class DhcpServerAM:
    """Full-featured DHCP server automaton (RFC 2131).

    Implements the complete DHCP DORA flow (Discover/Offer/Request/Ack) plus
    INFORM, RELEASE, and DECLINE message handling with automatic lease
    management and periodic sweep of expired leases.

    Runs on a dedicated background thread with its own async runtime.

    Args:
        pool: DHCP address pool and network configuration.
        server_mac: Server MAC address as ``"aa:bb:cc:dd:ee:ff"``.  Defaults
            to ``"02:00:00:00:00:01"`` (locally-administered).
        sweep_interval: Interval in seconds between expired-lease sweeps
            (default: 60.0).

    Raises:
        ValueError: If *server_mac* is not a valid MAC address.

    Example::

        pool = DhcpPoolConfig(pool_start="10.0.0.10", pool_end="10.0.0.200")
        server = DhcpServerAM(pool, server_mac="aa:bb:cc:dd:ee:ff")
        server.start(AutomatonConfig(iface="en0"))
        # ... server handles DHCP requests in the background ...
        server.stop()
    """

    def __init__(
        self,
        pool: DhcpPoolConfig,
        server_mac: Optional[str] = None,
        sweep_interval: float = 60.0,
    ) -> None: ...
    def start(self, config: AutomatonConfig) -> None:
        """Start the DHCP server on a background thread.

        Args:
            config: Capture configuration specifying the interface.

        Raises:
            RuntimeError: If already running.
            OSError: If the capture device cannot be opened.
        """
        ...
    def stop(self) -> None:
        """Stop the DHCP server and join the background thread."""
        ...
    @property
    def is_running(self) -> bool:
        """True if the DHCP server is currently running."""
        ...
    def __enter__(self) -> DhcpServerAM: ...
    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None: ...
    def __repr__(self) -> str: ...

# ---------------------------------------------------------------------------
# Top-level I/O functions
# ---------------------------------------------------------------------------

def rdpcap(filename: str, count: int = 0) -> list[PcapPacket]:
    """Read packets from a PCAP or PcapNG file.

    Loads all (or up to *count*) packets from a capture file and returns
    them as a list of :class:`PcapPacket` objects, each containing a parsed
    :class:`Packet` and capture metadata.

    The file format (classic PCAP or PcapNG) is detected automatically.

    Args:
        filename: Path to the capture file (``.pcap`` or ``.pcapng``).
        count: Maximum number of packets to read.  ``0`` (default) reads
            all packets.

    Returns:
        A list of :class:`PcapPacket` objects.

    Raises:
        OSError: If the file cannot be opened or is not valid PCAP/PcapNG.

    Example::

        pkts = rdpcap("capture.pcap")
        print(f"Read {len(pkts)} packets")
        pkts[0].packet.show()

        # Read only the first 100 packets
        first_100 = rdpcap("large.pcap", count=100)
    """
    ...

def wrpcap(filename: str, packets: list[Any]) -> None:
    """Write packets to a PCAP file.

    Serializes a list of packets to a capture file.  If *filename* ends in
    ``.pcapng``, the PcapNG format is used automatically; otherwise classic
    PCAP is written.

    Accepts :class:`Packet`, :class:`PcapPacket`, and :class:`LayerStack`
    objects in the *packets* list.

    Args:
        filename: Output file path.
        packets: List of ``Packet``, ``PcapPacket``, or ``LayerStack``
            objects to write.

    Raises:
        OSError: If the file cannot be created or written.

    Example::

        pkt = Ether() / IP(dst="10.0.0.1") / TCP(dport=80)
        wrpcap("output.pcap", [pkt.build()])

        # Round-trip: read then write
        pkts = rdpcap("input.pcap")
        wrpcap("copy.pcap", pkts)
    """
    ...

def wrpcapng(filename: str, packets: list[Any]) -> None:
    """Write packets to a PcapNG file.

    Identical to :func:`wrpcap` but always writes PcapNG format regardless
    of the file extension.

    Args:
        filename: Output file path.
        packets: List of ``Packet``, ``PcapPacket``, or ``LayerStack``
            objects to write.

    Raises:
        OSError: If the file cannot be created or written.

    Example::

        pkts = rdpcap("capture.pcap")
        wrpcapng("output.pcapng", pkts)
    """
    ...

def extract_flows(
    pcap_path: str,
    config: Optional[FlowConfig] = None,
    verbose: bool = False,
) -> list[Conversation]:
    """Extract network flows/conversations from a PCAP file.

    Performs streaming flow extraction directly from a capture file without
    loading all packets into memory.  Groups packets into bidirectional
    flows using canonical 5-tuple keys (src/dst IP, src/dst port, protocol),
    tracks TCP state machines, and optionally reassembles TCP streams.

    Args:
        pcap_path: Path to the PCAP or PcapNG file.
        config: Optional :class:`FlowConfig` for custom timeouts, buffer
            limits, and tracking options.  Uses sensible defaults when
            ``None``.
        verbose: Print progress messages during extraction.

    Returns:
        A list of :class:`Conversation` objects, one per detected flow.

    Raises:
        OSError: If the file cannot be opened.

    Example::

        # Basic extraction
        flows = extract_flows("capture.pcap")
        for f in flows:
            print(f.summary())

        # With custom config
        cfg = FlowConfig(tcp_established_timeout=3600, verbose=True)
        flows = extract_flows("capture.pcap", config=cfg)
    """
    ...

def extract_flows_from_packets(
    packets: list[Packet],
    config: Optional[FlowConfig] = None,
    verbose: bool = False,
) -> list[Conversation]:
    """Extract network flows/conversations from already-loaded packets.

    Same as :func:`extract_flows` but operates on a list of :class:`Packet`
    objects already in memory rather than reading from a file.

    Args:
        packets: List of parsed :class:`Packet` objects.
        config: Optional :class:`FlowConfig` for custom timeouts and limits.
        verbose: Print progress messages during extraction.

    Returns:
        A list of :class:`Conversation` objects.

    Example::

        pkts = rdpcap("capture.pcap")
        raw_packets = [p.packet for p in pkts]
        flows = extract_flows_from_packets(raw_packets)
    """
    ...

def sniff(
    iface: Optional[str] = None,
    filter: Optional[str] = None,
    count: int = 0,
    timeout: Optional[float] = None,
    prn: Optional[Callable[[Packet], Any]] = None,
    stop_filter: Optional[Callable[[Packet], bool]] = None,
    snaplen: int = 65535,
    promisc: bool = True,
) -> list[Packet]:
    """Capture packets from a network interface (Scapy-compatible).

    Blocks until *count* packets are captured, *timeout* seconds elapse,
    or *stop_filter* returns True.  The GIL is released while waiting for
    packets, so other Python threads can run concurrently.

    Args:
        iface: Network interface name (e.g. ``"en0"``, ``"eth0"``).
            Defaults to the system default interface.
        filter: BPF filter expression (e.g. ``"tcp port 80"``).  Use
            :func:`validate_filter` to check filter syntax beforehand.
        count: Stop after capturing this many packets.  ``0`` means
            unlimited (rely on *timeout* or *stop_filter* to stop).
        timeout: Stop after this many seconds.  ``None`` means no timeout.
        prn: Optional callback ``(Packet) -> Any`` invoked for each captured
            packet.  The return value is ignored.
        stop_filter: Optional callback ``(Packet) -> bool``.  When it
            returns ``True``, capture stops (the triggering packet is still
            included in results).
        snaplen: Maximum bytes to capture per packet (default: 65535).
        promisc: Enable promiscuous mode (default: True).

    Returns:
        A list of captured :class:`Packet` objects (already parsed).

    Raises:
        ValueError: If the interface is not found or the BPF filter is
            invalid.
        OSError: If capture permissions are insufficient.

    Example::

        # Capture 10 TCP packets on port 80
        pkts = sniff(iface="en0", filter="tcp port 80", count=10)

        # Capture with a callback and timeout
        sniff(iface="en0", prn=lambda p: print(p.summary()), timeout=5.0)

        # Stop when a packet exceeds 1000 bytes
        pkts = sniff(iface="en0", stop_filter=lambda p: len(p) > 1000)
    """
    ...

def list_interfaces() -> list[dict[str, Any]]:
    """List all available network interfaces.

    Returns:
        A list of dicts, each with keys:
            - ``"name"`` (str): Interface name (e.g. ``"en0"``).
            - ``"description"`` (str): Human-readable description.
            - ``"addresses"`` (list[str]): IP addresses assigned to the
              interface.

    Example::

        for iface in list_interfaces():
            print(f"{iface['name']}: {iface['description']}")
    """
    ...

def validate_filter(filter: str) -> bool:
    """Validate a BPF filter string.

    Compiles the filter expression to check its syntax without starting
    a capture.

    Args:
        filter: BPF filter expression to validate (e.g. ``"tcp port 80"``).

    Returns:
        ``True`` if the filter is syntactically valid.

    Raises:
        ValueError: If the filter expression is invalid, with a message
            describing the syntax error.

    Example::

        validate_filter("tcp port 80")       # Returns True
        validate_filter("invalid syntax")    # Raises ValueError
    """
    ...
