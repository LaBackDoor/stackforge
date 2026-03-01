__version__ = "0.2.0"

# Re-export all public classes from the Rust extension
from stackforge.stackforge import (
    ARP,
    HTTP,
    HTTP2,
    ICMP,
    IP,
    L2TP,
    QUIC,
    SSH,
    TCP,
    TLS,
    UDP,
    # Flow extraction
    Conversation,
    Ether,
    FlowConfig,
    HTTPResponse,
    ICMPv6,
    # New protocol builders
    IPv6,
    LayerIndex,
    LayerKind,
    LayerStack,
    Packet,
    PcapPacket,
    PcapReader,
    Raw,
    extract_flows,
    extract_flows_from_packets,
    rdpcap,
    wrpcap,
)

from .custom import (
    ByteField,
    CustomLayer,
    IntField,
    LongField,
    ShortField,
    StrLenField,
    get_protocol,
    list_protocols,
)

__all__ = [
    "Packet",
    "LayerKind",
    "LayerIndex",
    # Layer builders
    "Ether",
    "IP",
    "TCP",
    "UDP",
    "ARP",
    "ICMP",
    "SSH",
    "TLS",
    "Raw",
    "LayerStack",
    # New protocol builders
    "IPv6",
    "ICMPv6",
    "HTTP",
    "HTTPResponse",
    "QUIC",
    "HTTP2",
    "L2TP",
    # PCAP I/O
    "rdpcap",
    "wrpcap",
    "PcapPacket",
    "PcapReader",
    # Flow extraction
    "Conversation",
    "FlowConfig",
    "extract_flows",
    "extract_flows_from_packets",
    # Custom protocol API
    "CustomLayer",
    "ByteField",
    "ShortField",
    "IntField",
    "LongField",
    "StrLenField",
    "get_protocol",
    "list_protocols",
    "__version__",
]
