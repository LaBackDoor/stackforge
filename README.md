# Stackforge

[![CI](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml/badge.svg)](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/stackforge)](https://pypi.org/project/stackforge/)
[![Crates.io](https://img.shields.io/crates/v/stackforge-core)](https://crates.io/crates/stackforge-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-book-blue)](docs/book/README.md)

**Stackforge** is a high-performance networking stack written in Rust with Python bindings. It provides Scapy-like packet manipulation with native Rust performance — build, parse, and inspect network packets using a familiar `/` stacking syntax.

## Features

- **Scapy-style API** — Stack layers with `Ether() / IP() / TCP()`, set fields with keyword arguments
- **High Performance** — Core logic in Rust, zero-copy parsing, copy-on-write mutation
- **Broad Protocol Support** — Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS, TLS, SSH, HTTP/1.x, HTTP/2, QUIC, L2TP, MQTT, MQTT-SN, Modbus, Z-Wave, FTP, TFTP, SMTP, POP3, IMAP, 802.11 (Wi-Fi), 802.15.4 (Zigbee), and custom protocols
- **Live Packet Capture** — Sniff packets from network interfaces with BPF filters, callbacks, and stop conditions
- **Answering Machines** — Async automaton framework for building network responders (DHCP server, ARP spoofer, custom callback-based machines)
- **Stateful Flow Extraction** — Extract bidirectional conversations from PCAP/PcapNG files with TCP state tracking, stream reassembly, UDP timeout handling, and optional max packet/flow length tracking
- **Flow Anonymization** — ML-optimized anonymization with Crypto-PAn prefix-preserving IP anonymization, port generalization, order-preserving timestamp perturbation, TCP sequence offsetting, and payload truncation
- **Memory-Budgeted Streaming** — Process gigabyte-sized captures without loading everything into RAM; set a memory budget and reassembly buffers automatically spill to memory-mapped temp files
- **PCAP & PcapNG I/O** — Read and write both classic PCAP and PcapNG files with auto-detection via `rdpcap()` / `wrpcap()` / `wrpcapng()`
- **Parallel Parsing** — Multi-threaded packet parsing with `WorkerPool` and `parse_batch()`
- **Python Bindings** — Seamless integration via PyO3/maturin
- **Custom Protocols** — Define runtime protocols with `CustomLayer` and typed fields

## Installation

```bash
pip install stackforge
```

Or with uv:

```bash
uv add stackforge
```

## Quick Start

### Build and send packets

```python
from stackforge import Ether, IP, TCP, UDP, ICMP, Raw

# TCP SYN packet
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
print(pkt.show())

# UDP DNS query
pkt = Ether() / IP(dst="8.8.8.8") / UDP(dport=53)

# ICMP echo request
pkt = Ether() / IP(dst="10.0.0.1") / ICMP.echo_request(id=0x1234, seq=1)

# Packet with raw payload
pkt = Ether() / IP(dst="10.0.0.1") / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n")
```

### Build to bytes

```python
stack = Ether() / IP(dst="10.0.0.1") / TCP(dport=443, flags="S")

# Build into a Packet object
pkt = stack.build()

# Or get raw bytes directly
raw = stack.bytes()
```

### Parse packets from bytes

```python
from stackforge import Packet, LayerKind

raw_bytes = b"\xff\xff..."  # raw packet bytes
pkt = Packet(raw_bytes)
pkt.parse()

print(pkt.layer_count)                  # 3
print(pkt.has_layer(LayerKind.Tcp))     # True
print(pkt.summary())                    # "Ethernet / IPv4 / TCP"
print(pkt.show())                       # detailed layer view
```

### Read and write PCAP / PcapNG files

```python
from stackforge import rdpcap, wrpcap, wrpcapng, PcapReader, Ether, IP, TCP

# Write packets to a pcap file
packets = [
    Ether() / IP(dst="192.168.1.1") / TCP(dport=80, flags="S"),
    Ether() / IP(dst="10.0.0.1") / TCP(dport=443, flags="SA"),
]
wrpcap("capture.pcap", packets)

# Write PcapNG format explicitly
wrpcapng("capture.pcapng", packets)

# wrpcap auto-detects format from extension
wrpcap("capture.pcapng", packets)  # writes PcapNG

# Read any format (auto-detected)
packets = rdpcap("capture.pcap")    # classic PCAP
packets = rdpcap("capture.pcapng")  # PcapNG — same API
for pkt in packets:
    print(pkt.summary())

# Stream large captures (works with both formats)
for pkt in PcapReader("large_capture.pcapng"):
    print(pkt.summary())
```

## Protocol Reference

### Layer Builders

```python
from stackforge import Ether, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6, DNS, Raw

# Ethernet
Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")

# IPv4
IP(src="10.0.0.1", dst="192.168.1.100", ttl=128)

# IPv6
IPv6(src="::1", dst="2001:db8::1", hlim=64)

# TCP
TCP(sport=12345, dport=443, flags="SA", seq=1000, ack=2000)

# UDP
UDP(sport=5000, dport=53)

# ARP
ARP(op="who-has", pdst="192.168.1.100")
ARP(op="is-at", pdst="192.168.1.100")

# ICMP
ICMP(type=8, code=0)
ICMP.echo_request(id=0x1234, seq=1)
ICMP.echo_reply(id=0xABCD, seq=42)
ICMP.dest_unreach(code=3)
ICMP.redirect(code=1, gateway="10.0.0.1")
ICMP.time_exceeded(code=0)

# ICMPv6
ICMPv6(type=128, code=0)           # echo request

# DNS
DNS(id=0x1234, qr=0, rd=1)         # query

# Raw payload
Raw(load=b"Hello")
Raw.from_hex("deadbeef")
Raw.zeros(10)
Raw.repeat(0x41, 5)                 # b"AAAAA"
Raw.pattern(b"AB", 7)              # b"ABABABA"
```

### Field Access

```python
from stackforge import Packet, LayerKind

pkt = Packet(raw_bytes)
pkt.parse()

# Generic field access (searches all layers)
print(pkt.src)
print(pkt.dport)

# Layer-specific field access (use when field name exists in multiple layers)
dns_id = pkt.getfieldval(LayerKind.Dns, "id")
ip_id  = pkt.getfieldval(LayerKind.Ipv4, "id")

# Introspect available fields
print(pkt.fields)                          # list of all field names

# Layer presence and bytes
print(pkt.has_layer(LayerKind.Http))
print(pkt.get_layer_bytes(LayerKind.Http))
```

### Custom Protocols

```python
from stackforge.custom import CustomLayer, ByteField, ShortField, IntField, StrLenField

class MyHeader(CustomLayer):
    name = "MyHeader"
    fields_desc = [
        ByteField("version", default=1),
        ShortField("length", default=0),
        IntField("magic", default=0xDEADBEEF),
        StrLenField("payload", default=b"", length_from=lambda pkt: pkt.length),
    ]

pkt = Ether() / IP() / UDP(dport=9999) / MyHeader(version=2, magic=0xCAFEBABE)
```

### HTTP/1.x

```python
from stackforge import Packet, LayerKind

# HTTP is auto-detected on TCP ports 80, 8080, 8000, 8008, 8888
pkt = Packet(raw_bytes)
pkt.parse()

if pkt.has_layer(LayerKind.Http):
    print(pkt.get_layer_bytes(LayerKind.Http))
```

### HTTP/2

```python
# HTTP/2 is auto-detected via the client preface magic bytes on TCP
pkt = Packet(raw_bytes)
pkt.parse()

if pkt.has_layer(LayerKind.Http2):
    print(pkt.summary())   # "Ethernet / IPv4 / TCP / HTTP2"
```

### QUIC

```python
# QUIC is auto-detected on UDP ports 443 / 4433 via the Fixed Bit
pkt = Packet(raw_bytes)
pkt.parse()

if pkt.has_layer(LayerKind.Quic):
    print(pkt.getfieldval(LayerKind.Quic, "dst_conn_id"))
    print(pkt.getfieldval(LayerKind.Quic, "packet_number"))
```

### 802.11 (Wi-Fi)

```python
# Dot11 frames are parsed directly (not over Ethernet)
from stackforge import Packet, LayerKind

pkt = Packet(raw_bytes)
pkt.parse()   # expects radiotap + Dot11 frame

print(pkt.has_layer(LayerKind.Dot11))
```

### 802.15.4 (Zigbee)

```python
# Dot15d4 frames include optional CRC-16 (CCITT Kermit)
pkt = Packet(raw_bytes)
pkt.parse()

print(pkt.has_layer(LayerKind.Dot15d4))
print(pkt.has_layer(LayerKind.Dot15d4Fcs))
```

### L2TP

```python
# L2TP v2 auto-detected on UDP port 1701
pkt = Packet(raw_bytes)
pkt.parse()

print(pkt.has_layer(LayerKind.L2tp))
```

### IoT Protocols

```python
from stackforge import MQTT, MQTTSN, Modbus, ZWave

# MQTT (auto-detected on TCP port 1883)
pkt = Ether() / IP() / TCP(dport=1883) / MQTT(msg_type=1)  # CONNECT

# MQTT-SN (auto-detected on UDP port 1883)
pkt = Ether() / IP() / UDP(dport=1883) / MQTTSN(msg_type=0x04)  # PUBLISH

# Modbus TCP (auto-detected on TCP port 502)
pkt = Ether() / IP() / TCP(dport=502) / Modbus(func_code=3, data=b"\x00\x01\x00\x0a")

# Z-Wave (wireless, not auto-detected over TCP/UDP)
pkt = ZWave(home_id=0x12345678, src=1, dst=2, cmd_class=0x25, cmd=0x01)
```

### Email & File Transfer Protocols

```python
from stackforge import FTP, TFTP, SMTP, POP3, IMAP

# FTP (TCP port 21), SMTP (TCP ports 25/587/465), POP3 (TCP port 110), IMAP (TCP port 143)
# All auto-detected during packet parsing

# TFTP (UDP port 69)
pkt = Ether() / IP() / UDP(dport=69) / TFTP(opcode=1, filename="test.txt", mode="octet")
```

### Live Packet Capture

Capture packets from network interfaces with BPF filters, callbacks, and stop conditions.

```python
from stackforge import sniff, Sniffer, list_interfaces, validate_filter

# Quick capture (Scapy-compatible API)
packets = sniff(iface="en0", filter="tcp port 80", count=10, timeout=5.0)

# With per-packet callback
def handle_pkt(pkt):
    print(pkt.summary())

sniff(iface="en0", filter="udp", prn=handle_pkt, count=100)

# With stop condition
sniff(iface="en0", stop_filter=lambda pkt: pkt.has_layer(LayerKind.Dns), timeout=30.0)

# Iterator-based sniffer for more control
sniffer = Sniffer(iface="en0", filter="icmp", snaplen=65535, promisc=True)
sniffer.start()
for pkt in sniffer:
    print(pkt.summary())
sniffer.stop()

# List available network interfaces
for iface in list_interfaces():
    print(iface)

# Validate a BPF filter string
validate_filter("tcp port 80 and host 10.0.0.1")
```

### Parallel Parsing

Parse packets across multiple threads for high-throughput workloads:

```python
from stackforge import parse_batch, WorkerPool, rdpcap

# One-shot parallel parse
packets = rdpcap("capture.pcap")
parsed = parse_batch(packets)

# Reusable worker pool
pool = WorkerPool()
parsed = pool.parse_batch(packets)
```

### Answering Machines

Build network responders using the async automaton framework. Answering machines run on a background thread with their own event loop, sniffing packets and sending replies automatically.

```python
from stackforge import AnsweringMachine, AutomatonConfig, DhcpServerAM, DhcpPoolConfig

# Callback-based answering machine
def is_request(pkt):
    return pkt.has_layer(LayerKind.Arp)

def make_reply(pkt):
    return (Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at")).bytes()

am = AnsweringMachine(is_request, make_reply, bpf_filter="arp")
config = AutomatonConfig(iface="en0")
am.start(config)
# ... machine responds to ARP requests in the background ...
am.stop()

# Built-in DHCP server
pool = DhcpPoolConfig(
    pool_start="192.168.1.100",
    pool_end="192.168.1.200",
    server_ip="192.168.1.1",
    subnet_mask="255.255.255.0",
    gateway="192.168.1.1",
    dns_servers=["8.8.8.8", "8.8.4.4"],
    lease_time=86400,
)
dhcp = DhcpServerAM(pool, server_mac="02:00:00:00:00:01")
dhcp.start(AutomatonConfig(iface="en0"))
# ... full DHCP DORA + INFORM/RELEASE/DECLINE handling ...
dhcp.stop()

# Context manager support
with DhcpServerAM(pool) as dhcp:
    dhcp.start(AutomatonConfig())
    # server runs until the block exits
```

### Stateful Flow Extraction

Extract bidirectional conversations from PCAP captures with full TCP state machine tracking, stream reassembly, and UDP timeout-based flow grouping.

```python
from stackforge import extract_flows, extract_flows_from_packets, FlowConfig, rdpcap

# Extract conversations from a PCAP file
conversations = extract_flows("capture.pcap")

for conv in conversations:
    print(f"{conv.src_addr}:{conv.src_port} <-> {conv.dst_addr}:{conv.dst_port}")
    print(f"  Protocol: {conv.protocol}, Status: {conv.status}")
    print(f"  Packets: {conv.total_packets}, Bytes: {conv.total_bytes}")
    print(f"  Duration: {conv.duration:.3f}s")

    # TCP-specific state and reassembled stream data
    if conv.tcp_state:
        print(f"  TCP State: {conv.tcp_state}")
    if conv.reassembled_forward:
        print(f"  Forward stream: {len(conv.reassembled_forward)} bytes")
    if conv.reassembled_reverse:
        print(f"  Reverse stream: {len(conv.reassembled_reverse)} bytes")

    # Check for dropped segments (buffer/fragment limits exceeded)
    if conv.dropped_segments > 0:
        print(f"  WARNING: {conv.dropped_segments} segments dropped (fwd={conv.dropped_segments_fwd}, rev={conv.dropped_segments_rev})")

    # Indices into the original packet list
    print(f"  Packet indices: {conv.packet_indices}")
```

Use `extract_flows_from_packets` to extract flows from already-loaded packets:

```python
packets = rdpcap("capture.pcap")
conversations = extract_flows_from_packets(packets)
```

Enable verbose mode to see progress feedback on stderr during extraction:

```python
# Quick verbose flag on the function call
conversations = extract_flows("capture.pcap", verbose=True)

# Or via FlowConfig
config = FlowConfig(verbose=True)
conversations = extract_flows("capture.pcap", config=config)
```

Verbose output shows real-time progress with processing rate, memory usage, ETA, and spill stats:

```
[+] stackforge flow extraction engine
[+] File: capture.pcap (2.3 GB)
[+] Mode: streaming (packets read from disk on-the-fly)
[+] Memory budget: 1.00 GB
[+] Processing...

    [1m 23s] 100,000 pkts | 1,234 flows | 85,432/s (avg 72,150/s) | mem ~45.2 MB
    [2m 48s] 200,000 pkts | 2,567 flows | 78,901/s (avg 71,428/s) | mem ~89.1 MB | 3 spills

[+] Finalizing (sorting 88,254 flows)...
[+] Complete: 88,254 flows extracted
[+] Wall time: 1h 12m
[!] Warning: 2,847 TCP segments dropped across 134 flows (buffer/fragment limits exceeded)
[!] Tip: increase max_reassembly_buffer or max_ooo_fragments to capture more data
```

Customize timeouts, buffer limits, and memory budget with `FlowConfig`:

```python
config = FlowConfig(
    tcp_established_timeout=3600.0,  # 1 hour (default: 86400s)
    udp_timeout=60.0,                # 1 minute (default: 120s)
    max_reassembly_buffer=1048576,   # 1 MB per flow (default: 16 MB)
)
conversations = extract_flows("capture.pcap", config=config)
```

#### Memory-Budgeted Flow Extraction

For large captures, set a memory budget so reassembly buffers automatically spill to disk when RAM is tight:

```python
config = FlowConfig(
    memory_budget=256 * 1024 * 1024,  # 256 MB RAM budget
    spill_dir="/tmp/stackforge-spill", # optional custom spill directory
    store_packet_indices=False,        # save ~8 bytes/pkt on large captures
    progress_interval=500_000,         # report every 500K packets (default: 100K)
)
conversations = extract_flows("large_capture.pcapng", config=config)
```

Packets stream from disk one at a time (never loaded all at once). When TCP reassembly buffers exceed the budget, the largest buffers are transparently spilled to memory-mapped temp files and read back on demand. Temp files are automatically cleaned up via RAII.

Optional: Track maximum packet sizes during flow extraction:

```python
config = FlowConfig(
    track_max_packet_len=True,   # Track max per-direction (forward_max_packet_len, reverse_max_packet_len)
    track_max_flow_len=True,     # Track overall max (max_flow_len)
)
conversations = extract_flows("capture.pcap", config=config)

for conv in conversations:
    print(f"Max fwd packet: {conv.forward_max_packet_len} bytes")
    print(f"Max rev packet: {conv.reverse_max_packet_len} bytes")
    print(f"Max overall: {conv.max_flow_len} bytes")
```

Disabled by default (zero overhead). Enable only when needed for flow analysis.

#### ICMP and ICMPv6 Flow Tracking

Automatically correlate ICMP echo request/reply pairs and track other ICMP message types:

```python
conversations = extract_flows("capture.pcap")

for conv in conversations:
    if conv.protocol == "ICMP" or conv.protocol == "ICMPv6":
        print(f"ICMP Echo: {conv.src_addr} <-> {conv.dst_addr}")
        print(f"  Type: {conv.icmp_type}, Code: {conv.icmp_code}")
        print(f"  Identifier: {conv.icmp_identifier}")
        print(f"  Requests: {conv.icmp_request_count}, Replies: {conv.icmp_reply_count}")
        print(f"  Last seq: {conv.icmp_last_seq}")
```

Features:
- Echo request/reply pairs correlated via identifier (symmetric src/dst ports)
- Non-echo message types tracked via (type, code) substitution
- Properties: `icmp_type`, `icmp_code`, `icmp_identifier`, `icmp_request_count`, `icmp_reply_count`, `icmp_last_seq`
- Returns `None` for non-ICMP flows

### Flow Anonymization

Anonymize extracted flows for ML pipelines and privacy-compliant data sharing. Supports Crypto-PAn prefix-preserving IP anonymization, port generalization, timestamp perturbation, TCP sequence number offsetting, and payload truncation.

```python
from stackforge import extract_flows, AnonymizationPolicy

# Use a built-in preset optimized for ML feature preservation
policy = AnonymizationPolicy.ml_optimized()
flows = extract_flows("capture.pcap", anonymization=policy)

for f in flows:
    print(f"{f.src_addr}:{f.src_port} -> {f.dst_addr}:{f.dst_port}")
    # IPs are prefix-preserving anonymized, ports preserve well-known values,
    # timestamps are shifted, TCP seq numbers are offset, payloads are truncated
```

#### Presets

```python
# ML-optimized: Crypto-PAn IPs, preserve well-known ports, epoch shift timestamps,
# random TCP seq offset, truncate payloads to 256 bytes
policy = AnonymizationPolicy.ml_optimized()

# Maximum privacy: Crypto-PAn IPs, categorize all ports, epoch shift + jitter,
# random TCP seq offset, truncate all payloads
policy = AnonymizationPolicy.maximum_privacy()
```

#### Custom Policies

```python
policy = AnonymizationPolicy(
    ip_mode="crypto_pan",            # "crypto_pan" or None (passthrough)
    mac_mode="salted_hash",          # "salted_hash", "salted_hash_preserve_oui", or None
    port_mode="preserve_well_known", # "preserve_well_known", "categorize", or None
    timestamp_mode="epoch_shift",    # "epoch_shift", "epoch_shift_jitter", or None
    tcp_seq_mode="random_offset",    # "random_offset" or None
    payload_mode="truncate_all",     # "truncate_all", "truncate_to", or None
)

# With explicit keys for reproducibility
policy = AnonymizationPolicy(
    ip_mode="crypto_pan",
    crypto_pan_key=bytes(range(32)),  # 32-byte key (random if omitted)
)

# Timestamp jitter and payload truncation limit
policy = AnonymizationPolicy(
    timestamp_mode="epoch_shift_jitter",
    timestamp_jitter_ms=10,           # bounded per-timestamp noise (ms)
    payload_mode="truncate_to",
    payload_truncate_bytes=256,       # keep first N bytes
)
```

#### Works with Any Flow Source

```python
from stackforge import extract_flows_from_packets, Ether, IP, TCP

# From already-loaded packets
pkts = [
    (Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(dport=80, flags="S")).build()
    for _ in range(10)
]
for p in pkts:
    p.parse()

policy = AnonymizationPolicy(ip_mode="crypto_pan", crypto_pan_key=bytes(range(32)))
flows = extract_flows_from_packets(pkts, anonymization=policy)
```

Key properties:
- **Prefix-preserving**: Two IPs sharing a /24 subnet will share a /24 subnet after anonymization
- **Deterministic**: Same key always produces the same mapping
- **Order-preserving timestamps**: Relative durations and ordering are maintained
- **ML-friendly**: Flow statistics (packet counts, byte counts, durations) are preserved

## Rust Crate

The core library is available as a standalone Rust crate:

```toml
[dependencies]
stackforge-core = "0.7"
```

## Development

```bash
# Set up environment
uv sync

# Build Rust extension (required after Rust changes)
uv run maturin develop

# Run tests
cargo test               # Rust tests (~1475 tests)
uv run pytest tests/python  # Python tests (~1633 tests)

# Lint and format
cargo fmt
cargo clippy
uv run ruff check .
```

## Citing Stackforge

If you use Stackforge in academic research or published work, please cite it:

```bibtex
@software{stackforge,
  title = {Stackforge: High-Performance Packet Manipulation in Rust with Python Bindings},
  url = {https://github.com/LaBackDoor/stackforge},
  license = {GPL-3.0}
}
```

Or in plain text:

> Stackforge: High-Performance Packet Manipulation in Rust with Python Bindings. https://github.com/LaBackDoor/stackforge

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
