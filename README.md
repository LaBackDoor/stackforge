# Stackforge

[![CI](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml/badge.svg)](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/stackforge)](https://pypi.org/project/stackforge/)
[![Crates.io](https://img.shields.io/crates/v/stackforge-core)](https://crates.io/crates/stackforge-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)

**Stackforge** is a high-performance networking stack written in Rust with Python bindings. It provides Scapy-like packet manipulation with native Rust performance — build, parse, and inspect network packets using a familiar `/` stacking syntax.

## Features

- **Scapy-style API** — Stack layers with `Ether() / IP() / TCP()`, set fields with keyword arguments
- **High Performance** — Core logic in Rust, zero-copy parsing, copy-on-write mutation
- **Broad Protocol Support** — Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, ICMPv6, DNS, HTTP/1.x, HTTP/2, QUIC, L2TP, 802.11 (Wi-Fi), 802.15.4 (Zigbee), and custom protocols
- **PCAP I/O** — Read and write pcap files with `rdpcap()` / `wrpcap()`
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

### Read and write PCAP files

```python
from stackforge import rdpcap, wrpcap, PcapReader, Ether, IP, TCP

# Write packets to a pcap file
packets = [
    Ether() / IP(dst="192.168.1.1") / TCP(dport=80, flags="S"),
    Ether() / IP(dst="10.0.0.1") / TCP(dport=443, flags="SA"),
]
wrpcap("capture.pcap", packets)

# Read all packets at once
packets = rdpcap("capture.pcap")
for pkt in packets:
    print(pkt.summary())

# Stream large pcap files
for pkt in PcapReader("large_capture.pcap"):
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

## Rust Crate

The core library is available as a standalone Rust crate:

```toml
[dependencies]
stackforge-core = "0.3"
```

## Development

```bash
# Set up environment
uv sync

# Build Rust extension (required after Rust changes)
uv run maturin develop

# Run tests
cargo test               # Rust tests
uv run pytest tests/python

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
