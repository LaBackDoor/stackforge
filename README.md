# Stackforge

[![CI](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml/badge.svg)](https://github.com/LaBackDoor/stackforge/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/stackforge)](https://pypi.org/project/stackforge/)
[![Crates.io](https://img.shields.io/crates/v/stackforge-core)](https://crates.io/crates/stackforge-core)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)

**Stackforge** is a high-performance networking stack written in Rust with Python bindings. It provides Scapy-like packet manipulation with native Rust performance — build, parse, and inspect network packets using a familiar `/` stacking syntax.

## Features

- **Scapy-style API** — Stack layers with `Ether() / IP() / TCP()`, set fields with keyword arguments
- **High Performance** — Core logic in Rust, zero-copy parsing, copy-on-write mutation
- **Protocol Support** — Ethernet, ARP, IPv4, TCP, UDP, ICMP, Raw payloads
- **PCAP I/O** — Read and write pcap files with `rdpcap()` / `wrpcap()`
- **Python Bindings** — Seamless integration via PyO3/maturin

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

### Layer builders

```python
from stackforge import Ether, IP, TCP, UDP, ARP, ICMP, Raw

# Ethernet
Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66")

# IPv4
IP(src="10.0.0.1", dst="192.168.1.100", ttl=128)

# TCP with flags and ports
TCP(sport=12345, dport=443, flags="SA", seq=1000, ack=2000)

# UDP
UDP(sport=5000, dport=53)

# ARP
ARP(op="who-has", pdst="192.168.1.100")
ARP(op="is-at", pdst="192.168.1.100")

# ICMP
ICMP(type=8, code=0)                                  # generic
ICMP.echo_request(id=0x1234, seq=1)                    # echo request
ICMP.echo_reply(id=0xABCD, seq=42)                     # echo reply
ICMP.dest_unreach(code=3)                              # destination unreachable
ICMP.redirect(code=1, gateway="10.0.0.1")              # redirect
ICMP.time_exceeded(code=0)                             # TTL exceeded

# Raw payload
Raw(load=b"Hello")
Raw.from_hex("deadbeef")
Raw.zeros(10)
Raw.repeat(0x41, 5)                                    # b"AAAAA"
Raw.pattern(b"AB", 7)                                  # b"ABABABA"
```

## Rust Crate

The core library is available as a standalone Rust crate:

```toml
[dependencies]
stackforge-core = "0.2"
```

## Development

```bash
# Set up environment
uv sync

# Build Rust extension (required after Rust changes)
uv run maturin develop

# Run tests
uv run cargo test    # Rust tests (needs venv for scapy compat tests)
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
