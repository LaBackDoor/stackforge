# The Stackforge Book

**High-performance packet manipulation in Rust with Python bindings — a complete user guide.**

Stackforge brings Scapy-style packet crafting to Rust-native performance. This book covers everything from your first packet to advanced flow extraction, custom protocols, answering machines, and using the Rust crate directly.

---

## Table of Contents

### Getting Started

1. **[Introduction & Installation](01-introduction.md)**
   What Stackforge is, how to install it, and an overview of the architecture.

2. **[Your First Packet](02-first-packet.md)**
   Building packets with `/` stacking, inspecting with `.show()` and `.summary()`, accessing fields.

3. **[Packet Parsing & Dissection](03-parsing.md)**
   Parsing raw bytes, protocol detection, field access patterns, and common gotchas.

### Core Features

4. **[Protocol Reference](04-protocols.md)**
   Every supported protocol with constructor parameters, parsed fields, and examples. Covers Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, DNS, HTTP/1.x, HTTP/2, QUIC, TLS, SSH, MQTT, MQTT-SN, Modbus, Z-Wave, FTP, TFTP, SMTP, POP3, IMAP, L2TP, 802.11, and 802.15.4.

5. **[PCAP I/O](05-pcap.md)**
   Reading and writing PCAP and PcapNG files, streaming large captures with `PcapReader`, and format auto-detection.

6. **[Sniffing & Live Capture](06-sniffing.md)**
   The `sniff()` function, the `Sniffer` iterator, BPF filters, interface discovery, and practical recipes.

### Advanced Features

7. **[Flow Extraction & Analysis](07-flows.md)**
   Stateful conversation extraction from PCAP files, TCP state machine tracking, stream reassembly, ICMP echo correlation, memory-budgeted streaming, and verbose progress.

8. **[Custom Protocols](08-custom.md)**
   Defining runtime protocols with `CustomLayer`, typed fields, protocol registry, and integration with built-in layers.

9. **[Automata & Answering Machines](09-automata.md)**
   Building network responders with `AnsweringMachine`, the built-in DHCP server, `AutomatonConfig`, and the Rust `Automaton` trait.

### For Rust Developers

10. **[The Rust Crate](10-rust.md)**
    Using `stackforge-core` from Rust: builders, parsing, the `Layer` trait, PCAP I/O, flow extraction, sniffing, and utilities.

### Reference

11. **[Scapy Migration Guide](11-migration.md)**
    Side-by-side comparison of Scapy and Stackforge APIs. Import changes, field access, layer checking, PCAP I/O, sniffing, custom protocols, and performance notes.

---

## Quick Links

- **Repository:** [github.com/LaBackDoor/stackforge](https://github.com/LaBackDoor/stackforge)
- **PyPI:** [pypi.org/project/stackforge](https://pypi.org/project/stackforge/)
- **Crates.io:** [crates.io/crates/stackforge-core](https://crates.io/crates/stackforge-core)
- **License:** GPL-3.0
