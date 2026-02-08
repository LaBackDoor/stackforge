#!/usr/bin/env python3
"""
Generate test fixtures using Scapy.

This script creates pre-built packet binaries for use in tests
without requiring Scapy at test runtime.
"""

import json
from pathlib import Path

from scapy.all import (
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    raw,
)


def generate_fixtures():
    """Generate all test fixtures."""
    fixtures_dir = Path(__file__).parent.parent / "fixtures" / "scapy_packets"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    fixtures = {
        # Ethernet fixtures
        "ethernet_basic": Ether(),
        "ethernet_broadcast": Ether(dst="ff:ff:ff:ff:ff:ff"),
        "ethernet_custom_macs": Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66"),
        # ARP fixtures
        "arp_request": Ether() / ARP(op="who-has", pdst="192.168.1.1"),
        "arp_reply": Ether() / ARP(op="is-at", psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff"),
        "arp_basic": ARP(),
        # TCP fixtures
        "tcp_syn": Ether() / IP() / TCP(flags="S"),
        "tcp_synack": Ether() / IP() / TCP(flags="SA"),
        "tcp_ack": Ether() / IP() / TCP(flags="A"),
        "tcp_fin": Ether() / IP() / TCP(flags="F"),
        "tcp_rst": Ether() / IP() / TCP(flags="R"),
        "tcp_psh_ack": Ether() / IP() / TCP(flags="PA"),
        "tcp_with_payload": Ether() / IP() / TCP() / Raw(load=b"Hello, World!"),
        # UDP fixtures
        "udp_basic": Ether() / IP() / UDP(),
        "udp_dns": Ether() / IP() / UDP(dport=53),
        "udp_with_payload": Ether() / IP() / UDP() / Raw(load=b"UDP Data"),
        # ICMP fixtures
        "icmp_echo_request": Ether() / IP() / ICMP(type=8),
        "icmp_echo_reply": Ether() / IP() / ICMP(type=0),
        "icmp_dest_unreach": Ether() / IP() / ICMP(type=3, code=3),
        "icmp_time_exceeded": Ether() / IP() / ICMP(type=11),
        "icmp_redirect": Ether() / IP() / ICMP(type=5, code=1, gw="10.0.0.1"),
        # IP fixtures
        "ipv4_basic": Ether() / IP(),
        "ipv4_custom": Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=128),
        "ipv4_df_flag": Ether() / IP(flags="DF"),
        # Stacking combinations
        "ether_arp": Ether() / ARP(),
        "ether_ip": Ether() / IP(),
        "ether_ip_tcp": Ether() / IP() / TCP(),
        "ether_ip_udp": Ether() / IP() / UDP(),
        "ether_ip_icmp": Ether() / IP() / ICMP(),
    }

    metadata = {}

    for name, pkt in fixtures.items():
        # Save binary
        bin_path = fixtures_dir / f"{name}.bin"
        with open(bin_path, "wb") as f:
            f.write(raw(pkt))

        # Save metadata
        metadata[name] = {
            "size": len(raw(pkt)),
            "layers": [layer.name for layer in pkt.layers()],
            "summary": pkt.summary(),
        }

        print(f"Generated {name}: {len(raw(pkt))} bytes")

    # Save metadata
    metadata_path = fixtures_dir.parent / "expected_outputs.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nGenerated {len(fixtures)} fixtures")
    print(f"Metadata saved to {metadata_path}")


if __name__ == "__main__":
    generate_fixtures()
