"""ARP layer Scapy compatibility tests."""

from stackforge import ARP


class TestARPCompat:
    """Test ARP layer byte-for-byte compatibility with Scapy."""

    def test_arp_default(self, compare_with_scapy):
        """Test default ARP packet."""
        stackforge_pkt = ARP().bytes()
        # Scapy auto-fills hwsrc (offset 8-13) and psrc (offset 14-17) with system values
        # Stackforge uses zeros by default, so we mask these fields
        matches, report = compare_with_scapy(stackforge_pkt, "ARP()", ignore_fields=[(8, 18)])
        assert matches, report

    def test_arp_who_has(self, compare_with_scapy):
        """Test ARP who-has request."""
        stackforge_pkt = ARP(op="who-has", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'ARP(op="who-has", pdst="192.168.1.1")', ignore_fields=[(8, 18)]
        )
        assert matches, report

    def test_arp_is_at(self, compare_with_scapy):
        """Test ARP is-at reply."""
        stackforge_pkt = ARP(op="is-at", psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(op="is-at", psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")',
        )
        assert matches, report

    def test_arp_request_full(self, compare_with_scapy):
        """Test complete ARP request with all fields."""
        stackforge_pkt = ARP(
            hwsrc="00:11:22:33:44:55",
            psrc="192.168.1.100",
            pdst="192.168.1.1",
            op="who-has",
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(hwsrc="00:11:22:33:44:55", psrc="192.168.1.100",'
            ' pdst="192.168.1.1", op="who-has")',
        )
        assert matches, report

    def test_arp_reply_full(self, compare_with_scapy):
        """Test complete ARP reply with all fields."""
        stackforge_pkt = ARP(
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
            hwdst="00:11:22:33:44:55",
            pdst="192.168.1.100",
            op="is-at",
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1",'
            ' hwdst="00:11:22:33:44:55", pdst="192.168.1.100",'
            ' op="is-at")',
        )
        assert matches, report

    def test_arp_hwtype_ethernet(self, compare_with_scapy):
        """Test ARP with Ethernet hardware type."""
        stackforge_pkt = ARP(hwtype=1).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, "ARP(hwtype=1)", ignore_fields=[(8, 18)]
        )
        assert matches, report

    def test_arp_ptype_ipv4(self, compare_with_scapy):
        """Test ARP with IPv4 protocol type."""
        stackforge_pkt = ARP(ptype=0x0800).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, "ARP(ptype=0x0800)", ignore_fields=[(8, 18)]
        )
        assert matches, report

    def test_arp_gratuitous(self, compare_with_scapy):
        """Test gratuitous ARP."""
        stackforge_pkt = ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.1")',
            ignore_fields=[(8, 18)],
        )
        assert matches, report

    def test_arp_broadcast_hwdst(self, compare_with_scapy):
        """Test ARP with broadcast hardware destination."""
        stackforge_pkt = ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.1")',
            ignore_fields=[(8, 18)],
        )
        assert matches, report

    def test_arp_zero_hwdst(self, compare_with_scapy):
        """Test ARP with zero hardware destination."""
        stackforge_pkt = ARP(hwdst="00:00:00:00:00:00", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(hwdst="00:00:00:00:00:00", pdst="192.168.1.1")',
            ignore_fields=[(8, 18)],
        )
        assert matches, report

    def test_arp_various_ips(self, compare_with_scapy):
        """Test ARP with various IP addresses."""
        ip_addresses = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "8.8.8.8",
            "255.255.255.255",
        ]

        for ip in ip_addresses:
            stackforge_pkt = ARP(pdst=ip).bytes()
            matches, report = compare_with_scapy(
                stackforge_pkt, f'ARP(pdst="{ip}")', ignore_fields=[(8, 18)]
            )
            assert matches, f"IP {ip} mismatch: {report}"

    def test_arp_length(self):
        """Test ARP packet size."""
        stackforge_pkt = ARP().bytes()
        assert len(stackforge_pkt) == 28, "ARP packet should be 28 bytes"

    def test_arp_hwtype_offset(self):
        """Test hardware type is at correct offset."""
        stackforge_pkt = ARP(hwtype=1).bytes()
        # Hardware type at bytes 0-1 (big-endian)
        assert stackforge_pkt[0:2] == b"\x00\x01"

    def test_arp_ptype_offset(self):
        """Test protocol type is at correct offset."""
        stackforge_pkt = ARP(ptype=0x0800).bytes()
        # Protocol type at bytes 2-3 (big-endian)
        assert stackforge_pkt[2:4] == b"\x08\x00"

    def test_arp_hwlen_offset(self):
        """Test hardware length is at correct offset."""
        stackforge_pkt = ARP().bytes()
        # Hardware length at byte 4
        assert stackforge_pkt[4] == 6  # Ethernet MAC is 6 bytes

    def test_arp_plen_offset(self):
        """Test protocol length is at correct offset."""
        stackforge_pkt = ARP().bytes()
        # Protocol length at byte 5
        assert stackforge_pkt[5] == 4  # IPv4 address is 4 bytes

    def test_arp_op_offset(self):
        """Test operation code is at correct offset."""
        stackforge_pkt = ARP(op="who-has").bytes()
        # Operation at bytes 6-7 (big-endian, 1=request)
        assert stackforge_pkt[6:8] == b"\x00\x01"

    def test_arp_op_is_at_value(self):
        """Test is-at operation has correct value."""
        stackforge_pkt = ARP(op="is-at").bytes()
        # Operation at bytes 6-7 (big-endian, 2=reply)
        assert stackforge_pkt[6:8] == b"\x00\x02"

    def test_arp_probe(self, compare_with_scapy):
        """Test ARP probe (psrc=0.0.0.0)."""
        stackforge_pkt = ARP(psrc="0.0.0.0", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'ARP(psrc="0.0.0.0", pdst="192.168.1.1")', ignore_fields=[(8, 18)]
        )
        assert matches, report

    def test_arp_announcement(self, compare_with_scapy):
        """Test ARP announcement."""
        stackforge_pkt = ARP(
            op="is-at",
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.100",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.100",
        ).bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt,
            'ARP(op="is-at", hwsrc="aa:bb:cc:dd:ee:ff",'
            ' psrc="192.168.1.100", hwdst="00:00:00:00:00:00",'
            ' pdst="192.168.1.100")',
        )
        assert matches, report

    def test_arp_different_subnets(self, compare_with_scapy):
        """Test ARP with source and dest in different subnets."""
        stackforge_pkt = ARP(psrc="10.0.0.1", pdst="192.168.1.1").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'ARP(psrc="10.0.0.1", pdst="192.168.1.1")', ignore_fields=[(8, 14)]
        )
        assert matches, report

    def test_arp_multicast_hwsrc(self, compare_with_scapy):
        """Test ARP with multicast source MAC."""
        stackforge_pkt = ARP(hwsrc="01:00:5e:00:00:01").bytes()
        matches, report = compare_with_scapy(
            stackforge_pkt, 'ARP(hwsrc="01:00:5e:00:00:01")', ignore_fields=[(14, 18)]
        )
        assert matches, report
