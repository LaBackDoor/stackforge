//! Integration tests for SSH protocol layer.

use stackforge_core::{LayerKind, Packet, SshBuilder};

#[test]
fn test_parse_ssh_version_exchange() {
    // Ethernet + IPv4 + TCP + SSH version exchange
    let mut data = Vec::new();
    // Ethernet header (14 bytes)
    data.extend_from_slice(&[0xff; 6]); // dst
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
    data.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, // version/ihl, tos, total len (filled later)
        0x00, 0x01, 0x40, 0x00, // id, flags
        0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP, checksum
        192, 168, 1, 1, // src
        192, 168, 1, 2, // dst
    ]);

    // TCP header (20 bytes) - port 22
    data.extend_from_slice(&[
        0x00, 0x16, // sport = 22 (SSH)
        0xC0, 0x00, // dport = 49152
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0xFF, 0xFF, // data offset=5, flags=SYN, window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ]);

    // SSH version exchange payload
    let ssh_payload = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1\r\n";
    data.extend_from_slice(ssh_payload);

    // Fix IP total length
    let ip_total_len = (data.len() - 14) as u16;
    data[16] = (ip_total_len >> 8) as u8;
    data[17] = (ip_total_len & 0xFF) as u8;

    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    assert!(pkt.get_layer(LayerKind::Ssh).is_some());
    assert!(pkt.get_layer(LayerKind::Tcp).is_some());

    let layers = pkt.layer_enums();
    let ssh = layers.iter().find(|l| l.kind() == LayerKind::Ssh).unwrap();
    let summary = ssh.summary(pkt.as_bytes());
    assert!(summary.contains("SSH-2.0-OpenSSH_9.2p1"));
}

#[test]
fn test_parse_ssh_binary_packet() {
    // Ethernet + IPv4 + TCP + SSH binary packet
    let mut data = Vec::new();
    // Ethernet header (14 bytes)
    data.extend_from_slice(&[0xff; 6]);
    data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    data.extend_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes)
    data.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
        192, 168, 1, 2,
    ]);

    // TCP header (20 bytes) - destination port 22
    data.extend_from_slice(&[
        0xC0, 0x00, // sport = 49152
        0x00, 0x16, // dport = 22
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xFF, 0xFF, 0x00, 0x00, 0x00,
        0x00,
    ]);

    // SSH binary packet: KEXINIT (type 20)
    let mut ssh_data = vec![0u8; 28];
    ssh_data[0..4].copy_from_slice(&24u32.to_be_bytes()); // packet_length = 24
    ssh_data[4] = 8; // padding_length = 8
    ssh_data[5] = 20; // message_type = KEXINIT
    data.extend_from_slice(&ssh_data);

    // Fix IP total length
    let ip_total_len = (data.len() - 14) as u16;
    data[16] = (ip_total_len >> 8) as u8;
    data[17] = (ip_total_len & 0xFF) as u8;

    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    assert!(pkt.get_layer(LayerKind::Ssh).is_some());

    let layers = pkt.layer_enums();
    let ssh = layers.iter().find(|l| l.kind() == LayerKind::Ssh).unwrap();
    let summary = ssh.summary(pkt.as_bytes());
    assert!(summary.contains("KEXINIT"));
}

#[test]
fn test_ssh_builder_version_exchange() {
    let builder = SshBuilder::version_exchange("OpenSSH_9.2p1");
    let bytes = builder.build();
    assert_eq!(bytes, b"SSH-2.0-OpenSSH_9.2p1\r\n");
}

#[test]
fn test_ssh_builder_default() {
    let builder = SshBuilder::new();
    let bytes = builder.build();
    assert!(bytes.starts_with(b"SSH-2.0-"));
    assert!(bytes.ends_with(b"\r\n"));
}

#[test]
fn test_ssh_layer_kind_name() {
    assert_eq!(LayerKind::Ssh.name(), "SSH");
}

#[test]
fn test_ssh_pcap_parse() {
    // Read the sample SSH pcap file
    let packets = stackforge_core::rdpcap("tests/sample_pcap/ssh_ed25519.pcap").unwrap();
    assert!(!packets.is_empty(), "pcap should have packets");

    // Check that some packets have SSH layers
    let mut found_ssh = false;
    for cap in &packets {
        let mut pkt = cap.packet.clone();
        pkt.parse().unwrap();
        if pkt.get_layer(LayerKind::Ssh).is_some() {
            found_ssh = true;
            break;
        }
    }
    assert!(found_ssh, "should find at least one SSH packet in the pcap");
}

#[test]
fn test_ssh_pcap_version_exchange() {
    let packets = stackforge_core::rdpcap("tests/sample_pcap/ssh_ed25519.pcap").unwrap();

    // Find SSH version exchange packets
    let mut found_version = false;
    for cap in &packets {
        let mut pkt = cap.packet.clone();
        pkt.parse().unwrap();
        if let Some(_ssh_idx) = pkt.get_layer(LayerKind::Ssh) {
            let layers = pkt.layer_enums();
            let ssh = layers.iter().find(|l| l.kind() == LayerKind::Ssh).unwrap();
            let summary = ssh.summary(pkt.as_bytes());
            if summary.contains("Version Exchange") {
                found_version = true;
                assert!(
                    summary.contains("SSH-2.0"),
                    "version exchange should contain SSH-2.0"
                );
                break;
            }
        }
    }
    assert!(
        found_version,
        "should find SSH version exchange in the pcap"
    );
}

#[test]
fn test_ssh_show_fields() {
    let packets = stackforge_core::rdpcap("tests/sample_pcap/ssh_ed25519.pcap").unwrap();

    for cap in &packets {
        let mut pkt = cap.packet.clone();
        pkt.parse().unwrap();
        if pkt.get_layer(LayerKind::Ssh).is_some() {
            let layers = pkt.layer_enums();
            let ssh = layers.iter().find(|l| l.kind() == LayerKind::Ssh).unwrap();
            let fields = ssh.show_fields(pkt.as_bytes());
            assert!(!fields.is_empty(), "SSH layer should have show fields");
            break;
        }
    }
}
