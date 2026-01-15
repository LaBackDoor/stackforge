use stackforge_core::{hexdump, hexstr, internet_checksum};

#[test]
fn test_hexdump_output() {
    let data = b"Hello, World!";
    let dump = hexdump(data);

    assert!(dump.contains("48 65 6c 6c")); // "Hell" in hex
    assert!(dump.contains("|Hello, World!|"));
}

#[test]
fn test_hexstr() {
    let data = [0xde, 0xad, 0xbe, 0xef];
    assert_eq!(hexstr(&data), "deadbeef");
}

#[test]
fn test_checksum() {
    // Known good IP header
    let header = [
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00,
        0x00, // checksum field = 0
        0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
    ];

    let checksum = internet_checksum(&header);
    // Checksum should be non-zero for this data
    assert_ne!(checksum, 0);
}
