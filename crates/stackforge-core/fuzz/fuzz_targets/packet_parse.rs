#![no_main]
use libfuzzer_sys::fuzz_target;
use stackforge_core::packet::Packet;

fuzz_target!(|data: &[u8]| {
    // Main entry point: parse arbitrary bytes as an Ethernet packet.
    // This exercises every protocol parser reachable from Packet::parse().
    let mut pkt = Packet::from_bytes(data.to_vec());
    let _ = pkt.parse();

    // If parsing succeeded, exercise layer access to catch panics in
    // field-reading code.
    if pkt.is_parsed() {
        for layer in pkt.layers() {
            let _ = pkt.layer_bytes(layer.kind);
        }
        let _ = pkt.payload();
    }
});
