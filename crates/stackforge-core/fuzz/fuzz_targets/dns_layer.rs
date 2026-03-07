#![no_main]
use libfuzzer_sys::fuzz_target;
use stackforge_core::layer::Layer;
use stackforge_core::layer::dns::DnsLayer;
use stackforge_core::layer::dns::query::DnsQuestion;
use stackforge_core::layer::dns::rr::DnsResourceRecord;
use stackforge_core::layer::field_ext::DnsName;

fuzz_target!(|data: &[u8]| {
    // Fuzz DNS name decompression — a classic source of infinite loops and
    // out-of-bounds reads when pointer chains are malformed.
    let _ = DnsName::decode(data, 0);

    // Fuzz question parsing
    let _ = DnsQuestion::parse(data, 0);

    // Fuzz resource-record parsing (walks name + rdata)
    let _ = DnsResourceRecord::parse(data, 0);

    // Fuzz the full DNS layer field accessors.
    // Simulate a DNS layer that spans the entire buffer.
    if data.len() >= 12 {
        let dns = DnsLayer::new(0, data.len());
        let _ = dns.questions(data);
        let _ = dns.answers_rr(data);
        let _ = dns.authorities(data);
        let _ = dns.additionals(data);
        let _ = dns.summary(data);
    }
});
