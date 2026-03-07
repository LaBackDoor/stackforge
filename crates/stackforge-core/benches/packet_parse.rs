use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use stackforge_core::packet::Packet;

/// Minimal Ethernet + ARP packet (42 bytes).
fn arp_packet() -> Vec<u8> {
    vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
        0x08, 0x06, // type: ARP
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, // hw/proto
        0x00, 0x01, // op: request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // hwsrc
        0xc0, 0xa8, 0x01, 0x01, // psrc
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hwdst
        0xc0, 0xa8, 0x01, 0x02, // pdst
    ]
}

/// Ethernet + IPv4 + TCP + HTTP-like payload (~74 bytes).
fn tcp_packet() -> Vec<u8> {
    let mut pkt = vec![
        // Ethernet (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
        0x08, 0x00, // IPv4
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x3c, // ver/ihl/tos/total_len
        0x00, 0x01, 0x00, 0x00, // id/flags/frag
        0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP, checksum
        0xc0, 0xa8, 0x01, 0x01, // src
        0xc0, 0xa8, 0x01, 0x02, // dst
        // TCP (20 bytes)
        0x00, 0x50, 0x1f, 0x90, // sport=80, dport=8080
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0x20, 0x00, // data_offset=5, SYN, window
        0x00, 0x00, 0x00, 0x00, // checksum, urgent
    ];
    // Add some raw payload
    pkt.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    pkt
}

/// Ethernet + IPv4 + UDP + DNS (small query, ~72 bytes).
fn dns_packet() -> Vec<u8> {
    vec![
        // Ethernet (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00, // IPv4
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x3a,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // proto=UDP
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02,
        // UDP (8 bytes)
        0xd0, 0x00, 0x00, 0x35, // src=53248, dst=53 (DNS)
        0x00, 0x1e, 0x00, 0x00, // len/checksum
        // DNS header (12 bytes)
        0xab, 0xcd, // id
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // qdcount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
        // Question: example.com A
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // root
        0x00, 0x01, // A
        0x00, 0x01, // IN
    ]
}

fn bench_parse_single(c: &mut Criterion) {
    let arp = arp_packet();
    let tcp = tcp_packet();
    let dns = dns_packet();

    let mut group = c.benchmark_group("parse_single");

    group.throughput(Throughput::Bytes(arp.len() as u64));
    group.bench_function("arp", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(black_box(arp.clone()));
            pkt.parse().unwrap();
            black_box(&pkt);
        })
    });

    group.throughput(Throughput::Bytes(tcp.len() as u64));
    group.bench_function("tcp_http", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(black_box(tcp.clone()));
            pkt.parse().unwrap();
            black_box(&pkt);
        })
    });

    group.throughput(Throughput::Bytes(dns.len() as u64));
    group.bench_function("dns", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(black_box(dns.clone()));
            pkt.parse().unwrap();
            black_box(&pkt);
        })
    });

    group.finish();
}

fn bench_parse_batch(c: &mut Criterion) {
    let tcp = tcp_packet();

    let mut group = c.benchmark_group("parse_batch");
    for batch_size in [100, 1_000, 10_000] {
        let packets: Vec<Vec<u8>> = (0..batch_size).map(|_| tcp.clone()).collect();
        let total_bytes: u64 = packets.iter().map(|p| p.len() as u64).sum();

        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &packets,
            |b, pkts| {
                b.iter(|| {
                    for raw in pkts {
                        let mut pkt = Packet::from_bytes(raw.clone());
                        pkt.parse().unwrap();
                        black_box(&pkt);
                    }
                })
            },
        );
    }
    group.finish();
}

fn bench_field_access(c: &mut Criterion) {
    let tcp_data = tcp_packet();
    let mut pkt = Packet::from_bytes(tcp_data);
    pkt.parse().unwrap();

    let mut group = c.benchmark_group("field_access");

    group.bench_function("ethernet_src", |b| {
        b.iter(|| {
            let eth = pkt.ethernet().unwrap();
            black_box(eth.src(pkt.as_bytes()));
        })
    });

    group.bench_function("ipv4_src", |b| {
        b.iter(|| {
            let ip = pkt.ipv4().unwrap();
            black_box(ip.src(pkt.as_bytes()));
        })
    });

    group.bench_function("tcp_src_port", |b| {
        b.iter(|| {
            let tcp = pkt.tcp().unwrap();
            black_box(tcp.sport(pkt.as_bytes()));
        })
    });

    group.bench_function("get_layer_lookup", |b| {
        b.iter(|| {
            black_box(pkt.get_layer(stackforge_core::layer::LayerKind::Tcp));
        })
    });

    group.finish();
}

fn bench_copy_on_write(c: &mut Criterion) {
    let tcp_data = tcp_packet();

    c.bench_function("copy_on_write_unshared", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(tcp_data.clone());
            pkt.parse().unwrap();
            pkt.with_data_mut(|data| {
                data[0] = 0xff;
            });
            black_box(&pkt);
        })
    });

    c.bench_function("copy_on_write_shared", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(tcp_data.clone());
            pkt.parse().unwrap();
            let _shared = pkt.bytes(); // create a shared reference
            pkt.with_data_mut(|data| {
                data[0] = 0xff;
            });
            black_box(&pkt);
        })
    });
}

criterion_group!(
    benches,
    bench_parse_single,
    bench_parse_batch,
    bench_field_access,
    bench_copy_on_write,
);
criterion_main!(benches);
