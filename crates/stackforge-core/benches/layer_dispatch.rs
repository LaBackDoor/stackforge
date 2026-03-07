use criterion::{Criterion, black_box, criterion_group, criterion_main};
use stackforge_core::layer::{LayerIndex, LayerKind};
use stackforge_core::packet::Packet;

/// Build a TCP/HTTP packet for dispatch benchmarks.
fn tcp_packet() -> Vec<u8> {
    let mut pkt = vec![
        // Ethernet (14 bytes)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01,
        0x01, 0xc0, 0xa8, 0x01, 0x02, // TCP (20 bytes)
        0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    pkt.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    pkt
}

fn bench_layer_enum_dispatch(c: &mut Criterion) {
    let data = tcp_packet();
    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    let buf = pkt.as_bytes();
    let enums = pkt.layer_enums();

    let mut group = c.benchmark_group("layer_dispatch");

    // Benchmark kind() dispatch
    group.bench_function("kind", |b| {
        b.iter(|| {
            for le in &enums {
                black_box(le.kind());
            }
        })
    });

    // Benchmark summary() dispatch (the most expensive — allocates String)
    group.bench_function("summary", |b| {
        b.iter(|| {
            for le in &enums {
                black_box(le.summary(buf));
            }
        })
    });

    // Benchmark header_len() dispatch
    group.bench_function("header_len", |b| {
        b.iter(|| {
            for le in &enums {
                black_box(le.header_len(buf));
            }
        })
    });

    // Benchmark index() dispatch
    group.bench_function("index", |b| {
        b.iter(|| {
            for le in &enums {
                black_box(le.index());
            }
        })
    });

    // Benchmark field_names() dispatch
    group.bench_function("field_names", |b| {
        b.iter(|| {
            for le in &enums {
                black_box(le.field_names());
            }
        })
    });

    group.finish();
}

fn bench_layer_enum_construction(c: &mut Criterion) {
    let data = tcp_packet();
    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    let layers: Vec<LayerIndex> = pkt.layers().to_vec();

    c.bench_function("layer_enum_construction", |b| {
        b.iter(|| {
            for idx in &layers {
                black_box(pkt.layer_enum(idx));
            }
        })
    });
}

fn bench_get_layer_linear_search(c: &mut Criterion) {
    let data = tcp_packet();
    let mut pkt = Packet::from_bytes(data);
    pkt.parse().unwrap();

    let mut group = c.benchmark_group("get_layer");

    // Search for first layer (best case)
    group.bench_function("first_layer", |b| {
        b.iter(|| {
            black_box(pkt.get_layer(LayerKind::Ethernet));
        })
    });

    // Search for last layer (worst case for linear scan)
    group.bench_function("last_layer", |b| {
        b.iter(|| {
            black_box(pkt.get_layer(LayerKind::Http));
        })
    });

    // Search for missing layer
    group.bench_function("missing_layer", |b| {
        b.iter(|| {
            black_box(pkt.get_layer(LayerKind::Dns));
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_layer_enum_dispatch,
    bench_layer_enum_construction,
    bench_get_layer_linear_search,
);
criterion_main!(benches);
