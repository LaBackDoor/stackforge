use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use stackforge_core::packet::Packet;

/// Generate N synthetic TCP packets for throughput testing.
fn generate_tcp_batch(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let src_port = ((i % 65000) + 1024) as u16;
            let s = src_port.to_be_bytes();
            let mut pkt = vec![
                // Ethernet (14 bytes)
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
                // IPv4 (20 bytes)
                0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
                0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // TCP (20 bytes)
                s[0], s[1], // sport (varies)
                0x00, 0x50, // dport=80
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            // 20 bytes of payload
            pkt.extend_from_slice(&[0x41u8; 20]);
            pkt
        })
        .collect()
}

fn bench_sequential_throughput(c: &mut Criterion) {
    let batch = generate_tcp_batch(10_000);
    let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();

    let mut group = c.benchmark_group("throughput_sequential");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("10k_packets", |b| {
        b.iter(|| {
            for raw in &batch {
                let mut pkt = Packet::from_bytes(raw.clone());
                pkt.parse().unwrap();
                black_box(&pkt);
            }
        })
    });

    group.finish();
}

fn bench_parallel_throughput(c: &mut Criterion) {
    use rayon::prelude::*;

    let batch = generate_tcp_batch(10_000);
    let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();

    let mut group = c.benchmark_group("throughput_parallel");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("10k_packets_rayon", |b| {
        b.iter(|| {
            let parsed: Vec<Packet> = batch
                .par_iter()
                .map(|raw| {
                    let mut pkt = Packet::from_bytes(raw.clone());
                    let _ = pkt.parse();
                    pkt
                })
                .collect();
            black_box(&parsed);
        })
    });

    group.finish();
}

fn bench_parse_vs_clone(c: &mut Criterion) {
    let raw = generate_tcp_batch(1)[0].clone();

    let mut group = c.benchmark_group("overhead");

    group.bench_function("bytes_clone", |b| {
        let data = bytes::Bytes::from(raw.clone());
        b.iter(|| {
            black_box(data.clone());
        })
    });

    group.bench_function("packet_from_bytes", |b| {
        b.iter(|| {
            black_box(Packet::from_bytes(raw.clone()));
        })
    });

    group.bench_function("packet_from_slice", |b| {
        b.iter(|| {
            black_box(Packet::from_slice(black_box(&raw)));
        })
    });

    group.bench_function("full_parse", |b| {
        b.iter(|| {
            let mut pkt = Packet::from_bytes(raw.clone());
            pkt.parse().unwrap();
            black_box(&pkt);
        })
    });

    group.finish();
}

fn bench_mmap_vs_copy_rdpcap(c: &mut Criterion) {
    use std::io::Cursor;
    use std::time::Duration;

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    // Generate a PCAP file with 10k packets.
    let batch = generate_tcp_batch(10_000);
    let mut pcap_buf = Vec::new();
    let header = PcapHeader::default();
    let mut writer = PcapWriter::with_header(Cursor::new(&mut pcap_buf), header).unwrap();
    for (i, raw) in batch.iter().enumerate() {
        let pkt = PcapPacket::new(Duration::from_secs(i as u64), raw.len() as u32, raw);
        writer.write_packet(&pkt).unwrap();
    }
    drop(writer);

    let total_bytes = pcap_buf.len() as u64;
    let tmpdir = tempfile::tempdir().unwrap();
    let path = tmpdir.path().join("bench.pcap");
    std::fs::write(&path, &pcap_buf).unwrap();

    let mut group = c.benchmark_group("rdpcap_mmap_vs_copy");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("mmap_zero_copy", |b| {
        b.iter(|| {
            let reader = stackforge_core::MmapPcapReader::open(&path).unwrap();
            let pkts: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();
            black_box(&pkts);
        })
    });

    group.bench_function("streaming_copy", |b| {
        b.iter(|| {
            let iter = stackforge_core::CaptureIterator::open(&path).unwrap();
            let pkts: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
            black_box(&pkts);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_throughput,
    bench_parallel_throughput,
    bench_parse_vs_clone,
    bench_mmap_vs_copy_rdpcap,
);
criterion_main!(benches);
