//! Zero-copy memory-mapped PCAP reader.
//!
//! Maps the entire PCAP file into the process address space and yields packets
//! as `Bytes` slices into the mapped region — no per-packet heap allocation.
//!
//! Falls back gracefully: if the file is PcapNG, callers should use
//! [`super::CaptureIterator`] instead.

use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use memmap2::Mmap;

use crate::error::{PacketError, Result};
use crate::packet::Packet;

use super::{CapturedPacket, LinkType, PcapMetadata};

/// PCAP global header size in bytes.
const PCAP_GLOBAL_HEADER_LEN: usize = 24;

/// PCAP per-packet record header size in bytes.
const PCAP_RECORD_HEADER_LEN: usize = 16;

/// PCAP magic numbers.
const MAGIC_USEC: u32 = 0xA1B2_C3D4;
const MAGIC_NSEC: u32 = 0xA1B2_3C4D;
const MAGIC_PCAPNG: u32 = 0x0A0D_0D0A;

/// Endianness and timestamp resolution detected from magic bytes.
#[derive(Debug, Clone, Copy)]
enum PcapEndian {
    LittleUsec,
    BigUsec,
    LittleNsec,
    BigNsec,
}

/// Zero-copy memory-mapped PCAP file reader.
///
/// The entire file is mapped into virtual memory via `mmap(2)`. Each packet
/// returned by the iterator holds a `Bytes` slice directly into the mapped
/// region — no data is copied. The OS page cache handles physical I/O
/// transparently, making repeated reads (e.g. ML training epochs) essentially
/// free after the first pass.
///
/// # Supported formats
///
/// Only classic PCAP (`.pcap`) is supported. PcapNG files are detected and
/// rejected with a descriptive error so callers can fall back to the streaming
/// [`super::CaptureIterator`].
///
/// # Safety
///
/// The file must not be modified or truncated by another process while the
/// reader is alive. This is the standard assumption for `mmap`-based readers.
#[derive(Debug)]
pub struct MmapPcapReader {
    /// The entire file as a single `Bytes`, backed by the memory map.
    data: Bytes,
    /// Current byte offset into the file.
    offset: usize,
    /// Detected endianness and timestamp resolution.
    endian: PcapEndian,
    /// Link-layer type from the global header.
    link_type: LinkType,
}

impl MmapPcapReader {
    /// Open a classic PCAP file with memory-mapped I/O.
    ///
    /// Returns an error if the file is PcapNG (use the streaming reader) or
    /// has an unrecognised magic number.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .map_err(|e| PacketError::Io(format!("failed to open {}: {e}", path.display())))?;

        // SAFETY: the file is opened read-only and we assume no external
        // modification while the reader is alive.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| PacketError::Io(format!("failed to mmap {}: {e}", path.display())))?;

        Self::from_mmap(mmap)
    }

    /// Create a reader from a pre-existing `Mmap`.
    fn from_mmap(mmap: Mmap) -> Result<Self> {
        let raw = &mmap[..];
        if raw.len() < PCAP_GLOBAL_HEADER_LEN {
            return Err(PacketError::Io(
                "file too small for PCAP global header".into(),
            ));
        }

        let magic_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let magic_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);

        let endian = if magic_le == MAGIC_USEC {
            PcapEndian::LittleUsec
        } else if magic_be == MAGIC_USEC {
            PcapEndian::BigUsec
        } else if magic_le == MAGIC_NSEC {
            PcapEndian::LittleNsec
        } else if magic_be == MAGIC_NSEC {
            PcapEndian::BigNsec
        } else if magic_le == MAGIC_PCAPNG || magic_be == MAGIC_PCAPNG {
            return Err(PacketError::Io(
                "file is PcapNG format; use the streaming CaptureIterator instead".into(),
            ));
        } else {
            return Err(PacketError::Io(format!(
                "unknown PCAP magic: {:02X}{:02X}{:02X}{:02X}",
                raw[0], raw[1], raw[2], raw[3],
            )));
        };

        // Network (link type) field is at global header offset 20.
        let network = read_u32_endian(raw, 20, endian);

        // Transfer ownership of the mmap into a Bytes so `.slice()` calls are
        // zero-copy reference-counted views.
        let data = Bytes::from_owner(mmap);

        Ok(Self {
            data,
            offset: PCAP_GLOBAL_HEADER_LEN,
            endian,
            link_type: LinkType(network),
        })
    }

    /// Returns the link-layer type from the PCAP global header.
    #[inline]
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Returns the total file size in bytes.
    #[inline]
    pub fn file_len(&self) -> usize {
        self.data.len()
    }
}

/// Read a `u32` at `offset` in `buf` using the given endianness.
#[inline]
fn read_u32_endian(buf: &[u8], offset: usize, endian: PcapEndian) -> u32 {
    let b = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    match endian {
        PcapEndian::LittleUsec | PcapEndian::LittleNsec => u32::from_le_bytes(b),
        PcapEndian::BigUsec | PcapEndian::BigNsec => u32::from_be_bytes(b),
    }
}

impl Iterator for MmapPcapReader {
    type Item = Result<CapturedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.data.len().saturating_sub(self.offset);
        if remaining < PCAP_RECORD_HEADER_LEN {
            return None;
        }

        // Parse the 16-byte record header.
        let ts_sec = read_u32_endian(&self.data, self.offset, self.endian);
        let ts_frac = read_u32_endian(&self.data, self.offset + 4, self.endian);
        let incl_len = read_u32_endian(&self.data, self.offset + 8, self.endian) as usize;
        let orig_len = read_u32_endian(&self.data, self.offset + 12, self.endian);

        let data_start = self.offset + PCAP_RECORD_HEADER_LEN;
        let data_end = data_start + incl_len;

        if data_end > self.data.len() {
            return Some(Err(PacketError::Io(format!(
                "PCAP record at offset {} claims {incl_len} bytes but only {} remain",
                self.offset,
                self.data.len() - data_start,
            ))));
        }

        // Zero-copy slice — just a ref-count increment, no memcpy.
        let pkt_bytes = self.data.slice(data_start..data_end);
        let mut pkt = Packet::from_bytes(pkt_bytes);
        let _ = pkt.parse();

        let timestamp = match self.endian {
            PcapEndian::LittleUsec | PcapEndian::BigUsec => {
                Duration::new(u64::from(ts_sec), ts_frac.saturating_mul(1_000))
            },
            PcapEndian::LittleNsec | PcapEndian::BigNsec => {
                Duration::new(u64::from(ts_sec), ts_frac)
            },
        };

        self.offset = data_end;

        Some(Ok(CapturedPacket {
            packet: pkt,
            metadata: PcapMetadata {
                timestamp,
                orig_len,
                interface_id: None,
                comment: None,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    fn sample_ethernet_packet() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // EtherType: IPv4
            0x00, 0x00, 0x00, 0x00, // dummy payload
        ]
    }

    fn write_pcap_to_vec(packets: &[(Duration, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let header = PcapHeader::default();
        let mut writer = PcapWriter::with_header(Cursor::new(&mut buf), header).unwrap();
        for (ts, data) in packets {
            let pkt = PcapPacket::new(*ts, data.len() as u32, data);
            writer.write_packet(&pkt).unwrap();
        }
        drop(writer);
        buf
    }

    #[test]
    fn test_mmap_reader_basic() {
        let eth = sample_ethernet_packet();
        let pcap_data = write_pcap_to_vec(&[
            (Duration::from_secs(1), &eth),
            (Duration::from_secs(2), &eth),
            (Duration::from_secs(3), &eth),
        ]);

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("test.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        let reader = MmapPcapReader::open(&path).unwrap();
        assert_eq!(reader.link_type(), LinkType::ETHERNET);

        let packets: Vec<_> = reader.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].metadata.timestamp, Duration::from_secs(1));
        assert_eq!(packets[1].metadata.timestamp, Duration::from_secs(2));
        assert_eq!(packets[2].metadata.timestamp, Duration::from_secs(3));
    }

    #[test]
    fn test_mmap_reader_empty() {
        let pcap_data = write_pcap_to_vec(&[]);
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("empty.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        let reader = MmapPcapReader::open(&path).unwrap();
        let packets: Vec<_> = reader.collect::<std::result::Result<Vec<_>, _>>().unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn test_mmap_reader_packet_data_matches_streaming() {
        let eth = sample_ethernet_packet();
        let pcap_data = write_pcap_to_vec(&[(Duration::from_secs(42), &eth)]);

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("cmp.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        // Read with mmap
        let mmap_pkts: Vec<_> = MmapPcapReader::open(&path)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        // Read with streaming
        let stream_pkts: Vec<_> = super::super::reader::rdpcap(&path).unwrap();

        assert_eq!(mmap_pkts.len(), stream_pkts.len());
        assert_eq!(
            mmap_pkts[0].packet.as_bytes(),
            stream_pkts[0].packet.as_bytes()
        );
        assert_eq!(
            mmap_pkts[0].metadata.timestamp,
            stream_pkts[0].metadata.timestamp
        );
        assert_eq!(
            mmap_pkts[0].metadata.orig_len,
            stream_pkts[0].metadata.orig_len
        );
    }

    #[test]
    fn test_mmap_reader_rejects_pcapng() {
        // PcapNG starts with Section Header Block magic: 0x0A0D0D0A
        let mut pcapng_data = vec![0x0A, 0x0D, 0x0D, 0x0A];
        pcapng_data.extend_from_slice(&[0u8; 24]); // pad to min size

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("test.pcapng");
        std::fs::write(&path, &pcapng_data).unwrap();

        let err = MmapPcapReader::open(&path).unwrap_err();
        assert!(format!("{err}").contains("PcapNG"));
    }

    #[test]
    fn test_mmap_reader_zero_copy_shares_buffer() {
        let eth = sample_ethernet_packet();
        let pcap_data = write_pcap_to_vec(&[
            (Duration::from_secs(1), &eth),
            (Duration::from_secs(2), &eth),
        ]);

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("zerocopy.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        let reader = MmapPcapReader::open(&path).unwrap();
        let packets: Vec<_> = reader.collect::<std::result::Result<Vec<_>, _>>().unwrap();

        // Both packets should reference the same underlying allocation
        // (the mmap). We verify by checking that the data pointers fall
        // within a contiguous region.
        let p0_ptr = packets[0].packet.as_bytes().as_ptr() as usize;
        let p1_ptr = packets[1].packet.as_bytes().as_ptr() as usize;
        // Second packet's data should be at a higher address within the same mapping.
        assert!(p1_ptr > p0_ptr);
        // And the gap should be small (just a record header between them).
        let gap = p1_ptr - p0_ptr;
        assert!(gap < eth.len() + PCAP_RECORD_HEADER_LEN + 64);
    }

    #[test]
    fn test_mmap_reader_metadata() {
        let eth = sample_ethernet_packet();
        let pcap_data = write_pcap_to_vec(&[(Duration::from_millis(1500), &eth)]);

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("meta.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        let packets: Vec<_> = MmapPcapReader::open(&path)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].metadata.orig_len, eth.len() as u32);
        assert_eq!(packets[0].packet.len(), eth.len());
        assert!(packets[0].metadata.interface_id.is_none());
    }

    #[test]
    fn test_mmap_reader_parsed() {
        let eth = sample_ethernet_packet();
        let pcap_data = write_pcap_to_vec(&[(Duration::from_secs(1), &eth)]);

        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("parsed.pcap");
        std::fs::write(&path, &pcap_data).unwrap();

        let packets: Vec<_> = MmapPcapReader::open(&path)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        // Packets should be pre-parsed (layers identified).
        assert!(packets[0].packet.is_parsed());
        assert!(packets[0].packet.layer_count() > 0);
    }
}
