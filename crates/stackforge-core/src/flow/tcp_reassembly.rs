use std::collections::BTreeMap;
use std::path::Path;

use super::config::FlowConfig;
use super::error::FlowError;
use super::spill::ReassemblyStorage;

/// Result of processing a TCP segment through the reassembly engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyAction {
    /// Segment was in-order and appended; value is bytes added to reassembled buffer.
    DataReady(usize),
    /// Segment was out-of-order and cached in the `BTreeMap`.
    Buffered,
    /// Segment was a total duplicate (already fully received).
    Duplicate,
    /// Segment had partial overlap; value is the trimmed bytes appended.
    OverlapTrimmed(usize),
    /// No payload in this segment.
    Empty,
}

/// TCP stream reassembly engine using a `BTreeMap` for out-of-order segment management.
///
/// Mirrors Wireshark's reassemble.c logic: segments are keyed by absolute TCP
/// sequence number. In-order segments are immediately appended to the contiguous
/// reassembled buffer, while out-of-order segments are cached until gaps are filled.
#[derive(Debug)]
pub struct TcpReassembler {
    /// Out-of-order segment cache: sequence number → payload.
    segments: BTreeMap<u32, Vec<u8>>,
    /// Next expected sequence number (advanced as data arrives in-order).
    next_expected_seq: u32,
    /// Contiguous reassembled byte stream (may be in memory or on disk).
    reassembled: ReassemblyStorage,
    /// Total bytes currently buffered in out-of-order cache.
    total_buffered: usize,
    /// Number of distinct out-of-order fragments.
    fragment_count: usize,
    /// Whether the reassembler has been initialized with an ISN.
    initialized: bool,
}

impl TcpReassembler {
    /// Create a new uninitialized reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            next_expected_seq: 0,
            reassembled: ReassemblyStorage::new(),
            total_buffered: 0,
            fragment_count: 0,
            initialized: false,
        }
    }

    /// Initialize with the first observed sequence number (ISN + 1 for data after SYN).
    pub fn initialize(&mut self, initial_seq: u32) {
        self.next_expected_seq = initial_seq;
        self.initialized = true;
    }

    /// Whether this reassembler has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the contiguous reassembled data if it's in memory.
    ///
    /// Returns `None` if the data has been spilled to disk.
    /// Use [`read_reassembled`] for guaranteed access regardless of storage location.
    #[must_use]
    pub fn reassembled_data(&self) -> &[u8] {
        self.reassembled.as_slice().unwrap_or(&[])
    }

    /// Read the reassembled data regardless of storage location.
    ///
    /// Works for both in-memory and spilled-to-disk data.
    pub fn read_reassembled(&self) -> std::io::Result<Vec<u8>> {
        self.reassembled.read_all()
    }

    /// Drain and return the reassembled data, resetting the buffer.
    pub fn drain_reassembled(&mut self) -> std::io::Result<Vec<u8>> {
        self.reassembled.drain()
    }

    /// Total bytes in the out-of-order buffer.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.total_buffered
    }

    /// Number of out-of-order fragments.
    #[must_use]
    pub fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Total bytes currently held in memory (reassembled + OOO segments).
    #[must_use]
    pub fn in_memory_bytes(&self) -> usize {
        self.reassembled.in_memory_bytes() + self.total_buffered
    }

    /// Spill reassembled data to a temporary file on disk.
    ///
    /// Returns the number of bytes freed from memory.
    pub fn spill(&mut self, spill_dir: Option<&Path>) -> std::io::Result<usize> {
        self.reassembled.spill_to_disk(spill_dir)
    }

    /// Whether the reassembled data has been spilled to disk.
    #[must_use]
    pub fn is_spilled(&self) -> bool {
        self.reassembled.is_spilled()
    }

    /// Process an incoming TCP segment.
    ///
    /// Handles in-order, out-of-order, overlapping, and duplicate segments
    /// according to the algorithm described in the architectural blueprint.
    pub fn process_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        config: &FlowConfig,
    ) -> Result<ReassemblyAction, FlowError> {
        if payload.is_empty() {
            return Ok(ReassemblyAction::Empty);
        }

        // Auto-initialize on first data segment if not yet initialized
        if !self.initialized {
            self.initialize(seq);
        }

        let seg_end = seq.wrapping_add(payload.len() as u32);

        // Case 1: Total duplicate — segment is entirely before next_expected_seq
        if self.seq_before_or_equal(seg_end, self.next_expected_seq) {
            return Ok(ReassemblyAction::Duplicate);
        }

        // Case 2: Partial overlap — segment starts before next_expected_seq
        // but extends beyond it
        if self.seq_before(seq, self.next_expected_seq) {
            let overlap = self.next_expected_seq.wrapping_sub(seq) as usize;
            if overlap >= payload.len() {
                return Ok(ReassemblyAction::Duplicate);
            }
            let trimmed = &payload[overlap..];
            self.reassembled.extend_from_slice(trimmed);
            self.next_expected_seq = self.next_expected_seq.wrapping_add(trimmed.len() as u32);
            self.try_drain_buffered();
            return Ok(ReassemblyAction::OverlapTrimmed(trimmed.len()));
        }

        // Case 3: In-order arrival — seq == next_expected_seq
        if seq == self.next_expected_seq {
            self.reassembled.extend_from_slice(payload);
            self.next_expected_seq = self.next_expected_seq.wrapping_add(payload.len() as u32);
            self.try_drain_buffered();
            return Ok(ReassemblyAction::DataReady(payload.len()));
        }

        // Case 4: Out-of-order — seq > next_expected_seq (gap exists)
        // Check limits before buffering
        if self.fragment_count >= config.max_ooo_fragments {
            return Err(FlowError::TooManyFragments {
                count: self.fragment_count,
                limit: config.max_ooo_fragments,
            });
        }
        if self.total_buffered + payload.len() > config.max_reassembly_buffer {
            return Err(FlowError::ReassemblyBufferFull {
                limit: config.max_reassembly_buffer,
            });
        }

        self.segments.insert(seq, payload.to_vec());
        self.total_buffered += payload.len();
        self.fragment_count += 1;
        Ok(ReassemblyAction::Buffered)
    }

    /// Drain contiguous segments from the `BTreeMap` that can now be appended.
    fn try_drain_buffered(&mut self) {
        loop {
            let key = {
                let entry = self.segments.range(..=self.next_expected_seq).next_back();
                match entry {
                    Some((&k, _)) => k,
                    None => break,
                }
            };

            if let Some(data) = self.segments.remove(&key) {
                let seg_end = key.wrapping_add(data.len() as u32);

                self.total_buffered -= data.len();
                self.fragment_count -= 1;

                if self.seq_after(seg_end, self.next_expected_seq) {
                    if self.seq_before(key, self.next_expected_seq) {
                        let overlap = self.next_expected_seq.wrapping_sub(key) as usize;
                        if overlap < data.len() {
                            self.reassembled.extend_from_slice(&data[overlap..]);
                            self.next_expected_seq = seg_end;
                        }
                    } else {
                        self.reassembled.extend_from_slice(&data);
                        self.next_expected_seq = seg_end;
                    }
                }
            }
        }
    }

    /// Check if `a` is strictly before `b` in the sequence space (handles wrapping).
    fn seq_before(&self, a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }

    /// Check if `a` is before or equal to `b` in the sequence space.
    fn seq_before_or_equal(&self, a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) <= 0
    }

    /// Check if `a` is strictly after `b` in the sequence space.
    fn seq_after(&self, a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) > 0
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> FlowConfig {
        FlowConfig::default()
    }

    #[test]
    fn test_in_order_reassembly() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(1000);

        let action = r.process_segment(1000, b"hello", &config).unwrap();
        assert_eq!(action, ReassemblyAction::DataReady(5));
        assert_eq!(r.reassembled_data(), b"hello");
        assert_eq!(r.next_expected_seq, 1005);

        let action = r.process_segment(1005, b" world", &config).unwrap();
        assert_eq!(action, ReassemblyAction::DataReady(6));
        assert_eq!(r.reassembled_data(), b"hello world");
    }

    #[test]
    fn test_out_of_order_then_fill_gap() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(1000);

        let action = r.process_segment(1005, b" world", &config).unwrap();
        assert_eq!(action, ReassemblyAction::Buffered);
        assert_eq!(r.fragment_count(), 1);

        let action = r.process_segment(1000, b"hello", &config).unwrap();
        assert_eq!(action, ReassemblyAction::DataReady(5));
        assert_eq!(r.reassembled_data(), b"hello world");
        assert_eq!(r.fragment_count(), 0);
    }

    #[test]
    fn test_total_duplicate() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(1000);

        r.process_segment(1000, b"hello", &config).unwrap();
        let action = r.process_segment(1000, b"hello", &config).unwrap();
        assert_eq!(action, ReassemblyAction::Duplicate);
        assert_eq!(r.reassembled_data(), b"hello");
    }

    #[test]
    fn test_partial_overlap() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(1000);

        r.process_segment(1000, b"hello", &config).unwrap();
        let action = r.process_segment(1003, b"lo wo", &config).unwrap();
        assert_eq!(action, ReassemblyAction::OverlapTrimmed(3));
        assert_eq!(r.reassembled_data(), b"hello wo");
    }

    #[test]
    fn test_empty_payload() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(1000);

        let action = r.process_segment(1000, b"", &config).unwrap();
        assert_eq!(action, ReassemblyAction::Empty);
    }

    #[test]
    fn test_fragment_limit() {
        let mut config = default_config();
        config.max_ooo_fragments = 2;

        let mut r = TcpReassembler::new();
        r.initialize(1000);

        r.process_segment(1010, b"a", &config).unwrap();
        r.process_segment(1020, b"b", &config).unwrap();
        let err = r.process_segment(1030, b"c", &config);
        assert!(matches!(err, Err(FlowError::TooManyFragments { .. })));
    }

    #[test]
    fn test_buffer_size_limit() {
        let mut config = default_config();
        config.max_reassembly_buffer = 10;

        let mut r = TcpReassembler::new();
        r.initialize(1000);

        r.process_segment(1010, b"12345", &config).unwrap();
        let err = r.process_segment(1020, b"123456", &config);
        assert!(matches!(err, Err(FlowError::ReassemblyBufferFull { .. })));
    }

    #[test]
    fn test_multiple_ooo_segments_drain() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(100);

        r.process_segment(110, b"ccc", &config).unwrap();
        r.process_segment(105, b"bbbbb", &config).unwrap();
        assert_eq!(r.fragment_count(), 2);

        r.process_segment(100, b"aaaaa", &config).unwrap();
        assert_eq!(r.reassembled_data(), b"aaaaabbbbbccc");
        assert_eq!(r.fragment_count(), 0);
    }

    #[test]
    fn test_auto_initialize() {
        let config = default_config();
        let mut r = TcpReassembler::new();

        let action = r.process_segment(5000, b"data", &config).unwrap();
        assert_eq!(action, ReassemblyAction::DataReady(4));
        assert!(r.is_initialized());
        assert_eq!(r.reassembled_data(), b"data");
    }

    #[test]
    fn test_drain_reassembled() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(0);

        r.process_segment(0, b"hello", &config).unwrap();
        let data = r.drain_reassembled().unwrap();
        assert_eq!(data, b"hello");
        assert!(r.reassembled_data().is_empty());
    }

    #[test]
    fn test_spill_and_read() {
        let config = default_config();
        let mut r = TcpReassembler::new();
        r.initialize(0);

        r.process_segment(0, b"spill test data", &config).unwrap();
        assert_eq!(r.in_memory_bytes(), 15);

        let freed = r.spill(None).unwrap();
        assert_eq!(freed, 15);
        assert!(r.is_spilled());
        assert_eq!(r.in_memory_bytes(), 0);

        let data = r.read_reassembled().unwrap();
        assert_eq!(data, b"spill test data");
    }
}
