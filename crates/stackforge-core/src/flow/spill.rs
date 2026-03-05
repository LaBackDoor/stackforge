//! Disk spill manager for memory-budgeted flow extraction.
//!
//! Provides `ReassemblyStorage` for data that can be transparently spilled to
//! mmap'd temp files when RAM budget is exceeded, and `MemoryTracker` for
//! global memory accounting.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use memmap2::Mmap;
use tempfile::NamedTempFile;

/// A handle to reassembly data that may be in memory or on disk.
///
/// When in memory, behaves like a `Vec<u8>`. When spilled, data lives in a
/// temporary file and is read back via `mmap` on demand. The temp file is
/// auto-deleted when this value is dropped.
#[derive(Debug)]
pub enum ReassemblyStorage {
    /// Data held in memory.
    InMemory(Vec<u8>),
    /// Data flushed to a memory-mapped temporary file.
    OnDisk { file: NamedTempFile, len: usize },
}

impl ReassemblyStorage {
    /// Create new empty in-memory storage.
    pub fn new() -> Self {
        Self::InMemory(Vec::new())
    }

    /// Current byte length of stored data.
    pub fn len(&self) -> usize {
        match self {
            Self::InMemory(v) => v.len(),
            Self::OnDisk { len, .. } => *len,
        }
    }

    /// Whether storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append data. Only valid when `InMemory`.
    ///
    /// # Panics
    /// Panics if storage has been spilled to disk. Callers must ensure data
    /// is not appended after a spill (in practice, spilling only happens
    /// for completed/idle flows).
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        match self {
            Self::InMemory(v) => v.extend_from_slice(data),
            Self::OnDisk { .. } => {
                panic!("cannot extend spilled storage; data already on disk");
            },
        }
    }

    /// Spill in-memory data to disk, returning the number of bytes freed.
    ///
    /// If already on disk or empty, returns 0.
    pub fn spill_to_disk(&mut self, spill_dir: Option<&Path>) -> std::io::Result<usize> {
        let old = std::mem::replace(self, Self::InMemory(Vec::new()));
        match old {
            Self::InMemory(data) => {
                if data.is_empty() {
                    *self = Self::InMemory(data);
                    return Ok(0);
                }
                let freed = data.len();
                let mut tmpfile = match spill_dir {
                    Some(dir) => NamedTempFile::new_in(dir)?,
                    None => NamedTempFile::new()?,
                };
                tmpfile.write_all(&data)?;
                tmpfile.flush()?;
                *self = Self::OnDisk {
                    file: tmpfile,
                    len: freed,
                };
                Ok(freed)
            },
            already_on_disk @ Self::OnDisk { .. } => {
                *self = already_on_disk;
                Ok(0)
            },
        }
    }

    /// Read all data back. Works for both in-memory and on-disk storage.
    pub fn read_all(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::InMemory(v) => Ok(v.clone()),
            Self::OnDisk { file, len } => {
                if *len == 0 {
                    return Ok(Vec::new());
                }
                // Safety: the file is exclusively ours (NamedTempFile), and we
                // only read from it after flushing. The mmap is short-lived.
                let mmap = unsafe { Mmap::map(file.as_file())? };
                Ok(mmap[..*len].to_vec())
            },
        }
    }

    /// Get a reference to in-memory data. Returns `None` if spilled.
    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            Self::InMemory(v) => Some(v),
            Self::OnDisk { .. } => None,
        }
    }

    /// Whether data is currently on disk.
    pub fn is_spilled(&self) -> bool {
        matches!(self, Self::OnDisk { .. })
    }

    /// Bytes currently held in memory (0 if spilled).
    pub fn in_memory_bytes(&self) -> usize {
        match self {
            Self::InMemory(v) => v.len(),
            Self::OnDisk { .. } => 0,
        }
    }

    /// Drain and return data, resetting to empty. Reads from disk if spilled.
    pub fn drain(&mut self) -> std::io::Result<Vec<u8>> {
        let data = self.read_all()?;
        *self = Self::InMemory(Vec::new());
        Ok(data)
    }
}

impl Default for ReassemblyStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Global memory tracker for the flow extraction engine.
///
/// Uses atomic operations for thread-safe accounting without locks.
#[derive(Debug)]
pub struct MemoryTracker {
    /// Current estimated memory usage in bytes.
    current: AtomicUsize,
    /// Budget limit (None = unlimited).
    budget: Option<usize>,
}

impl MemoryTracker {
    /// Create a new tracker with an optional budget.
    pub fn new(budget: Option<usize>) -> Self {
        Self {
            current: AtomicUsize::new(0),
            budget,
        }
    }

    /// Record newly allocated bytes.
    pub fn add(&self, bytes: usize) {
        self.current.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record freed bytes.
    pub fn subtract(&self, bytes: usize) {
        self.current.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Current estimated memory usage.
    pub fn current_usage(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    /// Whether current usage exceeds the budget.
    pub fn is_over_budget(&self) -> bool {
        match self.budget {
            Some(b) => self.current_usage() > b,
            None => false,
        }
    }

    /// Whether a budget has been set.
    pub fn has_budget(&self) -> bool {
        self.budget.is_some()
    }

    /// The configured budget, if any.
    pub fn budget(&self) -> Option<usize> {
        self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reassembly_storage_in_memory() {
        let mut s = ReassemblyStorage::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.is_spilled());

        s.extend_from_slice(b"hello");
        assert_eq!(s.len(), 5);
        assert_eq!(s.as_slice(), Some(b"hello".as_slice()));
        assert_eq!(s.in_memory_bytes(), 5);

        let data = s.read_all().unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_reassembly_storage_spill_and_read() {
        let mut s = ReassemblyStorage::new();
        s.extend_from_slice(b"test data for spill");

        let freed = s.spill_to_disk(None).unwrap();
        assert_eq!(freed, 19);
        assert!(s.is_spilled());
        assert_eq!(s.len(), 19);
        assert_eq!(s.in_memory_bytes(), 0);
        assert!(s.as_slice().is_none());

        let data = s.read_all().unwrap();
        assert_eq!(data, b"test data for spill");
    }

    #[test]
    fn test_reassembly_storage_spill_empty() {
        let mut s = ReassemblyStorage::new();
        let freed = s.spill_to_disk(None).unwrap();
        assert_eq!(freed, 0);
        assert!(!s.is_spilled());
    }

    #[test]
    fn test_reassembly_storage_double_spill() {
        let mut s = ReassemblyStorage::new();
        s.extend_from_slice(b"data");
        s.spill_to_disk(None).unwrap();

        // Second spill should be a no-op
        let freed = s.spill_to_disk(None).unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn test_reassembly_storage_drain() {
        let mut s = ReassemblyStorage::new();
        s.extend_from_slice(b"drain me");
        let data = s.drain().unwrap();
        assert_eq!(data, b"drain me");
        assert!(s.is_empty());
    }

    #[test]
    fn test_reassembly_storage_drain_spilled() {
        let mut s = ReassemblyStorage::new();
        s.extend_from_slice(b"spilled drain");
        s.spill_to_disk(None).unwrap();
        let data = s.drain().unwrap();
        assert_eq!(data, b"spilled drain");
        assert!(s.is_empty());
        assert!(!s.is_spilled());
    }

    #[test]
    fn test_memory_tracker_no_budget() {
        let tracker = MemoryTracker::new(None);
        assert!(!tracker.has_budget());
        tracker.add(1_000_000);
        assert!(!tracker.is_over_budget());
    }

    #[test]
    fn test_memory_tracker_with_budget() {
        let tracker = MemoryTracker::new(Some(1000));
        assert!(tracker.has_budget());
        assert_eq!(tracker.budget(), Some(1000));

        tracker.add(500);
        assert_eq!(tracker.current_usage(), 500);
        assert!(!tracker.is_over_budget());

        tracker.add(600);
        assert_eq!(tracker.current_usage(), 1100);
        assert!(tracker.is_over_budget());

        tracker.subtract(200);
        assert_eq!(tracker.current_usage(), 900);
        assert!(!tracker.is_over_budget());
    }
}
