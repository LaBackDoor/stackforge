//! Order-preserving timestamp anonymization.
//!
//! Shifts all timestamps by a random epoch offset and optionally adds
//! bounded per-timestamp jitter. The epoch offset is generated once per
//! engine session, so relative durations and ordering are preserved.

use std::time::Duration;

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

/// Timestamp anonymizer with epoch shift and optional jitter.
#[derive(Debug)]
pub struct TimestampAnonymizer {
    /// Fixed offset applied to all timestamps.
    epoch_offset: Duration,
    /// Maximum per-timestamp jitter in milliseconds (0 = no jitter).
    jitter_ms: u32,
    /// RNG for jitter generation (only used if `jitter_ms > 0`).
    rng: StdRng,
}

impl TimestampAnonymizer {
    /// Create a new anonymizer with epoch shift only.
    pub fn epoch_shift_only(rng: &mut StdRng) -> Self {
        // Random offset: 30-365 days into the future
        let offset_secs: u64 = rng.random_range(30 * 86400..365 * 86400);
        Self {
            epoch_offset: Duration::from_secs(offset_secs),
            jitter_ms: 0,
            rng: StdRng::from_os_rng(),
        }
    }

    /// Create a new anonymizer with epoch shift and bounded jitter.
    pub fn with_jitter(jitter_ms: u32, rng: &mut StdRng) -> Self {
        let offset_secs: u64 = rng.random_range(30 * 86400..365 * 86400);
        Self {
            epoch_offset: Duration::from_secs(offset_secs),
            jitter_ms,
            rng: StdRng::from_os_rng(),
        }
    }

    /// Anonymize a single timestamp.
    ///
    /// Applies the epoch offset and optional jitter.
    pub fn anonymize(&mut self, ts: Duration) -> Duration {
        let shifted = ts + self.epoch_offset;
        if self.jitter_ms == 0 {
            return shifted;
        }
        let jitter = Duration::from_millis(
            self.rng.random_range(0..=u64::from(self.jitter_ms)),
        );
        shifted + jitter
    }

    /// The fixed epoch offset applied to all timestamps.
    #[must_use]
    pub fn epoch_offset(&self) -> Duration {
        self.epoch_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_epoch_shift_preserves_ordering() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut anon = TimestampAnonymizer::epoch_shift_only(&mut rng);

        let t1 = Duration::from_secs(100);
        let t2 = Duration::from_secs(200);
        let t3 = Duration::from_secs(300);

        let a1 = anon.anonymize(t1);
        let a2 = anon.anonymize(t2);
        let a3 = anon.anonymize(t3);

        assert!(a1 < a2);
        assert!(a2 < a3);
    }

    #[test]
    fn test_epoch_shift_preserves_duration() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut anon = TimestampAnonymizer::epoch_shift_only(&mut rng);

        let t1 = Duration::from_secs(100);
        let t2 = Duration::from_secs(200);

        let a1 = anon.anonymize(t1);
        let a2 = anon.anonymize(t2);

        // Without jitter, duration is perfectly preserved
        assert_eq!(a2 - a1, t2 - t1);
    }

    #[test]
    fn test_offset_is_positive() {
        let mut rng = StdRng::seed_from_u64(42);
        let anon = TimestampAnonymizer::epoch_shift_only(&mut rng);
        // At least 30 days
        assert!(anon.epoch_offset() >= Duration::from_secs(30 * 86400));
    }

    #[test]
    fn test_jitter_adds_noise() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut anon = TimestampAnonymizer::with_jitter(10, &mut rng);
        let ts = Duration::from_secs(100);

        // Collect multiple anonymizations to check variance
        let results: Vec<Duration> = (0..100).map(|_| anon.anonymize(ts)).collect();

        // Not all results should be identical (probabilistically guaranteed)
        let first = results[0];
        assert!(results.iter().any(|&r| r != first));
    }
}
