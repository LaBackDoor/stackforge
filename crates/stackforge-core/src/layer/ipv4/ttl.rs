//! TTL (Time To Live) utilities.
//!
//! Provides functions to guess the original TTL and number of hops
//! based on the current TTL value.

/// Common initial TTL values used by various operating systems.
/// 32:  Some ancient systems
/// 64:  Linux, macOS, modern Windows
/// 128: Older Windows
/// 255: Network infrastructure (Cisco, etc.)
const INITIAL_TTLS: [u8; 4] = [32, 64, 128, 255];

/// Estimate the original TTL based on the current TTL.
///
/// This finds the smallest standard initial TTL that is greater than
/// or equal to the current TTL.
#[must_use]
pub fn estimate_original(current_ttl: u8) -> u8 {
    for &initial in &INITIAL_TTLS {
        if current_ttl <= initial {
            return initial;
        }
    }
    // Should be unreachable for u8, but fallback to 255
    255
}

/// Estimate the number of hops the packet has traveled.
///
/// Calculated as `original_ttl - current_ttl`.
#[must_use]
pub fn estimate_hops(current_ttl: u8) -> u8 {
    let original = estimate_original(current_ttl);
    original.saturating_sub(current_ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_original() {
        assert_eq!(estimate_original(1), 32);
        assert_eq!(estimate_original(30), 32);
        assert_eq!(estimate_original(32), 32);

        assert_eq!(estimate_original(33), 64);
        assert_eq!(estimate_original(60), 64);
        assert_eq!(estimate_original(64), 64);

        assert_eq!(estimate_original(65), 128);
        assert_eq!(estimate_original(100), 128);
        assert_eq!(estimate_original(128), 128);

        assert_eq!(estimate_original(129), 255);
        assert_eq!(estimate_original(200), 255);
        assert_eq!(estimate_original(255), 255);
    }

    #[test]
    fn test_estimate_hops() {
        assert_eq!(estimate_hops(30), 2); // 32 - 30
        assert_eq!(estimate_hops(63), 1); // 64 - 63
        assert_eq!(estimate_hops(54), 10); // 64 - 54
        assert_eq!(estimate_hops(128), 0); // 128 - 128
    }
}
