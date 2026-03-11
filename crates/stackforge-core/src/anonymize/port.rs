//! Port generalization for transport layer anonymization.
//!
//! Ports are categorized into three IANA ranges and optionally replaced
//! with sentinel values. Well-known destination ports (0-1023) can be
//! preserved for service identification in ML models.

/// IANA port category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortCategory {
    /// System / well-known ports (0-1023).
    WellKnown,
    /// Registered / user ports (1024-49151).
    Registered,
    /// Dynamic / ephemeral ports (49152-65535).
    Ephemeral,
}

/// Sentinel values representing each port category.
impl PortCategory {
    /// Representative sentinel value for this category.
    #[must_use]
    pub const fn sentinel(self) -> u16 {
        match self {
            Self::WellKnown => 0,
            Self::Registered => 1024,
            Self::Ephemeral => 49152,
        }
    }
}

/// Classify a port into its IANA category.
#[must_use]
pub const fn categorize_port(port: u16) -> PortCategory {
    match port {
        0..=1023 => PortCategory::WellKnown,
        1024..=49151 => PortCategory::Registered,
        _ => PortCategory::Ephemeral,
    }
}

/// Generalize a port to its category sentinel.
///
/// If `preserve_well_known_dst` is `true` and this is a destination port
/// in the well-known range, the original port value is returned unchanged.
#[must_use]
pub const fn generalize_port(port: u16, preserve_well_known_dst: bool, is_dst: bool) -> u16 {
    if preserve_well_known_dst && is_dst && port <= 1023 {
        return port;
    }
    categorize_port(port).sentinel()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize() {
        assert_eq!(categorize_port(80), PortCategory::WellKnown);
        assert_eq!(categorize_port(443), PortCategory::WellKnown);
        assert_eq!(categorize_port(8080), PortCategory::Registered);
        assert_eq!(categorize_port(49152), PortCategory::Ephemeral);
        assert_eq!(categorize_port(60000), PortCategory::Ephemeral);
        assert_eq!(categorize_port(0), PortCategory::WellKnown);
        assert_eq!(categorize_port(1023), PortCategory::WellKnown);
        assert_eq!(categorize_port(1024), PortCategory::Registered);
    }

    #[test]
    fn test_generalize_preserves_well_known_dst() {
        // Destination port 443 preserved
        assert_eq!(generalize_port(443, true, true), 443);
        // Source port 443 NOT preserved
        assert_eq!(generalize_port(443, true, false), 0);
    }

    #[test]
    fn test_generalize_categorize_all() {
        // Even dst ports are generalized when preserve_well_known_dst = false
        assert_eq!(generalize_port(443, false, true), 0);
        assert_eq!(generalize_port(8080, false, true), 1024);
        assert_eq!(generalize_port(55000, false, true), 49152);
    }

    #[test]
    fn test_generalize_ephemeral_src() {
        assert_eq!(generalize_port(54321, true, false), 49152);
    }
}
