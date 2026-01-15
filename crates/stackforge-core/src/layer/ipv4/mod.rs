//! IPv4 layer module.
//!
//! This module implements the IPv4 protocol, providing packet parsing (via `Ipv4Layer`),
//! construction (via `Ipv4Builder`), fragmentation, options handling, and checksum verification.

// Register submodules
pub mod builder;
pub mod checksum;
pub mod fragmentation;
pub mod header;
pub mod options;
pub mod protocol;
pub mod routing;
pub mod ttl;

// Re-export primary types for easier access
pub use builder::Ipv4Builder;
pub use checksum::ipv4_checksum;
pub use fragmentation::{DEFAULT_MTU, Fragment, FragmentInfo, Ipv4Fragmenter};
pub use header::{
    IPV4_MAX_HEADER_LEN, IPV4_MIN_HEADER_LEN, Ipv4Flags, Ipv4Layer, offsets as ipv4_offsets,
};
pub use options::{Ipv4Option, Ipv4OptionClass, Ipv4OptionType, Ipv4Options, Ipv4OptionsBuilder};
pub use routing::Ipv4Route;
