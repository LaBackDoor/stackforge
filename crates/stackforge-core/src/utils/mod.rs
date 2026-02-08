//! Utility functions for packet manipulation.
//!
//! This module provides helper functions like hexdump, checksum calculation,
//! and other common operations used in network programming.
//!
//! The utilities are organized into submodules:
//! - [`hex`]: Hexdump and hex string utilities
//! - [`checksum`]: Checksum calculation and verification
//! - [`compare`]: Binary comparison and diff utilities
//! - [`padding`]: Padding and alignment utilities
//! - [`bits`]: Bitwise operations and byte order conversions
//! - [`random`]: Random data generation (feature-gated)

pub mod bits;
pub mod checksum;
pub mod compare;
pub mod hex;
pub mod padding;
pub mod random;

// Re-export commonly used functions
pub use bits::{be_to_u16, be_to_u32, extract_bits, set_bits, u16_to_be, u32_to_be};
pub use checksum::{
    finalize_checksum, internet_checksum, partial_checksum, transport_checksum, verify_checksum,
};
pub use compare::{byte_diff, find_diff};
pub use hex::{hexdump, hexstr, hexstr_sep, parse_hex, pretty_bytes};
pub use padding::{align_to, ethernet_min_frame, pad_to};

#[cfg(feature = "rand")]
pub use random::{random_bytes, random_mac};
