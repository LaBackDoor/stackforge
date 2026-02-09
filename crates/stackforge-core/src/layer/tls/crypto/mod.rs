//! TLS cryptographic primitives.
//!
//! Feature-gated behind the `tls` feature flag.
//! Implements hash, HMAC, PRF, HKDF, and cipher abstractions.

#[cfg(feature = "tls")]
pub mod cipher_aead;
#[cfg(feature = "tls")]
pub mod cipher_block;
#[cfg(feature = "tls")]
pub mod cipher_stream;
pub mod compression;
pub mod groups;
#[cfg(feature = "tls")]
pub mod hash;
#[cfg(feature = "tls")]
pub mod hkdf_tls13;
#[cfg(feature = "tls")]
pub mod hmac_tls;
#[cfg(feature = "tls")]
pub mod prf;
pub mod suites;

#[cfg(feature = "tls")]
pub use hash::TlsHash;
#[cfg(feature = "tls")]
pub use hkdf_tls13::Tls13Hkdf;
#[cfg(feature = "tls")]
pub use hmac_tls::TlsHmac;
#[cfg(feature = "tls")]
pub use prf::Prf;
