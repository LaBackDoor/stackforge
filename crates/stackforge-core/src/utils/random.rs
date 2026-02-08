//! Random data generation utilities (feature-gated).

#[cfg(feature = "rand")]
use rand::Rng;

/// Generate random bytes.
#[cfg(feature = "rand")]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random()).collect()
}

/// Generate a random MAC address.
#[cfg(feature = "rand")]
pub fn random_mac() -> crate::MacAddress {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 6];
    rng.fill(&mut bytes);
    // Set locally administered bit, clear multicast bit
    bytes[0] = (bytes[0] | 0x02) & 0xFE;
    crate::MacAddress::new(bytes)
}
