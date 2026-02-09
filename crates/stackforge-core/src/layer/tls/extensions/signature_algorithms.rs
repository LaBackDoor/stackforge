//! Signature Algorithms extension (type 0x000D).
//!
//! Lists supported signature/hash algorithm pairs.

use super::Extension;

/// Parse signature algorithms from extension data.
pub fn parse_signature_algorithms(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut algs = Vec::new();
    let mut offset = 2;
    let end = (2 + list_len).min(data.len());

    while offset + 1 < end {
        algs.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += 2;
    }

    algs
}

/// Build signature_algorithms extension.
pub fn build_signature_algorithms(algorithms: &[u16]) -> Extension {
    let list_len = (algorithms.len() * 2) as u16;
    let mut data = Vec::with_capacity(2 + algorithms.len() * 2);
    data.extend_from_slice(&list_len.to_be_bytes());
    for &alg in algorithms {
        data.extend_from_slice(&alg.to_be_bytes());
    }
    Extension::new(0x000D, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithms() {
        let algs = vec![0x0401, 0x0403, 0x0804]; // SHA256+RSA, SHA256+ECDSA, RSA-PSS-SHA256
        let ext = build_signature_algorithms(&algs);
        let parsed = parse_signature_algorithms(&ext.data);
        assert_eq!(parsed, algs);
    }
}
