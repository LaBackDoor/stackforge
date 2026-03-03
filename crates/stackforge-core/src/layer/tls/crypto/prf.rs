//! TLS Pseudorandom Function (PRF) implementations.
//!
//! Implements PRF for `SSLv3`, TLS 1.0/1.1, and TLS 1.2 (RFC 5246).

use super::hash::TlsHash;
use super::hmac_tls::TlsHmac;

/// `P_hash` expansion function (RFC 4346 Section 5).
///
/// `P_hash(secret`, seed) = `HMAC_hash(secret`, A(1) + seed) +
///                        `HMAC_hash(secret`, A(2) + seed) +
///                        `HMAC_hash(secret`, A(3) + seed) + ...
///
/// where A(0) = seed, A(i) = `HMAC_hash(secret`, A(i-1))
fn p_hash(hash: TlsHash, secret: &[u8], seed: &[u8], req_len: usize) -> Vec<u8> {
    let hmac = TlsHmac::new(hash, secret);
    let mut result = Vec::with_capacity(req_len);

    // A(1) = HMAC_hash(secret, seed)
    let mut a = hmac.digest(seed);

    while result.len() < req_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let output = hmac.digest(&input);
        result.extend_from_slice(&output);

        // A(i+1) = HMAC_hash(secret, A(i))
        a = hmac.digest(&a);
    }

    result.truncate(req_len);
    result
}

/// TLS PRF abstraction.
#[derive(Debug, Clone)]
pub struct Prf {
    hash: TlsHash,
    tls_version: u16,
}

impl Prf {
    /// Create a new PRF for the given TLS version and hash.
    #[must_use]
    pub fn new(hash: TlsHash, tls_version: u16) -> Self {
        Self { hash, tls_version }
    }

    /// The core PRF function.
    #[must_use]
    pub fn prf(&self, secret: &[u8], label: &[u8], seed: &[u8], req_len: usize) -> Vec<u8> {
        let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
        combined_seed.extend_from_slice(label);
        combined_seed.extend_from_slice(seed);

        match self.tls_version {
            // SSLv3
            0x0300 => self.prf_sslv3(secret, &combined_seed, req_len),
            // TLS 1.0 and 1.1
            0x0301 | 0x0302 => self.prf_tls10(secret, &combined_seed, req_len),
            // TLS 1.2+
            _ => p_hash(self.hash, secret, &combined_seed, req_len),
        }
    }

    /// `SSLv3` PRF: MD5(secret + SHA1('A' + secret + seed)) + ...
    fn prf_sslv3(&self, secret: &[u8], seed: &[u8], req_len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(req_len);
        let mut idx: u8 = 0;

        while result.len() < req_len {
            idx += 1;
            // 'A', 'BB', 'CCC', ...
            let prefix: Vec<u8> = vec![0x40 + idx; idx as usize];

            // SHA1(prefix + secret + seed)
            let mut sha_input = Vec::with_capacity(prefix.len() + secret.len() + seed.len());
            sha_input.extend_from_slice(&prefix);
            sha_input.extend_from_slice(secret);
            sha_input.extend_from_slice(seed);
            let sha_hash = TlsHash::Sha1.digest(&sha_input);

            // MD5(secret + sha_hash)
            let mut md5_input = Vec::with_capacity(secret.len() + sha_hash.len());
            md5_input.extend_from_slice(secret);
            md5_input.extend_from_slice(&sha_hash);
            let md5_hash = TlsHash::Md5.digest(&md5_input);

            result.extend_from_slice(&md5_hash);
        }

        result.truncate(req_len);
        result
    }

    /// TLS 1.0/1.1 PRF: XOR of `P_MD5` and `P_SHA1` with split secret.
    fn prf_tls10(&self, secret: &[u8], seed: &[u8], req_len: usize) -> Vec<u8> {
        let half = secret.len().div_ceil(2);
        let s1 = &secret[..half];
        let s2 = &secret[secret.len() - half..];

        let p_md5 = p_hash(TlsHash::Md5, s1, seed, req_len);
        let p_sha1 = p_hash(TlsHash::Sha1, s2, seed, req_len);

        // XOR the two halves
        p_md5
            .iter()
            .zip(p_sha1.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    /// Compute master secret from pre-master secret and randoms.
    #[must_use]
    pub fn compute_master_secret(
        &self,
        pre_master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Vec<u8> {
        let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);
        self.prf(pre_master_secret, b"master secret", &seed, 48)
    }

    /// Compute extended master secret (RFC 7627).
    #[must_use]
    pub fn compute_extended_master_secret(
        &self,
        pre_master_secret: &[u8],
        handshake_hash: &[u8],
    ) -> Vec<u8> {
        self.prf(
            pre_master_secret,
            b"extended master secret",
            handshake_hash,
            48,
        )
    }

    /// Derive key block from master secret and randoms.
    #[must_use]
    pub fn derive_key_block(
        &self,
        master_secret: &[u8],
        server_random: &[u8],
        client_random: &[u8],
        req_len: usize,
    ) -> Vec<u8> {
        let mut seed = Vec::with_capacity(server_random.len() + client_random.len());
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);
        self.prf(master_secret, b"key expansion", &seed, req_len)
    }

    /// Compute verify data for Finished message.
    #[must_use]
    pub fn compute_verify_data(
        &self,
        master_secret: &[u8],
        is_client: bool,
        handshake_hash: &[u8],
    ) -> Vec<u8> {
        let label = if is_client {
            b"client finished" as &[u8]
        } else {
            b"server finished" as &[u8]
        };
        // TLS 1.2: verify_data_length = 12
        self.prf(master_secret, label, handshake_hash, 12)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p_hash_basic() {
        // Simple smoke test - P_SHA256 should produce deterministic output
        let secret = b"secret";
        let seed = b"seed";
        let result1 = p_hash(TlsHash::Sha256, secret, seed, 32);
        let result2 = p_hash(TlsHash::Sha256, secret, seed, 32);
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_p_hash_length() {
        let result = p_hash(TlsHash::Sha256, b"key", b"seed", 100);
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn test_prf_tls12() {
        let prf = Prf::new(TlsHash::Sha256, 0x0303);
        let result = prf.prf(b"secret", b"label", b"seed", 32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_prf_tls10() {
        let prf = Prf::new(TlsHash::Sha256, 0x0301);
        let result = prf.prf(b"secret", b"label", b"seed", 32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_master_secret_length() {
        let prf = Prf::new(TlsHash::Sha256, 0x0303);
        let client_random = [0u8; 32];
        let server_random = [0u8; 32];
        let pms = [0u8; 48];
        let ms = prf.compute_master_secret(&pms, &client_random, &server_random);
        assert_eq!(ms.len(), 48);
    }

    #[test]
    fn test_verify_data_length() {
        let prf = Prf::new(TlsHash::Sha256, 0x0303);
        let ms = [0u8; 48];
        let hash = TlsHash::Sha256.digest(b"handshake messages");
        let vd = prf.compute_verify_data(&ms, true, &hash);
        assert_eq!(vd.len(), 12);
    }

    #[test]
    fn test_key_block() {
        let prf = Prf::new(TlsHash::Sha256, 0x0303);
        let ms = [0u8; 48];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let kb = prf.derive_key_block(&ms, &sr, &cr, 104);
        assert_eq!(kb.len(), 104);
    }
}
