//! TLS 1.3 HKDF key schedule (RFC 8446 Section 7.1).
//!
//! Implements HKDF-Extract, HKDF-Expand, and TLS 1.3-specific
//! Derive-Secret and expand_label operations.

use hkdf::Hkdf;

use super::hash::TlsHash;

/// TLS 1.3 HKDF key derivation.
#[derive(Debug, Clone)]
pub struct Tls13Hkdf {
    hash: TlsHash,
}

impl Tls13Hkdf {
    pub fn new(hash: TlsHash) -> Self {
        Self { hash }
    }

    /// HKDF-Extract(salt, ikm) -> prk
    ///
    /// Extract is just HMAC(salt, ikm).
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        use super::hmac_tls::TlsHmac;
        // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
        let hmac = TlsHmac::new(self.hash, salt);
        hmac.digest(ikm)
    }

    /// HKDF-Expand(prk, info, length) -> okm
    pub fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        match self.hash {
            TlsHash::Sha256 => {
                let hk = Hkdf::<sha2::Sha256>::from_prk(prk).expect("valid PRK length");
                let mut okm = vec![0u8; length];
                hk.expand(info, &mut okm).expect("valid output length");
                okm
            }
            TlsHash::Sha384 => {
                let hk = Hkdf::<sha2::Sha384>::from_prk(prk).expect("valid PRK length");
                let mut okm = vec![0u8; length];
                hk.expand(info, &mut okm).expect("valid output length");
                okm
            }
            _ => {
                let hk = Hkdf::<sha2::Sha256>::from_prk(prk).expect("valid PRK length");
                let mut okm = vec![0u8; length];
                hk.expand(info, &mut okm).expect("valid output length");
                okm
            }
        }
    }

    /// TLS 1.3 HKDF-Expand-Label(Secret, Label, Context, Length)
    ///
    /// struct {
    ///     uint16 length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    pub fn expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let tls_label = [b"tls13 ", label].concat();

        // Build HkdfLabel structure
        let mut info = Vec::with_capacity(2 + 1 + tls_label.len() + 1 + context.len());
        info.extend_from_slice(&(length as u16).to_be_bytes());
        info.push(tls_label.len() as u8);
        info.extend_from_slice(&tls_label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        self.expand(secret, &info, length)
    }

    /// Derive-Secret(Secret, Label, Messages)
    ///
    /// = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    pub fn derive_secret(&self, secret: &[u8], label: &[u8], messages: &[u8]) -> Vec<u8> {
        let transcript_hash = self.hash.digest(messages);
        self.expand_label(secret, label, &transcript_hash, self.hash.hash_len())
    }

    /// Compute Finished verify data.
    ///
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    /// verify_data = HMAC(finished_key, Transcript-Hash(handshake_context))
    pub fn compute_verify_data(&self, base_key: &[u8], handshake_context: &[u8]) -> Vec<u8> {
        let finished_key = self.expand_label(base_key, b"finished", &[], self.hash.hash_len());
        let transcript_hash = self.hash.digest(handshake_context);
        let hmac = super::hmac_tls::TlsHmac::new(self.hash, &finished_key);
        hmac.digest(&transcript_hash)
    }

    /// Get the hash length for this HKDF instance.
    pub fn hash_len(&self) -> usize {
        self.hash.hash_len()
    }
}

/// TLS 1.3 key schedule helper.
///
/// Implements the full key schedule from RFC 8446 Section 7.1.
#[derive(Debug, Clone)]
pub struct Tls13KeySchedule {
    hkdf: Tls13Hkdf,
    early_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
}

impl Tls13KeySchedule {
    pub fn new(hash: TlsHash) -> Self {
        Self {
            hkdf: Tls13Hkdf::new(hash),
            early_secret: None,
            handshake_secret: None,
            master_secret: None,
        }
    }

    /// Step 1: Derive Early Secret from PSK (or zeros).
    pub fn derive_early_secret(&mut self, psk: Option<&[u8]>) -> &[u8] {
        let hash_len = self.hkdf.hash_len();
        let zeros = vec![0u8; hash_len];
        let ikm = psk.unwrap_or(&zeros);
        let salt = vec![0u8; hash_len];
        self.early_secret = Some(self.hkdf.extract(&salt, ikm));
        self.early_secret.as_ref().unwrap()
    }

    /// Step 2: Derive Handshake Secret from shared secret.
    pub fn derive_handshake_secret(&mut self, shared_secret: &[u8]) -> &[u8] {
        let early_secret = self
            .early_secret
            .as_ref()
            .expect("must derive early secret first");
        let derived = self.hkdf.derive_secret(early_secret, b"derived", &[]);
        self.handshake_secret = Some(self.hkdf.extract(&derived, shared_secret));
        self.handshake_secret.as_ref().unwrap()
    }

    /// Step 3: Derive Master Secret.
    pub fn derive_master_secret(&mut self) -> &[u8] {
        let hs_secret = self
            .handshake_secret
            .as_ref()
            .expect("must derive handshake secret first");
        let hash_len = self.hkdf.hash_len();
        let zeros = vec![0u8; hash_len];
        let derived = self.hkdf.derive_secret(hs_secret, b"derived", &[]);
        self.master_secret = Some(self.hkdf.extract(&derived, &zeros));
        self.master_secret.as_ref().unwrap()
    }

    /// Derive client/server handshake traffic secret.
    pub fn client_handshake_traffic_secret(&self, transcript: &[u8]) -> Vec<u8> {
        let hs = self
            .handshake_secret
            .as_ref()
            .expect("must derive handshake secret first");
        self.hkdf.derive_secret(hs, b"c hs traffic", transcript)
    }

    pub fn server_handshake_traffic_secret(&self, transcript: &[u8]) -> Vec<u8> {
        let hs = self
            .handshake_secret
            .as_ref()
            .expect("must derive handshake secret first");
        self.hkdf.derive_secret(hs, b"s hs traffic", transcript)
    }

    /// Derive client/server application traffic secret.
    pub fn client_application_traffic_secret(&self, transcript: &[u8]) -> Vec<u8> {
        let ms = self
            .master_secret
            .as_ref()
            .expect("must derive master secret first");
        self.hkdf.derive_secret(ms, b"c ap traffic", transcript)
    }

    pub fn server_application_traffic_secret(&self, transcript: &[u8]) -> Vec<u8> {
        let ms = self
            .master_secret
            .as_ref()
            .expect("must derive master secret first");
        self.hkdf.derive_secret(ms, b"s ap traffic", transcript)
    }

    /// Derive traffic keys from a traffic secret.
    pub fn derive_traffic_keys(
        &self,
        traffic_secret: &[u8],
        key_len: usize,
        iv_len: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let key = self.hkdf.expand_label(traffic_secret, b"key", &[], key_len);
        let iv = self.hkdf.expand_label(traffic_secret, b"iv", &[], iv_len);
        (key, iv)
    }

    /// Get reference to the HKDF instance.
    pub fn hkdf(&self) -> &Tls13Hkdf {
        &self.hkdf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract_expand() {
        let hkdf = Tls13Hkdf::new(TlsHash::Sha256);
        let ikm = vec![0x0b; 22];
        let salt = vec![0u8; 13];
        let prk = hkdf.extract(&salt, &ikm);
        assert_eq!(prk.len(), 32);

        let okm = hkdf.expand(&prk, b"test info", 42);
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn test_expand_label() {
        let hkdf = Tls13Hkdf::new(TlsHash::Sha256);
        let secret = vec![0xab; 32];
        let result = hkdf.expand_label(&secret, b"key", &[], 16);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_derive_secret() {
        let hkdf = Tls13Hkdf::new(TlsHash::Sha256);
        let secret = vec![0xcd; 32];
        let result = hkdf.derive_secret(&secret, b"derived", &[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_key_schedule() {
        let mut ks = Tls13KeySchedule::new(TlsHash::Sha256);

        // Step 1: Early Secret (no PSK)
        let early = ks.derive_early_secret(None);
        assert_eq!(early.len(), 32);

        // Step 2: Handshake Secret (with dummy shared secret)
        let shared = vec![0xff; 32];
        let hs = ks.derive_handshake_secret(&shared);
        assert_eq!(hs.len(), 32);

        // Step 3: Master Secret
        let ms = ks.derive_master_secret();
        assert_eq!(ms.len(), 32);

        // Derive traffic secrets
        let c_hs = ks.client_handshake_traffic_secret(b"transcript");
        assert_eq!(c_hs.len(), 32);

        let s_hs = ks.server_handshake_traffic_secret(b"transcript");
        assert_eq!(s_hs.len(), 32);

        let c_ap = ks.client_application_traffic_secret(b"transcript");
        assert_eq!(c_ap.len(), 32);

        // Derive keys
        let (key, iv) = ks.derive_traffic_keys(&c_hs, 16, 12);
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_verify_data() {
        let hkdf = Tls13Hkdf::new(TlsHash::Sha256);
        let base_key = vec![0x42; 32];
        let vd = hkdf.compute_verify_data(&base_key, b"handshake context");
        assert_eq!(vd.len(), 32);
    }

    #[test]
    fn test_sha384_key_schedule() {
        let mut ks = Tls13KeySchedule::new(TlsHash::Sha384);
        let early = ks.derive_early_secret(None);
        assert_eq!(early.len(), 48);

        let shared = vec![0xff; 48];
        let hs = ks.derive_handshake_secret(&shared);
        assert_eq!(hs.len(), 48);
    }
}
