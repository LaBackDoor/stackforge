//! TLS Session state management.
//!
//! Tracks the state of a TLS connection including version, cipher suite,
//! randoms, master secret, and derived keys.

#[cfg(feature = "tls")]
use super::crypto::hash::TlsHash;
#[cfg(feature = "tls")]
use super::crypto::suites::{CipherSuite, find_suite};

/// Connection end identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEnd {
    Client,
    Server,
}

/// TLS connection state for one direction (read or write).
#[derive(Debug, Clone)]
pub struct ConnState {
    /// Sequence number for MAC computation.
    pub seq_num: u64,
    /// Encryption key.
    pub key: Vec<u8>,
    /// MAC key (for CBC suites).
    pub mac_key: Vec<u8>,
    /// IV (fixed for AEAD, per-record for CBC in TLS 1.0).
    pub iv: Vec<u8>,
}

impl ConnState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seq_num: 0,
            key: Vec::new(),
            mac_key: Vec::new(),
            iv: Vec::new(),
        }
    }

    /// Increment the sequence number and return the previous value.
    pub fn next_seq_num(&mut self) -> u64 {
        let n = self.seq_num;
        self.seq_num += 1;
        n
    }
}

impl Default for ConnState {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS session state.
#[derive(Debug, Clone)]
pub struct TlsSession {
    /// Negotiated TLS version.
    pub version: u16,
    /// Selected cipher suite ID.
    pub cipher_suite_id: u16,
    /// Client random (32 bytes).
    pub client_random: [u8; 32],
    /// Server random (32 bytes).
    pub server_random: [u8; 32],
    /// Master secret (48 bytes).
    pub master_secret: Vec<u8>,
    /// Read (decryption) state.
    pub read_state: ConnState,
    /// Write (encryption) state.
    pub write_state: ConnState,
    /// Our connection end.
    pub connection_end: ConnectionEnd,
    /// Handshake transcript (for `verify_data` and TLS 1.3).
    pub transcript: Vec<u8>,
    /// Whether the handshake is complete.
    pub handshake_complete: bool,
    /// Extended master secret enabled.
    pub extended_master_secret: bool,
    /// Encrypt-then-MAC enabled.
    pub encrypt_then_mac: bool,
}

impl TlsSession {
    /// Create a new client session.
    #[must_use]
    pub fn new_client() -> Self {
        Self {
            version: 0x0303,
            cipher_suite_id: 0,
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            master_secret: Vec::new(),
            read_state: ConnState::new(),
            write_state: ConnState::new(),
            connection_end: ConnectionEnd::Client,
            transcript: Vec::new(),
            handshake_complete: false,
            extended_master_secret: false,
            encrypt_then_mac: false,
        }
    }

    /// Create a new server session.
    #[must_use]
    pub fn new_server() -> Self {
        let mut session = Self::new_client();
        session.connection_end = ConnectionEnd::Server;
        session
    }

    /// Append handshake message bytes to the transcript.
    pub fn update_transcript(&mut self, data: &[u8]) {
        self.transcript.extend_from_slice(data);
    }

    /// Derive keys from master secret and install them.
    #[cfg(feature = "tls")]
    pub fn derive_keys(&mut self) {
        let suite = match find_suite(self.cipher_suite_id) {
            Some(s) => s,
            None => return,
        };

        let hash = match suite.hash {
            super::crypto::suites::SuiteHash::Sha256 => TlsHash::Sha256,
            super::crypto::suites::SuiteHash::Sha384 => TlsHash::Sha384,
            _ => TlsHash::Sha256,
        };

        let prf = super::crypto::prf::Prf::new(hash, self.version);
        let key_block_len = suite.key_block_len();
        let key_block = prf.derive_key_block(
            &self.master_secret,
            &self.server_random,
            &self.client_random,
            key_block_len,
        );

        self.install_keys(suite, &key_block);
    }

    /// Install keys from key block.
    #[cfg(feature = "tls")]
    fn install_keys(&mut self, suite: &CipherSuite, key_block: &[u8]) {
        let mut offset = 0;

        // client_write_MAC_key
        let client_mac = key_block[offset..offset + suite.mac_len].to_vec();
        offset += suite.mac_len;
        // server_write_MAC_key
        let server_mac = key_block[offset..offset + suite.mac_len].to_vec();
        offset += suite.mac_len;
        // client_write_key
        let client_key = key_block[offset..offset + suite.key_len].to_vec();
        offset += suite.key_len;
        // server_write_key
        let server_key = key_block[offset..offset + suite.key_len].to_vec();
        offset += suite.key_len;
        // client_write_IV
        let client_iv = key_block[offset..offset + suite.iv_len].to_vec();
        offset += suite.iv_len;
        // server_write_IV
        let server_iv = key_block[offset..offset + suite.iv_len].to_vec();
        let _ = offset + suite.iv_len;

        match self.connection_end {
            ConnectionEnd::Client => {
                self.write_state.key = client_key;
                self.write_state.mac_key = client_mac;
                self.write_state.iv = client_iv;
                self.read_state.key = server_key;
                self.read_state.mac_key = server_mac;
                self.read_state.iv = server_iv;
            },
            ConnectionEnd::Server => {
                self.read_state.key = client_key;
                self.read_state.mac_key = client_mac;
                self.read_state.iv = client_iv;
                self.write_state.key = server_key;
                self.write_state.mac_key = server_mac;
                self.write_state.iv = server_iv;
            },
        }
    }
}

/// NSS key log file parser.
///
/// Parses NSS key log files (SSLKEYLOGFILE format) used by Wireshark
/// for TLS session decryption.
#[derive(Debug, Clone)]
pub struct NssKeyLogEntry {
    /// Label (e.g., "`CLIENT_RANDOM`", "`CLIENT_HANDSHAKE_TRAFFIC_SECRET`").
    pub label: String,
    /// Client random or other identifier (hex-encoded in the file, decoded here).
    pub client_random: Vec<u8>,
    /// Secret value.
    pub secret: Vec<u8>,
}

/// Parse an NSS key log file.
#[must_use]
pub fn parse_nss_key_log(content: &str) -> Vec<NssKeyLogEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() != 3 {
            continue;
        }

        let label = parts[0].to_string();
        let client_random = match hex_decode(parts[1]) {
            Some(v) => v,
            None => continue,
        };
        let secret = match hex_decode(parts[2]) {
            Some(v) => v,
            None => continue,
        };

        entries.push(NssKeyLogEntry {
            label,
            client_random,
            secret,
        });
    }

    entries
}

/// Simple hex decoder.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        result.push(byte);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = TlsSession::new_client();
        assert_eq!(session.connection_end, ConnectionEnd::Client);
        assert_eq!(session.version, 0x0303);
        assert!(!session.handshake_complete);
    }

    #[test]
    fn test_conn_state_seq_num() {
        let mut state = ConnState::new();
        assert_eq!(state.next_seq_num(), 0);
        assert_eq!(state.next_seq_num(), 1);
        assert_eq!(state.next_seq_num(), 2);
    }

    #[test]
    fn test_transcript() {
        let mut session = TlsSession::new_client();
        session.update_transcript(b"hello");
        session.update_transcript(b" world");
        assert_eq!(session.transcript, b"hello world");
    }

    #[test]
    fn test_parse_nss_key_log() {
        let content = "# SSL/TLS secrets log file
CLIENT_RANDOM 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 aabbccdd
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 eeff0011
";
        let entries = parse_nss_key_log(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, "CLIENT_RANDOM");
        assert_eq!(entries[0].client_random.len(), 32);
        assert_eq!(entries[0].secret, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(entries[1].label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("aabb"), Some(vec![0xaa, 0xbb]));
        assert_eq!(hex_decode("0102"), Some(vec![0x01, 0x02]));
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None); // invalid hex
    }
}
