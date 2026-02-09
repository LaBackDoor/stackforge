//! SSLv2 handshake message parsing and building.

/// SSLv2 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sslv2MessageType(pub u8);

impl Sslv2MessageType {
    pub const ERROR: Self = Self(0);
    pub const CLIENT_HELLO: Self = Self(1);
    pub const CLIENT_MASTER_KEY: Self = Self(2);
    pub const CLIENT_FINISHED: Self = Self(3);
    pub const SERVER_HELLO: Self = Self(4);
    pub const SERVER_VERIFY: Self = Self(5);
    pub const SERVER_FINISHED: Self = Self(6);
    pub const REQUEST_CERTIFICATE: Self = Self(7);
    pub const CLIENT_CERTIFICATE: Self = Self(8);

    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "ERROR",
            1 => "CLIENT_HELLO",
            2 => "CLIENT_MASTER_KEY",
            3 => "CLIENT_FINISHED",
            4 => "SERVER_HELLO",
            5 => "SERVER_VERIFY",
            6 => "SERVER_FINISHED",
            7 => "REQUEST_CERTIFICATE",
            8 => "CLIENT_CERTIFICATE",
            _ => "UNKNOWN",
        }
    }
}

/// SSLv2 ClientHello message.
///
/// ```text
/// msg_type:1, version:2, cipher_specs_len:2, session_id_len:2,
/// challenge_len:2, cipher_specs:var, session_id:var, challenge:var
/// ```
#[derive(Debug, Clone)]
pub struct Sslv2ClientHello {
    /// SSLv2 version (typically 0x0002).
    pub version: u16,
    /// 3-byte cipher suite IDs.
    pub cipher_specs: Vec<u32>,
    /// Session ID for resumption.
    pub session_id: Vec<u8>,
    /// Challenge (random bytes).
    pub challenge: Vec<u8>,
}

impl Sslv2ClientHello {
    /// Parse from record data (after msg_type byte).
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Skip msg_type byte if present
        let data = if !data.is_empty() && data[0] == 0x01 {
            &data[1..]
        } else {
            data
        };

        if data.len() < 8 {
            return None;
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        let cipher_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let session_id_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let challenge_len = u16::from_be_bytes([data[6], data[7]]) as usize;

        let mut offset = 8;

        // Cipher specs (3 bytes each)
        let mut cipher_specs = Vec::new();
        let cipher_end = (offset + cipher_len).min(data.len());
        while offset + 3 <= cipher_end {
            let cs = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]);
            cipher_specs.push(cs);
            offset += 3;
        }
        offset = cipher_end;

        // Session ID
        let session_id = if offset + session_id_len <= data.len() {
            let sid = data[offset..offset + session_id_len].to_vec();
            offset += session_id_len;
            sid
        } else {
            Vec::new()
        };

        // Challenge
        let challenge = if offset + challenge_len <= data.len() {
            data[offset..offset + challenge_len].to_vec()
        } else if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            version,
            cipher_specs,
            session_id,
            challenge,
        })
    }

    /// Build SSLv2 ClientHello record data (including msg_type byte).
    pub fn build(&self) -> Vec<u8> {
        let cipher_len = self.cipher_specs.len() * 3;
        let mut buf = Vec::new();

        buf.push(0x01); // msg_type
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&(cipher_len as u16).to_be_bytes());
        buf.extend_from_slice(&(self.session_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.challenge.len() as u16).to_be_bytes());

        for &cs in &self.cipher_specs {
            let bytes = cs.to_be_bytes();
            buf.extend_from_slice(&bytes[1..4]); // 3 bytes
        }
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.challenge);

        buf
    }
}

/// SSLv2 ServerHello message.
#[derive(Debug, Clone)]
pub struct Sslv2ServerHello {
    /// 0 = new session, 1 = resumed.
    pub session_id_hit: u8,
    /// Certificate type (1 = X.509).
    pub certificate_type: u8,
    /// Version.
    pub version: u16,
    /// Server certificate (DER-encoded).
    pub certificate: Vec<u8>,
    /// 3-byte cipher suite IDs.
    pub cipher_specs: Vec<u32>,
    /// Connection ID.
    pub connection_id: Vec<u8>,
}

impl Sslv2ServerHello {
    /// Parse from record data (after msg_type byte).
    pub fn parse(data: &[u8]) -> Option<Self> {
        let data = if !data.is_empty() && data[0] == 0x04 {
            &data[1..]
        } else {
            data
        };

        if data.len() < 10 {
            return None;
        }

        let session_id_hit = data[0];
        let certificate_type = data[1];
        let version = u16::from_be_bytes([data[2], data[3]]);
        let cert_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let cipher_len = u16::from_be_bytes([data[6], data[7]]) as usize;
        let conn_id_len = u16::from_be_bytes([data[8], data[9]]) as usize;

        let mut offset = 10;

        let certificate = if offset + cert_len <= data.len() {
            let cert = data[offset..offset + cert_len].to_vec();
            offset += cert_len;
            cert
        } else {
            Vec::new()
        };

        let mut cipher_specs = Vec::new();
        let cipher_end = (offset + cipher_len).min(data.len());
        while offset + 3 <= cipher_end {
            let cs = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]);
            cipher_specs.push(cs);
            offset += 3;
        }
        offset = cipher_end;

        let connection_id = if offset + conn_id_len <= data.len() {
            data[offset..offset + conn_id_len].to_vec()
        } else if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            session_id_hit,
            certificate_type,
            version,
            certificate,
            cipher_specs,
            connection_id,
        })
    }
}

/// SSLv2 ClientMasterKey message.
#[derive(Debug, Clone)]
pub struct Sslv2ClientMasterKey {
    /// Selected 3-byte cipher suite.
    pub cipher_suite: u32,
    /// Clear key portion.
    pub clear_key: Vec<u8>,
    /// Encrypted key portion (RSA encrypted).
    pub encrypted_key: Vec<u8>,
    /// Key argument (IV for block ciphers).
    pub key_arg: Vec<u8>,
}

impl Sslv2ClientMasterKey {
    /// Parse from record data (after msg_type byte).
    pub fn parse(data: &[u8]) -> Option<Self> {
        let data = if !data.is_empty() && data[0] == 0x02 {
            &data[1..]
        } else {
            data
        };

        if data.len() < 9 {
            return None;
        }

        let cipher_suite = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let clear_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let enc_len = u16::from_be_bytes([data[5], data[6]]) as usize;
        let arg_len = u16::from_be_bytes([data[7], data[8]]) as usize;

        let mut offset = 9;

        let clear_key = if offset + clear_len <= data.len() {
            let ck = data[offset..offset + clear_len].to_vec();
            offset += clear_len;
            ck
        } else {
            Vec::new()
        };

        let encrypted_key = if offset + enc_len <= data.len() {
            let ek = data[offset..offset + enc_len].to_vec();
            offset += enc_len;
            ek
        } else {
            Vec::new()
        };

        let key_arg = if offset + arg_len <= data.len() {
            data[offset..offset + arg_len].to_vec()
        } else if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            cipher_suite,
            clear_key,
            encrypted_key,
            key_arg,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sslv2_client_hello() {
        let mut data = Vec::new();
        data.push(0x01); // msg_type = CLIENT_HELLO
        data.extend_from_slice(&[0x00, 0x02]); // version = 0x0002
        data.extend_from_slice(&[0x00, 0x09]); // cipher_specs_len = 9 (3 ciphers)
        data.extend_from_slice(&[0x00, 0x00]); // session_id_len = 0
        data.extend_from_slice(&[0x00, 0x10]); // challenge_len = 16
        // 3 cipher specs (3 bytes each)
        data.extend_from_slice(&[0x07, 0x00, 0xC0]); // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        data.extend_from_slice(&[0x05, 0x00, 0x80]); // SSL_CK_RC4_128_WITH_MD5
        data.extend_from_slice(&[0x03, 0x00, 0x80]); // SSL_CK_RC2_128_CBC_WITH_MD5
        // Challenge (16 bytes)
        data.extend_from_slice(&[0x42; 16]);

        let ch = Sslv2ClientHello::parse(&data).unwrap();
        assert_eq!(ch.version, 0x0002);
        assert_eq!(ch.cipher_specs.len(), 3);
        assert_eq!(ch.cipher_specs[0], 0x0700C0);
        assert_eq!(ch.cipher_specs[1], 0x050080);
        assert_eq!(ch.cipher_specs[2], 0x030080);
        assert!(ch.session_id.is_empty());
        assert_eq!(ch.challenge.len(), 16);
    }

    #[test]
    fn test_roundtrip_sslv2_client_hello() {
        let ch = Sslv2ClientHello {
            version: 0x0002,
            cipher_specs: vec![0x0700C0, 0x050080],
            session_id: Vec::new(),
            challenge: vec![0x42; 16],
        };
        let built = ch.build();
        let parsed = Sslv2ClientHello::parse(&built).unwrap();
        assert_eq!(parsed.version, ch.version);
        assert_eq!(parsed.cipher_specs, ch.cipher_specs);
        assert_eq!(parsed.challenge, ch.challenge);
    }

    #[test]
    fn test_parse_sslv2_server_hello() {
        let mut data = Vec::new();
        data.push(0x04); // msg_type = SERVER_HELLO
        data.push(0x00); // session_id_hit = 0
        data.push(0x01); // certificate_type = X.509
        data.extend_from_slice(&[0x00, 0x02]); // version = 0x0002
        data.extend_from_slice(&[0x00, 0x03]); // cert_len = 3
        data.extend_from_slice(&[0x00, 0x06]); // cipher_len = 6
        data.extend_from_slice(&[0x00, 0x10]); // conn_id_len = 16
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // certificate
        data.extend_from_slice(&[0x07, 0x00, 0xC0]); // cipher 1
        data.extend_from_slice(&[0x05, 0x00, 0x80]); // cipher 2
        data.extend_from_slice(&[0x42; 16]); // connection_id

        let sh = Sslv2ServerHello::parse(&data).unwrap();
        assert_eq!(sh.session_id_hit, 0);
        assert_eq!(sh.certificate_type, 1);
        assert_eq!(sh.version, 0x0002);
        assert_eq!(sh.certificate, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(sh.cipher_specs.len(), 2);
        assert_eq!(sh.connection_id.len(), 16);
    }

    #[test]
    fn test_parse_sslv2_client_master_key() {
        let mut data = Vec::new();
        data.push(0x02); // msg_type
        data.extend_from_slice(&[0x05, 0x00, 0x80]); // cipher = RC4_128_WITH_MD5
        data.extend_from_slice(&[0x00, 0x00]); // clear_key_len = 0
        data.extend_from_slice(&[0x00, 0x04]); // encrypted_key_len = 4
        data.extend_from_slice(&[0x00, 0x00]); // key_arg_len = 0
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // encrypted key

        let cmk = Sslv2ClientMasterKey::parse(&data).unwrap();
        assert_eq!(cmk.cipher_suite, 0x050080);
        assert!(cmk.clear_key.is_empty());
        assert_eq!(cmk.encrypted_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(cmk.key_arg.is_empty());
    }

    #[test]
    fn test_message_type_names() {
        assert_eq!(Sslv2MessageType::CLIENT_HELLO.name(), "CLIENT_HELLO");
        assert_eq!(Sslv2MessageType::SERVER_HELLO.name(), "SERVER_HELLO");
        assert_eq!(
            Sslv2MessageType::CLIENT_MASTER_KEY.name(),
            "CLIENT_MASTER_KEY"
        );
    }
}
