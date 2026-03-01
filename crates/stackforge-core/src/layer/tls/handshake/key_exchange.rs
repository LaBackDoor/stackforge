//! TLS Key Exchange messages (ServerKeyExchange, ClientKeyExchange).

/// ServerKeyExchange message (type 12).
///
/// Content depends on the key exchange algorithm:
/// - DHE: dh_p, dh_g, dh_Ys, signature
/// - ECDHE: curve_type, named_curve, point, signature
#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    /// Raw key exchange parameters.
    pub params: Vec<u8>,
    /// Parsed parameters (if recognizable).
    pub parsed: Option<ServerKxParams>,
}

/// Parsed server key exchange parameters.
#[derive(Debug, Clone)]
pub enum ServerKxParams {
    /// Diffie-Hellman ephemeral parameters.
    Dhe {
        dh_p: Vec<u8>,
        dh_g: Vec<u8>,
        dh_ys: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Elliptic Curve Diffie-Hellman parameters.
    Ecdhe {
        curve_type: u8,
        named_curve: u16,
        point: Vec<u8>,
        signature: Vec<u8>,
    },
}

impl ServerKeyExchange {
    /// Parse from raw body bytes.
    pub fn parse(data: &[u8]) -> Self {
        // Try to parse as ECDHE first (curve_type=3 for named_curve)
        let parsed = if data.len() >= 4 && data[0] == 0x03 {
            Self::parse_ecdhe(data)
        } else {
            Self::parse_dhe(data)
        };

        Self {
            params: data.to_vec(),
            parsed,
        }
    }

    fn parse_ecdhe(data: &[u8]) -> Option<ServerKxParams> {
        if data.len() < 4 {
            return None;
        }

        let curve_type = data[0];
        let named_curve = u16::from_be_bytes([data[1], data[2]]);
        let point_len = data[3] as usize;

        if data.len() < 4 + point_len {
            return None;
        }
        let point = data[4..4 + point_len].to_vec();
        let rest = &data[4 + point_len..];

        // Remaining is the signature
        let signature = rest.to_vec();

        Some(ServerKxParams::Ecdhe {
            curve_type,
            named_curve,
            point,
            signature,
        })
    }

    fn parse_dhe(data: &[u8]) -> Option<ServerKxParams> {
        let mut offset = 0;

        if offset + 2 > data.len() {
            return None;
        }
        let p_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + p_len > data.len() {
            return None;
        }
        let dh_p = data[offset..offset + p_len].to_vec();
        offset += p_len;

        if offset + 2 > data.len() {
            return None;
        }
        let g_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + g_len > data.len() {
            return None;
        }
        let dh_g = data[offset..offset + g_len].to_vec();
        offset += g_len;

        if offset + 2 > data.len() {
            return None;
        }
        let ys_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + ys_len > data.len() {
            return None;
        }
        let dh_ys = data[offset..offset + ys_len].to_vec();
        offset += ys_len;

        let signature = data[offset..].to_vec();

        Some(ServerKxParams::Dhe {
            dh_p,
            dh_g,
            dh_ys,
            signature,
        })
    }

    pub fn build(&self) -> Vec<u8> {
        self.params.clone()
    }
}

/// ClientKeyExchange message (type 16).
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    /// Raw exchange key data.
    pub data: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn parse(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    pub fn build(&self) -> Vec<u8> {
        self.data.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ecdhe_ske() {
        let mut data = Vec::new();
        data.push(0x03); // curve_type = named_curve
        data.extend_from_slice(&[0x00, 0x17]); // secp256r1
        data.push(65); // point length
        data.extend_from_slice(&[0x04; 65]); // uncompressed point
        data.extend_from_slice(&[0xDE, 0xAD]); // signature stub

        let ske = ServerKeyExchange::parse(&data);
        match ske.parsed.unwrap() {
            ServerKxParams::Ecdhe {
                curve_type,
                named_curve,
                point,
                signature,
            } => {
                assert_eq!(curve_type, 0x03);
                assert_eq!(named_curve, 0x0017);
                assert_eq!(point.len(), 65);
                assert_eq!(signature, vec![0xDE, 0xAD]);
            },
            _ => panic!("Expected ECDHE"),
        }
    }

    #[test]
    fn test_parse_dhe_ske() {
        let mut data = Vec::new();
        // dh_p: length=4, value=0x01020304
        data.extend_from_slice(&[0x00, 0x04]);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // dh_g: length=1, value=0x02
        data.extend_from_slice(&[0x00, 0x01]);
        data.push(0x02);
        // dh_Ys: length=4
        data.extend_from_slice(&[0x00, 0x04]);
        data.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]);
        // signature
        data.extend_from_slice(&[0xFF, 0xFE]);

        let ske = ServerKeyExchange::parse(&data);
        match ske.parsed.unwrap() {
            ServerKxParams::Dhe {
                dh_p,
                dh_g,
                dh_ys,
                signature,
            } => {
                assert_eq!(dh_p, vec![0x01, 0x02, 0x03, 0x04]);
                assert_eq!(dh_g, vec![0x02]);
                assert_eq!(dh_ys, vec![0x05, 0x06, 0x07, 0x08]);
                assert_eq!(signature, vec![0xFF, 0xFE]);
            },
            _ => panic!("Expected DHE"),
        }
    }
}
