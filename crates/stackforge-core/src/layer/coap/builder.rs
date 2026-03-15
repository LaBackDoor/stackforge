//! CoAP packet builder.
//!
//! Provides a fluent API for constructing CoAP messages (RFC 7252).
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::coap::builder::CoapBuilder;
//!
//! // Default: CON GET with MID=0, no token, no options, no payload.
//! let pkt = CoapBuilder::new().build();
//! assert_eq!(pkt, vec![0x40, 0x01, 0x00, 0x00]);
//!
//! // CON PUT to /sensor/temp with JSON payload.
//! let pkt = CoapBuilder::new()
//!     .put()
//!     .msg_id(0x1234)
//!     .token(vec![0xAB, 0xCD])
//!     .uri_path("sensor/temp")
//!     .content_format(50) // application/json
//!     .payload(b"25.5".to_vec())
//!     .build();
//! assert!(pkt.len() > 4);
//! ```

use super::{
    ACK, CODE_DELETE, CODE_GET, CODE_POST, CODE_PUT, CON, NON, OPT_CONTENT_FORMAT, OPT_URI_PATH,
    RST,
};

/// Builder for CoAP packets.
///
/// By default, builds a Confirmable (CON) GET request with message ID 0,
/// no token, no options, and no payload.
#[derive(Debug, Clone)]
pub struct CoapBuilder {
    /// CoAP version (default: 1).
    ver: u8,
    /// Message type: CON=0, NON=1, ACK=2, RST=3.
    msg_type: u8,
    /// Code byte: class(3 bits).detail(5 bits).
    code: u8,
    /// Message ID (16-bit).
    msg_id: u16,
    /// Token bytes (0-8).
    token: Vec<u8>,
    /// Options as (option_number, value) pairs. Sorted by number at build time.
    options: Vec<(u16, Vec<u8>)>,
    /// Payload bytes.
    payload: Vec<u8>,
}

impl Default for CoapBuilder {
    fn default() -> Self {
        Self {
            ver: 1,
            msg_type: CON,
            code: CODE_GET,
            msg_id: 0,
            token: Vec::new(),
            options: Vec::new(),
            payload: Vec::new(),
        }
    }
}

impl CoapBuilder {
    /// Create a new CoAP builder. Defaults to CON GET with MID=0.
    ///
    /// ```rust
    /// use stackforge_core::layer::coap::builder::CoapBuilder;
    ///
    /// let pkt = CoapBuilder::new().build();
    /// // Ver=1, Type=CON, TKL=0 → 0x40; Code=GET → 0x01; MID=0 → 0x00 0x00
    /// assert_eq!(pkt, vec![0x40, 0x01, 0x00, 0x00]);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Message type setters ==========

    /// Set message type to Confirmable (CON, 0).
    #[must_use]
    pub fn con(mut self) -> Self {
        self.msg_type = CON;
        self
    }

    /// Set message type to Non-confirmable (NON, 1).
    #[must_use]
    pub fn non(mut self) -> Self {
        self.msg_type = NON;
        self
    }

    /// Set message type to Acknowledgement (ACK, 2).
    #[must_use]
    pub fn ack(mut self) -> Self {
        self.msg_type = ACK;
        self
    }

    /// Set message type to Reset (RST, 3).
    #[must_use]
    pub fn rst(mut self) -> Self {
        self.msg_type = RST;
        self
    }

    /// Set the raw message type value (0-3).
    #[must_use]
    pub fn msg_type(mut self, t: u8) -> Self {
        self.msg_type = t;
        self
    }

    // ========== Code setters ==========

    /// Set code to GET (0.01).
    #[must_use]
    pub fn get(mut self) -> Self {
        self.code = CODE_GET;
        self
    }

    /// Set code to POST (0.02).
    #[must_use]
    pub fn post(mut self) -> Self {
        self.code = CODE_POST;
        self
    }

    /// Set code to PUT (0.03).
    #[must_use]
    pub fn put(mut self) -> Self {
        self.code = CODE_PUT;
        self
    }

    /// Set code to DELETE (0.04).
    #[must_use]
    pub fn delete(mut self) -> Self {
        self.code = CODE_DELETE;
        self
    }

    /// Set the raw code from class and detail.
    ///
    /// The code byte is encoded as `(class << 5) | detail`.
    #[must_use]
    pub fn code(mut self, class: u8, detail: u8) -> Self {
        self.code = ((class & 0x07) << 5) | (detail & 0x1F);
        self
    }

    // ========== Other field setters ==========

    /// Set the message ID.
    #[must_use]
    pub fn msg_id(mut self, id: u16) -> Self {
        self.msg_id = id;
        self
    }

    /// Set the token bytes (0-8 bytes).
    #[must_use]
    pub fn token(mut self, t: Vec<u8>) -> Self {
        self.token = t;
        self
    }

    // ========== Option setters ==========

    /// Add a raw option by number and value.
    #[must_use]
    pub fn option(mut self, number: u16, value: Vec<u8>) -> Self {
        self.options.push((number, value));
        self
    }

    /// Convenience: add Uri-Path option(s) for each path segment.
    ///
    /// The path is split on '/' and each non-empty segment becomes a
    /// separate Uri-Path option (number 11).
    ///
    /// ```rust
    /// use stackforge_core::layer::coap::builder::CoapBuilder;
    ///
    /// let pkt = CoapBuilder::new()
    ///     .uri_path("sensor/temp")
    ///     .build();
    /// // Should contain two Uri-Path options.
    /// assert!(pkt.len() > 4);
    /// ```
    #[must_use]
    pub fn uri_path(mut self, path: &str) -> Self {
        for segment in path.split('/') {
            if !segment.is_empty() {
                self.options
                    .push((OPT_URI_PATH, segment.as_bytes().to_vec()));
            }
        }
        self
    }

    /// Convenience: add a Content-Format option (number 12).
    ///
    /// Common values: 0 = text/plain, 40 = application/link-format,
    /// 41 = application/xml, 42 = application/octet-stream,
    /// 47 = application/exi, 50 = application/json, 60 = application/cbor.
    #[must_use]
    pub fn content_format(mut self, fmt: u16) -> Self {
        let value = if fmt == 0 {
            vec![]
        } else if fmt <= 0xFF {
            vec![fmt as u8]
        } else {
            fmt.to_be_bytes().to_vec()
        };
        self.options.push((OPT_CONTENT_FORMAT, value));
        self
    }

    /// Set the payload bytes.
    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    // ========== Build ==========

    /// Serialize the CoAP message into bytes.
    ///
    /// 1. Builds the 4-byte header.
    /// 2. Appends the token.
    /// 3. Sorts options by number and delta-encodes them.
    /// 4. If payload is non-empty, appends the 0xFF marker and payload.
    ///
    /// ```rust
    /// use stackforge_core::layer::coap::builder::CoapBuilder;
    ///
    /// let pkt = CoapBuilder::new().build();
    /// assert_eq!(pkt.len(), 4);
    /// assert_eq!(pkt[0] >> 6, 1); // version = 1
    /// assert_eq!((pkt[0] >> 4) & 0x03, 0); // type = CON
    /// assert_eq!(pkt[0] & 0x0F, 0); // TKL = 0
    /// assert_eq!(pkt[1], 1); // code = GET
    /// ```
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let tkl = self.token.len().min(8) as u8;

        // Estimate capacity.
        let mut buf = Vec::with_capacity(
            4 + self.token.len()
                + self.options.len() * 4
                + if self.payload.is_empty() {
                    0
                } else {
                    1 + self.payload.len()
                },
        );

        // Byte 0: [Ver(2)][Type(2)][TKL(4)]
        let byte0 = ((self.ver & 0x03) << 6) | ((self.msg_type & 0x03) << 4) | (tkl & 0x0F);
        buf.push(byte0);

        // Byte 1: Code
        buf.push(self.code);

        // Bytes 2-3: Message ID
        buf.extend_from_slice(&self.msg_id.to_be_bytes());

        // Token
        buf.extend_from_slice(&self.token[..tkl as usize]);

        // Options: sort by number, then delta-encode.
        let mut sorted_opts = self.options.clone();
        sorted_opts.sort_by_key(|(num, _)| *num);

        let mut prev_number: u16 = 0;
        for (number, value) in &sorted_opts {
            let delta = number - prev_number;
            let opt_len = value.len();
            encode_option(&mut buf, delta, opt_len, value);
            prev_number = *number;
        }

        // Payload
        if !self.payload.is_empty() {
            buf.push(0xFF); // payload marker
            buf.extend_from_slice(&self.payload);
        }

        buf
    }
}

/// Encode a single CoAP option into `buf` using delta-encoding.
fn encode_option(buf: &mut Vec<u8>, delta: u16, opt_len: usize, value: &[u8]) {
    // Determine nibbles and extended bytes for delta.
    let (delta_nibble, delta_ext) = encode_extended(delta);
    // Determine nibbles and extended bytes for length.
    let (len_nibble, len_ext) = encode_extended(opt_len as u16);

    // First byte: [delta_nibble(4)][len_nibble(4)]
    buf.push((delta_nibble << 4) | len_nibble);

    // Extended delta bytes.
    if let Some(ext) = delta_ext {
        buf.extend_from_slice(&ext);
    }

    // Extended length bytes.
    if let Some(ext) = len_ext {
        buf.extend_from_slice(&ext);
    }

    // Option value.
    buf.extend_from_slice(value);
}

/// Encode a value using the CoAP extended encoding scheme.
///
/// Returns (nibble, optional extended bytes).
fn encode_extended(val: u16) -> (u8, Option<Vec<u8>>) {
    if val < 13 {
        (val as u8, None)
    } else if val < 269 {
        (13, Some(vec![(val - 13) as u8]))
    } else {
        let ext = (val - 269).to_be_bytes();
        (14, Some(ext.to_vec()))
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::coap::{
        COAP_MIN_HEADER_LEN, CODE_CONTENT, CODE_EMPTY, CoapLayer, OPT_MAX_AGE, OPT_URI_QUERY,
        is_coap_payload,
    };

    #[test]
    fn test_default_con_get() {
        let pkt = CoapBuilder::new().build();
        assert_eq!(pkt.len(), 4);
        // Ver=1, Type=CON(0), TKL=0 → 0x40
        assert_eq!(pkt[0], 0x40);
        // Code = GET (0.01) → 0x01
        assert_eq!(pkt[1], 0x01);
        // MID = 0
        assert_eq!(&pkt[2..4], &[0x00, 0x00]);
        // Must be valid CoAP.
        assert!(is_coap_payload(&pkt));
    }

    #[test]
    fn test_non_post() {
        let pkt = CoapBuilder::new().non().post().msg_id(0xBEEF).build();
        // Ver=1, Type=NON(1), TKL=0 → 0x50
        assert_eq!(pkt[0], 0x50);
        // Code = POST (0.02) → 0x02
        assert_eq!(pkt[1], 0x02);
        assert_eq!(&pkt[2..4], &[0xBE, 0xEF]);
    }

    #[test]
    fn test_ack_content() {
        let pkt = CoapBuilder::new()
            .ack()
            .code(2, 5) // 2.05 Content
            .msg_id(1)
            .build();
        // Ver=1, Type=ACK(2), TKL=0 → 0x60
        assert_eq!(pkt[0], 0x60);
        assert_eq!(pkt[1], CODE_CONTENT);
    }

    #[test]
    fn test_rst() {
        let pkt = CoapBuilder::new().rst().code(0, 0).msg_id(42).build();
        // Ver=1, Type=RST(3), TKL=0 → 0x70
        assert_eq!(pkt[0], 0x70);
        assert_eq!(pkt[1], CODE_EMPTY);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 42);
    }

    #[test]
    fn test_with_token() {
        let pkt = CoapBuilder::new()
            .token(vec![0xDE, 0xAD, 0xBE, 0xEF])
            .build();
        // TKL=4 → byte0 = 0x44
        assert_eq!(pkt[0], 0x44);
        assert_eq!(&pkt[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_uri_path_single() {
        let pkt = CoapBuilder::new().uri_path("temp").build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value, b"temp");
    }

    #[test]
    fn test_uri_path_multi_segment() {
        let pkt = CoapBuilder::new().uri_path("sensor/temp").build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value, b"sensor");
        assert_eq!(opts[1].number, OPT_URI_PATH);
        assert_eq!(opts[1].value, b"temp");
    }

    #[test]
    fn test_uri_path_leading_slash() {
        let pkt = CoapBuilder::new().uri_path("/sensor/temp").build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        // Leading slash produces empty segment which is skipped.
        assert_eq!(opts.len(), 2);
    }

    #[test]
    fn test_content_format() {
        let pkt = CoapBuilder::new().content_format(50).build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_CONTENT_FORMAT);
        assert_eq!(opts[0].value, vec![50]);
    }

    #[test]
    fn test_content_format_zero() {
        let pkt = CoapBuilder::new().content_format(0).build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_CONTENT_FORMAT);
        assert_eq!(opts[0].value, Vec::<u8>::new());
    }

    #[test]
    fn test_content_format_large() {
        let pkt = CoapBuilder::new().content_format(0x1234).build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].value, vec![0x12, 0x34]);
    }

    #[test]
    fn test_payload() {
        let pkt = CoapBuilder::new().payload(b"hello".to_vec()).build();
        let layer = CoapLayer::at_start(pkt.len());
        let payload = layer.payload(&pkt);
        assert_eq!(payload, Some(b"hello".as_slice()));
    }

    #[test]
    fn test_full_message() {
        let pkt = CoapBuilder::new()
            .con()
            .put()
            .msg_id(0x1234)
            .token(vec![0xAB, 0xCD])
            .uri_path("sensor/temp")
            .content_format(50)
            .payload(b"25.5".to_vec())
            .build();

        assert!(is_coap_payload(&pkt));

        let layer = CoapLayer::at_start(pkt.len());
        assert_eq!(layer.ver(&pkt).unwrap(), 1);
        assert_eq!(layer.msg_type(&pkt).unwrap(), 0); // CON
        assert_eq!(layer.tkl(&pkt).unwrap(), 2);
        assert_eq!(layer.code(&pkt).unwrap(), CODE_PUT);
        assert_eq!(layer.msg_id(&pkt).unwrap(), 0x1234);
        assert_eq!(layer.token(&pkt).unwrap(), &[0xAB, 0xCD]);

        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 3); // 2x Uri-Path + 1x Content-Format
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[0].value, b"sensor");
        assert_eq!(opts[1].number, OPT_URI_PATH);
        assert_eq!(opts[1].value, b"temp");
        assert_eq!(opts[2].number, OPT_CONTENT_FORMAT);

        assert_eq!(layer.payload(&pkt), Some(b"25.5".as_slice()));
    }

    #[test]
    fn test_options_sorted() {
        // Add options in reverse order; builder should sort them.
        let pkt = CoapBuilder::new()
            .option(OPT_URI_QUERY, b"key=val".to_vec())
            .option(OPT_URI_PATH, b"test".to_vec())
            .build();

        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 2);
        // Uri-Path (11) should come before Uri-Query (15).
        assert_eq!(opts[0].number, OPT_URI_PATH);
        assert_eq!(opts[1].number, OPT_URI_QUERY);
    }

    #[test]
    fn test_extended_delta_encoding() {
        // Option number 60 (Size1): delta=60 requires extended encoding (13+47).
        let pkt = CoapBuilder::new().option(60, vec![0x10]).build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, 60);
        assert_eq!(opts[0].value, vec![0x10]);
    }

    #[test]
    fn test_large_option_value() {
        // Option value > 12 bytes triggers extended length encoding.
        let long_value = vec![0x42; 20];
        let pkt = CoapBuilder::new()
            .option(OPT_URI_PATH, long_value.clone())
            .build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].value, long_value);
    }

    #[test]
    fn test_encode_extended() {
        // < 13: no extension.
        assert_eq!(encode_extended(0), (0, None));
        assert_eq!(encode_extended(12), (12, None));
        // 13-268: one extension byte.
        assert_eq!(encode_extended(13), (13, Some(vec![0])));
        assert_eq!(encode_extended(268), (13, Some(vec![255])));
        // >= 269: two extension bytes.
        assert_eq!(encode_extended(269), (14, Some(vec![0, 0])));
        assert_eq!(encode_extended(300), (14, Some(vec![0, 31])));
    }

    #[test]
    fn test_delete() {
        let pkt = CoapBuilder::new().delete().build();
        assert_eq!(pkt[1], CODE_DELETE);
    }

    #[test]
    fn test_no_payload_no_marker() {
        let pkt = CoapBuilder::new().build();
        // With no options and no payload, packet is exactly 4 bytes.
        assert_eq!(pkt.len(), COAP_MIN_HEADER_LEN);
        // No 0xFF marker present.
        assert!(!pkt.contains(&0xFF));
    }

    #[test]
    fn test_roundtrip_max_age_option() {
        // Max-Age (14) with value 60.
        let pkt = CoapBuilder::new().option(OPT_MAX_AGE, vec![0x3C]).build();
        let layer = CoapLayer::at_start(pkt.len());
        let opts = layer.options(&pkt);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].number, OPT_MAX_AGE);
        assert_eq!(opts[0].value, vec![0x3C]);
    }
}
