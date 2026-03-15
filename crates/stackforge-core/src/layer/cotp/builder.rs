//! COTP packet builder.
//!
//! Provides a fluent API for constructing COTP (ISO 8073) PDUs.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::cotp::builder::CotpBuilder;
//!
//! // Default: DT with EOT=1 -> \x02\xF0\x80
//! let pkt = CotpBuilder::new().build();
//! assert_eq!(pkt, b"\x02\xF0\x80");
//!
//! // Connection Request
//! let pkt = CotpBuilder::cr()
//!     .dst_ref(0x0000)
//!     .src_ref(0x000C)
//!     .build();
//! assert_eq!(pkt, b"\x06\xE0\x00\x00\x00\x0C\x00");
//! ```

/// Builder for COTP PDUs.
#[derive(Debug, Clone)]
pub struct CotpBuilder {
    /// PDU type byte (high nibble is type code).
    pdu_type: u8,
    /// Destination reference (for CR/CC/DR/DC).
    dst_ref: u16,
    /// Source reference (for CR/CC/DR/DC).
    src_ref: u16,
    /// Class + option byte (for CR/CC).
    class_option: u8,
    /// TPDU number (for DT, upper 7 bits).
    tpdu_nr: u8,
    /// End of transmission flag (for DT, bit 7 of byte 2).
    eot: bool,
    /// Raw parameter bytes (appended after the fixed header for CR/CC).
    params: Vec<u8>,
}

impl Default for CotpBuilder {
    fn default() -> Self {
        Self {
            pdu_type: 0xF0, // DT
            dst_ref: 0,
            src_ref: 0,
            class_option: 0,
            tpdu_nr: 0,
            eot: true, // Default DT with EOT=1
            params: Vec::new(),
        }
    }
}

impl CotpBuilder {
    /// Create a new COTP builder. Default: DT with EOT=1.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a DT (Data Transfer) builder with EOT=1.
    #[must_use]
    pub fn dt() -> Self {
        Self::default()
    }

    /// Create a CR (Connection Request) builder.
    #[must_use]
    pub fn cr() -> Self {
        Self {
            pdu_type: 0xE0,
            dst_ref: 0,
            src_ref: 0,
            class_option: 0,
            tpdu_nr: 0,
            eot: false,
            params: Vec::new(),
        }
    }

    /// Create a CC (Connection Confirm) builder.
    #[must_use]
    pub fn cc() -> Self {
        Self {
            pdu_type: 0xD0,
            dst_ref: 0,
            src_ref: 0,
            class_option: 0,
            tpdu_nr: 0,
            eot: false,
            params: Vec::new(),
        }
    }

    /// Set the PDU type byte.
    #[must_use]
    pub fn pdu_type(mut self, pdu_type: u8) -> Self {
        self.pdu_type = pdu_type;
        self
    }

    /// Set the destination reference (for CR/CC/DR/DC).
    #[must_use]
    pub fn dst_ref(mut self, dst_ref: u16) -> Self {
        self.dst_ref = dst_ref;
        self
    }

    /// Set the source reference (for CR/CC/DR/DC).
    #[must_use]
    pub fn src_ref(mut self, src_ref: u16) -> Self {
        self.src_ref = src_ref;
        self
    }

    /// Set the class+option byte (for CR/CC).
    #[must_use]
    pub fn class_option(mut self, class_option: u8) -> Self {
        self.class_option = class_option;
        self
    }

    /// Set the TPDU number (for DT, upper 7 bits of byte 2).
    #[must_use]
    pub fn tpdu_nr(mut self, nr: u8) -> Self {
        self.tpdu_nr = nr & 0x7F;
        self
    }

    /// Set the EOT flag (for DT).
    #[must_use]
    pub fn eot(mut self, eot: bool) -> Self {
        self.eot = eot;
        self
    }

    /// Set raw parameter bytes (appended after the fixed CR/CC header).
    #[must_use]
    pub fn params(mut self, params: Vec<u8>) -> Self {
        self.params = params;
        self
    }

    /// Check if this builder produces a DT PDU.
    fn is_dt(&self) -> bool {
        self.pdu_type & 0xF0 == 0xF0
    }

    /// Serialize the COTP PDU into bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        if self.is_dt() {
            // DT: LI=2, PDU type, TPDU-NR+EOT byte
            let nr_eot = (self.tpdu_nr & 0x7F) | if self.eot { 0x80 } else { 0x00 };
            vec![0x02, self.pdu_type, nr_eot]
        } else {
            // CR/CC/DR/DC: LI, PDU type, dst_ref(2), src_ref(2), class_option, [params]
            let fixed_len = 6 + self.params.len(); // excluding LI byte
            let li = fixed_len as u8;
            let mut buf = Vec::with_capacity(1 + fixed_len);

            buf.push(li);
            buf.push(self.pdu_type);
            buf.extend_from_slice(&self.dst_ref.to_be_bytes());
            buf.extend_from_slice(&self.src_ref.to_be_bytes());
            buf.push(self.class_option);
            buf.extend_from_slice(&self.params);

            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dt() {
        let pkt = CotpBuilder::new().build();
        // DT: LI=2, PDU=0xF0, nr=0|eot=1 -> 0x80
        assert_eq!(pkt, b"\x02\xF0\x80");
    }

    #[test]
    fn test_dt_explicit() {
        let pkt = CotpBuilder::dt().build();
        assert_eq!(pkt, b"\x02\xF0\x80");
    }

    #[test]
    fn test_dt_no_eot() {
        let pkt = CotpBuilder::dt().eot(false).build();
        assert_eq!(pkt, b"\x02\xF0\x00");
    }

    #[test]
    fn test_dt_with_tpdu_nr() {
        let pkt = CotpBuilder::dt().tpdu_nr(3).build();
        // nr=3, eot=1 -> 0x80 | 0x03 = 0x83
        assert_eq!(pkt, b"\x02\xF0\x83");
    }

    #[test]
    fn test_cr() {
        let pkt = CotpBuilder::cr().dst_ref(0x0000).src_ref(0x000C).build();
        // LI=6, PDU=0xE0, dst_ref=0x0000, src_ref=0x000C, class=0x00
        assert_eq!(pkt, b"\x06\xE0\x00\x00\x00\x0C\x00");
    }

    #[test]
    fn test_cc() {
        let pkt = CotpBuilder::cc().dst_ref(0x000C).src_ref(0x0001).build();
        // LI=6, PDU=0xD0, dst_ref=0x000C, src_ref=0x0001, class=0x00
        assert_eq!(pkt, b"\x06\xD0\x00\x0C\x00\x01\x00");
    }

    #[test]
    fn test_cr_with_params() {
        let pkt = CotpBuilder::cr()
            .dst_ref(0)
            .src_ref(1)
            .params(vec![0xC1, 0x02, 0x01, 0x00])
            .build();
        // LI = 6 + 4 = 10
        assert_eq!(pkt[0], 10); // LI
        assert_eq!(pkt[1], 0xE0); // CR
        assert_eq!(&pkt[7..], &[0xC1, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_cr_class_option() {
        let pkt = CotpBuilder::cr().class_option(0x40).build();
        assert_eq!(pkt[6], 0x40);
    }
}
