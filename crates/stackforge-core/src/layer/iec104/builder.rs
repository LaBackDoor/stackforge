//! IEC 60870-5-104 APDU builder.
//!
//! Provides a fluent API for constructing IEC 104 APDUs (Application Protocol
//! Data Units) in I-format, S-format, and U-format.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::iec104::builder::Iec104Builder;
//!
//! // Default: U-format STARTDT_ACT
//! let pkt = Iec104Builder::new().build();
//! assert_eq!(pkt, b"\x68\x04\x07\x00\x00\x00");
//!
//! // S-format with RSN=5
//! let pkt = Iec104Builder::new().s_format().rx(5).build();
//! assert_eq!(pkt.len(), 6);
//!
//! // I-format with ASDU
//! let pkt = Iec104Builder::new()
//!     .i_format()
//!     .tx(0)
//!     .rx(0)
//!     .type_id(100) // C_IC_NA_1
//!     .cot(6)       // activation
//!     .common_addr(1)
//!     .ioa(0)
//!     .asdu_data(vec![20]) // QOI=20 (station interrogation)
//!     .build();
//! ```

use super::ApduType;

/// U-format subtype byte values.
pub const U_STARTDT_ACT: u8 = 0x07;
pub const U_STARTDT_CON: u8 = 0x0B;
pub const U_STOPDT_ACT: u8 = 0x13;
pub const U_STOPDT_CON: u8 = 0x23;
pub const U_TESTFR_ACT: u8 = 0x43;
pub const U_TESTFR_CON: u8 = 0x83;

/// Builder for IEC 60870-5-104 APDUs.
///
/// By default, builds a U-format STARTDT_ACT message (`\x68\x04\x07\x00\x00\x00`).
#[derive(Debug, Clone)]
pub struct Iec104Builder {
    apdu_type: ApduType,
    tx: u16,
    rx: u16,
    u_type: u8,
    // ASDU fields (for I-format)
    type_id: u8,
    sq: bool,
    num_objects: u8,
    cot: u8,
    cot_test: bool,
    cot_negative: bool,
    org: u8,
    common_addr: u16,
    ioa: u32,
    asdu_data: Vec<u8>,
}

impl Default for Iec104Builder {
    fn default() -> Self {
        Self {
            apdu_type: ApduType::U,
            tx: 0,
            rx: 0,
            u_type: U_STARTDT_ACT,
            type_id: 0,
            sq: false,
            num_objects: 0,
            cot: 0,
            cot_test: false,
            cot_negative: false,
            org: 0,
            common_addr: 0,
            ioa: 0,
            asdu_data: Vec::new(),
        }
    }
}

impl Iec104Builder {
    /// Create a new IEC 104 builder. Default: U-format STARTDT_ACT.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ========================================================================
    // APDU type setters
    // ========================================================================

    /// Set APDU type to I-format (Information transfer).
    #[must_use]
    pub fn i_format(mut self) -> Self {
        self.apdu_type = ApduType::I;
        self
    }

    /// Set APDU type to S-format (Supervisory).
    #[must_use]
    pub fn s_format(mut self) -> Self {
        self.apdu_type = ApduType::S;
        self
    }

    /// Set APDU type to U-format (Unnumbered).
    #[must_use]
    pub fn u_format(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self
    }

    // ========================================================================
    // Sequence number setters
    // ========================================================================

    /// Set send sequence number (I-format only).
    #[must_use]
    pub fn tx(mut self, n: u16) -> Self {
        self.tx = n;
        self
    }

    /// Set receive sequence number (I-format and S-format).
    #[must_use]
    pub fn rx(mut self, n: u16) -> Self {
        self.rx = n;
        self
    }

    // ========================================================================
    // U-format subtype setters
    // ========================================================================

    /// Set U-format subtype byte directly.
    #[must_use]
    pub fn u_type(mut self, t: u8) -> Self {
        self.u_type = t;
        self.apdu_type = ApduType::U;
        self
    }

    /// U-format: STARTDT activation.
    #[must_use]
    pub fn startdt_act(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_STARTDT_ACT;
        self
    }

    /// U-format: STARTDT confirmation.
    #[must_use]
    pub fn startdt_con(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_STARTDT_CON;
        self
    }

    /// U-format: STOPDT activation.
    #[must_use]
    pub fn stopdt_act(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_STOPDT_ACT;
        self
    }

    /// U-format: STOPDT confirmation.
    #[must_use]
    pub fn stopdt_con(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_STOPDT_CON;
        self
    }

    /// U-format: TESTFR activation.
    #[must_use]
    pub fn testfr_act(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_TESTFR_ACT;
        self
    }

    /// U-format: TESTFR confirmation.
    #[must_use]
    pub fn testfr_con(mut self) -> Self {
        self.apdu_type = ApduType::U;
        self.u_type = U_TESTFR_CON;
        self
    }

    // ========================================================================
    // ASDU field setters (I-format)
    // ========================================================================

    /// Set ASDU type ID.
    #[must_use]
    pub fn type_id(mut self, t: u8) -> Self {
        self.type_id = t;
        self
    }

    /// Set structure qualifier (SQ bit).
    #[must_use]
    pub fn sq(mut self, b: bool) -> Self {
        self.sq = b;
        self
    }

    /// Set number of information objects.
    #[must_use]
    pub fn num_objects(mut self, n: u8) -> Self {
        self.num_objects = n;
        self
    }

    /// Set cause of transmission.
    #[must_use]
    pub fn cot(mut self, c: u8) -> Self {
        self.cot = c;
        self
    }

    /// Set COT test flag.
    #[must_use]
    pub fn cot_test(mut self, b: bool) -> Self {
        self.cot_test = b;
        self
    }

    /// Set COT negative flag.
    #[must_use]
    pub fn cot_negative(mut self, b: bool) -> Self {
        self.cot_negative = b;
        self
    }

    /// Set originator address.
    #[must_use]
    pub fn org(mut self, o: u8) -> Self {
        self.org = o;
        self
    }

    /// Set common address.
    #[must_use]
    pub fn common_addr(mut self, a: u16) -> Self {
        self.common_addr = a;
        self
    }

    /// Set information object address (3 bytes, 0-16777215).
    #[must_use]
    pub fn ioa(mut self, a: u32) -> Self {
        self.ioa = a & 0x00FF_FFFF;
        self
    }

    /// Set raw information element data (appended after the IOA in the ASDU).
    #[must_use]
    pub fn asdu_data(mut self, d: Vec<u8>) -> Self {
        self.asdu_data = d;
        self
    }

    // ========================================================================
    // Build
    // ========================================================================

    /// Build the APDU into a byte vector.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        match self.apdu_type {
            ApduType::U => self.build_u(),
            ApduType::S => self.build_s(),
            ApduType::I => self.build_i(),
        }
    }

    fn build_u(&self) -> Vec<u8> {
        vec![
            0x68,        // Start byte
            0x04,        // APDU length (always 4 for U-format)
            self.u_type, // Control field byte 1
            0x00,        // Control field byte 2
            0x00,        // Control field byte 3
            0x00,        // Control field byte 4
        ]
    }

    fn build_s(&self) -> Vec<u8> {
        let rx_shifted = self.rx << 1;
        let rx_bytes = rx_shifted.to_le_bytes();
        vec![
            0x68,        // Start byte
            0x04,        // APDU length (always 4 for S-format)
            0x01,        // Control field byte 1: bits 0-1 = 01 (S-format)
            0x00,        // Control field byte 2
            rx_bytes[0], // RSN low
            rx_bytes[1], // RSN high
        ]
    }

    fn build_i(&self) -> Vec<u8> {
        // Build control field
        let tx_shifted = self.tx << 1;
        let rx_shifted = self.rx << 1;
        let tx_bytes = tx_shifted.to_le_bytes();
        let rx_bytes = rx_shifted.to_le_bytes();

        // Build ASDU
        let mut asdu = Vec::new();
        asdu.push(self.type_id);

        // Variable structure qualifier: SQ(1) | num_objects(7)
        let vsq = if self.sq { 0x80 } else { 0x00 } | (self.num_objects & 0x7F);
        asdu.push(vsq);

        // Cause of transmission (2 bytes LE)
        let mut cot_byte = self.cot & 0x3F;
        if self.cot_negative {
            cot_byte |= 0x40;
        }
        if self.cot_test {
            cot_byte |= 0x80;
        }
        asdu.push(cot_byte);
        asdu.push(self.org);

        // Common address (2 bytes LE)
        let ca_bytes = self.common_addr.to_le_bytes();
        asdu.push(ca_bytes[0]);
        asdu.push(ca_bytes[1]);

        // IOA (3 bytes LE)
        asdu.push((self.ioa & 0xFF) as u8);
        asdu.push(((self.ioa >> 8) & 0xFF) as u8);
        asdu.push(((self.ioa >> 16) & 0xFF) as u8);

        // Information element data
        asdu.extend_from_slice(&self.asdu_data);

        // Compute total APDU length: 4 (control) + ASDU length
        let apdu_length = (4 + asdu.len()) as u8;

        let mut result = Vec::with_capacity(2 + apdu_length as usize);
        result.push(0x68); // Start byte
        result.push(apdu_length); // APDU length
        result.push(tx_bytes[0]); // SSN low
        result.push(tx_bytes[1]); // SSN high
        result.push(rx_bytes[0]); // RSN low
        result.push(rx_bytes[1]); // RSN high
        result.extend_from_slice(&asdu);
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_startdt_act() {
        let pkt = Iec104Builder::new().build();
        assert_eq!(pkt, b"\x68\x04\x07\x00\x00\x00");
    }

    #[test]
    fn test_u_format_variants() {
        assert_eq!(
            Iec104Builder::new().startdt_act().build(),
            b"\x68\x04\x07\x00\x00\x00"
        );
        assert_eq!(
            Iec104Builder::new().startdt_con().build(),
            b"\x68\x04\x0B\x00\x00\x00"
        );
        assert_eq!(
            Iec104Builder::new().stopdt_act().build(),
            b"\x68\x04\x13\x00\x00\x00"
        );
        assert_eq!(
            Iec104Builder::new().stopdt_con().build(),
            b"\x68\x04\x23\x00\x00\x00"
        );
        assert_eq!(
            Iec104Builder::new().testfr_act().build(),
            b"\x68\x04\x43\x00\x00\x00"
        );
        assert_eq!(
            Iec104Builder::new().testfr_con().build(),
            b"\x68\x04\x83\x00\x00\x00"
        );
    }

    #[test]
    fn test_s_format() {
        let pkt = Iec104Builder::new().s_format().rx(5).build();
        assert_eq!(pkt.len(), 6);
        assert_eq!(pkt[0], 0x68);
        assert_eq!(pkt[1], 0x04);
        assert_eq!(pkt[2], 0x01); // S-format marker
        assert_eq!(pkt[3], 0x00);
        // rx=5 → shifted = 10 = 0x000A LE
        assert_eq!(pkt[4], 0x0A);
        assert_eq!(pkt[5], 0x00);
    }

    #[test]
    fn test_i_format_interrogation() {
        let pkt = Iec104Builder::new()
            .i_format()
            .tx(0)
            .rx(0)
            .type_id(100) // C_IC_NA_1
            .num_objects(1)
            .cot(6) // activation
            .common_addr(1)
            .ioa(0)
            .asdu_data(vec![20]) // QOI=20
            .build();

        assert_eq!(pkt[0], 0x68); // Start byte
        // Length = 4 (ctrl) + 10 (ASDU: 1+1+2+2+3+1) = 14
        assert_eq!(pkt[1], 14);
        // Control field: tx=0<<1=0, rx=0<<1=0
        assert_eq!(pkt[2], 0x00);
        assert_eq!(pkt[3], 0x00);
        assert_eq!(pkt[4], 0x00);
        assert_eq!(pkt[5], 0x00);
        // ASDU
        assert_eq!(pkt[6], 100); // type_id
        assert_eq!(pkt[7], 1); // VSQ: SQ=0, num=1
        assert_eq!(pkt[8], 6); // COT: activation
        assert_eq!(pkt[9], 0); // ORG
        assert_eq!(pkt[10], 1); // Common addr low
        assert_eq!(pkt[11], 0); // Common addr high
        assert_eq!(pkt[12], 0); // IOA byte 0
        assert_eq!(pkt[13], 0); // IOA byte 1
        assert_eq!(pkt[14], 0); // IOA byte 2
        assert_eq!(pkt[15], 20); // QOI
    }

    #[test]
    fn test_i_format_sequence_numbers() {
        let pkt = Iec104Builder::new()
            .i_format()
            .tx(100)
            .rx(50)
            .type_id(1)
            .num_objects(1)
            .cot(3)
            .common_addr(1)
            .ioa(1)
            .asdu_data(vec![0x01])
            .build();

        // tx=100 → shifted=200=0x00C8 LE → [0xC8, 0x00]
        assert_eq!(pkt[2], 0xC8);
        assert_eq!(pkt[3], 0x00);
        // rx=50 → shifted=100=0x0064 LE → [0x64, 0x00]
        assert_eq!(pkt[4], 0x64);
        assert_eq!(pkt[5], 0x00);
    }

    #[test]
    fn test_cot_flags() {
        let pkt = Iec104Builder::new()
            .i_format()
            .type_id(45)
            .num_objects(1)
            .cot(7)
            .cot_test(true)
            .cot_negative(true)
            .common_addr(1)
            .ioa(1)
            .asdu_data(vec![0x01])
            .build();

        // COT byte: cause=7, negative=0x40, test=0x80 → 0xC7
        assert_eq!(pkt[8], 0xC7);
    }

    #[test]
    fn test_sq_flag() {
        let pkt = Iec104Builder::new()
            .i_format()
            .type_id(1)
            .sq(true)
            .num_objects(10)
            .cot(20)
            .common_addr(1)
            .ioa(100)
            .build();

        // VSQ: SQ=1, num=10 → 0x80 | 0x0A = 0x8A
        assert_eq!(pkt[7], 0x8A);
    }

    #[test]
    fn test_ioa_3_byte_encoding() {
        let pkt = Iec104Builder::new()
            .i_format()
            .type_id(1)
            .num_objects(1)
            .cot(3)
            .common_addr(1)
            .ioa(0x010203)
            .asdu_data(vec![0x01])
            .build();

        // IOA: 0x010203 LE → [0x03, 0x02, 0x01]
        assert_eq!(pkt[12], 0x03);
        assert_eq!(pkt[13], 0x02);
        assert_eq!(pkt[14], 0x01);
    }
}
