//! S7comm packet builder.
//!
//! Provides a fluent API for constructing S7 Communication Protocol packets.
//!
//! # Examples
//!
//! ```rust
//! use stackforge_core::layer::s7comm::builder::S7CommBuilder;
//!
//! // Default: Job with Setup Communication
//! let pkt = S7CommBuilder::new().build();
//! assert_eq!(pkt[0], 0x32); // protocol_id
//! assert_eq!(pkt[1], 0x01); // rosctr = Job
//! assert_eq!(pkt[10], 0xF0); // function = Setup Communication
//!
//! // Ack_Data with Setup Communication
//! let pkt = S7CommBuilder::ack_data().pdu_ref(1).build();
//! assert_eq!(pkt[1], 0x03); // rosctr = Ack_Data
//! assert_eq!(pkt.len(), 12 + 1); // header(12) + function byte(1)
//! ```

use super::{S7COMM_MAGIC, function, rosctr};

/// Builder for S7comm packets.
#[derive(Debug, Clone)]
pub struct S7CommBuilder {
    /// ROSCTR (message type). Default: Job (0x01).
    rosctr: u8,
    /// PDU Reference. Default: 0.
    pdu_ref: u16,
    /// Error class (for Ack_Data). Default: 0.
    error_class: u8,
    /// Error code (for Ack_Data). Default: 0.
    error_code: u8,
    /// Parameter area bytes.
    parameters: Vec<u8>,
    /// Data area bytes.
    data: Vec<u8>,
}

impl Default for S7CommBuilder {
    fn default() -> Self {
        Self {
            rosctr: rosctr::JOB,
            pdu_ref: 0,
            error_class: 0,
            error_code: 0,
            parameters: vec![function::SETUP_COMMUNICATION],
            data: Vec::new(),
        }
    }
}

impl S7CommBuilder {
    /// Create a new S7comm builder. Default: Job with Setup Communication.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a Job builder.
    #[must_use]
    pub fn job() -> Self {
        Self {
            rosctr: rosctr::JOB,
            ..Self::default()
        }
    }

    /// Create an Ack_Data builder.
    #[must_use]
    pub fn ack_data() -> Self {
        Self {
            rosctr: rosctr::ACK_DATA,
            ..Self::default()
        }
    }

    /// Create a Userdata builder.
    #[must_use]
    pub fn userdata() -> Self {
        Self {
            rosctr: rosctr::USERDATA,
            parameters: vec![function::CPU_SERVICES],
            ..Self::default()
        }
    }

    /// Set the ROSCTR (message type).
    #[must_use]
    pub fn rosctr(mut self, rosctr: u8) -> Self {
        self.rosctr = rosctr;
        self
    }

    /// Set the PDU reference.
    #[must_use]
    pub fn pdu_ref(mut self, pdu_ref: u16) -> Self {
        self.pdu_ref = pdu_ref;
        self
    }

    /// Set the error class (for Ack_Data).
    #[must_use]
    pub fn error_class(mut self, ec: u8) -> Self {
        self.error_class = ec;
        self
    }

    /// Set the error code (for Ack_Data).
    #[must_use]
    pub fn error_code(mut self, ec: u8) -> Self {
        self.error_code = ec;
        self
    }

    /// Set the function code (replaces the first byte of parameters).
    #[must_use]
    pub fn function(mut self, func: u8) -> Self {
        if self.parameters.is_empty() {
            self.parameters.push(func);
        } else {
            self.parameters[0] = func;
        }
        self
    }

    /// Shorthand: set function to Setup Communication (0xF0).
    #[must_use]
    pub fn setup_communication(self) -> Self {
        self.function(function::SETUP_COMMUNICATION)
    }

    /// Shorthand: set function to Read Var (0x04).
    #[must_use]
    pub fn read_var(self) -> Self {
        self.function(function::READ_VAR)
    }

    /// Shorthand: set function to Write Var (0x05).
    #[must_use]
    pub fn write_var(self) -> Self {
        self.function(function::WRITE_VAR)
    }

    /// Set the raw parameter area bytes (replaces existing parameters).
    #[must_use]
    pub fn parameters(mut self, params: Vec<u8>) -> Self {
        self.parameters = params;
        self
    }

    /// Set the raw data area bytes.
    #[must_use]
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Check if building an Ack_Data message (which has error fields).
    fn is_ack_data(&self) -> bool {
        self.rosctr == rosctr::ACK_DATA
    }

    /// Compute the header size.
    fn header_size(&self) -> usize {
        if self.is_ack_data() {
            12 // 10 base + 2 error bytes
        } else {
            10
        }
    }

    /// Compute the total packet size.
    #[must_use]
    pub fn packet_size(&self) -> usize {
        self.header_size() + self.parameters.len() + self.data.len()
    }

    /// Serialize the S7comm packet into bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let total = self.packet_size();
        let mut buf = Vec::with_capacity(total);

        // Byte 0: Protocol ID
        buf.push(S7COMM_MAGIC);
        // Byte 1: ROSCTR
        buf.push(self.rosctr);
        // Bytes 2-3: Reserved
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Bytes 4-5: PDU Reference
        buf.extend_from_slice(&self.pdu_ref.to_be_bytes());
        // Bytes 6-7: Parameter Length
        let param_len = self.parameters.len() as u16;
        buf.extend_from_slice(&param_len.to_be_bytes());
        // Bytes 8-9: Data Length
        let data_len = self.data.len() as u16;
        buf.extend_from_slice(&data_len.to_be_bytes());

        // Ack_Data: error fields (bytes 10-11)
        if self.is_ack_data() {
            buf.push(self.error_class);
            buf.push(self.error_code);
        }

        // Parameter area
        buf.extend_from_slice(&self.parameters);

        // Data area
        buf.extend_from_slice(&self.data);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_job_setup() {
        let pkt = S7CommBuilder::new().build();

        assert_eq!(pkt[0], 0x32); // protocol_id
        assert_eq!(pkt[1], 0x01); // rosctr = Job
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0); // reserved
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0); // pdu_ref
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 1); // param_length = 1 (function byte)
        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 0); // data_length
        assert_eq!(pkt[10], 0xF0); // function = Setup Communication
        assert_eq!(pkt.len(), 11); // 10 header + 1 param
    }

    #[test]
    fn test_ack_data() {
        let pkt = S7CommBuilder::ack_data()
            .pdu_ref(1)
            .error_class(0)
            .error_code(0)
            .build();

        assert_eq!(pkt[0], 0x32);
        assert_eq!(pkt[1], 0x03); // Ack_Data
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1); // pdu_ref
        assert_eq!(pkt[10], 0x00); // error_class
        assert_eq!(pkt[11], 0x00); // error_code
        assert_eq!(pkt[12], 0xF0); // function
        assert_eq!(pkt.len(), 13); // 12 header + 1 param
    }

    #[test]
    fn test_job_read_var() {
        let pkt = S7CommBuilder::job().read_var().pdu_ref(2).build();

        assert_eq!(pkt[1], 0x01); // Job
        assert_eq!(pkt[10], 0x04); // Read Var
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 2); // pdu_ref
    }

    #[test]
    fn test_job_write_var() {
        let pkt = S7CommBuilder::job().write_var().build();
        assert_eq!(pkt[10], 0x05); // Write Var
    }

    #[test]
    fn test_userdata() {
        let pkt = S7CommBuilder::userdata().build();
        assert_eq!(pkt[1], 0x07); // Userdata
        assert_eq!(pkt[10], 0x00); // CPU Services
    }

    #[test]
    fn test_custom_parameters() {
        let params = vec![0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0];
        let pkt = S7CommBuilder::job().parameters(params.clone()).build();

        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 8); // param_length
        assert_eq!(&pkt[10..18], &params);
    }

    #[test]
    fn test_with_data() {
        let pkt = S7CommBuilder::job()
            .read_var()
            .data(vec![0xFF, 0x04, 0x00, 0x08, 0xDE, 0xAD])
            .build();

        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 6); // data_length
        assert_eq!(&pkt[11..17], &[0xFF, 0x04, 0x00, 0x08, 0xDE, 0xAD]);
    }

    #[test]
    fn test_ack_data_with_error() {
        let pkt = S7CommBuilder::ack_data()
            .error_class(0x81)
            .error_code(0x04)
            .build();

        assert_eq!(pkt[10], 0x81); // error_class
        assert_eq!(pkt[11], 0x04); // error_code
    }

    #[test]
    fn test_packet_size() {
        let b = S7CommBuilder::new();
        assert_eq!(b.packet_size(), 11); // 10 header + 1 param (function byte)

        let b = S7CommBuilder::ack_data();
        assert_eq!(b.packet_size(), 13); // 12 header + 1 param
    }

    #[test]
    fn test_setup_communication_shorthand() {
        let pkt = S7CommBuilder::job().setup_communication().build();
        assert_eq!(pkt[10], 0xF0);
    }
}
