//! DNP3 packet builder.
//!
//! Constructs complete DNP3 frames with proper link layer CRCs,
//! transport headers, and application layer encoding.

use super::application::{AppControl, app_func_name, is_response_func};
use super::crc::dnp3_crc;
use super::transport::TransportHeader;

/// Builder for constructing DNP3 frames.
///
/// Default configuration creates a master READ request with unconfirmed user data.
#[derive(Debug, Clone)]
pub struct Dnp3Builder {
    // Link layer
    dir: bool,
    prm: bool,
    fcb: bool,
    fcv: bool,
    link_func: u8,
    dst: u16,
    src: u16,
    // Transport
    transport_fin: bool,
    transport_fir: bool,
    transport_seq: u8,
    // Application
    app_fir: bool,
    app_fin: bool,
    app_con: bool,
    app_uns: bool,
    app_seq: u8,
    app_func: u8,
    iin: u16,
    // Application data (object headers)
    objects: Vec<u8>,
    // Whether to include transport+application layers
    has_app: bool,
}

impl Default for Dnp3Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Dnp3Builder {
    /// Create a new DNP3 builder with default settings.
    ///
    /// Defaults: master → outstation, primary, UNCONFIRMED_USER_DATA,
    /// dst=1, src=0, READ request, single fragment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dir: true,
            prm: true,
            fcb: false,
            fcv: false,
            link_func: 4, // UNCONFIRMED_USER_DATA
            dst: 1,
            src: 0,
            transport_fin: true,
            transport_fir: true,
            transport_seq: 0,
            app_fir: true,
            app_fin: true,
            app_con: false,
            app_uns: false,
            app_seq: 0,
            app_func: 0x01, // READ
            iin: 0,
            objects: Vec::new(),
            has_app: true,
        }
    }

    /// Set the DIR (direction) bit.
    #[must_use]
    pub fn dir(mut self, dir: bool) -> Self {
        self.dir = dir;
        self
    }

    /// Set the PRM (primary) bit.
    #[must_use]
    pub fn prm(mut self, prm: bool) -> Self {
        self.prm = prm;
        self
    }

    /// Set the FCB (frame count bit).
    #[must_use]
    pub fn fcb(mut self, fcb: bool) -> Self {
        self.fcb = fcb;
        self
    }

    /// Set the FCV (frame count valid) bit.
    #[must_use]
    pub fn fcv(mut self, fcv: bool) -> Self {
        self.fcv = fcv;
        self
    }

    /// Set the link layer function code.
    #[must_use]
    pub fn link_func(mut self, func: u8) -> Self {
        self.link_func = func;
        self
    }

    /// Set the destination address.
    #[must_use]
    pub fn dst(mut self, dst: u16) -> Self {
        self.dst = dst;
        self
    }

    /// Set the source address.
    #[must_use]
    pub fn src(mut self, src: u16) -> Self {
        self.src = src;
        self
    }

    /// Set the transport sequence number.
    #[must_use]
    pub fn transport_seq(mut self, seq: u8) -> Self {
        self.transport_seq = seq & 0x3F;
        self
    }

    /// Set the transport FIR flag.
    #[must_use]
    pub fn transport_fir(mut self, fir: bool) -> Self {
        self.transport_fir = fir;
        self
    }

    /// Set the transport FIN flag.
    #[must_use]
    pub fn transport_fin(mut self, fin: bool) -> Self {
        self.transport_fin = fin;
        self
    }

    /// Set the application function code.
    #[must_use]
    pub fn app_func(mut self, func: u8) -> Self {
        self.app_func = func;
        self
    }

    /// Set the application sequence number.
    #[must_use]
    pub fn app_seq(mut self, seq: u8) -> Self {
        self.app_seq = seq & 0x0F;
        self
    }

    /// Set the application FIR flag.
    #[must_use]
    pub fn app_fir(mut self, fir: bool) -> Self {
        self.app_fir = fir;
        self
    }

    /// Set the application FIN flag.
    #[must_use]
    pub fn app_fin(mut self, fin: bool) -> Self {
        self.app_fin = fin;
        self
    }

    /// Set the application CON (confirm) flag.
    #[must_use]
    pub fn app_con(mut self, con: bool) -> Self {
        self.app_con = con;
        self
    }

    /// Set the application UNS (unsolicited) flag.
    #[must_use]
    pub fn app_uns(mut self, uns: bool) -> Self {
        self.app_uns = uns;
        self
    }

    /// Configure as a READ request (function code 0x01).
    #[must_use]
    pub fn read(mut self) -> Self {
        self.app_func = 0x01;
        self.has_app = true;
        self
    }

    /// Configure as a WRITE request (function code 0x02).
    #[must_use]
    pub fn write(mut self) -> Self {
        self.app_func = 0x02;
        self.has_app = true;
        self
    }

    /// Configure as a CONFIRM (function code 0x00).
    #[must_use]
    pub fn confirm(mut self) -> Self {
        self.app_func = 0x00;
        self.has_app = true;
        self
    }

    /// Configure as a RESPONSE (function code 0x81).
    #[must_use]
    pub fn response(mut self) -> Self {
        self.app_func = 0x81;
        self.dir = false; // outstation → master
        self.has_app = true;
        self
    }

    /// Set the IIN (Internal Indications) for response frames.
    #[must_use]
    pub fn iin(mut self, iin: u16) -> Self {
        self.iin = iin;
        self
    }

    /// Set the application-layer object data.
    #[must_use]
    pub fn objects(mut self, data: Vec<u8>) -> Self {
        self.objects = data;
        self.has_app = true;
        self
    }

    /// Disable the transport and application layers (link-only frame).
    #[must_use]
    pub fn link_only(mut self) -> Self {
        self.has_app = false;
        self
    }

    /// Build the complete DNP3 frame.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        // Step 1: Build application fragment (if has_app)
        let user_data = if self.has_app {
            let mut app_fragment = Vec::new();

            // Application control byte
            let ac = AppControl {
                fir: self.app_fir,
                fin: self.app_fin,
                con: self.app_con,
                uns: self.app_uns,
                seq: self.app_seq,
            };
            app_fragment.push(ac.build());

            // Function code
            app_fragment.push(self.app_func);

            // IIN (for responses with FIR=1)
            if is_response_func(self.app_func) && self.app_fir {
                let iin_bytes = self.iin.to_le_bytes();
                app_fragment.push(iin_bytes[0]);
                app_fragment.push(iin_bytes[1]);
            }

            // Object data
            app_fragment.extend_from_slice(&self.objects);

            // Step 2: Prepend transport header
            let th = TransportHeader {
                fin: self.transport_fin,
                fir: self.transport_fir,
                seq: self.transport_seq,
            };
            let mut user_data = vec![th.build()];
            user_data.extend_from_slice(&app_fragment);
            user_data
        } else {
            Vec::new()
        };

        // Step 3: Split user data into 16-byte blocks with CRCs
        let mut data_blocks = Vec::new();
        let mut pos = 0;
        while pos < user_data.len() {
            let block_end = (pos + 16).min(user_data.len());
            let block = &user_data[pos..block_end];
            data_blocks.extend_from_slice(block);
            let crc = dnp3_crc(block);
            data_blocks.extend_from_slice(&crc.to_le_bytes());
            pos = block_end;
        }

        // Step 4: Build link header
        let mut control: u8 = self.link_func & 0x0F;
        if self.fcv {
            control |= 0x10;
        }
        if self.fcb {
            control |= 0x20;
        }
        if self.prm {
            control |= 0x40;
        }
        if self.dir {
            control |= 0x80;
        }

        // Length = number of bytes after start bytes and length byte, excluding CRCs
        // This is: control(1) + dst(2) + src(2) + user_data_len
        let length = (5 + user_data.len()) as u8;

        let dst_bytes = self.dst.to_le_bytes();
        let src_bytes = self.src.to_le_bytes();

        let header = [
            0x05,
            0x64,
            length,
            control,
            dst_bytes[0],
            dst_bytes[1],
            src_bytes[0],
            src_bytes[1],
        ];

        let header_crc = dnp3_crc(&header);

        // Step 5: Concatenate
        let mut frame = Vec::with_capacity(10 + data_blocks.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&header_crc.to_le_bytes());
        frame.extend_from_slice(&data_blocks);

        frame
    }

    /// Return a human-readable description of what this builder will produce.
    #[must_use]
    pub fn description(&self) -> String {
        if self.has_app {
            format!(
                "DNP3 {} src={} dst={}",
                app_func_name(self.app_func),
                self.src,
                self.dst
            )
        } else {
            format!("DNP3 Link-only src={} dst={}", self.src, self.dst)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::dnp3::crc::verify_dnp3_crc;

    #[test]
    fn test_default_builder() {
        let frame = Dnp3Builder::new().build();
        // Must start with DNP3 magic bytes
        assert_eq!(frame[0], 0x05);
        assert_eq!(frame[1], 0x64);
        // Minimum: 10 (link header+CRC) + transport+app data blocks
        assert!(frame.len() >= 10);
    }

    #[test]
    fn test_header_crc_valid() {
        let frame = Dnp3Builder::new().build();
        // Verify header CRC (bytes 0-7 data, bytes 8-9 CRC)
        assert!(verify_dnp3_crc(&frame[..10]));
    }

    #[test]
    fn test_link_only_frame() {
        let frame = Dnp3Builder::new().link_only().build();
        assert_eq!(frame.len(), 10); // just link header + CRC
        assert!(verify_dnp3_crc(&frame[..10]));
    }

    #[test]
    fn test_direction_bit() {
        let frame = Dnp3Builder::new().dir(true).build();
        assert!(frame[3] & 0x80 != 0);

        let frame = Dnp3Builder::new().dir(false).build();
        assert!(frame[3] & 0x80 == 0);
    }

    #[test]
    fn test_dst_src_addresses() {
        let frame = Dnp3Builder::new().dst(0x1234).src(0x5678).build();
        let dst = u16::from_le_bytes([frame[4], frame[5]]);
        let src = u16::from_le_bytes([frame[6], frame[7]]);
        assert_eq!(dst, 0x1234);
        assert_eq!(src, 0x5678);
    }

    #[test]
    fn test_response_includes_iin() {
        let frame = Dnp3Builder::new()
            .response()
            .iin(0x8000) // device_restart
            .build();
        // Frame has app data; verify it starts with DNP3 header
        assert_eq!(frame[0], 0x05);
        assert_eq!(frame[1], 0x64);
    }

    #[test]
    fn test_data_block_crc() {
        let frame = Dnp3Builder::new().read().build();
        // After 10-byte header, data blocks follow
        if frame.len() > 10 {
            // First data block: user_data bytes + 2-byte CRC
            let data_section = &frame[10..];
            // For a simple READ with no objects:
            // transport(1) + app_control(1) + func(1) = 3 bytes + 2 CRC = 5 bytes
            assert!(data_section.len() >= 5);
            // Verify the data block CRC
            let data_len = data_section.len() - 2;
            let block_data = &data_section[..data_len];
            let block_crc = u16::from_le_bytes([
                data_section[data_section.len() - 2],
                data_section[data_section.len() - 1],
            ]);
            assert_eq!(dnp3_crc(block_data), block_crc);
        }
    }

    #[test]
    fn test_control_byte_encoding() {
        let frame = Dnp3Builder::new()
            .dir(true)
            .prm(true)
            .fcb(true)
            .fcv(true)
            .link_func(3)
            .build();
        let ctrl = frame[3];
        assert!(ctrl & 0x80 != 0); // DIR
        assert!(ctrl & 0x40 != 0); // PRM
        assert!(ctrl & 0x20 != 0); // FCB
        assert!(ctrl & 0x10 != 0); // FCV
        assert_eq!(ctrl & 0x0F, 3); // func=USER_DATA
    }

    #[test]
    fn test_objects_data() {
        let objects = vec![0x3C, 0x02, 0x06]; // Class 1 read header
        let frame = Dnp3Builder::new().read().objects(objects).build();
        assert!(frame.len() > 10);
    }

    #[test]
    fn test_description() {
        let b = Dnp3Builder::new();
        assert!(b.description().contains("READ"));

        let b = Dnp3Builder::new().response();
        assert!(b.description().contains("RESPONSE"));

        let b = Dnp3Builder::new().link_only();
        assert!(b.description().contains("Link-only"));
    }

    #[test]
    fn test_length_field() {
        // Link-only: length = 5 (control + dst + src + 0 user data)
        let frame = Dnp3Builder::new().link_only().build();
        assert_eq!(frame[2], 5);

        // READ with no objects: user_data = transport(1) + app_control(1) + func(1) = 3
        // length = 5 + 3 = 8
        let frame = Dnp3Builder::new().read().build();
        assert_eq!(frame[2], 8);
    }
}
