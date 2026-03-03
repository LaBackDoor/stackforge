//! IEEE 802.11 frame builder.
//!
//! Provides a fluent API for constructing 802.11 frames, including
//! convenience methods for common frame types (beacon, probe, auth, etc.).

use super::management::{
    Dot11AssocReq, Dot11AssocResp, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11ProbeResp,
};
use super::{DOT11_MGMT_HEADER_LEN, DOT11_WDS_HEADER_LEN, build_frame_control, crc32_ieee, types};
use crate::layer::dot11::data::Dot11QoS;
use crate::layer::dot11::ie::Dot11Elt;
use crate::layer::field::MacAddress;

// ============================================================================
// Dot11Builder
// ============================================================================

/// Builder for constructing 802.11 frames with a fluent API.
///
/// # Example
/// ```ignore
/// let frame = Dot11Builder::new()
///     .frame_type(types::frame_type::MANAGEMENT)
///     .subtype(types::mgmt_subtype::BEACON)
///     .addr1(MacAddress::BROADCAST)
///     .addr2(bssid)
///     .addr3(bssid)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Dot11Builder {
    /// Protocol version (default 0).
    pub proto: u8,
    /// Frame type (Management/Control/Data).
    pub frame_type: u8,
    /// Frame subtype.
    pub subtype: u8,
    /// Flags byte (`to_DS`, `from_DS`, retry, etc.).
    pub flags: u8,
    /// Duration/ID field.
    pub duration: u16,
    /// Address 1 (receiver/destination).
    pub addr1: MacAddress,
    /// Address 2 (transmitter/source).
    pub addr2: MacAddress,
    /// Address 3 (BSSID or other).
    pub addr3: MacAddress,
    /// Address 4 (only in WDS mode).
    pub addr4: Option<MacAddress>,
    /// Sequence Control field.
    pub seq_ctrl: u16,
    /// Frame body payload (management body, data, etc.).
    pub body: Vec<u8>,
    /// Whether to append FCS.
    pub with_fcs: bool,
}

impl Default for Dot11Builder {
    fn default() -> Self {
        Self {
            proto: 0,
            frame_type: types::frame_type::MANAGEMENT,
            subtype: 0,
            flags: 0,
            duration: 0,
            addr1: MacAddress::BROADCAST,
            addr2: MacAddress::ZERO,
            addr3: MacAddress::ZERO,
            addr4: None,
            seq_ctrl: 0,
            body: Vec::new(),
            with_fcs: false,
        }
    }
}

impl Dot11Builder {
    /// Create a new builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the protocol version (usually 0).
    #[must_use]
    pub fn proto(mut self, proto: u8) -> Self {
        self.proto = proto;
        self
    }

    /// Set the frame type.
    #[must_use]
    pub fn frame_type(mut self, ft: u8) -> Self {
        self.frame_type = ft;
        self
    }

    /// Set the frame subtype.
    #[must_use]
    pub fn subtype(mut self, st: u8) -> Self {
        self.subtype = st;
        self
    }

    /// Set the flags byte.
    #[must_use]
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Set the `to_DS` flag.
    #[must_use]
    pub fn to_ds(mut self, val: bool) -> Self {
        if val {
            self.flags |= types::fc_flags::TO_DS;
        } else {
            self.flags &= !types::fc_flags::TO_DS;
        }
        self
    }

    /// Set the `from_DS` flag.
    #[must_use]
    pub fn from_ds(mut self, val: bool) -> Self {
        if val {
            self.flags |= types::fc_flags::FROM_DS;
        } else {
            self.flags &= !types::fc_flags::FROM_DS;
        }
        self
    }

    /// Set the retry flag.
    #[must_use]
    pub fn retry(mut self, val: bool) -> Self {
        if val {
            self.flags |= types::fc_flags::RETRY;
        } else {
            self.flags &= !types::fc_flags::RETRY;
        }
        self
    }

    /// Set the protected frame flag.
    #[must_use]
    pub fn protected(mut self, val: bool) -> Self {
        if val {
            self.flags |= types::fc_flags::PROTECTED;
        } else {
            self.flags &= !types::fc_flags::PROTECTED;
        }
        self
    }

    /// Set the Duration/ID field.
    #[must_use]
    pub fn duration(mut self, dur: u16) -> Self {
        self.duration = dur;
        self
    }

    /// Set Address 1 (receiver/destination).
    #[must_use]
    pub fn addr1(mut self, mac: MacAddress) -> Self {
        self.addr1 = mac;
        self
    }

    /// Set Address 2 (transmitter/source).
    #[must_use]
    pub fn addr2(mut self, mac: MacAddress) -> Self {
        self.addr2 = mac;
        self
    }

    /// Set Address 3 (BSSID or other).
    #[must_use]
    pub fn addr3(mut self, mac: MacAddress) -> Self {
        self.addr3 = mac;
        self
    }

    /// Set Address 4 (WDS mode).
    #[must_use]
    pub fn addr4(mut self, mac: MacAddress) -> Self {
        self.addr4 = Some(mac);
        self
    }

    /// Set the Sequence Control field directly.
    #[must_use]
    pub fn seq_ctrl(mut self, sc: u16) -> Self {
        self.seq_ctrl = sc;
        self
    }

    /// Set sequence number and fragment number.
    #[must_use]
    pub fn seq_num(mut self, seq: u16, frag: u8) -> Self {
        self.seq_ctrl = ((seq & 0x0FFF) << 4) | u16::from(frag & 0x0F);
        self
    }

    /// Set the frame body (payload after the header).
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Enable FCS (Frame Check Sequence) appending.
    #[must_use]
    pub fn with_fcs(mut self, enable: bool) -> Self {
        self.with_fcs = enable;
        self
    }

    /// Calculate the header size based on frame type and addresses.
    #[must_use]
    pub fn header_size(&self) -> usize {
        if self.addr4.is_some() {
            DOT11_WDS_HEADER_LEN
        } else {
            match self.frame_type {
                types::frame_type::CONTROL => match self.subtype {
                    types::ctrl_subtype::ACK | types::ctrl_subtype::CTS => 10,
                    _ => 16,
                },
                _ => DOT11_MGMT_HEADER_LEN,
            }
        }
    }

    /// Build the frame bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let header_len = self.header_size();
        let total = header_len + self.body.len() + if self.with_fcs { 4 } else { 0 };
        let mut buf = vec![0u8; total];

        // Frame Control
        let fc = build_frame_control(self.proto, self.frame_type, self.subtype, self.flags);
        buf[0..2].copy_from_slice(&fc.to_le_bytes());

        // Duration/ID
        buf[2..4].copy_from_slice(&self.duration.to_le_bytes());

        // Address 1 (always present at offset 4)
        buf[4..10].copy_from_slice(self.addr1.as_bytes());

        // Address 2 (present if header_len >= 16)
        if header_len >= 16 {
            buf[10..16].copy_from_slice(self.addr2.as_bytes());
        }

        // Address 3 + Sequence Control (present if header_len >= 24)
        if header_len >= 24 {
            buf[16..22].copy_from_slice(self.addr3.as_bytes());
            buf[22..24].copy_from_slice(&self.seq_ctrl.to_le_bytes());
        }

        // Address 4 (present if header_len >= 30)
        if let Some(ref a4) = self.addr4
            && header_len >= 30
        {
            buf[24..30].copy_from_slice(a4.as_bytes());
        }

        // Body
        if !self.body.is_empty() {
            buf[header_len..header_len + self.body.len()].copy_from_slice(&self.body);
        }

        // FCS
        if self.with_fcs {
            let fcs_offset = header_len + self.body.len();
            let fcs = crc32_ieee(&buf[0..fcs_offset]);
            buf[fcs_offset..fcs_offset + 4].copy_from_slice(&fcs.to_le_bytes());
        }

        buf
    }

    // ========================================================================
    // Convenience constructors
    // ========================================================================

    /// Create a Beacon frame builder.
    #[must_use]
    pub fn beacon(bssid: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::BEACON)
            .addr1(MacAddress::BROADCAST)
            .addr2(bssid)
            .addr3(bssid)
    }

    /// Create a Probe Request frame builder.
    #[must_use]
    pub fn probe_request(src: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::PROBE_REQ)
            .addr1(MacAddress::BROADCAST)
            .addr2(src)
            .addr3(MacAddress::BROADCAST)
    }

    /// Create a Probe Response frame builder.
    #[must_use]
    pub fn probe_response(dst: MacAddress, bssid: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::PROBE_RESP)
            .addr1(dst)
            .addr2(bssid)
            .addr3(bssid)
    }

    /// Create an Authentication frame builder.
    #[must_use]
    pub fn authentication(dst: MacAddress, src: MacAddress, bssid: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::AUTH)
            .addr1(dst)
            .addr2(src)
            .addr3(bssid)
    }

    /// Create a Deauthentication frame builder.
    #[must_use]
    pub fn deauthentication(dst: MacAddress, src: MacAddress, bssid: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::DEAUTH)
            .addr1(dst)
            .addr2(src)
            .addr3(bssid)
    }

    /// Create an Association Request frame builder.
    #[must_use]
    pub fn assoc_request(dst: MacAddress, src: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::ASSOC_REQ)
            .addr1(dst)
            .addr2(src)
            .addr3(dst)
    }

    /// Create an ACK frame builder.
    #[must_use]
    pub fn ack(dst: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::CONTROL)
            .subtype(types::ctrl_subtype::ACK)
            .addr1(dst)
    }

    /// Create an RTS frame builder.
    #[must_use]
    pub fn rts(dst: MacAddress, src: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::CONTROL)
            .subtype(types::ctrl_subtype::RTS)
            .addr1(dst)
            .addr2(src)
    }

    /// Create a CTS frame builder.
    #[must_use]
    pub fn cts(dst: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::CONTROL)
            .subtype(types::ctrl_subtype::CTS)
            .addr1(dst)
    }

    /// Create a Data frame builder (to AP: `to_DS=1`).
    #[must_use]
    pub fn data_to_ap(bssid: MacAddress, src: MacAddress, dst: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::DATA)
            .subtype(types::data_subtype::DATA)
            .to_ds(true)
            .addr1(bssid)
            .addr2(src)
            .addr3(dst)
    }

    /// Create a Data frame builder (from AP: `from_DS=1`).
    #[must_use]
    pub fn data_from_ap(dst: MacAddress, bssid: MacAddress, src: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::DATA)
            .subtype(types::data_subtype::DATA)
            .from_ds(true)
            .addr1(dst)
            .addr2(bssid)
            .addr3(src)
    }

    /// Create a `QoS` Data frame builder (to AP: `to_DS=1`).
    #[must_use]
    pub fn qos_data_to_ap(bssid: MacAddress, src: MacAddress, dst: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::DATA)
            .subtype(types::data_subtype::QOS_DATA)
            .to_ds(true)
            .addr1(bssid)
            .addr2(src)
            .addr3(dst)
    }

    /// Create a WDS Data frame builder (`to_DS=1`, `from_DS=1`).
    #[must_use]
    pub fn data_wds(ra: MacAddress, ta: MacAddress, da: MacAddress, sa: MacAddress) -> Self {
        Self::new()
            .frame_type(types::frame_type::DATA)
            .subtype(types::data_subtype::DATA)
            .to_ds(true)
            .from_ds(true)
            .addr1(ra)
            .addr2(ta)
            .addr3(da)
            .addr4(sa)
    }

    // ========================================================================
    // Convenience: build with management body
    // ========================================================================

    /// Build a beacon frame with the given body parameters and IEs.
    #[must_use]
    pub fn build_beacon(
        bssid: MacAddress,
        timestamp: u64,
        beacon_interval: u16,
        capability: u16,
        ies: &[Dot11Elt],
    ) -> Vec<u8> {
        let mut body = Dot11Beacon::build(timestamp, beacon_interval, capability);
        body.extend(Dot11Elt::build_chain(ies));
        Self::beacon(bssid).body(body).build()
    }

    /// Build a probe request frame with the given IEs.
    #[must_use]
    pub fn build_probe_request(src: MacAddress, ies: &[Dot11Elt]) -> Vec<u8> {
        let body = Dot11Elt::build_chain(ies);
        Self::probe_request(src).body(body).build()
    }

    /// Build a probe response frame with the given body parameters and IEs.
    #[must_use]
    pub fn build_probe_response(
        dst: MacAddress,
        bssid: MacAddress,
        timestamp: u64,
        beacon_interval: u16,
        capability: u16,
        ies: &[Dot11Elt],
    ) -> Vec<u8> {
        let mut body = Dot11ProbeResp::build(timestamp, beacon_interval, capability);
        body.extend(Dot11Elt::build_chain(ies));
        Self::probe_response(dst, bssid).body(body).build()
    }

    /// Build an authentication frame.
    #[must_use]
    pub fn build_auth(
        dst: MacAddress,
        src: MacAddress,
        bssid: MacAddress,
        algo: u16,
        seqnum: u16,
        status: u16,
    ) -> Vec<u8> {
        let body = Dot11Auth::build(algo, seqnum, status);
        Self::authentication(dst, src, bssid).body(body).build()
    }

    /// Build a deauthentication frame.
    #[must_use]
    pub fn build_deauth(
        dst: MacAddress,
        src: MacAddress,
        bssid: MacAddress,
        reason: u16,
    ) -> Vec<u8> {
        let body = Dot11Deauth::build(reason);
        Self::deauthentication(dst, src, bssid).body(body).build()
    }

    /// Build an association request frame.
    #[must_use]
    pub fn build_assoc_request(
        dst: MacAddress,
        src: MacAddress,
        capability: u16,
        listen_interval: u16,
        ies: &[Dot11Elt],
    ) -> Vec<u8> {
        let mut body = Dot11AssocReq::build(capability, listen_interval);
        body.extend(Dot11Elt::build_chain(ies));
        Self::assoc_request(dst, src).body(body).build()
    }

    /// Build an association response frame.
    #[must_use]
    pub fn build_assoc_response(
        dst: MacAddress,
        bssid: MacAddress,
        capability: u16,
        status: u16,
        aid: u16,
        ies: &[Dot11Elt],
    ) -> Vec<u8> {
        let mut body = Dot11AssocResp::build(capability, status, aid);
        body.extend(Dot11Elt::build_chain(ies));
        Self::new()
            .frame_type(types::frame_type::MANAGEMENT)
            .subtype(types::mgmt_subtype::ASSOC_RESP)
            .addr1(dst)
            .addr2(bssid)
            .addr3(bssid)
            .body(body)
            .build()
    }

    /// Build a data frame with `QoS` header.
    #[must_use]
    pub fn build_qos_data(
        bssid: MacAddress,
        src: MacAddress,
        dst: MacAddress,
        tid: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Dot11QoS::build(tid, false, 0, false, 0);
        body.extend_from_slice(payload);
        Self::qos_data_to_ap(bssid, src, dst).body(body).build()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::dot11::Dot11Layer;

    #[test]
    fn test_builder_default() {
        let builder = Dot11Builder::new();
        assert_eq!(builder.frame_type, types::frame_type::MANAGEMENT);
        assert_eq!(builder.subtype, 0);
        assert_eq!(builder.flags, 0);
        assert_eq!(builder.duration, 0);
        assert_eq!(builder.addr1, MacAddress::BROADCAST);
        assert!(!builder.with_fcs);
    }

    #[test]
    fn test_builder_beacon() {
        let bssid = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let frame = Dot11Builder::beacon(bssid).build();

        assert_eq!(frame.len(), DOT11_MGMT_HEADER_LEN);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(
            layer.frame_type(&frame).unwrap(),
            types::frame_type::MANAGEMENT
        );
        assert_eq!(layer.subtype(&frame).unwrap(), types::mgmt_subtype::BEACON);
        assert!(layer.addr1(&frame).unwrap().is_broadcast());
        assert_eq!(layer.addr2(&frame).unwrap(), bssid);
        assert_eq!(layer.addr3(&frame).unwrap(), bssid);
    }

    #[test]
    fn test_builder_ack() {
        let dst = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let frame = Dot11Builder::ack(dst).build();

        assert_eq!(frame.len(), 10);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(
            layer.frame_type(&frame).unwrap(),
            types::frame_type::CONTROL
        );
        assert_eq!(layer.subtype(&frame).unwrap(), types::ctrl_subtype::ACK);
        assert_eq!(layer.addr1(&frame).unwrap(), dst);
    }

    #[test]
    fn test_builder_rts() {
        let dst = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let src = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let frame = Dot11Builder::rts(dst, src).build();

        assert_eq!(frame.len(), 16);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(
            layer.frame_type(&frame).unwrap(),
            types::frame_type::CONTROL
        );
        assert_eq!(layer.subtype(&frame).unwrap(), types::ctrl_subtype::RTS);
        assert_eq!(layer.addr1(&frame).unwrap(), dst);
        assert_eq!(layer.addr2(&frame).unwrap(), src);
    }

    #[test]
    fn test_builder_wds_data() {
        let ra = MacAddress::new([0x01; 6]);
        let ta = MacAddress::new([0x02; 6]);
        let da = MacAddress::new([0x03; 6]);
        let sa = MacAddress::new([0x04; 6]);
        let frame = Dot11Builder::data_wds(ra, ta, da, sa).build();

        assert_eq!(frame.len(), DOT11_WDS_HEADER_LEN);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(layer.frame_type(&frame).unwrap(), types::frame_type::DATA);
        assert!(layer.to_ds(&frame).unwrap());
        assert!(layer.from_ds(&frame).unwrap());
        assert!(layer.has_addr4(&frame));
        assert_eq!(layer.addr1(&frame).unwrap(), ra);
        assert_eq!(layer.addr2(&frame).unwrap(), ta);
        assert_eq!(layer.addr3(&frame).unwrap(), da);
        assert_eq!(layer.addr4(&frame).unwrap(), sa);
    }

    #[test]
    fn test_builder_with_body() {
        let bssid = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let body = vec![0xAA, 0xBB, 0xCC];
        let frame = Dot11Builder::beacon(bssid).body(body.clone()).build();

        assert_eq!(frame.len(), DOT11_MGMT_HEADER_LEN + 3);
        assert_eq!(&frame[DOT11_MGMT_HEADER_LEN..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_builder_with_fcs() {
        let bssid = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let frame = Dot11Builder::beacon(bssid).with_fcs(true).build();

        assert_eq!(frame.len(), DOT11_MGMT_HEADER_LEN + 4); // +4 for FCS

        // Verify FCS
        let data = &frame[..DOT11_MGMT_HEADER_LEN];
        let expected_fcs = crc32_ieee(data);
        let actual_fcs = u32::from_le_bytes([
            frame[DOT11_MGMT_HEADER_LEN],
            frame[DOT11_MGMT_HEADER_LEN + 1],
            frame[DOT11_MGMT_HEADER_LEN + 2],
            frame[DOT11_MGMT_HEADER_LEN + 3],
        ]);
        assert_eq!(actual_fcs, expected_fcs);
    }

    #[test]
    fn test_builder_flags() {
        let frame = Dot11Builder::new()
            .frame_type(types::frame_type::DATA)
            .subtype(0)
            .to_ds(true)
            .retry(true)
            .protected(true)
            .build();

        let layer = Dot11Layer::new(0, frame.len());
        assert!(layer.to_ds(&frame).unwrap());
        assert!(!layer.from_ds(&frame).unwrap());
        assert!(layer.retry(&frame).unwrap());
        assert!(layer.protected(&frame).unwrap());
    }

    #[test]
    fn test_builder_seq_num() {
        let frame = Dot11Builder::new().seq_num(100, 3).build();

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(layer.sequence_num(&frame).unwrap(), 100);
        assert_eq!(layer.fragment_num(&frame).unwrap(), 3);
    }

    #[test]
    fn test_build_beacon_convenience() {
        let bssid = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ies = vec![
            Dot11Elt::ssid("TestNetwork"),
            Dot11Elt::new(types::ie_id::RATES, vec![0x82, 0x84, 0x8B, 0x96]),
            Dot11Elt::new(types::ie_id::DS_PARAMETER_SET, vec![6]),
        ];

        let frame = Dot11Builder::build_beacon(bssid, 0, 100, 0x0431, &ies);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(
            layer.frame_type(&frame).unwrap(),
            types::frame_type::MANAGEMENT
        );
        assert_eq!(layer.subtype(&frame).unwrap(), types::mgmt_subtype::BEACON);

        // Verify body contains beacon fixed fields + IEs
        let body_offset = DOT11_MGMT_HEADER_LEN;
        // Timestamp (8) + Beacon Interval (2) + Capability (2) = 12
        assert!(frame.len() > body_offset + 12);
        // Check beacon interval
        let bi = u16::from_le_bytes([frame[body_offset + 8], frame[body_offset + 9]]);
        assert_eq!(bi, 100);
    }

    #[test]
    fn test_build_auth_convenience() {
        let dst = MacAddress::new([0xAA; 6]);
        let src = MacAddress::new([0xBB; 6]);
        let bssid = MacAddress::new([0xAA; 6]);

        let frame = Dot11Builder::build_auth(dst, src, bssid, 0, 1, 0);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(layer.subtype(&frame).unwrap(), types::mgmt_subtype::AUTH);

        // Check auth body
        let body_offset = DOT11_MGMT_HEADER_LEN;
        let algo = u16::from_le_bytes([frame[body_offset], frame[body_offset + 1]]);
        let seqnum = u16::from_le_bytes([frame[body_offset + 2], frame[body_offset + 3]]);
        let status = u16::from_le_bytes([frame[body_offset + 4], frame[body_offset + 5]]);
        assert_eq!(algo, 0);
        assert_eq!(seqnum, 1);
        assert_eq!(status, 0);
    }

    #[test]
    fn test_build_deauth_convenience() {
        let dst = MacAddress::BROADCAST;
        let src = MacAddress::new([0xBB; 6]);
        let bssid = MacAddress::new([0xBB; 6]);

        let frame = Dot11Builder::build_deauth(dst, src, bssid, 7);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(layer.subtype(&frame).unwrap(), types::mgmt_subtype::DEAUTH);

        let body_offset = DOT11_MGMT_HEADER_LEN;
        let reason = u16::from_le_bytes([frame[body_offset], frame[body_offset + 1]]);
        assert_eq!(reason, 7);
    }

    #[test]
    fn test_build_probe_request_convenience() {
        let src = MacAddress::new([0xCC; 6]);
        let ies = vec![
            Dot11Elt::ssid(""), // broadcast probe
            Dot11Elt::new(types::ie_id::RATES, vec![0x82, 0x84]),
        ];

        let frame = Dot11Builder::build_probe_request(src, &ies);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(
            layer.subtype(&frame).unwrap(),
            types::mgmt_subtype::PROBE_REQ
        );
        assert!(layer.addr1(&frame).unwrap().is_broadcast());
        assert_eq!(layer.addr2(&frame).unwrap(), src);

        // Verify IEs are in the body
        let ie_data = &frame[DOT11_MGMT_HEADER_LEN..];
        let ies_parsed = Dot11Elt::parse_all(ie_data, 0);
        assert_eq!(ies_parsed.len(), 2);
        assert_eq!(ies_parsed[0].id, 0);
    }

    #[test]
    fn test_build_qos_data_convenience() {
        let bssid = MacAddress::new([0xAA; 6]);
        let src = MacAddress::new([0xBB; 6]);
        let dst = MacAddress::new([0xCC; 6]);
        let payload = b"hello";

        let frame = Dot11Builder::build_qos_data(bssid, src, dst, 3, payload);

        let layer = Dot11Layer::new(0, frame.len());
        assert_eq!(layer.frame_type(&frame).unwrap(), types::frame_type::DATA);
        assert_eq!(
            layer.subtype(&frame).unwrap(),
            types::data_subtype::QOS_DATA
        );
        assert!(layer.to_ds(&frame).unwrap());

        // QoS header is at offset 24 (after standard header)
        let qos = Dot11QoS::new(DOT11_MGMT_HEADER_LEN);
        assert_eq!(qos.tid(&frame).unwrap(), 3);

        // Payload follows QoS
        let payload_offset = DOT11_MGMT_HEADER_LEN + 2;
        assert_eq!(&frame[payload_offset..payload_offset + 5], b"hello");
    }

    #[test]
    fn test_header_size_calculation() {
        assert_eq!(
            Dot11Builder::beacon(MacAddress::BROADCAST).header_size(),
            24
        );
        assert_eq!(Dot11Builder::ack(MacAddress::BROADCAST).header_size(), 10);
        assert_eq!(
            Dot11Builder::rts(MacAddress::BROADCAST, MacAddress::ZERO).header_size(),
            16
        );
        assert_eq!(
            Dot11Builder::data_wds(
                MacAddress::ZERO,
                MacAddress::ZERO,
                MacAddress::ZERO,
                MacAddress::ZERO
            )
            .header_size(),
            30
        );
    }
}
