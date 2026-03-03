//! IEEE 802.15.4 Beacon frame parsing and building.
//!
//! A beacon frame payload follows the base 802.15.4 header and contains:
//! - Superframe Specification (2 bytes, LE)
//! - GTS Specification (1 byte)
//! - GTS Directions (0 or 1 byte, present if GTS descriptor count > 0)
//! - GTS Descriptor List (variable, 3 bytes per descriptor)
//! - Pending Address Specification (1 byte)
//! - Pending Address List (variable)

use crate::layer::field::{FieldError, read_u16_le};

/// GTS descriptor: short address + starting slot/length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtsDescriptor {
    /// Short address of the device (2 bytes, LE).
    pub short_addr: u16,
    /// GTS starting slot (4 bits).
    pub starting_slot: u8,
    /// GTS length (4 bits).
    pub length: u8,
}

/// Parsed beacon frame payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconPayload {
    // Superframe Specification (2 bytes, LE)
    /// Beacon order (4 bits).
    pub beacon_order: u8,
    /// Superframe order (4 bits).
    pub superframe_order: u8,
    /// Final CAP slot (4 bits).
    pub final_cap_slot: u8,
    /// Battery life extension (1 bit).
    pub battery_life_ext: bool,
    /// PAN coordinator (1 bit).
    pub pan_coordinator: bool,
    /// Association permit (1 bit).
    pub assoc_permit: bool,

    // GTS Specification (1 byte)
    /// GTS descriptor count (3 bits).
    pub gts_desc_count: u8,
    /// GTS permit (1 bit).
    pub gts_permit: bool,

    // GTS Directions (0 or 1 byte)
    /// GTS direction mask (7 bits), present if `gts_desc_count` > 0.
    pub gts_dir_mask: u8,

    // GTS Descriptor List
    /// GTS descriptors (3 bytes each).
    pub gts_descriptors: Vec<GtsDescriptor>,

    // Pending Address Specification (1 byte)
    /// Number of short addresses pending (3 bits).
    pub pa_num_short: u8,
    /// Number of extended (long) addresses pending (3 bits).
    pub pa_num_long: u8,

    // Pending Address List
    /// Short addresses pending (2 bytes each).
    pub pa_short_addresses: Vec<u16>,
    /// Long addresses pending (8 bytes each).
    pub pa_long_addresses: Vec<u64>,
}

impl BeaconPayload {
    /// Parse a beacon payload from the buffer at the given offset.
    /// Returns the parsed payload and the number of bytes consumed.
    pub fn parse(buf: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        let mut pos = offset;

        // Superframe Specification (2 bytes, LE)
        if buf.len() < pos + 2 {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 2,
                have: buf.len().saturating_sub(pos),
            });
        }
        let sf_spec = read_u16_le(buf, pos)?;
        pos += 2;

        // Scapy bit ordering in bytes: sf_spec is LE u16
        // Bits 0-3: Beacon Order
        // Bits 4-7: Superframe Order
        // Bits 8-11: Final CAP Slot
        // Bit 12: Battery Life Extension
        // Bit 13: Reserved
        // Bit 14: PAN Coordinator
        // Bit 15: Association Permit
        let beacon_order = (sf_spec & 0x0F) as u8;
        let superframe_order = ((sf_spec >> 4) & 0x0F) as u8;
        let final_cap_slot = ((sf_spec >> 8) & 0x0F) as u8;
        let battery_life_ext = (sf_spec & 0x1000) != 0;
        let pan_coordinator = (sf_spec & 0x4000) != 0;
        let assoc_permit = (sf_spec & 0x8000) != 0;

        // GTS Specification (1 byte)
        if buf.len() < pos + 1 {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 1,
                have: buf.len().saturating_sub(pos),
            });
        }
        let gts_spec = buf[pos];
        pos += 1;

        // Bits 0-2: GTS Descriptor Count
        // Bits 3-6: Reserved
        // Bit 7: GTS Permit
        let gts_desc_count = gts_spec & 0x07;
        let gts_permit = (gts_spec & 0x80) != 0;

        // GTS Directions (1 byte, present if gts_desc_count > 0)
        let mut gts_dir_mask: u8 = 0;
        if gts_desc_count > 0 {
            if buf.len() < pos + 1 {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: 1,
                    have: buf.len().saturating_sub(pos),
                });
            }
            let gts_dir = buf[pos];
            pos += 1;
            // Bits 0-6: Direction Mask, Bit 7: Reserved
            gts_dir_mask = gts_dir & 0x7F;
        }

        // GTS Descriptor List (3 bytes per descriptor)
        let gts_list_len = (gts_desc_count as usize) * 3;
        if buf.len() < pos + gts_list_len {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: gts_list_len,
                have: buf.len().saturating_sub(pos),
            });
        }
        let mut gts_descriptors = Vec::with_capacity(gts_desc_count as usize);
        for _ in 0..gts_desc_count {
            let short_addr = read_u16_le(buf, pos)?;
            let slot_len = buf[pos + 2];
            let starting_slot = slot_len & 0x0F;
            let length = (slot_len >> 4) & 0x0F;
            gts_descriptors.push(GtsDescriptor {
                short_addr,
                starting_slot,
                length,
            });
            pos += 3;
        }

        // Pending Address Specification (1 byte)
        if buf.len() < pos + 1 {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 1,
                have: buf.len().saturating_sub(pos),
            });
        }
        let pa_spec = buf[pos];
        pos += 1;

        // Bits 0-2: Number of Short Addresses Pending
        // Bit 3: Reserved
        // Bits 4-6: Number of Extended Addresses Pending
        // Bit 7: Reserved
        let pa_num_short = pa_spec & 0x07;
        let pa_num_long = (pa_spec >> 4) & 0x07;

        // Pending Short Addresses (2 bytes each)
        let pa_short_len = (pa_num_short as usize) * 2;
        if buf.len() < pos + pa_short_len {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: pa_short_len,
                have: buf.len().saturating_sub(pos),
            });
        }
        let mut pa_short_addresses = Vec::with_capacity(pa_num_short as usize);
        for _ in 0..pa_num_short {
            pa_short_addresses.push(read_u16_le(buf, pos)?);
            pos += 2;
        }

        // Pending Long Addresses (8 bytes each)
        let pa_long_len = (pa_num_long as usize) * 8;
        if buf.len() < pos + pa_long_len {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: pa_long_len,
                have: buf.len().saturating_sub(pos),
            });
        }
        let mut pa_long_addresses = Vec::with_capacity(pa_num_long as usize);
        for _ in 0..pa_num_long {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[pos..pos + 8]);
            pa_long_addresses.push(u64::from_le_bytes(bytes));
            pos += 8;
        }

        let consumed = pos - offset;
        Ok((
            Self {
                beacon_order,
                superframe_order,
                final_cap_slot,
                battery_life_ext,
                pan_coordinator,
                assoc_permit,
                gts_desc_count,
                gts_permit,
                gts_dir_mask,
                gts_descriptors,
                pa_num_short,
                pa_num_long,
                pa_short_addresses,
                pa_long_addresses,
            },
            consumed,
        ))
    }

    /// Build the beacon payload bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Superframe Specification (2 bytes, LE)
        let mut sf_spec: u16 = 0;
        sf_spec |= u16::from(self.beacon_order) & 0x0F;
        sf_spec |= (u16::from(self.superframe_order) & 0x0F) << 4;
        sf_spec |= (u16::from(self.final_cap_slot) & 0x0F) << 8;
        if self.battery_life_ext {
            sf_spec |= 0x1000;
        }
        if self.pan_coordinator {
            sf_spec |= 0x4000;
        }
        if self.assoc_permit {
            sf_spec |= 0x8000;
        }
        out.extend_from_slice(&sf_spec.to_le_bytes());

        // GTS Specification (1 byte)
        let gts_count = self.gts_descriptors.len().min(7) as u8;
        let mut gts_spec: u8 = gts_count & 0x07;
        if self.gts_permit {
            gts_spec |= 0x80;
        }
        out.push(gts_spec);

        // GTS Directions (1 byte, only if descriptors present)
        if gts_count > 0 {
            out.push(self.gts_dir_mask & 0x7F);
        }

        // GTS Descriptor List (3 bytes each)
        for desc in &self.gts_descriptors {
            out.extend_from_slice(&desc.short_addr.to_le_bytes());
            let slot_len = (desc.starting_slot & 0x0F) | ((desc.length & 0x0F) << 4);
            out.push(slot_len);
        }

        // Pending Address Specification (1 byte)
        let pa_num_short = self.pa_short_addresses.len().min(7) as u8;
        let pa_num_long = self.pa_long_addresses.len().min(7) as u8;
        let pa_spec = (pa_num_short & 0x07) | ((pa_num_long & 0x07) << 4);
        out.push(pa_spec);

        // Pending Short Addresses
        for &addr in &self.pa_short_addresses {
            out.extend_from_slice(&addr.to_le_bytes());
        }

        // Pending Long Addresses
        for &addr in &self.pa_long_addresses {
            out.extend_from_slice(&addr.to_le_bytes());
        }

        out
    }

    /// Get a human-readable summary of this beacon.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "802.15.4 Beacon assocPermit({}) panCoord({}) beaconOrder={} sfOrder={}",
            self.assoc_permit, self.pan_coordinator, self.beacon_order, self.superframe_order,
        )
    }
}

impl Default for BeaconPayload {
    fn default() -> Self {
        Self {
            beacon_order: 15,
            superframe_order: 15,
            final_cap_slot: 15,
            battery_life_ext: false,
            pan_coordinator: false,
            assoc_permit: false,
            gts_desc_count: 0,
            gts_permit: true,
            gts_dir_mask: 0,
            gts_descriptors: Vec::new(),
            pa_num_short: 0,
            pa_num_long: 0,
            pa_short_addresses: Vec::new(),
            pa_long_addresses: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_beacon() {
        // Minimal beacon: sf_spec=0xFF0F (beacon_order=15, sf_order=15, final_cap=15),
        //   gts_spec=0x80 (permit=true, count=0),
        //   pa_spec=0x00
        let buf = [
            0xFF, 0x8F, // Superframe Spec (LE): beacon=15, sf=15, final_cap=15, pan_coord=1
            0x80, // GTS spec: permit=true, count=0
            0x00, // Pending addr spec: 0 short, 0 long
        ];
        let (beacon, consumed) = BeaconPayload::parse(&buf, 0).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(beacon.beacon_order, 15);
        assert_eq!(beacon.superframe_order, 15);
        assert_eq!(beacon.final_cap_slot, 15); // bits 8-11 of 0x8FFF = 0xF
        assert!(beacon.gts_permit);
        assert_eq!(beacon.gts_desc_count, 0);
        assert_eq!(beacon.pa_num_short, 0);
        assert_eq!(beacon.pa_num_long, 0);
    }

    #[test]
    fn test_parse_beacon_with_defaults() {
        // Build with defaults and round-trip
        let beacon = BeaconPayload::default();
        let bytes = beacon.build();
        let (parsed, consumed) = BeaconPayload::parse(&bytes, 0).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.beacon_order, 15);
        assert_eq!(parsed.superframe_order, 15);
        assert_eq!(parsed.final_cap_slot, 15);
        assert!(!parsed.battery_life_ext);
        assert!(!parsed.pan_coordinator);
        assert!(!parsed.assoc_permit);
        assert!(parsed.gts_permit);
        assert_eq!(parsed.gts_desc_count, 0);
    }

    #[test]
    fn test_beacon_with_gts_descriptors() {
        let beacon = BeaconPayload {
            beacon_order: 7,
            superframe_order: 3,
            final_cap_slot: 10,
            battery_life_ext: false,
            pan_coordinator: true,
            assoc_permit: true,
            gts_desc_count: 2,
            gts_permit: true,
            gts_dir_mask: 0x03,
            gts_descriptors: vec![
                GtsDescriptor {
                    short_addr: 0x1234,
                    starting_slot: 5,
                    length: 3,
                },
                GtsDescriptor {
                    short_addr: 0x5678,
                    starting_slot: 8,
                    length: 2,
                },
            ],
            pa_num_short: 0,
            pa_num_long: 0,
            pa_short_addresses: Vec::new(),
            pa_long_addresses: Vec::new(),
        };

        let bytes = beacon.build();
        let (parsed, consumed) = BeaconPayload::parse(&bytes, 0).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.beacon_order, 7);
        assert_eq!(parsed.superframe_order, 3);
        assert_eq!(parsed.final_cap_slot, 10);
        assert!(parsed.pan_coordinator);
        assert!(parsed.assoc_permit);
        assert_eq!(parsed.gts_desc_count, 2);
        assert!(parsed.gts_permit);
        assert_eq!(parsed.gts_dir_mask, 0x03);
        assert_eq!(parsed.gts_descriptors.len(), 2);
        assert_eq!(parsed.gts_descriptors[0].short_addr, 0x1234);
        assert_eq!(parsed.gts_descriptors[0].starting_slot, 5);
        assert_eq!(parsed.gts_descriptors[0].length, 3);
        assert_eq!(parsed.gts_descriptors[1].short_addr, 0x5678);
        assert_eq!(parsed.gts_descriptors[1].starting_slot, 8);
        assert_eq!(parsed.gts_descriptors[1].length, 2);
    }

    #[test]
    fn test_beacon_with_pending_addresses() {
        let beacon = BeaconPayload {
            beacon_order: 15,
            superframe_order: 15,
            final_cap_slot: 15,
            battery_life_ext: false,
            pan_coordinator: false,
            assoc_permit: false,
            gts_desc_count: 0,
            gts_permit: false,
            gts_dir_mask: 0,
            gts_descriptors: Vec::new(),
            pa_num_short: 2,
            pa_num_long: 1,
            pa_short_addresses: vec![0x1111, 0x2222],
            pa_long_addresses: vec![0x0102030405060708],
        };

        let bytes = beacon.build();
        let (parsed, consumed) = BeaconPayload::parse(&bytes, 0).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.pa_num_short, 2);
        assert_eq!(parsed.pa_num_long, 1);
        assert_eq!(parsed.pa_short_addresses, vec![0x1111, 0x2222]);
        assert_eq!(parsed.pa_long_addresses, vec![0x0102030405060708]);
    }

    #[test]
    fn test_parse_with_offset() {
        let beacon = BeaconPayload::default();
        let bytes = beacon.build();
        let mut buf = vec![0xAA, 0xBB, 0xCC];
        buf.extend_from_slice(&bytes);

        let (parsed, _) = BeaconPayload::parse(&buf, 3).unwrap();
        assert_eq!(parsed.beacon_order, 15);
    }

    #[test]
    fn test_parse_buffer_too_short() {
        let buf = [0xFF]; // Too short for superframe spec
        let result = BeaconPayload::parse(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_roundtrip() {
        let beacon = BeaconPayload {
            beacon_order: 4,
            superframe_order: 2,
            final_cap_slot: 9,
            battery_life_ext: true,
            pan_coordinator: true,
            assoc_permit: true,
            gts_desc_count: 1,
            gts_permit: true,
            gts_dir_mask: 0x01,
            gts_descriptors: vec![GtsDescriptor {
                short_addr: 0xABCD,
                starting_slot: 3,
                length: 4,
            }],
            pa_num_short: 1,
            pa_num_long: 0,
            pa_short_addresses: vec![0x9999],
            pa_long_addresses: Vec::new(),
        };

        let bytes = beacon.build();
        let (parsed, _) = BeaconPayload::parse(&bytes, 0).unwrap();
        assert_eq!(parsed.beacon_order, beacon.beacon_order);
        assert_eq!(parsed.superframe_order, beacon.superframe_order);
        assert_eq!(parsed.final_cap_slot, beacon.final_cap_slot);
        assert_eq!(parsed.battery_life_ext, beacon.battery_life_ext);
        assert_eq!(parsed.pan_coordinator, beacon.pan_coordinator);
        assert_eq!(parsed.assoc_permit, beacon.assoc_permit);
        assert_eq!(parsed.gts_permit, beacon.gts_permit);
        assert_eq!(parsed.gts_dir_mask, beacon.gts_dir_mask);
        assert_eq!(parsed.gts_descriptors, beacon.gts_descriptors);
        assert_eq!(parsed.pa_short_addresses, beacon.pa_short_addresses);
        assert_eq!(parsed.pa_long_addresses, beacon.pa_long_addresses);
    }

    #[test]
    fn test_summary() {
        let beacon = BeaconPayload {
            assoc_permit: true,
            pan_coordinator: true,
            beacon_order: 7,
            superframe_order: 3,
            ..BeaconPayload::default()
        };
        let summary = beacon.summary();
        assert!(summary.contains("assocPermit(true)"));
        assert!(summary.contains("panCoord(true)"));
        assert!(summary.contains("beaconOrder=7"));
    }
}
