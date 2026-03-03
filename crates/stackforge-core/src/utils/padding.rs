//! Padding and alignment utilities.

/// Pad data to a minimum length with zeros.
#[must_use]
pub fn pad_to(data: &[u8], min_len: usize) -> Vec<u8> {
    if data.len() >= min_len {
        data.to_vec()
    } else {
        let mut padded = data.to_vec();
        padded.resize(min_len, 0);
        padded
    }
}

/// Pad data to align to a boundary.
#[must_use]
pub fn align_to(data: &[u8], alignment: usize) -> Vec<u8> {
    let padded_len = data.len().div_ceil(alignment) * alignment;
    pad_to(data, padded_len)
}

/// Calculate the minimum Ethernet frame size (including padding).
#[must_use]
pub fn ethernet_min_frame(data: &[u8]) -> Vec<u8> {
    // Minimum Ethernet frame is 64 bytes (including 4-byte FCS)
    // Without FCS, it's 60 bytes
    pad_to(data, 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_to() {
        let data = [1, 2, 3];
        let padded = pad_to(&data, 6);
        assert_eq!(padded, vec![1, 2, 3, 0, 0, 0]);

        // No padding needed
        let padded = pad_to(&data, 2);
        assert_eq!(padded, vec![1, 2, 3]);
    }

    #[test]
    fn test_align_to() {
        let data = [1, 2, 3, 4, 5];
        let aligned = align_to(&data, 4);
        assert_eq!(aligned.len(), 8);
        assert_eq!(&aligned[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_ethernet_min_frame() {
        let data = vec![0u8; 20];
        let frame = ethernet_min_frame(&data);
        assert_eq!(frame.len(), 60);
    }
}
