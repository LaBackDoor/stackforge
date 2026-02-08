//! Binary comparison and diff utilities.

use std::fmt::Write;

/// Compare two byte slices and return the first differing index.
pub fn find_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let min_len = a.len().min(b.len());

    for i in 0..min_len {
        if a[i] != b[i] {
            return Some(i);
        }
    }

    if a.len() != b.len() {
        Some(min_len)
    } else {
        None
    }
}

/// Generate a diff between two byte slices.
pub fn byte_diff(a: &[u8], b: &[u8]) -> String {
    let mut output = String::new();
    let max_len = a.len().max(b.len());

    writeln!(output, "Comparing {} bytes vs {} bytes", a.len(), b.len()).unwrap();

    for i in 0..max_len {
        let byte_a = a.get(i).copied();
        let byte_b = b.get(i).copied();

        if byte_a != byte_b {
            let a_str = byte_a
                .map(|b| format!("{:02x}", b))
                .unwrap_or_else(|| "--".to_string());
            let b_str = byte_b
                .map(|b| format!("{:02x}", b))
                .unwrap_or_else(|| "--".to_string());
            writeln!(output, "  offset {:04x}: {} != {}", i, a_str, b_str).unwrap();
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_diff() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 9, 4, 5];
        assert_eq!(find_diff(&a, &b), Some(2));

        let c = [1, 2, 3, 4, 5];
        assert_eq!(find_diff(&a, &c), None);

        let d = [1, 2, 3];
        assert_eq!(find_diff(&a, &d), Some(3));
    }
}
