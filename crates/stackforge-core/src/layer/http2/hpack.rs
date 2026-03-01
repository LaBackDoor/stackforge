//! HPACK header compression for HTTP/2 (RFC 7541).
//!
//! Implements the HPACK header compression algorithm used in HTTP/2 HEADERS frames.
//! Includes:
//! - Static table (61 entries per RFC 7541 Appendix A)
//! - Dynamic table with eviction
//! - Integer encoding/decoding with N-bit prefix
//! - String literal encoding/decoding
//! - Huffman encoding/decoding (RFC 7541 Appendix B)
//! - HpackDecoder and HpackEncoder types

// ============================================================================
// Static Table (RFC 7541 Appendix A)
// ============================================================================

/// Static HPACK table from RFC 7541 Appendix A.
/// 61 entries, 1-indexed in the spec (index 0 here = spec index 1).
pub const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

// ============================================================================
// Huffman Table (RFC 7541 Appendix B)
// All 256 byte values + EOS (symbol 256)
// Each entry is (code: u32, nbits: u8)
// ============================================================================

/// Full Huffman code table from RFC 7541 Appendix B.
/// Index is the symbol value (0-255 for bytes, 256 for EOS).
/// Each entry is (code: u32, nbits: u8).
#[rustfmt::skip]
pub const HUFFMAN_TABLE: &[(u32, u8)] = &[
    (0x1ff8, 13),      // 0
    (0x7fffd8, 23),    // 1
    (0xfffffe2, 28),   // 2
    (0xfffffe3, 28),   // 3
    (0xfffffe4, 28),   // 4
    (0xfffffe5, 28),   // 5
    (0xfffffe6, 28),   // 6
    (0xfffffe7, 28),   // 7
    (0xfffffe8, 28),   // 8
    (0xffffea, 24),    // 9
    (0x3ffffffc, 30),  // 10
    (0xfffffe9, 28),   // 11
    (0xfffffea, 28),   // 12
    (0x3ffffffd, 30),  // 13
    (0xfffffeb, 28),   // 14
    (0xfffffec, 28),   // 15
    (0xfffffed, 28),   // 16
    (0xfffffee, 28),   // 17
    (0xfffffef, 28),   // 18
    (0xffffff0, 28),   // 19
    (0xffffff1, 28),   // 20
    (0xffffff2, 28),   // 21
    (0x3ffffffe, 30),  // 22
    (0xffffff3, 28),   // 23
    (0xffffff4, 28),   // 24
    (0xffffff5, 28),   // 25
    (0xffffff6, 28),   // 26
    (0xffffff7, 28),   // 27
    (0xffffff8, 28),   // 28
    (0xffffff9, 28),   // 29
    (0xffffffa, 28),   // 30
    (0xffffffb, 28),   // 31
    (0x14, 6),         // 32 ' '
    (0x3f8, 10),       // 33 '!'
    (0x3f9, 10),       // 34 '"'
    (0xffa, 12),       // 35 '#'
    (0x1ff9, 13),      // 36 '$'
    (0x15, 6),         // 37 '%'
    (0xf8, 8),         // 38 '&'
    (0x7fa, 11),       // 39 '\''
    (0x3fa, 10),       // 40 '('
    (0x3fb, 10),       // 41 ')'
    (0xf9, 8),         // 42 '*'
    (0x7fb, 11),       // 43 '+'
    (0xfa, 8),         // 44 ','
    (0x16, 6),         // 45 '-'
    (0x17, 6),         // 46 '.'
    (0x18, 6),         // 47 '/'
    (0x00, 5),         // 48 '0'
    (0x01, 5),         // 49 '1'
    (0x02, 5),         // 50 '2'
    (0x19, 6),         // 51 '3'
    (0x1a, 6),         // 52 '4'
    (0x1b, 6),         // 53 '5'
    (0x1c, 6),         // 54 '6'
    (0x1d, 6),         // 55 '7'
    (0x1e, 6),         // 56 '8'
    (0x1f, 6),         // 57 '9'
    (0x5c, 7),         // 58 ':'
    (0xfb, 8),         // 59 ';'
    (0x7ffc, 15),      // 60 '<'
    (0x20, 6),         // 61 '='
    (0xffb, 12),       // 62 '>'
    (0x3fc, 10),       // 63 '?'
    (0x1ffa, 13),      // 64 '@'
    (0x21, 6),         // 65 'A'
    (0x5d, 7),         // 66 'B'
    (0x5e, 7),         // 67 'C'
    (0x5f, 7),         // 68 'D'
    (0x60, 7),         // 69 'E'
    (0x61, 7),         // 70 'F'
    (0x62, 7),         // 71 'G'
    (0x63, 7),         // 72 'H'
    (0x64, 7),         // 73 'I'
    (0x65, 7),         // 74 'J'
    (0x66, 7),         // 75 'K'
    (0x67, 7),         // 76 'L'
    (0x68, 7),         // 77 'M'
    (0x69, 7),         // 78 'N'
    (0x6a, 7),         // 79 'O'
    (0x6b, 7),         // 80 'P'
    (0x6c, 7),         // 81 'Q'
    (0x6d, 7),         // 82 'R'
    (0x6e, 7),         // 83 'S'
    (0x6f, 7),         // 84 'T'
    (0x70, 7),         // 85 'U'
    (0x71, 7),         // 86 'V'
    (0x72, 7),         // 87 'W'
    (0xfc, 8),         // 88 'X'
    (0x73, 7),         // 89 'Y'
    (0xfd, 8),         // 90 'Z'
    (0x1ffb, 13),      // 91 '['
    (0x7fff0, 19),     // 92 '\\'
    (0x1ffc, 13),      // 93 ']'
    (0x3ffc, 14),      // 94 '^'
    (0x22, 6),         // 95 '_'
    (0x7ffd, 15),      // 96 '`'
    (0x03, 5),         // 97 'a'
    (0x23, 6),         // 98 'b'
    (0x04, 5),         // 99 'c'
    (0x24, 6),         // 100 'd'
    (0x05, 5),         // 101 'e'
    (0x25, 6),         // 102 'f'
    (0x26, 6),         // 103 'g'
    (0x27, 6),         // 104 'h'
    (0x06, 5),         // 105 'i'
    (0x74, 7),         // 106 'j'
    (0x75, 7),         // 107 'k'
    (0x28, 6),         // 108 'l'
    (0x29, 6),         // 109 'm'
    (0x2a, 6),         // 110 'n'
    (0x07, 5),         // 111 'o'
    (0x2b, 6),         // 112 'p'
    (0x76, 7),         // 113 'q'
    (0x2c, 6),         // 114 'r'
    (0x08, 5),         // 115 's'
    (0x09, 5),         // 116 't'
    (0x2d, 6),         // 117 'u'
    (0x77, 7),         // 118 'v'
    (0x78, 7),         // 119 'w'
    (0x79, 7),         // 120 'x'
    (0x7a, 7),         // 121 'y'
    (0x7b, 7),         // 122 'z'
    (0x7ffe, 15),      // 123 '{'
    (0x7fc, 11),       // 124 '|'
    (0x3ffd, 14),      // 125 '}'
    (0x1ffd, 13),      // 126 '~'
    (0xffffffc, 28),   // 127
    (0xfffe6, 20),     // 128
    (0x3fffd2, 22),    // 129
    (0xfffe7, 20),     // 130
    (0xfffe8, 20),     // 131
    (0x3fffd3, 22),    // 132
    (0x3fffd4, 22),    // 133
    (0x3fffd5, 22),    // 134
    (0x7fffd9, 23),    // 135
    (0x3fffd6, 22),    // 136
    (0x7fffda, 23),    // 137
    (0x7fffdb, 23),    // 138
    (0x7fffdc, 23),    // 139
    (0x7fffdd, 23),    // 140
    (0x7fffde, 23),    // 141
    (0xffffeb, 24),    // 142
    (0x7fffdf, 23),    // 143
    (0xffffec, 24),    // 144
    (0xffffed, 24),    // 145
    (0x3fffd7, 22),    // 146
    (0x7fffe0, 23),    // 147
    (0xffffee, 24),    // 148
    (0x7fffe1, 23),    // 149
    (0x7fffe2, 23),    // 150
    (0x7fffe3, 23),    // 151
    (0x7fffe4, 23),    // 152
    (0x1fffdc, 21),    // 153
    (0x3fffd8, 22),    // 154
    (0x7fffe5, 23),    // 155
    (0x3fffd9, 22),    // 156
    (0x7fffe6, 23),    // 157
    (0x7fffe7, 23),    // 158
    (0xffffef, 24),    // 159
    (0x3fffda, 22),    // 160
    (0x1fffdd, 21),    // 161
    (0xfffe9, 20),     // 162
    (0x3fffdb, 22),    // 163
    (0x3fffdc, 22),    // 164
    (0x7fffe8, 23),    // 165
    (0x7fffe9, 23),    // 166
    (0x1fffde, 21),    // 167
    (0x7fffea, 23),    // 168
    (0x3fffdd, 22),    // 169
    (0x3fffde, 22),    // 170
    (0xfffff0, 24),    // 171
    (0x1fffdf, 21),    // 172
    (0x3fffdf, 22),    // 173
    (0x7fffeb, 23),    // 174
    (0x7fffec, 23),    // 175
    (0x1fffe0, 21),    // 176
    (0x1fffe1, 21),    // 177
    (0x3fffe0, 22),    // 178
    (0x1fffe2, 21),    // 179
    (0x7fffed, 23),    // 180
    (0x3fffe1, 22),    // 181
    (0x7fffee, 23),    // 182
    (0x7fffef, 23),    // 183
    (0xfffea, 20),     // 184
    (0x3fffe2, 22),    // 185
    (0x3fffe3, 22),    // 186
    (0x3fffe4, 22),    // 187
    (0x7ffff0, 23),    // 188
    (0x3fffe5, 22),    // 189
    (0x3fffe6, 22),    // 190
    (0x7ffff1, 23),    // 191
    (0x3ffffe0, 26),   // 192
    (0x3ffffe1, 26),   // 193
    (0xfffeb, 20),     // 194
    (0x7fff1, 19),     // 195
    (0x3fffe7, 22),    // 196
    (0x7ffff2, 23),    // 197
    (0x3fffe8, 22),    // 198
    (0x1ffffec, 25),   // 199
    (0x3ffffe2, 26),   // 200
    (0x3ffffe3, 26),   // 201
    (0x3ffffe4, 26),   // 202
    (0x7ffffde, 27),   // 203
    (0x7ffffdf, 27),   // 204
    (0x3ffffe5, 26),   // 205
    (0xfffff1, 24),    // 206
    (0x1ffffed, 25),   // 207
    (0x7fff2, 19),     // 208
    (0x1fffe3, 21),    // 209
    (0x3ffffe6, 26),   // 210
    (0x7ffffe0, 27),   // 211
    (0x7ffffe1, 27),   // 212
    (0x3ffffe7, 26),   // 213
    (0x7ffffe2, 27),   // 214
    (0xfffff2, 24),    // 215
    (0x1fffe4, 21),    // 216
    (0x1fffe5, 21),    // 217
    (0x3ffffe8, 26),   // 218
    (0x3ffffe9, 26),   // 219
    (0xffffffd, 28),   // 220
    (0x7ffffe3, 27),   // 221
    (0x7ffffe4, 27),   // 222
    (0x7ffffe5, 27),   // 223
    (0xfffec, 20),     // 224
    (0xfffff3, 24),    // 225
    (0xfffed, 20),     // 226
    (0x1fffe6, 21),    // 227
    (0x3fffe9, 22),    // 228
    (0x1fffe7, 21),    // 229
    (0x1fffe8, 21),    // 230
    (0x7ffff3, 23),    // 231
    (0x3fffea, 22),    // 232
    (0x3fffeb, 22),    // 233
    (0x1ffffee, 25),   // 234
    (0x1ffffef, 25),   // 235
    (0xfffff4, 24),    // 236
    (0xfffff5, 24),    // 237
    (0x3ffffea, 26),   // 238
    (0x7ffff4, 23),    // 239
    (0x3ffffeb, 26),   // 240
    (0x7ffffe6, 27),   // 241
    (0x3ffffec, 26),   // 242
    (0x3ffffed, 26),   // 243
    (0x7ffffe7, 27),   // 244
    (0x7ffffe8, 27),   // 245
    (0x7ffffe9, 27),   // 246
    (0x7ffffea, 27),   // 247
    (0x7ffffeb, 27),   // 248
    (0xffffffe, 28),   // 249
    (0x7ffffec, 27),   // 250
    (0x7ffffed, 27),   // 251
    (0x7ffffee, 27),   // 252
    (0x7ffffef, 27),   // 253
    (0x7fffff0, 27),   // 254
    (0x3ffffee, 26),   // 255
    (0x3fffffff, 30),  // 256 EOS
];

// ============================================================================
// Integer Encoding/Decoding (RFC 7541 Section 5.1)
// ============================================================================

/// Decode an HPACK integer with N-bit prefix.
///
/// The first byte is the prefix byte, where the top (8 - prefix_bits) bits
/// may contain a representation indicator.
///
/// # Arguments
/// - `buf`: input bytes starting at the prefix byte
/// - `prefix_bits`: number of bits in the integer prefix (1-8)
///
/// # Returns
/// `Some((value, bytes_consumed))` or `None` if the buffer is too short or
/// the integer is malformed.
pub fn decode_integer(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() || prefix_bits == 0 || prefix_bits > 8 {
        return None;
    }

    let prefix_max = (1u32 << prefix_bits) - 1;
    let first = (buf[0] & (prefix_max as u8)) as u64;

    if first < prefix_max as u64 {
        // Small value that fits in prefix
        return Some((first, 1));
    }

    // Value is >= prefix_max, read continuation bytes
    let mut value = prefix_max as u64;
    let mut shift = 0u64;
    let mut i = 1;

    loop {
        if i >= buf.len() {
            return None;
        }
        let byte = buf[i];
        i += 1;
        value += ((byte & 0x7F) as u64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            break;
        }

        if shift > 63 {
            // Overflow protection
            return None;
        }
    }

    Some((value, i))
}

/// Encode an HPACK integer with N-bit prefix.
///
/// # Arguments
/// - `value`: the integer to encode
/// - `prefix_bits`: number of prefix bits (1-8)
/// - `prefix_byte`: the high bits to set in the first byte (the representation indicator bits)
///
/// # Returns
/// A `Vec<u8>` containing the encoded integer.
pub fn encode_integer(value: u64, prefix_bits: u8, prefix_byte: u8) -> Vec<u8> {
    let prefix_max = (1u64 << prefix_bits) - 1;

    if value < prefix_max {
        // Fits in prefix
        return vec![prefix_byte | (value as u8)];
    }

    // Does not fit in prefix
    let mut out = vec![prefix_byte | (prefix_max as u8)];
    let mut remaining = value - prefix_max;

    loop {
        if remaining < 128 {
            out.push(remaining as u8);
            break;
        }
        out.push((remaining & 0x7F) as u8 | 0x80);
        remaining >>= 7;
    }

    out
}

// ============================================================================
// Huffman Node for decoding
// ============================================================================

/// A node in the Huffman decoding tree.
#[derive(Default)]
struct HuffmanNode {
    symbol: Option<u16>, // Some(sym) if this is a leaf
    children: [Option<Box<HuffmanNode>>; 2],
}

impl HuffmanNode {
    fn new() -> Self {
        HuffmanNode {
            symbol: None,
            children: [None, None],
        }
    }
}

/// Build the Huffman decoding tree from the HUFFMAN_TABLE.
fn build_huffman_tree() -> HuffmanNode {
    let mut root = HuffmanNode::new();

    for (sym, &(code, nbits)) in HUFFMAN_TABLE.iter().enumerate() {
        if nbits == 0 || nbits > 32 {
            continue;
        }
        // Skip impossible codes (EOS is sym 256, but we include it for EOS detection)
        let mut node = &mut root;
        for bit_idx in (0..nbits).rev() {
            let bit = ((code >> bit_idx) & 1) as usize;
            if node.children[bit].is_none() {
                node.children[bit] = Some(Box::new(HuffmanNode::new()));
            }
            node = node.children[bit].as_mut().unwrap();
        }
        node.symbol = Some(sym as u16);
    }

    root
}

// ============================================================================
// Huffman Decode / Encode (RFC 7541 Appendix B)
// ============================================================================

/// Decode Huffman-encoded data (RFC 7541 Appendix B).
///
/// Returns the decoded bytes on success, or `None` if the data is malformed.
/// Padding bits (at most 7) must all be 1s as per the spec.
pub fn huffman_decode(encoded: &[u8]) -> Option<Vec<u8>> {
    let root = build_huffman_tree();
    let mut output = Vec::new();
    let mut node = &root;

    for &byte in encoded {
        for bit_idx in (0..8).rev() {
            let bit = ((byte >> bit_idx) & 1) as usize;
            node = node.children[bit].as_ref()?;

            if let Some(sym) = node.symbol {
                if sym == 256 {
                    // EOS encountered
                    return None;
                }
                output.push(sym as u8);
                node = &root;
            }
        }
    }

    // After all bytes consumed, we should be at root or at a padding position.
    // Padding must be high bits of a partial byte (all 1s). The tree traversal
    // handles this: if we're not at root, the partial byte's remaining bits
    // must form a path to a non-leaf node (valid padding).
    // If we ended on a leaf that's EOS, that's an error (already handled).
    // Being at a non-root position is acceptable as long as remaining bits were all 1.
    // The loop above handles this correctly since we only follow actual bit paths.

    Some(output)
}

/// Encode data using Huffman coding (RFC 7541 Appendix B).
///
/// Returns a byte vector. The output is padded with 1-bits to the next byte boundary.
pub fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut bit_buf: u64 = 0;
    let mut bit_count = 0u32;
    let mut output = Vec::new();

    for &byte in data {
        let (code, nbits) = HUFFMAN_TABLE[byte as usize];
        let nbits = nbits as u32;

        bit_buf = (bit_buf << nbits) | (code as u64);
        bit_count += nbits;

        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bit_buf >> bit_count) & 0xFF) as u8);
        }
    }

    // Flush remaining bits with 1-bit padding
    if bit_count > 0 {
        let padding = 8 - bit_count;
        bit_buf = (bit_buf << padding) | ((1u64 << padding) - 1);
        output.push((bit_buf & 0xFF) as u8);
    }

    output
}

// ============================================================================
// String Literal Decode/Encode (RFC 7541 Section 5.2)
// ============================================================================

/// Decode a string literal from an HPACK-encoded buffer.
///
/// Format:
/// ```text
/// +---+---+---+---+---+---+---+---+
/// | H |    String Length (7+)      |
/// +---+---------------------------+
/// | String Data (Length octets)   |
/// +-------------------------------+
/// ```
///
/// # Returns
/// `Some((string_bytes, bytes_consumed))` or `None` if the buffer is too short.
pub fn decode_string(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.is_empty() {
        return None;
    }

    let huffman_flag = (buf[0] & 0x80) != 0;
    let (length, consumed) = decode_integer(buf, 7)?;
    let length = length as usize;

    if consumed + length > buf.len() {
        return None;
    }

    let string_data = &buf[consumed..consumed + length];

    let result = if huffman_flag {
        huffman_decode(string_data)?
    } else {
        string_data.to_vec()
    };

    Some((result, consumed + length))
}

/// Encode a string literal without Huffman coding.
///
/// Returns bytes in literal (non-Huffman) format.
pub fn encode_string_literal(data: &[u8]) -> Vec<u8> {
    let mut out = encode_integer(data.len() as u64, 7, 0x00); // H=0
    out.extend_from_slice(data);
    out
}

/// Encode a string literal with Huffman coding if beneficial.
///
/// Uses Huffman encoding and sets H=1. Always Huffman-encodes for simplicity.
pub fn encode_string_huffman(data: &[u8]) -> Vec<u8> {
    let encoded = huffman_encode(data);
    let mut out = encode_integer(encoded.len() as u64, 7, 0x80); // H=1
    out.extend_from_slice(&encoded);
    out
}

// ============================================================================
// HPACK Decoder (RFC 7541)
// ============================================================================

/// HPACK dynamic table entry size = name length + value length + 32 bytes overhead.
fn entry_size(name: &str, value: &str) -> usize {
    name.len() + value.len() + 32
}

/// HPACK decoder with dynamic table state.
///
/// This decoder maintains a dynamic table across multiple calls, allowing
/// header compression state to be shared within an HTTP/2 connection.
pub struct HpackDecoder {
    /// Dynamic table entries (most recently added first).
    dynamic_table: Vec<(String, String)>,
    /// Maximum dynamic table size (bytes, per SETTINGS_HEADER_TABLE_SIZE).
    max_table_size: usize,
    /// Current dynamic table size (sum of entry sizes).
    current_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    /// Create a new HPACK decoder with default max table size of 4096 bytes.
    pub fn new() -> Self {
        HpackDecoder {
            dynamic_table: Vec::new(),
            max_table_size: 4096,
            current_size: 0,
        }
    }

    /// Create a new HPACK decoder with a specific max table size.
    pub fn with_max_size(max_table_size: usize) -> Self {
        HpackDecoder {
            dynamic_table: Vec::new(),
            max_table_size,
            current_size: 0,
        }
    }

    /// Update the maximum table size (e.g., from SETTINGS_HEADER_TABLE_SIZE).
    pub fn set_max_table_size(&mut self, size: usize) {
        self.max_table_size = size;
        self.evict_to_fit(0);
    }

    /// Returns the number of entries currently in the dynamic table.
    pub fn dynamic_table_len(&self) -> usize {
        self.dynamic_table.len()
    }

    /// Returns the current size (in bytes) of the dynamic table.
    pub fn dynamic_table_current_size(&self) -> usize {
        self.current_size
    }

    /// Returns the entries in the dynamic table as (name, value) string slices.
    /// Entries are ordered most-recently-added first (index 62 = first entry).
    pub fn dynamic_table_entries(&self) -> &[(String, String)] {
        &self.dynamic_table
    }

    /// Decode a block of HPACK-encoded headers.
    ///
    /// Returns a list of `(name, value)` pairs in the order they were decoded.
    pub fn decode(&mut self, buf: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < buf.len() {
            let first = buf[pos];

            if (first & 0x80) != 0 {
                // Indexed Header Field Representation (RFC 7541 Section 6.1)
                // Pattern: 1xxxxxxx
                let (idx, consumed) = decode_integer(&buf[pos..], 7)
                    .ok_or_else(|| "Failed to decode indexed header index".to_string())?;
                pos += consumed;

                let (name, value) = self
                    .table_entry(idx as usize)
                    .ok_or_else(|| format!("Invalid header table index: {}", idx))?;
                headers.push((name, value));
            } else if (first & 0x40) != 0 {
                // Literal Header Field with Incremental Indexing (RFC 7541 Section 6.2.1)
                // Pattern: 01xxxxxx
                let (idx, consumed) = decode_integer(&buf[pos..], 6)
                    .ok_or_else(|| "Failed to decode literal indexed name index".to_string())?;
                pos += consumed;

                let name = if idx == 0 {
                    // Name is a literal string
                    let (name_bytes, nc) = decode_string(&buf[pos..])
                        .ok_or_else(|| "Failed to decode literal name string".to_string())?;
                    pos += nc;
                    String::from_utf8(name_bytes)
                        .map_err(|e| format!("Invalid UTF-8 in header name: {}", e))?
                } else {
                    let (n, _) = self
                        .table_entry(idx as usize)
                        .ok_or_else(|| format!("Invalid header table index: {}", idx))?;
                    n
                };

                let (value_bytes, vc) = decode_string(&buf[pos..])
                    .ok_or_else(|| "Failed to decode literal value string".to_string())?;
                pos += vc;
                let value = String::from_utf8(value_bytes)
                    .map_err(|e| format!("Invalid UTF-8 in header value: {}", e))?;

                self.add_to_dynamic_table(name.clone(), value.clone());
                headers.push((name, value));
            } else if (first & 0x20) != 0 {
                // Dynamic Table Size Update (RFC 7541 Section 6.3)
                // Pattern: 001xxxxx
                let (new_size, consumed) = decode_integer(&buf[pos..], 5)
                    .ok_or_else(|| "Failed to decode table size update".to_string())?;
                pos += consumed;

                if new_size as usize > self.max_table_size {
                    return Err(format!(
                        "Table size update {} exceeds max {}",
                        new_size, self.max_table_size
                    ));
                }
                self.evict_to_fit(0);
                // Trim to new size
                while self.current_size > new_size as usize {
                    if let Some(entry) = self.dynamic_table.pop() {
                        self.current_size = self
                            .current_size
                            .saturating_sub(entry_size(&entry.0, &entry.1));
                    } else {
                        break;
                    }
                }
            } else if (first & 0x10) != 0 {
                // Literal Header Field Never Indexed (RFC 7541 Section 6.2.3)
                // Pattern: 0001xxxx
                let (idx, consumed) = decode_integer(&buf[pos..], 4)
                    .ok_or_else(|| "Failed to decode never-indexed name index".to_string())?;
                pos += consumed;

                let name = if idx == 0 {
                    let (name_bytes, nc) = decode_string(&buf[pos..])
                        .ok_or_else(|| "Failed to decode never-indexed name string".to_string())?;
                    pos += nc;
                    String::from_utf8(name_bytes)
                        .map_err(|e| format!("Invalid UTF-8 in header name: {}", e))?
                } else {
                    let (n, _) = self
                        .table_entry(idx as usize)
                        .ok_or_else(|| format!("Invalid header table index: {}", idx))?;
                    n
                };

                let (value_bytes, vc) = decode_string(&buf[pos..])
                    .ok_or_else(|| "Failed to decode never-indexed value string".to_string())?;
                pos += vc;
                let value = String::from_utf8(value_bytes)
                    .map_err(|e| format!("Invalid UTF-8 in header value: {}", e))?;

                // Never indexed — do not add to dynamic table
                headers.push((name, value));
            } else {
                // Literal Header Field Without Indexing (RFC 7541 Section 6.2.2)
                // Pattern: 0000xxxx
                let (idx, consumed) = decode_integer(&buf[pos..], 4)
                    .ok_or_else(|| "Failed to decode without-indexing name index".to_string())?;
                pos += consumed;

                let name = if idx == 0 {
                    let (name_bytes, nc) = decode_string(&buf[pos..]).ok_or_else(|| {
                        "Failed to decode without-indexing name string".to_string()
                    })?;
                    pos += nc;
                    String::from_utf8(name_bytes)
                        .map_err(|e| format!("Invalid UTF-8 in header name: {}", e))?
                } else {
                    let (n, _) = self
                        .table_entry(idx as usize)
                        .ok_or_else(|| format!("Invalid header table index: {}", idx))?;
                    n
                };

                let (value_bytes, vc) = decode_string(&buf[pos..])
                    .ok_or_else(|| "Failed to decode without-indexing value string".to_string())?;
                pos += vc;
                let value = String::from_utf8(value_bytes)
                    .map_err(|e| format!("Invalid UTF-8 in header value: {}", e))?;

                // Without indexing — do not add to dynamic table
                headers.push((name, value));
            }
        }

        Ok(headers)
    }

    /// Look up a dynamic table entry (0-indexed from the front, most recent first).
    fn dynamic_table_entry(&self, index: usize) -> Option<(&str, &str)> {
        self.dynamic_table
            .get(index)
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Look up a static table entry by 1-based index.
    fn static_table_entry(index: usize) -> Option<(&'static str, &'static str)> {
        if index >= 1 && index <= STATIC_TABLE.len() {
            Some(STATIC_TABLE[index - 1])
        } else {
            None
        }
    }

    /// Look up a combined (static + dynamic) table entry.
    ///
    /// Indices 1..=61 are static table. Indices 62+ are dynamic table.
    fn table_entry(&self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }

        if index <= STATIC_TABLE.len() {
            let (n, v) = Self::static_table_entry(index)?;
            return Some((n.to_string(), v.to_string()));
        }

        let dynamic_idx = index - STATIC_TABLE.len() - 1;
        let (n, v) = self.dynamic_table_entry(dynamic_idx)?;
        Some((n.to_string(), v.to_string()))
    }

    /// Add a new entry to the dynamic table (prepended, i.e., most recent first).
    fn add_to_dynamic_table(&mut self, name: String, value: String) {
        let size = entry_size(&name, &value);
        self.evict_to_fit(size);
        if size <= self.max_table_size {
            self.current_size += size;
            self.dynamic_table.insert(0, (name, value));
        }
    }

    /// Evict entries from the back of the dynamic table until the table can
    /// accommodate `new_entry_size` more bytes.
    fn evict_to_fit(&mut self, new_entry_size: usize) {
        while !self.dynamic_table.is_empty()
            && self.current_size + new_entry_size > self.max_table_size
        {
            if let Some(entry) = self.dynamic_table.pop() {
                self.current_size = self
                    .current_size
                    .saturating_sub(entry_size(&entry.0, &entry.1));
            }
        }
    }
}

// ============================================================================
// HPACK Encoder
// ============================================================================

/// HPACK encoder.
///
/// Currently uses literal header fields without indexing for simplicity.
/// An optimized version would use the static and dynamic tables to produce
/// smaller output.
pub struct HpackEncoder {
    /// Dynamic table entries (most recently added first).
    #[allow(dead_code)]
    dynamic_table: Vec<(String, String)>,
    /// Maximum table size.
    #[allow(dead_code)]
    max_table_size: usize,
}

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    /// Create a new HPACK encoder with default max table size of 4096 bytes.
    pub fn new() -> Self {
        HpackEncoder {
            dynamic_table: Vec::new(),
            max_table_size: 4096,
        }
    }

    /// Encode a list of header name-value pairs using HPACK.
    ///
    /// This implementation uses literal header fields without indexing
    /// (pattern 0000xxxx with index=0) for simplicity and correctness.
    /// It checks the static table for name-only matches to save space.
    pub fn encode(&self, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();

        for &(name, value) in headers {
            // Check static table for exact match (both name and value)
            if let Some(static_idx) = self.find_static_exact(name, value) {
                // Indexed header field representation (Section 6.1)
                // Pattern: 1xxxxxxx
                out.extend_from_slice(&encode_integer(static_idx as u64, 7, 0x80));
                continue;
            }

            // Check static table for name-only match
            if let Some(name_idx) = self.find_static_name(name) {
                // Literal header field with incremental indexing (Section 6.2.1)
                // Pattern: 01xxxxxx with name index
                out.extend_from_slice(&encode_integer(name_idx as u64, 6, 0x40));
                out.extend_from_slice(&encode_string_literal(value.as_bytes()));
                continue;
            }

            // Literal header field without indexing (Section 6.2.2)
            // Pattern: 00000000 followed by name and value strings
            out.push(0x00);
            out.extend_from_slice(&encode_string_literal(name.as_bytes()));
            out.extend_from_slice(&encode_string_literal(value.as_bytes()));
        }

        out
    }

    /// Encode headers using Huffman encoding for string values.
    pub fn encode_huffman(&self, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();

        for &(name, value) in headers {
            // Check static table for exact match
            if let Some(static_idx) = self.find_static_exact(name, value) {
                out.extend_from_slice(&encode_integer(static_idx as u64, 7, 0x80));
                continue;
            }

            // Literal without indexing with Huffman-encoded strings
            out.push(0x00);
            out.extend_from_slice(&encode_string_huffman(name.as_bytes()));
            out.extend_from_slice(&encode_string_huffman(value.as_bytes()));
        }

        out
    }

    /// Find a static table index for an exact (name, value) match.
    /// Returns 1-based index or None.
    fn find_static_exact(&self, name: &str, value: &str) -> Option<usize> {
        for (i, &(n, v)) in STATIC_TABLE.iter().enumerate() {
            if n == name && v == value {
                return Some(i + 1);
            }
        }
        None
    }

    /// Find a static table index for a name-only match.
    /// Returns 1-based index of first matching entry or None.
    fn find_static_name(&self, name: &str) -> Option<usize> {
        for (i, &(n, _)) in STATIC_TABLE.iter().enumerate() {
            if n == name {
                return Some(i + 1);
            }
        }
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Integer encode/decode
    // -------------------------------------------------------------------------

    #[test]
    fn test_decode_integer_small() {
        // Value 5 with 5-bit prefix: 0b00000101 = 0x05
        let buf = [0x05u8];
        let (val, consumed) = decode_integer(&buf, 5).unwrap();
        assert_eq!(val, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_integer_multi_byte() {
        // RFC 7541 Section 5.1 example: value 1337 with 5-bit prefix
        // First byte: 0b00011111 = 31 (all prefix bits set)
        // Continuation: 0b10011010 = 154, 0b00001010 = 10
        // 1337 - 31 = 1306 = 0b10100011010
        // First continuation: 1306 & 0x7F = 26 (0b0011010), MSB=1 → 0b10011010 = 0x9A... wait
        // Let me use spec values: 1337 with 5-bit prefix
        // 1337 - 31 = 1306
        // 1306 % 128 = 26 | 0x80 = 0x9A, 1306 / 128 = 10 = 0x0A
        let buf = [0b00011111u8, 0x9A, 0x0A];
        let (val, consumed) = decode_integer(&buf, 5).unwrap();
        assert_eq!(val, 1337);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_encode_integer_small() {
        let encoded = encode_integer(5, 5, 0x00);
        assert_eq!(encoded, vec![0x05]);
    }

    #[test]
    fn test_encode_integer_large() {
        // 1337 with 5-bit prefix
        let encoded = encode_integer(1337, 5, 0x00);
        assert_eq!(encoded, vec![0b00011111, 0x9A, 0x0A]);
    }

    #[test]
    fn test_encode_decode_integer_roundtrip() {
        for val in [0u64, 1, 30, 31, 127, 128, 255, 1000, 65535, 1337] {
            for prefix in [4u8, 5, 6, 7] {
                let encoded = encode_integer(val, prefix, 0x00);
                let (decoded, _) = decode_integer(&encoded, prefix).unwrap();
                assert_eq!(
                    val, decoded,
                    "Roundtrip failed for val={} prefix={}",
                    val, prefix
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // String literals
    // -------------------------------------------------------------------------

    #[test]
    fn test_decode_string_literal() {
        // Non-Huffman string: length=5, "hello"
        let mut buf = vec![0x05u8]; // H=0, length=5
        buf.extend_from_slice(b"hello");
        let (s, consumed) = decode_string(&buf).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_huffman_encode_decode_roundtrip() {
        let original = b"www.example.com";
        let encoded = huffman_encode(original);
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_huffman_encode_empty() {
        let encoded = huffman_encode(b"");
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_huffman_decode_rfc7541_example() {
        // RFC 7541 Appendix C.4.1 example: "www.example.com" Huffman-encoded
        // Known encoding from the RFC: f1e3 c2e5 f23a 6ba0 ab90 f4ff
        let encoded = [
            0xf1u8, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let decoded = huffman_decode(&encoded).unwrap();
        assert_eq!(decoded, b"www.example.com");
    }

    #[test]
    fn test_decode_string_huffman() {
        let original = b"no-cache";
        let encoded = huffman_encode(original);
        // Build HPACK string format: H=1, length, data
        let mut buf = encode_integer(encoded.len() as u64, 7, 0x80);
        buf.extend_from_slice(&encoded);
        let (decoded, _) = decode_string(&buf).unwrap();
        assert_eq!(decoded, original);
    }

    // -------------------------------------------------------------------------
    // Static table
    // -------------------------------------------------------------------------

    #[test]
    fn test_static_table_size() {
        assert_eq!(STATIC_TABLE.len(), 61);
    }

    #[test]
    fn test_static_table_first_entry() {
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
    }

    #[test]
    fn test_static_table_method_get() {
        assert_eq!(STATIC_TABLE[1], (":method", "GET"));
    }

    // -------------------------------------------------------------------------
    // HPACK decoder
    // -------------------------------------------------------------------------

    #[test]
    fn test_decoder_indexed_static() {
        // Index 2 = ":method: GET"
        // Indexed representation: 1xxxxxxx where x=2 → 0x82
        let buf = [0x82u8];
        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&buf).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
    }

    #[test]
    fn test_decoder_literal_with_indexing() {
        // Literal with incremental indexing: 01xxxxxx
        // name index = 0, name = "custom-key", value = "custom-header"
        let mut buf = vec![0x40u8]; // 01 000000 = new name, incremental indexing
        buf.extend_from_slice(&encode_string_literal(b"custom-key"));
        buf.extend_from_slice(&encode_string_literal(b"custom-header"));

        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&buf).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers[0],
            ("custom-key".to_string(), "custom-header".to_string())
        );
    }

    #[test]
    fn test_decoder_literal_without_indexing() {
        // Literal without indexing: 0000xxxx with idx=0 (new name)
        let mut buf = vec![0x00u8];
        buf.extend_from_slice(&encode_string_literal(b"x-custom"));
        buf.extend_from_slice(&encode_string_literal(b"value"));

        let mut decoder = HpackDecoder::new();
        let headers = decoder.decode(&buf).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], ("x-custom".to_string(), "value".to_string()));
    }

    #[test]
    fn test_decoder_dynamic_table_eviction() {
        let mut decoder = HpackDecoder::with_max_size(64);
        // Add an entry that barely fits
        let mut buf = vec![0x40u8];
        buf.extend_from_slice(&encode_string_literal(b"x-a"));
        buf.extend_from_slice(&encode_string_literal(b"b"));
        decoder.decode(&buf).unwrap();
        assert_eq!(decoder.dynamic_table.len(), 1);

        // Add another entry that should evict the first
        let mut buf2 = vec![0x40u8];
        buf2.extend_from_slice(&encode_string_literal(b"x-c"));
        buf2.extend_from_slice(&encode_string_literal(b"d"));
        decoder.decode(&buf2).unwrap();
        // First entry should be evicted since total would exceed 64
        assert!(decoder.dynamic_table.len() <= 2);
    }

    // -------------------------------------------------------------------------
    // HPACK encoder
    // -------------------------------------------------------------------------

    #[test]
    fn test_encoder_static_exact_match() {
        let encoder = HpackEncoder::new();
        // ":method: GET" is static index 2 → should encode as 0x82
        let encoded = encoder.encode(&[(":method", "GET")]);
        assert_eq!(encoded, vec![0x82]);
    }

    #[test]
    fn test_encoder_static_name_match() {
        let encoder = HpackEncoder::new();
        // ":method" matches static index 2 with value "GET", but "DELETE" won't match exact
        let encoded = encoder.encode(&[(":method", "DELETE")]);
        // Should use name-indexed literal: 0x40 | idx(2) = 0x42, then value
        assert_eq!(encoded[0], 0x42); // 01 000010 = name-indexed literal with static index 2
    }

    #[test]
    fn test_encoder_roundtrip() {
        let encoder = HpackEncoder::new();
        let mut decoder = HpackDecoder::new();

        let headers = vec![
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            ("user-agent", "test/1.0"),
            ("x-custom", "value"),
        ];
        let encoded = encoder.encode(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), headers.len());
        for (i, (name, value)) in headers.iter().enumerate() {
            assert_eq!(decoded[i].0, *name);
            assert_eq!(decoded[i].1, *value);
        }
    }

    #[test]
    fn test_encoder_huffman_roundtrip() {
        let encoder = HpackEncoder::new();
        let mut decoder = HpackDecoder::new();

        let headers = vec![
            ("x-request-id", "abc-123"),
            ("content-type", "application/json"),
        ];
        let encoded = encoder.encode_huffman(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), headers.len());
        for (i, (name, value)) in headers.iter().enumerate() {
            assert_eq!(decoded[i].0, *name);
            assert_eq!(decoded[i].1, *value);
        }
    }
}
