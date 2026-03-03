//! QUIC frame types and frame parsing (RFC 9000 Section 19 / Table 3).

use super::varint;

/// QUIC frame types as defined in RFC 9000 Table 3.
///
/// Discriminants are not used here (the `Unknown(u8)` variant holds the raw byte
/// for unrecognised frame types).  Use [`FrameType::from_u8`] to construct and
/// [`FrameType::as_u8`] to convert back to the wire byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Padding,
    Ping,
    Ack,
    AckEcn,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    /// Stream frames (raw type byte 0x08-0x0F depending on flags).
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    MaxStreamsBidi,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    StreamsBlockedBidi,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    ConnectionCloseApp,
    HandshakeDone,
    Unknown(u8),
}

impl FrameType {
    /// Return the canonical wire byte for this frame type (the lowest byte in
    /// any range, e.g. `Stream` → `0x08`).
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Padding => 0x00,
            Self::Ping => 0x01,
            Self::Ack => 0x02,
            Self::AckEcn => 0x03,
            Self::ResetStream => 0x04,
            Self::StopSending => 0x05,
            Self::Crypto => 0x06,
            Self::NewToken => 0x07,
            Self::Stream => 0x08,
            Self::MaxData => 0x10,
            Self::MaxStreamData => 0x11,
            Self::MaxStreams => 0x12,
            Self::MaxStreamsBidi => 0x13,
            Self::DataBlocked => 0x14,
            Self::StreamDataBlocked => 0x15,
            Self::StreamsBlocked => 0x16,
            Self::StreamsBlockedBidi => 0x17,
            Self::NewConnectionId => 0x18,
            Self::RetireConnectionId => 0x19,
            Self::PathChallenge => 0x1A,
            Self::PathResponse => 0x1B,
            Self::ConnectionClose => 0x1C,
            Self::ConnectionCloseApp => 0x1D,
            Self::HandshakeDone => 0x1E,
            Self::Unknown(t) => *t,
        }
    }
}

impl FrameType {
    /// Convert a raw byte to a `FrameType`.
    ///
    /// Stream frames in the range 0x08-0x0F are all mapped to `Stream`;
    /// the low 3 bits carry flags (OFF, LEN, FIN) and are preserved in the
    /// raw byte but collapsed to the `Stream` variant here.
    #[must_use]
    pub fn from_u8(t: u8) -> Self {
        match t {
            0x00 => Self::Padding,
            0x01 => Self::Ping,
            0x02 => Self::Ack,
            0x03 => Self::AckEcn,
            0x04 => Self::ResetStream,
            0x05 => Self::StopSending,
            0x06 => Self::Crypto,
            0x07 => Self::NewToken,
            0x08..=0x0F => Self::Stream,
            0x10 => Self::MaxData,
            0x11 => Self::MaxStreamData,
            0x12 => Self::MaxStreams,
            0x13 => Self::MaxStreamsBidi,
            0x14 => Self::DataBlocked,
            0x15 => Self::StreamDataBlocked,
            0x16 => Self::StreamsBlocked,
            0x17 => Self::StreamsBlockedBidi,
            0x18 => Self::NewConnectionId,
            0x19 => Self::RetireConnectionId,
            0x1A => Self::PathChallenge,
            0x1B => Self::PathResponse,
            0x1C => Self::ConnectionClose,
            0x1D => Self::ConnectionCloseApp,
            0x1E => Self::HandshakeDone,
            _ => Self::Unknown(t),
        }
    }

    /// Return a human-readable name for this frame type.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Padding => "PADDING",
            Self::Ping => "PING",
            Self::Ack => "ACK",
            Self::AckEcn => "ACK_ECN",
            Self::ResetStream => "RESET_STREAM",
            Self::StopSending => "STOP_SENDING",
            Self::Crypto => "CRYPTO",
            Self::NewToken => "NEW_TOKEN",
            Self::Stream => "STREAM",
            Self::MaxData => "MAX_DATA",
            Self::MaxStreamData => "MAX_STREAM_DATA",
            Self::MaxStreams => "MAX_STREAMS",
            Self::MaxStreamsBidi => "MAX_STREAMS_BIDI",
            Self::DataBlocked => "DATA_BLOCKED",
            Self::StreamDataBlocked => "STREAM_DATA_BLOCKED",
            Self::StreamsBlocked => "STREAMS_BLOCKED",
            Self::StreamsBlockedBidi => "STREAMS_BLOCKED_BIDI",
            Self::NewConnectionId => "NEW_CONNECTION_ID",
            Self::RetireConnectionId => "RETIRE_CONNECTION_ID",
            Self::PathChallenge => "PATH_CHALLENGE",
            Self::PathResponse => "PATH_RESPONSE",
            Self::ConnectionClose => "CONNECTION_CLOSE",
            Self::ConnectionCloseApp => "CONNECTION_CLOSE_APP",
            Self::HandshakeDone => "HANDSHAKE_DONE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// A parsed QUIC frame — a lightweight view into the payload buffer.
///
/// Does not own data; `offset` and `length` describe the region of the
/// original buffer that contains this frame.
#[derive(Debug, Clone)]
pub struct QuicFrame {
    /// The frame type.
    pub frame_type: FrameType,
    /// Byte offset in the payload buffer where this frame starts.
    pub offset: usize,
    /// Total byte length of this frame (including the type byte).
    pub length: usize,
}

/// Parse all frames from a decrypted QUIC payload buffer.
///
/// This is a best-effort parser: it stops at the first parse error or unknown
/// frame type rather than returning an error.  The returned `Vec` may therefore
/// be incomplete if the payload is malformed or encrypted.
#[must_use]
pub fn parse_frames(buf: &[u8]) -> Vec<QuicFrame> {
    let mut frames = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        let frame_start = pos;
        let raw_type = buf[pos];
        let frame_type = FrameType::from_u8(raw_type);
        pos += 1; // consume type byte

        match frame_type {
            FrameType::Padding => {
                // A run of 0x00 bytes; each counts as a separate PADDING frame.
                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: 1,
                });
            },

            FrameType::Ping => {
                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: 1,
                });
            },

            FrameType::Ack | FrameType::AckEcn => {
                // ACK: type(1) + largest_ack(varint) + ack_delay(varint) +
                //      ack_range_count(varint) + first_ack_range(varint) +
                //      [ack_range_count * (gap(varint) + ack_range(varint))] +
                //      [ECT0_count, ECT1_count, ECN_CE_count if AckEcn]
                let remaining = &buf[pos..];
                let (largest_ack, n1) = match varint::decode(remaining) {
                    Some(v) => v,
                    None => break,
                };
                let _ = largest_ack;
                pos += n1;

                let remaining = &buf[pos..];
                let (_ack_delay, n2) = match varint::decode(remaining) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                let remaining = &buf[pos..];
                let (ack_range_count, n3) = match varint::decode(remaining) {
                    Some(v) => v,
                    None => break,
                };
                pos += n3;

                // first_ack_range
                let remaining = &buf[pos..];
                let (_first_range, n4) = match varint::decode(remaining) {
                    Some(v) => v,
                    None => break,
                };
                pos += n4;

                // subsequent ack ranges: gap + ack_range for each
                let mut ok = true;
                for _ in 0..ack_range_count {
                    if let Some((_, ng)) = varint::decode(&buf[pos..]) {
                        pos += ng;
                    } else {
                        ok = false;
                        break;
                    }
                    if let Some((_, nr)) = varint::decode(&buf[pos..]) {
                        pos += nr;
                    } else {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }

                // ECN counts (AckEcn only)
                if frame_type == FrameType::AckEcn {
                    for _ in 0..3 {
                        if let Some((_, n)) = varint::decode(&buf[pos..]) {
                            pos += n;
                        } else {
                            break;
                        }
                    }
                }

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::Crypto => {
                // CRYPTO: type(1) + offset(varint) + length(varint) + data
                let (_crypto_offset, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let (data_len, n2) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                let data_len = data_len as usize;
                if pos + data_len > buf.len() {
                    break;
                }
                pos += data_len;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::NewToken => {
                // NEW_TOKEN: type(1) + token_length(varint) + token
                let (token_len, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let token_len = token_len as usize;
                if pos + token_len > buf.len() {
                    break;
                }
                pos += token_len;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::Stream => {
                // Stream type byte low 3 bits:
                //   bit 0x01 = OFF bit (offset field present)
                //   bit 0x02 = LEN bit (length field present)
                //   bit 0x04 = FIN bit
                let off_bit = raw_type & 0x01 != 0;
                let len_bit = raw_type & 0x02 != 0;

                // stream_id (varint)
                let (_stream_id, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                // optional offset field
                if off_bit {
                    let (_stream_offset, n2) = match varint::decode(&buf[pos..]) {
                        Some(v) => v,
                        None => break,
                    };
                    pos += n2;
                }

                // optional length field
                if len_bit {
                    let (data_len, n3) = match varint::decode(&buf[pos..]) {
                        Some(v) => v,
                        None => break,
                    };
                    pos += n3;

                    let data_len = data_len as usize;
                    if pos + data_len > buf.len() {
                        break;
                    }
                    pos += data_len;
                } else {
                    // No length field — data extends to end of packet.
                    pos = buf.len();
                }

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::MaxData
            | FrameType::MaxStreams
            | FrameType::MaxStreamsBidi
            | FrameType::DataBlocked
            | FrameType::StreamsBlocked
            | FrameType::StreamsBlockedBidi
            | FrameType::RetireConnectionId => {
                // Single varint argument.
                let (_, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::MaxStreamData | FrameType::StreamDataBlocked => {
                // Two varint arguments: stream_id + limit/offset.
                let (_, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let (_, n2) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::ResetStream => {
                // RESET_STREAM: stream_id(varint) + app_error_code(varint) + final_size(varint)
                for _ in 0..3 {
                    let (_, n) = if let Some(v) = varint::decode(&buf[pos..]) {
                        v
                    } else {
                        frames.push(QuicFrame {
                            frame_type,
                            offset: frame_start,
                            length: pos - frame_start,
                        });
                        return frames;
                    };
                    pos += n;
                }
                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::StopSending => {
                // STOP_SENDING: stream_id(varint) + app_error_code(varint)
                for _ in 0..2 {
                    let (_, n) = if let Some(v) = varint::decode(&buf[pos..]) {
                        v
                    } else {
                        frames.push(QuicFrame {
                            frame_type,
                            offset: frame_start,
                            length: pos - frame_start,
                        });
                        return frames;
                    };
                    pos += n;
                }
                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::NewConnectionId => {
                // NEW_CONNECTION_ID: seq_no(varint) + retire_prior_to(varint) +
                //   conn_id_len(u8) + conn_id(N bytes) + stateless_reset_token(16 bytes)
                let (_, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let (_, n2) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                if pos >= buf.len() {
                    break;
                }
                let conn_id_len = buf[pos] as usize;
                pos += 1;

                if pos + conn_id_len + 16 > buf.len() {
                    break;
                }
                pos += conn_id_len + 16;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::PathChallenge | FrameType::PathResponse => {
                // Fixed 8-byte data field.
                if pos + 8 > buf.len() {
                    break;
                }
                pos += 8;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::ConnectionClose => {
                // CONNECTION_CLOSE: error_code(varint) + frame_type(varint) +
                //   reason_phrase_len(varint) + reason_phrase
                let (_, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let (_, n2) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                let (phrase_len, n3) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n3;

                let phrase_len = phrase_len as usize;
                if pos + phrase_len > buf.len() {
                    break;
                }
                pos += phrase_len;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::ConnectionCloseApp => {
                // CONNECTION_CLOSE (app): error_code(varint) +
                //   reason_phrase_len(varint) + reason_phrase
                let (_, n1) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n1;

                let (phrase_len, n2) = match varint::decode(&buf[pos..]) {
                    Some(v) => v,
                    None => break,
                };
                pos += n2;

                let phrase_len = phrase_len as usize;
                if pos + phrase_len > buf.len() {
                    break;
                }
                pos += phrase_len;

                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: pos - frame_start,
                });
            },

            FrameType::HandshakeDone => {
                // HANDSHAKE_DONE: no fields.
                frames.push(QuicFrame {
                    frame_type,
                    offset: frame_start,
                    length: 1,
                });
            },

            FrameType::Unknown(_) => {
                // Stop on unknown frame type to avoid mis-parsing.
                break;
            },
        }
    }

    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_type_from_u8() {
        assert_eq!(FrameType::from_u8(0x00), FrameType::Padding);
        assert_eq!(FrameType::from_u8(0x01), FrameType::Ping);
        assert_eq!(FrameType::from_u8(0x02), FrameType::Ack);
        assert_eq!(FrameType::from_u8(0x06), FrameType::Crypto);
        assert_eq!(FrameType::from_u8(0x08), FrameType::Stream);
        assert_eq!(FrameType::from_u8(0x0F), FrameType::Stream);
        assert_eq!(FrameType::from_u8(0x1E), FrameType::HandshakeDone);
        assert_eq!(FrameType::from_u8(0xFF), FrameType::Unknown(0xFF));
    }

    #[test]
    fn test_frame_type_names() {
        assert_eq!(FrameType::Padding.name(), "PADDING");
        assert_eq!(FrameType::Crypto.name(), "CRYPTO");
        assert_eq!(FrameType::Stream.name(), "STREAM");
        assert_eq!(FrameType::Unknown(0xAB).name(), "UNKNOWN");
    }

    #[test]
    fn test_parse_padding_and_ping() {
        let buf = [0x00u8, 0x00, 0x01]; // two PADDING, one PING
        let frames = parse_frames(&buf);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].frame_type, FrameType::Padding);
        assert_eq!(frames[1].frame_type, FrameType::Padding);
        assert_eq!(frames[2].frame_type, FrameType::Ping);
        assert_eq!(frames[2].offset, 2);
        assert_eq!(frames[2].length, 1);
    }

    #[test]
    fn test_parse_handshake_done() {
        let buf = [0x1Eu8];
        let frames = parse_frames(&buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::HandshakeDone);
        assert_eq!(frames[0].length, 1);
    }

    #[test]
    fn test_parse_crypto_frame() {
        // CRYPTO: type=0x06, offset=0(varint:1 byte=0x00), length=4(varint:1 byte=0x04), data
        let buf = [0x06u8, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let frames = parse_frames(&buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Crypto);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].length, 7); // 1 + 1 + 1 + 4
    }

    #[test]
    fn test_parse_stream_frame_with_len() {
        // STREAM type=0x0A (OFF=0, LEN=1, FIN=0): stream_id=1, length=2, data
        // 0x0A = 0b00001010: OFF bit=0, LEN bit=1, FIN bit=0
        let buf = [0x0Au8, 0x01, 0x02, 0xAA, 0xBB];
        let frames = parse_frames(&buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Stream);
        assert_eq!(frames[0].length, 5);
    }

    #[test]
    fn test_parse_stops_on_unknown() {
        let buf = [0x01u8, 0xFF, 0x01]; // PING, Unknown(0xFF), PING
        let frames = parse_frames(&buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Ping);
    }
}
