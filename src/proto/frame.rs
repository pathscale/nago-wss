//! Frame headers, RFC 6455 §5.2.
//!
//! Decoding is incremental and copy-free: [`Header::decode`] is handed whatever
//! bytes have arrived and reports [`Incomplete`] rather than consuming them, so
//! the caller can keep filling the same buffer. Nothing here allocates.

use super::opcode::OpCode;

/// Why a frame could not be decoded.
///
/// These are all fatal: RFC 6455 §5.2 requires failing the connection rather
/// than skipping a frame, because the stream is self-delimiting and a bad
/// header means every following byte offset is suspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// An opcode from a reserved range.
    ReservedOpCode(u8),
    /// RSV1/2/3 set with no extension negotiated to define them.
    ReservedBitSet,
    /// A control frame longer than 125 bytes, or fragmented. §5.5 forbids both.
    InvalidControlFrame,
    /// A length not encoded in its shortest form, or with the high bit set.
    ///
    /// §5.2 requires the minimal encoding, and a 64-bit length must have its
    /// most significant bit clear. Accepting a non-minimal length would admit
    /// two encodings of the same frame.
    InvalidLength,
    /// The frame's payload exceeds the configured limit.
    TooLarge,
}

/// Not enough bytes yet. Carries no position: the caller retries from the start
/// of the same buffer once more data lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incomplete;

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Whether this frame completes its message.
    pub fin: bool,
    /// What the frame carries.
    pub opcode: OpCode,
    /// The masking key, present exactly when the MASK bit was set.
    pub mask: Option<[u8; 4]>,
    /// Payload length in bytes, already validated against the limit.
    pub payload_len: u64,
}

impl Header {
    /// The largest header RFC 6455 permits: 2 fixed + 8 length + 4 mask.
    pub const MAX_ENCODED_LEN: usize = 14;

    /// Decode a header from the front of `input`.
    ///
    /// On success returns the header and how many bytes it occupied, so the
    /// caller can advance past it to the payload. `max_payload` rejects an
    /// oversized frame from its length field alone, before any of the payload
    /// is read or buffered.
    pub fn decode(
        input: &[u8],
        max_payload: u64,
    ) -> Result<Result<(Self, usize), Incomplete>, FrameError> {
        if input.len() < 2 {
            return Ok(Err(Incomplete));
        }

        let first = input[0];
        let second = input[1];

        // RSV1/2/3. No extensions are negotiated (no permessage-deflate), so
        // any of these being set is unconditionally an error.
        if first & 0x70 != 0 {
            return Err(FrameError::ReservedBitSet);
        }

        let fin = first & 0x80 != 0;
        let opcode =
            OpCode::from_bits(first & 0x0F).ok_or(FrameError::ReservedOpCode(first & 0x0F))?;

        let masked = second & 0x80 != 0;
        let short_len = second & 0x7F;

        // §5.5: control frames carry at most 125 bytes and are never fragmented.
        // Checked before the extended length is read, because a control frame
        // has no extended length to read.
        if opcode.is_control() && (short_len > 125 || !fin) {
            return Err(FrameError::InvalidControlFrame);
        }

        let mut cursor = 2usize;
        let payload_len: u64 = match short_len {
            126 => {
                if input.len() < cursor + 2 {
                    return Ok(Err(Incomplete));
                }
                let value = u16::from_be_bytes([input[cursor], input[cursor + 1]]) as u64;
                cursor += 2;
                // Shortest-form: 0-125 must use the one-byte encoding.
                if value < 126 {
                    return Err(FrameError::InvalidLength);
                }
                value
            }
            127 => {
                if input.len() < cursor + 8 {
                    return Ok(Err(Incomplete));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&input[cursor..cursor + 8]);
                let value = u64::from_be_bytes(bytes);
                cursor += 8;
                // The high bit must be clear, and anything under 65536 had a
                // shorter encoding available.
                if value & 0x8000_0000_0000_0000 != 0 || value <= u16::MAX as u64 {
                    return Err(FrameError::InvalidLength);
                }
                value
            }
            n => n as u64,
        };

        if payload_len > max_payload {
            return Err(FrameError::TooLarge);
        }

        let mask = if masked {
            if input.len() < cursor + 4 {
                return Ok(Err(Incomplete));
            }
            let key = [
                input[cursor],
                input[cursor + 1],
                input[cursor + 2],
                input[cursor + 3],
            ];
            cursor += 4;
            Some(key)
        } else {
            None
        };

        Ok(Ok((
            Self {
                fin,
                opcode,
                mask,
                payload_len,
            },
            cursor,
        )))
    }

    /// How many bytes [`Self::encode`] will write for this header.
    #[inline]
    pub const fn encoded_len(&self) -> usize {
        let length_bytes = if self.payload_len < 126 {
            0
        } else if self.payload_len <= u16::MAX as u64 {
            2
        } else {
            8
        };
        let mask_bytes = if self.mask.is_some() { 4 } else { 0 };
        2 + length_bytes + mask_bytes
    }

    /// Write this header into `out`, returning how many bytes were written.
    ///
    /// `out` must hold at least [`Self::encoded_len`]; a short buffer returns
    /// `None` rather than writing a partial header.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let needed = self.encoded_len();
        if out.len() < needed {
            return None;
        }

        out[0] = (if self.fin { 0x80 } else { 0 }) | self.opcode.to_bits();

        let mask_bit = if self.mask.is_some() { 0x80 } else { 0 };
        let mut cursor = 2usize;

        if self.payload_len < 126 {
            out[1] = mask_bit | self.payload_len as u8;
        } else if self.payload_len <= u16::MAX as u64 {
            out[1] = mask_bit | 126;
            out[cursor..cursor + 2].copy_from_slice(&(self.payload_len as u16).to_be_bytes());
            cursor += 2;
        } else {
            out[1] = mask_bit | 127;
            out[cursor..cursor + 8].copy_from_slice(&self.payload_len.to_be_bytes());
            cursor += 8;
        }

        if let Some(key) = self.mask {
            out[cursor..cursor + 4].copy_from_slice(&key);
            cursor += 4;
        }

        Some(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_LIMIT: u64 = u64::MAX;

    fn decode(input: &[u8]) -> Result<Result<(Header, usize), Incomplete>, FrameError> {
        Header::decode(input, NO_LIMIT)
    }

    #[test]
    fn decodes_a_short_unmasked_text_frame() {
        // FIN + text, length 5.
        let (header, used) = decode(&[0x81, 0x05]).unwrap().unwrap();
        assert!(header.fin);
        assert_eq!(header.opcode, OpCode::Text);
        assert_eq!(header.payload_len, 5);
        assert_eq!(header.mask, None);
        assert_eq!(used, 2);
    }

    #[test]
    fn decodes_a_masked_frame_and_reports_the_key() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let mut input = alloc::vec![0x81, 0x85];
        input.extend_from_slice(&key);
        let (header, used) = decode(&input).unwrap().unwrap();
        assert_eq!(header.mask, Some(key));
        assert_eq!(used, 6);
    }

    #[test]
    fn reports_incomplete_without_consuming() {
        assert_eq!(decode(&[]).unwrap(), Err(Incomplete));
        assert_eq!(decode(&[0x81]).unwrap(), Err(Incomplete));
        // Says 126 (extended length follows) but the two bytes are missing.
        assert_eq!(decode(&[0x81, 0x7E]).unwrap(), Err(Incomplete));
        // Mask bit set but the key is short.
        assert_eq!(decode(&[0x81, 0x85, 0x00, 0x00]).unwrap(), Err(Incomplete));
    }

    #[test]
    fn rejects_reserved_bits_and_opcodes() {
        assert_eq!(decode(&[0xC1, 0x00]), Err(FrameError::ReservedBitSet));
        assert_eq!(decode(&[0x83, 0x00]), Err(FrameError::ReservedOpCode(3)));
        assert_eq!(decode(&[0x8B, 0x00]), Err(FrameError::ReservedOpCode(0xB)));
    }

    #[test]
    fn rejects_oversized_and_fragmented_control_frames() {
        // Ping with a 126-byte payload.
        assert_eq!(decode(&[0x89, 0x7E]), Err(FrameError::InvalidControlFrame));
        // Ping without FIN.
        assert_eq!(decode(&[0x09, 0x00]), Err(FrameError::InvalidControlFrame));
    }

    #[test]
    fn rejects_non_minimal_lengths() {
        // 126-form carrying a value that fits the 7-bit form.
        assert_eq!(
            decode(&[0x81, 0x7E, 0x00, 0x05]),
            Err(FrameError::InvalidLength)
        );
        // 127-form carrying a value that fits the 16-bit form.
        assert_eq!(
            decode(&[0x81, 0x7F, 0, 0, 0, 0, 0, 0, 0x01, 0x00]),
            Err(FrameError::InvalidLength)
        );
        // 64-bit length with the high bit set.
        assert_eq!(
            decode(&[0x81, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::InvalidLength)
        );
    }

    #[test]
    fn enforces_the_payload_limit_from_the_header_alone() {
        // A 16-bit length of 1000 against a 100-byte limit: rejected without
        // any payload having been buffered.
        assert_eq!(
            Header::decode(&[0x82, 0x7E, 0x03, 0xE8], 100),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn round_trips_every_length_class() {
        for (len, expected) in [(5u64, 2usize), (200, 4), (70_000, 10)] {
            let header = Header {
                fin: true,
                opcode: OpCode::Binary,
                mask: None,
                payload_len: len,
            };
            let mut buffer = [0u8; Header::MAX_ENCODED_LEN];
            let written = header.encode(&mut buffer).expect("buffer is large enough");
            assert_eq!(written, expected, "unexpected header width for len {len}");
            assert_eq!(written, header.encoded_len());

            let (back, used) = decode(&buffer[..written]).unwrap().unwrap();
            assert_eq!(back, header);
            assert_eq!(used, written);
        }
    }

    #[test]
    fn round_trips_a_masked_header() {
        let header = Header {
            fin: false,
            opcode: OpCode::Continuation,
            mask: Some([1, 2, 3, 4]),
            payload_len: 300,
        };
        let mut buffer = [0u8; Header::MAX_ENCODED_LEN];
        let written = header.encode(&mut buffer).unwrap();
        let (back, used) = decode(&buffer[..written]).unwrap().unwrap();
        assert_eq!(back, header);
        assert_eq!(used, written);
    }

    #[test]
    fn encode_refuses_a_short_buffer() {
        let header = Header {
            fin: true,
            opcode: OpCode::Text,
            mask: None,
            payload_len: 70_000,
        };
        assert_eq!(header.encode(&mut [0u8; 4]), None);
    }
}
